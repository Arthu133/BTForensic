from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import unquote

from .anonymization_decoder import decode_anonymization_payload
from .domain_utils import TargetInfo, url_matches_target
from .safe_redaction import mask_url_query, redact_headers


TEXT_EXTENSIONS = {".tmp", ".log", ".json", ".ldb", ".txt", ".dat"}
SCAN_DIRS = ("Network", "Network Logs", "Service Worker", "Cache")
MAX_FILE_SIZE = 25 * 1024 * 1024
SENSITIVE_WORDS = ("cookie", "authorization", "token", "secret", "session")


def _candidate_files(profile_path: Path):
    bases = [profile_path]
    bases.extend(profile_path / name for name in SCAN_DIRS if (profile_path / name).exists())
    seen = set()
    for base in bases:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            if path.suffix.lower() in TEXT_EXTENSIONS and path.stat().st_size <= MAX_FILE_SIZE:
                yield path


def _extract_json_fields(line: str) -> dict:
    try:
        obj = json.loads(line)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    headers = obj.get("headers") if isinstance(obj.get("headers"), dict) else {}
    return {
        "url": obj.get("url") or obj.get("request_url"),
        "origin": obj.get("origin"),
        "referrer": obj.get("referrer") or obj.get("referer"),
        "initiator": obj.get("initiator"),
        "method": obj.get("method"),
        "status_code": obj.get("status") or obj.get("status_code"),
        "timestamp": obj.get("timestamp") or obj.get("time"),
        "headers": redact_headers(headers),
    }


def _regex_extract(line: str) -> dict:
    url_match = re.search(r"https?://[^\s\"'<>\\]+", line)
    method_match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", line)
    status_match = re.search(r"\bstatus(?:_code)?[\"'\s:=]+(\d{3})\b", line, re.IGNORECASE)
    origin_match = re.search(r"\borigin[\"'\s:=]+([^,\s\"']+)", line, re.IGNORECASE)
    ref_match = re.search(r"\breferr?er[\"'\s:=]+([^,\s\"']+)", line, re.IGNORECASE)
    initiator_match = re.search(r"\binitiator[\"'\s:=]+([^,\s\"']+)", line, re.IGNORECASE)
    return {
        "url": url_match.group(0) if url_match else None,
        "origin": origin_match.group(1) if origin_match else None,
        "referrer": ref_match.group(1) if ref_match else None,
        "initiator": initiator_match.group(1) if initiator_match else None,
        "method": method_match.group(1) if method_match else None,
        "status_code": int(status_match.group(1)) if status_match else None,
        "timestamp": None,
        "headers": {},
    }


def _safe_decoded_items(decoded: dict) -> dict:
    safe_decoded = [
        item for item in decoded["decoded"]
        if not any(word in item.lower() for word in SENSITIVE_WORDS)
    ]
    return {**decoded, "decoded": safe_decoded}


def _extract_anonymization(line: str) -> list[dict]:
    results = []
    patterns = (
        r"(?P<label>anonymization[_-]?key)[\"'\s:=]+(?P<value>\"(?:\\.|[^\"])+\"|'(?:\\.|[^'])+'|[^,\s}\]]+)",
        r"(?P<label>network[_\s-]?isolation[_\s-]?key)[\"'\s:=]+(?P<value>\"(?:\\.|[^\"])+\"|'(?:\\.|[^'])+'|[^,\s}\]]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, line, re.IGNORECASE):
            value = match.group("value").strip().strip("\"'")
            value = unquote(value)
            decoded = decode_anonymization_payload(value)
            results.append({"field": match.group("label"), **_safe_decoded_items(decoded)})
    return results


def _flatten_anonymization_urls(records: list[dict]) -> list[str]:
    urls = []
    seen = set()
    for record in records:
        for url in record.get("extracted_urls", []):
            if url not in seen:
                seen.add(url)
                urls.append(mask_url_query(url))
    return urls


def _infer_origins_from_anonymization(records: list[dict], target: TargetInfo) -> list[str]:
    origins = []
    seen = set()
    for url in _flatten_anonymization_urls(records):
        if url_matches_target(url, target):
            continue
        if url not in seen:
            seen.add(url)
            origins.append(url)
    return origins


def analyze_network_logs(profile_name: str, profile_path: Path, target: TargetInfo, logger: logging.Logger) -> dict:
    result = {"network_log_matches": [], "errors": []}
    try:
        matches = []
        target_texts = {target.domain.lower(), target.raw.lower()}
        if target.normalized_url:
            target_texts.add(target.normalized_url.lower())
        for path in _candidate_files(profile_path):
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    for line_no, line in enumerate(handle, start=1):
                        lower = line.lower()
                        if not any(text and text in lower for text in target_texts):
                            continue
                        fields = _extract_json_fields(line)
                        regex_fields = _regex_extract(line)
                        fields = {key: fields.get(key) or regex_fields.get(key) for key in regex_fields}
                        fields["headers"] = redact_headers(fields.get("headers"))
                        anonymization = _extract_anonymization(line)
                        matches.append(
                            {
                                "profile": profile_name,
                                "file": str(path),
                                "line": line_no,
                                "url": mask_url_query(fields.get("url")),
                                "origin": mask_url_query(fields.get("origin")),
                                "referrer": mask_url_query(fields.get("referrer")),
                                "initiator": mask_url_query(fields.get("initiator")),
                                "method": fields.get("method"),
                                "status_code": fields.get("status_code"),
                                "timestamp": fields.get("timestamp"),
                                "anonymization": anonymization,
                                "anonymization_urls": _flatten_anonymization_urls(anonymization),
                                "inferred_origins_from_anonymization": _infer_origins_from_anonymization(anonymization, target),
                                "headers": fields.get("headers") or {},
                                "snippet": line.strip()[:500],
                            }
                        )
            except Exception as exc:
                msg = f"Failed to scan {path}: {exc}"
                logger.warning(msg)
                result["errors"].append(msg)
        result["network_log_matches"] = matches
        return result
    except Exception as exc:
        msg = f"Failed network log analysis for profile {profile_name}: {exc}"
        logger.error(msg)
        result["errors"].append(msg)
        return result
