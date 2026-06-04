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


def _select_string_command(network_dir: Path, target: TargetInfo) -> str:
    pattern = target.normalized_url or target.raw or target.domain
    return f'Select-String -Path "{network_dir}\\*.tmp" -Pattern "{pattern}" -List | % Path'


def _candidate_files(profile_path: Path):
    seen = set()

    primary_network_dirs = [profile_path / "Network"]
    user_data_network_dir = profile_path.parent / "Network"
    if user_data_network_dir not in primary_network_dirs:
        primary_network_dirs.append(user_data_network_dir)

    for network_dir in primary_network_dirs:
        if not network_dir.exists():
            continue
        for path in sorted(network_dir.glob("*.tmp")):
            if path.is_file() and path.stat().st_size <= MAX_FILE_SIZE:
                seen.add(path)
                yield path, "primary_network_tmp_select_string", network_dir

    bases = [profile_path]
    bases.extend(profile_path / name for name in SCAN_DIRS if (profile_path / name).exists())
    for base in bases:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            if path.suffix.lower() in TEXT_EXTENSIONS and path.stat().st_size <= MAX_FILE_SIZE:
                yield path, "fallback_text_artifact_scan", None


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


def _load_json_lenient(raw: str):
    cleaned = raw.strip().strip("\x00")
    try:
        return json.loads(cleaned)
    except Exception:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(cleaned[start:end + 1])
            except Exception:
                return None
    return None


def _server_matches_target(server: str | None, target: TargetInfo) -> bool:
    if not server:
        return False
    return url_matches_target(server, target) or target.domain.lower() in server.lower()


def _walk_anonymization_values(obj, path: str = ""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else str(key)
            key_lower = str(key).lower()
            if ("anonymization" in key_lower or "isolation" in key_lower) and isinstance(value, str):
                yield current_path, value
            yield from _walk_anonymization_values(value, current_path)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk_anonymization_values(value, f"{path}[{index}]")


def _http_server_property_matches(
    profile_name: str,
    path: Path,
    raw: str,
    target: TargetInfo,
    discovery_method: str,
    select_string_equivalent: str | None,
) -> list[dict]:
    obj = _load_json_lenient(raw)
    if not isinstance(obj, dict):
        return []

    servers = (
        obj.get("net", {})
        .get("http_server_properties", {})
        .get("servers", [])
    )
    if not isinstance(servers, list):
        return []

    matches = []
    for index, server_obj in enumerate(servers):
        if not isinstance(server_obj, dict):
            continue
        server = server_obj.get("server")
        if not _server_matches_target(server, target):
            continue

        anonymization = []
        for field_path, value in _walk_anonymization_values(server_obj):
            decoded = decode_anonymization_payload(unquote(value))
            anonymization.append({"field": field_path, **_safe_decoded_items(decoded)})

        matches.append(
            {
                "profile": profile_name,
                "file": str(path),
                "discovery_method": discovery_method,
                "select_string_equivalent": select_string_equivalent,
                "line": None,
                "source": "net.http_server_properties.servers",
                "jq_filter_equivalent": '.net.http_server_properties.servers[] | select(.server|test("TARGET"))',
                "server_index": index,
                "matched_server": mask_url_query(server),
                "url": mask_url_query(server),
                "origin": None,
                "referrer": None,
                "initiator": None,
                "method": None,
                "status_code": None,
                "timestamp": None,
                "anonymization": anonymization,
                "anonymization_urls": _flatten_anonymization_urls(anonymization),
                "inferred_origins_from_anonymization": _infer_origins_from_anonymization(anonymization, target),
                "headers": {},
                "snippet": json.dumps({"server": server, "keys": sorted(server_obj.keys())}, ensure_ascii=False)[:500],
            }
        )
    return matches


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
        for path, discovery_method, network_dir in _candidate_files(profile_path):
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
                if not any(text and text in raw.lower() for text in target_texts):
                    continue

                select_string_equivalent = (
                    _select_string_command(network_dir, target)
                    if discovery_method == "primary_network_tmp_select_string" and network_dir is not None
                    else None
                )

                matches.extend(
                    _http_server_property_matches(
                        profile_name,
                        path,
                        raw,
                        target,
                        discovery_method,
                        select_string_equivalent,
                    )
                )

                for line_no, line in enumerate(raw.splitlines(), start=1):
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
                            "discovery_method": discovery_method,
                            "select_string_equivalent": select_string_equivalent,
                            "line": line_no,
                            "source": "text_match",
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
