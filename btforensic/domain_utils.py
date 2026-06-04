from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class TargetInfo:
    raw: str
    domain: str
    normalized_url: str | None
    path: str | None
    is_url: bool


def _parse_with_default_scheme(value: str):
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return urlparse(candidate)


def normalize_host(host: str | None) -> str:
    if not host:
        return ""
    host = host.strip().lower().rstrip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        return host[4:]
    return host


def normalize_target(raw_target: str) -> TargetInfo:
    raw_target = raw_target.strip()
    parsed = _parse_with_default_scheme(raw_target)
    domain = normalize_host(parsed.hostname or parsed.netloc or raw_target.split("/", 1)[0])
    path = parsed.path or None
    is_url = bool(path and path != "/") or "://" in raw_target
    normalized_url = None
    if is_url and domain:
        scheme = parsed.scheme or "https"
        normalized_url = f"{scheme}://{parsed.netloc.lower()}{parsed.path or ''}"
        if parsed.query:
            normalized_url += f"?{parsed.query}"
    return TargetInfo(
        raw=raw_target,
        domain=domain,
        normalized_url=normalized_url,
        path=path,
        is_url=is_url,
    )


def host_matches_domain(host: str | None, target_domain: str) -> bool:
    host_norm = normalize_host(host)
    target_norm = normalize_host(target_domain)
    return bool(host_norm and target_norm and (host_norm == target_norm or host_norm.endswith(f".{target_norm}")))


def extract_host(url: str | None) -> str:
    if not url:
        return ""
    parsed = _parse_with_default_scheme(url)
    return normalize_host(parsed.hostname or "")


def url_matches_target(url: str | None, target: TargetInfo) -> bool:
    if not url:
        return False
    parsed = _parse_with_default_scheme(url)
    host = normalize_host(parsed.hostname)
    if not host_matches_domain(host, target.domain):
        return False
    if target.is_url and target.path:
        target_path = target.path.rstrip("/")
        current_path = (parsed.path or "").rstrip("/")
        if current_path == target_path:
            return True
        return current_path.startswith(f"{target_path}/")
    return True


def relation_kind(url: str | None, target: TargetInfo) -> str:
    if not url_matches_target(url, target):
        return "unrelated"
    if target.is_url and target.normalized_url:
        parsed_url = _parse_with_default_scheme(url or "")
        parsed_target = _parse_with_default_scheme(target.normalized_url)
        if (
            normalize_host(parsed_url.hostname) == normalize_host(parsed_target.hostname)
            and (parsed_url.path or "/").rstrip("/") == (parsed_target.path or "/").rstrip("/")
        ):
            return "target_url"
    return "target_domain"
