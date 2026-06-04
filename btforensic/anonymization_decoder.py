from __future__ import annotations

import base64
import json
import re
from urllib.parse import unquote, urlparse


URL_RE = re.compile(r"https?://[^\s\"'<>\\,)]+", re.IGNORECASE)


def _try_json_unescape(value: str) -> str | None:
    try:
        decoded = json.loads(f'"{value}"')
    except Exception:
        return None
    return decoded if decoded != value else None


def _try_base64(value: str) -> str | None:
    compact = value.strip()
    if not compact or len(compact) % 4 not in (0, 2, 3):
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    padded = compact + "=" * (-len(compact) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        text = raw.decode("utf-8")
    except Exception:
        return None
    if not text or sum(ch.isprintable() for ch in text) / max(len(text), 1) < 0.85:
        return None
    return text


def _extract_urls(values: list[str]) -> list[str]:
    found = []
    seen = set()
    for value in values:
        for match in URL_RE.finditer(value):
            url = match.group(0).rstrip(".,;]")
            if url not in seen:
                seen.add(url)
                found.append(url)
    return found


def _extract_domains(urls: list[str]) -> list[str]:
    domains = []
    seen = set()
    for url in urls:
        host = urlparse(url).hostname
        if host and host not in seen:
            seen.add(host)
            domains.append(host)
    return domains


def _decode_once(value: str) -> list[tuple[str, str]]:
    candidates = []
    url_decoded = unquote(value)
    if url_decoded != value:
        candidates.append(("url_encoding", url_decoded))

    json_unescaped = _try_json_unescape(value)
    if json_unescaped:
        candidates.append(("json_escaped", json_unescaped))

    base64_decoded = _try_base64(value)
    if base64_decoded:
        candidates.append(("base64", base64_decoded))
    return candidates


def decode_anonymization_payload(value: str | None) -> dict:
    original = value or ""
    if not original:
        return {"original": original, "decoded": [], "detected": [], "extracted_urls": [], "extracted_domains": []}

    detected = []
    decoded = []
    seen_values = {original}
    queue = [original]
    for _ in range(3):
        if not queue:
            break
        current = queue.pop(0)
        for kind, text in _decode_once(current):
            if text in seen_values:
                continue
            seen_values.add(text)
            queue.append(text)
            if kind not in detected:
                detected.append(kind)
            decoded.append(text)

    urls = _extract_urls([original, *decoded])
    domains = _extract_domains(urls)

    return {
        "original": original,
        "decoded": decoded,
        "detected": detected,
        "extracted_urls": urls,
        "extracted_domains": domains,
    }
