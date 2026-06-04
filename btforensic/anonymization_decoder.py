from __future__ import annotations

import base64
import json
import re
from urllib.parse import unquote


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


def decode_anonymization_payload(value: str | None) -> dict:
    original = value or ""
    candidates = []
    if not original:
        return {"original": original, "decoded": [], "detected": []}

    url_decoded = unquote(original)
    if url_decoded != original:
        candidates.append(("url_encoding", url_decoded))

    json_unescaped = _try_json_unescape(original)
    if json_unescaped:
        candidates.append(("json_escaped", json_unescaped))

    base64_decoded = _try_base64(original)
    if base64_decoded:
        candidates.append(("base64", base64_decoded))

    detected = []
    decoded = []
    seen = set()
    for kind, text in candidates:
        if text in seen:
            continue
        seen.add(text)
        detected.append(kind)
        decoded.append(text)

    return {"original": original, "decoded": decoded, "detected": detected}
