from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "code",
    "key",
    "password",
    "refresh_token",
    "secret",
    "session",
    "sessionid",
    "sid",
    "token",
}


def sha256_value(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.encode("utf-8", errors="replace")
    return hashlib.sha256(value).hexdigest()


def redact_headers(headers: dict | None) -> dict:
    if not headers:
        return {}
    redacted = {}
    for key, value in headers.items():
        if str(key).lower() in SENSITIVE_HEADERS or any(part in str(key).lower() for part in ("token", "secret")):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def mask_url_query(url: str | None) -> str | None:
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.query:
        return url
    masked = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS or any(word in key.lower() for word in ("token", "session", "auth", "password")):
            masked.append((key, "[REDACTED]"))
        else:
            masked.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(masked)))


def safe_cookie_record(row: dict) -> dict:
    value = row.get("value")
    encrypted_value = row.get("encrypted_value")
    value_hash = sha256_value(value if value not in (None, "") else encrypted_value)
    return {
        "host_key": row.get("host_key"),
        "name": row.get("name"),
        "path": row.get("path"),
        "creation_utc": row.get("creation_utc"),
        "expires_utc": row.get("expires_utc"),
        "last_access_utc": row.get("last_access_utc"),
        "is_secure": row.get("is_secure"),
        "is_httponly": row.get("is_httponly"),
        "samesite": row.get("samesite"),
        "source_scheme": row.get("source_scheme"),
        "value_sha256": value_hash,
    }
