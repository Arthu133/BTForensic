from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


PRIVACY_STRICT = "strict"
PRIVACY_STANDARD = "standard"
PRIVACY_CHOICES = (PRIVACY_STRICT, PRIVACY_STANDARD)
REDACTED_STRICT = "[REDACTED_BY_PRIVACY_STRICT]"

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

SENSITIVE_FIELD_NAMES = {
    "access_token",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "cookie",
    "encrypted_value",
    "password",
    "proxy_authorization",
    "refresh_token",
    "secret",
    "session",
    "set_cookie",
    "token",
    "value",
}

IDENTITY_FIELD_PARTS = (
    "account_name",
    "account_sid",
    "account_upn",
    "accountname",
    "accountsid",
    "accountupn",
    "device_id",
    "device_name",
    "deviceid",
    "devicename",
    "initiatingprocessaccount",
)

PATH_FIELD_PARTS = (
    "current_path",
    "filepath",
    "folderpath",
    "folder_path",
    "local_path",
    "previousfolderpath",
    "profile_path",
    "source_file",
    "target_path",
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:\\|\\\\)[^\r\n\"'<>|]+"
)
POSIX_PATH_RE = re.compile(
    r"(?:(?:/home|/users|/mnt|/media|/tmp|/var/tmp)/[^\r\n\"'<>]+)"
)
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(jwt|token|session|sessionid|sid|auth|password|passwd|secret|api[_-]?key|code)\s*[:=]\s*[^\s\"'&,;]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)

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


def _short_hash(value: str | bytes | None) -> str:
    return (sha256_value(value) or "0" * 64)[:12]


def _key_name(key: str | None) -> str:
    return str(key or "").lower().replace("-", "_").replace(" ", "_")


def is_identity_key(key: str | None) -> bool:
    key_norm = _key_name(key)
    return any(part in key_norm for part in IDENTITY_FIELD_PARTS)


def is_path_key(key: str | None) -> bool:
    key_norm = _key_name(key)
    return key_norm in {"file", "path"} or any(part in key_norm for part in PATH_FIELD_PARTS)


def looks_like_local_path(value: str | None) -> bool:
    if not value:
        return False
    text = str(value)
    return bool(WINDOWS_PATH_RE.search(text) or POSIX_PATH_RE.search(text))


def should_redact_path_value(key: str | None, value: str | None) -> bool:
    key_norm = _key_name(key)
    if any(part in key_norm for part in PATH_FIELD_PARTS):
        return True
    if key_norm in {"file", "path"}:
        return looks_like_local_path(value)
    return False


def redact_identity_value(value: str | None, label: str = "IDENTITY") -> str | None:
    if value in (None, ""):
        return value
    if str(value).startswith(f"[{label.upper()}_REDACTED:"):
        return str(value)
    return f"[{label.upper()}_REDACTED:{_short_hash(str(value))}]"


def redact_local_path(value: str | None) -> str | None:
    if value in (None, ""):
        return value
    text = str(value)
    if text.startswith("[LOCAL_PATH_REDACTED:"):
        return text
    trimmed = text.rstrip("\\/")
    name = re.split(r"[\\/]", trimmed)[-1] if trimmed else ""
    if not name or name == trimmed:
        return f"[LOCAL_PATH_REDACTED:{_short_hash(text)}]"
    if re.search(r"\s|https?://|\[REDACTED\]", name, re.IGNORECASE):
        return f"[LOCAL_PATH_REDACTED:{_short_hash(text)}]"
    return f"[LOCAL_PATH_REDACTED:{_short_hash(text)}]\\{name}"


def redact_paths_in_text(text: str) -> str:
    text = WINDOWS_PATH_RE.sub(lambda match: redact_local_path(match.group(0)) or REDACTED_STRICT, text)
    return POSIX_PATH_RE.sub(lambda match: redact_local_path(match.group(0)) or REDACTED_STRICT, text)


def redact_sensitive_text(text: str | None, redact_paths: bool = False) -> str | None:
    if text is None:
        return text
    redacted = str(text)
    protected_urls = []

    def protect_url(match):
        protected_urls.append(mask_url_query(match.group(0)) or match.group(0))
        return f"__BTF_URL_{len(protected_urls) - 1}__"

    redacted = URL_RE.sub(protect_url, redacted)
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)} [REDACTED]" if pattern.pattern.startswith("(?i)\\b(bearer") else "[REDACTED]", redacted)
    if redact_paths:
        redacted = redact_paths_in_text(redacted)
    for index, url in enumerate(protected_urls):
        redacted = redacted.replace(f"__BTF_URL_{index}__", url)
    return redacted


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


def sanitize_for_privacy(value, privacy: str = PRIVACY_STRICT, key: str | None = None):
    key_norm = _key_name(key)
    strict = privacy == PRIVACY_STRICT
    if isinstance(value, bytes):
        return {
            "redacted_bytes": True,
            "size": len(value),
            "sha256": sha256_value(value),
        }
    if isinstance(value, list):
        return [sanitize_for_privacy(item, privacy=privacy, key=key) for item in value]
    if isinstance(value, dict):
        sanitized = {}
        is_counter_item = set(value.keys()) == {"value", "count"}
        for child_key, item in value.items():
            child_key_norm = _key_name(child_key)
            if child_key_norm in {"headers", "request_headers", "response_headers"} and isinstance(item, dict):
                sanitized[child_key] = redact_headers(item)
            elif child_key_norm == "snippet" and strict:
                sanitized[child_key] = REDACTED_STRICT
            elif child_key_norm in SENSITIVE_FIELD_NAMES and not (is_counter_item and child_key_norm == "value"):
                sanitized[child_key] = "[REDACTED]"
            elif strict and is_identity_key(child_key) and isinstance(item, str):
                label = "DEVICE" if "device" in child_key_norm else "ACCOUNT"
                sanitized[child_key] = redact_identity_value(item, label)
            elif strict and should_redact_path_value(child_key, item) and isinstance(item, str):
                sanitized[child_key] = redact_local_path(item)
            else:
                sanitized[child_key] = sanitize_for_privacy(item, privacy=privacy, key=str(child_key))
        return sanitized
    if isinstance(value, str):
        if strict and is_identity_key(key):
            label = "DEVICE" if "device" in key_norm else "ACCOUNT"
            return redact_identity_value(value, label)
        if strict and should_redact_path_value(key, value):
            return redact_local_path(value)
        return redact_sensitive_text(value, redact_paths=strict)
    return value


def safe_cookie_record(row: dict) -> dict:
    value = row.get("value")
    encrypted_value = row.get("encrypted_value")
    hash_source = value if value not in (None, "", b"") else encrypted_value
    value_hash = sha256_value(hash_source)
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
        "value_hash_source": "value" if value not in (None, "", b"") else "encrypted_value",
    }
