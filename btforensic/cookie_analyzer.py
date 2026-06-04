from __future__ import annotations

import logging
from pathlib import Path

from .domain_utils import TargetInfo, host_matches_domain
from .safe_redaction import safe_cookie_record
from .sqlite_exporter import copied_sqlite_connection, export_table, rows_to_dicts, table_exists
from .timestamp_utils import chrome_time_to_iso_local, chrome_time_to_iso_utc


def _cookie_db(profile_path: Path) -> Path | None:
    for candidate in (profile_path / "Network" / "Cookies", profile_path / "Cookies"):
        if candidate.exists():
            return candidate
    return None


def _safe_record(row: dict, profile: str, relation: str) -> dict:
    record = safe_cookie_record(row)
    record.update(
        {
            "profile": profile,
            "relation": relation,
            "creation_utc_iso": chrome_time_to_iso_utc(record.get("creation_utc")),
            "creation_local_iso": chrome_time_to_iso_local(record.get("creation_utc")),
            "expires_utc_iso": chrome_time_to_iso_utc(record.get("expires_utc")),
            "last_access_utc_iso": chrome_time_to_iso_utc(record.get("last_access_utc")),
        }
    )
    return record


def analyze_cookies(profile_name: str, profile_path: Path, target: TargetInfo, related_hosts: set[str], logger: logging.Logger) -> dict:
    db_path = _cookie_db(profile_path)
    result = {"cookies_matches": [], "raw_cookies": [], "errors": []}
    if not db_path:
        msg = f"Cookies database not found for profile {profile_name}"
        logger.warning(msg)
        result["errors"].append(msg)
        return result

    try:
        with copied_sqlite_connection(db_path) as conn:
            if not table_exists(conn, "cookies"):
                msg = f"Cookies table not found for profile {profile_name}"
                logger.warning(msg)
                result["errors"].append(msg)
                return result
            raw = export_table(conn, "cookies")
            result["raw_cookies"] = [
                {"profile": profile_name, **safe_cookie_record(row)}
                for row in raw
            ]
            rows = rows_to_dicts(conn.execute("SELECT * FROM cookies").fetchall())
            matches = []
            for row in rows:
                host = row.get("host_key", "").lstrip(".")
                if host_matches_domain(host, target.domain):
                    matches.append(_safe_record(row, profile_name, "target_domain"))
                elif host in related_hosts:
                    matches.append(_safe_record(row, profile_name, "third_party_in_time_window"))
            result["cookies_matches"] = matches
            return result
    except Exception as exc:
        msg = f"Failed to analyze Cookies for profile {profile_name}: {exc}"
        logger.error(msg)
        result["errors"].append(msg)
        return result
