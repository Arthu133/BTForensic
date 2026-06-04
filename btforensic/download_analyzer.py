from __future__ import annotations

import logging
from pathlib import Path

from .domain_utils import TargetInfo, url_matches_target
from .safe_redaction import mask_url_query
from .sqlite_exporter import copied_sqlite_connection, get_columns, rows_to_dicts, table_exists
from .timestamp_utils import chrome_time_to_datetime, chrome_time_to_iso_local, chrome_time_to_iso_utc


def _in_windows(chrome_time, windows: list[tuple]) -> bool:
    dt = chrome_time_to_datetime(chrome_time)
    if not dt:
        return False
    return any(start <= dt <= end for start, end in windows)


def analyze_downloads(profile_name: str, profile_path: Path, target: TargetInfo, windows: list[tuple], logger: logging.Logger) -> dict:
    result = {"downloads_matches": [], "errors": []}
    db_path = profile_path / "History"
    if not db_path.exists():
        msg = f"History not found for download analysis in profile {profile_name}"
        logger.warning(msg)
        result["errors"].append(msg)
        return result

    try:
        with copied_sqlite_connection(db_path) as conn:
            if not table_exists(conn, "downloads"):
                msg = f"downloads table not found for profile {profile_name}"
                logger.warning(msg)
                result["errors"].append(msg)
                return result

            columns = get_columns(conn, "downloads")
            select_cols = ", ".join(columns)
            downloads = rows_to_dicts(conn.execute(f"SELECT {select_cols} FROM downloads").fetchall())
            chains = {}
            if table_exists(conn, "downloads_url_chains"):
                for row in rows_to_dicts(conn.execute("SELECT * FROM downloads_url_chains ORDER BY id, chain_index").fetchall()):
                    chains.setdefault(row.get("id"), []).append(row.get("url"))

            matches = []
            for row in downloads:
                urls = [row.get("tab_url"), row.get("site_url"), row.get("referrer"), row.get("url")] + chains.get(row.get("id"), [])
                urls = [url for url in urls if url]
                direct = any(url_matches_target(url, target) for url in urls)
                time_related = _in_windows(row.get("start_time"), windows)
                if not (direct or time_related):
                    continue
                matches.append(
                    {
                        "profile": profile_name,
                        "id": row.get("id"),
                        "relation": "target_url_or_domain" if direct else "within_target_time_window",
                        "source_urls": [mask_url_query(url) for url in urls],
                        "local_path": row.get("target_path") or row.get("current_path"),
                        "start_time": row.get("start_time"),
                        "start_time_utc": chrome_time_to_iso_utc(row.get("start_time")),
                        "start_time_local": chrome_time_to_iso_local(row.get("start_time")),
                        "received_bytes": row.get("received_bytes"),
                        "total_bytes": row.get("total_bytes"),
                        "state": row.get("state"),
                        "danger_type": row.get("danger_type"),
                    }
                )
            result["downloads_matches"] = matches
            return result
    except Exception as exc:
        msg = f"Failed to analyze Downloads for profile {profile_name}: {exc}"
        logger.error(msg)
        result["errors"].append(msg)
        return result
