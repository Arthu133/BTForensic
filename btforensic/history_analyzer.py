from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path

from .domain_utils import TargetInfo, extract_host, relation_kind, url_matches_target
from .safe_redaction import mask_url_query
from .sqlite_exporter import copied_sqlite_connection, export_table, rows_to_dicts, table_exists
from .timestamp_utils import chrome_time_to_datetime, chrome_time_to_iso_local, chrome_time_to_iso_utc


def _visit_row(row: dict, profile: str, target: TargetInfo) -> dict:
    return {
        "profile": profile,
        "url_id": row.get("url_id"),
        "visit_id": row.get("visit_id"),
        "url": mask_url_query(row.get("url")),
        "title": row.get("title"),
        "visit_time": row.get("visit_time"),
        "visit_time_utc": chrome_time_to_iso_utc(row.get("visit_time")),
        "visit_time_local": chrome_time_to_iso_local(row.get("visit_time")),
        "from_visit": row.get("from_visit"),
        "transition": row.get("transition"),
        "typed_count": row.get("typed_count"),
        "visit_count": row.get("visit_count"),
        "last_visit_time": row.get("last_visit_time"),
        "last_visit_time_utc": chrome_time_to_iso_utc(row.get("last_visit_time")),
        "relation": relation_kind(row.get("url"), target),
    }


def analyze_history(profile_name: str, profile_path: Path, target: TargetInfo, window_minutes: int, logger: logging.Logger) -> dict:
    db_path = profile_path / "History"
    empty = {
        "history_matches": [],
        "visits_matches": [],
        "related_urls": [],
        "windows": [],
        "summary": {},
        "raw_urls": [],
        "raw_visits": [],
        "errors": [],
    }
    if not db_path.exists():
        msg = f"History not found for profile {profile_name}"
        logger.warning(msg)
        empty["errors"].append(msg)
        return empty

    try:
        with copied_sqlite_connection(db_path) as conn:
            raw_urls = export_table(conn, "urls")
            raw_visits = export_table(conn, "visits")
            empty["raw_urls"] = [{"profile": profile_name, **row} for row in raw_urls]
            empty["raw_visits"] = [{"profile": profile_name, **row} for row in raw_visits]

            if not (table_exists(conn, "urls") and table_exists(conn, "visits")):
                msg = f"History database missing urls or visits table for profile {profile_name}"
                logger.warning(msg)
                empty["errors"].append(msg)
                return empty

            rows = rows_to_dicts(
                conn.execute(
                    """
                    SELECT
                      urls.id AS url_id,
                      visits.id AS visit_id,
                      urls.url,
                      urls.title,
                      urls.visit_count,
                      urls.typed_count,
                      urls.last_visit_time,
                      visits.visit_time,
                      visits.from_visit,
                      visits.transition
                    FROM visits
                    JOIN urls ON visits.url = urls.id
                    WHERE urls.url LIKE ?
                    ORDER BY visits.visit_time
                    """,
                    (f"%{target.domain}%",),
                ).fetchall()
            )
            matched = [_visit_row(row, profile_name, target) for row in rows if url_matches_target(row.get("url"), target)]

            visit_times = [chrome_time_to_datetime(row.get("visit_time")) for row in matched]
            visit_times = [dt for dt in visit_times if dt is not None]
            windows = []
            related = []
            if visit_times:
                delta = timedelta(minutes=window_minutes)
                min_dt = min(visit_times) - delta
                max_dt = max(visit_times) + delta
                windows.append({"start_utc": min_dt.isoformat().replace("+00:00", "Z"), "end_utc": max_dt.isoformat().replace("+00:00", "Z")})
                min_chrome = int((min_dt - chrome_time_to_datetime(1)).total_seconds() * 1_000_000) + 1
                max_chrome = int((max_dt - chrome_time_to_datetime(1)).total_seconds() * 1_000_000) + 1
                related_rows = rows_to_dicts(
                    conn.execute(
                        """
                        SELECT
                          urls.id AS url_id,
                          visits.id AS visit_id,
                          urls.url,
                          urls.title,
                          urls.visit_count,
                          urls.typed_count,
                          urls.last_visit_time,
                          visits.visit_time,
                          visits.from_visit,
                          visits.transition
                        FROM visits
                        JOIN urls ON visits.url = urls.id
                        WHERE visits.visit_time BETWEEN ? AND ?
                        ORDER BY visits.visit_time
                        """,
                        (min_chrome, max_chrome),
                    ).fetchall()
                )
                related = [
                    {
                        **_visit_row(row, profile_name, target),
                        "host": extract_host(row.get("url")),
                        "is_target": url_matches_target(row.get("url"), target),
                    }
                    for row in related_rows
                ]

            first = min(visit_times).isoformat().replace("+00:00", "Z") if visit_times else None
            last = max(visit_times).isoformat().replace("+00:00", "Z") if visit_times else None
            summary = {
                "profile": profile_name,
                "first_seen_utc": first,
                "last_seen_utc": last,
                "access_count": len(matched),
                "titles": sorted({row.get("title") for row in matched if row.get("title")}),
                "unique_urls": sorted({row.get("url") for row in matched if row.get("url")}),
            }
            history_matches = []
            for row in matched:
                url = row.get("url")
                if not any(item.get("url") == url for item in history_matches):
                    history_matches.append(
                        {
                            "profile": profile_name,
                            "url": url,
                            "title": row.get("title"),
                            "typed_count": row.get("typed_count"),
                            "visit_count": row.get("visit_count"),
                            "last_visit_time_utc": row.get("last_visit_time_utc"),
                            "relation": row.get("relation"),
                        }
                    )
            return {
                "history_matches": history_matches,
                "visits_matches": matched,
                "related_urls": related,
                "windows": windows,
                "summary": summary,
                "raw_urls": empty["raw_urls"],
                "raw_visits": empty["raw_visits"],
                "errors": [],
            }
    except Exception as exc:
        msg = f"Failed to analyze History for profile {profile_name}: {exc}"
        logger.error(msg)
        empty["errors"].append(msg)
        return empty
