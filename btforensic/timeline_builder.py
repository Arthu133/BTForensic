from __future__ import annotations

from datetime import datetime, timezone

from .timestamp_utils import chrome_time_to_iso_utc


def _event(event_type: str, timestamp: str | None, profile: str | None, description: str, data: dict) -> dict:
    return {
        "type": event_type,
        "timestamp_utc": timestamp,
        "profile": profile,
        "description": description,
        "data": data,
    }


def _sort_key(item: dict):
    ts = item.get("timestamp_utc")
    if not ts:
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.max.replace(tzinfo=timezone.utc)


def build_timeline(
    visits: list[dict],
    cookies: list[dict],
    bookmarks: list[dict],
    downloads: list[dict],
    network_matches: list[dict],
    origins: dict,
) -> list[dict]:
    events = []
    for row in visits:
        events.append(_event("visit", row.get("visit_time_utc"), row.get("profile"), f"Visited {row.get('url')}", row))
    for row in cookies:
        events.append(_event("cookie_created", row.get("creation_utc_iso"), row.get("profile"), f"Cookie created: {row.get('host_key')} {row.get('name')}", row))
        events.append(_event("cookie_accessed", row.get("last_access_utc_iso"), row.get("profile"), f"Cookie accessed: {row.get('host_key')} {row.get('name')}", row))
    for row in bookmarks:
        events.append(_event("bookmark_created", row.get("date_added_utc"), row.get("profile"), f"Bookmark created: {row.get('name')}", row))
    for row in downloads:
        events.append(_event("download_started", row.get("start_time_utc"), row.get("profile"), f"Download started: {row.get('local_path')}", row))
    for row in network_matches:
        timestamp = row.get("timestamp")
        if isinstance(timestamp, int) or (isinstance(timestamp, str) and timestamp.isdigit()):
            timestamp = chrome_time_to_iso_utc(timestamp)
        events.append(_event("network_log_match", timestamp, row.get("profile"), f"Network log match in {row.get('file')}", row))
    for row in origins.get("records_calling_target", []):
        events.append(_event("origin_referrer_event", row.get("timestamp"), row.get("profile"), "Origin/referrer/initiator related to target", row))
    return sorted([event for event in events if event.get("timestamp_utc")], key=_sort_key)
