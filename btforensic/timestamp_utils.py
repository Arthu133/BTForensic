from __future__ import annotations

from datetime import datetime, timezone, timedelta


CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_time_to_datetime(value: int | str | None) -> datetime | None:
    """Convert Chrome/WebKit microseconds since 1601-01-01 UTC to datetime."""
    if value in (None, "", 0, "0"):
        return None
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    return CHROME_EPOCH + timedelta(microseconds=micros)


def chrome_time_to_iso_utc(value: int | str | None) -> str | None:
    dt = chrome_time_to_datetime(value)
    if not dt:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def chrome_time_to_iso_local(value: int | str | None) -> str | None:
    dt = chrome_time_to_datetime(value)
    if not dt:
        return None
    return dt.astimezone().isoformat()


def iso_from_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
