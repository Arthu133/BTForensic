from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .domain_utils import TargetInfo
from .safe_redaction import mask_url_query


MDE_MODE = "manual_advanced_hunting_export_no_api"

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SENSITIVE_ARGUMENT_RE = re.compile(
    r"(?i)(--?[\w-]*(?:token|session|auth|password|secret|key|code)[\w-]*(?:=|\s+))([^\s\"']+)"
)
_SENSITIVE_FIELD_PARTS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "session",
    "token",
    "apikey",
    "api_key",
)


def _escape_kql_string(value: str | None) -> str:
    return (value or "").replace("\\", "\\\\").replace('"', '\\"')


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_kql_datetime(value: datetime | None, fallback: str) -> str:
    if value is None:
        return fallback
    return f"datetime({value.strftime('%Y-%m-%dT%H:%M:%SZ')})"


def _history_time_bounds(history_summaries: list[dict], window_minutes: int) -> tuple[datetime | None, datetime | None]:
    first_values = [_parse_datetime(item.get("first_seen_utc")) for item in history_summaries or []]
    last_values = [_parse_datetime(item.get("last_seen_utc")) for item in history_summaries or []]
    first_values = [item for item in first_values if item]
    last_values = [item for item in last_values if item]
    if not first_values or not last_values:
        return None, None
    delta = timedelta(minutes=window_minutes)
    return min(first_values) - delta, max(last_values) + delta


def _mask_text(value: str) -> str:
    masked = _URL_RE.sub(lambda match: mask_url_query(match.group(0)) or match.group(0), value)
    return _SENSITIVE_ARGUMENT_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", masked)


def sanitize_mde_record(record: dict[str, Any]) -> dict[str, Any]:
    sanitized = {}
    for key, value in record.items():
        key_text = str(key)
        key_lower = key_text.lower()
        if any(part in key_lower for part in _SENSITIVE_FIELD_PARTS):
            sanitized[key_text] = "[REDACTED]"
        elif isinstance(value, str):
            sanitized[key_text] = _mask_text(value)
        else:
            sanitized[key_text] = value
    return sanitized


def _read_json_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("Results", "results", "value", "data", "rows"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    raise ValueError("JSON export must be a list of records or contain Results/value/data/rows.")


def _read_csv_records(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def load_defender_input(path: Path, target: TargetInfo) -> dict[str, Any]:
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Defender input file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        rows = _read_json_records(path)
        input_format = "json"
    else:
        rows = _read_csv_records(path)
        input_format = "csv"

    target_needles = [target.domain.lower()]
    if target.normalized_url:
        target_needles.append(target.normalized_url.lower())

    def row_matches(row: dict[str, Any]) -> bool:
        text = " ".join(str(value).lower() for value in row.values() if value is not None)
        return any(needle and needle in text for needle in target_needles)

    matching_rows = [row for row in rows if row_matches(row)]
    timestamps = [_parse_datetime(row.get("Timestamp") or row.get("TimeGenerated")) for row in rows]
    timestamps = [item for item in timestamps if item]

    def top_values(*fields: str, limit: int = 10) -> list[dict[str, Any]]:
        counter: Counter[str] = Counter()
        for row in rows:
            for field in fields:
                value = row.get(field)
                if value not in (None, ""):
                    counter[_mask_text(str(value))] += 1
                    break
        return [{"value": value, "count": count} for value, count in counter.most_common(limit)]

    sample_records = [sanitize_mde_record(row) for row in matching_rows[:25]]
    return {
        "mode": MDE_MODE,
        "source_file": str(path),
        "input_format": input_format,
        "total_rows": len(rows),
        "target_matching_rows": len(matching_rows),
        "first_timestamp_utc": min(timestamps).strftime("%Y-%m-%dT%H:%M:%SZ") if timestamps else None,
        "last_timestamp_utc": max(timestamps).strftime("%Y-%m-%dT%H:%M:%SZ") if timestamps else None,
        "top_devices": top_values("DeviceName", "DeviceId"),
        "top_accounts": top_values("InitiatingProcessAccountUpn", "InitiatingProcessAccountName", "AccountUpn", "AccountName"),
        "top_processes": top_values("InitiatingProcessFileName", "FileName", "ProcessName"),
        "top_parent_processes": top_values("InitiatingProcessParentFileName", "ParentProcessName"),
        "top_remote_urls": top_values("RemoteUrl", "Url", "RequestUrl"),
        "top_remote_ips": top_values("RemoteIP", "RemoteIp", "DestinationIp"),
        "top_action_types": top_values("ActionType"),
        "sample_matching_records": sample_records,
        "note": "Input was parsed from a manually exported Advanced Hunting result. No Defender API call was made.",
    }


def build_defender_kql(
    target: TargetInfo,
    history_summaries: list[dict] | None,
    window_minutes: int,
    device_name: str | None = None,
    account_name: str | None = None,
) -> str:
    start_time, end_time = _history_time_bounds(history_summaries or [], window_minutes)
    target_url = (target.normalized_url or target.raw) if target.is_url else ""
    target_url = target_url or ""
    start_literal = _format_kql_datetime(start_time, "datetime(START_TIME_UTC)")
    end_literal = _format_kql_datetime(end_time, "datetime(END_TIME_UTC)")
    window_literal = f"{max(window_minutes, 1)}m"

    variables = f"""// BTForensic Microsoft Defender for Endpoint Advanced Hunting pack
// Workflow: run the primary query, export the results as CSV or JSON, then pass the export with --defender-input.
// No API connection, token, or Defender credential is used by BTForensic.
let TargetDomain = "{_escape_kql_string(target.domain)}";
let TargetUrl = "{_escape_kql_string(target_url)}";
let StartTime = {start_literal};
let EndTime = {end_literal};
let Window = {window_literal};
let DeviceFilter = "{_escape_kql_string(device_name)}";
let AccountFilter = "{_escape_kql_string(account_name)}";
let BrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe"]);
"""

    return (
        variables
        + r"""

// 1. Primary input query for BTForensic
// Export this result and feed it back with: BTForensic ... --defender-input ".\mde_network_results.csv"
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceFilter == "" or DeviceName =~ DeviceFilter
| where AccountFilter == "" or InitiatingProcessAccountName =~ AccountFilter or InitiatingProcessAccountUpn =~ AccountFilter
| where RemoteUrl has TargetDomain
    or (TargetUrl != "" and RemoteUrl has TargetUrl)
    or InitiatingProcessCommandLine has TargetDomain
    or tostring(AdditionalFields) has TargetDomain
| where InitiatingProcessFileName in~ (BrowserProcesses)
    or InitiatingProcessCommandLine has_any ("chrome", "msedge", "brave", "chromium")
    or RemoteUrl has TargetDomain
| project Timestamp, DeviceName, DeviceId, ReportId, ActionType,
    InitiatingProcessAccountName, InitiatingProcessAccountUpn,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, InitiatingProcessParentCommandLine,
    RemoteUrl, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, AdditionalFields
| order by Timestamp asc;

// 2. Browser process tree near the target window
DeviceProcessEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceFilter == "" or DeviceName =~ DeviceFilter
| where AccountFilter == "" or AccountName =~ AccountFilter or AccountUpn =~ AccountFilter
| where FileName in~ (BrowserProcesses)
    or InitiatingProcessFileName in~ (BrowserProcesses)
    or ProcessCommandLine has TargetDomain
    or InitiatingProcessCommandLine has TargetDomain
| project Timestamp, DeviceName, DeviceId, AccountName, AccountUpn,
    FileName, ProcessCommandLine, ProcessId,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, InitiatingProcessParentCommandLine,
    SHA256, FolderPath, ActionType
| order by Timestamp asc;

// 3. File activity from browser processes near the target window
DeviceFileEvents
| where Timestamp between (StartTime .. EndTime)
| where DeviceFilter == "" or DeviceName =~ DeviceFilter
| where AccountFilter == "" or InitiatingProcessAccountName =~ AccountFilter or InitiatingProcessAccountUpn =~ AccountFilter
| where InitiatingProcessFileName in~ (BrowserProcesses)
    or InitiatingProcessCommandLine has TargetDomain
    or FolderPath has_any ("Downloads", ".crdownload")
| project Timestamp, DeviceName, DeviceId, ActionType, FolderPath, FileName,
    SHA256, PreviousFolderPath, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp asc;

// 4. Alerts and evidence on devices that contacted the target
let TargetDevices =
    DeviceNetworkEvents
    | where Timestamp between (StartTime .. EndTime)
    | where RemoteUrl has TargetDomain or (TargetUrl != "" and RemoteUrl has TargetUrl)
    | distinct DeviceId;
AlertEvidence
| where Timestamp between (StartTime .. EndTime)
| where DeviceId in (TargetDevices)
    or RemoteUrl has TargetDomain
| join kind=leftouter (
    AlertInfo
    | project AlertId, Title, Severity, Category, DetectionSource, ServiceSource, AttackTechniques
) on AlertId
| project Timestamp, AlertId, Title, Severity, Category, DetectionSource,
    DeviceName, DeviceId, EntityType, EvidenceRole, FileName, FolderPath,
    SHA256, RemoteUrl, RemoteIP, AccountName, AccountSid, AttackTechniques
| order by Timestamp asc;

// 5. Logons on devices that contacted the target
let TargetDeviceNames =
    DeviceNetworkEvents
    | where Timestamp between (StartTime .. EndTime)
    | where RemoteUrl has TargetDomain or (TargetUrl != "" and RemoteUrl has TargetUrl)
    | distinct DeviceName;
DeviceLogonEvents
| where Timestamp between ((StartTime - Window) .. (EndTime + Window))
| where DeviceName in (TargetDeviceNames)
| project Timestamp, DeviceName, AccountName, AccountUpn, LogonType,
    ActionType, FailureReason, RemoteDeviceName, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc;

// 6. Same target across other endpoints
DeviceNetworkEvents
| where Timestamp between (StartTime .. EndTime)
| where RemoteUrl has TargetDomain or (TargetUrl != "" and RemoteUrl has TargetUrl)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Devices=dcount(DeviceId), DeviceNames=make_set(DeviceName, 50),
    Accounts=make_set(InitiatingProcessAccountName, 50),
    Processes=make_set(InitiatingProcessFileName, 50),
    RemoteIPs=make_set(RemoteIP, 50),
    Count=count()
    by RemoteUrl
| order by Count desc;

// 7. Endpoint telemetry around each browser network hit
let BrowserHits =
    DeviceNetworkEvents
    | where Timestamp between (StartTime .. EndTime)
    | where RemoteUrl has TargetDomain or (TargetUrl != "" and RemoteUrl has TargetUrl)
    | project DeviceId, DeviceName, HitTime=Timestamp, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine;
DeviceEvents
| join kind=inner BrowserHits on DeviceId
| where Timestamp between ((HitTime - Window) .. (HitTime + Window))
| project Timestamp, DeviceName, ActionType, RemoteUrl, HitTime,
    InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by HitTime asc, Timestamp asc;
"""
    )


def build_defender_context(
    target: TargetInfo,
    history_summaries: list[dict] | None,
    window_minutes: int,
    input_path: str | None = None,
    device_name: str | None = None,
    account_name: str | None = None,
) -> dict[str, Any]:
    summary = load_defender_input(Path(input_path), target) if input_path else None
    kql = build_defender_kql(target, history_summaries, window_minutes, device_name, account_name)
    return {
        "mode": MDE_MODE,
        "input_summary": summary,
        "kql_queries": kql,
        "kql_filters": {
            "device_name": device_name,
            "account_name": account_name,
            "window_minutes": window_minutes,
        },
    }
