from __future__ import annotations

from collections import Counter


def _first_last(summaries: list[dict]) -> tuple[str | None, str | None]:
    firsts = [item.get("first_seen_utc") for item in summaries if item.get("first_seen_utc")]
    lasts = [item.get("last_seen_utc") for item in summaries if item.get("last_seen_utc")]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def _unique(values):
    seen = set()
    output = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def probable_callers(context: dict) -> list[dict]:
    callers = []
    for item in context.get("network_log_matches", []) or []:
        evidence = f"{item.get('file')}:{item.get('line') or '-'}"
        source = item.get("source") or "network"
        for origin in item.get("inferred_origins_from_anonymization", []) or []:
            callers.append(
                {
                    "caller": origin,
                    "confidence": "high",
                    "method": "decoded anonymization payload",
                    "source": source,
                    "evidence": evidence,
                    "target_record": item.get("matched_server") or item.get("url"),
                }
            )
        for field in ("initiator", "referrer", "origin"):
            value = item.get(field)
            if value:
                callers.append(
                    {
                        "caller": value,
                        "confidence": "medium",
                        "method": field,
                        "source": source,
                        "evidence": evidence,
                        "target_record": item.get("matched_server") or item.get("url"),
                    }
                )

    counter = Counter((item["caller"], item["method"], item["source"]) for item in callers)
    collapsed = {}
    for item in callers:
        key = (item["caller"], item["method"], item["source"])
        if key not in collapsed:
            collapsed[key] = {**item, "count": counter[key]}
    return sorted(
        collapsed.values(),
        key=lambda item: (0 if item["confidence"] == "high" else 1, -item["count"], item["caller"]),
    )


def build_case_summary(context: dict) -> dict:
    summaries = context.get("history_summaries", []) or []
    first_seen, last_seen = _first_last(summaries)
    access_count = sum(item.get("access_count", 0) for item in summaries)
    callers = probable_callers(context)
    network_matches = context.get("network_log_matches", []) or []
    scan_summaries = context.get("network_scan_summaries", []) or []
    return {
        "target": context.get("target_raw"),
        "target_domain": context.get("target_domain"),
        "profiles": context.get("profiles", []),
        "first_seen_utc": first_seen,
        "last_seen_utc": last_seen,
        "access_count": access_count,
        "probable_callers": callers,
        "probable_caller_found": bool(callers),
        "network_match_count": len(network_matches),
        "history_match_count": len(context.get("visits_matches", []) or []),
        "cookie_match_count": len(context.get("cookies_matches", []) or []),
        "bookmark_match_count": len(context.get("bookmarks_matches", []) or []),
        "download_match_count": len(context.get("downloads_matches", []) or []),
        "network_files": _unique(item.get("file") for item in network_matches),
        "network_scan": {
            "primary_network_files_scanned": sum(
                item.get("primary_network_files_scanned", item.get("primary_tmp_files_scanned", 0))
                for item in scan_summaries
            ),
            "fallback_text_files_scanned": sum(item.get("fallback_text_files_scanned", 0) for item in scan_summaries),
            "primary_network_files_with_target": sum(
                item.get("primary_network_files_with_target", item.get("primary_tmp_files_with_target", 0))
                for item in scan_summaries
            ),
            "fallback_text_files_with_target": sum(item.get("fallback_text_files_with_target", 0) for item in scan_summaries),
            "files_with_target": _unique(
                file_path
                for item in scan_summaries
                for file_path in (item.get("files_with_target", []) or [])
            ),
        },
        "errors": context.get("errors", []) or [],
    }
