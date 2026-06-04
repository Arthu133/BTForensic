from __future__ import annotations

from pathlib import Path

from .summary_builder import build_case_summary


def _count(items) -> int:
    return len(items or [])


def _first_last(summaries: list[dict]) -> tuple[str | None, str | None]:
    firsts = [item.get("first_seen_utc") for item in summaries if item.get("first_seen_utc")]
    lasts = [item.get("last_seen_utc") for item in summaries if item.get("last_seen_utc")]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def write_report(output_path: Path, context: dict) -> None:
    case_summary = build_case_summary(context)
    summaries = context.get("history_summaries", [])
    first_seen, last_seen = _first_last(summaries)
    access_count = sum(item.get("access_count", 0) for item in summaries)
    errors = context.get("errors", [])
    profiles = ", ".join(context.get("profiles", [])) or "None"
    origins = context.get("origins_and_referrers", {})

    lines = [
        "# BTForensic Report",
        "",
        "## Executive Summary",
        "",
        f"- Target: `{context.get('target_raw')}`",
        f"- Normalized domain: `{context.get('target_domain')}`",
        f"- Profiles analyzed: {profiles}",
        f"- First seen: {first_seen or 'Not found'}",
        f"- Last seen: {last_seen or 'Not found'}",
        f"- Access count: {access_count}",
        f"- Bookmarks found: {_count(context.get('bookmarks_matches'))}",
        f"- Cookies related: {_count(context.get('cookies_matches'))}",
        f"- Downloads in window: {_count(context.get('downloads_matches'))}",
        f"- Network log matches: {_count(context.get('network_log_matches'))}",
        f"- Probable caller found: {'Yes' if case_summary['probable_caller_found'] else 'No'}",
        "",
        "## Who Called The URL",
        "",
    ]

    callers = case_summary.get("probable_callers", [])
    if callers:
        lines.append("| Caller | Confidence | Method | Evidence | Target Record |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in callers[:25]:
            lines.append(
                f"| `{item.get('caller')}` | {item.get('confidence')} | {item.get('method')} | "
                f"`{item.get('evidence')}` | `{item.get('target_record') or ''}` |"
            )
    else:
        lines.extend(
            [
                "- No caller/origin could be inferred from network logs, referrers, initiators, or anonymization payloads.",
                "- Check `artifacts/network_log_matches.json` for raw matched records and decoded anonymization evidence.",
            ]
        )

    lines.extend(
        [
            "",
            "## Evidence Counts",
            "",
            f"- History visits matched: {case_summary['history_match_count']}",
            f"- Network records matched: {case_summary['network_match_count']}",
            f"- Cookies matched: {case_summary['cookie_match_count']}",
            f"- Bookmarks matched: {case_summary['bookmark_match_count']}",
            f"- Downloads matched: {case_summary['download_match_count']}",
            f"- Primary Network files scanned: {case_summary['network_scan']['primary_network_files_scanned']}",
            f"- Primary Network files containing target: {case_summary['network_scan']['primary_network_files_with_target']}",
            "",
            "## Network Files With Target Evidence",
            "",
        ]
    )
    files_with_target = case_summary["network_scan"].get("files_with_target") or case_summary.get("network_files")
    if files_with_target:
        for file_path in files_with_target[:50]:
            lines.append(f"- `{file_path}`")
    else:
        lines.append("- No network files contained target evidence.")

    lines.extend(
        [
            "",
        "## History",
        "",
        ]
    )

    if context.get("history_matches"):
        for item in context["history_matches"][:50]:
            lines.append(f"- `{item.get('profile')}` {item.get('url')} | visits={item.get('visit_count')} typed={item.get('typed_count')} title={item.get('title') or ''}")
    else:
        lines.append("- No matching history entries found.")

    lines.extend(["", "## Cookies", ""])
    if context.get("cookies_matches"):
        for item in context["cookies_matches"][:50]:
            lines.append(
                f"- `{item.get('profile')}` {item.get('host_key')} `{item.get('name')}` path={item.get('path')} "
                f"secure={item.get('is_secure')} httponly={item.get('is_httponly')} sha256={item.get('value_sha256')}"
            )
    else:
        lines.append("- No related cookies found.")

    lines.extend(["", "## Bookmarks", ""])
    if context.get("bookmarks_matches"):
        for item in context["bookmarks_matches"][:50]:
            lines.append(f"- `{item.get('profile')}` {item.get('path')} / {item.get('name')} -> {item.get('url')}")
    else:
        lines.append("- No matching bookmarks found.")

    lines.extend(["", "## Downloads", ""])
    if context.get("downloads_matches"):
        for item in context["downloads_matches"][:50]:
            lines.append(f"- `{item.get('profile')}` {item.get('start_time_utc')} {item.get('local_path')} state={item.get('state')} danger={item.get('danger_type')}")
    else:
        lines.append("- No downloads found in the target window.")

    lines.extend(["", "## Network Calls", ""])
    if context.get("network_log_matches"):
        for item in context["network_log_matches"][:50]:
            lines.append(f"- `{item.get('profile')}` {item.get('file')}:{item.get('line')} {item.get('method') or ''} {item.get('url') or item.get('origin') or ''}")
    else:
        lines.append("- No network log matches found.")

    lines.extend(["", "## Origins, Referrers And Initiators", ""])
    lines.append(f"- Direct target calls: {_count(origins.get('direct_target_calls'))}")
    lines.append(f"- Records calling target: {_count(origins.get('records_calling_target'))}")
    lines.append(f"- Possible redirects: {_count(origins.get('possible_redirects'))}")
    for item in origins.get("third_party_domains_in_time_window", [])[:25]:
        lines.append(f"- Third-party domain: `{item.get('domain')}` count={item.get('count')}")
    for item in origins.get("referrers", [])[:25]:
        lines.append(f"- Referrer: `{item.get('referrer')}` count={item.get('count')}")
    for item in origins.get("initiators", [])[:25]:
        lines.append(f"- Initiator: `{item.get('initiator')}` count={item.get('count')}")

    lines.extend(["", "## Consolidated Timeline", ""])
    for item in context.get("timeline", [])[:100]:
        lines.append(f"- {item.get('timestamp_utc')} `{item.get('type')}` `{item.get('profile')}` {item.get('description')}")
    if not context.get("timeline"):
        lines.append("- No timestamped events found.")

    lines.extend(["", "## Missing Artifacts And Errors", ""])
    if errors:
        for error in errors:
            lines.append(f"- {error}")
    else:
        lines.append("- No errors recorded.")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
