from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .bookmark_analyzer import analyze_bookmarks
from .browser_discovery import discover_profiles
from .cookie_analyzer import analyze_cookies
from .domain_utils import extract_host, normalize_target
from .download_analyzer import analyze_downloads
from .history_analyzer import analyze_history
from .logging_config import setup_logging
from .network_log_analyzer import analyze_network_logs
from .origins_analyzer import build_origins_and_referrers
from .report_writer import write_report
from .safe_redaction import mask_url_query, redact_headers, sha256_value
from .sqlite_exporter import write_json
from .summary_builder import build_case_summary
from .timeline_builder import build_timeline
from .timestamp_utils import chrome_time_to_datetime


BANNER = r"""
 ____ _____ _____                          _
| __ )_   _|  ___|__  _ __ ___ _ __  ___(_) ___
|  _ \ | | | |_ / _ \| '__/ _ \ '_ \/ __| |/ __|
| |_) || | |  _| (_) | | |  __/ | | \__ \ | (__
|____/ |_| |_|  \___/|_|  \___|_| |_|___/_|\___|

Defensive Chromium browser forensics | read-only local analysis
made by tzndias
"""


def print_banner() -> None:
    print(BANNER.strip())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="BTForensic",
        description="Defensive read-only forensic analyzer for Chromium-based browser artifacts.",
    )
    parser.add_argument("--user-data", required=True, help="Path to the browser User Data directory.")
    parser.add_argument("--target", required=True, help="Target domain or URL to investigate.")
    parser.add_argument("--output", help="Directory where reports and JSON artifacts will be written. If omitted, prints a terminal summary only.")
    parser.add_argument("--profile", help="Analyze a specific browser profile, such as Default or Profile 1.")
    parser.add_argument("--window-minutes", type=int, default=30, help="Correlation window around target visits. Default: 30.")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed logging.")
    parser.add_argument("--version", action="version", version=f"BTForensic {__version__}")
    return parser


def _sanitize_json(value):
    if isinstance(value, bytes):
        return {
            "redacted_bytes": True,
            "size": len(value),
            "sha256": sha256_value(value),
        }
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if key_lower in {"headers", "request_headers", "response_headers"} and isinstance(item, dict):
                sanitized[key] = redact_headers(item)
            elif key_lower in {"url", "referrer", "referer", "origin", "initiator", "tab_url", "site_url"} and isinstance(item, str):
                sanitized[key] = mask_url_query(item)
            elif key_lower in {"value", "encrypted_value", "cookie", "authorization"}:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_json(item)
        return sanitized
    return value


def _visit_windows(visits: list[dict], window_minutes: int) -> list[tuple]:
    windows = []
    delta = timedelta(minutes=window_minutes)
    for visit in visits:
        dt = chrome_time_to_datetime(visit.get("visit_time"))
        if dt:
            windows.append((dt - delta, dt + delta))
    return windows


def _print_terminal_summary(context: dict) -> None:
    summary = build_case_summary(context)
    print()
    print("BTForensic Findings")
    print("===================")
    print(f"Target: {summary['target']} ({summary['target_domain']})")
    print(f"Profiles: {', '.join(summary['profiles']) or 'None'}")
    print(f"First seen: {summary['first_seen_utc'] or 'Not found'}")
    print(f"Last seen: {summary['last_seen_utc'] or 'Not found'}")
    print()
    print("Evidence counts")
    print(f"- History visits: {summary['history_match_count']}")
    print(f"- Network records: {summary['network_match_count']}")
    print(f"- Cookies: {summary['cookie_match_count']}")
    print(f"- Bookmarks: {summary['bookmark_match_count']}")
    print(f"- Downloads: {summary['download_match_count']}")
    network_scan = summary.get("network_scan", {})
    print(f"- Primary Network files scanned: {network_scan.get('primary_network_files_scanned', 0)}")
    print(f"- Primary Network files containing target: {network_scan.get('primary_network_files_with_target', 0)}")
    print()
    print("Who called the URL")
    callers = summary.get("probable_callers", [])
    if callers:
        for item in callers[:10]:
            print(f"- {item['caller']} [{item['confidence']}] via {item['method']} ({item['source']})")
            print(f"  evidence: {item['evidence']}")
            if item.get("target_record"):
                print(f"  target record: {item['target_record']}")
    else:
        print("- Not identified from available History, Network logs, referrer/initiator fields, or anonymization payloads.")
    files_with_target = network_scan.get("files_with_target") or summary.get("network_files")
    if files_with_target:
        print()
        print("Network files with target evidence")
        for file_path in files_with_target[:10]:
            print(f"- {file_path}")
    if summary.get("errors"):
        print()
        print("Warnings/errors")
        for error in summary["errors"][:10]:
            print(f"- {error}")


def run(args: argparse.Namespace) -> int:
    print_banner()

    output_dir = Path(args.output) if args.output else None
    artifacts_dir = output_dir / "artifacts" if output_dir else None
    raw_dir = output_dir / "raw_converted" if output_dir else None
    if output_dir:
        for directory in (artifacts_dir, raw_dir, output_dir / "logs"):
            directory.mkdir(parents=True, exist_ok=True)

    logger = setup_logging(output_dir, args.verbose)
    logger.info("BTForensic started")

    user_data = Path(args.user_data).expanduser()
    if not user_data.exists():
        logger.error("User Data path does not exist: %s", user_data)
        return 2

    target = normalize_target(args.target)
    logger.info("Target normalized: %s", target.domain)

    profiles = discover_profiles(user_data, args.profile)
    if not profiles:
        logger.error("No browser profiles found under: %s", user_data)
        return 3
    logger.info("Found profiles: %s", ", ".join(profile.name for profile in profiles))

    history_matches = []
    visits_matches = []
    cookies_matches = []
    bookmarks_matches = []
    downloads_matches = []
    network_log_matches = []
    network_scan_summaries = []
    related_urls = []
    history_summaries = []
    raw_urls = []
    raw_visits = []
    raw_cookies = []
    raw_bookmarks = []
    errors = []

    for profile in profiles:
        logger.info("Analyzing profile: %s", profile.name)
        history = analyze_history(profile.name, profile.path, target, args.window_minutes, logger)
        history_matches.extend(history["history_matches"])
        visits_matches.extend(history["visits_matches"])
        related_urls.extend(history["related_urls"])
        raw_urls.extend(history["raw_urls"])
        raw_visits.extend(history["raw_visits"])
        errors.extend(history["errors"])
        if history["summary"]:
            history_summaries.append(history["summary"])
        logger.info("History matches: %s", len(history["visits_matches"]))

        related_hosts = {
            extract_host(row.get("url"))
            for row in history["related_urls"]
            if extract_host(row.get("url")) and not row.get("is_target")
        }
        cookies = analyze_cookies(profile.name, profile.path, target, related_hosts, logger)
        cookies_matches.extend(cookies["cookies_matches"])
        raw_cookies.extend(cookies["raw_cookies"])
        errors.extend(cookies["errors"])
        logger.info("Cookie matches: %s", len(cookies["cookies_matches"]))

        bookmarks = analyze_bookmarks(profile.name, profile.path, target, raw_dir, logger)
        bookmarks_matches.extend(bookmarks["bookmarks_matches"])
        if bookmarks["raw_bookmarks"]:
            raw_bookmarks.append(bookmarks["raw_bookmarks"])
        errors.extend(bookmarks["errors"])
        logger.info("Bookmark matches: %s", len(bookmarks["bookmarks_matches"]))

        windows = _visit_windows(history["visits_matches"], args.window_minutes)
        downloads = analyze_downloads(profile.name, profile.path, target, windows, logger)
        downloads_matches.extend(downloads["downloads_matches"])
        errors.extend(downloads["errors"])
        logger.info("Download matches in time window: %s", len(downloads["downloads_matches"]))

        network = analyze_network_logs(profile.name, profile.path, target, logger)
        network_log_matches.extend(network["network_log_matches"])
        network_scan_summaries.append(network.get("scan_summary", {}))
        errors.extend(network["errors"])
        logger.info("Network log matches: %s", len(network["network_log_matches"]))

    origins = build_origins_and_referrers(target, related_urls, network_log_matches)
    timeline = build_timeline(visits_matches, cookies_matches, bookmarks_matches, downloads_matches, network_log_matches, origins)

    artifact_payloads = {
        "history_matches.json": history_matches,
        "visits_matches.json": visits_matches,
        "cookies_matches.json": cookies_matches,
        "bookmarks_matches.json": bookmarks_matches,
        "downloads_matches.json": downloads_matches,
        "network_log_matches.json": network_log_matches,
        "origins_and_referrers.json": origins,
    }
    raw_payloads = {
        "history_urls.json": raw_urls,
        "history_visits.json": raw_visits,
        "cookies.json": raw_cookies,
        "bookmarks.json": raw_bookmarks,
    }

    context = {
        "target_raw": target.raw,
        "target_domain": target.domain,
        "profiles": [profile.name for profile in profiles],
        "history_summaries": history_summaries,
        "history_matches": _sanitize_json(history_matches),
        "visits_matches": _sanitize_json(visits_matches),
        "cookies_matches": cookies_matches,
        "bookmarks_matches": _sanitize_json(bookmarks_matches),
        "downloads_matches": _sanitize_json(downloads_matches),
        "network_log_matches": _sanitize_json(network_log_matches),
        "network_scan_summaries": _sanitize_json(network_scan_summaries),
        "origins_and_referrers": _sanitize_json(origins),
        "timeline": _sanitize_json(timeline),
        "errors": errors,
    }

    if output_dir:
        for filename, payload in artifact_payloads.items():
            write_json(artifacts_dir / filename, _sanitize_json(payload))
        for filename, payload in raw_payloads.items():
            write_json(raw_dir / filename, _sanitize_json(payload))
        write_json(output_dir / "timeline.json", _sanitize_json(timeline))
        report_path = output_dir / "BTForensic_report.md"
        write_report(report_path, context)

        logger.info("Report written to: %s", report_path)
        logger.info("Timeline written to: %s", output_dir / "timeline.json")
    else:
        _print_terminal_summary(context)
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
