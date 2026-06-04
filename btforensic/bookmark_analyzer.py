from __future__ import annotations

import json
import logging
from pathlib import Path

from .domain_utils import TargetInfo, url_matches_target
from .jq_parser import normalize_json_file
from .safe_redaction import mask_url_query
from .timestamp_utils import chrome_time_to_iso_local, chrome_time_to_iso_utc


def _walk_bookmarks(node: dict, path: list[str]):
    node_type = node.get("type")
    name = node.get("name") or ""
    current_path = path + ([name] if name else [])
    if node_type == "url":
        yield {
            "name": name,
            "url": node.get("url"),
            "path": " / ".join(path),
            "date_added": node.get("date_added"),
        }
    for child in node.get("children", []) or []:
        yield from _walk_bookmarks(child, current_path)


def analyze_bookmarks(profile_name: str, profile_path: Path, target: TargetInfo, raw_output: Path | None, logger: logging.Logger) -> dict:
    bookmarks_path = profile_path / "Bookmarks"
    result = {"bookmarks_matches": [], "raw_bookmarks": None, "errors": []}
    if not bookmarks_path.exists():
        msg = f"Bookmarks not found for profile {profile_name}"
        logger.warning(msg)
        result["errors"].append(msg)
        return result
    try:
        if raw_output is None:
            normalized = json.loads(bookmarks_path.read_text(encoding="utf-8"))
        else:
            normalized = normalize_json_file(bookmarks_path, raw_output / f"{profile_name}_bookmarks.json", logger)
        result["raw_bookmarks"] = {"profile": profile_name, "bookmarks": normalized}
        roots = normalized.get("roots", {})
        matches = []
        for root_name, root_node in roots.items():
            for item in _walk_bookmarks(root_node, [root_name]):
                if url_matches_target(item.get("url"), target):
                    matches.append(
                        {
                            "profile": profile_name,
                            "name": item.get("name"),
                            "url": mask_url_query(item.get("url")),
                            "path": item.get("path"),
                            "date_added": item.get("date_added"),
                            "date_added_utc": chrome_time_to_iso_utc(item.get("date_added")),
                            "date_added_local": chrome_time_to_iso_local(item.get("date_added")),
                        }
                    )
        result["bookmarks_matches"] = matches
        return result
    except Exception as exc:
        msg = f"Failed to analyze Bookmarks for profile {profile_name}: {exc}"
        logger.error(msg)
        result["errors"].append(msg)
        return result
