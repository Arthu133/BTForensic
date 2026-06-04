from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROFILE_MARKERS = ("History", "Bookmarks", "Cookies")


@dataclass(frozen=True)
class BrowserProfile:
    name: str
    path: Path


def _looks_like_profile(path: Path) -> bool:
    if not path.is_dir():
        return False
    if any((path / marker).exists() for marker in PROFILE_MARKERS):
        return True
    if (path / "Network" / "Cookies").exists():
        return True
    return False


def discover_profiles(user_data: Path, profile_name: str | None = None) -> list[BrowserProfile]:
    if profile_name:
        profile_path = user_data / profile_name
        if _looks_like_profile(profile_path):
            return [BrowserProfile(profile_name, profile_path)]
        return []

    profiles: list[BrowserProfile] = []
    if _looks_like_profile(user_data):
        profiles.append(BrowserProfile(user_data.name, user_data))

    for child in sorted(user_data.iterdir() if user_data.exists() else []):
        if _looks_like_profile(child):
            profiles.append(BrowserProfile(child.name, child))

    unique: dict[Path, BrowserProfile] = {}
    for profile in profiles:
        unique[profile.path.resolve()] = profile
    return list(unique.values())
