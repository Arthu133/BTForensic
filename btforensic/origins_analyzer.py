from __future__ import annotations

from collections import Counter, defaultdict

from .domain_utils import TargetInfo, extract_host, url_matches_target


def build_origins_and_referrers(target: TargetInfo, related_urls: list[dict], network_matches: list[dict]) -> dict:
    direct_calls = []
    called_target = []
    third_party = Counter()
    referrers = defaultdict(int)
    initiators = defaultdict(int)

    for row in related_urls:
        url = row.get("url")
        host = extract_host(url)
        if not host:
            continue
        if row.get("is_target") or url_matches_target(url, target):
            direct_calls.append(row)
        else:
            third_party[host] += 1

    for row in network_matches:
        url = row.get("url")
        origin = row.get("origin")
        referrer = row.get("referrer")
        initiator = row.get("initiator")
        if url_matches_target(url, target):
            called_target.append(row)
        if referrer:
            referrers[referrer] += 1
        if initiator:
            initiators[initiator] += 1
        for inferred_origin in row.get("inferred_origins_from_anonymization", []) or []:
            initiators[f"anonymization:{inferred_origin}"] += 1
        for candidate in (url, origin, referrer, initiator, *(row.get("inferred_origins_from_anonymization", []) or [])):
            host = extract_host(candidate)
            if host and not url_matches_target(candidate, target):
                third_party[host] += 1

    return {
        "direct_target_calls": direct_calls,
        "records_calling_target": called_target,
        "third_party_domains_in_time_window": [
            {"domain": domain, "count": count}
            for domain, count in third_party.most_common()
        ],
        "referrers": [{"referrer": key, "count": value} for key, value in sorted(referrers.items())],
        "initiators": [{"initiator": key, "count": value} for key, value in sorted(initiators.items())],
        "possible_redirects": [
            row for row in related_urls
            if row.get("transition") is not None and int(row.get("transition") or 0) & 0x10000000
        ],
    }
