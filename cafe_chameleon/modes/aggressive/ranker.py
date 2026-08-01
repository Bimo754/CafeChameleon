"""
cafe_chameleon.modes.aggressive.ranker - BSSID scoring and auto-selection ranking algorithm.
"""

import re

DIGIT_REGEX = re.compile(r"[^\d]")


def calculate_bssid_score(bssid_item, air_clients_map: dict | None = None) -> tuple[int, int, int]:
    """
    Calculates auto-selection score for a BSSID based on:
    1. Signal strength percentage (heavily prioritized)
    2. Number of captured clients (secondary boost / tie-breaker)
    """
    bssid_mac = bssid_item["bssid"].lower()

    try:
        clean_sig = DIGIT_REGEX.sub("", str(bssid_item.get("signal", 0)))
        signal_pct = int(clean_sig) if clean_sig else 0
    except (ValueError, TypeError):
        signal_pct = 0

    client_count = 0
    if air_clients_map and bssid_mac in air_clients_map:
        client_count = len(air_clients_map[bssid_mac])

    score = (signal_pct * 75) + (client_count * 80)
    return score, client_count, signal_pct
