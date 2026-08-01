"""
cafe_chameleon.modes.aggressive.ranker - BSSID scoring and auto-selection ranking algorithm.
"""

import re


def calculate_bssid_score(bssid_item: dict, air_clients_map: dict | None = None) -> tuple[int, int, int]:
    """
    Calculates auto-selection score for a BSSID based on:
    1. Signal strength percentage (heavily prioritized)
    2. Number of captured clients (secondary boost / tie-breaker)
    """
    bssid_mac = bssid_item["bssid"].lower()

    try:
        signal_pct = int(re.sub(r"[^\d]", "", str(bssid_item.get("signal", 0))))
    except Exception:
        signal_pct = 0

    client_count = 0
    if air_clients_map and bssid_mac in air_clients_map:
        client_count = len(air_clients_map[bssid_mac])

    score = (signal_pct * 75) + (client_count * 80)
    return score, client_count, signal_pct
