"""
cafe_chameleon.aggressive.ranker - BSSID scoring and auto-selection ranking algorithm.
"""

import re


def calculate_bssid_score(bssid_item: dict, air_clients_map: dict | None = None) -> tuple[int, int, int]:
    """
    Calculates auto-selection score for a BSSID based on:
    1. Number of captured clients (the more clients, the higher score / priority)
    2. Signal strength percentage (the better signal, the higher score)
    """
    bssid_mac = bssid_item["bssid"].lower()

    try:
        signal_pct = int(re.sub(r"[^\d]", "", str(bssid_item.get("signal", 0))))
    except Exception:
        signal_pct = 0

    client_count = 0
    if air_clients_map and bssid_mac in air_clients_map:
        client_count = len(air_clients_map[bssid_mac])

    # Score formula: Heavily weight client count so BSSIDs with clients rank first,
    # and break ties/rank remaining BSSIDs using signal strength percentage.
    score = (client_count * 1000) + signal_pct
    return score, client_count, signal_pct
