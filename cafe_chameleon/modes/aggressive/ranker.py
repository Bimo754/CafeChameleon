"""
cafe_chameleon.modes.aggressive.ranker - BSSID scoring and auto-selection ranking algorithm.
"""

import re
from cafe_chameleon.utils.blacklist import is_blacklisted, load_blacklist

DIGIT_REGEX = re.compile(r"[^\d]")


def is_client_active(mac: str, air_clients_map: dict | None = None) -> bool:
    """Checks if a client MAC address is recorded as having active data session traffic."""
    if not mac or not air_clients_map:
        return False
    mac_lower = mac.lower()
    if is_blacklisted(mac_lower):
        return False
    if hasattr(air_clients_map, "is_client_active") and callable(air_clients_map.is_client_active):
        return air_clients_map.is_client_active(mac_lower)
    if hasattr(air_clients_map, "client_metadata") and isinstance(air_clients_map.client_metadata, dict):
        meta = air_clients_map.client_metadata.get(mac_lower)
        if isinstance(meta, dict):
            return bool(meta.get("active"))
    meta_dict = getattr(air_clients_map, "client_metadata", None)
    if isinstance(meta_dict, dict) and mac_lower in meta_dict:
        return bool(meta_dict[mac_lower].get("active"))
    active_set = getattr(air_clients_map, "active_clients", None)
    if isinstance(active_set, (set, list, tuple)):
        return mac_lower in active_set
    return False


def count_active_clients(bssid: str, air_clients_map: dict | None = None) -> int:
    """Counts the number of active clients associated with a given BSSID."""
    if not bssid or not air_clients_map:
        return 0
    bssid_mac = bssid.lower()
    blacklist = load_blacklist()
    if is_blacklisted(bssid_mac, blacklist):
        return 0

    if hasattr(air_clients_map, "count_active_clients") and callable(air_clients_map.count_active_clients):
        return air_clients_map.count_active_clients(bssid_mac)

    clients_dict = air_clients_map.get(bssid_mac, {})
    if not isinstance(clients_dict, dict):
        return 0

    return sum(1 for mac in clients_dict if not is_blacklisted(mac, blacklist) and is_client_active(mac, air_clients_map))


def get_active_clients_for_bssid(bssid: str, air_clients_map: dict | None = None) -> list[str]:
    """Returns the list of active client MAC addresses for a given BSSID."""
    if not bssid or not air_clients_map:
        return []
    bssid_mac = bssid.lower()
    blacklist = load_blacklist()
    if is_blacklisted(bssid_mac, blacklist):
        return []

    if hasattr(air_clients_map, "get_active_clients_for_bssid") and callable(air_clients_map.get_active_clients_for_bssid):
        return air_clients_map.get_active_clients_for_bssid(bssid_mac)

    clients_dict = air_clients_map.get(bssid_mac, {})
    if not isinstance(clients_dict, dict):
        return []

    return [mac for mac in clients_dict if not is_blacklisted(mac, blacklist) and is_client_active(mac, air_clients_map)]


def calculate_bssid_score(
    bssid_item,
    air_clients_map: dict | None = None,
    prioritize_clients: bool = False
) -> tuple[int, int, int]:
    """
    Calculates auto-selection score for a BSSID based on:
    - Default:
      1. Signal strength percentage (heavily prioritized)
      2. Active clients (strong bonus boost for confirmed session traffic)
      3. Total captured clients (secondary tie-breaker)
    - With prioritize_clients=True:
      1. Active clients (heavily prioritized above all)
      2. Total captured clients (secondary prioritization)
      3. Signal strength percentage (tertiary tie-breaker)
    """
    bssid_mac = bssid_item["bssid"].lower()
    blacklist = load_blacklist()

    try:
        clean_sig = DIGIT_REGEX.sub("", str(bssid_item.get("signal", 0)))
        signal_pct = int(clean_sig) if clean_sig else 0
    except (ValueError, TypeError):
        signal_pct = 0

    client_count = 0
    if air_clients_map and bssid_mac in air_clients_map:
        clients_val = air_clients_map[bssid_mac]
        if isinstance(clients_val, dict):
            client_count = sum(1 for m in clients_val if not is_blacklisted(m, blacklist))

    active_count = count_active_clients(bssid_mac, air_clients_map)
    idle_count = max(0, client_count - active_count)

    if prioritize_clients:
        score = (active_count * 20000) + (idle_count * 10000) + (signal_pct * 75)
    else:
        score = (signal_pct * 75) + (active_count * 300) + (idle_count * 80)

    return score, client_count, signal_pct
