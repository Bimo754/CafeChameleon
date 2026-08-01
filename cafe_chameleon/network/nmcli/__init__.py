"""
cafe_chameleon.network.nmcli - NetworkManager (nmcli) Wi-Fi control package.
"""

from .profiles import get_active_profile, get_ssid_for_profile
from .bssid import scan_bssids_for_ssid, get_connected_bssid, lock_bssid, DEFAULT_BSSID
from .ui_status import select_bssid_interactively, show_status
from .restore import restore_auto, reset_mac

__all__ = [
    "DEFAULT_BSSID",
    "get_active_profile",
    "get_ssid_for_profile",
    "scan_bssids_for_ssid",
    "get_connected_bssid",
    "select_bssid_interactively",
    "show_status",
    "lock_bssid",
    "restore_auto",
    "reset_mac"
]
