"""
cafe_chameleon.network.nmcli - NetworkManager (nmcli) Wi-Fi control package.
"""

from .profiles import get_active_profile, get_ssid_for_profile, get_active_security, is_open_security, is_encrypted_security
from .bssid import scan_bssids_for_ssid, get_connected_bssid, get_bssid_security, lock_bssid, DEFAULT_BSSID
from .ui_status import select_bssid_interactively, show_status
from .restore import restore_auto, reset_mac

__all__ = [
    "DEFAULT_BSSID",
    "get_active_profile",
    "get_ssid_for_profile",
    "get_active_security",
    "is_open_security",
    "is_encrypted_security",
    "scan_bssids_for_ssid",
    "get_connected_bssid",
    "get_bssid_security",
    "select_bssid_interactively",
    "show_status",
    "lock_bssid",
    "restore_auto",
    "reset_mac"
]
