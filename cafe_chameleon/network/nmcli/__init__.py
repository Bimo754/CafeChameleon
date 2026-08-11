"""
cafe_chameleon.network.nmcli - NetworkManager (nmcli) Wi-Fi control package.
"""

from .profiles import get_active_profile, get_ssid_for_profile, get_active_security, is_open_security, is_encrypted_security
from .bssid import scan_bssids_for_ssid, scan_nearby_wifi_networks, get_connected_bssid, get_bssid_security, lock_bssid
from .ui_status import select_bssid_interactively, show_status, show_wifi_scan
from .restore import restore_auto, reset_mac, release_interface, change_mac
from .reconnect import reconnect_wifi

__all__ = [
    "get_active_profile",
    "get_ssid_for_profile",
    "get_active_security",
    "is_open_security",
    "is_encrypted_security",
    "scan_bssids_for_ssid",
    "scan_nearby_wifi_networks",
    "get_connected_bssid",
    "get_bssid_security",
    "select_bssid_interactively",
    "show_status",
    "show_wifi_scan",
    "lock_bssid",
    "restore_auto",
    "reset_mac",
    "release_interface",
    "change_mac",
    "reconnect_wifi"
]
