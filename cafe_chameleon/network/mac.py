"""
cafe_chameleon.network.mac - MAC address spoofing via macchanger, validation, and query utilities.
"""

import re

from cafe_chameleon.utils.process import _run


def is_valid_mac(val: str) -> bool:
    """Returns True if val is a valid 6-byte hexadecimal MAC address string."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", val)) if val else False


def set_mac_address(interface: str, mac: str, profile: str | None = None) -> bool:
    """
    Changes the MAC address of an interface using NetworkManager's nmcli cloned-mac-address property.
    If NetworkManager profile is not provided, attempts to auto-detect the active Wi-Fi profile.
    Falls back to ip link set address and macchanger if NetworkManager is unavailable or profile is missing.
    """
    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", mac], debug=False)
        if rc == 0:
            rc_up, _ = _run(["nmcli", "connection", "up", profile], debug=False, timeout=8.0)
            if rc_up == 0:
                return True

    # Fallback method: manual link down -> address change -> link up
    _run(f"ip link set dev {interface} down", debug=False)
    rc_ip, _ = _run(f"ip link set dev {interface} address {mac}", debug=False)
    rc_mc, _ = _run(f"macchanger -m {mac} {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)
    return rc_ip == 0 or rc_mc == 0


def reset_mac_address(interface: str, profile: str | None = None) -> bool:
    """Resets the MAC address of a connection profile back to default hardware MAC."""
    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""], debug=False)
        _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""], debug=False)
        rc_up, _ = _run(["nmcli", "connection", "up", profile], debug=False, timeout=8.0)
        if rc_up == 0:
            return True

    # Fallback to manual link down -> macchanger -p -> link up
    _run(f"ip link set dev {interface} down", debug=False)
    rc_mc, _ = _run(f"macchanger -p {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)
    return rc_mc == 0


def get_current_mac(interface: str) -> str | None:
    """Gets the current MAC address of an interface using sysfs, falling back to macchanger -s."""
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            addr = f.read().strip().lower()
            if addr and is_valid_mac(addr):
                return addr
    except Exception:
        pass

    rc, out = _run(f"macchanger -s {interface}", debug=False)
    if rc == 0 and out:
        m = re.search(r"Current MAC:\s+([0-9a-fa-f:]+)", out, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return None
