"""
cafe_chameleon.scanners.detector.validator - Network interface existence and managed mode validation helpers.
"""

import os


def is_valid_managed_iface(item: str) -> bool:
    """Returns True if interface is a physical/managed network interface (not loopback, docker, or monitor mode)."""
    if not item or item == "lo":
        return False
    if any(item.startswith(p) for p in ("br-", "veth", "docker", "lxc", "tun", "tap", "virbr", "mon")):
        return False
    if any(item.endswith(s) for s in ("mon", "mon0", "mon1", "mon2")):
        return False
    return True


def validate_interface(iface: str | None) -> bool:
    """Checks if the given interface exists in sysfs and is not a monitor interface."""
    if not iface or not is_valid_managed_iface(iface):
        return False
    return os.path.exists(f"/sys/class/net/{iface}")


def find_suitable_interface() -> str | None:
    """Finds any active physical/wireless network interface on the system (excluding monitor interfaces)."""
    if os.path.exists("/sys/class/net"):
        try:
            for item in os.listdir("/sys/class/net"):
                if is_valid_managed_iface(item) and (item.startswith("wlan") or item.startswith("wlp")):
                    return item
            for item in os.listdir("/sys/class/net"):
                if is_valid_managed_iface(item):
                    return item
        except Exception:
            pass
    return None


def check_interface_warning(target_iface: str | None = None) -> str | None:
    """
    Checks if target_iface or default interface exists on system.
    Returns warning message string if interface is missing/invalid, or None if OK.
    """
    ifaces = []
    if os.path.exists("/sys/class/net"):
        try:
            for item in os.listdir("/sys/class/net"):
                if is_valid_managed_iface(item):
                    ifaces.append(item)
        except Exception:
            pass

    iface_to_check = target_iface or "wlan0"

    if iface_to_check not in ifaces:
        wireless_ifaces = [i for i in ifaces if i.startswith("wlan") or i.startswith("wlp")]
        if wireless_ifaces:
            return f"Specified network interface '{iface_to_check}' was not found. Using detected interface '{wireless_ifaces[0]}' instead."
        else:
            return f"No suitable network interface (like '{iface_to_check}') was found on this system."

    return None
