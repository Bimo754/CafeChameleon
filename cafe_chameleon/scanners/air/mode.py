"""
cafe_chameleon.scanners.air.mode - Monitor & Managed mode interface switching logic.
"""

import shutil
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import set_air_mode
from cafe_chameleon.network.sysfs import wait_for_carrier


def get_monitor_interface(default_iface: str = "wlan0") -> str:
    """Detects active monitor mode interface name (e.g. wlan0mon or wlan0)."""
    rc, out = _run(["ip", "-o", "link", "show"])
    for line in out.splitlines():
        if "wlan0mon" in line or "mon0" in line:
            parts = line.split(":", 2)
            if len(parts) >= 2:
                return parts[1].strip()
    return default_iface


def set_monitor_mode(interface: str = "wlan0") -> str:
    """
    Switches interface to 802.11 monitor mode natively using airmon-ng or iw/ip.
    Returns the monitor interface name (e.g. wlan0mon or wlan0).
    """
    set_air_mode("Monitor")

    if shutil.which("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], debug=False)
        _run(["airmon-ng", "start", interface], debug=False)
    else:
        _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
        _run(["iw", "dev", interface, "set", "type", "monitor"], debug=False)
        _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    mon_iface = get_monitor_interface(interface)
    return mon_iface


def set_managed_mode(interface: str = "wlan0") -> None:
    """
    Restores interface to MANAGED mode natively and restarts NetworkManager / wpa_supplicant.
    """
    set_air_mode("Managed")
    mon_iface = get_monitor_interface(interface)

    if shutil.which("airmon-ng"):
        if mon_iface != interface:
            _run(["airmon-ng", "stop", mon_iface], debug=False)
        _run(["airmon-ng", "stop", interface], debug=False)

    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
    _run(["iw", "dev", interface, "set", "type", "managed"], debug=False)
    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    if shutil.which("systemctl"):
        _run(["systemctl", "restart", "wpa_supplicant"], debug=False)
        _run(["systemctl", "restart", "NetworkManager"], debug=False)
    elif shutil.which("service"):
        _run(["service", "wpa_supplicant", "restart"], debug=False)
        _run(["service", "NetworkManager", "restart"], debug=False)

    start_t = time.time()
    while time.time() - start_t < 10:
        rc, out = _run(["nmcli", "dev", "status"], debug=False)
        if interface in out and ("disconnected" in out or "connected" in out or "connecting" in out):
            break
        time.sleep(0.5)

    wait_for_carrier(interface, timeout=6.0)
