"""
cafe_chameleon.scanners.air.mode - Monitor & Managed mode interface switching logic.
"""

import shutil
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import set_air_mode
from cafe_chameleon.network.sysfs import wait_for_carrier


def is_monitor_mode_active(iface: str = "wlan0") -> bool:
    """Checks if the given interface or system has an active 802.11 monitor interface."""
    rc, out = _run(f"iw dev {iface} info", debug=False)
    if rc == 0 and "type monitor" in out.lower():
        return True
    mon = get_monitor_interface(iface)
    if mon != iface:
        rc, out_mon = _run(f"iw dev {mon} info", debug=False)
        if rc == 0 and "type monitor" in out_mon.lower():
            return True
    rc, link_out = _run(["ip", "-o", "link", "show"], debug=False)
    for line in link_out.splitlines():
        if f"{iface}mon" in line or "mon0" in line or "wlan0mon" in line:
            return True
    return False


def get_monitor_interface(default_iface: str = "wlan0") -> str:
    """Detects active monitor mode interface name (e.g. wlan0mon, wlan0, or mon0)."""
    # 1. Check iw dev for any interface configured as type monitor
    rc, iw_out = _run(["iw", "dev"], debug=False)
    if rc == 0 and iw_out:
        current_iface = None
        for line in iw_out.splitlines():
            line_str = line.strip()
            if line_str.startswith("Interface "):
                current_iface = line_str.split()[1].strip()
            elif current_iface and "type monitor" in line_str:
                if current_iface == default_iface or current_iface.startswith(default_iface) or "mon" in current_iface:
                    return current_iface

    # 2. Check ip -o link show
    rc, out = _run(["ip", "-o", "link", "show"], debug=False)
    if rc == 0 and out:
        target_mon = f"{default_iface}mon"
        for line in out.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip()
                if name == target_mon or name in ("wlan0mon", "mon0", "mon1") or (name.endswith("mon") and name.startswith(default_iface[:4])):
                    return name

    return default_iface


def set_monitor_mode(interface: str = "wlan0") -> str:
    """
    Switches interface to 802.11 monitor mode natively using airmon-ng or iw/ip.
    Returns the monitor interface name (e.g. wlan0mon or wlan0).
    """
    set_air_mode("Monitor")

    # Unmanage in NetworkManager and clear DHCP leases before monitor switch
    _run(["nmcli", "device", "disconnect", interface], debug=False)
    _run(["nmcli", "device", "set", interface, "managed", "no"], debug=False)
    _run(["pkill", "-9", "-f", f"dhclient.*{interface}"], debug=False)
    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)

    switched = False
    if shutil.which("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], debug=False)
        rc_air, _ = _run(["airmon-ng", "start", interface], debug=False)
        if rc_air == 0:
            switched = True

    if not switched or not is_monitor_mode_active(interface):
        _run(["iw", "dev", interface, "set", "type", "monitor"], debug=False)
        _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    mon_iface = get_monitor_interface(interface)
    _run(["ip", "link", "set", "dev", mon_iface, "up"], debug=False)
    time.sleep(0.4)

    try:
        from scapy.config import conf
        if hasattr(conf, "ifaces") and hasattr(conf.ifaces, "reload"):
            conf.ifaces.reload()
    except Exception:
        pass

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

    if mon_iface != interface:
        _run(["iw", "dev", mon_iface, "del"], debug=False)

    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
    _run(["iw", "dev", interface, "set", "type", "managed"], debug=False)
    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    _run(["nmcli", "device", "set", interface, "managed", "yes"], debug=False)

    if shutil.which("systemctl"):
        rc_nm, _ = _run(["systemctl", "is-active", "--quiet", "NetworkManager"], debug=False)
        rc_wpa, _ = _run(["systemctl", "is-active", "--quiet", "wpa_supplicant"], debug=False)
        if rc_nm != 0 or rc_wpa != 0:
            _run(["systemctl", "restart", "wpa_supplicant"], debug=False)
            _run(["systemctl", "restart", "NetworkManager"], debug=False)
    elif shutil.which("service"):
        rc_nm, _ = _run(["service", "NetworkManager", "status"], debug=False)
        rc_wpa, _ = _run(["service", "wpa_supplicant", "status"], debug=False)
        if rc_nm != 0 or rc_wpa != 0:
            _run(["service", "wpa_supplicant", "restart"], debug=False)
            _run(["service", "NetworkManager", "restart"], debug=False)

    start_t = time.time()
    while time.time() - start_t < 10:
        rc, out = _run(["nmcli", "dev", "status"], debug=False)
        if interface in out and ("disconnected" in out or "connected" in out or "connecting" in out):
            break
        time.sleep(0.5)

    try:
        from scapy.config import conf
        if hasattr(conf, "ifaces") and hasattr(conf.ifaces, "reload"):
            conf.ifaces.reload()
    except Exception:
        pass

