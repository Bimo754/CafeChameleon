"""
cafe_chameleon.scanners.air.mode - Monitor & Managed mode interface switching logic.
"""

import shutil
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import set_air_mode
from cafe_chameleon.network.sysfs import wait_for_carrier


def get_base_interface(iface: str = "wlan0") -> str:
    """Normalizes a monitor interface name (e.g. wlan0mon or mon0) back to its base wireless interface (e.g. wlan0)."""
    if not iface:
        return "wlan0"
    if iface.endswith("mon") and len(iface) > 3:
        return iface[:-3]
    if iface.startswith("mon") and iface != "wlan0":
        rc, iw_out = _run(["iw", "dev"], debug=False)
        if rc == 0 and iw_out:
            for line in iw_out.splitlines():
                line_str = line.strip()
                if line_str.startswith("Interface "):
                    name = line_str.split()[1].strip()
                    if not name.startswith("mon") and not name.endswith("mon"):
                        return name
        return "wlan0"
    return iface


def is_monitor_mode_active(iface: str = "wlan0") -> bool:
    """Checks if the given interface or system has an active 802.11 monitor interface."""
    base_iface = get_base_interface(iface)
    rc, out = _run(f"iw dev {base_iface} info", debug=False)
    if rc == 0 and "type monitor" in out.lower():
        return True
    mon = get_monitor_interface(base_iface)
    if mon != base_iface:
        rc, out_mon = _run(f"iw dev {mon} info", debug=False)
        if rc == 0 and "type monitor" in out_mon.lower():
            return True
    if mon != iface:
        rc, out_given = _run(f"iw dev {iface} info", debug=False)
        if rc == 0 and "type monitor" in out_given.lower():
            return True
    rc, link_out = _run(["ip", "-o", "link", "show"], debug=False)
    for line in link_out.splitlines():
        if f"{base_iface}mon" in line or "mon0" in line or "wlan0mon" in line or (iface and f"{iface}" in line and "mon" in line):
            return True
    return False


def get_monitor_interface(default_iface: str = "wlan0") -> str:
    """Detects active monitor mode interface name (e.g. wlan0mon, wlan0, or mon0)."""
    base_iface = get_base_interface(default_iface)
    # 1. Check iw dev for any interface configured as type monitor
    rc, iw_out = _run(["iw", "dev"], debug=False)
    if rc == 0 and iw_out:
        current_iface = None
        for line in iw_out.splitlines():
            line_str = line.strip()
            if line_str.startswith("Interface "):
                current_iface = line_str.split()[1].strip()
            elif current_iface and "type monitor" in line_str:
                if current_iface == base_iface or current_iface.startswith(base_iface) or "mon" in current_iface:
                    return current_iface

    # 2. Check ip -o link show
    rc, out = _run(["ip", "-o", "link", "show"], debug=False)
    if rc == 0 and out:
        target_mon = f"{base_iface}mon"
        for line in out.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                name = parts[1].strip()
                if name == target_mon or name in ("wlan0mon", "mon0", "mon1") or (name.endswith("mon") and name.startswith(base_iface[:4])):
                    return name

    return base_iface


def set_monitor_mode(interface: str = "wlan0") -> str:
    """
    Switches interface to 802.11 monitor mode natively using airmon-ng or iw/ip.
    Returns the monitor interface name (e.g. wlan0mon or wlan0).
    """
    set_air_mode("Monitor")

    base_iface = get_base_interface(interface)
    try:
        from cafe_chameleon.utils.state import set_restore_params, get_restore_params
        curr_p = get_restore_params()
        prof = curr_p.get("profile") if curr_p else None
        mac = curr_p.get("macaddress") if curr_p else ""
        ipm = curr_p.get("ipmask") if curr_p else ""
        brd = curr_p.get("broadcast") if curr_p else ""
        gw = curr_p.get("gateway") if curr_p else ""
        set_restore_params(base_iface, mac, ipm, brd, gw, profile=prof)
    except Exception:
        pass

    # Unmanage in NetworkManager and clear DHCP leases before monitor switch
    _run(["nmcli", "device", "disconnect", base_iface], debug=False)
    _run(["nmcli", "device", "set", base_iface, "managed", "no"], debug=False)
    _run(["pkill", "-9", "-f", f"dhclient.*{base_iface}"], debug=False)
    _run(["ip", "link", "set", "dev", base_iface, "down"], debug=False)

    switched = False
    if shutil.which("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], debug=False)
        rc_air, _ = _run(["airmon-ng", "start", base_iface], debug=False)
        if rc_air == 0:
            switched = True

    if not switched or not is_monitor_mode_active(base_iface):
        _run(["iw", "dev", base_iface, "set", "type", "monitor"], debug=False)
        _run(["ip", "link", "set", "dev", base_iface, "up"], debug=False)

    mon_iface = get_monitor_interface(base_iface)
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
    base_iface = get_base_interface(interface)
    mon_iface = get_monitor_interface(base_iface)

    if shutil.which("airmon-ng"):
        if mon_iface and mon_iface != base_iface:
            _run(["airmon-ng", "stop", mon_iface], debug=False)
        if interface and interface != base_iface and interface != mon_iface:
            _run(["airmon-ng", "stop", interface], debug=False)
        _run(["airmon-ng", "stop", base_iface], debug=False)

    if mon_iface and mon_iface != base_iface:
        _run(["iw", "dev", mon_iface, "del"], debug=False)
    if interface and interface != base_iface and interface != mon_iface:
        _run(["iw", "dev", interface, "del"], debug=False)

    _run(["ip", "link", "set", "dev", base_iface, "down"], debug=False)
    _run(["iw", "dev", base_iface, "set", "type", "managed"], debug=False)
    _run(["ip", "link", "set", "dev", base_iface, "up"], debug=False)

    _run(["nmcli", "device", "set", base_iface, "managed", "yes"], debug=False)

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
        if base_iface in out and ("disconnected" in out or "connected" in out or "connecting" in out):
            break
        time.sleep(0.5)

    try:
        from scapy.config import conf
        if hasattr(conf, "ifaces") and hasattr(conf.ifaces, "reload"):
            conf.ifaces.reload()
    except Exception:
        pass


