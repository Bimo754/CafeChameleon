"""
cafe_chameleon.network.nmcli.restore - Auto-roaming restoration and profile MAC resetting.
"""

import sys

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_plus, log_minus, log_step, log_wait
from .profiles import get_active_profile


def restore_auto(profile: str | None = None) -> None:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        sys.exit(1)

    from cafe_chameleon.scanners.detector import auto_detect_network_params
    from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
    params = auto_detect_network_params()
    iface = params.get("interface") or "wlan0"
    if is_monitor_mode_active(iface):
        set_managed_mode(iface)

    trace(f"[FEATURE] Restoring profile '{profile}' to auto-roam and default permanent MAC")
    log_step(f"Resetting BSSID lock & MAC on profile '{profile}'...")
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""])
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""])
    log_wait(f"Reconnecting '{profile}' (auto-roam)...")
    rc_up, _ = _run(["nmcli", "connection", "up", profile])
    if rc_up == 0:
        log_plus("Restored auto-roaming & HW MAC.")
    else:
        log_minus("Failed reconnecting profile after reset.")


def reset_mac(profile: str | None = None) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        return False

    trace(f"[FEATURE] Resetting MAC address on profile '{profile}' to original hardware default")
    log_step(f"Resetting cloned MAC on profile '{profile}'...")
    rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""])
    log_wait(f"Reconnecting profile '{profile}'...")
    rc_up, _ = _run(["nmcli", "connection", "up", profile], timeout=15.0)
    if rc_up == 0:
        log_plus("Reset MAC to permanent HW default.")
        return True
    else:
        from cafe_chameleon.scanners.detector import auto_detect_network_params
        from cafe_chameleon.network.mac import reset_mac_address
        params = auto_detect_network_params()
        iface = params.get("interface") or "wlan0"
        if reset_mac_address(iface, profile):
            log_plus("Reset MAC via fallback method.")
            return True
        else:
            log_minus("Failed to reset MAC address.")
            return False
