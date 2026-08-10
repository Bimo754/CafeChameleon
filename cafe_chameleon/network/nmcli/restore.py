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


def release_interface(interface: str | None = None, profile: str | None = None) -> bool:
    """
    Completely unlocks and releases a wireless interface from all locks and states:
    1. Terminates any lingering DHCP clients / raw packet capture processes.
    2. Tears down 802.11 monitor mode and deletes virtual monitor devices (e.g. wlan0mon).
    3. Clears NetworkManager BSSID lock and cloned MAC configurations on the profile.
    4. Resets the hardware MAC address to factory permanent default.
    5. Restores NetworkManager device management and brings interface up in clean managed state.
    """
    from cafe_chameleon.scanners.detector import auto_detect_network_params
    from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
    from cafe_chameleon.network.mac import reset_mac_address
    from cafe_chameleon.network.sysfs import wait_for_carrier

    params = auto_detect_network_params(target_iface=interface)
    iface = interface or params.get("interface") or "wlan0"
    prof = profile or get_active_profile()

    trace(f"[FEATURE] Releasing and unlocking interface {iface} (Profile: {prof or 'None'})")
    log_step(f"Releasing and unlocking interface {iface}...")

    # 1. Terminate lingering dhclient processes on this interface
    log_wait(f"Terminating any lingering background DHCP processes on {iface}...")
    _run(f"pkill -9 -f 'dhclient.*{iface}'", debug=False)

    # 2. Restore from monitor mode if active
    if is_monitor_mode_active(iface):
        log_wait(f"Restoring {iface} from monitor mode to managed station mode...")
        set_managed_mode(iface)

    # 3. Clear BSSID lock and cloned MAC on connection profile
    if prof:
        log_wait(f"Clearing BSSID lock & cloned MAC on NetworkManager profile '{prof}'...")
        _run(["nmcli", "connection", "modify", prof, "802-11-wireless.bssid", ""], debug=False)
        _run(["nmcli", "connection", "modify", prof, "802-11-wireless.cloned-mac-address", ""], debug=False)

    # 4. Reset MAC address to permanent hardware default
    log_wait(f"Resetting hardware MAC address on {iface}...")
    reset_mac_address(iface, profile=prof)

    # 5. Ensure device is marked managed in NetworkManager
    log_wait(f"Ensuring NetworkManager management enabled on {iface}...")
    _run(["nmcli", "device", "set", iface, "managed", "yes"], debug=False)

    # 6. Reconnect profile if available
    if prof:
        log_wait(f"Reconnecting profile '{prof}'...")
        _run(["nmcli", "connection", "up", prof], debug=False, timeout=15.0)

    wait_for_carrier(iface, timeout=4.0)
    log_plus(f"Interface {iface} released and unlocked successfully.")
    return True

