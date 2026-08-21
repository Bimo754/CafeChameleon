"""
cafe_chameleon.network.nmcli.restore - Auto-roaming restoration and profile MAC resetting.
"""

import sys
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_plus, log_minus, log_step, log_wait, log_warning
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
    from cafe_chameleon.scanners.detector import auto_detect_network_params
    from cafe_chameleon.network.mac import reset_mac_address
    profile = profile or get_active_profile()
    params = auto_detect_network_params()
    iface = params.get("interface") or "wlan0"
    return reset_mac_address(iface, profile)


def change_mac(mac: str | None = None, profile: str | None = None, loop: bool = True, timeout: float = 5.0) -> bool:
    """
    Changes the MAC address of a connection profile or active interface to a specified or random MAC.
    If loop is True, automatically retries on failure or timeout (5s) until success or Ctrl+C.
    """
    from cafe_chameleon.network.mac import is_valid_mac, generate_random_mac, set_mac_address
    from cafe_chameleon.scanners.detector import auto_detect_network_params

    if mac is not None:
        if not is_valid_mac(mac):
            log_minus(f"Error: Invalid MAC address '{mac}'.", force=True)
            return False
        explicit_mac = mac.lower()
    else:
        explicit_mac = None

    profile = profile or get_active_profile()

    attempt = 1
    while True:
        try:
            target_mac = explicit_mac if explicit_mac is not None else generate_random_mac()

            if profile:
                trace(f"[FEATURE] Attempt {attempt}: Setting MAC address on profile '{profile}' to {target_mac}")
                log_step(f"Setting cloned MAC on profile '{profile}' to {target_mac} (Attempt {attempt})...")
                rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", target_mac])
                if rc == 0:
                    log_wait(f"Reconnecting profile '{profile}' (timeout: {int(timeout)}s)...")
                    rc_up, _ = _run(["nmcli", "connection", "up", profile], timeout=timeout)
                    if rc_up != 0:
                        log_wait("Rescanning Wi-Fi & retrying reconnect...")
                        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
                        _run(["nmcli", "connection", "up", profile], timeout=timeout)

            params = auto_detect_network_params()
            iface = params.get("interface") or "wlan0"
            if set_mac_address(iface, target_mac, profile):
                return True

            if not loop:
                log_minus(f"Failed to change MAC address to {target_mac}.", force=True)
                return False

            log_warning(f"MAC change attempt {attempt} failed or timed out ({int(timeout)}s). Retrying (Press Ctrl+C to abort)...")
            attempt += 1
            time.sleep(1.0)

        except KeyboardInterrupt:
            log_minus("\nMAC change aborted by user (Ctrl+C).", force=True)
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
    from cafe_chameleon.scanners.detector import auto_detect_network_params, find_suitable_interface
    from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode, get_monitor_interface
    from cafe_chameleon.network.mac import reset_mac_address
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.utils.state import get_restore_params

    restore_p = get_restore_params()
    if not interface and restore_p and restore_p.get("interface"):
        interface = restore_p.get("interface")
    if not profile and restore_p and restore_p.get("profile"):
        profile = restore_p.get("profile")

    if not interface:
        params = auto_detect_network_params(target_iface=None)
        cand_iface = params.get("interface")
        if cand_iface and not cand_iface.startswith("eth") and not cand_iface.startswith("en"):
            interface = cand_iface
        else:
            mon_cand = get_monitor_interface("wlan0")
            if mon_cand and mon_cand != "wlan0":
                interface = "wlan0"
            else:
                interface = find_suitable_interface() or "wlan0"

    iface = interface or "wlan0"
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
    log_plus(f"Interface {iface} released and unlocked successfully.", force=True)
    return True

