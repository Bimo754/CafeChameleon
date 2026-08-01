import random
import re

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.state import get_use_original_mac
from cafe_chameleon.utils.tracing import trace


def is_valid_mac(val: str) -> bool:
    """Returns True if val is a valid 6-byte hexadecimal MAC address string."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", val)) if val else False


def generate_random_mac() -> str:
    """Generates a random unicast, locally-administered MAC address."""
    first_byte = random.choice([0x02, 0x06, 0x0A, 0x0E, 0x12, 0x16, 0x1A, 0x1E])
    rest = [random.randint(0, 255) for _ in range(5)]
    mac_bytes = [first_byte] + rest
    return ":".join(f"{b:02x}" for b in mac_bytes)


def get_permanent_mac(interface: str) -> str | None:
    """Gets the original hardware permanent MAC address of an interface."""
    try:
        with open(f"/sys/class/net/{interface}/perm_addr", "r") as f:
            addr = f.read().strip().lower()
            if addr and is_valid_mac(addr):
                return addr
    except Exception:
        pass

    rc, out = _run(f"macchanger -s {interface}", debug=False)
    if rc == 0 and out:
        m = re.search(r"Permanent MAC:\s+([0-9a-fa-f:]+)", out, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return get_current_mac(interface)


def get_attack_mac(interface: str) -> str:
    """
    Returns the MAC address to use for attack operations.
    If get_use_original_mac() is True (flag -m supplied), returns original hardware MAC.
    Otherwise, returns a newly generated random MAC address.
    """
    if get_use_original_mac():
        perm = get_permanent_mac(interface)
        if perm:
            trace(f"[FEATURE] Attack MAC mode: ORIGINAL MAC ({perm}) requested via -m flag.")
            return perm
    rand_mac = generate_random_mac()
    trace(f"[FEATURE] Attack MAC mode: RANDOM MAC ({rand_mac}) generated for attack.")
    return rand_mac


def set_mac_address(interface: str, mac: str, profile: str | None = None) -> bool:
    """
    Changes the MAC address of an interface using NetworkManager's nmcli cloned-mac-address property.
    If NetworkManager profile is not provided, attempts to auto-detect the active Wi-Fi profile.
    Falls back to ip link set address and macchanger if NetworkManager is unavailable or profile is missing.
    """
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.ui.console import log_step, log_wait
    trace(f"[FEATURE] Setting MAC address on {interface} to {mac} (Profile: {profile or 'Auto'})")
    log_step(f"Setting MAC {mac} on {interface}...")

    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", mac], debug=False)
        if rc == 0:
            log_wait(f"Reconnecting profile '{profile}' with MAC {mac}...")
            _run(f"ip link set dev {interface} up", debug=False)
            rc_up, _ = _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)
            if rc_up == 0 or wait_for_carrier(interface, timeout=6.0):
                return True
            # Retry connection after wifi rescan without tearing down the interface
            log_wait("Rescanning Wi-Fi & retrying reconnect...")
            _run(["nmcli", "device", "wifi", "rescan"], debug=False)
            rc_up2, _ = _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)
            if rc_up2 == 0 or wait_for_carrier(interface, timeout=6.0):
                return True

    # Fallback method (only when NM profile is absent/unavailable): manual link down -> address change -> link up
    log_wait(f"Applying manual MAC change -> {mac}...")
    _run(f"ip link set dev {interface} down", debug=False)
    rc_ip, _ = _run(f"ip link set dev {interface} address {mac}", debug=False)
    rc_mc, _ = _run(f"macchanger -m {mac} {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)
    wait_for_carrier(interface, timeout=6.0)

    if profile:
        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
        _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)

    return rc_ip == 0 or rc_mc == 0


def reset_mac_address(interface: str, profile: str | None = None) -> bool:
    """Resets the MAC address of a connection profile back to default hardware MAC."""
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.ui.console import log_step, log_wait
    trace(f"[FEATURE] Resetting MAC address on {interface} to hardware default (Profile: {profile or 'Auto'})")
    log_step(f"Resetting MAC to HW default on {interface}...")

    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""], debug=False)
        log_wait(f"Reconnecting profile '{profile}'...")
        rc_up, _ = _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)
        if rc_up == 0 or wait_for_carrier(interface, timeout=6.0):
            return True

    # Fallback to manual link down -> macchanger -p -> link up
    log_wait("Restoring hardware MAC via macchanger...")
    _run(f"ip link set dev {interface} down", debug=False)
    rc_mc, _ = _run(f"macchanger -p {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)
    wait_for_carrier(interface, timeout=6.0)

    if profile:
        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
        _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)

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
