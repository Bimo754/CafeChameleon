"""
cafe_chameleon.network.mac - MAC address validation, random generation, and NetworkManager hardware address spoofing.
"""

import random
import re

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.state import get_use_original_mac
from cafe_chameleon.utils.tracing import trace

MAC_VALID_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
PERM_MAC_REGEX = re.compile(r"Permanent MAC:\s+([0-9a-fa-f:]+)", re.IGNORECASE)
CURR_MAC_REGEX = re.compile(r"Current MAC:\s+([0-9a-fa-f:]+)", re.IGNORECASE)


def is_valid_mac(val: str) -> bool:
    """Returns True if val is a valid 6-byte hexadecimal MAC address string."""
    return bool(MAC_VALID_REGEX.match(val)) if val else False


def generate_random_mac() -> str:
    """Generates a random unicast, locally-administered MAC address across all 64 valid prefixes."""
    first_byte = (random.randint(0, 15) << 4) | random.choice([0x02, 0x06, 0x0A, 0x0E])
    rest = [random.randint(0, 255) for _ in range(5)]
    mac_bytes = [first_byte] + rest
    return ":".join(f"{b:02x}" for b in mac_bytes)


def get_permanent_mac(interface: str) -> str | None:
    """Gets the original hardware permanent MAC address of an interface."""
    try:
        with open(f"/sys/class/net/{interface}/perm_addr", "r") as f:
            addr = f.read().strip().lower()
            if addr and is_valid_mac(addr) and addr != "00:00:00:00:00:00":
                return addr
    except Exception:
        pass

    rc, out = _run(["macchanger", "-s", interface], debug=False)
    if rc == 0 and out:
        m = PERM_MAC_REGEX.search(out)
        if m and is_valid_mac(m.group(1)) and m.group(1).lower() != "00:00:00:00:00:00":
            return m.group(1).lower()

    rc, out = _run(["ethtool", "-P", interface], debug=False)
    if rc == 0 and out:
        m = re.search(r"Permanent address:\s+([0-9a-fa-f:]+)", out, re.IGNORECASE)
        if m and is_valid_mac(m.group(1)) and m.group(1).lower() != "00:00:00:00:00:00":
            return m.group(1).lower()

    rc, out = _run(["nmcli", "-t", "-f", "GENERAL.PERM-HWADDR", "dev", "show", interface], debug=False)
    if rc == 0 and out:
        val = out.replace("GENERAL.PERM-HWADDR:", "").strip().lower()
        if is_valid_mac(val) and val != "00:00:00:00:00:00":
            return val

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
    Changes the MAC address of an interface using macchanger / ip link directly on kernel netdevice
    and updates NetworkManager's cloned-mac-address property.
    """
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.ui.console import log_step, log_wait, log_plus, log_minus
    clean_mac = mac.lower()
    trace(f"[FEATURE] Setting MAC address on {interface} to {clean_mac} (Profile: {profile or 'Auto'})")
    log_step(f"Setting MAC {clean_mac} on {interface}...")

    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", clean_mac], debug=False)

    log_wait(f"Applying MAC change on {interface} -> {clean_mac}...")
    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
    rc_ip, _ = _run(["ip", "link", "set", "dev", interface, "address", clean_mac], debug=False)
    rc_mc, _ = _run(["macchanger", "-m", clean_mac, interface], debug=False)
    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)
    wait_for_carrier(interface, timeout=6.0)

    if profile:
        log_wait(f"Reconnecting profile '{profile}'...")
        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
        _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)
        wait_for_carrier(interface, timeout=6.0)

    curr = get_current_mac(interface)
    success = bool((curr and curr.lower() == clean_mac) or rc_ip == 0 or rc_mc == 0)
    if success:
        log_plus(f"MAC address changed to {clean_mac} on {interface}.", verbose_only=True)
    else:
        log_minus(f"Failed to change MAC address to {clean_mac} on {interface}.", force=True)
    return success


def reset_mac_address(interface: str, profile: str | None = None) -> bool:
    """Resets the MAC address of an interface and profile back to permanent hardware MAC."""
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.ui.console import log_step, log_wait, log_plus, log_minus
    perm_mac = get_permanent_mac(interface)
    trace(f"[FEATURE] Resetting MAC address on {interface} to permanent hardware default ({perm_mac or 'HW'})")
    log_step(f"Resetting MAC to HW default on {interface}...")

    if not profile:
        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            profile = get_active_profile()
        except Exception:
            profile = None

    if profile:
        _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""], debug=False)

    log_wait(f"Restoring permanent hardware MAC on {interface}...")
    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
    rc_mc, _ = _run(["macchanger", "-p", interface], debug=False)
    if perm_mac:
        _run(["ip", "link", "set", "dev", interface, "address", perm_mac], debug=False)
    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)
    wait_for_carrier(interface, timeout=6.0)

    if profile:
        log_wait(f"Reconnecting profile '{profile}'...")
        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
        _run(["nmcli", "connection", "up", profile], debug=False, timeout=15.0)
        wait_for_carrier(interface, timeout=6.0)

    curr = get_current_mac(interface)
    success = bool((curr and perm_mac and curr.lower() == perm_mac.lower()) or rc_mc == 0)
    if success:
        log_plus(f"MAC address reset to permanent HW default ({perm_mac or 'HW'}) on {interface}.", force=True)
    else:
        log_minus(f"Failed to reset MAC address on {interface}.", force=True)
    return success


def get_current_mac(interface: str) -> str | None:
    """Gets the current MAC address of an interface using sysfs, falling back to macchanger -s, ip link, or nmcli."""
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            addr = f.read().strip().lower()
            if addr and is_valid_mac(addr):
                return addr
    except Exception:
        pass

    rc, out = _run(["macchanger", "-s", interface], debug=False)
    if rc == 0 and out:
        m = CURR_MAC_REGEX.search(out)
        if m and is_valid_mac(m.group(1)):
            return m.group(1).lower()

    rc, out = _run(["ip", "-o", "link", "show", "dev", interface], debug=False)
    if rc == 0 and out:
        m = re.search(r"link/ether\s+([0-9a-fa-f:]+)", out, re.IGNORECASE)
        if m and is_valid_mac(m.group(1)):
            return m.group(1).lower()

    rc, out = _run(["nmcli", "-t", "-f", "GENERAL.HWADDR", "dev", "show", interface], debug=False)
    if rc == 0 and out:
        val = out.replace("GENERAL.HWADDR:", "").strip().lower()
        if is_valid_mac(val):
            return val

    return None

