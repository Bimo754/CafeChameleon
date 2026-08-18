"""
cafe_chameleon.network.sysfs - Linux sysfs network carrier polling & interface link readiness verification.
"""

import os
import time

from cafe_chameleon.config import DEFAULT_CARRIER_TIMEOUT
from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_wait, log_step, log_warning


def get_carrier_status(interface: str) -> bool:
    """
    Checks the Linux sysfs interface carrier, operstate, and link readiness.
    Returns True if carrier is detected (sysfs carrier == 1, operstate in ['up', 'unknown', 'dormant'],
    or active link reported via iw/ip).
    """
    carrier_path = f"/sys/class/net/{interface}/carrier"
    operstate_path = f"/sys/class/net/{interface}/operstate"
    flags_path = f"/sys/class/net/{interface}/flags"

    if os.path.exists(carrier_path):
        try:
            with open(carrier_path, "r") as f:
                val = f.read().strip()
                if val == "1":
                    return True
        except (OSError, IOError):
            pass

    if os.path.exists(operstate_path):
        try:
            with open(operstate_path, "r") as f:
                val = f.read().strip().lower()
                # 'dormant' is standard for 802.1X / wpa_supplicant managed wireless links
                if val in ("up", "unknown", "dormant"):
                    return True
        except (OSError, IOError):
            pass

    if os.path.exists(flags_path):
        try:
            with open(flags_path, "r") as f:
                val = f.read().strip()
                flags = int(val, 0)
                # IFF_RUNNING (0x40) or (IFF_UP 0x1 and IFF_BROADCAST 0x2)
                if (flags & 0x40) != 0 or (flags & 0x1) != 0:
                    rc_iw, iw_out = _run(["iw", "dev", interface, "link"], debug=False)
                    if rc_iw == 0 and ("Connected to" in iw_out or "associated" in iw_out.lower()):
                        return True
        except (OSError, IOError, ValueError):
            pass

    rc, iw_out = _run(["iw", "dev", interface, "link"], debug=False)
    if rc == 0 and ("Connected to" in iw_out or "associated" in iw_out.lower()):
        return True

    rc, out = _run(["ip", "link", "show", "dev", interface], debug=False)
    if rc == 0 and ("LOWER_UP" in out or "state UP" in out or "state UNKNOWN" in out or "state DORMANT" in out) and "NO-CARRIER" not in out:
        return True

    return False


def wait_for_carrier(interface: str, timeout: float = DEFAULT_CARRIER_TIMEOUT, poll_interval: float = 0.05) -> bool:
    """
    Polls sysfs carrier status until the interface hardware link becomes ready
    or timeout expires. Returns True if carrier detected, False on timeout.
    """
    if get_carrier_status(interface):
        return True

    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    log_wait(f"Syncing link carrier on {interface}...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        if get_carrier_status(interface):
            log_step(f"Carrier active on {interface}.")
            return True
        time.sleep(poll_interval)
    
    ok = get_carrier_status(interface)
    if ok:
        log_step(f"Carrier active on {interface}.")
    else:
        log_warning(f"Carrier wait timeout ({timeout:.1f}s) on {interface}.")
    return ok
