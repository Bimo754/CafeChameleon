"""
cafe_chameleon.network.sysfs - Linux sysfs network carrier polling & interface link readiness verification.
"""

import os
import time

from cafe_chameleon.utils.process import _run


def get_carrier_status(interface: str) -> bool:
    """
    Checks the Linux sysfs interface carrier and operstate.
    Returns True if carrier is detected (sysfs carrier == 1 or operstate in ['up', 'unknown']).
    """
    carrier_path = f"/sys/class/net/{interface}/carrier"
    operstate_path = f"/sys/class/net/{interface}/operstate"

    if os.path.exists(carrier_path):
        try:
            with open(carrier_path, "r") as f:
                val = f.read().strip()
                if val == "1":
                    return True
        except Exception:
            pass

    if os.path.exists(operstate_path):
        try:
            with open(operstate_path, "r") as f:
                val = f.read().strip().lower()
                if val in ("up", "unknown"):
                    return True
        except Exception:
            pass

    # Fallback to ip link command check
    rc, out = _run(f"ip link show dev {interface}", debug=False)
    if rc == 0 and ("LOWER_UP" in out or "state UP" in out or "state UNKNOWN" in out):
        return True

    return False


def wait_for_carrier(interface: str, timeout: float = 5.0, poll_interval: float = 0.05) -> bool:
    """
    Polls sysfs carrier status until the interface hardware link becomes ready
    or timeout expires. Returns True if carrier detected, False on timeout.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if get_carrier_status(interface):
            return True
        time.sleep(poll_interval)
    return get_carrier_status(interface)

