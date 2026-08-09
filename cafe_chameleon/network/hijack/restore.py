"""
cafe_chameleon.network.hijack.restore - Fast network restoration procedure.
"""

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_plus, log_step, log_wait
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.nmcli import get_active_profile
from cafe_chameleon.network.mac import reset_mac_address
from cafe_chameleon.network.arp import send_gratuitous_arp


def restore(interface: str, macaddress: str, ipmask: str, broadcast: str, gateway: str, profile: str | None = None) -> None:
    """Refined, fast network restoration procedure with link carrier synchronization and full NM cleanup."""
    trace(f"[FEATURE] Restoring network configuration on interface {interface} to MAC {macaddress}, IP {ipmask}, GW {gateway}")
    log_step(f"Restoring HW MAC & network settings on {interface}...")

    from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
    if is_monitor_mode_active(interface):
        log_wait(f"Restoring {interface} from monitor mode to managed mode...")
        set_managed_mode(interface)

    active_profile = profile or get_active_profile()
    if active_profile:
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.bssid", ""], debug=False)
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.cloned-mac-address", ""], debug=False)

    reset_mac_address(interface, profile=active_profile)

    _run(f"ip link set dev {interface} down", debug=False)
    _run(f"macchanger -p {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)

    log_wait("Synchronizing adapter link...")
    wait_for_carrier(interface, timeout=4.0)

    try:
        _run(f"ip addr flush dev {interface}")
        _run(f"ip addr add {ipmask} broadcast {broadcast} dev {interface}")
    except Exception:
        pass

    try:
        _run(f"ip route flush dev {interface}")
        if gateway:
            _run(f"ip route replace default via {gateway} dev {interface} onlink")
    except Exception:
        pass

    if active_profile:
        log_wait(f"Reconnecting profile '{active_profile}'...")
        _run(["nmcli", "connection", "up", active_profile], debug=False, timeout=15.0)

    local_ip_only = ipmask.split("/")[0] if "/" in ipmask else ipmask
    if gateway and local_ip_only:
        try:
            send_gratuitous_arp(interface, local_ip_only, gateway)
        except Exception:
            pass

    log_plus("Restored original network configuration.")
