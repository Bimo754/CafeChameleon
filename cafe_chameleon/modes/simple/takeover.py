"""
cafe_chameleon.modes.simple.takeover - Host impersonation testing loop for Simple mode.
"""

import time

from cafe_chameleon.utils.signals import HijackSkipInterrupt
from cafe_chameleon.ui.console import (
    log_scan,
    log_main,
    log_plus,
    log_hijack,
    set_scan_status,
    set_hijack_status
)
from cafe_chameleon.ui.prompts import ask_proceed, ask_restore
from cafe_chameleon.network.nmcli import get_active_security
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.hijack import hijack
from cafe_chameleon.scanners.resolver import is_valid_ipv4
from cafe_chameleon.utils.blacklist import is_blacklisted, load_blacklist


def test_discovered_hosts(unique_hosts: list[dict], interface: str, gw_ip: str, gw_mac: str, netmask: str, broadcast: str, local_mac: str, ipmask: str, profile: str | None, args) -> bool:
    """Iterates through discovered active hosts and attempts host impersonation/takeover."""
    set_scan_status(scan_type="Host Takeover")
    log_main("[*] Testing discovered hosts for internet access...")

    force_deauth = getattr(args, "force_deauth", False)
    no_gateway = getattr(args, "no_gateway", False)
    active_sec = getattr(args, "security", None) or get_active_security(profile=profile, interface=interface)
    blacklist = load_blacklist()

    for host in unique_hosts:
        try:
            if not is_valid_ipv4(host["ip"]):
                continue
            if is_blacklisted(host.get("mac", ""), blacklist):
                continue
            is_gw = (gw_ip and host["ip"] == gw_ip) or (gw_mac and host["mac"].lower() == gw_mac.lower())
            if not is_gw:
                log_hijack(f"[*] Impersonating host: IP {host['ip']} ({host['mac']})...")
                set_hijack_status(ip=host['ip'], mac=host['mac'], technique="Simple Impersonation Sweep", clear_section2=True)
                hijack_success = hijack(
                    interface, host['ip'], host['mac'], netmask, broadcast, gw_ip,
                    profile=profile, bssid=None, security=active_sec, force_deauth=force_deauth,
                    no_gateway=no_gateway
                )
                if hijack_success:
                    log_scan("[+] SUCCESS! Internet access established!")
                    log_main(f"\033[92m[+] SUCCESS! Internet active via {host['ip']} ({host['mac']})!\033[0m")
                    set_scan_status(scan_type="Internet Active")
                    if not getattr(args, "force", False):
                        return True

                if getattr(args, "force", False):
                    if not ask_proceed():
                        log_scan("[-] Stopped after impersonation.")
                        log_main("[-] Stopped after impersonation.")
                        has_acc = hijack_success or has_internet()
                        if ask_restore(default_restore=not has_acc):
                            from cafe_chameleon.network.nmcli import release_interface
                            release_interface(interface=interface, profile=profile)
                        else:
                            log_plus("Keeping current network config.")
                        set_hijack_status(ip=None, mac=None, technique="Idle")
                        return has_acc

                time.sleep(0.5)
        except HijackSkipInterrupt:
            log_scan(f"\033[93m[-] Skipping host {host['ip']} (Ctrl+C)...\033[0m")
            log_main(f"\033[93m[-] Skipping host {host['ip']} (Ctrl+C)...\033[0m")
            set_hijack_status(ip=None, mac=None, technique="Idle")
            continue

    set_hijack_status(ip=None, mac=None, technique="Idle")
    return False
