"""
cafe_chameleon.scanners.resolver.sweep - Active Layer 3 subnet sweep and ARP fallback scanner trigger.
"""

import ipaddress
import shutil

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from .kernel_cache import check_kernel_cache, is_valid_ipv4


def sweep_l3_and_fallback(mac_clean: str, interface: str, target_subnet: str | None) -> str | None:
    if not target_subnet:
        return None

    try:
        set_hijack_status(ip=None, technique="Subnet L3 Sweep", clear_section2=True)
        log_hijack("[*] Performing L3 subnet sweep to trigger ARP responses...")
        trace(f"[*] Resolving {mac_clean} -> Subnet L3 Sweep...")
        net_obj = ipaddress.ip_network(target_subnet, strict=False)
        sweep_target = str(net_obj)
        if net_obj.prefixlen < 24:
            sweep_target = f"{net_obj.network_address}/24"

        if shutil.which("nmap"):
            cmd = [
                "nmap", "-sn", "-PE", "-PS80,443,8080,53", "-PU53,137,5353",
                "--min-rate", "400", "-n", "-e", interface, sweep_target
            ]
            _run(cmd, debug=False)
        else:
            import socket
            import concurrent.futures

            def probe_ip(ip_str):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.05)
                    s.sendto(b"\x00", (ip_str, 80))
                    s.close()
                except Exception:
                    pass

            hosts_list = list(net_obj.hosts())[:254]
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                executor.map(probe_ip, [str(h) for h in hosts_list])
    except Exception:
        pass

    log_hijack("[*] Re-checking kernel neighbor table after L3 sweep...")
    ip_found = check_kernel_cache(mac_clean, interface)
    if ip_found:
        set_hijack_status(ip=ip_found, technique="Post-Sweep Cache")
        log_hijack(f"\033[92m[+] IP found in post-sweep kernel cache -> {ip_found}\033[0m")
        return ip_found

    set_hijack_status(ip=None, technique="ARP Scan Fallback", clear_section2=True)
    log_hijack("[*] Running Scapy ARP scan fallback...")
    trace(f"[*] Resolving {mac_clean} -> ARP Scan Fallback...")
    hosts = scan_subnet(target_subnet, interface, silent=True)
    for h in hosts:
        if h["mac"].lower() == mac_clean and is_valid_ipv4(h["ip"]):
            set_hijack_status(ip=h["ip"], technique="ARP Scan Fallback")
            log_hijack(f"\033[92m[+] IP resolved via ARP scan fallback -> {h['ip']}\033[0m")
            return h["ip"]

    return None
