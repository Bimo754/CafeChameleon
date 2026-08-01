"""
cafe_chameleon.scanners.arp_scanner - Active Layer 2 Scapy ARP subnet scanner.
"""

import sys

from cafe_chameleon.ui.console import log_scan
from cafe_chameleon.utils.process import _run


def scan_subnet(subnet_cidr, interface: str, silent: bool = False) -> list[dict]:
    """
    Multi-stage active Layer 2/3 subnet scanner.
    Sends ARP requests, ICMP/UDP probes, inspects kernel neighbor cache,
    and runs fast Nmap sweeps to discover all active targets.
    """
    try:
        from scapy.all import Ether, ARP, srp
    except ImportError:
        if not silent:
            log_scan("[-] scapy is required for subnet scanning. Install with: pip install scapy")
        sys.exit(1)

    import ipaddress
    import os
    import re
    import shutil
    import socket
    import concurrent.futures
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.scanners.nmap_scanner import nmap_scan_subnet

    # Ensure link carrier is UP before sending raw Scapy frames
    _run(f"ip link set dev {interface} up", debug=False)
    wait_for_carrier(interface, timeout=5.0)

    discovered = {}  # ip -> mac
    target_net = ipaddress.ip_network(str(subnet_cidr), strict=False)

    def harvest_kernel_neighbors():
        try:
            rc, out = _run(["ip", "-4", "neighbor", "show", "dev", interface], debug=False)
            if out:
                for line in out.splitlines():
                    m = re.search(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fa-f:]+)", line, re.IGNORECASE)
                    if m:
                        ip_str, mac_str = m.group(1), m.group(2).lower()
                        if mac_str != "00:00:00:00:00:00":
                            try:
                                if ipaddress.ip_address(ip_str) in target_net:
                                    discovered[ip_str] = mac_str
                            except ValueError:
                                pass
            if os.path.exists("/proc/net/arp"):
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_str, mac_str = parts[0], parts[3].lower()
                            if mac_str != "00:00:00:00:00:00":
                                try:
                                    if ipaddress.ip_address(ip_str) in target_net:
                                        discovered[ip_str] = mac_str
                                except ValueError:
                                    pass
        except Exception:
            pass

    # 1. Harvest existing kernel neighbor cache & /proc/net/arp
    harvest_kernel_neighbors()

    # 2. Scapy Layer 2 ARP Broadcast Sweep
    arp_req = ARP(pdst=str(subnet_cidr))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    try:
        answered, _ = srp(packet, timeout=2, iface=interface, verbose=False)
        for sent, received in answered:
            discovered[received.psrc] = received.hwsrc.lower()
    except PermissionError:
        if not silent:
            log_scan("[-] Permission denied. Root privileges required to send raw packets.")
        sys.exit(1)
    except OSError:
        _run(f"ip link set dev {interface} up", debug=False)
        if wait_for_carrier(interface, timeout=5.0):
            try:
                answered, _ = srp(packet, timeout=2, iface=interface, verbose=False)
                for sent, received in answered:
                    discovered[received.psrc] = received.hwsrc.lower()
            except Exception:
                pass
        elif not silent:
            log_scan(f"[-] Interface {interface} is currently unavailable.")

    # 3. Concurrent Socket Probe Sweep to force kernel ARP resolution for silent/unicast hosts
    hosts_to_probe = [str(h) for h in target_net.hosts() if str(h) not in discovered]
    if hosts_to_probe:
        def probe_target(ip_str):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.1)
                s.sendto(b"\x00", (ip_str, 80))
                s.close()
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(probe_target, hosts_to_probe)

        harvest_kernel_neighbors()

    # 4. Nmap Ping / SYN Sweep fallback if nmap is available
    if shutil.which("nmap"):
        try:
            nmap_results = nmap_scan_subnet(subnet_cidr, interface)
            for h in nmap_results:
                discovered[h["ip"]] = h["mac"].lower()
        except Exception:
            pass

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]

