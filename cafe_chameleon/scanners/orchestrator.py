"""
cafe_chameleon.scanners.orchestrator - Deep scanner orchestration combining passive, active ARP, and Nmap scans.
"""

from cafe_chameleon.scanners.passive_scanner import passive_sniff_subnet
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from cafe_chameleon.scanners.nmap_scanner import nmap_scan_subnet


def deep_scan_subnet(subnet_cidr, interface: str, gateway_ip: str | None = None, gateway_mac: str | None = None, local_ip: str | None = None, local_mac: str | None = None, duration: int = 30) -> list[dict]:
    """
    Combines:
    1. 30-second passive traffic sniffing
    2. Active Scapy ARP scan
    3. Fast Nmap TCP SYN user endpoint scan
    Filters out local host and router/gateway infrastructure to return ONLY user devices.
    """
    hosts_map = {}

    # Phase 1: Passive traffic capture
    passive_hosts = passive_sniff_subnet(subnet_cidr, interface, duration=duration)
    for h in passive_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 2: Active Scapy ARP scan
    active_hosts = scan_subnet(subnet_cidr, interface)
    for h in active_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 3: Nmap user endpoint scan
    nmap_hosts = nmap_scan_subnet(subnet_cidr, interface)
    for h in nmap_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 4: Filter out Gateway & Local Host (User Devices Only)
    user_hosts = []
    gw_ip_clean = (gateway_ip or "").strip()
    gw_mac_clean = (gateway_mac or "").strip().lower()
    local_ip_clean = (local_ip or "").strip()
    local_mac_clean = (local_mac or "").strip().lower()

    for ip, mac in hosts_map.items():
        mac_lower = mac.lower()
        if gw_ip_clean and ip == gw_ip_clean:
            continue
        if gw_mac_clean and mac_lower == gw_mac_clean:
            continue
        if local_ip_clean and ip == local_ip_clean:
            continue
        if local_mac_clean and mac_lower == local_mac_clean:
            continue
        user_hosts.append({"ip": ip, "mac": mac})

    return user_hosts
