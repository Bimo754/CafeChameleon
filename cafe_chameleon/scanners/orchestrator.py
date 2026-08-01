from cafe_chameleon.scanners.passive_scanner import passive_sniff_subnet
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from cafe_chameleon.scanners.nmap_scanner import nmap_scan_subnet
from cafe_chameleon.ui.console import set_scan_status, log_scan


def deep_scan_subnet(subnet_cidr, interface: str, gateway_ip: str | None = None, gateway_mac: str | None = None, local_ip: str | None = None, local_mac: str | None = None, duration: int = 30) -> list[dict]:
    """
    Combines:
    1. 30-second passive traffic sniffing
    2. Active Scapy ARP scan
    3. Fast Nmap TCP SYN user endpoint scan
    Filters out local host and router/gateway infrastructure to return ONLY user devices.
    """
    hosts_map = {}
    set_scan_status(subnet=subnet_cidr, count=0, scan_type="Passive Traffic Sniffing (30s)")
    log_scan(f"[*] Starting Passive Traffic Sniffing on {subnet_cidr}...")

    # Phase 1: Passive traffic capture
    passive_hosts = passive_sniff_subnet(subnet_cidr, interface, duration=duration)
    for h in passive_hosts:
        hosts_map[h["ip"]] = h["mac"]

    set_scan_status(subnet=subnet_cidr, count=len(hosts_map), scan_type="Active Scapy ARP Probe")
    log_scan(f"[+] Passive scan complete ({len(passive_hosts)} hosts). Dispatching ARP Probes...")

    # Phase 2: Active Scapy ARP scan
    active_hosts = scan_subnet(subnet_cidr, interface)
    for h in active_hosts:
        hosts_map[h["ip"]] = h["mac"]

    set_scan_status(subnet=subnet_cidr, count=len(hosts_map), scan_type="Fast Nmap SYN Scan")
    log_scan(f"[+] ARP scan complete ({len(active_hosts)} hosts). Dispatching Nmap Endpoint Sweep...")

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
        if mac_lower.startswith("01:00:5e") or mac_lower.startswith("33:33") or mac_lower.startswith("00:00:5e"):
            continue
        if gw_mac_clean and len(gw_mac_clean) >= 14 and len(mac_lower) >= 14:
            if mac_lower[:14] == gw_mac_clean[:14]:
                continue
        user_hosts.append({"ip": ip, "mac": mac})

    set_scan_status(subnet=subnet_cidr, count=len(user_hosts), scan_type="Completed")
    log_scan(f"\n[+] Deep Scan Complete: Identified {len(user_hosts)} active user device(s).")
    for idx, h in enumerate(user_hosts, 1):
        log_scan(f"  [{idx}] IP: \033[1;32m{h['ip']:<16}\033[0m MAC: \033[1;36m{h['mac']}\033[0m")

    return user_hosts
