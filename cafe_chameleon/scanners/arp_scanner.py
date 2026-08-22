"""
cafe_chameleon.scanners.arp_scanner - High-efficiency active Scapy broadcast ARP scanner.
"""

import ipaddress
from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4
from cafe_chameleon.scanners.nmap_scanner import nmap_scan_subnet
from cafe_chameleon.ui.console import log_scan


def scan_subnet(
    subnet_cidr,
    interface: str,
    gateway_ip: str | None = None,
    gateway_mac: str | None = None,
    timeout: float = 2.0
) -> list[dict]:
    """
    Executes a fast, direct Scapy broadcast ARP sweep over the subnet to force all
    connected endpoints (including silent mobile devices) to reply with ARP responses.
    Merges results with Nmap ping scan to guarantee maximum discovery.
    """
    discovered = {}  # ip -> mac

    if gateway_ip and gateway_mac and gateway_mac != "00:00:00:00:00:00":
        if is_valid_ipv4(gateway_ip, subnet_cidr=str(subnet_cidr)):
            discovered[gateway_ip] = gateway_mac.lower()

    try:
        from scapy.all import srp, Ether, ARP
        target_net_str = str(subnet_cidr)

        # Build broadcast ARP request packet targeting all host IPs in the subnet
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_net_str)
        ans, _ = srp(pkt, iface=interface, timeout=timeout, verbose=False, retry=1)

        for snd, rcv in ans:
            if rcv.haslayer(ARP):
                ip_src = str(rcv[ARP].psrc) if hasattr(rcv[ARP], "psrc") else None
                mac_src = str(rcv[ARP].hwsrc).lower() if hasattr(rcv[ARP], "hwsrc") else None
                if ip_src and mac_src and mac_src != "00:00:00:00:00:00":
                    if is_valid_ipv4(ip_src, subnet_cidr=target_net_str):
                        discovered[ip_src] = mac_src
    except Exception as e:
        log_scan(f"[-] Scapy ARP scan warning on {interface}: {e}")

    # Harvest / merge with Nmap scan to guarantee comprehensive results
    nmap_results = nmap_scan_subnet(subnet_cidr, interface, gateway_ip=gateway_ip, gateway_mac=gateway_mac, silent=True)
    for host in nmap_results:
        discovered.setdefault(host["ip"], host["mac"].lower())

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]


arp_scan_subnet = scan_subnet

