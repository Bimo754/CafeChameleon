"""
cafe_chameleon.scanners.passive_scanner - Passive broadcast/multicast traffic sniffer.
"""

import ipaddress
from cafe_chameleon.ui.console import log_scan
from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4


def passive_sniff_subnet(subnet_cidr, interface: str, duration: int = 30) -> list[dict]:
    """
    Passively sniffs traffic on the interface for `duration` seconds.
    Extracts source IP and MAC addresses from background broadcast/multicast/ARP/IP traffic.
    Ignores public internet IPs and invalid endpoints.
    """
    try:
        from scapy.all import sniff, IP, ARP, Ether
    except ImportError:
        log_scan("[-] scapy is required for passive sniffing. Install with: pip install scapy")
        return []

    log_scan(f"Passively sniffing traffic on {interface} ({duration}s)...")
    try:
        target_net = ipaddress.ip_network(str(subnet_cidr), strict=False)
    except ValueError:
        return []

    discovered = {}

    def packet_callback(pkt):
        src_ip = None
        src_mac = None
        dst_ip = None
        dst_mac = None

        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            src_ip = str(arp_layer.psrc) if arp_layer.psrc else None
            src_mac = str(arp_layer.hwsrc).lower() if arp_layer.hwsrc else None
            dst_ip = str(arp_layer.pdst) if arp_layer.pdst else None
            dst_mac = str(arp_layer.hwdst).lower() if arp_layer.hwdst else None
        elif pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = str(ip_layer.src) if ip_layer.src else None
            dst_ip = str(ip_layer.dst) if ip_layer.dst else None
            if pkt.haslayer(Ether):
                src_mac = str(pkt[Ether].src).lower() if pkt[Ether].src else None
                dst_mac = str(pkt[Ether].dst).lower() if pkt[Ether].dst else None

        for ip_cand, mac_cand in ((src_ip, src_mac), (dst_ip, dst_mac)):
            if ip_cand and mac_cand:
                if mac_cand in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or mac_cand.startswith("01:00:5e") or mac_cand.startswith("33:33") or mac_cand.startswith("00:00:5e"):
                    continue
                if is_valid_ipv4(ip_cand, subnet_cidr=str(target_net)):
                    if ip_cand not in discovered:
                        discovered[ip_cand] = mac_cand

    try:
        bpf_filter = "arp or (ip and (broadcast or multicast))"
        try:
            sniff(iface=interface, filter=bpf_filter, timeout=duration, prn=packet_callback, store=False)
        except Exception:
            sniff(iface=interface, timeout=duration, prn=packet_callback, store=False)
    except Exception as e:
        log_scan(f"[-] Passive sniffing exception on {interface}: {e}")

    log_scan(f"Passive sniff complete: Found {len(discovered)} active host(s).")
    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]
