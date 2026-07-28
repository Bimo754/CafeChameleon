"""
cafe_chameleon.scanners.passive_scanner - Passive broadcast/multicast traffic sniffer.
"""

import ipaddress

from cafe_chameleon.ui.console import log_scan


def passive_sniff_subnet(subnet_cidr, interface: str, duration: int = 30) -> list[dict]:
    """
    Passively sniffs traffic on the interface for `duration` seconds.
    Extracts source IP and MAC addresses from background broadcast/multicast/ARP/IP traffic.
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

        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
        elif pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src

        if src_ip and src_mac:
            src_mac = src_mac.lower()
            if src_ip in ("0.0.0.0", "255.255.255.255") or src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                return
            if src_mac.startswith("01:00:5e") or src_mac.startswith("33:33"):
                return

            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj in target_net and not ip_obj.is_multicast and not ip_obj.is_loopback:
                    if src_ip not in discovered:
                        discovered[src_ip] = src_mac
            except ValueError:
                pass

    try:
        sniff(iface=interface, timeout=duration, prn=packet_callback, store=False)
    except Exception as e:
        log_scan(f"[-] Passive sniffing exception on {interface}: {e}")

    log_scan(f"Passive sniff complete: Found {len(discovered)} active host(s).")
    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]
