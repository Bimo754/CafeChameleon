"""
cafe_chameleon.scanners.resolver.listener - Passive multicast & broadcast traffic listener for MAC resolution.
"""

from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from .kernel_cache import is_valid_ipv4


def listen_passive_traffic(mac_clean: str, interface: str, timeout: int = 3, target_subnet: str | None = None) -> str | None:
    try:
        set_hijack_status(ip=None, mac=mac_clean, technique="Passive Traffic Listener", clear_section2=True)
        log_hijack(f"[*] Listening for broadcast/multicast packets ({timeout}s)...")
        trace(f"[*] Resolving {mac_clean} -> Passive Listener ({timeout}s)...")
        from scapy.all import sniff, Ether, IP, ARP, BOOTP
        sniffed_ip = [None]

        def passive_mac_callback(pkt):
            if sniffed_ip[0]:
                return
            src_mac = None
            dst_mac = None

            if pkt.haslayer(Ether):
                src_mac = str(pkt[Ether].src).lower() if pkt[Ether].src else None
                dst_mac = str(pkt[Ether].dst).lower() if pkt[Ether].dst else None
            elif pkt.haslayer(ARP):
                src_mac = str(pkt[ARP].hwsrc).lower() if pkt[ARP].hwsrc else None
                dst_mac = str(pkt[ARP].hwdst).lower() if pkt[ARP].hwdst else None

            cand_ip = None
            if src_mac == mac_clean:
                # Target is transmitting
                if pkt.haslayer(ARP):
                    psrc = str(pkt[ARP].psrc) if hasattr(pkt[ARP], "psrc") else None
                    if is_valid_ipv4(psrc, subnet_cidr=target_subnet):
                        cand_ip = psrc
                elif pkt.haslayer(IP):
                    ip_src = str(pkt[IP].src) if hasattr(pkt[IP], "src") else None
                    ip_dst = str(pkt[IP].dst) if hasattr(pkt[IP], "dst") else None
                    if is_valid_ipv4(ip_src, subnet_cidr=target_subnet):
                        cand_ip = ip_src
                    elif is_valid_ipv4(ip_dst, subnet_cidr=target_subnet):
                        cand_ip = ip_dst
                elif BOOTP and pkt.haslayer(BOOTP):
                    bootp = pkt[BOOTP]
                    ciaddr = str(bootp.ciaddr) if hasattr(bootp, "ciaddr") else None
                    yiaddr = str(bootp.yiaddr) if hasattr(bootp, "yiaddr") else None
                    if is_valid_ipv4(ciaddr, subnet_cidr=target_subnet):
                        cand_ip = ciaddr
                    elif is_valid_ipv4(yiaddr, subnet_cidr=target_subnet):
                        cand_ip = yiaddr
            elif dst_mac == mac_clean:
                # Target is receiving
                if pkt.haslayer(ARP):
                    pdst = str(pkt[ARP].pdst) if hasattr(pkt[ARP], "pdst") else None
                    if is_valid_ipv4(pdst, subnet_cidr=target_subnet):
                        cand_ip = pdst
                elif pkt.haslayer(IP):
                    ip_dst = str(pkt[IP].dst) if hasattr(pkt[IP], "dst") else None
                    ip_src = str(pkt[IP].src) if hasattr(pkt[IP], "src") else None
                    if is_valid_ipv4(ip_dst, subnet_cidr=target_subnet):
                        cand_ip = ip_dst
                    elif is_valid_ipv4(ip_src, subnet_cidr=target_subnet):
                        cand_ip = ip_src

            if cand_ip and is_valid_ipv4(cand_ip, subnet_cidr=target_subnet):
                sniffed_ip[0] = cand_ip

        sniff(iface=interface, timeout=timeout, prn=passive_mac_callback, store=False)
        if sniffed_ip[0]:
            set_hijack_status(ip=sniffed_ip[0], mac=mac_clean, technique="Passive Listener")
            log_hijack(f"\033[92m[+] IP resolved via passive listening -> {sniffed_ip[0]}\033[0m")
            return sniffed_ip[0]
    except Exception:
        pass
    return None
