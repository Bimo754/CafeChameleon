"""
cafe_chameleon.scanners.resolver.listener - Passive multicast & broadcast traffic listener for MAC resolution.
"""

from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from .kernel_cache import is_valid_ipv4


def listen_passive_traffic(mac_clean: str, interface: str, timeout: int = 3) -> str | None:
    try:
        set_hijack_status(ip=None, technique="Passive Traffic Listener", clear_section2=True)
        log_hijack(f"[*] Listening for broadcast/multicast packets ({timeout}s)...")
        trace(f"[*] Resolving {mac_clean} -> Passive Listener ({timeout}s)...")
        from scapy.all import sniff, Ether, IP, ARP, BOOTP
        sniffed_ip = [None]

        def passive_mac_callback(pkt):
            if sniffed_ip[0]:
                return
            src_mac = None
            src_ip = None

            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.lower()
            elif pkt.haslayer(ARP):
                src_mac = pkt[ARP].hwsrc.lower()

            if src_mac == mac_clean:
                if pkt.haslayer(ARP):
                    src_ip = str(pkt[ARP].psrc)
                elif pkt.haslayer(IP):
                    src_ip = str(pkt[IP].src)
                elif BOOTP and pkt.haslayer(BOOTP):
                    bootp = pkt[BOOTP]
                    if hasattr(bootp, "ciaddr") and str(bootp.ciaddr) not in ("0.0.0.0", "255.255.255.255"):
                        src_ip = str(bootp.ciaddr)
                    elif hasattr(bootp, "yiaddr") and str(bootp.yiaddr) not in ("0.0.0.0", "255.255.255.255"):
                        src_ip = str(bootp.yiaddr)

                if src_ip and is_valid_ipv4(src_ip):
                    sniffed_ip[0] = src_ip

        sniff(iface=interface, timeout=timeout, prn=passive_mac_callback, store=False)
        if sniffed_ip[0]:
            set_hijack_status(ip=sniffed_ip[0], technique="Passive Listener")
            log_hijack(f"\033[92m[+] IP resolved via passive listening -> {sniffed_ip[0]}\033[0m")
            return sniffed_ip[0]
    except Exception:
        pass
    return None
