"""
cafe_chameleon.scanners.resolver.probes - Active Layer 2 Unicast ARP, Layer 3 TCP SYN, and DHCP Inform probes.
"""

import random

from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from .kernel_cache import is_valid_ipv4


def probe_unicast_arp(mac_clean: str, candidate_ips: list[str], interface: str, target_subnet: str | None = None) -> str | None:
    if not candidate_ips:
        return None
    try:
        set_hijack_status(ip=None, technique="Unicast ARP Probe", clear_section2=True)
        log_hijack(f"[*] Transmitting L2 unicast ARP probes across {len(candidate_ips)} IP candidates...")
        trace(f"[*] Resolving {mac_clean} -> Unicast ARP Probe...")
        from scapy.all import Ether, ARP, srp
        unicast_arp_pkts = [
            Ether(dst=mac_clean) / ARP(op=1, pdst=ip)
            for ip in candidate_ips
        ]
        ans, _ = srp(unicast_arp_pkts, timeout=1.5, iface=interface, verbose=False)
        for sent, rcv in ans:
            if rcv.haslayer(ARP) and rcv[ARP].op == 2 and rcv[ARP].hwsrc.lower() == mac_clean:
                res_ip = str(rcv[ARP].psrc)
                if is_valid_ipv4(res_ip, subnet_cidr=target_subnet):
                    set_hijack_status(ip=res_ip, technique="Unicast ARP Probe")
                    log_hijack(f"\033[92m[+] IP resolved via L2 Unicast ARP -> {res_ip}\033[0m")
                    return res_ip
    except Exception:
        pass
    return None


def probe_tcp_syn(mac_clean: str, candidate_ips: list[str], interface: str, target_subnet: str | None = None) -> str | None:
    if not candidate_ips:
        return None
    try:
        set_hijack_status(ip=None, technique="L3 TCP SYN Probe", clear_section2=True)
        log_hijack("[*] Injecting direct L3 TCP SYN frames (Port 80/445)...")
        trace(f"[*] Resolving {mac_clean} -> L3 TCP SYN Probe...")
        from scapy.all import Ether, IP, TCP, srp
        tcp_syn_pkts = [
            Ether(dst=mac_clean) / IP(dst=ip) / TCP(dport=80, flags="S")
            for ip in candidate_ips
        ]
        ans_tcp, _ = srp(tcp_syn_pkts, timeout=1.5, iface=interface, verbose=False)
        for sent, rcv in ans_tcp:
            if rcv.haslayer(Ether) and rcv[Ether].src.lower() == mac_clean:
                if rcv.haslayer(IP) and rcv.haslayer(TCP) and rcv[TCP].flags in ("R", "RA", "SA", 0x14, 0x12):
                    res_ip = str(rcv[IP].src)
                    if is_valid_ipv4(res_ip, subnet_cidr=target_subnet):
                        set_hijack_status(ip=res_ip, technique="L3 TCP SYN Probe")
                        log_hijack(f"\033[92m[+] IP resolved via L3 TCP SYN -> {res_ip}\033[0m")
                        return res_ip

        tcp_smb_pkts = [
            Ether(dst=mac_clean) / IP(dst=ip) / TCP(dport=445, flags="S")
            for ip in candidate_ips[:100]
        ]
        ans_smb, _ = srp(tcp_smb_pkts, timeout=1.0, iface=interface, verbose=False)
        for sent, rcv in ans_smb:
            if rcv.haslayer(Ether) and rcv[Ether].src.lower() == mac_clean:
                if rcv.haslayer(IP) and rcv.haslayer(TCP) and rcv[TCP].flags in ("R", "RA", "SA", 0x14, 0x12):
                    res_ip = str(rcv[IP].src)
                    if is_valid_ipv4(res_ip, subnet_cidr=target_subnet):
                        set_hijack_status(ip=res_ip, technique="L3 TCP SYN Probe")
                        log_hijack(f"\033[92m[+] IP resolved via L3 TCP SYN -> {res_ip}\033[0m")
                        return res_ip
    except Exception:
        pass
    return None


def probe_dhcp_inform(mac_clean: str, interface: str, target_subnet: str | None = None) -> str | None:
    try:
        set_hijack_status(ip=None, technique="DHCP Inform Query", clear_section2=True)
        log_hijack("[*] Broadcasting direct DHCP INFORM query packet...")
        trace(f"[*] Resolving {mac_clean} -> DHCP Inform Probe...")
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp
        mac_bytes = bytes.fromhex(mac_clean.replace(":", ""))
        rand_xid = random.randint(1, 0xFFFFFFFF)
        dhcp_inform = (
            Ether(src=mac_clean.lower(), dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_bytes.ljust(16, b"\x00"), xid=rand_xid, flags=0x8000) /
            DHCP(options=[
                ("message-type", "inform"),
                ("client_id", b"\x01" + mac_bytes),
                "end"
            ])
        )
        ans_dhcp, _ = srp(dhcp_inform, timeout=1.5, iface=interface, verbose=False)
        for sent, rcv in ans_dhcp:
            if rcv.haslayer(BOOTP):
                bootp = rcv[BOOTP]
                for addr in (getattr(bootp, "yiaddr", None), getattr(bootp, "ciaddr", None)):
                    if addr and is_valid_ipv4(str(addr), subnet_cidr=target_subnet):
                        res_ip = str(addr)
                        set_hijack_status(ip=res_ip, technique="DHCP Inform")
                        log_hijack(f"\033[92m[+] IP resolved via DHCP Inform -> {res_ip}\033[0m")
                        return res_ip
    except Exception:
        pass
    return None
