"""
cafe_chameleon.scanners.resolver - Multi-stage MAC-to-IP resolution engine.
"""

import ipaddress
import os
import random
import shutil

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.scanners.detector import auto_detect_network_params
from cafe_chameleon.scanners.arp_scanner import scan_subnet



def is_valid_ipv4(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(str(ip_str))
        return ip_obj.version == 4 and not (ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or str(ip_str) == "255.255.255.255")
    except ValueError:
        return False


def resolve_mac_to_ip(target_mac: str, interface: str, target_subnet: str | None = None) -> str | None:
    """
    Guaranteed aggressive multi-stage IP resolution for a target MAC address:
    1. Inspects Linux kernel neighbor table (`ip -4 neighbor`) and `/proc/net/arp`
    2. Direct Unicast ARP Probe Sweep (Ether(dst=target_mac)) - Bypasses AP/Client Isolation
    3. Direct Layer 3 Frame Injection Sweep (TCP SYN/UDP to target_mac) - Forces TCP RST/ACK from target kernel stack
    4. Direct DHCP INFORM Query to gateway / broadcast
    5. Short passive multicast & broadcast traffic listener (mDNS, LLMNR, SSDP, DHCP, ARP)
    6. Active Layer 3 Subnet Sweep & Scapy ARP scan fallback
    """
    if not target_mac:
        return None

    from cafe_chameleon.ui.console import log_hijack, set_hijack_status
    mac_clean = target_mac.strip().lower()

    if not target_subnet:
        params = auto_detect_network_params(target_iface=interface)
        if params.get("cidr"):
            target_subnet = params["cidr"]
        elif params.get("local_ip"):
            target_subnet = f"{params['local_ip']}/24"
        elif params.get("gateway_ip"):
            target_subnet = f"{params['gateway_ip']}/24"

    set_hijack_status(ip=None, technique="Kernel ARP Cache", clear_section2=True)
    log_hijack("[*] Checking kernel neighbor table & /proc/net/arp...")

    # Stage 1: Inspect kernel neighbor cache & /proc/net/arp
    def check_kernel_cache():
        rc, out = _run(["ip", "-4", "neighbor", "show", "dev", interface], debug=False)
        if out:
            for line in out.splitlines():
                if mac_clean in line.lower():
                    parts = line.split()
                    if len(parts) >= 1 and is_valid_ipv4(parts[0]):
                        return parts[0]

        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3].lower() == mac_clean and is_valid_ipv4(parts[0]):
                            return parts[0]
            except Exception:
                pass
        return None

    ip_found = check_kernel_cache()
    if ip_found:
        set_hijack_status(ip=ip_found, technique="Kernel ARP Cache")
        log_hijack(f"\033[92m[+] IP found in kernel cache -> {ip_found}\033[0m")
        return ip_found

    # Prepare IP candidate list from subnet
    candidate_ips = []
    if target_subnet:
        try:
            net_obj = ipaddress.ip_network(target_subnet, strict=False)
            if net_obj.prefixlen < 24:
                local_hosts = list(net_obj.hosts())[:254]
            else:
                local_hosts = list(net_obj.hosts())
            candidate_ips = [str(h) for h in local_hosts]
        except Exception:
            pass

    # Stage 2: Aggressive Unicast ARP Probe Sweep (Bypasses AP Client Isolation)
    if candidate_ips:
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
                    if is_valid_ipv4(res_ip):
                        set_hijack_status(ip=res_ip, technique="Unicast ARP Probe")
                        log_hijack(f"\033[92m[+] IP resolved via L2 Unicast ARP -> {res_ip}\033[0m")
                        return res_ip
        except Exception:
            pass

    # Stage 3: Aggressive Direct L3 TCP SYN & UDP Frame Injection (Forces TCP RST reply from target OS)
    if candidate_ips:
        try:
            set_hijack_status(ip=None, technique="L3 TCP SYN Probe", clear_section2=True)
            log_hijack("[*] Injecting direct L3 TCP SYN frames (Port 80/445)...")
            trace(f"[*] Resolving {mac_clean} -> L3 TCP SYN Probe...")
            from scapy.all import Ether, IP, TCP, UDP, srp
            tcp_syn_pkts = [
                Ether(dst=mac_clean) / IP(dst=ip) / TCP(dport=80, flags="S")
                for ip in candidate_ips
            ]
            ans_tcp, _ = srp(tcp_syn_pkts, timeout=1.5, iface=interface, verbose=False)
            for sent, rcv in ans_tcp:
                if rcv.haslayer(Ether) and rcv[Ether].src.lower() == mac_clean:
                    if rcv.haslayer(IP) and rcv.haslayer(TCP) and rcv[TCP].flags in ("R", "RA", "SA", 0x14, 0x12):
                        res_ip = str(rcv[IP].src)
                        if is_valid_ipv4(res_ip):
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
                        if is_valid_ipv4(res_ip):
                            set_hijack_status(ip=res_ip, technique="L3 TCP SYN Probe")
                            log_hijack(f"\033[92m[+] IP resolved via L3 TCP SYN -> {res_ip}\033[0m")
                            return res_ip
        except Exception:
            pass

    # Stage 4: DHCP INFORM Direct Query Probe to DHCP Gateway / Broadcast
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
                    if addr and is_valid_ipv4(str(addr)):
                        res_ip = str(addr)
                        set_hijack_status(ip=res_ip, technique="DHCP Inform")
                        log_hijack(f"\033[92m[+] IP resolved via DHCP Inform -> {res_ip}\033[0m")
                        return res_ip
    except Exception:
        pass

    # Stage 5: Passive Multicast / Broadcast Traffic Listener (3 seconds)
    try:
        set_hijack_status(ip=None, technique="Passive Traffic Listener", clear_section2=True)
        log_hijack("[*] Listening for broadcast/multicast packets (3s)...")
        trace(f"[*] Resolving {mac_clean} -> Passive Listener (3s)...")
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

        sniff(iface=interface, timeout=3, prn=passive_mac_callback, store=False)
        if sniffed_ip[0]:
            set_hijack_status(ip=sniffed_ip[0], technique="Passive Listener")
            log_hijack(f"\033[92m[+] IP resolved via passive listening -> {sniffed_ip[0]}\033[0m")
            return sniffed_ip[0]
    except Exception:
        pass

    # Stage 6: Active Layer 3 Unicast Sweep to force kernel neighbor population
    if target_subnet:
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

        # Re-check kernel cache after Layer 3 sweep
        log_hijack("[*] Re-checking kernel neighbor table after L3 sweep...")
        ip_found = check_kernel_cache()
        if ip_found:
            set_hijack_status(ip=ip_found, technique="Post-Sweep Cache")
            log_hijack(f"\033[92m[+] IP found in post-sweep kernel cache -> {ip_found}\033[0m")
            return ip_found

    # Stage 7: Trigger ARP resolution scan fallback
    if target_subnet:
        set_hijack_status(ip=None, technique="ARP Scan Fallback", clear_section2=True)
        log_hijack("[*] Running Scapy ARP scan fallback...")
        trace(f"[*] Resolving {mac_clean} -> ARP Scan Fallback...")
        hosts = scan_subnet(target_subnet, interface, silent=True)
        for h in hosts:
            if h["mac"].lower() == mac_clean and is_valid_ipv4(h["ip"]):
                set_hijack_status(ip=h["ip"], technique="ARP Scan Fallback")
                log_hijack(f"\033[92m[+] IP resolved via ARP scan fallback -> {h['ip']}\033[0m")
                return h["ip"]

    set_hijack_status(ip=None, technique="Resolution Exhausted")
    log_hijack("\033[91m[-] IP resolution exhausted for target MAC\033[0m")
    return None


    return None

