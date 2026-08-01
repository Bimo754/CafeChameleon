"""
cafe_chameleon.scanners.resolver.resolver - Multi-stage MAC-to-IP resolution engine orchestrator.
"""

import ipaddress

from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from cafe_chameleon.scanners.detector import auto_detect_network_params

from .kernel_cache import check_kernel_cache
from .probes import probe_unicast_arp, probe_tcp_syn, probe_dhcp_inform
from .listener import listen_passive_traffic
from .sweep import sweep_l3_and_fallback


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

    # Stage 1: Kernel ARP cache check
    ip_found = check_kernel_cache(mac_clean, interface)
    if ip_found:
        set_hijack_status(ip=ip_found, technique="Kernel ARP Cache")
        log_hijack(f"\033[92m[+] IP found in kernel cache -> {ip_found}\033[0m")
        return ip_found

    # Prepare IP candidate list
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

    # Stage 2: Direct Unicast ARP Probe Sweep
    ip_found = probe_unicast_arp(mac_clean, candidate_ips, interface)
    if ip_found:
        return ip_found

    # Stage 3: Direct L3 TCP SYN & SMB Probes
    ip_found = probe_tcp_syn(mac_clean, candidate_ips, interface)
    if ip_found:
        return ip_found

    # Stage 4: DHCP INFORM Query Probe
    ip_found = probe_dhcp_inform(mac_clean, interface)
    if ip_found:
        return ip_found

    # Stage 5: Passive Traffic Listener (3 seconds)
    ip_found = listen_passive_traffic(mac_clean, interface, timeout=3)
    if ip_found:
        return ip_found

    # Stage 6 & 7: L3 Sweep and ARP Scan Fallback
    ip_found = sweep_l3_and_fallback(mac_clean, interface, target_subnet)
    if ip_found:
        return ip_found

    set_hijack_status(ip=None, technique="Resolution Exhausted")
    log_hijack("\033[91m[-] IP resolution exhausted for target MAC\033[0m")
    return None
