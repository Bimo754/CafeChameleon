"""
cafe_chameleon.scanners.arp_scanner - Active Layer 2 Scapy ARP subnet scanner.
"""

import sys

from cafe_chameleon.ui.console import log_scan
from cafe_chameleon.utils.process import _run


def scan_subnet(subnet_cidr, interface: str) -> list[dict]:
    """
    Sends ARP requests to a target subnet chunk.
    Returns a list of dicts with active IPs and MACs.
    """
    try:
        from scapy.all import Ether, ARP, srp
    except ImportError:
        log_scan("[-] scapy is required for subnet scanning. Install with: pip install scapy")
        sys.exit(1)

    from cafe_chameleon.network.sysfs import wait_for_carrier
    wait_for_carrier(interface, timeout=5.0)

    arp_req = ARP(pdst=str(subnet_cidr))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    alive_hosts = []
    try:
        answered, _ = srp(packet, timeout=2, iface=interface, verbose=False)
        for sent, received in answered:
            alive_hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    except PermissionError:
        log_scan("[-] Permission denied. Root privileges required to send raw packets.")
        sys.exit(1)
    except OSError as e:
        log_scan(f"[-] Interface error on {interface} ({e}). Polling link carrier...")
        _run(f"ip link set dev {interface} up", debug=False)
        if wait_for_carrier(interface, timeout=4.0):
            try:
                answered, _ = srp(packet, timeout=2, iface=interface, verbose=False)
                for sent, received in answered:
                    alive_hosts.append({"ip": received.psrc, "mac": received.hwsrc})
            except Exception:
                pass

    return alive_hosts
