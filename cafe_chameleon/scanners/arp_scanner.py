"""
cafe_chameleon.scanners.arp_scanner - Nmap Ping Scan subnet interface module.
"""

from cafe_chameleon.scanners.nmap_scanner import nmap_scan_subnet


def scan_subnet(
    subnet_cidr,
    interface: str,
    silent: bool = False,
    parent_net=None,
    gateway_ip: str | None = None,
    gateway_mac: str | None = None
) -> list[dict]:
    """
    Subnet block scanner using Nmap Ping Scan (-sn).
    Executes Nmap Ping Scan across subnet blocks to discover active endpoints.
    """
    return nmap_scan_subnet(
        subnet_cidr=subnet_cidr,
        interface=interface,
        parent_net=parent_net,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac
    )
