"""
cafe_chameleon.scanners.resolver.kernel_cache - Kernel neighbor table and ARP cache inspection.
"""

import os
import ipaddress

from cafe_chameleon.utils.process import _run


def is_valid_ipv4(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(str(ip_str))
        return ip_obj.version == 4 and not (ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or str(ip_str) == "255.255.255.255")
    except ValueError:
        return False


def check_kernel_cache(mac_clean: str, interface: str) -> str | None:
    """Inspects Linux kernel neighbor cache (`ip -4 neighbor`) and `/proc/net/arp`."""
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
