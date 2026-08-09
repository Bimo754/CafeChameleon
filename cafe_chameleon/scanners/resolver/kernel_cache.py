"""
cafe_chameleon.scanners.resolver.kernel_cache - Kernel neighbor table and ARP cache inspection.
"""

import os
import ipaddress

from cafe_chameleon.utils.process import _run


def is_valid_ipv4(ip_str: str | None, subnet_cidr: str | None = None, require_private: bool = True) -> bool:
    """
    Validates whether an IP address string is a valid, usable local/private IPv4 address.
    Filters out and ignores public/global internet IPs (Google, Facebook, Cloudflare, AWS, etc.),
    as well as multicast, loopback, link-local (169.254.x.x), unspecified (0.0.0.0),
    reserved, and broadcast (255.255.255.255) addresses.
    Optionally validates membership within target subnet_cidr.
    """
    if not ip_str:
        return False
    try:
        clean_str = str(ip_str).strip()
        ip_obj = ipaddress.ip_address(clean_str)
        if ip_obj.version != 4:
            return False
        if clean_str in ("0.0.0.0", "255.255.255.255"):
            return False
        if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False
        if require_private:
            # Must be within private/local space (RFC 1918 or CGNAT 100.64.0.0/10) and not globally routable
            is_local_range = ip_obj.is_private or (ip_obj in ipaddress.ip_network("100.64.0.0/10"))
            if not is_local_range or ip_obj.is_global:
                return False
        if subnet_cidr:
            try:
                net_obj = ipaddress.ip_network(str(subnet_cidr), strict=False)
                if ip_obj not in net_obj:
                    return False
            except Exception:
                pass
        return True
    except (ValueError, Exception):
        return False


def check_kernel_cache(mac_clean: str, interface: str, target_subnet: str | None = None) -> str | None:
    """Inspects Linux kernel neighbor cache (`ip -4 neighbor`) and `/proc/net/arp`."""
    rc, out = _run(["ip", "-4", "neighbor", "show", "dev", interface], debug=False)
    if out:
        for line in out.splitlines():
            if mac_clean in line.lower():
                parts = line.split()
                if len(parts) >= 1 and is_valid_ipv4(parts[0], subnet_cidr=target_subnet):
                    return parts[0]

    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].lower() == mac_clean and is_valid_ipv4(parts[0], subnet_cidr=target_subnet):
                        return parts[0]
        except Exception:
            pass
    return None
