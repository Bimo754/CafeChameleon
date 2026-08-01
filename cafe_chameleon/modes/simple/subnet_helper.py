"""
cafe_chameleon.modes.simple.subnet_helper - Target subnet CIDR auto-detection, validation, and splitting.
"""

import ipaddress
import sys

from cafe_chameleon.ui.console import log_scan, log_main, log_warning
from cafe_chameleon.scanners.resolver import is_valid_ipv4


def prepare_target_subnet(args, auto_params: dict, local_ip: str | None, quiet_header: bool = False) -> ipaddress.IPv4Network | None:
    """Detects, parses, and expands/splits target CIDR subnet."""
    subnet_arg = getattr(args, "subnet", None)
    target_arg = getattr(args, "target", None)
    target_str = subnet_arg or target_arg

    if not target_str and auto_params.get("cidr"):
        try:
            net_obj = ipaddress.ip_network(auto_params["cidr"], strict=False)
            target_str = str(net_obj)
        except ValueError:
            target_str = auto_params["cidr"]

    if not target_str and auto_params.get("gateway_ip") and is_valid_ipv4(auto_params["gateway_ip"]):
        gw_ip_parts = auto_params["gateway_ip"].split(".")
        if len(gw_ip_parts) == 4:
            target_str = f"{gw_ip_parts[0]}.{gw_ip_parts[1]}.{gw_ip_parts[2]}.0/24"

    if not target_str and local_ip and is_valid_ipv4(local_ip):
        local_ip_parts = local_ip.split(".")
        if len(local_ip_parts) == 4:
            target_str = f"{local_ip_parts[0]}.{local_ip_parts[1]}.{local_ip_parts[2]}.0/24"

    if not target_str:
        if quiet_header:
            log_warning("[-] Could not auto-detect target network subnet CIDR.")
            log_main("[-] Could not auto-detect target network subnet CIDR.")
            return None
        else:
            log_scan("[-] Could not auto-detect target network subnet CIDR.")
            log_main("[-] Could not auto-detect target network subnet CIDR.")
            sys.exit(1)

    try:
        network = ipaddress.ip_network(target_str, strict=False)
        if getattr(args, "wide", False) and network.prefixlen >= 24:
            network = network.supernet(new_prefix=22)
        return network
    except ValueError as e:
        log_scan(f"[-] Invalid target network string '{target_str}': {e}")
        log_main(f"[-] Invalid target network string '{target_str}': {e}")
        if quiet_header:
            return None
        sys.exit(1)


def split_subnets_into_blocks(network: ipaddress.IPv4Network) -> list[ipaddress.IPv4Network]:
    """Splits target network into smaller /26 blocks (64 IPs per block) for reliability."""
    if network.prefixlen < 26:
        return list(network.subnets(new_prefix=26))
    return [network]
