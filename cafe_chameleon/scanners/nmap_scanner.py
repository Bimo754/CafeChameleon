"""
cafe_chameleon.scanners.nmap_scanner - Fast Nmap Ping Scan (-sn) targeting subnet blocks.
"""

import ipaddress
import re
import shutil

from cafe_chameleon.utils.process import _run
from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4


def nmap_scan_subnet(
    subnet_cidr,
    interface: str,
    parent_net=None,
    gateway_ip: str | None = None,
    gateway_mac: str | None = None,
    silent: bool = False
) -> list[dict]:
    """
    Executes a fast Nmap multi-protocol Ping Scan (-sn)
    targeting subnet blocks to discover all active endpoints (IP + MAC).
    """
    discovered = {}  # ip -> mac
    target_net_str = str(parent_net or subnet_cidr)

    # Pre-seed known gateway if provided
    if gateway_ip and gateway_mac and gateway_mac != "00:00:00:00:00:00":
        if is_valid_ipv4(gateway_ip, subnet_cidr=target_net_str):
            discovered[gateway_ip] = gateway_mac.lower()

    if shutil.which("nmap"):
        # Nmap Ping Scan (-sn): ICMP Echo (-PE), ICMP Timestamp (-PP), TCP SYN (-PS), UDP (-PU), ARP (-PR)
        cmd = [
            "nmap", "-sn", "-T4", "--max-rtt-timeout", "1500ms",
            "-PR", "-PE", "-PP",
            "-PS80,443,8080,22,445,139", "-PU53,137,5353",
            "--max-retries", "2",
            "-n", "-e", interface,
            str(subnet_cidr)
        ]
        rc, out = _run(cmd, debug=False)
        if rc != 0 or not out:
            cmd_fallback = [
                "nmap", "-sn", "-T4", "--max-rtt-timeout", "1500ms",
                "-PR", "-PE", "-PP",
                "-PS80,443,8080,22,445,139", "-PU53,137,5353",
                "--max-retries", "2", "-n", str(subnet_cidr)
            ]
            rc, out = _run(cmd_fallback, debug=False)

        if out:
            current_ip = None
            for line in out.splitlines():
                line = line.strip()
                if "Nmap scan report for" in line:
                    ip_m = re.search(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
                    if ip_m:
                        current_ip = ip_m.group(1)
                elif "MAC Address:" in line and current_ip:
                    mac_m = re.search(r"MAC Address:\s+([0-9a-fa-f:]+)", line, re.IGNORECASE)
                    if mac_m:
                        mac = mac_m.group(1).lower()
                        if is_valid_ipv4(current_ip, subnet_cidr=target_net_str):
                            discovered[current_ip] = mac

    # Harvest from kernel neighbor cache in case Nmap triggered ARP/IP resolution
    try:
        rc, neigh_out = _run(["ip", "-4", "neighbor", "show", "dev", interface], debug=False)
        if neigh_out:
            for line in neigh_out.splitlines():
                m = re.search(r"^(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fa-f:]+)", line, re.IGNORECASE)
                if m:
                    ip_str, mac_str = m.group(1), m.group(2).lower()
                    if mac_str != "00:00:00:00:00:00":
                        if is_valid_ipv4(ip_str, subnet_cidr=target_net_str):
                            if ip_str not in discovered:
                                discovered[ip_str] = mac_str
    except Exception:
        pass

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]


scan_subnet = nmap_scan_subnet
