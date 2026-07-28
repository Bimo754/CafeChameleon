"""
cafe_chameleon.scanners.nmap_scanner - Fast Nmap TCP SYN probe scan targeting common user ports.
"""

import re
import shutil

from cafe_chameleon.utils.process import _run


def nmap_scan_subnet(subnet_cidr, interface: str) -> list[dict]:
    """
    Executes a fast Nmap TCP SYN probe scan targeting common user ports
    to discover firewalled user endpoints.
    Returns list of dicts: [{'ip': ip, 'mac': mac}, ...]
    """
    if not shutil.which("nmap"):
        return []

    cmd = [
        "nmap", "-PN", "-sS",
        "-p", "80,443,8080,22,445,139,3389,8000,8888,5353",
        "--min-rate", "300",
        "-n", "-e", interface,
        str(subnet_cidr)
    ]
    rc, out = _run(cmd, debug=False)
    if rc != 0 or not out:
        return []

    discovered = {}
    current_ip = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for "):
            ip_m = re.search(r"Nmap scan report for\s+(\S+)", line)
            if ip_m:
                current_ip = ip_m.group(1)
        elif "MAC Address:" in line and current_ip:
            mac_m = re.search(r"MAC Address:\s+([0-9a-fa-f:]+)", line, re.IGNORECASE)
            if mac_m:
                mac = mac_m.group(1).lower()
                discovered[current_ip] = mac

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]
