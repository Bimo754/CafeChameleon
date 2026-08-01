"""
cafe_chameleon.scanners.nmap_scanner - Fast Nmap TCP SYN probe scan targeting common user ports.
"""

import re
import shutil

from cafe_chameleon.utils.process import _run


def nmap_scan_subnet(subnet_cidr, interface: str) -> list[dict]:
    """
    Executes a fast Nmap multi-protocol Ping Scan (-sn)
    to discover all active network endpoints.
    Returns list of dicts: [{'ip': ip, 'mac': mac}, ...]
    """
    if not shutil.which("nmap"):
        return []

    cmd = [
        "nmap", "-sn", "-PR", "-PE", "-PS80,443,8080,22,445", "-PU53,137,5353",
        "--min-rate", "400",
        "-n", "-e", interface,
        str(subnet_cidr)
    ]
    rc, out = _run(cmd, debug=False)
    if rc != 0 or not out:
        # Fallback without -e flag in case interface device binding was bouncing
        cmd_fallback = [
            "nmap", "-sn", "-PR", "-PE", "-PS80,443,8080,22,445", "-PU53,137,5353",
            "--min-rate", "400", "-n", str(subnet_cidr)
        ]
        rc, out = _run(cmd_fallback, debug=False)
        if rc != 0 or not out:
            return []

    discovered = {}
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
                discovered[current_ip] = mac

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]
