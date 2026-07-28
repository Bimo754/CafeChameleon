"""
cafe_chameleon.scanners.detector - Auto-detect local interface, IP, MAC, gateway, subnet CIDR, and SSID.
"""

import re
import sys

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_scan
from cafe_chameleon.network.internet import has_internet


def auto_detect_network_params(target_iface: str | None = None) -> dict:
    """
    Auto-detects default network interface, local IP, MAC, gateway, netmask,
    broadcast, wireless SSID, and router MAC.
    """
    info = {
        "interface": target_iface,
        "local_ip": None,
        "local_mac": None,
        "gateway_ip": None,
        "gateway_mac": None,
        "broadcast": None,
        "cidr": None,
        "ssid": None,
        "internet_access": False
    }

    # 1. Default interface & Gateway IP
    rc, route_out = _run(["ip", "-o", "-4", "route", "show", "to", "default"])
    if route_out:
        gw_match = re.search(r"via\s+(\S+)", route_out)
        dev_match = re.search(r"dev\s+(\S+)", route_out)
        if gw_match:
            info["gateway_ip"] = gw_match.group(1)
        if dev_match and not info["interface"]:
            dev_name = dev_match.group(1)
            if not any(dev_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                info["interface"] = dev_name

    if not info["interface"]:
        rc, link_out = _run(["ip", "-o", "link", "show"])
        for line in link_out.splitlines():
            if "state UP" in line and "LOOPBACK" not in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    if not any(iface_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                        info["interface"] = iface_name
                        break

    if not info["interface"]:
        info["interface"] = "wlan0"

    # 2. IP, netmask/CIDR, broadcast
    rc, addr_out = _run(["ip", "-o", "-4", "addr", "show", "dev", info["interface"]])
    if addr_out:
        ip_match = re.search(r"inet\s+(\S+)", addr_out)
        brd_match = re.search(r"brd\s+(\S+)", addr_out)
        if ip_match:
            info["cidr"] = ip_match.group(1)
            info["local_ip"] = info["cidr"].split("/")[0]
        if brd_match:
            info["broadcast"] = brd_match.group(1)

    # 3. Local MAC
    rc, mac_out = _run(["ip", "-0", "addr", "show", "dev", info["interface"]])
    if mac_out:
        mac_match = re.search(r"link/ether\s+([0-9a-fa-f:]+)", mac_out, re.IGNORECASE)
        if mac_match:
            info["local_mac"] = mac_match.group(1).lower()

    # 4. Wi-Fi SSID
    rc, iw_out = _run(["iw", "dev", info["interface"], "link"])
    if rc == 0 and iw_out:
        ssid_match = re.search(r"SSID:\s*(.*)", iw_out)
        if ssid_match:
            info["ssid"] = ssid_match.group(1).strip()

    # 5. Gateway MAC
    if info["gateway_ip"]:
        rc, neigh_out = _run(["ip", "neighbor", "show", info["gateway_ip"], "dev", info["interface"]])
        if neigh_out:
            gw_mac_m = re.search(r"lladdr\s+([0-9a-fa-f:]+)", neigh_out, re.IGNORECASE)
            if gw_mac_m:
                info["gateway_mac"] = gw_mac_m.group(1).lower()

    # 6. Check internet access
    info["internet_access"] = has_internet()

    return info


def get_interface_details(interface: str) -> tuple[str, str]:
    """Retrieves local IP and MAC address safely."""
    try:
        from scapy.all import get_if_addr, get_if_hwaddr
        local_ip = get_if_addr(interface)
        local_mac = get_if_hwaddr(interface)
        if local_ip and local_mac and local_ip != "0.0.0.0":
            return local_ip, local_mac
    except Exception:
        pass

    params = auto_detect_network_params(target_iface=interface)
    local_ip = params.get("local_ip") or "10.0.0.1"
    local_mac = params.get("local_mac") or "00:11:22:33:44:55"
    return local_ip, local_mac
