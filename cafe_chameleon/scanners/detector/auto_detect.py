"""
cafe_chameleon.scanners.detector.auto_detect - Auto-detection for subnet IP, MAC, gateway, and wireless parameters.
"""

import re

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_warning
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.models import NetworkParams
from .validator import validate_interface, find_suitable_interface

# Pre-compiled regular expression patterns for high-frequency detection logic
GW_VIA_REGEX = re.compile(r"via\s+(\S+)")
GW_DEV_REGEX = re.compile(r"dev\s+(\S+)")
INET_REGEX = re.compile(r"inet\s+(\S+)")
BRD_REGEX = re.compile(r"brd\s+(\S+)")
MAC_LINK_REGEX = re.compile(r"link/ether\s+([0-9a-fa-f:]+)", re.IGNORECASE)
SSID_LINK_REGEX = re.compile(r"SSID:\s*(.*)")
LLADDR_REGEX = re.compile(r"lladdr\s+([0-9a-fa-f:]+)", re.IGNORECASE)


def auto_detect_network_params(target_iface: str | None = None) -> NetworkParams:
    """
    Auto-detects default network interface, local IP, MAC, gateway, netmask,
    broadcast, wireless SSID, and router MAC. Returns a strongly-typed NetworkParams instance.
    """
    params = NetworkParams(interface=target_iface)
    target_requested = target_iface

    # 1. Default interface & Gateway IP
    rc, route_out = _run(["ip", "-o", "-4", "route", "show", "to", "default"])
    if route_out:
        gw_match = GW_VIA_REGEX.search(route_out)
        dev_match = GW_DEV_REGEX.search(route_out)
        if gw_match:
            params.gateway_ip = gw_match.group(1)
        if dev_match and not params.interface:
            dev_name = dev_match.group(1)
            if not any(dev_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                params.interface = dev_name

    if not params.interface:
        rc, link_out = _run(["ip", "-o", "link", "show"])
        for line in link_out.splitlines():
            if "state UP" in line and "LOOPBACK" not in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    if not any(iface_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                        params.interface = iface_name
                        break

    if target_requested:
        from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
        if is_monitor_mode_active(target_requested):
            set_managed_mode(target_requested)

    if not params.interface:
        suitable = find_suitable_interface()
        params.interface = suitable or "wlan0"

    if target_requested and not validate_interface(target_requested):
        log_warning(f"[!] Warning: Specified network interface '{target_requested}' not found on system.")
        suitable = find_suitable_interface()
        if suitable and suitable != target_requested:
            params.interface = suitable
            log_warning(f"[!] Warning: Using detected interface '{suitable}' instead.")
        else:
            log_warning(f"[!] Warning: No suitable network interface (like '{target_requested}') found on this system.")
    elif not validate_interface(params.interface):
        log_warning(f"[!] Warning: No suitable network interface (like '{params.interface}') found on this system.")

    if params.interface:
        from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
        if is_monitor_mode_active(params.interface):
            set_managed_mode(params.interface)

    # 2. IP, netmask/CIDR, broadcast
    rc, addr_out = _run(["ip", "-o", "-4", "addr", "show", "dev", params.interface])
    if addr_out:
        ip_match = INET_REGEX.search(addr_out)
        brd_match = BRD_REGEX.search(addr_out)
        if ip_match:
            params.cidr = ip_match.group(1)
            params.local_ip = params.cidr.split("/")[0]
        if brd_match:
            params.broadcast = brd_match.group(1)

    # 3. Local MAC
    rc, mac_out = _run(["ip", "-0", "addr", "show", "dev", params.interface])
    if mac_out:
        mac_match = MAC_LINK_REGEX.search(mac_out)
        if mac_match:
            params.local_mac = mac_match.group(1).lower()

    # 4. Wi-Fi SSID
    rc, iw_out = _run(["iw", "dev", params.interface, "link"])
    if rc == 0 and iw_out:
        ssid_match = SSID_LINK_REGEX.search(iw_out)
        if ssid_match:
            params.ssid = ssid_match.group(1).strip()

    # 5. Gateway MAC
    if params.gateway_ip:
        rc, neigh_out = _run(["ip", "neighbor", "show", params.gateway_ip, "dev", params.interface])
        if neigh_out:
            gw_mac_m = LLADDR_REGEX.search(neigh_out)
            if gw_mac_m:
                params.gateway_mac = gw_mac_m.group(1).lower()

    # 6. Check internet access
    params.internet_access = has_internet()

    return params


def get_interface_details(interface: str) -> tuple[str, str]:
    """Retrieves local IP and MAC address safely."""
    try:
        from scapy.all import get_if_addr, get_if_hwaddr
        from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4
        local_ip = get_if_addr(interface)
        local_mac = get_if_hwaddr(interface)
        if local_ip and local_mac and is_valid_ipv4(local_ip):
            return local_ip, local_mac
    except Exception:
        pass

    params = auto_detect_network_params(target_iface=interface)
    local_ip = params.get("local_ip") or "10.0.0.1"
    local_mac = params.get("local_mac") or "00:11:22:33:44:55"
    return local_ip, local_mac
