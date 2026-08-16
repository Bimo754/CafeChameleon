"""
cafe_chameleon.network.internet.gateway - High-speed gateway ping & pong detection.
"""

import re
import time
import socket
import struct

import ipaddress

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace

GW_VIA_REGEX = re.compile(r"via\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")


def _is_valid_ip(ip_str: str | None) -> bool:
    """Fast validation for IPv4 gateway address using stdlib."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        return ip.version == 4 and not ip.is_unspecified and not ip.is_multicast and str(ip) != "255.255.255.255"
    except (ValueError, Exception):
        return False



def get_default_gateway_ip(interface: str | None = None) -> str | None:
    """
    Rapidly resolves the default gateway IPv4 address.
    Checks /proc/net/route in-memory first for zero-overhead resolution,
    falling back to 'ip route' if needed.
    """
    # 1. Fast in-memory /proc/net/route check
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    if interface and fields[0] != interface:
                        continue
                    gw_hex = fields[2]
                    gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                    if gw_ip and gw_ip != "0.0.0.0" and _is_valid_ip(gw_ip):
                        return gw_ip
    except Exception:
        pass

    # 2. Fallback to 'ip route'
    try:
        cmd = ["ip", "-o", "-4", "route", "show", "to", "default"]
        if interface:
            cmd.extend(["dev", interface])
        rc, route_out = _run(cmd, debug=False)
        if route_out:
            m = GW_VIA_REGEX.search(route_out)
            if m:
                gw_ip = m.group(1).strip()
                if _is_valid_ip(gw_ip):
                    return gw_ip
    except Exception:
        pass

    return None


def ping_gateway_once(gateway_ip: str, interface: str | None = None, timeout: float = 0.25) -> bool:
    """
    Sends a single ICMP echo request to the gateway with numeric output and short timeout.
    Returns True if an ICMP Echo Reply (pong) is received.
    """
    if not gateway_ip or not _is_valid_ip(gateway_ip):
        return False

    eff_timeout = max(0.05, timeout)
    cmd = ["ping", "-c", "1", "-n", "-W", f"{eff_timeout:.2f}"]
    if interface:
        cmd.extend(["-I", interface])
    cmd.append(gateway_ip)

    rc, _ = _run(cmd, debug=False, timeout=eff_timeout + 0.5)
    return rc == 0


def wait_for_gateway_pong(
    gateway_ip: str | None = None,
    interface: str | None = None,
    timeout: float = 3.0,
    poll_interval: float = 0.05
) -> bool:
    """
    Repeatedly pings the gateway in a fast responsive loop until the first pong is received.
    The exact millisecond a pong is received (confirming bidirectional Layer 2 / Layer 3 connectivity),
    this function returns True immediately.
    If no pong is received within the timeout window, returns False.
    """
    resolved_ip = gateway_ip or get_default_gateway_ip(interface)
    if not resolved_ip:
        trace("[FEATURE] No default gateway IP detected; proceeding without gateway ping check.")
        return True

    start_time = time.time()
    trace(f"[FEATURE] Initiating gateway pong verification on {resolved_ip} (Timeout: {timeout}s, Interface: {interface or 'Auto'})")

    while time.time() - start_time < timeout:
        remaining = timeout - (time.time() - start_time)
        probe_timeout = min(0.25, max(0.05, remaining))

        if ping_gateway_once(resolved_ip, interface=interface, timeout=probe_timeout):
            elapsed_ms = (time.time() - start_time) * 1000
            trace(f"[FEATURE] Gateway {resolved_ip} pong received in {elapsed_ms:.1f}ms (device connected successfully to network)")
            return True

        time.sleep(poll_interval)

    trace(f"[-] Gateway {resolved_ip} ping timed out after {timeout}s (no pong received)")
    return False
