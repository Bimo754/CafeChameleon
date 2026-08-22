"""
cafe_chameleon.network.internet.gateway - High-speed, guaranteed gateway ping & pong reachability detection.
"""

import re
import time
import socket
import struct
import ipaddress

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace

from collections.abc import Callable
from .sockets import _probe_socket, _probe_dns_resolution

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


def check_gateway_neighbor_table(gateway_ip: str, interface: str | None = None) -> bool:
    """
    Inspects kernel ARP/Neighbor table (/proc/net/arp and 'ip neigh') to verify
    if the gateway has an active, resolved Layer 2 MAC entry.
    """
    if not gateway_ip or not _is_valid_ip(gateway_ip):
        return False

    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == gateway_ip:
                    if interface and parts[5] != interface:
                        continue
                    mac = parts[3].lower()
                    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not mac.startswith("00:00:00"):
                        return True
    except Exception:
        pass

    try:
        cmd = ["ip", "neigh", "show", gateway_ip]
        if interface:
            cmd.extend(["dev", interface])
        rc, out = _run(cmd, debug=False, timeout=1.0)
        if rc == 0 and out:
            lower = out.lower()
            if any(state in lower for state in ("reachable", "delay", "stale", "permanent")) and "incomplete" not in lower:
                return True
    except Exception:
        pass

    return False


def _probe_gateway_tcp(gateway_ip: str, ports: list[int] | None = None, timeout: float = 0.4) -> bool:
    """
    Fast Layer 4 TCP SYN probe to common gateway ports (DNS 53, HTTP 80, HTTPS 443, Router 8080).
    A successful SYN-ACK or RST (Connection Refused) packet definitively proves bidirectional
    Layer 2 + Layer 3 gateway reachability even if ICMP Echo is blocked.
    """
    if not gateway_ip or not _is_valid_ip(gateway_ip):
        return False

    check_ports = ports or [53, 80, 443, 8080]
    for port in check_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((gateway_ip, port))
                s.close()
                return True
            except ConnectionRefusedError:
                # RST received: Gateway responded at Layer 3/4!
                s.close()
                return True
            except (socket.timeout, OSError):
                s.close()
        except Exception:
            pass

    return False


def ping_gateway_once(gateway_ip: str, interface: str | None = None, timeout: float = 1.0) -> bool:
    """
    Sends a single ICMP echo request to the gateway with numeric output.
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


def arp_ping_gateway_once(gateway_ip: str, interface: str | None = None, timeout: float = 1.0) -> bool:
    """
    Fallback Layer 2 ARP and TCP reachability probe to detect if the gateway responds,
    guarding against gateways that actively drop ICMP Echo Requests.
    """
    if not gateway_ip or not _is_valid_ip(gateway_ip):
        return False

    eff_timeout = max(0.5, timeout)
    cmd = ["arping", "-c", "1", "-w", str(int(eff_timeout))]
    if interface:
        cmd.extend(["-I", interface])
    cmd.append(gateway_ip)

    rc, _ = _run(cmd, debug=False, timeout=eff_timeout + 0.5)
    if rc == 0:
        return True

    # Also check /proc/net/arp / kernel neighbor table
    if check_gateway_neighbor_table(gateway_ip, interface=interface):
        return True

    # Also check TCP reachability on router ports
    return _probe_gateway_tcp(gateway_ip, timeout=0.3)


def wait_for_gateway_pong(
    gateway_ip: str | None = None,
    interface: str | None = None,
    timeout: float = 3.5,
    poll_interval: float = 0.05,
    allow_arp_fallback: bool = True
) -> bool:
    """
    Repeatedly pings the gateway in a fast responsive loop until the first pong is received.
    The exact millisecond a pong is received (confirming bidirectional Layer 2 / Layer 3 connectivity),
    this function returns True immediately.
    If no pong is received within the timeout window, tests ARP fallback if enabled.
    If all probes fail, returns False.
    """
    resolved_ip = gateway_ip or get_default_gateway_ip(interface)
    if not resolved_ip:
        trace("[FEATURE] No default gateway IP detected; proceeding without gateway ping check.")
        return True

    start_time = time.time()
    trace(f"[FEATURE] Initiating gateway reachability verification on {resolved_ip} (Timeout: {timeout}s, Interface: {interface or 'Auto'})")

    while time.time() - start_time < timeout:
        remaining = timeout - (time.time() - start_time)
        probe_timeout = min(1.0, max(0.2, remaining))

        if ping_gateway_once(resolved_ip, interface=interface, timeout=probe_timeout):
            elapsed_ms = (time.time() - start_time) * 1000
            trace(f"[FEATURE] Gateway {resolved_ip} ICMP pong received in {elapsed_ms:.1f}ms (device connected successfully)")
            return True

        time.sleep(poll_interval)

    # If ICMP timed out, execute Layer 2 ARP fallback
    if allow_arp_fallback:
        trace(f"[FEATURE] Gateway {resolved_ip} ICMP ping timed out; trying Layer 2 ARP probe fallback...")
        if arp_ping_gateway_once(resolved_ip, interface=interface, timeout=1.0):
            trace(f"[FEATURE] Gateway {resolved_ip} answered L2 ARP probe (Layer 2 connectivity confirmed)")
            return True

    trace(f"[-] Gateway {resolved_ip} ping timed out after {timeout}s (no pong received)")
    return False


def wait_for_session_establishment(
    gateway_ip: str | None = None,
    interface: str | None = None,
    timeout: float = 3.0,
    poll_interval: float = 0.25,
    log_cb: Callable | None = None
) -> bool:
    """
    Verifies that the network session has fully established and settled following
    gateway reachability or connection association.

    Prevents false positive captive portal detections or false negative internet checks
    caused by probing immediately while the router/gateway firewall is still synchronizing
    session info, NAT/conntrack bindings, or RADIUS table rules.
    """
    from cafe_chameleon.config import PUBLIC_DNS_ENDPOINTS

    resolved_gw = gateway_ip or get_default_gateway_ip(interface)
    start_t = time.time()

    if log_cb:
        log_cb("[*] Verifying network session establishment...")
    trace(f"[FEATURE] Verifying network session establishment (Timeout: {timeout}s, GW: {resolved_gw or 'Auto'})")

    success_streak = 0
    required_streak = 1

    while time.time() - start_t < timeout:
        remaining = timeout - (time.time() - start_t)
        if remaining <= 0:
            break

        session_active = False

        # 1. Probe public socket endpoint
        for ep in PUBLIC_DNS_ENDPOINTS[:2]:
            if _probe_socket(ep, timeout=min(0.4, remaining)):
                session_active = True
                break

        # 2. If raw socket probe is unconfirmed, test DNS resolution probe
        if not session_active:
            if _probe_dns_resolution("connectivitycheck.gstatic.com", timeout=min(0.5, remaining)):
                session_active = True

        if session_active:
            success_streak += 1
            if success_streak >= required_streak:
                elapsed_ms = (time.time() - start_t) * 1000
                trace(f"[FEATURE] Network session confirmed active & settled in {elapsed_ms:.1f}ms")
                if log_cb:
                    log_cb("[+] Network session confirmed active!")
                return True
        else:
            success_streak = 0

        time.sleep(poll_interval)

    trace(f"[FEATURE] Session establishment polling window completed ({timeout}s elapsed)")
    return False

