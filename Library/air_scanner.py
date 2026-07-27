"""
Library/air_scanner.py - 802.11 Monitor Mode Over-The-Air Client Discovery.
Uses /usr/local/bin/monitor0 for monitor mode capture and /usr/local/bin/managed0 for restoration.
"""

import logging
import os
import re
import sys
import time

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from .utils import (
    _run,
    log_info,
    log_plus,
    log_warning,
    log_minus,
    log_air
)
from .adapter import wait_for_carrier


def get_monitor_interface(default_iface="wlan0"):
    """Detects active monitor mode interface name (e.g. wlan0mon or wlan0)."""
    rc, out = _run(["ip", "-o", "link", "show"])
    for line in out.splitlines():
        if "wlan0mon" in line or "mon0" in line:
            parts = line.split(":", 2)
            if len(parts) >= 2:
                return parts[1].strip()
    return default_iface


def set_monitor_mode(interface="wlan0"):
    """
    Switches interface to 802.11 monitor mode using /usr/local/bin/monitor0.
    Returns the monitor interface name (e.g. wlan0mon or wlan0).
    """
    log_air("Switching interface to 802.11 MONITOR mode...")
    _run(["/bin/bash", "/usr/local/bin/monitor0"])
    mon_iface = get_monitor_interface(interface)
    log_air(f"[+] Monitor mode active on: {mon_iface}")
    return mon_iface


def set_managed_mode(interface="wlan0"):
    """
    Restores interface to MANAGED mode and restarts NetworkManager using /usr/local/bin/managed0.
    """
    log_air("Restoring interface to MANAGED mode...")
    _run(["/bin/bash", "/usr/local/bin/managed0"])

    start_t = time.time()
    while time.time() - start_t < 10:
        rc, out = _run(["nmcli", "dev", "status"], debug=False)
        if interface in out and ("disconnected" in out or "connected" in out or "connecting" in out):
            break
        time.sleep(0.5)

    wait_for_carrier(interface, timeout=6.0)
    log_air("[+] Interface restored to MANAGED mode.")


def sniff_air_clients(target_bssids, interface="wlan0", duration=25):
    """
    Switches to monitor mode, sniffs 802.11 frames over-the-air for `duration` seconds,
    maps active client MAC and IP addresses to target BSSIDs, and cleanly restores managed mode.

    Returns dict: { 'bssid_mac': { 'client_mac': 'client_ip' or None } }
    """
    try:
        from scapy.all import sniff, Dot11, IP, ARP, BOOTP, DHCP
    except ImportError:
        try:
            from scapy.all import sniff, Dot11, IP, ARP
            BOOTP, DHCP = None, None
        except ImportError:
            log_air("[-] scapy is required for 802.11 frame capture. Install with: pip install scapy")
            return {}

    target_bssids_set = {b.lower() for b in target_bssids if b}
    bssid_to_clients = {b: {} for b in target_bssids_set}

    try:
        from .scanner import auto_detect_network_params
        auto_params = auto_detect_network_params(target_iface=interface)
        gw_mac = (auto_params.get("gateway_mac") or "").lower()
        local_mac = (auto_params.get("local_mac") or "").lower()
    except Exception:
        gw_mac, local_mac = "", ""

    ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "none"}
    if gw_mac:
        ignore_macs.add(gw_mac)
    if local_mac:
        ignore_macs.add(local_mac)
    ignore_macs.update(target_bssids_set)

    log_air(f"=== 802.11 AIR SNIFFER ({duration}s Monitor Capture) ===", clear=True)
    mon_iface = set_monitor_mode(interface)

    log_air(f"Sniffing 802.11 over-the-air frames on {mon_iface} for {duration}s...")

    def air_packet_callback(pkt):
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        addr1 = str(dot11.addr1).lower() if dot11.addr1 else None
        addr2 = str(dot11.addr2).lower() if dot11.addr2 else None
        addr3 = str(dot11.addr3).lower() if dot11.addr3 else None

        src_ip = None
        bootp_mac = None

        # 1. BOOTP & DHCP Inspection
        if BOOTP and pkt.haslayer(BOOTP):
            bootp = pkt[BOOTP]
            if hasattr(bootp, "chaddr") and bootp.chaddr:
                # Form MAC from chaddr bytes
                ch_bytes = bootp.chaddr[:6]
                bootp_mac = ":".join(f"{b:02x}" for b in ch_bytes).lower()

            if hasattr(bootp, "ciaddr") and str(bootp.ciaddr) not in ("0.0.0.0", "255.255.255.255"):
                src_ip = str(bootp.ciaddr)
            elif hasattr(bootp, "yiaddr") and str(bootp.yiaddr) not in ("0.0.0.0", "255.255.255.255"):
                src_ip = str(bootp.yiaddr)

            if not src_ip and DHCP and pkt.haslayer(DHCP):
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "requested_addr":
                        req_ip = str(opt[1])
                        if req_ip not in ("0.0.0.0", "255.255.255.255"):
                            src_ip = req_ip
                            break

        # 2. Scapy IP / ARP layer extraction
        if not src_ip:
            if pkt.haslayer(ARP):
                src_ip = str(pkt[ARP].psrc)
            elif pkt.haslayer(IP):
                src_ip = str(pkt[IP].src)

        # 3. 802.11 Data Frame (type 2) Payload unwrapping & LLC/SNAP parsing
        if not src_ip and dot11.type == 2:
            curr = dot11.payload
            while curr:
                if hasattr(curr, "name"):
                    if curr.name == "IP" and hasattr(curr, "src"):
                        src_ip = str(curr.src)
                        break
                    elif curr.name == "ARP" and hasattr(curr, "psrc"):
                        src_ip = str(curr.psrc)
                        break
                    elif curr.name == "BOOTP":
                        if hasattr(curr, "ciaddr") and str(curr.ciaddr) not in ("0.0.0.0", "255.255.255.255"):
                            src_ip = str(curr.ciaddr)
                            break
                        elif hasattr(curr, "yiaddr") and str(curr.yiaddr) not in ("0.0.0.0", "255.255.255.255"):
                            src_ip = str(curr.yiaddr)
                            break
                if hasattr(curr, "payload") and curr.payload != curr:
                    curr = curr.payload
                else:
                    break

            # Raw LLC/SNAP EtherType (0x0800 IPv4, 0x0806 ARP) fallback
            if not src_ip:
                try:
                    payload = bytes(dot11.payload)
                    snap_idx = payload.find(b"\xaa\xaa\x03\x00\x00\x00")
                    if snap_idx != -1 and len(payload) >= snap_idx + 8:
                        ethertype = payload[snap_idx+6:snap_idx+8]
                        data = payload[snap_idx+8:]
                        import socket
                        if ethertype == b"\x08\x00" and len(data) >= 20:  # IPv4
                            if (data[0] & 0xf0) == 0x40:  # IPv4
                                ip_raw = socket.inet_ntoa(data[12:16])
                                if ip_raw not in ("0.0.0.0", "255.255.255.255"):
                                    src_ip = ip_raw
                        elif ethertype == b"\x08\x06" and len(data) >= 28:  # ARP
                            ip_raw = socket.inet_ntoa(data[14:18])
                            if ip_raw not in ("0.0.0.0", "255.255.255.255"):
                                src_ip = ip_raw
                except Exception:
                    pass

        if src_ip in ("0.0.0.0", "255.255.255.255"):
            src_ip = None

        # Determine BSSID and Client MAC from 802.11 header addresses
        for bssid_candidate in (addr3, addr1, addr2):
            if bssid_candidate and bssid_candidate in target_bssids_set:
                matched_bssid = bssid_candidate

                for client_candidate in (bootp_mac, addr2, addr1):
                    if client_candidate and client_candidate != matched_bssid and client_candidate not in ignore_macs:
                        try:
                            first_byte = int(client_candidate.split(":")[0], 16)
                            if first_byte & 1:  # Multicast / Broadcast bit set
                                continue
                        except Exception:
                            continue

                        existing_ip = bssid_to_clients[matched_bssid].get(client_candidate)
                        if client_candidate not in bssid_to_clients[matched_bssid] or (not existing_ip and src_ip):
                            bssid_to_clients[matched_bssid][client_candidate] = src_ip
                            ip_str = f" ({src_ip})" if src_ip else ""
                            log_air(f"  [+] Caught Client: {client_candidate}{ip_str} on BSSID {matched_bssid}")

    import threading

    stop_hopper = threading.Event()

    def channel_hopper(iface):
        channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10]
        idx = 0
        while not stop_hopper.is_set():
            ch = channels[idx % len(channels)]
            _run(["iw", "dev", iface, "set", "channel", str(ch)], debug=False)
            idx += 1
            time.sleep(0.25)

    hopper_thread = threading.Thread(target=channel_hopper, args=(mon_iface,), daemon=True)
    hopper_thread.start()

    try:
        sniff(iface=mon_iface, timeout=duration, prn=air_packet_callback, store=False)
    except Exception as e:
        log_air(f"[-] Over-the-air capture exception on {mon_iface}: {e}")
    finally:
        stop_hopper.set()
        hopper_thread.join(timeout=1.0)
        set_managed_mode(interface)

    total_clients = sum(len(c) for c in bssid_to_clients.values())
    if total_clients > 0:
        log_air(f"\n[+] Air Sniff Complete: Found {total_clients} target client MAC(s).")
    else:
        log_air("\n[Info] Air Sniff Complete: No active client MACs captured.")

    return bssid_to_clients



