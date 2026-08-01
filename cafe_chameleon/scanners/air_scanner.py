"""
cafe_chameleon.scanners.air_scanner - 802.11 Monitor Mode Over-The-Air Client Discovery & Channel Hopper.
"""

import logging
import shutil
import threading
import time

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from cafe_chameleon.utils.signals import AirSkipInterrupt
from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_air, set_air_mode
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.scanners.detector import auto_detect_network_params


def get_monitor_interface(default_iface: str = "wlan0") -> str:
    """Detects active monitor mode interface name (e.g. wlan0mon or wlan0)."""
    rc, out = _run(["ip", "-o", "link", "show"])
    for line in out.splitlines():
        if "wlan0mon" in line or "mon0" in line:
            parts = line.split(":", 2)
            if len(parts) >= 2:
                return parts[1].strip()
    return default_iface


def set_monitor_mode(interface: str = "wlan0") -> str:
    """
    Switches interface to 802.11 monitor mode natively using airmon-ng or iw/ip.
    Returns the monitor interface name (e.g. wlan0mon or wlan0).
    """
    set_air_mode("Monitor")

    if shutil.which("airmon-ng"):
        _run(["airmon-ng", "check", "kill"], debug=False)
        _run(["airmon-ng", "start", interface], debug=False)
    else:
        _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
        _run(["iw", "dev", interface, "set", "type", "monitor"], debug=False)
        _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    mon_iface = get_monitor_interface(interface)
    return mon_iface


def set_managed_mode(interface: str = "wlan0") -> None:
    """
    Restores interface to MANAGED mode natively and restarts NetworkManager / wpa_supplicant.
    """
    set_air_mode("Managed")
    mon_iface = get_monitor_interface(interface)

    if shutil.which("airmon-ng"):
        if mon_iface != interface:
            _run(["airmon-ng", "stop", mon_iface], debug=False)
        _run(["airmon-ng", "stop", interface], debug=False)

    # Native iw/ip fallback / enforcement to ensure managed mode state
    _run(["ip", "link", "set", "dev", interface, "down"], debug=False)
    _run(["iw", "dev", interface, "set", "type", "managed"], debug=False)
    _run(["ip", "link", "set", "dev", interface, "up"], debug=False)

    # Restart NetworkManager & wpa_supplicant services
    if shutil.which("systemctl"):
        _run(["systemctl", "restart", "wpa_supplicant"], debug=False)
        _run(["systemctl", "restart", "NetworkManager"], debug=False)
    elif shutil.which("service"):
        _run(["service", "wpa_supplicant", "restart"], debug=False)
        _run(["service", "NetworkManager", "restart"], debug=False)

    start_t = time.time()
    while time.time() - start_t < 10:
        rc, out = _run(["nmcli", "dev", "status"], debug=False)
        if interface in out and ("disconnected" in out or "connected" in out or "connecting" in out):
            break
        time.sleep(0.5)

    wait_for_carrier(interface, timeout=6.0)


def sniff_air_clients(target_bssids: list[str], interface: str = "wlan0", duration: int = 25, target_channels: list[int] | None = None) -> dict:
    """
    Switches to monitor mode, sniffs 802.11 frames over-the-air for `duration` seconds,
    maps active client MAC and IP addresses to target BSSIDs, and cleanly restores managed mode.
    Focuses channel hopping specifically on target_channels when supplied.

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

    mon_iface = set_monitor_mode(interface)

    valid_target_channels = []
    if target_channels:
        for ch in target_channels:
            try:
                ch_int = int(ch)
                if ch_int > 0 and ch_int not in valid_target_channels:
                    valid_target_channels.append(ch_int)
            except (ValueError, TypeError):
                pass

    if valid_target_channels:
        hop_channels = valid_target_channels
    else:
        log_air(f"Using all channels", start='\n')
        hop_channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10]

    log_air(f"[*] Sniffing frames on {mon_iface} ({duration}s)...")

    def air_packet_callback(pkt):
        try:
            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]
            addr1 = str(dot11.addr1).lower() if dot11.addr1 else None
            addr2 = str(dot11.addr2).lower() if dot11.addr2 else None
            addr3 = str(dot11.addr3).lower() if dot11.addr3 else None

            src_ip = None
            bootp_mac = None

            fc_raw = getattr(dot11, "FCfield", 0)
            try:
                fc = int(fc_raw)
            except Exception:
                fc = 0

            to_ds = bool(fc & 1)
            from_ds = bool(fc & 2)
            is_protected = bool(fc & 0x40)  # WEP/WPA/WPA2/WPA3 Protected/Encrypted frame bit

            # 1. BOOTP & DHCP Inspection (only for unencrypted frames)
            if not is_protected and BOOTP and pkt.haslayer(BOOTP):
                bootp = pkt[BOOTP]
                if hasattr(bootp, "chaddr") and bootp.chaddr:
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

            # 2. Scapy IP / ARP layer extraction (only for unencrypted frames)
            if not src_ip and not is_protected:
                if pkt.haslayer(ARP):
                    src_ip = str(pkt[ARP].psrc)
                elif pkt.haslayer(IP):
                    src_ip = str(pkt[IP].src)

            # 3. 802.11 Data Frame Payload unwrapping & LLC/SNAP parsing (only for unencrypted frames)
            if not src_ip and not is_protected and dot11.type == 2:
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
                                if (data[0] & 0xf0) == 0x40:
                                    ip_raw = socket.inet_ntoa(data[12:16])
                                    if ip_raw not in ("0.0.0.0", "255.255.255.255"):
                                        src_ip = ip_raw
                            elif ethertype == b"\x08\x06" and len(data) >= 28:  # ARP
                                ip_raw = socket.inet_ntoa(data[14:18])
                                if ip_raw not in ("0.0.0.0", "255.255.255.255"):
                                    src_ip = ip_raw
                    except Exception:
                        pass

            if src_ip:
                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(str(src_ip))
                    if ip_obj.version != 4 or ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or str(src_ip) == "255.255.255.255":
                        src_ip = None
                except Exception:
                    src_ip = None

            # Determine BSSID and Client MAC from 802.11 header addresses and Frame Control direction
            matched_bssid = None
            client_candidate = None

            if to_ds and not from_ds:
                # Client -> AP (Data frame): addr1=BSSID (RA), addr2=Client MAC (TA/SA), addr3=DA (Gateway/Destination)
                if addr1 and addr1 in target_bssids_set:
                    matched_bssid = addr1
                    client_candidate = bootp_mac or addr2
            elif from_ds and not to_ds:
                # AP -> Client (Data frame): addr1=Client MAC (RA/DA), addr2=BSSID (TA/SA), addr3=SA (Gateway/Source)
                if addr2 and addr2 in target_bssids_set:
                    matched_bssid = addr2
                    client_candidate = bootp_mac or addr1
            elif not to_ds and not from_ds:
                # Management / Control / IBSS frames
                if dot11.type == 0 and hasattr(dot11, "subtype"):
                    if dot11.subtype in (0, 2, 11):  # Active Association / Reassociation / Authentication Requests
                        if addr1 and addr1 in target_bssids_set:
                            matched_bssid = addr1
                            client_candidate = bootp_mac or addr2
                        elif addr3 and addr3 in target_bssids_set:
                            matched_bssid = addr3
                            client_candidate = bootp_mac or addr2
                    elif dot11.subtype in (1, 3):  # Association / Reassociation Responses from AP
                        if addr2 and addr2 in target_bssids_set:
                            matched_bssid = addr2
                            client_candidate = bootp_mac or addr1
                        elif addr3 and addr3 in target_bssids_set:
                            matched_bssid = addr3
                            client_candidate = bootp_mac or addr1

            if matched_bssid and client_candidate:
                client_candidate = client_candidate.lower()
                if client_candidate != matched_bssid and client_candidate not in ignore_macs:
                    # Check for multicast/broadcast/VRRP or AP BSSID prefix match (same physical AP)
                    is_invalid = False
                    if client_candidate.startswith("01:00:5e") or client_candidate.startswith("33:33") or client_candidate.startswith("00:00:5e"):
                        is_invalid = True

                    if not is_invalid:
                        try:
                            first_byte = int(client_candidate.split(":")[0], 16)
                            if first_byte & 1:  # Multicast / Broadcast bit
                                is_invalid = True
                        except Exception:
                            is_invalid = True

                    if not is_invalid and len(client_candidate) >= 14:
                        client_prefix = client_candidate[:14]
                        for tb in target_bssids_set:
                            if len(tb) >= 14 and client_prefix == tb[:14]:
                                is_invalid = True
                                break

                    if not is_invalid:
                        existing_ip = bssid_to_clients[matched_bssid].get(client_candidate)
                        if client_candidate not in bssid_to_clients[matched_bssid] or (not existing_ip and src_ip):
                            bssid_to_clients[matched_bssid][client_candidate] = src_ip
                            ip_str = f" ({src_ip})" if src_ip else ""
                            log_air(f"  [+] Target Client: {client_candidate}{ip_str} on BSSID {matched_bssid}")
        except Exception:
            pass

    stop_hopper = threading.Event()

    def channel_hopper(iface):
        idx = 0
        while not stop_hopper.is_set():
            ch = hop_channels[idx % len(hop_channels)]
            _run(["iw", "dev", iface, "set", "channel", str(ch)], debug=False)
            idx += 1
            time.sleep(0.25)

    hopper_thread = threading.Thread(target=channel_hopper, args=(mon_iface,), daemon=True)
    hopper_thread.start()

    try:
        sniff(iface=mon_iface, timeout=duration, prn=air_packet_callback, store=False)
    except (AirSkipInterrupt, KeyboardInterrupt):
        log_air("\n\033[93m[-] Stopped air sniff. Processing captured targets...\033[0m")
    except Exception as e:
        log_air(f"[-] Over-the-air capture exception on {mon_iface}: {e}")
    finally:
        stop_hopper.set()
        hopper_thread.join(timeout=1.0)
        set_managed_mode(interface)

    total_clients = sum(len(c) for c in bssid_to_clients.values())
    if total_clients > 0:
        log_air(f"\n[+] Air Sniff Complete: Found {total_clients} target client(s).")
    else:
        log_air("\n[i] Air Sniff Complete: No active clients captured.")

    return bssid_to_clients

