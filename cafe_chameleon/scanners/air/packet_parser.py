"""
cafe_chameleon.scanners.air.packet_parser - Scapy 802.11 packet inspection and client extraction.
"""

from cafe_chameleon.ui.console import log_air


def parse_air_packet(pkt, target_bssids_set: set[str], ignore_macs: set[str], bssid_to_clients: dict, BOOTP=None, DHCP=None):
    """
    Parses a single Scapy 802.11 frame, extracts IP/MAC information,
    and updates bssid_to_clients dict.
    """
    try:
        from scapy.all import Dot11, IP, ARP
    except ImportError:
        return

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
        is_protected = bool(fc & 0x40)

        # 1. BOOTP & DHCP Inspection
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

        # 2. Scapy IP / ARP layer extraction
        if not src_ip and not is_protected:
            if pkt.haslayer(ARP):
                src_ip = str(pkt[ARP].psrc)
            elif pkt.haslayer(IP):
                src_ip = str(pkt[IP].src)

        # 3. 802.11 Data Frame Payload unwrapping & LLC/SNAP parsing
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

            if not src_ip:
                try:
                    payload = bytes(dot11.payload)
                    snap_idx = payload.find(b"\xaa\xaa\x03\x00\x00\x00")
                    if snap_idx != -1 and len(payload) >= snap_idx + 8:
                        ethertype = payload[snap_idx+6:snap_idx+8]
                        data = payload[snap_idx+8:]
                        import socket
                        if ethertype == b"\x08\x00" and len(data) >= 20:
                            if (data[0] & 0xf0) == 0x40:
                                ip_raw = socket.inet_ntoa(data[12:16])
                                if ip_raw not in ("0.0.0.0", "255.255.255.255"):
                                    src_ip = ip_raw
                        elif ethertype == b"\x08\x06" and len(data) >= 28:
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

        matched_bssid = None
        client_candidate = None

        if to_ds and not from_ds:
            if addr1 and addr1 in target_bssids_set:
                matched_bssid = addr1
                client_candidate = bootp_mac or addr2
        elif from_ds and not to_ds:
            if addr2 and addr2 in target_bssids_set:
                matched_bssid = addr2
                client_candidate = bootp_mac or addr1
        elif not to_ds and not from_ds:
            if dot11.type == 0 and hasattr(dot11, "subtype"):
                if dot11.subtype in (0, 2, 11):
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr2
                elif dot11.subtype in (1, 3):
                    if addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr1

        if matched_bssid and client_candidate:
            client_candidate = client_candidate.lower()
            if client_candidate != matched_bssid and client_candidate not in ignore_macs:
                is_invalid = False
                if client_candidate.startswith("01:00:5e") or client_candidate.startswith("33:33") or client_candidate.startswith("00:00:5e"):
                    is_invalid = True

                if not is_invalid:
                    try:
                        first_byte = int(client_candidate.split(":")[0], 16)
                        if first_byte & 1:
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
