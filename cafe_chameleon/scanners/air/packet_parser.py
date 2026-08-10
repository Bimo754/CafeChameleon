"""
cafe_chameleon.scanners.air.packet_parser - Scapy 802.11 packet inspection and client extraction.
"""

from cafe_chameleon.ui.console import log_air
from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4


def parse_air_packet(pkt, target_bssids_set: set[str], ignore_macs: set[str], bssid_to_clients: dict, BOOTP=None, DHCP=None):
    """
    Parses a single Scapy 802.11 frame, extracts IP/MAC information,
    and updates bssid_to_clients dict. Correctly parses local client IPs
    and ignores public internet IPs (e.g., Google, Facebook, Cloudflare).
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
        addr4 = str(getattr(dot11, "addr4", None)).lower() if getattr(dot11, "addr4", None) else None

        client_ip = None
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

            if hasattr(bootp, "ciaddr") and is_valid_ipv4(str(bootp.ciaddr)):
                client_ip = str(bootp.ciaddr)
            elif hasattr(bootp, "yiaddr") and is_valid_ipv4(str(bootp.yiaddr)):
                client_ip = str(bootp.yiaddr)

            if not client_ip and DHCP and pkt.haslayer(DHCP):
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "requested_addr":
                        req_ip = str(opt[1])
                        if is_valid_ipv4(req_ip):
                            client_ip = req_ip
                            break

        # 2. Scapy IP / ARP layer extraction
        if not client_ip and not is_protected:
            if pkt.haslayer(ARP):
                psrc = str(pkt[ARP].psrc) if hasattr(pkt[ARP], "psrc") else None
                pdst = str(pkt[ARP].pdst) if hasattr(pkt[ARP], "pdst") else None
                if from_ds and is_valid_ipv4(pdst):
                    client_ip = pdst
                elif to_ds and is_valid_ipv4(psrc):
                    client_ip = psrc
                elif is_valid_ipv4(psrc):
                    client_ip = psrc
                elif is_valid_ipv4(pdst):
                    client_ip = pdst
            elif pkt.haslayer(IP):
                src_cand = str(pkt[IP].src) if hasattr(pkt[IP], "src") else None
                dst_cand = str(pkt[IP].dst) if hasattr(pkt[IP], "dst") else None
                # When from_ds (AP -> Client), IP.dst is the local client IP and IP.src is remote server
                # When to_ds (Client -> AP), IP.src is the local client IP and IP.dst is remote server
                if from_ds:
                    if is_valid_ipv4(dst_cand):
                        client_ip = dst_cand
                    elif is_valid_ipv4(src_cand):
                        client_ip = src_cand
                elif to_ds:
                    if is_valid_ipv4(src_cand):
                        client_ip = src_cand
                    elif is_valid_ipv4(dst_cand):
                        client_ip = dst_cand
                else:
                    if is_valid_ipv4(src_cand):
                        client_ip = src_cand
                    elif is_valid_ipv4(dst_cand):
                        client_ip = dst_cand

        # 3. 802.11 Data Frame Payload unwrapping & LLC/SNAP parsing
        if not client_ip and not is_protected and dot11.type == 2:
            curr = dot11.payload
            while curr:
                if hasattr(curr, "name"):
                    if curr.name == "IP":
                        src_raw = str(curr.src) if hasattr(curr, "src") else None
                        dst_raw = str(curr.dst) if hasattr(curr, "dst") else None
                        if from_ds:
                            if is_valid_ipv4(dst_raw):
                                client_ip = dst_raw
                                break
                            elif is_valid_ipv4(src_raw):
                                client_ip = src_raw
                                break
                        else:
                            if is_valid_ipv4(src_raw):
                                client_ip = src_raw
                                break
                            elif is_valid_ipv4(dst_raw):
                                client_ip = dst_raw
                                break
                    elif curr.name == "ARP":
                        psrc_raw = str(curr.psrc) if hasattr(curr, "psrc") else None
                        pdst_raw = str(curr.pdst) if hasattr(curr, "pdst") else None
                        if from_ds:
                            if is_valid_ipv4(pdst_raw):
                                client_ip = pdst_raw
                                break
                            elif is_valid_ipv4(psrc_raw):
                                client_ip = psrc_raw
                                break
                        else:
                            if is_valid_ipv4(psrc_raw):
                                client_ip = psrc_raw
                                break
                            elif is_valid_ipv4(pdst_raw):
                                client_ip = pdst_raw
                                break
                    elif curr.name == "BOOTP":
                        ciaddr = str(curr.ciaddr) if hasattr(curr, "ciaddr") else None
                        yiaddr = str(curr.yiaddr) if hasattr(curr, "yiaddr") else None
                        if is_valid_ipv4(ciaddr):
                            client_ip = ciaddr
                            break
                        elif is_valid_ipv4(yiaddr):
                            client_ip = yiaddr
                            break
                if hasattr(curr, "payload") and curr.payload != curr:
                    curr = curr.payload
                else:
                    break

            if not client_ip:
                try:
                    payload = bytes(dot11.payload)
                    snap_idx = payload.find(b"\xaa\xaa\x03\x00\x00\x00")
                    if snap_idx != -1 and len(payload) >= snap_idx + 8:
                        ethertype = payload[snap_idx+6:snap_idx+8]
                        data = payload[snap_idx+8:]
                        import socket
                        if ethertype == b"\x08\x00" and len(data) >= 20:
                            if (data[0] & 0xf0) == 0x40:
                                ip_src = socket.inet_ntoa(data[12:16])
                                ip_dst = socket.inet_ntoa(data[16:20])
                                if from_ds:
                                    if is_valid_ipv4(ip_dst):
                                        client_ip = ip_dst
                                    elif is_valid_ipv4(ip_src):
                                        client_ip = ip_src
                                else:
                                    if is_valid_ipv4(ip_src):
                                        client_ip = ip_src
                                    elif is_valid_ipv4(ip_dst):
                                        client_ip = ip_dst
                        elif ethertype == b"\x08\x06" and len(data) >= 28:
                            arp_src = socket.inet_ntoa(data[14:18])
                            arp_dst = socket.inet_ntoa(data[24:28])
                            if from_ds:
                                if is_valid_ipv4(arp_dst):
                                    client_ip = arp_dst
                                elif is_valid_ipv4(arp_src):
                                    client_ip = arp_src
                            else:
                                if is_valid_ipv4(arp_src):
                                    client_ip = arp_src
                                elif is_valid_ipv4(arp_dst):
                                    client_ip = arp_dst
                except Exception:
                    pass

        if client_ip and not is_valid_ipv4(client_ip):
            client_ip = None

        matched_bssid = None
        client_candidate = None
        subtype = getattr(dot11, "subtype", None)

        # Frame Dissection & Client Mapping
        if to_ds and not from_ds:
            # Client -> AP (Uplink Data)
            if addr1 and addr1 in target_bssids_set:
                matched_bssid = addr1
                client_candidate = bootp_mac or addr2
            elif addr3 and addr3 in target_bssids_set:
                matched_bssid = addr3
                client_candidate = bootp_mac or addr2
        elif from_ds and not to_ds:
            # AP -> Client (Downlink Data)
            if addr2 and addr2 in target_bssids_set:
                matched_bssid = addr2
                client_candidate = bootp_mac or addr1
            elif addr3 and addr3 in target_bssids_set:
                matched_bssid = addr3
                client_candidate = bootp_mac or addr1
        elif to_ds and from_ds:
            # WDS / Mesh frame
            if addr1 in target_bssids_set:
                matched_bssid = addr1
                client_candidate = bootp_mac or addr4 or addr2
            elif addr2 in target_bssids_set:
                matched_bssid = addr2
                client_candidate = bootp_mac or addr3 or addr1
        else:
            # not to_ds and not from_ds (Management, Control, or Direct / IBSS Data)
            if dot11.type == 0:
                # 802.11 Management frames
                # Subtype 0: Assoc Req (addr1=BSSID, addr2=Client, addr3=BSSID)
                # Subtype 1: Assoc Resp (addr1=Client, addr2=BSSID, addr3=BSSID)
                # Subtype 2: Reassoc Req (addr1=BSSID, addr2=Client, addr3=BSSID)
                # Subtype 3: Reassoc Resp (addr1=Client, addr2=BSSID, addr3=BSSID)
                # Subtype 4: Probe Req (addr1=DA/Broadcast, addr2=Client, addr3=BSSID/Broadcast)
                # Subtype 5: Probe Resp (addr1=Client, addr2=BSSID, addr3=BSSID) -> HIGH VALUE FOR FAR CLIENTS!
                # Subtype 10: Disassoc (addr1=RA, addr2=TA, addr3=BSSID)
                # Subtype 11: Auth (addr1=RA, addr2=TA, addr3=BSSID)
                # Subtype 12: Deauth (addr1=RA, addr2=TA, addr3=BSSID)
                # Subtype 13: Action (addr1=RA, addr2=TA, addr3=BSSID)
                if subtype in (0, 2):
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr2
                elif subtype in (1, 3, 5):
                    # AP transmitting to Client
                    if addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr1
                elif subtype == 4:
                    # Client transmitting Probe Request directed to specific target BSSID
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr2
                elif subtype in (10, 11, 12, 13):
                    # Bi-directional management frames (Auth, Deauth, Disassoc, Action)
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        # If addr3 is BSSID, client is whichever of addr1/addr2 is not the BSSID
                        if addr1 and addr1 != addr3:
                            client_candidate = bootp_mac or addr1
                        elif addr2 and addr2 != addr3:
                            client_candidate = bootp_mac or addr2

            elif dot11.type == 1:
                # 802.11 Control frames
                # Subtype 8: Block ACK Request (addr1=RA, addr2=TA)
                # Subtype 10: PS-Poll (addr1=BSSID/RA, addr2=Client/TA)
                # Subtype 11: RTS (addr1=BSSID/RA, addr2=Client/TA)
                # Subtype 12: CTS (addr1=RA)
                if subtype in (8, 10, 11):
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = addr2
                    elif addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = addr1

            elif dot11.type == 2:
                # Direct / IBSS / Null Data
                if addr1 and addr1 in target_bssids_set:
                    matched_bssid = addr1
                    client_candidate = bootp_mac or addr2
                elif addr2 and addr2 in target_bssids_set:
                    matched_bssid = addr2
                    client_candidate = bootp_mac or addr1
                elif addr3 and addr3 in target_bssids_set:
                    matched_bssid = addr3
                    client_candidate = bootp_mac or (addr2 if addr2 and addr2 != addr3 else addr1)

        if matched_bssid and client_candidate:
            client_candidate = client_candidate.lower()
            if (
                client_candidate != matched_bssid
                and client_candidate not in ignore_macs
                and not client_candidate.startswith("02:00:00")
            ):
                is_invalid = False
                # Filter multicast / broadcast / IPv6 / VRRP / stimulator prefixes
                if (
                    client_candidate.startswith("01:00:5e")
                    or client_candidate.startswith("33:33")
                    or client_candidate.startswith("00:00:5e")
                    or client_candidate.startswith("02:00:00")
                    or client_candidate == "ff:ff:ff:ff:ff:ff"
                    or client_candidate == "00:00:00:00:00:00"
                ):
                    is_invalid = True

                # Check multicast / I/G bit on first octet
                if not is_invalid:
                    try:
                        first_byte = int(client_candidate.split(":")[0], 16)
                        if first_byte & 1:
                            is_invalid = True
                    except Exception:
                        is_invalid = True

                # Discard if client is another known AP BSSID
                if not is_invalid and client_candidate in target_bssids_set:
                    is_invalid = True

                if not is_invalid:
                    existing_ip = bssid_to_clients[matched_bssid].get(client_candidate)
                    if client_candidate not in bssid_to_clients[matched_bssid] or (not existing_ip and client_ip):
                        bssid_to_clients[matched_bssid][client_candidate] = client_ip
                        ip_str = f" ({client_ip})" if client_ip else ""
                        log_air(f"  [+] Target Client: {client_candidate}{ip_str} on BSSID {matched_bssid}")
    except Exception:
        pass
