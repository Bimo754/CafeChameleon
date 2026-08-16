"""
cafe_chameleon.scanners.air.packet_parser - Scapy 802.11 packet inspection and client extraction.
"""

from cafe_chameleon.ui.console import log_air
from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4


def extract_packet_rssi(pkt) -> int | None:
    """Extracts dBm antenna signal (RSSI) from RadioTap layer if present."""
    try:
        if hasattr(pkt, "fields") and "dBm_AntSignal" in pkt.fields and pkt.fields["dBm_AntSignal"] is not None:
            val = int(pkt.fields["dBm_AntSignal"])
            return (val - 256) if val > 0 else val
        if hasattr(pkt, "dBm_AntSignal") and pkt.dBm_AntSignal is not None:
            val = int(pkt.dBm_AntSignal)
            return (val - 256) if val > 0 else val
        if pkt.haslayer("RadioTap"):
            rt = pkt.getlayer("RadioTap")
            if rt and hasattr(rt, "fields") and "dBm_AntSignal" in rt.fields and rt.fields["dBm_AntSignal"] is not None:
                val = int(rt.fields["dBm_AntSignal"])
                return (val - 256) if val > 0 else val
            if rt and hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                val = int(rt.dBm_AntSignal)
                return (val - 256) if val > 0 else val
    except Exception:
        pass
    return None


def parse_air_packet(
    pkt,
    target_bssids_set: set[str],
    ignore_macs: set[str],
    bssid_to_clients: dict,
    BOOTP=None,
    DHCP=None,
    client_metadata: dict | None = None
):
    """
    Parses a single Scapy 802.11 frame, extracts IP/MAC information,
    and updates bssid_to_clients dict. Correctly parses local client IPs
    and ignores public internet IPs (e.g., Google, Facebook, Cloudflare).

    Guarantees that each unique client station is bound to at most ONE
    most-active BSSID, prioritizing confirmed Data frames over generic probes,
    and using RadioTap RSSI as a signal-strength tiebreaker.
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
        frame_priority = 1  # 3: Data/IP Traffic, 2: Direct Assoc/Auth, 1: Probe/Mgmt/Control

        # Frame Dissection & Client Mapping
        if to_ds and not from_ds:
            # Client -> AP (Uplink Data)
            frame_priority = 3
            if addr1 and addr1 in target_bssids_set:
                matched_bssid = addr1
                client_candidate = bootp_mac or addr2
            elif addr3 and addr3 in target_bssids_set:
                matched_bssid = addr3
                client_candidate = bootp_mac or addr2
        elif from_ds and not to_ds:
            # AP -> Client (Downlink Data)
            frame_priority = 3
            if addr2 and addr2 in target_bssids_set:
                matched_bssid = addr2
                client_candidate = bootp_mac or addr1
            elif addr3 and addr3 in target_bssids_set:
                matched_bssid = addr3
                client_candidate = bootp_mac or addr1
        elif to_ds and from_ds:
            # WDS / Mesh frame
            frame_priority = 3
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
                if subtype in (0, 2):
                    frame_priority = 2  # Assoc / Reassoc Req
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr2
                elif subtype in (1, 3):
                    frame_priority = 2  # Assoc / Reassoc Resp
                    if addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr1
                elif subtype == 5:
                    frame_priority = 1  # Probe Resp
                    if addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr1
                elif subtype == 4:
                    frame_priority = 1  # Probe Req
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        client_candidate = bootp_mac or addr2
                elif subtype in (10, 11, 12, 13):
                    # Bi-directional management frames (Auth, Deauth, Disassoc, Action)
                    frame_priority = 2 if subtype == 11 else 1
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = bootp_mac or addr2
                    elif addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = bootp_mac or addr1
                    elif addr3 and addr3 in target_bssids_set:
                        matched_bssid = addr3
                        if addr1 and addr1 != addr3:
                            client_candidate = bootp_mac or addr1
                        elif addr2 and addr2 != addr3:
                            client_candidate = bootp_mac or addr2

            elif dot11.type == 1:
                # 802.11 Control frames
                frame_priority = 1
                if subtype in (8, 10, 11):
                    if addr1 and addr1 in target_bssids_set:
                        matched_bssid = addr1
                        client_candidate = addr2
                    elif addr2 and addr2 in target_bssids_set:
                        matched_bssid = addr2
                        client_candidate = addr1

            elif dot11.type == 2:
                # Direct / IBSS / Null Data
                frame_priority = 3
                if addr1 and addr1 in target_bssids_set:
                    matched_bssid = addr1
                    client_candidate = bootp_mac or addr2
                elif addr2 and addr2 in target_bssids_set:
                    matched_bssid = addr2
                    client_candidate = bootp_mac or addr1
                elif addr3 and addr3 in target_bssids_set:
                    matched_bssid = addr3
                    client_candidate = bootp_mac or (addr2 if addr2 and addr2 != addr3 else addr1)

        # Elevate priority to 3 if a valid client IP was parsed from payload
        if client_ip:
            frame_priority = 3

        if matched_bssid and client_candidate:
            client_candidate = client_candidate.lower()
            matched_bssid = matched_bssid.lower()

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
                    curr_rssi = extract_packet_rssi(pkt)

                    # Determine if this frame is an active data transmission
                    is_data_carrying = False
                    if dot11.type == 2:
                        try:
                            sub_val = int(subtype) if subtype is not None else None
                        except (ValueError, TypeError):
                            sub_val = None

                        if sub_val in (0, 1, 2, 3, 8, 9, 10, 11):
                            is_data_carrying = True
                        elif hasattr(dot11, "payload") and dot11.payload is not None:
                            try:
                                p_bytes = bytes(dot11.payload)
                                if len(p_bytes) > 0:
                                    is_data_carrying = True
                            except Exception:
                                pass
                        elif sub_val is None:
                            is_data_carrying = True

                    is_active_frame = (dot11.type == 2 and is_data_carrying) or bool(client_ip and (to_ds or from_ds or dot11.type == 2))

                    # Ensure target BSSID bucket exists
                    if matched_bssid not in bssid_to_clients:
                        bssid_to_clients[matched_bssid] = {}

                    # Locate any existing BSSID association for this client
                    old_bssid = None
                    for b_cand, c_dict in bssid_to_clients.items():
                        if client_candidate in c_dict:
                            old_bssid = b_cand
                            break

                    if old_bssid is None:
                        # First time seeing this client station
                        bssid_to_clients[matched_bssid][client_candidate] = client_ip
                        if client_metadata is not None:
                            client_metadata[client_candidate] = {
                                "bssid": matched_bssid,
                                "priority": frame_priority,
                                "rssi": curr_rssi,
                                "ip": client_ip,
                                "active": is_active_frame,
                                "data_count": 1 if is_active_frame else (1 if frame_priority == 3 else 0),
                                "total_count": 1
                            }
                        if is_active_frame:
                            log_air(f"  [+] Active client: {client_candidate} on BSSID {matched_bssid}")
                        else:
                            log_air(f"  [+] Target Client: {client_candidate} on BSSID {matched_bssid}")

                    elif old_bssid == matched_bssid:
                        # Client seen again on its currently bound BSSID
                        existing_ip = bssid_to_clients[matched_bssid].get(client_candidate)
                        if client_ip and not existing_ip:
                            bssid_to_clients[matched_bssid][client_candidate] = client_ip

                        if client_metadata is not None:
                            meta = client_metadata.setdefault(client_candidate, {
                                "bssid": matched_bssid,
                                "priority": frame_priority,
                                "rssi": curr_rssi,
                                "ip": client_ip or existing_ip,
                                "active": False,
                                "data_count": 0,
                                "total_count": 0
                            })
                            prev_active = meta.get("active", False)
                            meta["priority"] = max(meta.get("priority", 1), frame_priority)
                            if is_active_frame:
                                meta["active"] = True
                            if curr_rssi is not None:
                                prev_rssi = meta.get("rssi")
                                meta["rssi"] = curr_rssi if prev_rssi is None else max(prev_rssi, curr_rssi)
                            if client_ip:
                                meta["ip"] = client_ip
                            if is_active_frame or frame_priority == 3:
                                meta["data_count"] = meta.get("data_count", 0) + 1
                            meta["total_count"] = meta.get("total_count", 0) + 1

                            if is_active_frame and not prev_active:
                                log_air(f"  [+] Active client: {client_candidate} on BSSID {matched_bssid}")

                    else:
                        # Client was previously bound to old_bssid, but now detected on matched_bssid
                        old_prio = 1
                        old_rssi = None
                        old_data_count = 0
                        old_active = False
                        old_ip = bssid_to_clients[old_bssid].get(client_candidate)

                        if client_metadata is not None and client_candidate in client_metadata:
                            meta = client_metadata[client_candidate]
                            old_prio = meta.get("priority", 1)
                            old_rssi = meta.get("rssi")
                            old_data_count = meta.get("data_count", 0)
                            old_active = meta.get("active", False)
                            if not old_ip:
                                old_ip = meta.get("ip")

                        # Re-association decision rule:
                        # 1. New frame has strictly higher priority (e.g. Data Frame vs Probe Request)
                        # 2. Equal priority, but new frame has significantly stronger RSSI (> 3 dBm) or old had no RSSI measurement
                        # 3. Equal priority == 3 (Data), but new BSSID has data activity while old had none
                        should_switch = False
                        if frame_priority > old_prio:
                            should_switch = True
                        elif frame_priority == old_prio:
                            if curr_rssi is not None and old_rssi is not None:
                                if curr_rssi > (old_rssi + 3):
                                    should_switch = True
                            elif curr_rssi is not None and old_rssi is None:
                                should_switch = True
                            elif frame_priority == 3 and old_data_count == 0:
                                should_switch = True

                        if should_switch:
                            # Migrate client cleanly from old_bssid to matched_bssid
                            bssid_to_clients[old_bssid].pop(client_candidate, None)
                            best_ip = client_ip or old_ip
                            bssid_to_clients[matched_bssid][client_candidate] = best_ip

                            new_active = is_active_frame or old_active
                            if client_metadata is not None:
                                client_metadata[client_candidate] = {
                                    "bssid": matched_bssid,
                                    "priority": frame_priority,
                                    "rssi": curr_rssi,
                                    "ip": best_ip,
                                    "active": new_active,
                                    "data_count": (old_data_count + 1 if is_active_frame else (1 if frame_priority == 3 else 0)),
                                    "total_count": (meta.get("total_count", 0) + 1) if (client_metadata and client_candidate in client_metadata) else 1
                                }
                            if is_active_frame and not old_active:
                                log_air(f"  [+] Active rebound: {client_candidate} -> BSSID {matched_bssid}")
                            else:
                                log_air(f"  [+] Rebound: {client_candidate} -> BSSID {matched_bssid}")
                        else:
                            # Retain binding on old_bssid, but update IP if newly discovered
                            if client_ip and not old_ip:
                                bssid_to_clients[old_bssid][client_candidate] = client_ip
                                if client_metadata is not None and client_candidate in client_metadata:
                                    client_metadata[client_candidate]["ip"] = client_ip
                            if is_active_frame and client_metadata is not None and client_candidate in client_metadata:
                                prev_active = client_metadata[client_candidate].get("active", False)
                                client_metadata[client_candidate]["active"] = True
                                if not prev_active:
                                    log_air(f"  [+] Active client: {client_candidate} on BSSID {old_bssid}")
    except Exception:
        pass
