"""
cafe_chameleon.scanners.air.stimulator - Active 802.11 packet stimulation engine.

Injects low-volume, high-efficiency 802.11 frames in monitor mode on active target channels:
1. Directed & Broadcast Probe Requests (forces APs to send high-power Probe Responses with client associations)
2. Micro-pulse Deauth/Disassoc triggers (forces dormant/power-saving clients to wake up and transmit re-association/auth frames)
3. Null Data / RTS frames (prompts APs to flush queued client downlink traffic)
"""

import random
import time

DEFAULT_STIM_MAC = "02:00:00:7c:4e:01"


def build_probe_req_packet(
    ssid: str = "",
    target_bssid: str = "ff:ff:ff:ff:ff:ff",
    source_mac: str = DEFAULT_STIM_MAC,
    channel: int = 1
):
    """
    Constructs an 802.11 Probe Request frame for the specified SSID and target BSSID.
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
    except ImportError:
        return None

    src = (source_mac or DEFAULT_STIM_MAC).lower()
    dst_mac = target_bssid.lower() if target_bssid else "ff:ff:ff:ff:ff:ff"
    bssid_mac = target_bssid.lower() if target_bssid and target_bssid != "ff:ff:ff:ff:ff:ff" else "ff:ff:ff:ff:ff:ff"

    ssid_bytes = ssid.encode("utf-8") if isinstance(ssid, str) else b""
    rates = b"\x82\x84\x8b\x96\x0c\x12\x18\x24"

    pkt = (
        RadioTap() /
        Dot11(type=0, subtype=4, addr1=dst_mac, addr2=src, addr3=bssid_mac) /
        Dot11ProbeReq() /
        Dot11Elt(ID="SSID", info=ssid_bytes) /
        Dot11Elt(ID="Rates", info=rates)
    )
    if 1 <= channel <= 14:
        pkt = pkt / Dot11Elt(ID="DSset", info=bytes([channel]))

    return pkt


def build_null_data_packet(
    target_bssid: str,
    source_mac: str = DEFAULT_STIM_MAC,
    to_ds: bool = True
):
    """
    Constructs an 802.11 Null Data (Keep-Alive / Polling) frame.
    """
    try:
        from scapy.all import RadioTap, Dot11
    except ImportError:
        return None

    src = (source_mac or DEFAULT_STIM_MAC).lower()
    fc = 1 if to_ds else 2  # to-DS or from-DS
    pkt = (
        RadioTap() /
        Dot11(type=2, subtype=4, FCfield=fc, addr1=target_bssid.lower(), addr2=src, addr3=target_bssid.lower())
    )
    return pkt


def build_wakeup_deauth_packet(
    target_bssid: str,
    client_mac: str = "ff:ff:ff:ff:ff:ff",
    reason: int = 7
):
    """
    Constructs an 802.11 Deauthentication micro-pulse frame to wake dormant clients.
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth
    except ImportError:
        return None

    pkt = (
        RadioTap() /
        Dot11(type=0, subtype=12, addr1=client_mac.lower(), addr2=target_bssid.lower(), addr3=target_bssid.lower()) /
        Dot11Deauth(reason=reason)
    )
    return pkt


class ClientStimulator:
    """
    Active 802.11 client stimulation coordinator for monitor mode discovery.
    """
    def __init__(
        self,
        interface: str,
        target_bssids: list[str],
        ssid: str = "",
        source_mac: str | None = None,
        enabled: bool = True,
        burst_count: int = 2
    ):
        self.interface = interface
        self.target_bssids = [b.lower() for b in target_bssids if b]
        self.ssid = ssid
        self.source_mac = (source_mac or DEFAULT_STIM_MAC).lower()
        self.enabled = enabled
        self.burst_count = max(1, burst_count)
        self._last_burst_time = 0.0

    def stimulate_channel(self, channel: int, target_bssid: str | None = None) -> int:
        """
        Transmits a stimulation packet burst on the current channel.
        Returns the number of frames transmitted.
        """
        if not self.enabled:
            return 0

        try:
            from scapy.all import sendp
        except ImportError:
            return 0

        packets_to_send = []

        # 1. SSID Broadcast Probe Request on active channel
        probe_pkt = build_probe_req_packet(
            ssid=self.ssid,
            target_bssid="ff:ff:ff:ff:ff:ff",
            source_mac=self.source_mac,
            channel=channel
        )
        if probe_pkt:
            packets_to_send.append(probe_pkt)

        # 2. Directed Probes & Wakeup Deauth pulses for target BSSIDs on this channel
        bssids_to_ping = [target_bssid.lower()] if target_bssid else self.target_bssids
        for bssid in bssids_to_ping[:4]:  # limit to top 4 BSSIDs per burst to avoid congestion
            directed_probe = build_probe_req_packet(
                ssid=self.ssid,
                target_bssid=bssid,
                source_mac=self.source_mac,
                channel=channel
            )
            if directed_probe:
                packets_to_send.append(directed_probe)

            # Micro-pulse wake-up deauth to broadcast (prompts dormant stations to re-auth/re-assoc)
            deauth_pkt = build_wakeup_deauth_packet(
                target_bssid=bssid,
                client_mac="ff:ff:ff:ff:ff:ff",
                reason=7
            )
            if deauth_pkt:
                packets_to_send.append(deauth_pkt)

            # Null data frame to AP
            null_pkt = build_null_data_packet(
                target_bssid=bssid,
                source_mac=self.source_mac
            )
            if null_pkt:
                packets_to_send.append(null_pkt)

        if not packets_to_send:
            return 0

        sent_count = 0
        try:
            sendp(packets_to_send, iface=self.interface, count=self.burst_count, inter=0.01, verbose=False)
            sent_count = len(packets_to_send) * self.burst_count
            self._last_burst_time = time.time()
        except Exception:
            pass

        return sent_count
