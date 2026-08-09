"""
cafe_chameleon.scanners.air.sniffer - Over-the-air 802.11 monitor mode client discovery coordinator.
"""

import re
from cafe_chameleon.config import DEFAULT_AIR_DURATION, DEFAULT_BSSID_THRESHOLD
from cafe_chameleon.utils.signals import AirSkipInterrupt
from cafe_chameleon.ui.console import log_air
from cafe_chameleon.scanners.detector import auto_detect_network_params

from .mode import set_monitor_mode, set_managed_mode
from .hopper import ChannelHopper
from .packet_parser import parse_air_packet

DIGIT_REGEX = re.compile(r"[^\d]")


def parse_clean_int(val) -> int | None:
    """Extracts integer value from string or number safely."""
    try:
        clean = DIGIT_REGEX.sub("", str(val))
        return int(clean) if clean else None
    except (ValueError, TypeError):
        return None


def calculate_channel_signals(bssids: list | None) -> dict[int, int]:
    """
    Computes maximum signal strength percentage for each channel present in the BSSID list.
    Returns: {channel_number: max_signal_pct}
    """
    channel_signals: dict[int, int] = {}
    if not bssids:
        return channel_signals

    for b in bssids:
        chan_val = b.get("chan") if hasattr(b, "get") else getattr(b, "chan", None)
        sig_val = b.get("signal") if hasattr(b, "get") else getattr(b, "signal", None)

        ch = parse_clean_int(chan_val)
        sig = parse_clean_int(sig_val) or 0

        if ch and ch > 0:
            channel_signals[ch] = max(channel_signals.get(ch, 0), sig)

    return channel_signals


def should_weight_channels_by_signal(bssid_count: int, threshold: int = DEFAULT_BSSID_THRESHOLD) -> bool:
    """
    Determines if signal-weighted channel hopping should be applied:
    - If threshold is 0: force signal-weighted behavior regardless of BSSID count.
    - If threshold > 0: only apply when BSSID count > threshold.
    """
    if threshold == 0:
        return True
    return bssid_count > threshold


def calculate_channel_dwell_times(
    channels: list[int],
    channel_signals: dict[int, int],
    base_dwell: float = 0.25
) -> dict[int, float]:
    """
    Calculates channel dwell times based on signal strength percentage.
    Channels with stronger BSSID signals receive proportionally more time.
    """
    dwell_times: dict[int, float] = {}
    for ch in channels:
        sig = channel_signals.get(ch, 0)
        # Scale dwell time proportional to signal strength (from 0.15s for 0% up to 0.75s for 100%)
        factor = max(0.6, sig / 40.0)
        dwell = round(base_dwell * factor, 2)
        dwell_times[ch] = max(0.15, dwell)

    return dwell_times


def sniff_air_clients(
    target_bssids: list[str],
    interface: str = "wlan0",
    duration: int = DEFAULT_AIR_DURATION,
    target_channels: list[int] | None = None,
    bssids: list | None = None,
    bssid_threshold: int = DEFAULT_BSSID_THRESHOLD
) -> dict:
    """
    Switches to monitor mode, sniffs 802.11 frames over-the-air for `duration` seconds,
    maps active client MAC and IP addresses to target BSSIDs, and cleanly restores managed mode.
    Focuses channel hopping specifically on target_channels when supplied.
    When BSSID count exceeds bssid_threshold (or threshold is 0), allocates more time to channels
    with stronger BSSID signals.

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

    hopper = None
    try:
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

        channel_signals = calculate_channel_signals(bssids) if bssids else {}
        bssid_count = len(bssids) if bssids is not None else len(target_bssids)
        use_weighted = should_weight_channels_by_signal(bssid_count, threshold=bssid_threshold)

        dwell_times = None
        if valid_target_channels:
            hop_channels = valid_target_channels
            if use_weighted and channel_signals:
                dwell_times = calculate_channel_dwell_times(hop_channels, channel_signals)
                log_air(f"[*] Signal-weighted channel hopping enabled ({bssid_count} BSSIDs, threshold: {bssid_threshold})")
        else:
            log_air("Using all channels")
            hop_channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10]
            if use_weighted and channel_signals:
                dwell_times = calculate_channel_dwell_times(hop_channels, channel_signals)
                log_air(f"[*] Signal-weighted channel hopping enabled ({bssid_count} BSSIDs, threshold: {bssid_threshold})")

        log_air(f"[*] Sniffing frames on {mon_iface} ({duration}s)...")

        def air_packet_callback(pkt):
            parse_air_packet(pkt, target_bssids_set, ignore_macs, bssid_to_clients, BOOTP=BOOTP, DHCP=DHCP)

        hopper = ChannelHopper(mon_iface, hop_channels, dwell_times=dwell_times)
        hopper.start()

        sniff(iface=mon_iface, timeout=duration, prn=air_packet_callback, store=False)
    except (AirSkipInterrupt, KeyboardInterrupt):
        log_air("\n\033[93m[-] Stopped air sniff (Ctrl+C). Processing captured targets...\033[0m")
    except Exception as e:
        log_air(f"[-] Over-the-air capture exception on {interface}: {e}")
    finally:
        if hopper:
            hopper.stop(timeout=1.0)
        set_managed_mode(interface)

    total_clients = sum(len(c) for c in bssid_to_clients.values())
    if total_clients > 0:
        log_air(f"\n[+] Air Sniff Complete: Found {total_clients} target client(s).")
    else:
        log_air("\n[i] Air Sniff Complete: No active clients captured.")

    return bssid_to_clients
