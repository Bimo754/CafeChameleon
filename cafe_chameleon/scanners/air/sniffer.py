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
from .stimulator import ClientStimulator

DIGIT_REGEX = re.compile(r"[^\d]")


class AirClientsMap(dict):
    """
    Specialized mapping container for BSSID-to-clients dictionary that preserves
    full dict interface ({bssid: {client_mac: ip}}) while providing attached
    client metadata, active status tracking, and helper querying methods.
    """
    def __init__(self, *args, client_metadata: dict | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_metadata: dict = client_metadata or {}

    @property
    def active_clients(self) -> set[str]:
        """Returns set of all active client MAC addresses."""
        return {
            mac.lower() for mac, meta in self.client_metadata.items()
            if isinstance(meta, dict) and meta.get("active")
        }

    def is_client_active(self, mac: str) -> bool:
        if not mac:
            return False
        meta = self.client_metadata.get(mac.lower())
        return bool(meta and meta.get("active"))

    def count_active_clients(self, bssid: str) -> int:
        if not bssid:
            return 0
        bssid_lower = bssid.lower()
        clients = self.get(bssid_lower, {})
        if not isinstance(clients, dict):
            return 0
        return sum(1 for mac in clients if self.is_client_active(mac))

    def get_active_clients_for_bssid(self, bssid: str) -> list[str]:
        if not bssid:
            return []
        bssid_lower = bssid.lower()
        clients = self.get(bssid_lower, {})
        if not isinstance(clients, dict):
            return []
        return [mac for mac in clients if self.is_client_active(mac)]


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


def calculate_channel_densities(bssids: list | None) -> dict[int, int]:
    """
    Computes count of target BSSIDs present on each channel.
    Returns: {channel_number: bssid_count}
    """
    channel_densities: dict[int, int] = {}
    if not bssids:
        return channel_densities

    for b in bssids:
        chan_val = b.get("chan") if hasattr(b, "get") else getattr(b, "chan", None)
        ch = parse_clean_int(chan_val)
        if ch and ch > 0:
            channel_densities[ch] = channel_densities.get(ch, 0) + 1

    return channel_densities


def should_weight_channels_by_signal(bssid_count: int, threshold: int = DEFAULT_BSSID_THRESHOLD) -> bool:
    """
    Determines if signal/density-weighted channel hopping should be applied:
    - If threshold is 0: force weighted behavior regardless of BSSID count.
    - If threshold > 0: only apply when BSSID count > threshold.
    """
    try:
        t_val = int(threshold)
    except (ValueError, TypeError):
        t_val = DEFAULT_BSSID_THRESHOLD
    if t_val == 0:
        return True
    return bssid_count > t_val


def calculate_channel_dwell_times(
    channels: list[int],
    channel_signals: dict[int, int],
    base_dwell: float = 0.30,
    channel_densities: dict[int, int] | None = None
) -> dict[int, float]:
    """
    Calculates channel dwell times based on signal strength percentage and BSSID density.
    Applies gentle scaling so strong channels get slightly more dwell without starving weaker/far channels.
    Maintains a robust floor of 0.25s and caps maximum dwell at 0.50s to guarantee frequent hopping cycles.
    """
    dwell_times: dict[int, float] = {}
    densities = channel_densities or {}

    for ch in channels:
        sig = channel_signals.get(ch, 0)
        density = densities.get(ch, 1)

        # Gentle scaling factor from signal strength (0.85 for 0% up to 1.35 for 100%)
        sig_factor = 0.85 + (sig / 200.0)
        # Bonus factor for channels with multiple target BSSIDs (up to +15%)
        density_bonus = min(0.15, (density - 1) * 0.05) if density > 1 else 0.0

        factor = sig_factor + density_bonus
        dwell = round(base_dwell * factor, 2)
        # Bounded between 0.25s and 0.50s to guarantee fast, balanced cycles across far & near APs
        dwell_times[ch] = max(0.25, min(0.50, dwell))

    return dwell_times


def calculate_scaled_air_duration(
    base_duration: int = DEFAULT_AIR_DURATION,
    channel_count: int = 1,
    min_seconds_per_channel: float = 4.0
) -> int:
    """
    Auto-scales the air sniffing duration based on unique channel count to guarantee
    sufficient dwell cycles per channel.
    """
    if channel_count <= 0:
        return base_duration
    scaled = int(round(channel_count * min_seconds_per_channel))
    return max(base_duration, scaled)


def sniff_air_clients(
    target_bssids: list[str],
    interface: str = "wlan0",
    duration: int = DEFAULT_AIR_DURATION,
    target_channels: list[int] | None = None,
    bssids: list | None = None,
    bssid_threshold: int = DEFAULT_BSSID_THRESHOLD,
    auto_scale_duration: bool = False,
    ssid: str = "",
    enable_stimulation: bool = True
) -> dict:
    """
    Switches to monitor mode, sniffs 802.11 frames over-the-air for `duration` seconds,
    maps active client MAC and IP addresses to target BSSIDs, cleanly restores managed mode,
    and transmits targeted 802.11 stimulation packets to wake sleeping clients and prompt APs.
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
    client_metadata = {}
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
        channel_densities = calculate_channel_densities(bssids) if bssids else {}
        bssid_count = len(bssids) if bssids is not None else len(target_bssids)
        use_weighted = should_weight_channels_by_signal(bssid_count, threshold=bssid_threshold)

        dwell_times = None
        if valid_target_channels:
            hop_channels = valid_target_channels
            if use_weighted and channel_signals:
                dwell_times = calculate_channel_dwell_times(hop_channels, channel_signals, channel_densities=channel_densities)
                log_air(f"[*] Balanced signal & density-weighted hopping enabled ({bssid_count} BSSIDs, threshold: {bssid_threshold})")
        else:
            log_air("Using all channels")
            hop_channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10]
            if use_weighted and channel_signals:
                dwell_times = calculate_channel_dwell_times(hop_channels, channel_signals, channel_densities=channel_densities)
                log_air(f"[*] Balanced signal & density-weighted hopping enabled ({bssid_count} BSSIDs, threshold: {bssid_threshold})")

        effective_duration = duration
        if auto_scale_duration and hop_channels:
            scaled_dur = calculate_scaled_air_duration(base_duration=duration, channel_count=len(hop_channels))
            if scaled_dur > effective_duration:
                log_air(f"[*] Auto-scaled air sniffing duration to {scaled_dur}s ({len(hop_channels)} unique channels detected)")
                effective_duration = scaled_dur

        # Initialize Active Client Stimulator
        stimulator = None
        if enable_stimulation:
            stimulator = ClientStimulator(
                interface=mon_iface,
                target_bssids=target_bssids,
                ssid=ssid,
                source_mac=local_mac or "02:00:00:7c:4e:01",
                enabled=True
            )
            if stimulator.source_mac:
                ignore_macs.add(stimulator.source_mac.lower())
            log_air(f"[*] Active 802.11 client stimulation enabled (Probe Requests, Micro-pulse Wake-up & Null Data)")

        # Estimate cycle time across target channels
        est_cycle_time = sum(dwell_times.get(ch, 0.25) for ch in hop_channels) if dwell_times else (len(hop_channels) * 0.25)
        if est_cycle_time > 0 and effective_duration < (est_cycle_time * 2):
            log_air(f"[i] Notice: Sniff duration ({effective_duration}s) allows ~{effective_duration / est_cycle_time:.1f} channel hopping cycles across {len(hop_channels)} channels.")

        log_air(f"[*] Sniffing frames on {mon_iface} ({effective_duration}s)...")

        client_metadata = {}

        def air_packet_callback(pkt):
            parse_air_packet(
                pkt,
                target_bssids_set,
                ignore_macs,
                bssid_to_clients,
                BOOTP=BOOTP,
                DHCP=DHCP,
                client_metadata=client_metadata
            )

        def on_channel_hop(ch: int):
            if stimulator:
                stimulator.stimulate_channel(ch)

        hopper = ChannelHopper(mon_iface, hop_channels, dwell_times=dwell_times, on_channel_change=on_channel_hop)
        hopper.start()

        sniff(iface=mon_iface, timeout=effective_duration, prn=air_packet_callback, store=False)
    except (AirSkipInterrupt, KeyboardInterrupt):
        log_air("\n\033[93m[-] Stopped air sniff (Ctrl+C). Processing captured targets...\033[0m")
    except Exception as e:
        log_air(f"[-] Over-the-air capture exception on {interface}: {e}")
    finally:
        if hopper:
            hopper.stop(timeout=1.0)
        set_managed_mode(interface)

    total_clients = sum(len(c) for c in bssid_to_clients.values())
    active_clients_count = sum(1 for m, info in client_metadata.items() if info.get("active"))
    if total_clients > 0:
        active_suffix = f" ({active_clients_count} active)" if active_clients_count > 0 else ""
        log_air(f"\n[+] Air Sniff Complete: Found {total_clients} target client(s){active_suffix}.")
    else:
        log_air("\n[i] Air Sniff Complete: No active clients captured.")

    return AirClientsMap(bssid_to_clients, client_metadata=client_metadata)
