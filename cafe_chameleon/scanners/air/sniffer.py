"""
cafe_chameleon.scanners.air.sniffer - Over-the-air 802.11 monitor mode client discovery coordinator.
"""

import re
import threading
import time
from cafe_chameleon.config import DEFAULT_AIR_DURATION, DEFAULT_BSSID_THRESHOLD
from cafe_chameleon.utils.signals import AirSkipInterrupt
from cafe_chameleon.ui.console import log_air, set_air_status
from cafe_chameleon.scanners.detector import auto_detect_network_params
from cafe_chameleon.utils.state import get_use_xterm
from cafe_chameleon.ui.xterm import XtermManager

from .mode import set_monitor_mode, set_managed_mode
from .hopper import ChannelHopper
from .packet_parser import parse_air_packet
from .stimulator import ClientStimulator

DIGIT_REGEX = re.compile(r"[^\d]")


def format_air_panel(
    client_metadata: dict | None = None,
    mode: str = "Monitor",
    remaining: str | int | None = "N/A",
    duration: int | None = None,
    include_banner: bool = True
) -> str:
    """
    Renders the Air Sniffer information panel:
    - Banner with 'AIR SNIFFER' header (if include_banner=True)
    - Mode and duration/remaining status (if include_banner=True)
    - Separator lines
    - Cleanly aligned table with columns: #, CLIENT BSSID, AP BSSID, IS ACTIVE
    """
    lines = []
    if include_banner:
        if mode == "Monitor":
            mode_colored = "\033[38;5;208mMonitor\033[0m"
        else:
            mode_colored = "\033[1;32mManaged\033[0m"

        if remaining is None or str(remaining).strip() == "":
            rem_str = "N/A"
        elif isinstance(remaining, (int, float)):
            rem_str = f"{int(remaining)}s"
        else:
            r_str = str(remaining).strip()
            rem_str = f"{r_str}s" if r_str.isdigit() else r_str

        if duration == 0:
            dur_info = " | \033[1;37mDuration:\033[0m \033[1;36mIndefinite\033[0m"
        elif duration and duration > 0:
            dur_info = f" | \033[1;37mDuration:\033[0m \033[1;36m{duration}s\033[0m"
        else:
            dur_info = ""

        lines.append("\033[1;35m─── 802.11 AIR SNIFFER ─────────────────────────────────\033[0m")
        lines.append(f"\033[1;37mMode:\033[0m {mode_colored}{dur_info} | \033[1;37mRemaining:\033[0m \033[1;33m{rem_str}\033[0m")
        lines.append("\033[1;30m────────────────────────────────────────────────────────\033[0m")

    lines.append(f"{'#':<4} {'CLIENT BSSID':<20} {'AP BSSID':<20} {'IS ACTIVE'}")
    lines.append("\033[1;30m────────────────────────────────────────────────────────\033[0m")

    clients_dict = client_metadata or {}
    if not clients_dict:
        lines.append("  (No clients captured yet...)")
    else:
        # Sort clients: active clients first, then alphabetically by MAC
        sorted_clients = sorted(
            clients_dict.items(),
            key=lambda item: (not bool(item[1].get("active") if isinstance(item[1], dict) else False), item[0])
        )
        for idx, (client_mac, meta) in enumerate(sorted_clients, start=1):
            if isinstance(meta, dict):
                ap_bssid = meta.get("bssid") or "N/A"
                is_active = bool(meta.get("active", False))
            else:
                ap_bssid = str(meta) if meta else "N/A"
                is_active = False

            active_colored = "\033[1;32mTrue\033[0m" if is_active else "\033[37mFalse\033[0m"
            lines.append(f" {idx:<3} {client_mac:<20} {ap_bssid:<20} {active_colored}")

    lines.append("\033[1;30m────────────────────────────────────────────────────────\033[0m")
    return "\n".join(lines)


class AirCountdownTimer:
    """Manages background countdown timer updating the air sniffer remaining seconds and rendering the live client table."""
    def __init__(
        self,
        duration: int,
        interval: float = 1.0,
        client_metadata: dict | None = None,
        on_tick=None,
        waiting_for_active: bool = False
    ):
        self.duration = duration
        self.interval = interval
        self.client_metadata = client_metadata if client_metadata is not None else {}
        self.on_tick = on_tick
        self.waiting_for_active = waiting_for_active
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._countdown_end = None
        self._active_triggered_duration = None
        self._thread = None

    def trigger_countdown(self, duration: int = 30) -> None:
        """Dynamically starts a countdown timer (e.g. when an active target is first detected)."""
        with self._lock:
            self.waiting_for_active = False
            self._active_triggered_duration = duration
            self._countdown_end = time.time() + duration
            set_air_status(mode="Monitor", remaining=f"{duration}s")
            self._render_tick(duration)

    def start(self) -> None:
        with self._lock:
            if self.waiting_for_active:
                set_air_status(mode="Monitor", remaining="Waiting for active...")
                self._render_tick("Waiting for active...")
            elif self.duration == 0:
                set_air_status(mode="Monitor", remaining="Indefinite")
                self._render_tick("Indefinite")
            else:
                self._countdown_end = time.time() + self.duration
                set_air_status(mode="Monitor", remaining=f"{self.duration}s")
                self._render_tick(self.duration)

        def timer_loop():
            while not self.stop_event.is_set():
                self.stop_event.wait(self.interval)
                if self.stop_event.is_set():
                    break
                with self._lock:
                    if self.waiting_for_active:
                        set_air_status(mode="Monitor", remaining="Waiting for active...")
                        self._render_tick("Waiting for active...")
                    elif self._countdown_end is not None:
                        now = time.time()
                        remaining = max(0, int(round(self._countdown_end - now)))
                        set_air_status(mode="Monitor", remaining=f"{remaining}s")
                        self._render_tick(remaining)
                        if remaining <= 0:
                            break
                    elif self.duration == 0:
                        set_air_status(mode="Monitor", remaining="Indefinite")
                        self._render_tick("Indefinite")

        self._thread = threading.Thread(target=timer_loop, daemon=True)
        self._thread.start()

    def _render_tick(self, remaining: int | str) -> None:
        if self.on_tick:
            try:
                self.on_tick(remaining)
            except Exception:
                pass
        else:
            is_xterm = bool(get_use_xterm() and XtermManager and XtermManager._instance and XtermManager._instance.enabled)
            eff_dur = self._active_triggered_duration if self._active_triggered_duration is not None else self.duration
            panel = format_air_panel(
                client_metadata=self.client_metadata,
                mode="Monitor",
                remaining=remaining,
                duration=eff_dur,
                include_banner=not is_xterm
            )
            log_air(panel, clear=True)

    def stop(self, timeout: float = 1.0) -> None:
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)


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

    def is_confirmed_client(self, mac: str) -> bool:
        """
        Returns True if the client has confirmed association/data activity,
        an assigned IP address, or is not pure unassociated LAA probe noise.
        """
        if not mac:
            return False
        meta = self.client_metadata.get(mac.lower())
        if not meta or not isinstance(meta, dict):
            return True
        if meta.get("active") or meta.get("ip"):
            return True
        if meta.get("data_count", 0) >= 1:
            return True
        # If seen only in probe requests and has LAA randomized MAC without IP/Data, treat as unconfirmed probe noise
        if meta.get("is_laa") and meta.get("probe_count", 0) > 0 and meta.get("data_count", 0) == 0:
            return False
        return True

    def get_confirmed_clients_for_bssid(self, bssid: str) -> dict[str, str | None]:
        """Returns dict of confirmed clients (mac -> ip) for a given BSSID."""
        if not bssid:
            return {}
        bssid_lower = bssid.lower()
        clients = self.get(bssid_lower, {})
        if not isinstance(clients, dict):
            return {}
        return {
            mac: ip for mac, ip in clients.items()
            if self.is_confirmed_client(mac)
        }


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

        sig_factor = 0.85 + (sig / 200.0)
        density_bonus = min(0.15, (density - 1) * 0.05) if density > 1 else 0.0

        factor = sig_factor + density_bonus
        dwell = round(base_dwell * factor, 2)
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
    enable_stimulation: bool = True,
    trigger_on_active: bool = False,
    active_trigger_duration: int = DEFAULT_AIR_DURATION
) -> dict:
    """
    Switches to monitor mode, sniffs 802.11 frames over-the-air for `duration` seconds,
    maps active client MAC and IP addresses to target BSSIDs, cleanly restores managed mode,
    and transmits targeted 802.11 stimulation packets to wake sleeping clients and prompt APs.
    Supports duration=0 for indefinite monitoring, and trigger_on_active for dynamic 30s collection.
    """
    try:
        from scapy.all import sniff, Dot11, IP, ARP, BOOTP, DHCP
    except ImportError:
        try:
            from scapy.all import sniff, Dot11, IP, ARP
            BOOTP, DHCP = None, None
        except ImportError:
            log_air("[-] scapy required for frame capture (pip install scapy)")
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
    try:
        from cafe_chameleon.utils.blacklist import load_blacklist
        ignore_macs.update(load_blacklist())
    except Exception:
        pass

    hopper = None
    client_metadata = {}
    active_triggered_event = threading.Event()
    countdown_deadline = [None]

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
        else:
            hop_channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 2, 3, 4, 5, 7, 8, 9, 10]
            if use_weighted and channel_signals:
                dwell_times = calculate_channel_dwell_times(hop_channels, channel_signals, channel_densities=channel_densities)

        effective_duration = duration
        if auto_scale_duration and hop_channels and duration > 0:
            scaled_dur = calculate_scaled_air_duration(base_duration=duration, channel_count=len(hop_channels))
            if scaled_dur > effective_duration:
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
            if trigger_on_active and effective_duration == 0 and not active_triggered_event.is_set():
                has_active = any(
                    isinstance(meta, dict) and meta.get("active")
                    for meta in client_metadata.values()
                )
                if has_active:
                    active_triggered_event.set()
                    countdown_deadline[0] = time.time() + active_trigger_duration
                    timer.trigger_countdown(active_trigger_duration)
                    log_air(f"\n\033[1;32m[+] Active target detected! Starting {active_trigger_duration}s collection window...\033[0m\n")

        def stop_check(pkt):
            if trigger_on_active and effective_duration == 0:
                if active_triggered_event.is_set() and countdown_deadline[0] is not None:
                    return time.time() >= countdown_deadline[0]
            return False

        def on_channel_hop(ch: int):
            if stimulator:
                stimulator.stimulate_channel(ch)

        hopper = ChannelHopper(mon_iface, hop_channels, dwell_times=dwell_times, on_channel_change=on_channel_hop)
        hopper.start()

        timer = AirCountdownTimer(
            duration=effective_duration,
            interval=1.0,
            client_metadata=client_metadata,
            waiting_for_active=bool(effective_duration == 0 and trigger_on_active)
        )
        timer.start()

        sniff_timeout = None if effective_duration == 0 else effective_duration
        try:
            try:
                from scapy.config import conf
                if hasattr(conf, "ifaces") and hasattr(conf.ifaces, "reload"):
                    conf.ifaces.reload()
            except Exception:
                pass

            sniff(
                iface=mon_iface,
                timeout=sniff_timeout,
                prn=air_packet_callback,
                stop_filter=stop_check if (trigger_on_active and effective_duration == 0) else None,
                store=False
            )
        finally:
            timer.stop()
    except (AirSkipInterrupt, KeyboardInterrupt):
        log_air("\n\033[93m[-] Stopped air sniff (Ctrl+C).\033[0m")
    except Exception as e:
        from cafe_chameleon.utils.tracing import trace, log_exception_to_trace
        trace(f"[FEATURE] Air capture error on {interface} ({mon_iface if 'mon_iface' in locals() else 'unknown'}): {e}")
        log_exception_to_trace(e)
        log_air(f"[-] Air capture error on {interface}: {e}")
    finally:
        if hopper:
            hopper.stop(timeout=1.0)
        log_air("", clear=True)
        set_managed_mode(interface)
        set_air_status(mode="Managed", remaining="0s")
        is_xterm = bool(get_use_xterm() and XtermManager and XtermManager._instance and XtermManager._instance.enabled)
        final_panel = format_air_panel(
            client_metadata=client_metadata,
            mode="Managed",
            remaining="0s",
            duration=active_trigger_duration if (trigger_on_active and active_triggered_event.is_set()) else effective_duration,
            include_banner=not is_xterm
        )
        log_air(final_panel, clear=True)

    return AirClientsMap(bssid_to_clients, client_metadata=client_metadata)
