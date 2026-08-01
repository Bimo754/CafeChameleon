"""
cafe_chameleon.scanners.air.sniffer - Over-the-air 802.11 monitor mode client discovery coordinator.
"""

from cafe_chameleon.utils.signals import AirSkipInterrupt
from cafe_chameleon.ui.console import log_air
from cafe_chameleon.scanners.detector import auto_detect_network_params

from .mode import set_monitor_mode, set_managed_mode
from .hopper import ChannelHopper
from .packet_parser import parse_air_packet


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
        parse_air_packet(pkt, target_bssids_set, ignore_macs, bssid_to_clients, BOOTP=BOOTP, DHCP=DHCP)

    hopper = ChannelHopper(mon_iface, hop_channels)
    hopper.start()

    try:
        sniff(iface=mon_iface, timeout=duration, prn=air_packet_callback, store=False)
    except (AirSkipInterrupt, KeyboardInterrupt):
        log_air("\n\033[93m[-] Stopped air sniff. Processing captured targets...\033[0m")
    except Exception as e:
        log_air(f"[-] Over-the-air capture exception on {mon_iface}: {e}")
    finally:
        hopper.stop(timeout=1.0)
        set_managed_mode(interface)

    total_clients = sum(len(c) for c in bssid_to_clients.values())
    if total_clients > 0:
        log_air(f"\n[+] Air Sniff Complete: Found {total_clients} target client(s).")
    else:
        log_air("\n[i] Air Sniff Complete: No active clients captured.")

    return bssid_to_clients
