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
    log_subnet_scan,
    set_main_status,
    set_scan_status,
    set_hijack_status,
    log_hijack,
    clear_window,
    log_step,
    get_user_input
)
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.mac import set_mac_address, get_attack_mac
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.network.nmcli import (
    get_active_profile,
    get_ssid_for_profile,
    scan_bssids_for_ssid,
    lock_bssid
)
from cafe_chameleon.config import DEFAULT_AIR_DURATION
from cafe_chameleon.scanners.detector import auto_detect_network_params
from cafe_chameleon.scanners.air import (
    sniff_air_clients,
    is_monitor_mode_active,
    set_managed_mode,
    calculate_scaled_air_duration
)

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.state import set_restore_params
from .selector import display_and_select_bssid
from .air_target_handler import filter_valid_air_clients, test_air_client_targets
from .ranker import is_client_active
from cafe_chameleon.network.hotspot import share_wifi_hotspot
from cafe_chameleon.utils.blacklist import is_blacklisted, load_blacklist


def handle_auto_share_if_requested(args, interface: str) -> None:
    """Automatically launches Wi-Fi Hotspot sharing if --share was passed to aggressive mode."""
    share_val = getattr(args, "share", None)
    if share_val:
        hotspot_name, hotspot_pass = share_val
        log_main(f"[+] Launching Wi-Fi Hotspot sharing (--share '{hotspot_name}')...")
        share_wifi_hotspot(hotspot_name=hotspot_name, password=hotspot_pass, interface=interface)


def run_scan_wrapper(args, quiet_header=False):
    """Deferred import to avoid circular dependency with simple scan runner."""
    from cafe_chameleon.modes.simple import run_simple
    return run_simple(args, quiet_header=quiet_header)


def run_aggressive(args) -> bool:
    """
    Main subcommand handler for Aggressive mode.
    Connects to each available BSSID for the target SSID one by one,
    checking for internet access or scanning until internet access is granted.
    Supports --air / --air-only over-the-air 802.11 monitor mode client discovery & direct takeover.
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
    set_restore_params(interface, "", "", "", "", profile=profile)

    air_arg = getattr(args, "air", None)
    air_only_arg = getattr(args, "air_only", None)
    is_air_only = air_only_arg is not None
    is_air = air_arg is not None or is_air_only
    air_duration = DEFAULT_AIR_DURATION
    user_specified_duration = False

    effective_air_arg = air_only_arg if air_only_arg is not None else air_arg
    if is_air:
        if isinstance(effective_air_arg, int) and effective_air_arg >= 0:
            air_duration = effective_air_arg
            user_specified_duration = True
        elif sys.stdin.isatty():
            try:
                val = get_user_input(f"Enter duration in seconds to listen in monitor mode [default: {DEFAULT_AIR_DURATION}]: ").strip()
                if val.isdigit() and int(val) >= 0:
                    air_duration = int(val)
                    user_specified_duration = True
            except (KeyboardInterrupt, EOFError):
                pass

    is_continuous_air_only = bool(is_air_only and air_duration == 0)

    if is_air:
        if air_duration == 0:
            status_str = "Air Sniffing (Hunting)" if is_air_only else "Air Sniffing (Indefinite)"
        else:
            status_str = f"Air Sniffing ({air_duration}s)"
    else:
        status_str = "Active Exploration"
    set_main_status(interface=interface, profile=profile, ssid=ssid, status=status_str)

    # 1. Initial internet check
    if has_internet():
        if not getattr(args, "force", False):
            log_main("[+] Internet online.")
            handle_auto_share_if_requested(args, interface)
            return True
        else:
            log_main("[!] Internet online (--force enabled). Continuing exploration...")

    # Continuous Active-Triggered Air-Only Hunting Loop (--air-only 0)
    if is_continuous_air_only:
        cycle = 1
        last_skip_time = 0
        persisted_bssid_targets = None
        tried_macs = set()

        while True:
            if profile:
                _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""], debug=False)
                _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""], debug=False)

            if is_monitor_mode_active(interface):
                set_managed_mode(interface)
                wait_for_carrier(interface, timeout=3.0)
                time.sleep(1.0)

            if has_internet():
                if not getattr(args, "force", False):
                    log_main("[+] Internet online.")
                    handle_auto_share_if_requested(args, interface)
                    return True
                else:
                    log_main("[!] Internet online (--force enabled). Continuing exploration...")

            bssids = scan_bssids_for_ssid(ssid)
            if not bssids:
                time.sleep(2.0)
                cycle += 1
                continue

            blacklist = load_blacklist()
            bssids = [b for b in bssids if not is_blacklisted(b.get("bssid", ""), blacklist)]
            if persisted_bssid_targets:
                bssids = [b for b in bssids if b.get("bssid", "").lower() in persisted_bssid_targets]
            if not bssids:
                time.sleep(2.0)
                cycle += 1
                continue

            log_main(f"[Cycle #{cycle}] Hunting...")
            set_main_status(interface=interface, profile=profile, ssid=ssid, status=f"Air Sniffing (Hunting) [#{cycle}]")

            target_bssid_list = [b["bssid"] for b in bssids]
            target_channel_list = [b["chan"] for b in bssids if b.get("chan")]
            threshold_val = getattr(args, "threshold", getattr(args, "bssid_threshold", 10))
            passive_only = getattr(args, "passive_only", False)

            air_clients_map = sniff_air_clients(
                target_bssid_list,
                interface=interface,
                duration=0,
                target_channels=target_channel_list,
                bssids=bssids,
                bssid_threshold=threshold_val,
                ssid=ssid,
                enable_stimulation=not passive_only,
                trigger_on_active=True,
                active_trigger_duration=30
            )
            if is_monitor_mode_active(interface):
                set_managed_mode(interface)
                wait_for_carrier(interface, timeout=3.0)
                time.sleep(1.0)
            set_main_status(status=f"Active Exploration [#{cycle}]")

            any_bssid_mode = bool(getattr(args, "any_bssid", False) is True)
            prioritize_clients = bool(
                not any_bssid_mode and (getattr(args, "clients", False) is True or getattr(args, "prioritize_clients", False) is True)
            )

            pooled_air_clients = {}
            if air_clients_map:
                for b_clients in air_clients_map.values():
                    if isinstance(b_clients, dict):
                        for mac, ip in b_clients.items():
                            if is_client_active(mac, air_clients_map):
                                if mac not in pooled_air_clients or (not pooled_air_clients[mac] and ip):
                                    pooled_air_clients[mac] = ip

            select_req = getattr(args, "select_bssid", False) if cycle == 1 else False
            ranked_bssids = display_and_select_bssid(
                bssids,
                air_clients_map,
                select_req,
                prioritize_clients=prioritize_clients,
                is_air_only=is_air_only
            )
            if cycle == 1 and getattr(args, "select_bssid", False) and ranked_bssids:
                persisted_bssid_targets = {b["bssid"].lower() for b in ranked_bssids}

            for idx, item in enumerate(ranked_bssids, start=1):
                target_bssid = item["bssid"]
                if is_blacklisted(target_bssid, blacklist):
                    continue

                signal_pct = item["signal"]
                chan = item["chan"]
                target_sec = item.get("security", "")

                if any_bssid_mode:
                    bssid_air_clients = pooled_air_clients
                else:
                    bssid_air_clients = {
                        m: ip for m, ip in air_clients_map.get(target_bssid.lower(), {}).items()
                        if is_client_active(m, air_clients_map)
                    }

                auto_params = auto_detect_network_params(target_iface=interface)
                new_air_clients = filter_valid_air_clients(
                    bssid_air_clients, tried_macs, auto_params, bssids, air_clients_map=air_clients_map, active_only=True
                )

                if not new_air_clients and bssid_air_clients:
                    # If all active clients were previously tried in earlier cycles, reset tried_macs to allow re-testing
                    if not is_air_only:
                        log_main(f"  [i] All active targets on BSSID {target_bssid} were previously attempted. Resetting tried target history...")
                    tried_macs.clear()
                    new_air_clients = filter_valid_air_clients(
                        bssid_air_clients, tried_macs, auto_params, bssids, air_clients_map=air_clients_map, active_only=True
                    )

                if not new_air_clients:
                    continue

                try:
                    clear_window("hijack")
                    clear_window("scan")
                    set_scan_status(subnet="N/A", count=0, scan_type="Idle")
                    set_hijack_status(ip=None, mac=None, technique="Idle")

                    msg = f"[{idx}/{len(ranked_bssids)}] Target: {target_bssid} (Sig: {signal_pct}%, Ch: {chan})"
                    log_info(msg)
                    if not is_air_only:
                        if any_bssid_mode:
                            log_main(f"[*] Connecting to {target_bssid}...", verbose_only=True)
                        else:
                            log_main(f"\n[{idx}/{len(ranked_bssids)}] Target {target_bssid} ({signal_pct}%, Ch {chan})", verbose_only=True)

                    if is_monitor_mode_active(interface):
                        set_managed_mode(interface)

                    attack_mac = get_attack_mac(interface)
                    set_mac_address(interface, attack_mac, profile=profile)

                    if not lock_bssid(target_bssid, profile):
                        if not is_air_only and not any_bssid_mode:
                            log_main(f"  [!] Lock failed: {target_bssid}")
                        continue

                    wait_for_carrier(interface, timeout=6.0)

                    if has_internet(interface=interface, ping_gateway=True):
                        log_main(f"\033[92m[+] SUCCESS! Internet verified on {target_bssid}!\033[0m")
                        if not getattr(args, "force", False):
                            handle_auto_share_if_requested(args, interface)
                            return True

                    success_air, stop_early = test_air_client_targets(
                        new_air_clients, interface, target_bssid, chan, profile, tried_macs, auto_params, args,
                        security=target_sec, air_clients_map=air_clients_map
                    )
                    if stop_early or (success_air and not getattr(args, "force", False)):
                        handle_auto_share_if_requested(args, interface)
                        return True

                    set_hijack_status(ip=None, mac=None, technique="Idle")

                except (KeyboardInterrupt, MainSkipInterrupt):
                    now = time.time()
                    if now - last_skip_time < 1.5:
                        log_warning("Double Ctrl+C. Exiting...")
                        log_main("[-] Double Ctrl+C. Exiting...")
                        if is_monitor_mode_active(interface):
                            set_managed_mode(interface)
                        raise

                    last_skip_time = now
                    log_warning(f"Skipping BSSID {target_bssid} (Ctrl+C)...")
                    log_main(f"\033[93m[-] Skipping BSSID {target_bssid} (Ctrl+C)...\033[0m")
                    continue

            if profile:
                _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""], debug=False)
                _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""], debug=False)
            cycle += 1
            if is_monitor_mode_active(interface):
                set_managed_mode(interface)
            wait_for_carrier(interface, timeout=3.0)
            time.sleep(1.5)

    # 2. Discover BSSIDs for the SSID
    bssids = scan_bssids_for_ssid(ssid)
    if not bssids:
        log_main(f"[-] No BSSIDs found for SSID '{ssid}'.")
        return False

    blacklist = load_blacklist()
    orig_bssid_count = len(bssids)
    bssids = [b for b in bssids if not is_blacklisted(b.get("bssid", ""), blacklist)]
    if len(bssids) < orig_bssid_count:
        log_main(f"[i] Filtered out {orig_bssid_count - len(bssids)} blacklisted BSSID(s).")

    if not bssids:
        log_main(f"[-] All discovered BSSIDs for SSID '{ssid}' are blacklisted.")
        return False

    log_main(f"[+] Discovered {len(bssids)} BSSID(s) for '{ssid}'")

    # 3. If --air mode is enabled, sniff over-the-air Dot11 frames in monitor mode FIRST
    air_clients_map = {}
    if is_air:
        if is_air_only:
            log_main(f"[Cycle #1] Hunting...")
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channel_list = [b["chan"] for b in bssids if b.get("chan")]

        unique_channels = set()
        for ch in target_channel_list:
            try:
                ch_int = int(str(ch).strip())
                if ch_int > 0:
                    unique_channels.add(ch_int)
            except (ValueError, TypeError):
                pass

        if not user_specified_duration and unique_channels and air_duration > 0:
            scaled_dur = calculate_scaled_air_duration(air_duration, len(unique_channels))
            if scaled_dur > air_duration:
                if not is_air_only:
                    log_main(f"[*] Auto-scaling air sniff duration to {scaled_dur}s for {len(unique_channels)} target channels.")
                air_duration = scaled_dur
                set_main_status(status=f"Air Sniffing ({air_duration}s)")

        threshold_val = getattr(args, "threshold", getattr(args, "bssid_threshold", 10))
        passive_only = getattr(args, "passive_only", False)
        air_clients_map = sniff_air_clients(
            target_bssid_list,
            interface=interface,
            duration=air_duration,
            target_channels=target_channel_list,
            bssids=bssids,
            bssid_threshold=threshold_val,
            ssid=ssid,
            enable_stimulation=not passive_only,
            trigger_on_active=False
        )
        if is_monitor_mode_active(interface):
            set_managed_mode(interface)
        set_main_status(status="Active Exploration")

    # 4. Display ranked BSSIDs & handle manual selection
    any_bssid_mode = bool(getattr(args, "any_bssid", False) is True)
    prioritize_clients = bool(
        not any_bssid_mode and (getattr(args, "clients", False) is True or getattr(args, "prioritize_clients", False) is True)
    )

    pooled_air_clients = {}
    if is_air and air_clients_map:
        for b_clients in air_clients_map.values():
            if isinstance(b_clients, dict):
                for mac, ip in b_clients.items():
                    if mac not in pooled_air_clients or (not pooled_air_clients[mac] and ip):
                        pooled_air_clients[mac] = ip

    if any_bssid_mode and is_air:
        if not is_air_only:
            log_main(f"[+] --any-bssid enabled: Pooled {len(pooled_air_clients)} client(s) across all BSSIDs for target testing.")

    bssids = display_and_select_bssid(
        bssids,
        air_clients_map,
        getattr(args, "select_bssid", False),
        prioritize_clients=prioritize_clients,
        is_air_only=is_air_only
    )

    tried_macs = set()
    last_skip_time = 0

    for idx, item in enumerate(bssids, start=1):
        target_bssid = item["bssid"]
        if is_blacklisted(target_bssid, blacklist):
            trace(f"[FEATURE] Skipping blacklisted target BSSID: {target_bssid}")
            if not is_air_only:
                log_main(f"  [-] Skipping blacklisted BSSID: {target_bssid}")
            continue

        signal_pct = item["signal"]
        chan = item["chan"]
        target_sec = item.get("security", "")

        try:
            clear_window("hijack")
            clear_window("scan")
            set_scan_status(subnet="N/A", count=0, scan_type="Idle")
            set_hijack_status(ip=None, mac=None, technique="Idle")

            msg = f"[{idx}/{len(bssids)}] Target: {target_bssid} (Sig: {signal_pct}%, Ch: {chan})"
            log_info(msg)
            if not is_air_only:
                if any_bssid_mode:
                    log_main(f"[*] Connecting to {target_bssid}...", verbose_only=True)
                else:
                    log_main(f"\n[{idx}/{len(bssids)}] Target {target_bssid} ({signal_pct}%, Ch {chan})", verbose_only=True)

            if is_monitor_mode_active(interface):
                set_managed_mode(interface)

            attack_mac = get_attack_mac(interface)
            trace(f"[FEATURE] Applying attack MAC {attack_mac} before locking to BSSID {target_bssid}")
            set_mac_address(interface, attack_mac, profile=profile)

            if not lock_bssid(target_bssid, profile):
                if not is_air_only and not any_bssid_mode:
                    log_main(f"  [!] Lock failed: {target_bssid}")
                continue

            wait_for_carrier(interface, timeout=6.0)

            if has_internet(interface=interface, ping_gateway=True):
                log_main(f"\033[92m[+] SUCCESS! Internet verified on {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    handle_auto_share_if_requested(args, interface)
                    return True
                else:
                    log_main(f"[!] --force enabled. Continuing attack on {target_bssid}...")

            if any_bssid_mode:
                bssid_air_clients = pooled_air_clients
            else:
                bssid_air_clients = air_clients_map.get(target_bssid.lower(), {})

            auto_params = auto_detect_network_params(target_iface=interface)
            new_air_clients = filter_valid_air_clients(bssid_air_clients, tried_macs, auto_params, bssids, air_clients_map=air_clients_map)

            if new_air_clients:
                success_air, stop_early = test_air_client_targets(
                    new_air_clients, interface, target_bssid, chan, profile, tried_macs, auto_params, args, security=target_sec, air_clients_map=air_clients_map
                )
                if stop_early or (success_air and not getattr(args, "force", False)):
                    handle_auto_share_if_requested(args, interface)
                    return True

            set_hijack_status(ip=None, mac=None, technique="Idle")

            if is_monitor_mode_active(interface):
                set_managed_mode(interface)

            if is_air_only:
                log_info(f"Skipping subnet scanning on BSSID {target_bssid} (--air-only enabled).")
            else:
                log_step(f"Scanning subnet on BSSID {target_bssid}...")
                log_subnet_scan(target_bssid)
                log_hijack(f"[*] Scanning subnet on BSSID {target_bssid}...")
                setattr(args, "interface", interface)
                success = run_scan_wrapper(args, quiet_header=True)

                set_scan_status(scan_type="Idle")

                if success or (has_internet() and not getattr(args, "force", False)):
                    log_plus(f"SUCCESS! Internet access granted via {target_bssid}!")
                    log_main(f"\033[92m[+] SUCCESS! Internet access granted via {target_bssid}!\033[0m")
                    if not getattr(args, "force", False):
                        handle_auto_share_if_requested(args, interface)
                        return True

            log_warning(f"No internet on BSSID {target_bssid}. Moving next...")
            if not is_air_only and not any_bssid_mode:
                log_main(f"  [-] No internet on BSSID {target_bssid}.")

        except (KeyboardInterrupt, MainSkipInterrupt):
            now = time.time()
            if now - last_skip_time < 1.5:
                log_warning("Double Ctrl+C. Exiting...")
                log_main("[-] Double Ctrl+C. Exiting...")
                if is_monitor_mode_active(interface):
                    set_managed_mode(interface)
                raise

            last_skip_time = now
            log_warning(f"Skipping BSSID {target_bssid} (Ctrl+C)...")
            log_main(f"\033[93m[-] Skipping BSSID {target_bssid} (Ctrl+C)...\033[0m")
            set_scan_status(subnet="N/A", count=0, scan_type="Idle")
            set_hijack_status(ip=None, mac=None, technique="Idle")
            try:
                if is_monitor_mode_active(interface):
                    set_managed_mode(interface)
            except Exception:
                pass
            time.sleep(0.5)
            continue

    log_warning("Aggressive completed all BSSIDs without internet access.")
    if not is_air_only:
        log_main("[-] Aggressive completed all BSSIDs without internet access.")
    if is_monitor_mode_active(interface):
        set_managed_mode(interface)
    return False
