"""
cafe_chameleon.modes.wifi.controller - Main execution handler for Wi-Fi management subcommand.
"""

import sys

from cafe_chameleon.ui.console import log_minus
from cafe_chameleon.network.mac import is_valid_mac
from cafe_chameleon.network.nmcli import show_status, show_wifi_scan, show_mac, lock_bssid, restore_auto, reset_mac, release_interface, change_mac, reconnect_wifi
from cafe_chameleon.network.hotspot import share_wifi_hotspot


def run_wifi(args) -> None:
    if getattr(args, "status", False):
        show_status()
    elif getattr(args, "scan", None) is not None:
        scan_args = args.scan
        target_ssid = " ".join(scan_args).strip() if scan_args else None
        if not show_wifi_scan(target_ssid=target_ssid):
            sys.exit(1)
    elif getattr(args, "lock", None) is not None:
        bssid = None
        profile = None
        lock_args = args.lock
        if len(lock_args) == 1:
            arg = lock_args[0]
            if is_valid_mac(arg):
                bssid = arg
            elif ":" in arg or "-" in arg:
                bssid = arg
            else:
                profile = arg
        elif len(lock_args) >= 2:
            mac_idx = None
            for idx, arg in enumerate(lock_args):
                if is_valid_mac(arg):
                    mac_idx = idx
                    break
            if mac_idx is None:
                for idx, arg in enumerate(lock_args):
                    if ":" in arg or "-" in arg:
                        mac_idx = idx
                        break
            if mac_idx is not None:
                bssid = lock_args[mac_idx]
                prof_parts = [a for i, a in enumerate(lock_args) if i != mac_idx]
                profile = " ".join(prof_parts).strip() if prof_parts else None
            else:
                bssid = None
                profile = " ".join(lock_args).strip() if lock_args else None

        if not lock_bssid(bssid, profile):
            sys.exit(1)
    elif getattr(args, "auto", None) is not None:
        auto_args = args.auto
        profile = " ".join(auto_args).strip() if auto_args else None
        restore_auto(profile)
    elif getattr(args, "mac", None) is not None:
        mac_args = args.mac

        # 1. Check for random MAC action ('random', 'rand', 'rnd')
        random_action = any(a.lower() in ("random", "rand", "rnd") for a in mac_args)
        if random_action:
            non_rand = [a for a in mac_args if a.lower() not in ("random", "rand", "rnd")]
            profile = " ".join(non_rand).strip() if non_rand else None
            if not change_mac(None, profile):
                sys.exit(1)
            return

        # 2. Check for reset MAC action ('reset', 'reset-mac', 'restore', 'default')
        reset_action = any(a.lower() in ("reset", "reset-mac", "restore", "default") for a in mac_args)
        if reset_action:
            non_reset = [a for a in mac_args if a.lower() not in ("reset", "reset-mac", "restore", "default")]
            profile = " ".join(non_reset).strip() if non_reset else None
            if not reset_mac(profile):
                sys.exit(1)
            return

        # 3. Check if a valid MAC address is passed in mac_args
        target_mac = None
        for arg in mac_args:
            if is_valid_mac(arg) or ":" in arg or "-" in arg:
                target_mac = arg
                break

        if target_mac:
            mac_idx = mac_args.index(target_mac)
            prof_parts = [a for i, a in enumerate(mac_args) if i != mac_idx]
            profile = " ".join(prof_parts).strip() if prof_parts else None
            if not change_mac(target_mac, profile):
                sys.exit(1)
            return

        # 4. Default action when omitted or when interface/profile provided: Show MAC info ('wifi -m')
        non_show = [a for a in mac_args if a.lower() not in ("show", "list", "ls", "info", "status", "get")]
        target_iface = None
        target_prof = None
        if len(non_show) == 1:
            arg = non_show[0]
            if arg.startswith(("wlan", "wlp", "eth", "en", "mon")):
                target_iface = arg
            else:
                target_prof = arg
        elif len(non_show) >= 2:
            iface_idx = None
            for idx, arg in enumerate(non_show):
                if arg.startswith(("wlan", "wlp", "eth", "en", "mon")):
                    iface_idx = idx
                    break
            if iface_idx is not None:
                target_iface = non_show[iface_idx]
                prof_parts = [a for i, a in enumerate(non_show) if i != iface_idx]
                target_prof = " ".join(prof_parts).strip() if prof_parts else None
            else:
                target_prof = " ".join(non_show).strip() if non_show else None

        if not show_mac(interface=target_iface, profile=target_prof):
            sys.exit(1)
    elif getattr(args, "reset_mac", None) is not None:
        reset_args = args.reset_mac
        profile = " ".join(reset_args).strip() if reset_args else None
        if not reset_mac(profile):
            sys.exit(1)
    elif getattr(args, "release", None) is not None:
        rel_args = args.release
        iface = None
        prof = None
        if len(rel_args) == 1:
            arg = rel_args[0]
            if is_valid_mac(arg):
                prof = arg
            elif arg.startswith(("wlan", "wlp", "eth", "en", "mon")):
                iface = arg
            else:
                prof = arg
        elif len(rel_args) >= 2:
            iface_idx = None
            for idx, arg in enumerate(rel_args):
                if arg.startswith(("wlan", "wlp", "eth", "en", "mon")):
                    iface_idx = idx
                    break
            if iface_idx is not None:
                iface = rel_args[iface_idx]
                prof_parts = [a for i, a in enumerate(rel_args) if i != iface_idx]
                prof = " ".join(prof_parts).strip() if prof_parts else None
            else:
                iface = rel_args[0]
                prof = " ".join(rel_args[1:]).strip() if len(rel_args) > 1 else None

        if not release_interface(interface=iface, profile=prof):
            sys.exit(1)
    elif getattr(args, "reconnect", None) is not None:
        rec_args = args.reconnect
        auto_loop = any(a.lower() in ("auto", "deauth") for a in rec_args)
        enable_deauth = any(a.lower() == "deauth" for a in rec_args)
        prof_parts = [a for a in rec_args if a.lower() not in ("auto", "deauth")]
        profile = " ".join(prof_parts).strip() if prof_parts else None

        if not reconnect_wifi(profile=profile, auto_loop=auto_loop, enable_deauth=enable_deauth):
            sys.exit(1)
    elif getattr(args, "share", None) is not None:
        hotspot_name, hotspot_pass = args.share
        iface = getattr(args, "interface", None)
        if not share_wifi_hotspot(hotspot_name=hotspot_name, password=hotspot_pass, interface=iface):
            sys.exit(1)
    else:
        log_minus("No wifi action specified. Use --scan, --status, --lock, --auto, --mac (-m reset/-m show), --release (-r), --reconnect, or --share.")
        sys.exit(1)
