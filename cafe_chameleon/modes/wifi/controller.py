"""
cafe_chameleon.modes.wifi.controller - Main execution handler for Wi-Fi management subcommand.
"""

import sys

from cafe_chameleon.ui.console import log_minus
from cafe_chameleon.network.mac import is_valid_mac
from cafe_chameleon.network.nmcli import show_status, lock_bssid, restore_auto, reset_mac, release_interface, change_mac


def run_wifi(args) -> None:
    if getattr(args, "status", False):
        show_status()
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
        target_mac = None
        profile = None
        if len(mac_args) == 0:
            target_mac = None
            profile = None
        elif len(mac_args) == 1:
            arg = mac_args[0]
            if is_valid_mac(arg):
                target_mac = arg
            elif ":" in arg or "-" in arg:
                target_mac = arg
            else:
                profile = arg
        else:
            mac_idx = None
            for idx, arg in enumerate(mac_args):
                if is_valid_mac(arg):
                    mac_idx = idx
                    break
            if mac_idx is None:
                for idx, arg in enumerate(mac_args):
                    if ":" in arg or "-" in arg:
                        mac_idx = idx
                        break
            if mac_idx is not None:
                target_mac = mac_args[mac_idx]
                prof_parts = [a for i, a in enumerate(mac_args) if i != mac_idx]
                profile = " ".join(prof_parts).strip() if prof_parts else None
            else:
                target_mac = None
                profile = " ".join(mac_args).strip() if mac_args else None

        if not change_mac(target_mac, profile):
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
    else:
        log_minus("No wifi action specified. Use --status, --lock, --auto, --mac, --reset-mac, or --release.")
        sys.exit(1)
