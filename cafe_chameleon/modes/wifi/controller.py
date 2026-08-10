"""
cafe_chameleon.modes.wifi.controller - Main execution handler for Wi-Fi management subcommand.
"""

import sys

from cafe_chameleon.ui.console import log_minus
from cafe_chameleon.network.mac import is_valid_mac
from cafe_chameleon.network.nmcli import show_status, lock_bssid, restore_auto, reset_mac, release_interface


def run_wifi(args) -> None:
    if getattr(args, "status", False):
        show_status()
    elif getattr(args, "lock", None) is not None:
        bssid = None
        profile = None
        lock_args = args.lock
        if len(lock_args) == 1:
            if is_valid_mac(lock_args[0]):
                bssid = lock_args[0]
            else:
                profile = lock_args[0]
        elif len(lock_args) >= 2:
            bssid = lock_args[0]
            profile = lock_args[1]

        if not lock_bssid(bssid, profile):
            sys.exit(1)
    elif getattr(args, "auto", None) is not None:
        auto_args = args.auto
        profile = auto_args[0] if len(auto_args) > 0 else None
        restore_auto(profile)
    elif getattr(args, "reset_mac", None) is not None:
        reset_args = args.reset_mac
        profile = reset_args[0] if len(reset_args) > 0 else None
        if not reset_mac(profile):
            sys.exit(1)
    elif getattr(args, "release", None) is not None:
        rel_args = args.release
        iface = None
        prof = None
        if len(rel_args) == 1:
            if is_valid_mac(rel_args[0]):
                prof = rel_args[0]
            elif rel_args[0].startswith("wlan") or rel_args[0].startswith("wlp") or rel_args[0].startswith("eth") or rel_args[0].startswith("en"):
                iface = rel_args[0]
            else:
                prof = rel_args[0]
        elif len(rel_args) >= 2:
            iface = rel_args[0]
            prof = rel_args[1]

        if not release_interface(interface=iface, profile=prof):
            sys.exit(1)
    else:
        log_minus("No wifi action specified. Use --status, --lock, --auto, --reset-mac, or --release.")
        sys.exit(1)
