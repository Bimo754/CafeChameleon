"""
cafe_chameleon.cli.commands.wifi - Command handler for 'wifi' (BSSID lock / auto-roam / status).
"""

import sys

from cafe_chameleon.ui.console import log_minus
from cafe_chameleon.network.mac import is_valid_mac
from cafe_chameleon.network.nmcli import show_status, lock_bssid, restore_auto


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
    else:
        log_minus("No wifi action specified. Use --status, --lock, or --auto.")
        sys.exit(1)
