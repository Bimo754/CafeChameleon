#!/usr/bin/env python3
"""
main.py - Entrypoint for CafeChameleon network toolkit.

Subcommands:
  simple     - Layer 2 ARP host enumeration & captive portal connection
  aggressive - Sequential multi-BSSID exploration & over-the-air client discovery
  wifi       - Manage WiFi BSSID lock / auto-roam / status via nmcli
"""

import sys

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.utils.state import set_debug, set_quiet, set_use_xterm
from cafe_chameleon.utils.signals import restore_and_exit
from cafe_chameleon.ui.console import init_xterm
from cafe_chameleon.ui.colors import BOLD, GREEN, RED, RESET


def main():
    try:
        args = parse_arguments()
        if getattr(args, "debug", False):
            set_debug(True)
        if getattr(args, "quiet", False):
            set_quiet(True)
        if getattr(args, "no_xterm", False):
            set_use_xterm(False)
        else:
            cmd = getattr(args, "command", "")
            has_air = getattr(args, "air", None) is not None

            if cmd == "wifi":
                active_windows = []
            elif cmd == "simple":
                active_windows = ["air", "scan", "hijack"] if has_air else ["scan", "hijack"]
            elif cmd == "aggressive":
                active_windows = ["main", "air", "scan", "hijack"] if has_air else ["main", "scan", "hijack"]
            else:
                active_windows = ["main", "air", "scan", "hijack"]

            if init_xterm(active_windows=active_windows):
                count = len(active_windows)
                print(f"[+] Multi-Window Xterm UI active ({count} centered window{'s' if count != 1 else ''} spawned).")
        cmd = getattr(args, "command", "")
        result = args.func(args)
        if cmd in ("aggressive", "simple"):
            if result:
                print(f"\n{BOLD}{GREEN}[+] Operation Complete: Internet Access Granted!{RESET}\n")
            else:
                print(f"\n{BOLD}{RED}[-] Operation Complete: No Internet Access Secured.{RESET}\n")

    except KeyboardInterrupt:
        restore_and_exit("Process interrupted by user (Ctrl+C).")
    except Exception as e:
        import traceback
        print(f"\n{BOLD}{RED}=== UNHANDLED EXCEPTION TRACEBACK ==={RESET}")
        traceback.print_exc()
        print(f"{BOLD}{RED}====================================={RESET}\n")
        restore_and_exit(f"Unhandled error: {e}")


if __name__ == "__main__":
    main()
