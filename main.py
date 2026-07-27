#!/usr/bin/env python3
"""
combined.py - Combined network utility CLI entrypoint

Subcommands:
  scan  - Layer 2 ARP host enumeration & captive portal connection
  kyk   - Sequential multi-BSSID exploration & scan until internet access is granted
  wifi  - Manage WiFi BSSID lock / auto-roam / status via nmcli
"""

import argparse
import sys

from Library.utils import set_debug, set_quiet, log_info
from Library.scanner import run_scan
from Library.wifi import run_wifi, DEFAULT_BSSID
from Library.kyk import run_kyk


def parse_arguments():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--debug", action="store_true", help="Enable verbose debug output for executed commands")
    parent_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential info logs")
    parent_parser.add_argument("--no-xterm", action="store_true", help="Disable multi-window xterm UI layout")
    parent_parser.add_argument("--force", action="store_true", help="Continue working even if internet access exists")

    parser = argparse.ArgumentParser(description="Combined Network Toolkit", parents=[parent_parser])
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan subcommand
    scan_p = subparsers.add_parser("scan", help="Layer 2 ARP network enumeration", parents=[parent_parser])
    scan_p.add_argument("-i", "--interface", required=False, help="Network interface (e.g., wlan0). Auto-detected if omitted.")
    scan_p.add_argument("-t", "--target", required=False, help="Target CIDR block (e.g., 172.16.40.0/22). Auto-detected if omitted.")
    scan_p.add_argument("--subnet", required=False, help="Target subnet for deep host discovery with 30s passive traffic sniffing (e.g., 10.68.192.0/24).")
    scan_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, help="Enable 802.11 monitor mode over-the-air packet capture using monitor0/managed0. Optional duration in seconds.")
    scan_p.set_defaults(func=run_scan)

    # kyk subcommand
    kyk_p = subparsers.add_parser("kyk", help="Sequential multi-BSSID exploration & scan until internet access is granted", parents=[parent_parser])
    kyk_p.add_argument("-i", "--interface", required=False, help="Network interface (e.g., wlan0). Auto-detected if omitted.")
    kyk_p.add_argument("-p", "--profile", required=False, help="Active Wi-Fi connection profile. Auto-detected if omitted.")
    kyk_p.add_argument("-t", "--target", required=False, help="Target CIDR block (e.g., 172.16.40.0/22). Auto-detected if omitted.")
    kyk_p.add_argument("--subnet", required=False, help="Target subnet for deep host discovery with 30s passive traffic sniffing (e.g., 10.68.192.0/24).")
    kyk_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, help="Enable 802.11 monitor mode over-the-air packet capture using monitor0/managed0. Optional duration in seconds.")
    kyk_p.add_argument("-s", "--select-bssid", action="store_true", help="Prompt user to select starting BSSID from discovered list")
    kyk_p.set_defaults(func=run_kyk)

    # wifi subcommand
    wifi_p = subparsers.add_parser("wifi", help="WiFi BSSID lock / auto-roam / status", parents=[parent_parser])
    group = wifi_p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--lock", nargs="*", metavar=("BSSID", "PROFILE"),
        help=f"Lock connection to a specific BSSID (default: {DEFAULT_BSSID}). Optional profile name."
    )
    group.add_argument(
        "--auto", nargs="*", metavar="PROFILE",
        help="Remove BSSID lock and connect to strongest AP (auto-roam). Optional profile name."
    )
    group.add_argument("--status", action="store_true", help="Show current Wi-Fi status and BSSID lock info")
    wifi_p.set_defaults(func=run_wifi)

    return parser.parse_args()



def main():
    try:
        args = parse_arguments()
        if getattr(args, "debug", False):
            set_debug(True)
        if getattr(args, "quiet", False):
            set_quiet(True)
        if getattr(args, "no_xterm", False):
            from Library.utils import set_use_xterm
            set_use_xterm(False)
        else:
            cmd = getattr(args, "command", "")
            has_air = getattr(args, "air", None) is not None

            if cmd == "wifi":
                active_windows = []
            elif cmd == "scan":
                active_windows = ["air", "scan", "hijack"] if has_air else ["scan", "hijack"]
            elif cmd == "kyk":
                active_windows = ["main", "air", "scan", "hijack"] if has_air else ["main", "scan", "hijack"]
            else:
                active_windows = ["main", "air", "scan", "hijack"]

            from Library.utils import init_xterm
            if init_xterm(active_windows=active_windows):
                count = len(active_windows)
                print(f"[+] Multi-Window Xterm UI active ({count} centered window{'s' if count != 1 else ''} spawned).")
        cmd = getattr(args, "command", "")
        result = args.func(args)
        if cmd in ("kyk", "scan"):
            from Library.colors.colors import BOLD, GREEN, RED, RESET
            if result:
                print(f"\n{BOLD}{GREEN}[+] Operation Complete: Internet Access Granted!{RESET}\n")
            else:
                print(f"\n{BOLD}{RED}[-] Operation Complete: No Internet Access Secured.{RESET}\n")


    except KeyboardInterrupt:
        from Library.utils import restore_and_exit
        restore_and_exit("Process interrupted by user (Ctrl+C).")
    except Exception as e:
        from Library.utils import restore_and_exit
        restore_and_exit(f"Unhandled error: {e}")





if __name__ == "__main__":
    main()

