"""
cafe_chameleon.cli.parser - CLI Argument Parser definitions for simple, aggressive, and wifi subcommands.
"""

import argparse

from cafe_chameleon.network.nmcli import DEFAULT_BSSID
from cafe_chameleon.cli.commands.simple import run_simple
from cafe_chameleon.cli.commands.aggressive import handle_aggressive
from cafe_chameleon.cli.commands.wifi import run_wifi


def parse_arguments():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--debug", action="store_true", help="Enable verbose debug output for executed commands")
    parent_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential info logs")
    parent_parser.add_argument("--no-xterm", action="store_true", help="Disable multi-window xterm UI layout")
    parent_parser.add_argument("--force", action="store_true", help="Continue working even if internet access exists")

    parser = argparse.ArgumentParser(
        description="CafeChameleon - Captive Network Internet Granter & Impersonation Toolkit",
        parents=[parent_parser]
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # simple subcommand
    simple_p = subparsers.add_parser(
        "simple",
        help="Layer 2 ARP network enumeration & host impersonation",
        parents=[parent_parser]
    )
    simple_p.add_argument("-i", "--interface", required=False, help="Network interface (e.g., wlan0). Auto-detected if omitted.")
    simple_p.add_argument("-t", "--target", required=False, help="Target CIDR block (e.g., 172.16.40.0/22). Auto-detected if omitted.")
    simple_p.add_argument("--subnet", required=False, help="Target subnet for deep host discovery with 30s passive traffic sniffing (e.g., 10.68.192.0/24).")
    simple_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, help="Enable 802.11 monitor mode over-the-air packet capture using monitor0/managed0. Optional duration in seconds.")
    simple_p.set_defaults(func=run_simple)

    # aggressive subcommand
    aggressive_p = subparsers.add_parser(
        "aggressive",
        help="Sequential multi-BSSID exploration & scan until internet access is granted",
        parents=[parent_parser]
    )
    aggressive_p.add_argument("-i", "--interface", required=False, help="Network interface (e.g., wlan0). Auto-detected if omitted.")
    aggressive_p.add_argument("-p", "--profile", required=False, help="Active Wi-Fi connection profile. Auto-detected if omitted.")
    aggressive_p.add_argument("-t", "--target", required=False, help="Target CIDR block (e.g., 172.16.40.0/22). Auto-detected if omitted.")
    aggressive_p.add_argument("--subnet", required=False, help="Target subnet for deep host discovery with 30s passive traffic sniffing (e.g., 10.68.192.0/24).")
    aggressive_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, help="Enable 802.11 monitor mode over-the-air packet capture using monitor0/managed0. Optional duration in seconds.")
    aggressive_p.add_argument("-s", "--select-bssid", action="store_true", help="Prompt user to select starting BSSID from discovered list")
    aggressive_p.set_defaults(func=handle_aggressive)

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
