"""
cafe_chameleon.cli.parser - CLI Argument Parser definitions for simple, aggressive, and wifi subcommands.
"""

import argparse

from cafe_chameleon.network.nmcli import DEFAULT_BSSID
from cafe_chameleon.cli.commands.simple import run_simple
from cafe_chameleon.cli.commands.aggressive import handle_aggressive
from cafe_chameleon.cli.commands.wifi import run_wifi


import argparse
import sys

from cafe_chameleon.network.nmcli import DEFAULT_BSSID
from cafe_chameleon.cli.commands.simple import run_simple
from cafe_chameleon.cli.commands.aggressive import handle_aggressive
from cafe_chameleon.cli.commands.wifi import run_wifi
from cafe_chameleon.ui.colors import BOLD, CYAN, GREEN, YELLOW, RESET, DIM


class CleanHelpFormatter(argparse.HelpFormatter):
    """Custom compact help formatter with clear column alignment and concise output."""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=30, width=100)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append(f"{option_string}")
                parts[-1] += f" {args_string}"
            return ", ".join(parts)


def parse_arguments():
    parent_parser = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    parent_parser.add_argument(
        "-i", "--interface", required=False, metavar="IFACE",
        help="Network interface (e.g. wlan0) [default: auto]"
    )
    parent_parser.add_argument(
        "-m", "--original-mac", action="store_true", dest="original_mac",
        help="Use hardware MAC (do not randomize)"
    )
    parent_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs")
    parent_parser.add_argument("--no-xterm", action="store_true", help="Disable multi-window xterm UI")
    parent_parser.add_argument("--force", action="store_true", help="Continue work even if internet is active")
    parent_parser.add_argument(
        "--debug", nargs="?", const="commands", choices=["commands", "tracing"], metavar="MODE",
        help="Debug mode: 'commands' or 'tracing'"
    )

    parser = argparse.ArgumentParser(
        prog="cafe-chameleon",
        description=f"{BOLD}{CYAN}CafeChameleon{RESET} ─ Captive Network Impersonation & Internet Toolkit",
        formatter_class=CleanHelpFormatter,
        parents=[parent_parser]
    )

    subparsers = parser.add_subparsers(dest="command", title="Subcommands", required=True)

    # simple subcommand
    simple_p = subparsers.add_parser(
        "simple",
        help="Layer 2 ARP scan & host impersonation",
        description=f"{BOLD}{CYAN}Simple Mode{RESET} ─ Layer 2 ARP scan & host impersonation",
        formatter_class=CleanHelpFormatter,
        parents=[parent_parser]
    )
    simple_p.add_argument("-t", "--target", required=False, metavar="CIDR", help="Target CIDR subnet [default: auto]")
    simple_p.add_argument("--subnet", required=False, metavar="CIDR", help="Subnet for deep host discovery")
    simple_p.add_argument("-w", "--wide", action="store_true", help="Expand target subnet to /22 (1024 IPs) for maximum target discovery")
    simple_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, metavar="SECS", help="Enable 802.11 monitor mode capture")
    simple_p.set_defaults(func=run_simple)

    # aggressive subcommand
    aggressive_p = subparsers.add_parser(
        "aggressive",
        help="Multi-BSSID exploration & scan until internet online",
        description=f"{BOLD}{CYAN}Aggressive Mode{RESET} ─ Multi-BSSID exploration & scan until internet online",
        formatter_class=CleanHelpFormatter,
        parents=[parent_parser]
    )
    aggressive_p.add_argument("-p", "--profile", required=False, metavar="NAME", help="Active Wi-Fi profile [default: auto]")
    aggressive_p.add_argument("-t", "--target", required=False, metavar="CIDR", help="Target CIDR subnet [default: auto]")
    aggressive_p.add_argument("--subnet", required=False, metavar="CIDR", help="Subnet for deep host discovery")
    aggressive_p.add_argument("--air", nargs="?", const=-1, type=int, default=None, metavar="SECS", help="Enable 802.11 monitor mode capture")
    aggressive_p.add_argument("-s", "--select-bssid", action="store_true", help="Interactively select starting BSSID")
    aggressive_p.set_defaults(func=handle_aggressive)

    # wifi subcommand
    wifi_p = subparsers.add_parser(
        "wifi",
        help="Wi-Fi BSSID lock, auto-roam & MAC management",
        description=f"{BOLD}{CYAN}Wi-Fi Controller{RESET} ─ BSSID lock, auto-roam & MAC management",
        formatter_class=CleanHelpFormatter,
        parents=[parent_parser]
    )
    group = wifi_p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--lock", nargs="*", metavar=("BSSID", "PROFILE"),
        help=f"Lock connection to BSSID (default: {DEFAULT_BSSID})"
    )
    group.add_argument(
        "--auto", nargs="*", metavar="PROFILE",
        help="Remove BSSID lock & auto-roam to strongest AP"
    )
    group.add_argument("--status", action="store_true", help="Display Wi-Fi status & lock info")
    group.add_argument(
        "--reset-mac", nargs="*", metavar="PROFILE",
        help="Reset MAC address back to original hardware default"
    )
    wifi_p.set_defaults(func=run_wifi)

    return parser.parse_args()

