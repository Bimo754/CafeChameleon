"""
cafe_chameleon.cli.parser - CLI Argument Parser definitions for simple, aggressive, and wifi subcommands.
"""

import argparse

from cafe_chameleon.modes.simple import run_simple
from cafe_chameleon.modes.aggressive import run_aggressive
from cafe_chameleon.modes.wifi import run_wifi
from cafe_chameleon.modes.blacklist import run_blacklist
from cafe_chameleon.ui.colors import BOLD, CYAN, YELLOW, RESET


class CleanHelpFormatter(argparse.HelpFormatter):
    """Custom streamlined help formatter with section heading colors and tight single-line alignment."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=32, width=140)

    def start_section(self, heading):
        heading_colored = f"{BOLD}{CYAN}{heading}{RESET}"
        super().start_section(heading_colored)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar = self._metavar_formatter(action, action.dest)(1)[0]
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for opt in action.option_strings:
                    parts.append(opt)
                parts[-1] += f" {args_string}"
            return ", ".join(parts)

    def _format_action(self, action):
        if isinstance(action, argparse._SubParsersAction):
            lines = []
            for subaction in action._get_subactions():
                cmd_header = subaction.dest
                help_position = self._max_help_position
                help_text = subaction.help if subaction.help else ""
                indent = " " * (help_position - len(cmd_header))
                lines.append("%*s%s%s%s\n" % (self._current_indent, "", cmd_header, indent, help_text))
            return "".join(lines)

        action_header = self._format_action_invocation(action)
        help_position = self._max_help_position

        if not action.help:
            tup = (self._current_indent, "", action_header)
            return "%*s%s\n" % tup
        else:
            help_text = self._expand_help(action)
            if len(action_header) < help_position:
                indent = " " * (help_position - len(action_header))
                return "%*s%s%s%s\n" % (self._current_indent, "", action_header, indent, help_text)
            else:
                indent = " " * help_position
                return "%*s%s\n%s%s\n" % (self._current_indent, "", action_header, indent, help_text)

    def _format_usage(self, usage, actions, groups, prefix):
        if prefix is None:
            prefix = f"{BOLD}{YELLOW}Usage:{RESET} "
        else:
            prefix = f"{BOLD}{YELLOW}{prefix}{RESET}"
        return super()._format_usage(usage, actions, groups, prefix)


def parse_arguments(args=None):
    # Common execution flags shared across all commands (including wifi and blacklist)
    common_parser = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common_exec = common_parser.add_argument_group("Global Flags")
    common_exec.add_argument("-q", "--quiet", action="store_true", help="Suppress info logs")
    common_exec.add_argument(
        "--debug", nargs="?", const="commands", choices=["commands", "tracing"], metavar="MODE",
        help="Debug mode ('commands' or 'tracing')"
    )
    common_exec.add_argument("-h", "--help", action="help", help="Show help message")

    # Parent parser for attack & scanning modes (simple & aggressive ONLY)
    scan_parent_parser = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS, parents=[common_parser])

    # Top-level main parser
    parser = argparse.ArgumentParser(
        prog="cafe-chameleon",
        usage="cafe-chameleon <subcommand> [options]",
        description=f"{BOLD}{CYAN}CafeChameleon{RESET} ─ Captive portal session hijacker and network impersonation toolkit.",
        formatter_class=CleanHelpFormatter,
        parents=[common_parser],
        add_help=False
    )

    subparsers = parser.add_subparsers(dest="command", title="Subcommands", required=True)

    # simple subcommand
    simple_p = subparsers.add_parser(
        "simple",
        help="Hijack sessions using subnet blocks ping scanning",
        usage="cafe-chameleon simple [options]",
        description=f"{BOLD}{CYAN}Simple Mode{RESET} ─ Hijack sessions using subnet blocks ping scanning",
        formatter_class=CleanHelpFormatter,
        parents=[scan_parent_parser],
        add_help=False
    )
    s_opts = simple_p.add_argument_group("Options")
    s_opts.add_argument("-t", "--target", required=False, metavar="CIDR", help="Target CIDR subnet [default: auto]")
    s_opts.add_argument("--subnet", required=False, metavar="CIDR", help="Subnet for deep host discovery")
    s_opts.add_argument("-w", "--wide", action="store_true", help="Expand target scan to /22 subnet")
    s_opts.add_argument("--air", nargs="?", const=-1, type=int, default=None, metavar="SECS", help="Enable 802.11 monitor capture")
    s_opts.add_argument("-i", "--interface", required=False, metavar="IFACE", help="Network interface [default: auto]")
    s_opts.add_argument("-m", "--original-mac", action="store_true", dest="original_mac", help="Use hardware MAC (do not randomize)")
    s_opts.add_argument("--force", action="store_true", help="Force scan even if internet is active")
    s_opts.add_argument("--force-deauth", action="store_true", dest="force_deauth", help="Force 802.11 deauth even on open networks")
    s_opts.add_argument("--no-gateway", action="store_true", dest="no_gateway", help="Skip gateway ping checks during host impersonation")
    s_opts.add_argument("--no-xterm", action="store_true", help="Disable multi-window UI")
    simple_p.set_defaults(func=run_simple)

    # aggressive subcommand
    aggressive_p = subparsers.add_parser(
        "aggressive",
        help="Hijack sessions of Multi-BSSID networks using AP roaming & air target discovery",
        usage="cafe-chameleon aggressive [options]",
        description=f"{BOLD}{CYAN}Aggressive Mode{RESET} ─ Hijack sessions of Multi-BSSID networks using AP roaming & air target discovery",
        formatter_class=CleanHelpFormatter,
        parents=[scan_parent_parser],
        add_help=False
    )
    a_opts = aggressive_p.add_argument_group("Options")
    a_opts.add_argument("-p", "--profile", required=False, metavar="NAME", help="Active Wi-Fi profile [default: auto]")
    a_opts.add_argument("-t", "--target", required=False, metavar="CIDR", help="Target CIDR subnet [default: auto]")
    a_opts.add_argument("--subnet", required=False, metavar="CIDR", help="Subnet for deep host discovery")
    a_opts.add_argument("-s", "--select-bssid", nargs="?", const=True, default=False, metavar="TARGETS", help="Select target BSSID(s) interactively or by range (e.g. 1, 1,2,7, 1-10,12)")
    a_opts.add_argument("-c", "--clients", action="store_true", dest="clients", help="Target BSSIDs with clients regardless of signal strength")
    a_opts.add_argument("--any-bssid", action="store_true", dest="any_bssid", help="Connect to any BSSID with strongest signal regardless of client AP association")
    a_opts.add_argument("--any-ip", action="store_true", dest="any_ip", help="Connect with any IP to the BSSID (skip target IP resolution probes)")
    a_opts.add_argument("-b", "--threshold", type=int, default=10, dest="threshold", metavar="NUM", help="BSSID count threshold to prioritize channels with stronger signal [default: 10]")
    a_opts.add_argument("--air", nargs="?", const=-1, type=int, default=None, metavar="SECS", help="Enable 802.11 monitor capture")
    a_opts.add_argument("--air-only", nargs="?", const=-1, type=int, default=None, dest="air_only", metavar="SECS", help="Enable 802.11 monitor capture only (skip subnet scanning)")
    a_opts.add_argument("--passive-only", action="store_true", dest="passive_only", help="Disable active 802.11 packet stimulation (pure passive listening)")
    a_opts.add_argument("-i", "--interface", required=False, metavar="IFACE", help="Network interface [default: auto]")
    a_opts.add_argument("-m", "--original-mac", action="store_true", dest="original_mac", help="Use hardware MAC (do not randomize)")
    a_opts.add_argument("--force", action="store_true", help="Force scan even if internet is active")
    a_opts.add_argument("--force-deauth", action="store_true", dest="force_deauth", help="Force 802.11 deauth even on open networks")
    a_opts.add_argument("--no-gateway", action="store_true", dest="no_gateway", help="Skip gateway ping checks during host impersonation")
    a_opts.add_argument("--share", nargs=2, metavar=("NAME", "PASSWORD"), dest="share", help="Automatically share Wi-Fi hotspot upon successful session hijack")
    a_opts.add_argument("--no-xterm", action="store_true", help="Disable multi-window UI")
    aggressive_p.set_defaults(func=run_aggressive)

    # wifi subcommand (uses common_parser ONLY, no network/xterm/mac/force flags)
    wifi_p = subparsers.add_parser(
        "wifi",
        help="Hijacked sessions connectivity & hardware properties management",
        usage="cafe-chameleon wifi <action>",
        description=f"{BOLD}{CYAN}Wi-Fi Controller{RESET} ─ Hijacked sessions connectivity & hardware properties management",
        formatter_class=CleanHelpFormatter,
        parents=[common_parser],
        add_help=False
    )
    wifi_action_grp = wifi_p.add_argument_group("Actions")
    wifi_mut = wifi_action_grp.add_mutually_exclusive_group(required=True)
    wifi_mut.add_argument(
        "--scan", nargs="*", metavar="SSID",
        help="Scan and display available nearby Wi-Fi networks and BSSIDs"
    )
    wifi_mut.add_argument(
        "-l", "--lock", nargs="*", metavar="BSSID",
        help="Lock connection to BSSID"
    )
    wifi_mut.add_argument(
        "-a", "--auto", nargs="*", metavar="PROFILE",
        help="Auto-roam to strongest AP"
    )
    wifi_mut.add_argument("-s", "--status", action="store_true", help="Show Wi-Fi & lock status")
    wifi_mut.add_argument(
        "-m", "--mac", nargs="*", metavar="MAC",
        help="Change MAC address to specified MAC, randomize if omitted, or show MAC info ('show')"
    )
    wifi_mut.add_argument(
        "-r", "--reset-mac", nargs="*", metavar="PROFILE",
        help="Reset MAC address to default"
    )
    wifi_mut.add_argument(
        "--release", nargs="*", metavar="INTERFACE",
        help="Release and unlock wireless interface (stop monitor mode, dhclient, and restore NetworkManager)"
    )
    wifi_mut.add_argument(
        "-c", "--reconnect", nargs="*", metavar="MODE",
        help="Reconnect to already connected BSSID with active MAC & IP ('auto' for continuous reconnect, 'deauth' for continuous reconnect with defensive deauth)"
    )
    wifi_mut.add_argument(
        "--share", nargs=2, metavar=("NAME", "PASSWORD"),
        help="Share Wi-Fi connection via AP hotspot (create_ap)"
    )
    wifi_p.set_defaults(func=run_wifi)

    # blacklist subcommand (uses common_parser ONLY)
    blacklist_p = subparsers.add_parser(
        "blacklist",
        help="Permanent MAC address & BSSID blacklist manager",
        usage="cafe-chameleon blacklist <action> [MAC]",
        description=f"{BOLD}{CYAN}Blacklist Manager{RESET} ─ Permanent MAC address & BSSID blacklist manager",
        formatter_class=CleanHelpFormatter,
        parents=[common_parser],
        add_help=False
    )
    bl_grp = blacklist_p.add_argument_group("Actions")
    bl_grp.add_argument(
        "action_args",
        nargs="*",
        metavar="ACTION [MAC]",
        help="Blacklist action ('add <mac>', 'remove <mac>', or 'list')"
    )
    bl_grp.add_argument("--add", "-a", dest="add_mac", metavar="MAC", help="Add MAC address to blacklist")
    bl_grp.add_argument("--remove", "-r", "--rm", dest="remove_mac", metavar="MAC", help="Remove MAC address from blacklist")
    bl_grp.add_argument("--list", "-l", dest="list_blacklisted", action="store_true", help="List all blacklisted MAC addresses")
    blacklist_p.set_defaults(func=run_blacklist)

    parsed = parser.parse_args(args)
    return parsed
