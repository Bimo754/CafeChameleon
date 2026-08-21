"""
cafe_chameleon.modes.blacklist.controller - Subcommand handler for blacklist management.
"""

from cafe_chameleon.utils.blacklist import (
    add_to_blacklist,
    remove_from_blacklist,
    list_blacklist,
    handle_blacklist_cli
)
from cafe_chameleon.ui.colors import BOLD, GREEN, RED, CYAN, YELLOW, RESET, colorize_brackets


def run_blacklist(args) -> int:
    """Executes blacklist subcommand actions (add, remove, list)."""
    if getattr(args, "add_mac", None):
        success, msg = add_to_blacklist(args.add_mac)
        print(colorize_brackets(f"{BOLD}{GREEN if success else RED}[{'+' if success else '-'}] {msg}{RESET}"))
        return 0 if success else 1

    if getattr(args, "remove_mac", None):
        success, msg = remove_from_blacklist(args.remove_mac)
        print(colorize_brackets(f"{BOLD}{GREEN if success else RED}[{'+' if success else '-'}] {msg}{RESET}"))
        return 0 if success else 1

    if getattr(args, "list_blacklisted", False):
        entries = list_blacklist()
        if not entries:
            print(colorize_brackets(f"{BOLD}{YELLOW}[i] Blacklist is empty (no MAC addresses blacklisted).{RESET}"))
        else:
            print(colorize_brackets(f"\n{BOLD}{CYAN}── BLACKLISTED CLIENT / BSSID MAC ADDRESSES ────────────────────────────{RESET}"))
            for idx, m in enumerate(entries, start=1):
                print(colorize_brackets(f"  [{idx}] {BOLD}{m}{RESET}"))
            print(colorize_brackets(f"{BOLD}{CYAN}────────────────────────────────────────────────────────────────────────{RESET}\n"))
        return 0

    action_args = []
    if hasattr(args, "action_args") and args.action_args:
        action_args.extend(args.action_args)
    elif hasattr(args, "action") and args.action:
        action_args.append(args.action)
        if hasattr(args, "mac") and args.mac:
            action_args.append(args.mac)

    return handle_blacklist_cli(action_args)
