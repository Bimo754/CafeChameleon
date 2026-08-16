"""
cafe_chameleon.modes.blacklist.controller - Subcommand handler for blacklist management.
"""

from cafe_chameleon.utils.blacklist import handle_blacklist_cli


def run_blacklist(args) -> int:
    """Executes blacklist subcommand actions (add, remove, list)."""
    if getattr(args, "add_mac", None):
        return handle_blacklist_cli(["add", args.add_mac])
    if getattr(args, "remove_mac", None):
        return handle_blacklist_cli(["remove", args.remove_mac])
    if getattr(args, "list_blacklisted", False):
        return handle_blacklist_cli(["list"])

    args_list = []
    if hasattr(args, "action_args") and args.action_args:
        args_list.extend(args.action_args)
    elif hasattr(args, "action") and args.action:
        args_list.append(args.action)
        if hasattr(args, "mac") and args.mac:
            args_list.append(args.mac)
    return handle_blacklist_cli(args_list)
