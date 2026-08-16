"""
cafe_chameleon.cli.commands.blacklist - Command handler adapter for 'blacklist' mode.
"""

from cafe_chameleon.modes.blacklist import run_blacklist


def handle_blacklist(args) -> int:
    return run_blacklist(args)
