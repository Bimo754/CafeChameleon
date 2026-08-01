"""
cafe_chameleon.cli.commands.simple - Command handler adapter for 'simple' mode.
"""

from cafe_chameleon.modes.simple import run_simple


def handle_simple(args, quiet_header: bool = False) -> bool:
    return run_simple(args, quiet_header=quiet_header)
