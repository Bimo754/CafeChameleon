"""
cafe_chameleon.cli.commands.wifi - Command handler adapter for 'wifi' mode.
"""

from cafe_chameleon.modes.wifi import run_wifi


def handle_wifi(args) -> None:
    return run_wifi(args)
