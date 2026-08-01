"""
cafe_chameleon.cli.commands.aggressive - Command handler adapter for 'aggressive' mode.
"""

from cafe_chameleon.modes.aggressive import run_aggressive


def handle_aggressive(args) -> bool:
    return run_aggressive(args)
