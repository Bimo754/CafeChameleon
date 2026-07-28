"""
cafe_chameleon.cli.commands.aggressive - Command handler for 'aggressive' (Sequential multi-BSSID exploration & over-the-air client discovery).
"""

from cafe_chameleon.aggressive.runner import run_aggressive


def handle_aggressive(args) -> bool:
    return run_aggressive(args)
