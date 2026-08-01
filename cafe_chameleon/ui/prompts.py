"""
cafe_chameleon.ui.prompts - Interactive user confirmation prompts.
"""

import sys

from cafe_chameleon.ui.console import get_user_input


def ask_proceed(prompt: str = "Do you want to proceed with the attack? [Y/n]: ") -> bool:
    """
    Prompts the user to decide whether to continue the attack after an impersonation.
    Returns True to proceed ('y', 'yes', or Enter), False to stop ('n', 'no').
    Auto-proceeds if running non-interactively.
    """
    if not sys.stdin.isatty():
        return True

    ans_raw = get_user_input(f"[?] {prompt}")
    ans = ans_raw.strip().lower()
    if ans in ("n", "no"):
        return False
    return True


def ask_restore(default_restore: bool = False, prompt: str = "Do you want to restore original MAC and network settings?") -> bool:
    """
    Prompts the user whether to restore original MAC and network settings.
    If default_restore is True: prompt displays [Y/n] (Enter -> restore).
    If default_restore is False: prompt displays [y/N] (Enter -> keep current MAC/settings).
    Returns True to restore, False to keep current settings.
    Auto-returns default_restore if running non-interactively.
    """
    if not sys.stdin.isatty():
        return default_restore

    options = "[Y/n]" if default_restore else "[y/N]"
    full_prompt = f"{prompt} {options}: "
    ans_raw = get_user_input(f"[?] {full_prompt}")
    if not ans_raw:
        return default_restore
    ans = ans_raw.strip().lower()
    if ans in ("y", "yes"):
        return True
    elif ans in ("n", "no"):
        return False
    return default_restore
