"""
Library/utils.py - Shared logging, process execution, and signal handling utilities.
"""

import os
import shlex
import signal
import subprocess
import sys

try:
    from .colors import colors
    HAS_COLORS = True
except ImportError:
    try:
        from Library.colors import colors
        HAS_COLORS = True
    except ImportError:
        HAS_COLORS = False

try:
    from .display import XtermManager
except ImportError:
    try:
        from Library.display import XtermManager
    except ImportError:
        XtermManager = None

DEBUG = False
QUIET = False
USE_XTERM = True
_RESTORE_PARAMS = None
_RESTORE_CALLBACK = None


def set_debug(val: bool):
    global DEBUG
    DEBUG = val


def get_debug() -> bool:
    return DEBUG


def set_quiet(val: bool):
    global QUIET
    QUIET = val


def get_quiet() -> bool:
    return QUIET


def set_use_xterm(val: bool):
    global USE_XTERM
    USE_XTERM = val


def init_xterm(active_windows=None):
    if USE_XTERM and XtermManager:
        xm = XtermManager.get_instance(enabled=True, active_windows=active_windows)
        if xm.enabled:
            return True
    return False



def close_xterm():
    if XtermManager and XtermManager._instance:
        XtermManager._instance.close()


def log_to_xterm(target, text, clear=False):
    if USE_XTERM and XtermManager and XtermManager._instance and XtermManager._instance.enabled:
        return XtermManager._instance.write(target, text, clear=clear)
    return False


def clear_window(target):
    if USE_XTERM and XtermManager and XtermManager._instance and XtermManager._instance.enabled:
        XtermManager._instance.clear(target)


def set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=None):
    global _RESTORE_PARAMS, _RESTORE_CALLBACK
    _RESTORE_PARAMS = {
        "interface": interface,
        "macaddress": local_mac,
        "ipmask": ipmask,
        "broadcast": broadcast,
        "gateway": gw_ip
    }
    if callback:
        _RESTORE_CALLBACK = callback


def get_restore_params():
    return _RESTORE_PARAMS


def restore_and_exit(reason="Terminated."):
    sys.stdout.write("\n")
    log_warning(f"Process exiting: {reason}")
    if _RESTORE_CALLBACK and _RESTORE_PARAMS and _RESTORE_PARAMS.get("interface"):
        try:
            _RESTORE_CALLBACK(
                _RESTORE_PARAMS["interface"],
                _RESTORE_PARAMS["macaddress"],
                _RESTORE_PARAMS["ipmask"],
                _RESTORE_PARAMS["broadcast"],
                _RESTORE_PARAMS["gateway"]
            )
        except Exception:
            pass
    close_xterm()
    os._exit(0)


def sigint_handler(sig, frame):
    restore_and_exit("Process interrupted by user (Ctrl+C).")



def register_signal_handler():
    signal.signal(signal.SIGINT, sigint_handler)


WINDOW_THEME_COLORS = {
    "main": "\033[96m",    # Cyan
    "air": "\033[95m",     # Purple
    "scan": "\033[92m",    # Green
    "hijack": "\033[93m"   # Yellow
}

def format_window_text(target: str, text: str) -> str:
    color = WINDOW_THEME_COLORS.get(target, "\033[0m")
    formatted = text.replace("\033[0m", f"\033[0m{color}")
    if not formatted.startswith("\033"):
        formatted = f"{color}{formatted}\033[0m{color}"
    else:
        formatted = f"{color}{formatted}\033[0m{color}"
    return formatted


def log_main(text, clear=False):
    if QUIET:
        return
    formatted = format_window_text("main", text)
    if not log_to_xterm("main", formatted, clear=clear):
        log_info(text)


def log_air(text, clear=False):
    if QUIET:
        return
    formatted = format_window_text("air", text)
    if not log_to_xterm("air", formatted, clear=clear):
        log_info(text)


def log_scan(text, clear=False):
    if QUIET:
        return
    formatted = format_window_text("scan", text)
    if not log_to_xterm("scan", formatted, clear=clear):
        log_info(text)


def log_hijack(text, clear=False):
    if QUIET:
        return
    formatted = format_window_text("hijack", text)
    if not log_to_xterm("hijack", formatted, clear=clear):
        log_info(text)


def log_info(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.info(text, end=end, start=start)
    else:
        print(f"{start}[Info] {text}", end=end)


def log_plus(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.plus(text, end=end, start=start)
    else:
        print(f"{start}[+] {text}", end=end)


def log_gplus(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.gplus(text, end=end, start=start)
    else:
        print(f"{start}[+] {text}", end=end)


def log_warning(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.warning(text, end=end, start=start)
    else:
        print(f"{start}[Warning] {text}", end=end)


def log_minus(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.minus(text, end=end, start=start)
    else:
        print(f"{start}[-] {text}", end=end)


def log_question(text, end=None, start=""):
    if QUIET:
        return
    if HAS_COLORS:
        colors.question(text, end=end, start=start)
    else:
        print(f"{start}[Question] {text}", end=end)


def ask_proceed(prompt="Do you want to proceed with the attack? [Y/n]: ") -> bool:
    """
    Prompts the user to decide whether to continue the attack after an impersonation.
    Returns True to proceed ('y', 'yes', or Enter), False to stop ('n', 'no').
    Auto-proceeds if running non-interactively.
    """
    if not sys.stdin.isatty():
        return True

    log_main(f"\n[?] {prompt}")
    try:
        sys.stdout.write(f"\033[93m[?] {prompt}\033[0m ")
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            return False
        ans = line.strip().lower()
        if ans in ("n", "no"):
            return False
        return True
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\n")
        return False


def ask_restore(default_restore=False, prompt="Do you want to restore original MAC and network settings?") -> bool:
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
    log_main(f"\n[?] {full_prompt}")
    try:
        sys.stdout.write(f"\033[93m[?] {full_prompt}\033[0m ")
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            return default_restore
        ans = line.strip().lower()
        if ans in ("y", "yes"):
            return True
        elif ans in ("n", "no"):
            return False
        return default_restore
    except (KeyboardInterrupt, EOFError):
        sys.stdout.write("\n")
        return default_restore


def _run(cmd, debug=None, timeout=None):
    """Run a shell command safely with timeout, return (returncode, stdout)."""
    is_debug = DEBUG if debug is None else debug

    if isinstance(cmd, str):
        cmd_str = cmd
        cmd_args = shlex.split(cmd)
    else:
        cmd_str = " ".join(cmd)
        cmd_args = cmd

    if is_debug:
        print(f"  [RUN] {cmd_str}")

    try:
        result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()

        if is_debug:
            if output:
                for line in output.splitlines():
                    print(f"    [OUT] {line}")
            if result.stderr and result.stderr.strip():
                for line in result.stderr.strip().splitlines():
                    print(f"    [ERR] {line}")

        return result.returncode, output
    except subprocess.TimeoutExpired:
        if is_debug:
            print(f"  [TIMEOUT] Command timed out after {timeout}s: {cmd_str}")
        return 124, ""
    except Exception as e:
        if is_debug:
            print(f"  [ERROR] Command execution error: {e}")
        return 1, ""


