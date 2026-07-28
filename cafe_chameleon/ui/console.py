"""
cafe_chameleon.ui.console - High-level logging facade routing to xterm windows or terminal stdout.
"""

from cafe_chameleon.utils.state import get_quiet, get_use_xterm
from cafe_chameleon.ui import colors
from cafe_chameleon.ui.xterm import XtermManager

WINDOW_THEME_COLORS = {
    "main": "\033[96m",    # Cyan
    "air": "\033[95m",     # Purple
    "scan": "\033[92m",    # Green
    "hijack": "\033[93m"   # Yellow
}


def init_xterm(active_windows=None) -> bool:
    if get_use_xterm() and XtermManager:
        xm = XtermManager.get_instance(enabled=True, active_windows=active_windows)
        if xm.enabled:
            return True
    return False


def close_xterm() -> None:
    if XtermManager and XtermManager._instance:
        XtermManager._instance.close()


def log_to_xterm(target: str, text: str, clear: bool = False) -> bool:
    if get_use_xterm() and XtermManager and XtermManager._instance and XtermManager._instance.enabled:
        return XtermManager._instance.write(target, text, clear=clear)
    return False


def clear_window(target: str) -> None:
    if get_use_xterm() and XtermManager and XtermManager._instance and XtermManager._instance.enabled:
        XtermManager._instance.clear(target)


def format_window_text(target: str, text: str) -> str:
    color = WINDOW_THEME_COLORS.get(target, "\033[0m")
    formatted = text.replace("\033[0m", f"\033[0m{color}")
    if not formatted.startswith("\033"):
        formatted = f"{color}{formatted}\033[0m{color}"
    else:
        formatted = f"{color}{formatted}\033[0m{color}"
    return formatted


def log_main(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    formatted = format_window_text("main", text)
    if not log_to_xterm("main", formatted, clear=clear):
        log_info(text)


def log_air(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    formatted = format_window_text("air", text)
    if not log_to_xterm("air", formatted, clear=clear):
        log_info(text)


def log_scan(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    formatted = format_window_text("scan", text)
    if not log_to_xterm("scan", formatted, clear=clear):
        log_info(text)


def log_hijack(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    formatted = format_window_text("hijack", text)
    if not log_to_xterm("hijack", formatted, clear=clear):
        log_info(text)


def log_info(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.info(text, end=end, start=start)


def log_plus(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.plus(text, end=end, start=start)


def log_gplus(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.gplus(text, end=end, start=start)


def log_warning(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.warning(text, end=end, start=start)


def log_minus(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.minus(text, end=end, start=start)


def log_question(text: str, end: str | None = None, start: str = "") -> None:
    if get_quiet():
        return
    colors.question(text, end=end, start=start)
