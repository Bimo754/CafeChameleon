"""
cafe_chameleon.ui.colors - ANSI color constants and formatted logging primitives.
"""

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


def _log(tag: str, color_code: str, text: str, end: str | None = None, start: str = "") -> None:
    """Internal helper for colored logging."""
    prefix = f"{start}{BOLD}{MAGENTA}[{RESET}{BOLD}{color_code}{tag}{RESET}{BOLD}{MAGENTA}]{RESET} "
    print(f"{prefix}{text}", end=end)


def info(text: str, end: str | None = None, start: str = "") -> None:
    _log("Info", GREEN, text, end=end, start=start)


def plus(text: str, end: str | None = None, start: str = "") -> None:
    _log("+", GREEN, text, end=end, start=start)


def gplus(text: str, end: str | None = None, start: str = "") -> None:
    _log("+", YELLOW, text, end=end, start=start)


def question(text: str, end: str | None = None, start: str = "") -> None:
    _log("Question", YELLOW, text, end=end, start=start)


def qmark(text: str, end: str | None = None, start: str = "") -> None:
    _log("?", YELLOW, text, end=end, start=start)


def warning(text: str, end: str | None = None, start: str = "") -> None:
    _log("Warning", RED, text, end=end, start=start)


def minus(text: str, end: str | None = None, start: str = "") -> None:
    _log("-", RED, text, end=end, start=start)


def bminus(text: str, end: str | None = None, start: str = "") -> None:
    _log("-", BLUE, text, end=end, start=start)
