# Library/colors/colors.py

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


def _log(tag, color_code, text, end=None, start=""):
    """Internal helper for colored logging."""
    prefix = f"{start}{BOLD}{MAGENTA}[{RESET}{BOLD}{color_code}{tag}{RESET}{BOLD}{MAGENTA}]{RESET} "
    print(f"{prefix}{text}", end=end)


def info(text, end=None, start=""):
    _log("Info", GREEN, text, end=end, start=start)


def plus(text, end=None, start=""):
    _log("+", GREEN, text, end=end, start=start)


def gplus(text, end=None, start=""):
    _log("+", YELLOW, text, end=end, start=start)


def question(text, end=None, start=""):
    _log("Question", YELLOW, text, end=end, start=start)


def qmark(text, end=None, start=""):
    _log("?", YELLOW, text, end=end, start=start)


def warning(text, end=None, start=""):
    _log("Warning", RED, text, end=end, start=start)


def minus(text, end=None, start=""):
    _log("-", RED, text, end=end, start=start)


def bminus(text, end=None, start=""):
    _log("-", BLUE, text, end=end, start=start)


