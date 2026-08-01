"""
cafe_chameleon.ui.colors - ANSI color constants and formatted logging primitives.
"""

import re

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

BRACKET_OPEN = f"{BOLD}{MAGENTA}[{RESET}"
BRACKET_CLOSE = f"{BOLD}{MAGENTA}]{RESET}"


ANSI_PATTERN = re.compile(r'(\x1b\[[0-9;]*[a-zA-Z])')


def colorize_brackets(text: str) -> str:
    """Format visible brackets [ and ] with bold magenta color."""
    if not text:
        return text

    parts = ANSI_PATTERN.split(text)

    new_parts = []
    for i, part in enumerate(parts):
        if i % 2 == 0:  # Non-ANSI text segment
            part = part.replace('[+]', '\x01PLUS\x02')
            part = part.replace('[-]', '\x01MINUS\x02')
            part = part.replace('[*]', '\x01STAR\x02')
            part = part.replace('[!]', '\x01EXCL\x02')
            part = part.replace('[?]', '\x01QUEST\x02')
            part = part.replace('[~]', '\x01TILDE\x02')
            part = part.replace('[i]', '\x01INFO\x02')

            part = part.replace('[', BRACKET_OPEN).replace(']', BRACKET_CLOSE)

            part = part.replace('\x01PLUS\x02', f'{BRACKET_OPEN}{BOLD}{GREEN}+{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01MINUS\x02', f'{BRACKET_OPEN}{BOLD}{RED}-{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01STAR\x02', f'{BRACKET_OPEN}{BOLD}{CYAN}*{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01EXCL\x02', f'{BRACKET_OPEN}{BOLD}{RED}!{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01QUEST\x02', f'{BRACKET_OPEN}{BOLD}{YELLOW}?{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01TILDE\x02', f'{BRACKET_OPEN}{BOLD}{YELLOW}~{RESET}{BRACKET_CLOSE}')
            part = part.replace('\x01INFO\x02', f'{BRACKET_OPEN}{BOLD}{CYAN}i{RESET}{BRACKET_CLOSE}')
        new_parts.append(part)

    return ''.join(new_parts)


def _log(tag: str, color_code: str, text: str, end: str | None = None, start: str = "") -> None:
    """Internal helper for clean, modern colored logging."""
    prefix = f"{start}{BRACKET_OPEN}{BOLD}{color_code}{tag}{RESET}{BRACKET_CLOSE} "
    formatted_text = colorize_brackets(text)
    print(f"{prefix}{formatted_text}", end=end)


def info(text: str, end: str | None = None, start: str = "") -> None:
    _log("i", CYAN, text, end=end, start=start)


def plus(text: str, end: str | None = None, start: str = "") -> None:
    _log("+", GREEN, text, end=end, start=start)


def gplus(text: str, end: str | None = None, start: str = "") -> None:
    _log("+", YELLOW, text, end=end, start=start)


def question(text: str, end: str | None = None, start: str = "") -> None:
    _log("?", YELLOW, text, end=end, start=start)


def qmark(text: str, end: str | None = None, start: str = "") -> None:
    _log("?", YELLOW, text, end=end, start=start)


def warning(text: str, end: str | None = None, start: str = "") -> None:
    _log("!", RED, text, end=end, start=start)


def minus(text: str, end: str | None = None, start: str = "") -> None:
    _log("-", RED, text, end=end, start=start)


def bminus(text: str, end: str | None = None, start: str = "") -> None:
    _log("-", BLUE, text, end=end, start=start)


def step(text: str, end: str | None = None, start: str = "") -> None:
    _log("*", CYAN, text, end=end, start=start)


def wait(text: str, end: str | None = None, start: str = "") -> None:
    _log("~", YELLOW, text, end=end, start=start)



