"""
cafe_chameleon.ui.console - High-level logging facade routing to xterm windows or terminal stdout.
"""

from cafe_chameleon.utils.state import get_quiet, get_verbose, get_use_xterm
from cafe_chameleon.ui import colors
from cafe_chameleon.ui.xterm import XtermManager

WINDOW_THEME_COLORS = {
    "main": "\033[38;5;215m",  # Warm Amber / Peach
    "air": "\033[95m",         # Purple
    "scan": "\033[92m",        # Green
    "hijack": "\033[93m"       # Yellow
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


def is_xterm_running() -> bool:
    return bool(get_use_xterm() and XtermManager and XtermManager._instance and XtermManager._instance.enabled)


def log_to_xterm(target: str, text: str, clear: bool = False, add_newline: bool = True) -> bool:
    if is_xterm_running():
        return XtermManager._instance.write(target, text, clear=clear, add_newline=add_newline)
    return False


def clear_window(target: str) -> None:
    if is_xterm_running():
        XtermManager._instance.clear(target)


def format_window_text(target: str, text: str) -> str:
    color = WINDOW_THEME_COLORS.get(target, "\033[0m")
    if "\033[" in text:
        return text.replace("\033[0m", f"\033[0m{color}")
    return f"{color}{text}\033[0m"


def log_main(text: str, clear: bool = False, add_newline: bool = True, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    if is_xterm_running():
        XtermManager._instance.write("main", format_window_text("main", text), clear=clear, add_newline=add_newline)
        return
    if clear:
        print("\033[H\033[2J\033[3J", end="", flush=True)
    end_char = "\n" if add_newline else ""
    print(colors.colorize_brackets(text), end=end_char, flush=True)


def log_subnet_scan(subnet: str) -> None:
    """Logs subnet scanning progress in the main launcher output."""
    text = f"Scanning subnet {subnet}"
    if is_xterm_running():
        XtermManager._instance.write("main", format_window_text("main", text), add_newline=True)
    if not get_quiet():
        print(colors.colorize_brackets(text), flush=True)


def log_hijack_attempt(ip: str, mac: str) -> None:
    """Logs host hijacking attempt to the launcher terminal window with clean single spacing."""
    clean_ip = str(ip).strip() if ip else "N/A"
    clean_mac = str(mac).strip() if mac else "N/A"
    text = f"Trying to hijack {clean_ip} - {clean_mac}"
    if not get_quiet():
        print(colors.colorize_brackets(text), flush=True)


def set_main_status(interface: str | None = None, profile: str | None = None, ssid: str | None = None, status: str | None = None) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        XtermManager._instance.set_main_status(interface=interface, profile=profile, ssid=ssid, status=status)


def log_air(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        XtermManager._instance.write("air", format_window_text("air", text), clear=clear)
        return
    if get_verbose():
        if clear:
            print("\033[H\033[2J\033[3J", end="", flush=True)
        print(colors.colorize_brackets(text))


_DEFAULT = object()


def set_air_status(mode=_DEFAULT, remaining=_DEFAULT) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        kwargs = {}
        if mode is not _DEFAULT:
            kwargs["mode"] = mode
        if remaining is not _DEFAULT:
            kwargs["remaining"] = remaining
        XtermManager._instance.set_air_status(**kwargs)


def set_air_mode(mode: str, remaining=_DEFAULT) -> None:
    set_air_status(mode=mode, remaining=remaining)


def log_scan(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        XtermManager._instance.write("scan", format_window_text("scan", text), clear=clear)
        return
    if get_verbose():
        print(colors.colorize_brackets(text))


def set_scan_status(subnet=_DEFAULT, count=_DEFAULT, scan_type=_DEFAULT) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        kwargs = {}
        if subnet is not _DEFAULT:
            kwargs["subnet"] = subnet
        if count is not _DEFAULT:
            kwargs["count"] = count
        if scan_type is not _DEFAULT:
            kwargs["scan_type"] = scan_type
        XtermManager._instance.set_scan_status(**kwargs)


def log_hijack(text: str, clear: bool = False) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        XtermManager._instance.write("hijack", format_window_text("hijack", text), clear=clear)
        return
    if get_verbose():
        print(colors.colorize_brackets(text))


def set_hijack_status(ip=_DEFAULT, mac=_DEFAULT, technique: str | None = None, clear_section2: bool = False) -> None:
    if get_quiet():
        return
    if is_xterm_running():
        kwargs = {"clear_section2": clear_section2}
        if ip is not _DEFAULT:
            kwargs["ip"] = ip
        if mac is not _DEFAULT:
            kwargs["mac"] = mac
        if technique is not None:
            kwargs["technique"] = technique
        XtermManager._instance.set_hijack_status(**kwargs)
    else:
        if technique:
            print(colors.colorize_brackets(f"[*] Technique: {technique}"))
        if ip is not _DEFAULT:
            if ip and str(ip).strip().lower() not in ("none", "not found", "n/a"):
                print(colors.colorize_brackets(f"[+] Resolved IP: {ip}"))
            elif ip is None or str(ip).strip().lower() in ("not found", "none", "n/a"):
                print(colors.colorize_brackets(f"[*] Resolved IP: Not Found"))
        if mac is not _DEFAULT:
            if mac and str(mac).strip().lower() not in ("none", "not found", "n/a"):
                print(colors.colorize_brackets(f"[+] Target MAC: {mac}"))
            elif mac is None or str(mac).strip().lower() in ("not found", "none", "n/a"):
                print(colors.colorize_brackets(f"[*] Target MAC: Not Found"))


def clear_hijack_section2() -> None:
    if get_quiet():
        return
    if is_xterm_running():
        XtermManager._instance.clear_hijack_section2()


def get_user_input(prompt: str = "") -> str:
    import os
    import sys
    import select

    clean_prompt = prompt.strip("\r\n") if prompt else ""
    if is_xterm_running():
        if clean_prompt:
            log_main(clean_prompt, add_newline=False)
        fifo_path = getattr(XtermManager._instance, "input_fifo", None)
        if fifo_path and os.path.exists(fifo_path):
            try:
                fd_fifo = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    rlist = [fd_fifo]
                    if sys.stdin.isatty():
                        rlist.append(sys.stdin.fileno())
                    r, _, _ = select.select(rlist, [], [], 120.0)
                    if fd_fifo in r:
                        content = os.read(fd_fifo, 1024).decode("utf-8", errors="ignore")
                        if content:
                            return content.strip("\r\n")
                    if sys.stdin.fileno() in r:
                        line = sys.stdin.readline()
                        return line.strip("\r\n")
                finally:
                    os.close(fd_fifo)
            except (KeyboardInterrupt, InterruptedError):
                raise
            except Exception:
                pass

    try:
        return input(prompt)
    except EOFError:
        return ""


def log_info(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    colors.info(text, end=end, start=start, force=force)


def log_plus(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    colors.plus(text, end=end, start=start, force=force)


def log_gplus(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    colors.gplus(text, end=end, start=start, force=force)


def log_warning(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    colors.warning(text, end=end, start=start, force=force)


def log_minus(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    if verbose_only and not get_verbose():
        return
    colors.minus(text, end=end, start=start, force=force)


def log_question(text: str, end: str | None = None, start: str = "", force: bool = False, verbose_only: bool = False) -> None:
    if get_quiet():
        return
    colors.question(text, end=end, start=start, force=force)


def log_step(text: str, end: str | None = None, start: str = "", force: bool = False) -> None:
    if get_quiet():
        return
    colors.step(text, end=end, start=start, force=force)


def log_wait(text: str, end: str | None = None, start: str = "", force: bool = False) -> None:
    if get_quiet():
        return
    colors.wait(text, end=end, start=start, force=force)
