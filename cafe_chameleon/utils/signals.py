"""
cafe_chameleon.utils.signals - Signal handling (SIGINT) and restore & exit mechanisms.
"""

import os
import signal
import sys

from .state import get_restore_params, get_restore_callback


EVENT_FILE = "/tmp/captive_xterm_fifos/last_ctrl_c.event"


class WindowCtrlCInterrupt(KeyboardInterrupt):
    """Base exception for window-specific Ctrl+C triggers."""
    def __init__(self, window_name: str):
        self.window_name = window_name
        super().__init__(f"Ctrl+C in window '{window_name}'")


class MainSkipInterrupt(WindowCtrlCInterrupt):
    """Triggered by Ctrl+C in Main window -> skip BSSID."""
    def __init__(self):
        super().__init__("main")


class AirSkipInterrupt(WindowCtrlCInterrupt):
    """Triggered by Ctrl+C in Air window -> stop air sniffing and proceed."""
    def __init__(self):
        super().__init__("air")


class HijackSkipInterrupt(WindowCtrlCInterrupt):
    """Triggered by Ctrl+C in Hijack window -> skip current target MAC."""
    def __init__(self):
        super().__init__("hijack")


class ScanSkipInterrupt(WindowCtrlCInterrupt):
    """Triggered by Ctrl+C in Scan window -> skip whole subnet block."""
    def __init__(self):
        super().__init__("scan")


def close_xterm():
    """Deferred import to avoid circular dependencies."""
    try:
        from cafe_chameleon.ui.xterm import XtermManager
        if XtermManager and XtermManager._instance:
            XtermManager._instance.close()
    except Exception:
        pass


def restore_and_exit(reason: str = "Terminated."):
    """Restores network settings if set and exits process immediately."""
    sys.stdout.write("\n")
    print(f"\033[91m[Warning] Process exiting: {reason}\033[0m")
    
    callback = get_restore_callback()
    params = get_restore_params()

    if callback and params and params.get("interface"):
        try:
            callback(
                params["interface"],
                params["macaddress"],
                params["ipmask"],
                params["broadcast"],
                params["gateway"],
                profile=params.get("profile")
            )
        except Exception:
            try:
                callback(
                    params["interface"],
                    params["macaddress"],
                    params["ipmask"],
                    params["broadcast"],
                    params["gateway"]
                )
            except Exception:
                pass

    close_xterm()
    os._exit(0)


def sigint_handler(sig, frame):
    window_name = None
    if os.path.exists(EVENT_FILE):
        try:
            with open(EVENT_FILE, "r") as f:
                window_name = f.read().strip()
            os.remove(EVENT_FILE)
        except Exception:
            pass

    if window_name == "air":
        raise AirSkipInterrupt()
    elif window_name == "hijack":
        raise HijackSkipInterrupt()
    elif window_name == "scan":
        raise ScanSkipInterrupt()
    elif window_name == "main":
        raise MainSkipInterrupt()
    else:
        raise KeyboardInterrupt()


def register_signal_handler():
    signal.signal(signal.SIGINT, sigint_handler)


