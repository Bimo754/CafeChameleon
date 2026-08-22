"""
cafe_chameleon.utils.signals - Central process signal trapping, interrupt handling, and clean teardown.
"""

import os
import sys
import signal
from cafe_chameleon.config import EVENT_FILE
from cafe_chameleon.utils.state import get_restore_callback, get_restore_params
from cafe_chameleon.ui.xterm import XtermManager


class WindowCtrlCInterrupt(Exception):
    """Base exception indicating an in-window user interrupt signal was received."""
    pass


class AirSkipInterrupt(WindowCtrlCInterrupt):
    """Raised when Ctrl+C is pressed inside the Air/Monitor window."""
    pass


class HijackSkipInterrupt(WindowCtrlCInterrupt):
    """Raised when Ctrl+C is pressed inside the Hijack window."""
    pass


class ScanSkipInterrupt(WindowCtrlCInterrupt):
    """Raised when Ctrl+C is pressed inside the Scanner window."""
    pass


class MainSkipInterrupt(WindowCtrlCInterrupt):
    """Raised when Ctrl+C is pressed inside the Main window."""
    pass


def reset_event():
    """Removes lingering FIFO event files."""
    if os.path.exists(EVENT_FILE):
        try:
            os.remove(EVENT_FILE)
        except Exception:
            pass


def close_xterm():
    """Gracefully closes all spawned auxiliary xterm windows."""
    reset_event()
    try:
        if XtermManager and XtermManager._instance:
            XtermManager._instance.close()
    except Exception:
        pass


def restore_and_exit(reason: str = "Terminated."):
    """Releases interface cleanly on termination and exits process, ignoring subsequent Ctrl+C / kill signals."""
    # Catch and ignore all further SIGINT/SIGTERM/SIGHUP signals so cleanup cannot be aborted midway
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except Exception:
        pass

    sys.stdout.write("\n")
    print(f"\033[91m[Warning] Process exiting: {reason}\033[0m")
    
    params = get_restore_params()

    # Release and unlock wireless interface (wifi --release mode)
    try:
        from cafe_chameleon.network.nmcli import release_interface
        prof = (params and params.get("profile"))
        iface = (params and params.get("interface"))
        release_interface(interface=iface, profile=prof)
    except Exception:
        # Fallback cleanup for monitor mode, NetworkManager profile, hardware MAC, and lingering dhclient
        try:
            from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode
            iface = (params and params.get("interface")) or "wlan0"
            if is_monitor_mode_active(iface):
                set_managed_mode(iface)
        except Exception:
            pass

        try:
            from cafe_chameleon.network.nmcli import get_active_profile
            from cafe_chameleon.network.mac import reset_mac_address
            from cafe_chameleon.utils.process import _run
            
            prof = (params and params.get("profile")) or get_active_profile()
            iface = (params and params.get("interface")) or "wlan0"
            if prof:
                _run(["nmcli", "connection", "modify", prof, "802-11-wireless.bssid", ""], debug=False)
                _run(["nmcli", "connection", "modify", prof, "802-11-wireless.cloned-mac-address", ""], debug=False)
            reset_mac_address(iface, profile=prof)
            _run(f"pkill -9 -f 'dhclient.*{iface}'", debug=False)
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


def sigterm_handler(sig, frame):
    restore_and_exit(f"Process received signal {sig} (window or terminal session closed).")


def register_signal_handler():
    try:
        signal.signal(signal.SIGINT, sigint_handler)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
    except Exception:
        pass
    if hasattr(signal, "SIGHUP"):
        try:
            signal.signal(signal.SIGHUP, sigterm_handler)
        except Exception:
            pass
