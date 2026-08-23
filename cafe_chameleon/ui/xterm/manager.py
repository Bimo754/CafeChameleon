"""
cafe_chameleon.ui.xterm.manager - Multi-Window Xterm Display Manager class implementation.
"""

import atexit
import os
import shutil
import subprocess
import sys
import threading
import time

from .screen import get_screen_resolution
from .fifos import FIFO_DIR, prepare_fifo, remove_fifos, get_fifo_path, get_input_fifo_path
from .tmux import setup_tmux_session, kill_tmux_session
from .headers import (
    format_main_header,
    format_air_header,
    format_hijack_header,
    format_scan_header
)


_DEFAULT = object()


class XtermManager:
    _instance = None

    def __init__(self, enabled=True, active_windows=None):
        if active_windows is None:
            active_windows = ["main", "air", "scan", "hijack"]

        self.active_windows = set(active_windows)
        self.enabled = (
            enabled
            and len(self.active_windows) > 0
            and bool(os.environ.get("DISPLAY"))
            and bool(shutil.which("xterm"))
        )

        self.fifos = {}
        for name in self.active_windows:
            self.fifos[name] = get_fifo_path(name)

        self.input_fifo = get_input_fifo_path()
        self.handles = {}
        self.procs = {}
        self.line_counts = {name: 0 for name in self.active_windows}

        # Persistent status tracking
        self.main_interface = "N/A"
        self.main_profile = "N/A"
        self.main_ssid = "N/A"
        self.main_status = "Idle"
        self.air_mode = "Managed"
        self.air_remaining = "N/A"
        self.hijack_ip = None
        self.hijack_mac = None
        self.hijack_technique = "Idle"
        self.scan_subnet = "N/A"
        self.scan_hosts_count = 0
        self.scan_type = "Idle"

        self.closing = False

        if self.enabled:
            self._setup_fifos_and_xterms()
            atexit.register(self.close)

    @classmethod
    def get_instance(cls, enabled=True, active_windows=None):
        if cls._instance is None:
            cls._instance = XtermManager(enabled=enabled, active_windows=active_windows)
        return cls._instance

    @classmethod
    def is_active(cls):
        inst = cls.get_instance()
        return inst.enabled

    def _setup_fifos_and_xterms(self):
        os.makedirs(FIFO_DIR, exist_ok=True)
        sw, sh = get_screen_resolution()

        target_w = int(sw * 0.75)
        target_h = int(sh * 0.75)
        cols = max(100, int(target_w / 9.6))
        rows = max(35, int(target_h / 19.0))
        x_offset = max(0, (sw - target_w) // 2)
        y_offset = max(0, (sh - target_h) // 2)

        for name in self.active_windows:
            prepare_fifo(self.fifos[name])
        prepare_fifo(self.input_fifo)

        setup_tmux_session(self.active_windows, self.fifos, self.input_fifo)

        xterm_cmd = [
            "xterm",
            "-title", "Captive Network Toolkit",
            "-geometry", f"{cols}x{rows}+{x_offset}+{y_offset}",
            "-bg", "#000000",
            "-fg", "#58a6ff",
            "-fa", "Monospace",
            "-fs", "10",
            "-tn", "xterm-256color",
            "-e", "tmux -2 attach-session -t captive_ui"
        ]
        proc = subprocess.Popen(xterm_cmd, start_new_session=True)
        self.procs["main_window"] = proc

        time.sleep(0.3)

        for name in self.active_windows:
            fifo_path = self.fifos[name]
            try:
                fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                self.handles[name] = os.fdopen(fd, "w", buffering=1)
            except Exception:
                pass

        self.window_headers = {
            "main": "\033[1;38;5;215m─── MAIN CONTROLLER & BSSID TRACKER ───────────────────────────────────\033[0m",
            "air": "\033[1;35m─── 802.11 AIR SNIFFER ─────────────────────────────────────────────────\033[0m",
            "scan": "\033[1;32m─── SUBNET HOST SCANNER ───────────────────────────────────────────────\033[0m",
            "hijack": "\033[1;33m─── IMPERSONATION & HIJACK ENGINE ─────────────────────────────────────\033[0m",
        }

        self.window_default_colors = {
            "main": "\033[38;5;215m",
            "air": "\033[95m",
            "scan": "\033[92m",
            "hijack": "\033[93m"
        }

        for name in self.active_windows:
            self.write(name, "", clear=True)

        threading.Thread(target=self._monitor_window_closures, daemon=True).start()

    def set_main_status(self, interface: str | None = None, profile: str | None = None, ssid: str | None = None, status: str | None = None) -> None:
        if interface is not None:
            self.main_interface = interface
        if profile is not None:
            self.main_profile = profile
        if ssid is not None:
            self.main_ssid = ssid
        if status is not None:
            self.main_status = status
        if not self.enabled or self.closing or "main" not in self.active_windows:
            return
        handle = self._ensure_handle("main")
        if handle:
            try:
                sec = format_main_header(self.main_interface, self.main_profile, self.main_ssid, self.main_status)
                default_color = self.window_default_colors.get("main", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def set_air_status(self, mode=_DEFAULT, remaining=_DEFAULT) -> None:
        if mode is not _DEFAULT and mode is not None:
            self.air_mode = str(mode)
        if remaining is not _DEFAULT:
            if remaining is None:
                self.air_remaining = "N/A"
            elif isinstance(remaining, (int, float)):
                self.air_remaining = f"{int(remaining)}s"
            else:
                r_str = str(remaining).strip()
                self.air_remaining = f"{r_str}s" if r_str.isdigit() else r_str
        if not self.enabled or self.closing or "air" not in self.active_windows:
            return
        handle = self._ensure_handle("air")
        if handle:
            try:
                sec = format_air_header(self.air_mode, self.air_remaining)
                default_color = self.window_default_colors.get("air", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def set_air_mode(self, mode: str, remaining=_DEFAULT) -> None:
        self.set_air_status(mode=mode, remaining=remaining)

    def set_hijack_status(self, ip=_DEFAULT, mac=_DEFAULT, technique: str | None = None, clear_section2: bool = False) -> None:
        if ip is not _DEFAULT:
            if ip is None or str(ip).strip() == "" or str(ip).strip().lower() in ("none", "not found", "n/a"):
                self.hijack_ip = None
            else:
                try:
                    from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4
                    if is_valid_ipv4(str(ip)):
                        self.hijack_ip = str(ip)
                    else:
                        self.hijack_ip = None
                except Exception:
                    self.hijack_ip = str(ip)
        if mac is not _DEFAULT:
            if mac is None or str(mac).strip() == "" or str(mac).strip().lower() in ("none", "not found", "n/a"):
                self.hijack_mac = None
            else:
                self.hijack_mac = str(mac).strip()
        if technique is not None:
            self.hijack_technique = str(technique) if technique else "Idle"
        if not self.enabled or self.closing or "hijack" not in self.active_windows:
            return
        handle = self._ensure_handle("hijack")
        if handle:
            try:
                sec = format_hijack_header(self.hijack_ip, self.hijack_mac, self.hijack_technique)
                default_color = self.window_default_colors.get("hijack", "\033[0m")
                if clear_section2:
                    handle.write(f"\033[2;1H{sec}\n\033[J{default_color}")
                else:
                    handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def clear_hijack_section2(self) -> None:
        if not self.enabled or self.closing or "hijack" not in self.active_windows:
            return
        handle = self._ensure_handle("hijack")
        if handle:
            try:
                default_color = self.window_default_colors.get("hijack", "\033[0m")
                handle.write(f"\033[6;1H\033[J{default_color}")
                handle.flush()
            except Exception:
                pass

    def set_scan_status(self, subnet=_DEFAULT, count=_DEFAULT, scan_type=_DEFAULT) -> None:
        if subnet is not _DEFAULT:
            self.scan_subnet = str(subnet) if (subnet is not None and str(subnet).strip() not in ("", "None")) else "N/A"
        if count is not _DEFAULT:
            self.scan_hosts_count = int(count) if count is not None else 0
        if scan_type is not _DEFAULT:
            self.scan_type = str(scan_type) if (scan_type is not None and str(scan_type).strip() not in ("", "None")) else "Idle"
        if not self.enabled or self.closing or "scan" not in self.active_windows:
            return
        handle = self._ensure_handle("scan")
        if handle:
            try:
                sec = format_scan_header(self.scan_subnet, self.scan_hosts_count, self.scan_type)
                default_color = self.window_default_colors.get("scan", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def _monitor_window_closures(self):
        while not self.closing:
            for name, proc in list(self.procs.items()):
                if proc.poll() is not None:
                    if not self.closing:
                        self.closing = True
                        try:
                            from cafe_chameleon.utils.signals import restore_and_exit
                            restore_and_exit(f"Xterm window '{name}' was closed by user.")
                        except Exception:
                            self.close()
                            os._exit(0)
                    return
            time.sleep(0.05)

    def _ensure_handle(self, target):
        if not self.enabled or self.closing or target not in self.active_windows:
            return None
        if target in self.handles:
            h = self.handles[target]
            if not getattr(h, "closed", False):
                return h
        fifo_path = self.fifos.get(target)
        if not fifo_path:
            return None
        try:
            fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            h = os.fdopen(fd, "w", buffering=1)
            self.handles[target] = h
            return h
        except Exception:
            return None

    def write(self, target, text, clear=False, add_newline=True):
        if not self.enabled or self.closing or target not in self.active_windows:
            return False
        handle = self._ensure_handle(target)
        if handle:
            try:
                if clear:
                    handle.write("\033[H\033[2J\033[3J")
                    header = self.window_headers.get(target, "")
                    default_color = self.window_default_colors.get(target, "\033[0m")
                    if header:
                        handle.write(f"{header}\n")
                    if target == "main":
                        handle.write(f"{format_main_header(self.main_interface, self.main_profile, self.main_ssid, self.main_status)}\n")
                    elif target == "air":
                        handle.write(f"{format_air_header(self.air_mode, self.air_remaining)}\n")
                    elif target == "hijack":
                        handle.write(f"{format_hijack_header(self.hijack_ip, self.hijack_mac, self.hijack_technique)}\n")
                    elif target == "scan":
                        handle.write(f"{format_scan_header(self.scan_subnet, self.scan_hosts_count, self.scan_type)}\n")
                    handle.write(f"{default_color}")
                    self.line_counts[target] = 0

                if text:
                    content = (text + "\n") if (add_newline and not text.endswith("\n")) else text
                    handle.write(content)
                    handle.flush()
                    self.line_counts[target] += content.count("\n")
                return True
            except Exception:
                try:
                    handle.close()
                except Exception:
                    pass
                self.handles.pop(target, None)
        return False

    def clear(self, target):
        self.write(target, "", clear=True)

    def play_completion_animation(self):
        """
        Launches a new dedicated pitch-black window to play the chameleon ASCII completion animation.
        """
        try:
            repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            cmd = [sys.executable, "-m", "cafe_chameleon.ui.animation", "random"]
            env = dict(os.environ)
            env["CAFE_ANIMATION_XTERM"] = "0"
            existing_ppath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{repo_dir}:{existing_ppath}" if existing_ppath else repo_dir
            subprocess.Popen(cmd, env=env)
        except Exception:
            pass

    def close(self):
        if self.closing:
            return
        self.closing = True

        kill_tmux_session()

        for h in self.handles.values():
            try:
                h.close()
            except Exception:
                pass
        for p in self.procs.values():
            try:
                p.terminate()
                p.kill()
            except Exception:
                pass
        remove_fifos(self.fifos, self.input_fifo)
        XtermManager._instance = None
