"""
cafe_chameleon.ui.xterm - Multi-Window Xterm Display Manager & Tmux session controller.
"""

import atexit
import os
import re
import shutil
import subprocess
import threading
import time

FIFO_DIR = "/tmp/captive_xterm_fifos"


def get_screen_resolution() -> tuple[int, int]:
    """Detects primary X11 monitor resolution or falls back to 1920x1080."""
    w, h = 1920, 1080
    try:
        res = subprocess.run(["xdpyinfo"], capture_output=True, text=True)
        m = re.search(r"dimensions:\s+(\d+)x(\d+)\s+pixels", res.stdout)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    try:
        res = subprocess.run(["xrandr"], capture_output=True, text=True)
        m = re.search(r"current\s+(\d+)\s+x\s+(\d+)", res.stdout)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return w, h


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
            self.fifos[name] = os.path.join(FIFO_DIR, f"{name}.fifo")

        self.input_fifo = os.path.join(FIFO_DIR, "main_input.fifo")
        self.handles = {}
        self.procs = {}
        self.line_counts = {name: 0 for name in self.active_windows}

        # Persistent status tracking
        self.main_interface = "N/A"
        self.main_profile = "N/A"
        self.main_ssid = "N/A"
        self.main_status = "Idle"
        self.air_mode = "Managed"
        self.hijack_ip = None
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

        # Compute 75% screen geometry centered
        target_w = int(sw * 0.75)
        target_h = int(sh * 0.75)
        cols = max(100, int(target_w / 8.0))
        rows = max(35, int(target_h / 16.0))
        x_offset = max(0, (sw - target_w) // 2)
        y_offset = max(0, (sh - target_h) // 2)

        session_name = "captive_ui"
        subprocess.run(["tmux", "kill-session", "-t", session_name], capture_output=True)

        for name in self.active_windows:
            fifo_path = self.fifos[name]
            if os.path.exists(fifo_path):
                try:
                    os.remove(fifo_path)
                except Exception:
                    pass
            os.mkfifo(fifo_path)

        if os.path.exists(self.input_fifo):
            try:
                os.remove(self.input_fifo)
            except Exception:
                pass
        os.mkfifo(self.input_fifo)

        event_file = "/tmp/captive_xterm_fifos/last_ctrl_c.event"
        ordered_names = [n for n in ["main", "air", "scan", "hijack"] if n in self.active_windows]
        first = ordered_names[0]
        main_pid = os.getpid()

        if first == "main":
            cmd_first = (
                f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {first} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; "
                f"(cat {self.fifos[first]} &); while true; do read -r line; echo \"$line\" > {self.input_fifo}; done'"
            )
        else:
            cmd_first = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {first} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {self.fifos[first]}; sleep 0.1; done'"

        subprocess.run(["tmux", "new-session", "-d", "-s", session_name, cmd_first], check=True)

        for name in ordered_names[1:]:
            if name == "main":
                cmd_next = (
                    f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {name} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; "
                    f"(cat {self.fifos[name]} &); while true; do read -r line; echo \"$line\" > {self.input_fifo}; done'"
                )
            else:
                cmd_next = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {name} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {self.fifos[name]}; sleep 0.1; done'"
            subprocess.run(["tmux", "split-window", "-t", session_name, cmd_next], check=True)

        subprocess.run(["tmux", "select-layout", "-t", session_name, "tiled"], check=True)
        subprocess.run(["tmux", "select-pane", "-t", f"{session_name}:0.0"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-g", "default-terminal", "xterm-256color"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-ga", "terminal-overrides", ",xterm-256color:Tc"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-g", "mouse", "on"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-g", "history-limit", "50000"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-t", session_name, "status", "off"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-t", session_name, "pane-border-style", "fg=#30363d"], capture_output=True)
        subprocess.run(["tmux", "set-option", "-t", session_name, "pane-active-border-style", "fg=#58a6ff"], capture_output=True)

        xterm_cmd = [
            "xterm",
            "-title", "Captive Network Toolkit",
            "-geometry", f"{cols}x{rows}+{x_offset}+{y_offset}",
            "-bg", "#0d1117",
            "-fg", "#58a6ff",
            "-fa", "Monospace",
            "-fs", "10",
            "-tn", "xterm-256color",
            "-e", f"tmux -2 attach-session -t {session_name}"
        ]
        proc = subprocess.Popen(xterm_cmd, start_new_session=True)
        self.procs["main_window"] = proc

        time.sleep(0.3)

        for name in self.active_windows:
            fifo_path = self.fifos[name]
            try:
                fd = os.open(fifo_path, os.O_WRONLY)
                self.handles[name] = os.fdopen(fd, "w", buffering=1)
            except Exception:
                pass

        self.window_headers = {
            "main": "\033[1;36m─── MAIN CONTROLLER & BSSID TRACKER ───────────────────────────────────\033[0m",
            "air": "\033[1;35m─── 802.11 AIR SNIFFER ─────────────────────────────────────────────────\033[0m",
            "scan": "\033[1;32m─── SUBNET HOST SCANNER ───────────────────────────────────────────────\033[0m",
            "hijack": "\033[1;33m─── IMPERSONATION & HIJACK ENGINE ─────────────────────────────────────\033[0m",
        }

        self.window_default_colors = {
            "main": "\033[96m",
            "air": "\033[95m",
            "scan": "\033[92m",
            "hijack": "\033[93m"
        }

        for name in self.active_windows:
            self.write(name, "", clear=True)

        # High-frequency background monitor for instant closure detection
        threading.Thread(target=self._monitor_window_closures, daemon=True).start()

    def _get_main_upper_section(self) -> str:
        line1 = f"\033[1;37mInterface:\033[0m \033[1;36m{self.main_interface}\033[0m | \033[1;37mProfile:\033[0m \033[1;36m{self.main_profile}\033[0m | \033[1;37mSSID:\033[0m \033[1;36m{self.main_ssid}\033[0m\033[K"
        line2 = f"\033[1;37mStatus:\033[0m \033[1;33m{self.main_status}\033[0m\033[K"
        line3 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
        return f"{line1}\n{line2}\n{line3}"

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
        handle = self.handles.get("main")
        if handle:
            try:
                sec = self._get_main_upper_section()
                default_color = self.window_default_colors.get("main", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def _get_air_upper_section(self) -> str:
        if self.air_mode == "Monitor":
            mode_colored = "\033[38;5;208mMonitor\033[0m"
        else:
            mode_colored = "\033[1;32mManaged\033[0m"
        line1 = f"\033[1;37mMode:\033[0m {mode_colored}\033[K"
        line2 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
        return f"{line1}\n{line2}"

    def set_air_mode(self, mode: str) -> None:
        self.air_mode = mode
        if not self.enabled or self.closing or "air" not in self.active_windows:
            return
        handle = self.handles.get("air")
        if handle:
            try:
                sec = self._get_air_upper_section()
                default_color = self.window_default_colors.get("air", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def _get_hijack_upper_section(self) -> str:
        if self.hijack_ip:
            ip_str = f"\033[1;32m{self.hijack_ip}\033[0m"
        else:
            ip_str = "\033[1;31mNot Found\033[0m"

        line1 = f"\033[1;37mIP:\033[0m {ip_str}\033[K"
        line2 = f"\033[1;37mTechnique:\033[0m \033[1;33m{self.hijack_technique}\033[0m\033[K"
        line3 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
        return f"{line1}\n{line2}\n{line3}"

    def set_hijack_status(self, ip: str | None = None, technique: str | None = None, clear_section2: bool = False) -> None:
        if ip is not None:
            try:
                import ipaddress
                ip_obj = ipaddress.ip_address(str(ip))
                if ip_obj.version == 4 and not (ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or str(ip) == "255.255.255.255"):
                    self.hijack_ip = str(ip)
            except Exception:
                pass
        if technique is not None:
            self.hijack_technique = technique
        if not self.enabled or self.closing or "hijack" not in self.active_windows:
            return
        handle = self.handles.get("hijack")
        if handle:
            try:
                sec = self._get_hijack_upper_section()
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
        handle = self.handles.get("hijack")
        if handle:
            try:
                default_color = self.window_default_colors.get("hijack", "\033[0m")
                handle.write(f"\033[5;1H\033[J{default_color}")
                handle.flush()
            except Exception:
                pass

    def _get_scan_upper_section(self) -> str:
        line1 = f"\033[1;37mSubnet:\033[0m \033[1;36m{self.scan_subnet}\033[0m | \033[1;37mHosts Found:\033[0m \033[1;32m{self.scan_hosts_count}\033[0m | \033[1;37mActive Scan:\033[0m \033[1;33m{self.scan_type}\033[0m\033[K"
        line2 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
        return f"{line1}\n{line2}"

    def set_scan_status(self, subnet: str | None = None, count: int | None = None, scan_type: str | None = None) -> None:
        if subnet is not None:
            self.scan_subnet = subnet
        if count is not None:
            self.scan_hosts_count = count
        if scan_type is not None:
            self.scan_type = scan_type
        if not self.enabled or self.closing or "scan" not in self.active_windows:
            return
        handle = self.handles.get("scan")
        if handle:
            try:
                sec = self._get_scan_upper_section()
                default_color = self.window_default_colors.get("scan", "\033[0m")
                handle.write(f"\033[s\033[2;1H{sec}\033[u{default_color}")
                handle.flush()
            except Exception:
                pass

    def _monitor_window_closures(self):
        """High-frequency monitor. Closing any xterm window instantly closes all others and exits."""
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

    def write(self, target, text, clear=False, add_newline=True):
        if not self.enabled or self.closing or target not in self.active_windows:
            return False
        handle = self.handles.get(target)
        if handle:
            try:
                if clear:
                    handle.write("\033[2J\033[H")
                    header = self.window_headers.get(target, "")
                    default_color = self.window_default_colors.get(target, "\033[0m")
                    if header:
                        handle.write(f"{header}\n")
                    if target == "main":
                        handle.write(f"{self._get_main_upper_section()}\n")
                    elif target == "air":
                        handle.write(f"{self._get_air_upper_section()}\n")
                    elif target == "hijack":
                        handle.write(f"{self._get_hijack_upper_section()}\n")
                    elif target == "scan":
                        handle.write(f"{self._get_scan_upper_section()}\n")
                    handle.write(f"{default_color}")
                    self.line_counts[target] = 0

                if text:
                    content = (text + "\n") if (add_newline and not text.endswith("\n")) else text
                    handle.write(content)
                    handle.flush()
                    self.line_counts[target] += content.count("\n")
                return True
            except Exception:
                pass
        return False


    def clear(self, target):
        self.write(target, "", clear=True)

    def close(self):
        if self.closing:
            return
        self.closing = True

        subprocess.run(["tmux", "kill-session", "-t", "captive_ui"], capture_output=True)

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
        for f in self.fifos.values():
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        XtermManager._instance = None
