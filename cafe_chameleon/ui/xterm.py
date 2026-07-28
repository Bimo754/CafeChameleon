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

        self.handles = {}
        self.procs = {}
        self.line_counts = {name: 0 for name in self.active_windows}
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
        xc, yc = sw // 2, sh // 2

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

        event_file = "/tmp/captive_xterm_fifos/last_ctrl_c.event"
        ordered_names = [n for n in ["main", "air", "scan", "hijack"] if n in self.active_windows]
        first = ordered_names[0]
        main_pid = os.getpid()
        cmd_first = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {first} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {self.fifos[first]}; sleep 0.1; done'"
        subprocess.run(["tmux", "new-session", "-d", "-s", session_name, cmd_first], check=True)

        for name in ordered_names[1:]:
            cmd_next = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {name} > {event_file}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {self.fifos[name]}; sleep 0.1; done'"
            subprocess.run(["tmux", "split-window", "-t", session_name, cmd_next], check=True)

        subprocess.run(["tmux", "select-layout", "-t", session_name, "tiled"], check=True)
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
            "-geometry", f"160x45+{max(0, xc - 640)}+{max(0, yc - 400)}",
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

        all_window_configs = {
            "main": ("MAIN CONTROLLER & BSSID TRACKER", "#0d1117", "#58a6ff", "1;36m========================================\n    AGGRESSIVE CONTROLLER & STATUS      \n========================================"),
            "air": ("802.11 AIR SNIFFER", "#0d1117", "#bc8cff", "1;35m========================================\n     802.11 AIR SNIFFER (MONITOR MODE)  \n========================================"),
            "scan": ("SUBNET HOST SCANNER", "#0d1117", "#7ee787", "1;32m========================================\n         SUBNET HOST SCANNER            \n========================================"),
            "hijack": ("IMPERSONATION & HIJACK ENGINE", "#0d1117", "#ffa657", "1;33m========================================\n     IMPERSONATION & HIJACK ENGINE      \n========================================"),
        }

        window_default_colors = {
            "main": "\033[96m",
            "air": "\033[95m",
            "scan": "\033[92m",
            "hijack": "\033[93m"
        }

        for name in self.active_windows:
            title, bg, fg, header_tag = all_window_configs[name]
            default_color = window_default_colors.get(name, "\033[0m")
            self.write(name, f"\033[2J\033[H\033[{header_tag}{default_color}\n")

        # High-frequency background monitor for instant closure detection
        threading.Thread(target=self._monitor_window_closures, daemon=True).start()

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

    def write(self, target, text, clear=False):
        if not self.enabled or self.closing or target not in self.active_windows:
            return False
        handle = self.handles.get(target)
        if handle:
            try:
                if clear:
                    handle.write("\033[2J\033[H")
                    self.line_counts[target] = 0

                content = text + ("\n" if not text.endswith("\n") else "")
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
