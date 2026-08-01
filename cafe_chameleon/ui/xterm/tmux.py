"""
cafe_chameleon.ui.xterm.tmux - Tmux session spawning and split-window layout controller.
"""

import os
import subprocess
from typing import Set

SESSION_NAME = "captive_ui"
EVENT_FILE = "/tmp/captive_xterm_fifos/last_ctrl_c.event"


def setup_tmux_session(active_windows: Set[str], fifos: dict, input_fifo: str) -> None:
    """Spawns tmux session and splits windows tiled based on active_windows set."""
    subprocess.run(["tmux", "kill-session", "-t", SESSION_NAME], capture_output=True)

    ordered_names = [n for n in ["main", "air", "scan", "hijack"] if n in active_windows]
    if not ordered_names:
        return

    first = ordered_names[0]
    main_pid = os.getpid()

    if first == "main":
        cmd_first = (
            f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {first} > {EVENT_FILE}; kill -INT {main_pid} 2>/dev/null\" INT; "
            f"(cat {fifos[first]} &); while true; do read -r line; echo \"$line\" > {input_fifo}; done'"
        )
    else:
        cmd_first = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {first} > {EVENT_FILE}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {fifos[first]}; sleep 0.1; done'"

    subprocess.run(["tmux", "new-session", "-d", "-s", SESSION_NAME, cmd_first], check=True)

    for name in ordered_names[1:]:
        if name == "main":
            cmd_next = (
                f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {name} > {EVENT_FILE}; kill -INT {main_pid} 2>/dev/null\" INT; "
                f"(cat {fifos[name]} &); while true; do read -r line; echo \"$line\" > {input_fifo}; done'"
            )
        else:
            cmd_next = f"sh -c 'stty -echoctl 2>/dev/null; trap \"echo {name} > {EVENT_FILE}; kill -INT {main_pid} 2>/dev/null\" INT; while true; do cat {fifos[name]}; sleep 0.1; done'"
        subprocess.run(["tmux", "split-window", "-t", SESSION_NAME, cmd_next], check=True)

    subprocess.run(["tmux", "select-layout", "-t", SESSION_NAME, "tiled"], check=True)
    subprocess.run(["tmux", "select-pane", "-t", f"{SESSION_NAME}:0.0"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-g", "default-terminal", "xterm-256color"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-ga", "terminal-overrides", ",xterm-256color:Tc"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-g", "mouse", "on"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-g", "history-limit", "50000"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-t", SESSION_NAME, "status", "off"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-t", SESSION_NAME, "pane-border-style", "fg=#30363d"], capture_output=True)
    subprocess.run(["tmux", "set-option", "-t", SESSION_NAME, "pane-active-border-style", "fg=#58a6ff"], capture_output=True)


def kill_tmux_session() -> None:
    """Kills the active tmux session."""
    subprocess.run(["tmux", "kill-session", "-t", SESSION_NAME], capture_output=True)
