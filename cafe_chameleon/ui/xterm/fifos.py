"""
cafe_chameleon.ui.xterm.fifos - FIFO pipe directory management and setup.
"""

import os

from cafe_chameleon.config import FIFO_DIR, EVENT_FILE


def get_fifo_path(name: str) -> str:
    """Returns absolute path to a named FIFO file."""
    return os.path.join(FIFO_DIR, f"{name}.fifo")


def get_input_fifo_path() -> str:
    """Returns absolute path to the main input FIFO file."""
    return os.path.join(FIFO_DIR, "main_input.fifo")


def prepare_fifo(fifo_path: str) -> None:
    """Removes stale FIFO if present and creates a fresh named pipe."""
    if os.path.exists(fifo_path):
        try:
            os.remove(fifo_path)
        except Exception:
            pass
    os.mkfifo(fifo_path)


def remove_fifos(fifos_dict: dict, input_fifo: str) -> None:
    """Cleanly removes all FIFO pipes on shutdown."""
    for f in fifos_dict.values():
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass
    if os.path.exists(input_fifo):
        try:
            os.remove(input_fifo)
        except Exception:
            pass
