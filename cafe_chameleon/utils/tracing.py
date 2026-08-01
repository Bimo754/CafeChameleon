"""
cafe_chameleon.utils.tracing - Silent trace logger for operation & command execution history.
"""

import os
import time
import traceback
from typing import List

from cafe_chameleon.utils.state import get_debug_tracing

TRACE_FILE = "cafe_chameleon_trace.log"
_TRACE_BUFFER: List[str] = []


def init_trace() -> None:
    """Initializes or resets the trace file for a new session."""
    global _TRACE_BUFFER
    _TRACE_BUFFER = []
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(TRACE_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== CafeChameleon Trace Session Started at {timestamp} ===\n\n")
    except Exception:
        pass


def trace(msg: str) -> None:
    """Silently records a trace entry if tracing debug mode is active."""
    if not get_debug_tracing():
        return

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {msg}"
    _TRACE_BUFFER.append(entry)

    try:
        with open(TRACE_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass


def get_recent_trace(count: int = 10) -> List[str]:
    """Returns the last `count` trace entries."""
    return _TRACE_BUFFER[-count:]


def get_trace_filepath() -> str:
    """Returns the absolute path to the trace log file."""
    return os.path.abspath(TRACE_FILE)


def log_exception_to_trace(exc: Exception) -> None:
    """Logs an exception traceback to the trace file silently."""
    if not get_debug_tracing():
        return
    tb_str = traceback.format_exc()
    trace(f"[ERROR] Unhandled Exception: {exc}\n{tb_str}")
