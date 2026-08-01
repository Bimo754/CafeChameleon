"""
cafe_chameleon.ui.xterm.screen - Screen resolution detection utilities.
"""

import re
import subprocess


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
