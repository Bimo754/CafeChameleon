"""
cafe_chameleon.ui.xterm - Multi-Window Xterm Display Manager package.
"""

from .manager import XtermManager
from .screen import get_screen_resolution

__all__ = ["XtermManager", "get_screen_resolution"]
