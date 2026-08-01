"""
cafe_chameleon.network.internet - Internet access verification & speed testing package.
"""

from .checker import has_internet
from .speed import test_internet_speed

__all__ = ["has_internet", "test_internet_speed"]
