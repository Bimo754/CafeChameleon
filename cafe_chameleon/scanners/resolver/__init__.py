"""
cafe_chameleon.scanners.resolver - Multi-stage MAC-to-IP resolution engine package.
"""

from .resolver import resolve_mac_to_ip
from .kernel_cache import is_valid_ipv4

__all__ = ["resolve_mac_to_ip", "is_valid_ipv4"]
