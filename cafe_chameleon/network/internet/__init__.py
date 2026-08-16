"""
cafe_chameleon.network.internet - Internet access verification & speed testing package.
"""

from .checker import has_internet
from .speed import test_internet_speed
from .gateway import wait_for_gateway_pong, ping_gateway_once, get_default_gateway_ip

__all__ = [
    "has_internet",
    "test_internet_speed",
    "wait_for_gateway_pong",
    "ping_gateway_once",
    "get_default_gateway_ip"
]
