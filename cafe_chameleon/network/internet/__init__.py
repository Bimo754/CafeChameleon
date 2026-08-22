"""
cafe_chameleon.network.internet - Internet access verification & speed testing package.
"""

from .checker import has_internet, verify_internet_connectivity, ConnectivityResult, ConnectivityState
from .speed import test_internet_speed
from .gateway import (
    wait_for_gateway_pong,
    wait_for_session_establishment,
    ping_gateway_once,
    arp_ping_gateway_once,
    check_gateway_neighbor_table,
    get_default_gateway_ip
)

__all__ = [
    "has_internet",
    "verify_internet_connectivity",
    "ConnectivityResult",
    "ConnectivityState",
    "test_internet_speed",
    "wait_for_gateway_pong",
    "wait_for_session_establishment",
    "ping_gateway_once",
    "arp_ping_gateway_once",
    "check_gateway_neighbor_table",
    "get_default_gateway_ip"
]
