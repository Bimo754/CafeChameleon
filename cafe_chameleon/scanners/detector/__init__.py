"""
cafe_chameleon.scanners.detector - Network interface and parameter detection package.
"""

from .validator import (
    is_valid_managed_iface,
    validate_interface,
    find_suitable_interface,
    check_interface_warning
)
from .auto_detect import (
    auto_detect_network_params,
    get_interface_details
)

__all__ = [
    "is_valid_managed_iface",
    "validate_interface",
    "find_suitable_interface",
    "check_interface_warning",
    "auto_detect_network_params",
    "get_interface_details"
]
