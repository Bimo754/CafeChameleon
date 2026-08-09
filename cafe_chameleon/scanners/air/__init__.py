"""
cafe_chameleon.scanners.air - 802.11 Monitor Mode Over-The-Air Client Discovery package.
"""

from .mode import get_monitor_interface, set_monitor_mode, set_managed_mode, is_monitor_mode_active
from .sniffer import (
    sniff_air_clients,
    calculate_channel_signals,
    calculate_channel_densities,
    calculate_channel_dwell_times,
    calculate_scaled_air_duration,
    should_weight_channels_by_signal
)

__all__ = [
    "get_monitor_interface",
    "set_monitor_mode",
    "set_managed_mode",
    "is_monitor_mode_active",
    "sniff_air_clients",
    "calculate_channel_signals",
    "calculate_channel_densities",
    "calculate_channel_dwell_times",
    "calculate_scaled_air_duration",
    "should_weight_channels_by_signal"
]
