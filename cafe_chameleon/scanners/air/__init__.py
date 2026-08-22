"""
cafe_chameleon.scanners.air - 802.11 Monitor Mode Over-The-Air Client Discovery package.
"""

from .mode import get_monitor_interface, set_monitor_mode, set_managed_mode, is_monitor_mode_active, get_base_interface
from .sniffer import (
    sniff_air_clients,
    AirClientsMap,
    calculate_channel_signals,
    calculate_channel_densities,
    calculate_channel_dwell_times,
    calculate_scaled_air_duration,
    should_weight_channels_by_signal
)
from .stimulator import (
    ClientStimulator,
    build_probe_req_packet,
    build_null_data_packet,
    build_wakeup_deauth_packet
)

__all__ = [
    "get_monitor_interface",
    "set_monitor_mode",
    "set_managed_mode",
    "is_monitor_mode_active",
    "get_base_interface",
    "sniff_air_clients",
    "AirClientsMap",
    "calculate_channel_signals",
    "calculate_channel_densities",
    "calculate_channel_dwell_times",
    "calculate_scaled_air_duration",
    "should_weight_channels_by_signal",
    "ClientStimulator",
    "build_probe_req_packet",
    "build_null_data_packet",
    "build_wakeup_deauth_packet"
]
