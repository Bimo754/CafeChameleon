"""
cafe_chameleon.models.network - Strongly-typed dataclasses for network parameters, BSSIDs, and hosts.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetworkParams:
    """Strongly-typed container for local network parameters."""
    interface: Optional[str] = None
    local_ip: Optional[str] = None
    local_mac: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    broadcast: Optional[str] = None
    cidr: Optional[str] = None
    ssid: Optional[str] = None
    internet_access: bool = False

    def get(self, key: str, default=None):
        """Dict-like get compatibility helper."""
        return getattr(self, key, default)

    def __getitem__(self, item: str):
        """Dict-like subscripting compatibility helper."""
        return getattr(self, item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "local_ip": self.local_ip,
            "local_mac": self.local_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "broadcast": self.broadcast,
            "cidr": self.cidr,
            "ssid": self.ssid,
            "internet_access": self.internet_access
        }


@dataclass
class BSSIDTarget:
    """Strongly-typed container for Wi-Fi BSSID scan target."""
    bssid: str
    ssid: str = ""
    signal: str = "0"
    chan: str = "1"
    active: bool = False

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def __getitem__(self, item: str):
        return getattr(self, item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "signal": self.signal,
            "chan": self.chan,
            "active": self.active
        }


@dataclass
class DiscoveredHost:
    """Strongly-typed container for active host target on subnet."""
    ip: str
    mac: str

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def __getitem__(self, item: str):
        return getattr(self, item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def to_dict(self) -> dict:
        return {"ip": self.ip, "mac": self.mac}
