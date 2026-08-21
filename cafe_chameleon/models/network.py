"""
cafe_chameleon.models.network - Strongly-typed dataclasses for network parameters, BSSIDs, and hosts.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class _DictCompatMixin:
    """Lightweight compatibility mixin providing dict-like access for dataclasses."""

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class NetworkParams(_DictCompatMixin):
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


@dataclass(slots=True)
class BSSIDTarget(_DictCompatMixin):
    """Strongly-typed container for Wi-Fi BSSID scan target."""
    bssid: str
    ssid: str = ""
    signal: str = "0"
    chan: str = "1"
    security: str = ""
    active: bool = False
    bars: str = ""
    mode: str = ""
    rate: str = ""

    @property
    def is_open(self) -> bool:
        sec = self.security.strip().lower() if self.security else ""
        return sec in ("", "--", "none", "(none)", "open")

    @property
    def is_encrypted(self) -> bool:
        return not self.is_open


@dataclass(slots=True)
class DiscoveredHost(_DictCompatMixin):
    """Strongly-typed container for active host target on subnet."""
    ip: str
    mac: str

