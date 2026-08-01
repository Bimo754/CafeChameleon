"""
cafe_chameleon.network.hijack - Network host impersonation and restoration package.
"""

from .impersonate import hijack
from .restore import restore

__all__ = ["hijack", "restore"]
