"""
cafe_chameleon.network.internet.sockets - Low-level socket connection probe.
"""

import socket


def _probe_socket(endpoint: tuple[str, int], timeout: float) -> bool:
    """Low-level socket connection probe across a single (ip, port) tuple."""
    try:
        with socket.create_connection(endpoint, timeout=timeout):
            return True
    except OSError:
        return False
