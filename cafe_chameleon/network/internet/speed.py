"""
cafe_chameleon.network.internet.speed - HTTP CDN speed verification testing.
"""

import time
import urllib.request
import urllib.error

from cafe_chameleon.config import SPEED_TEST_TARGETS, HTTP_HEADERS, DEFAULT_SPEED_MIN_KBPS
from cafe_chameleon.ui.console import log_warning


def test_internet_speed(timeout: float = 1.2, min_speed_kbps: float = DEFAULT_SPEED_MIN_KBPS) -> tuple[bool, float]:
    """
    Tests actual download speed by fetching static assets from fast global CDNs.
    Measures throughput on body chunks to ensure high accuracy without long waits.
    Enforces a strict overall cumulative timeout budget across all endpoint probes.
    Returns tuple: (is_fast_enough: bool, measured_kbps: float)
    """
    global_start = time.time()
    for url in SPEED_TEST_TARGETS:
        if time.time() - global_start >= timeout:
            break
        try:
            req = urllib.request.Request(url, headers=HTTP_HEADERS)
            t_start = time.time()
            remaining = timeout - (t_start - global_start)
            if remaining <= 0.1:
                break
            per_req_timeout = min(0.5, remaining)

            with urllib.request.urlopen(req, timeout=per_req_timeout) as resp:
                bytes_received = 0
                first_chunk_time = None

                while time.time() - global_start < timeout:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    if first_chunk_time is None:
                        first_chunk_time = time.time()
                    bytes_received += len(chunk)

                t_end = time.time()
                duration = max(t_end - (first_chunk_time or t_start), 0.001)

                if bytes_received > 0:
                    speed_kbps = (bytes_received / 1024.0) / duration
                    if speed_kbps >= min_speed_kbps:
                        return True, speed_kbps
                    else:
                        log_warning(f"Throttled connection detected: {speed_kbps:.2f} KB/s < {min_speed_kbps:.1f} KB/s threshold.")
                        return False, speed_kbps
        except (urllib.error.URLError, TimeoutError, OSError):
            continue

    return False, 0.0
