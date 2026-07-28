"""
cafe_chameleon.network.internet - Multi-stage captive portal detection & HTTP speed verification testing.
"""

import concurrent.futures
import socket
import time
import urllib.request

from cafe_chameleon.ui.console import log_warning


def _probe_socket(endpoint: tuple[str, int], timeout: float) -> bool:
    try:
        with socket.create_connection(endpoint, timeout=timeout):
            return True
    except OSError:
        return False


def test_internet_speed(timeout: float = 1.2, min_speed_kbps: float = 5.0) -> tuple[bool, float]:
    """
    Tests actual download speed by fetching static assets from fast global CDNs.
    Measures throughput on body chunks to ensure high accuracy without long waits.
    Enforces a strict overall cumulative timeout budget across all endpoint probes.
    Returns tuple: (is_fast_enough: bool, measured_kbps: float)
    """
    speed_targets = [
        "http://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "http://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
        "http://www.gstatic.com/webp/gallery/1.sm.webp",
        "http://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    global_start = time.time()
    for url in speed_targets:
        if time.time() - global_start >= timeout:
            break
        try:
            req = urllib.request.Request(url, headers=headers)
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
        except Exception:
            continue

    return False, 0.0


def has_internet(timeout: float = 0.8, strict: bool = True, check_speed: bool = True, min_speed_kbps: float = 5.0) -> bool:
    """
    Intense multi-stage internet verification check to guard against fake internet,
    captive portal walled gardens, and severely throttled connections.
    
    Checks:
    1. Low-level socket connection probe across multiple independent public endpoints in parallel.
    2. HTTP 204 Connectivity Check (http://connectivitycheck.gstatic.com/generate_204).
    3. NCSI Content Verification (http://www.msftncsi.com/ncsi.txt -> expects 'Microsoft NCSI').
    4. HTTP/HTTPS probe fallbacks (ping.archlinux.org).
    5. Fast speed verification check.
    """
    # Stage 1: Parallel socket connection probe across public endpoints
    public_endpoints = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("9.9.9.9", 53),
        ("1.1.1.1", 443)
    ]
    
    probe_timeout = min(timeout, 0.35)
    socket_passed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(public_endpoints)) as executor:
        futures = [executor.submit(_probe_socket, ep, probe_timeout) for ep in public_endpoints]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                socket_passed = True
                break

    if not socket_passed:
        return False

    if not strict:
        if check_speed:
            is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
            return is_fast
        return True

    # Stage 2: Captive portal interception & real internet payload check
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    portal_passed = False

    # Test 2A: Google 204 No Content check
    try:
        req = urllib.request.Request("http://connectivitycheck.gstatic.com/generate_204", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 204:
                portal_passed = True
    except Exception:
        pass

    # Test 2B: Microsoft NCSI Verification Check
    if not portal_passed:
        try:
            req = urllib.request.Request("http://www.msftncsi.com/ncsi.txt", headers={"User-Agent": "Microsoft NCSI"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(32).decode("utf-8", errors="ignore").strip()
                    if "Microsoft NCSI" in body:
                        portal_passed = True
        except Exception:
            pass

    # Test 2C: Arch / Linux ping probe
    if not portal_passed:
        try:
            req = urllib.request.Request("http://ping.archlinux.org/", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read(64).decode("utf-8", errors="ignore").strip()
                    if "Arch Linux" in body:
                        portal_passed = True
        except Exception:
            pass

    if not portal_passed:
        return False

    # Stage 3: Mandatory speed test to guard against throttled connection
    if check_speed:
        is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
        return is_fast

    return True
