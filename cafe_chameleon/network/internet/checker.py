"""
cafe_chameleon.network.internet.checker - Multi-stage captive portal detection & internet verification.
"""

import concurrent.futures
import urllib.request

from .sockets import _probe_socket
from .speed import test_internet_speed


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

    if check_speed:
        is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
        return is_fast

    return True
