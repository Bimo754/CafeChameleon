"""
cafe_chameleon.network.internet.checker - Guaranteed multi-stage captive portal detection & internet verification.
"""

import enum
import time
import dataclasses
import concurrent.futures
import urllib.request
import urllib.error

from cafe_chameleon.config import (
    PUBLIC_DNS_ENDPOINTS,
    DNS_TEST_DOMAINS,
    CAPTIVE_PORTAL_ENDPOINTS,
    HTTP_HEADERS,
    DEFAULT_SPEED_MIN_KBPS
)
from cafe_chameleon.utils.tracing import trace
from .sockets import _probe_socket, _probe_dns_resolution
from .speed import test_internet_speed
from .gateway import wait_for_gateway_pong


class ConnectivityState(str, enum.Enum):
    FULL_INTERNET = "full"
    CAPTIVE_PORTAL = "portal"
    LIMITED = "limited"
    NO_GATEWAY = "no_gateway"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class ConnectivityResult:
    state: ConnectivityState
    is_authenticated: bool = False
    gateway_reachable: bool = False
    dns_working: bool = False
    portal_detected: bool = False
    portal_url: str | None = None
    http_verified_endpoint: str | None = None
    speed_kbps: float = 0.0
    nmcli_state: str | None = None
    latency_ms: float = 0.0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom handler to intercept HTTP 3xx redirects without automatically following them."""
    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def _probe_http_endpoint(endpoint: dict, timeout: float = 1.5) -> tuple[bool, bool, str | None]:
    """
    Probes a single captive portal / internet verification endpoint.
    Returns: (is_authenticated: bool, is_captive_portal: bool, redirect_or_provider_url: str | None)
    """
    url = str(endpoint.get("url", ""))
    target_type = endpoint.get("type", "status_204")
    token = str(endpoint.get("token", ""))
    provider = str(endpoint.get("provider", url))

    if not url:
        return False, False, None

    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", getattr(resp, "code", 200))
            final_url = resp.geturl() if hasattr(resp, "geturl") else url

            # Detect HTTP redirect to captive portal login page
            is_redirected = False
            if final_url and url.split("?")[0].rstrip("/") not in final_url:
                is_redirected = True

            if target_type == "status_204":
                if status == 204 and not is_redirected:
                    return True, False, provider
                elif status in (200, 301, 302, 303, 307) or is_redirected:
                    return False, True, final_url

            elif target_type == "body_match":
                if status == 200 and not is_redirected:
                    body = resp.read(256).decode("utf-8", errors="ignore").strip()
                    if token and token in body:
                        return True, False, provider
                    else:
                        # Body does not contain token -> likely intercepted captive portal HTML
                        return False, True, final_url
                elif is_redirected or status in (301, 302, 303, 307):
                    return False, True, final_url

    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        trace(f"[FEATURE] Endpoint probe {provider} failed: {e}")

    return False, False, None


def verify_internet_connectivity(
    timeout: float = 1.5,
    strict: bool = True,
    check_speed: bool = False,
    min_speed_kbps: float = DEFAULT_SPEED_MIN_KBPS,
    gateway_ip: str | None = None,
    interface: str | None = None,
    ping_gateway: bool = False,
    gateway_timeout: float = 2.0
) -> ConnectivityResult:
    """
    Comprehensive multi-stage internet reachability and captive portal verification.
    Guarantees whether the client is authenticated with full internet access, trapped behind
    a captive portal, or disconnected.
    """
    start_t = time.time()
    res = ConnectivityResult(state=ConnectivityState.UNKNOWN)

    # 1. Gateway reachability check
    if ping_gateway or gateway_ip:
        gw_ok = wait_for_gateway_pong(gateway_ip=gateway_ip, interface=interface, timeout=gateway_timeout)
        res.gateway_reachable = gw_ok
        if not gw_ok:
            res.state = ConnectivityState.NO_GATEWAY
            res.latency_ms = (time.time() - start_t) * 1000
            return res
    else:
        res.gateway_reachable = True

    # 2. Native NetworkManager connectivity check (optional fast signal)
    try:
        from cafe_chameleon.network.nmcli.connectivity import get_nmcli_connectivity
        nm_state = get_nmcli_connectivity(force_check=False, timeout=0.5)
        res.nmcli_state = nm_state
    except Exception:
        pass

    # 3. Concurrent Multi-Provider HTTP 204 & Captive Portal Probing
    http_timeout = max(0.8, timeout)
    portal_passed = False
    portal_detected = False
    verified_provider = None
    portal_url = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(CAPTIVE_PORTAL_ENDPOINTS)) as executor:
        future_to_ep = {executor.submit(_probe_http_endpoint, ep, http_timeout): ep for ep in CAPTIVE_PORTAL_ENDPOINTS}
        for future in concurrent.futures.as_completed(future_to_ep):
            try:
                auth_ok, is_portal, prov_or_url = future.result()
                if auth_ok:
                    portal_passed = True
                    verified_provider = prov_or_url
                    res.dns_working = True
                    break
                elif is_portal:
                    portal_detected = True
                    if not portal_url and prov_or_url:
                        portal_url = prov_or_url
            except Exception:
                pass

    res.is_authenticated = portal_passed
    res.portal_detected = portal_detected
    res.portal_url = portal_url
    res.http_verified_endpoint = verified_provider

    # 4. Supplementary DNS and Low-Level Socket Probing
    if not portal_passed:
        # Check standard DNS resolution
        dns_ok = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(DNS_TEST_DOMAINS)) as executor:
            dns_futures = [executor.submit(_probe_dns_resolution, dom, min(1.0, timeout)) for dom in DNS_TEST_DOMAINS]
            for future in concurrent.futures.as_completed(dns_futures):
                if future.result():
                    dns_ok = True
                    break
        res.dns_working = dns_ok

        # Check raw socket connectivity
        socket_ok = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_DNS_ENDPOINTS)) as executor:
            sock_futures = [executor.submit(_probe_socket, ep, min(1.0, timeout)) for ep in PUBLIC_DNS_ENDPOINTS]
            for future in concurrent.futures.as_completed(sock_futures):
                if future.result():
                    socket_ok = True
                    break

        if dns_ok or socket_ok or (res.nmcli_state == "full"):
            if not portal_detected:
                # If non-strict, we can accept DNS/socket pass
                if not strict:
                    portal_passed = True
                    res.is_authenticated = True

    # 5. Determine State
    if portal_passed or (res.nmcli_state == "full" and not portal_detected):
        res.state = ConnectivityState.FULL_INTERNET
        res.is_authenticated = True
    elif portal_detected or (res.nmcli_state == "portal"):
        res.state = ConnectivityState.CAPTIVE_PORTAL
    elif res.dns_working:
        res.state = ConnectivityState.LIMITED
    else:
        res.state = ConnectivityState.LIMITED

    # 6. Optional Speed Verification
    if check_speed and res.is_authenticated:
        is_fast, speed_val = test_internet_speed(timeout=1.5, min_speed_kbps=min_speed_kbps)
        res.speed_kbps = speed_val
        if not is_fast:
            res.state = ConnectivityState.LIMITED
            res.is_authenticated = False

    res.latency_ms = (time.time() - start_t) * 1000
    trace(f"[FEATURE] Internet connectivity verification complete: State={res.state.value}, Auth={res.is_authenticated}, Provider={res.http_verified_endpoint}, Latency={res.latency_ms:.1f}ms")
    return res


def has_internet(
    timeout: float = 1.2,
    strict: bool = True,
    check_speed: bool = True,
    min_speed_kbps: float = DEFAULT_SPEED_MIN_KBPS,
    gateway_ip: str | None = None,
    interface: str | None = None,
    ping_gateway: bool = False,
    gateway_timeout: float = 2.0
) -> bool:
    """
    Guaranteed multi-stage internet verification check to guard against fake internet,
    captive portal walled gardens, and severely throttled connections.
    Optionally pings gateway first and triggers internet checks the millisecond a pong is received.
    """
    if ping_gateway or gateway_ip:
        gw_ok = wait_for_gateway_pong(gateway_ip=gateway_ip, interface=interface, timeout=gateway_timeout)
        # If gateway pong succeeds, we proceed to fast socket / HTTP check.
        # If gateway pong fails, we do not short-circuit to False immediately;
        # we allow socket & HTTP probes to run in case gateway drops ICMP packets.
    else:
        gw_ok = True

    # Low-level socket check for fast fallback compatibility
    probe_timeout = min(timeout, 0.8)
    socket_passed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_DNS_ENDPOINTS)) as executor:
        futures = [executor.submit(_probe_socket, ep, probe_timeout) for ep in PUBLIC_DNS_ENDPOINTS]
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                socket_passed = True
                break

    # If non-strict mode and sockets pass, verify speed if requested
    if not strict:
        if socket_passed:
            if check_speed:
                is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
                return is_fast
            return True

    # Multi-provider captive portal & HTTP 204 session verification
    portal_passed = False

    # Test 2A: Google 204 No Content check
    try:
        req = urllib.request.Request("http://connectivitycheck.gstatic.com/generate_204", headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", getattr(resp, "code", 0)) == 204:
                portal_passed = True
    except (urllib.error.URLError, TimeoutError, OSError):
        pass

    # Test 2B: Cloudflare 204
    if not portal_passed:
        try:
            req = urllib.request.Request("http://cp.cloudflare.com/generate_204", headers=HTTP_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", 0)) == 204:
                    portal_passed = True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    # Test 2C: Microsoft NCSI Verification Check
    if not portal_passed:
        try:
            req = urllib.request.Request("http://www.msftncsi.com/ncsi.txt", headers={"User-Agent": "Microsoft NCSI"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", 0)) == 200:
                    body = resp.read(32).decode("utf-8", errors="ignore").strip()
                    if "Microsoft NCSI" in body:
                        portal_passed = True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    # Test 2D: Apple Hotspot Detect Check
    if not portal_passed:
        try:
            req = urllib.request.Request("http://captive.apple.com/hotspot-detect.html", headers=HTTP_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", 0)) == 200:
                    body = resp.read(64).decode("utf-8", errors="ignore").strip()
                    if "Success" in body:
                        portal_passed = True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    # Test 2E: Ubuntu / Arch / Linux ping probe
    if not portal_passed:
        try:
            req = urllib.request.Request("http://connectivity-check.ubuntu.com/", headers=HTTP_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", getattr(resp, "code", 0)) == 200:
                    body = resp.read(64).decode("utf-8", errors="ignore").strip()
                    if "NetworkManager" in body or "online" in body:
                        portal_passed = True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    # Fallback to general verify_internet_connectivity if needed
    if not portal_passed and socket_passed:
        # Check if any other endpoint passed
        verify_res = verify_internet_connectivity(
            timeout=timeout,
            strict=strict,
            check_speed=False,
            gateway_ip=None,
            interface=interface,
            ping_gateway=False
        )
        if verify_res.is_authenticated:
            portal_passed = True

    if not portal_passed:
        return False

    if check_speed:
        is_fast, _ = test_internet_speed(timeout=1.2, min_speed_kbps=min_speed_kbps)
        return is_fast

    return True
