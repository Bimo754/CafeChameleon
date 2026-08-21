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
            geturl_fn = getattr(resp, "geturl", None)
            raw_url = geturl_fn() if callable(geturl_fn) else url
            final_url = raw_url if isinstance(raw_url, str) else url

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
                    raw_body = resp.read(256)
                    body = ""
                    if isinstance(raw_body, (bytes, bytearray)):
                        body = raw_body.decode("utf-8", errors="ignore").strip()
                    elif isinstance(raw_body, str):
                        body = raw_body.strip()

                    if token and token in body:
                        return True, False, provider
                    else:
                        # Body does not contain token -> intercepted captive portal HTML
                        return False, True, final_url
                elif is_redirected or status in (301, 302, 303, 307):
                    return False, True, final_url

    except Exception as e:
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
    if ping_gateway:
        gw_ok = wait_for_gateway_pong(gateway_ip=gateway_ip, interface=interface, timeout=gateway_timeout)
        res.gateway_reachable = gw_ok
        if not gw_ok and strict:
            res.state = ConnectivityState.NO_GATEWAY
            res.latency_ms = (time.time() - start_t) * 1000
            return res
    else:
        res.gateway_reachable = True

    # 2. Fast-track non-strict mode check via raw sockets
    if not strict:
        socket_ok = False
        exec_sock = concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_DNS_ENDPOINTS))
        try:
            sock_futures = [exec_sock.submit(_probe_socket, ep, min(0.6, timeout)) for ep in PUBLIC_DNS_ENDPOINTS]
            for future in concurrent.futures.as_completed(sock_futures, timeout=min(0.8, timeout)):
                if future.result():
                    socket_ok = True
                    break
        except Exception:
            pass
        finally:
            exec_sock.shutdown(wait=False, cancel_futures=True)

        if socket_ok:
            res.is_authenticated = True
            res.state = ConnectivityState.FULL_INTERNET
            if check_speed:
                is_fast, speed_val = test_internet_speed(timeout=1.5, min_speed_kbps=min_speed_kbps)
                res.speed_kbps = speed_val
                if not is_fast:
                    res.state = ConnectivityState.LIMITED
                    res.is_authenticated = False
            return res

    # 3. Concurrent Multi-Provider HTTP 204 & Captive Portal Probing
    http_timeout = min(1.0, max(0.6, timeout))
    portal_passed = False
    portal_detected = False
    verified_provider = None
    portal_url = None

    exec_http = concurrent.futures.ThreadPoolExecutor(max_workers=len(CAPTIVE_PORTAL_ENDPOINTS))
    try:
        future_to_ep = {exec_http.submit(_probe_http_endpoint, ep, http_timeout): ep for ep in CAPTIVE_PORTAL_ENDPOINTS}
        for future in concurrent.futures.as_completed(future_to_ep, timeout=http_timeout + 0.3):
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
    except Exception:
        pass
    finally:
        exec_http.shutdown(wait=False, cancel_futures=True)

    res.is_authenticated = portal_passed
    res.portal_detected = portal_detected
    res.portal_url = portal_url
    res.http_verified_endpoint = verified_provider

    # 4. Supplementary Low-Level Socket and DNS Probing
    if not portal_passed:
        socket_ok = False
        exec_supp = concurrent.futures.ThreadPoolExecutor(max_workers=len(PUBLIC_DNS_ENDPOINTS))
        try:
            sock_futures = [exec_supp.submit(_probe_socket, ep, min(0.6, timeout)) for ep in PUBLIC_DNS_ENDPOINTS]
            for future in concurrent.futures.as_completed(sock_futures, timeout=min(0.8, timeout)):
                if future.result():
                    socket_ok = True
                    break
        except Exception:
            pass
        finally:
            exec_supp.shutdown(wait=False, cancel_futures=True)

        if socket_ok or (res.nmcli_state == "full"):
            if not portal_detected and not strict:
                portal_passed = True
                res.is_authenticated = True

        if not portal_passed:
            dns_ok = False
            exec_dns = concurrent.futures.ThreadPoolExecutor(max_workers=len(DNS_TEST_DOMAINS))
            try:
                dns_futures = [exec_dns.submit(_probe_dns_resolution, dom, min(0.8, timeout)) for dom in DNS_TEST_DOMAINS]
                for future in concurrent.futures.as_completed(dns_futures, timeout=min(1.0, timeout)):
                    if future.result():
                        dns_ok = True
                        break
            except Exception:
                pass
            finally:
                exec_dns.shutdown(wait=False, cancel_futures=True)

            res.dns_working = dns_ok
            if dns_ok and not portal_detected and not strict:
                portal_passed = True
                res.is_authenticated = True

    # 5. Determine State
    if portal_passed:
        res.state = ConnectivityState.FULL_INTERNET
        res.is_authenticated = True
    elif not res.gateway_reachable:
        res.state = ConnectivityState.NO_GATEWAY
    elif portal_detected or (res.nmcli_state == "portal"):
        res.state = ConnectivityState.CAPTIVE_PORTAL
    elif res.nmcli_state == "full":
        res.state = ConnectivityState.FULL_INTERNET
        res.is_authenticated = True
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
    """
    res = verify_internet_connectivity(
        timeout=timeout,
        strict=strict,
        check_speed=check_speed,
        min_speed_kbps=min_speed_kbps,
        gateway_ip=gateway_ip,
        interface=interface,
        ping_gateway=ping_gateway,
        gateway_timeout=gateway_timeout
    )
    return res.is_authenticated
