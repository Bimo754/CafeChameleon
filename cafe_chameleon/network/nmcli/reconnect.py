"""
cafe_chameleon.network.nmcli.reconnect - Reconnection to active BSSID with current MAC and IP address.
"""

import time
import sys

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import (
    log_plus,
    log_minus,
    log_info,
    log_step,
    log_wait,
    log_warning
)
from cafe_chameleon.network.sysfs import wait_for_carrier, get_carrier_status
from cafe_chameleon.network.mac import get_current_mac, get_permanent_mac, is_valid_mac
from cafe_chameleon.network.arp import send_gratuitous_arp
from cafe_chameleon.network.internet import has_internet, wait_for_gateway_pong
from .profiles import get_active_profile, get_ssid_for_profile
from .bssid import get_connected_bssid, scan_bssids_for_ssid


def reconnect_wifi(
    profile: str | None = None,
    interface: str | None = None,
    target_bssid: str | None = None,
    target_mac: str | None = None,
    target_ip: str | None = None,
    auto_loop: bool = False,
    timeout: float = 5.0,
    max_retries: int = 3,
    check_interval: float = 2.0
) -> bool:
    """
    Reconnects to the already connected or specified BSSID using the currently active
    MAC address and IP address.

    If auto_loop is True, enters a continuous monitoring loop that automatically
    reconnects whenever the link drops or internet access is lost, until Ctrl+C.
    """
    from cafe_chameleon.scanners.detector import auto_detect_network_params

    # 1. Interface & Profile resolution
    params = auto_detect_network_params(target_iface=interface)
    iface = interface or params.get("interface") or "wlan0"
    prof = profile or get_active_profile()

    if not prof:
        rc, out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], debug=False)
        for line in out.splitlines():
            if line.endswith(":802-11-wireless") or line.endswith(":wifi"):
                prof = line.rsplit(":", 1)[0]
                break

    if not prof:
        log_minus("Error: No active or saved Wi-Fi profile detected.")
        return False

    # 2. Target BSSID resolution
    bssid = target_bssid or get_connected_bssid(iface)
    if not bssid:
        rc, prof_bssid = _run(["nmcli", "-g", "802-11-wireless.bssid", "connection", "show", prof], debug=False)
        if prof_bssid:
            cleaned_prof_bssid = prof_bssid.replace(r"\:", ":").replace("\\", "").strip()
            if is_valid_mac(cleaned_prof_bssid):
                bssid = cleaned_prof_bssid.upper()

    if not bssid:
        ssid = get_ssid_for_profile(prof)
        if ssid:
            bssids = scan_bssids_for_ssid(ssid)
            if bssids:
                bssid = bssids[0]["bssid"].upper()

    if not bssid:
        log_minus(f"Error: Could not detect target BSSID for profile '{prof}'.")
        return False

    # 3. Target MAC address resolution
    mac = target_mac or get_current_mac(iface)
    if not mac or not is_valid_mac(mac):
        rc, prof_mac = _run(["nmcli", "-g", "802-11-wireless.cloned-mac-address", "connection", "show", prof], debug=False)
        if prof_mac:
            cleaned_prof_mac = prof_mac.replace(r"\:", ":").replace("\\", "").strip()
            if is_valid_mac(cleaned_prof_mac):
                mac = cleaned_prof_mac.lower()

    if not mac or not is_valid_mac(mac):
        mac = get_permanent_mac(iface)

    if not mac:
        log_minus(f"Error: Could not determine active MAC address on {iface}.")
        return False

    # 4. Target IP configuration resolution
    local_ip = target_ip or params.get("local_ip")
    cidr = params.get("cidr", "")
    netmask = cidr.split("/")[1] if cidr and "/" in cidr else "24"
    broadcast = params.get("broadcast", "255.255.255.255")
    gateway = params.get("gateway_ip", "")

    if auto_loop:
        return monitor_and_auto_reconnect(
            profile=prof,
            interface=iface,
            bssid=bssid,
            mac=mac,
            local_ip=local_ip,
            netmask=netmask,
            broadcast=broadcast,
            gateway=gateway,
            timeout=timeout,
            max_retries=max_retries,
            check_interval=check_interval
        )

    return perform_reconnect(
        profile=prof,
        interface=iface,
        bssid=bssid,
        mac=mac,
        local_ip=local_ip,
        netmask=netmask,
        broadcast=broadcast,
        gateway=gateway,
        timeout=timeout,
        max_retries=max_retries
    )


def perform_reconnect(
    profile: str,
    interface: str,
    bssid: str,
    mac: str,
    local_ip: str | None,
    netmask: str,
    broadcast: str,
    gateway: str,
    timeout: float = 5.0,
    max_retries: int = 3
) -> bool:
    """Performs the single reconnection routine with 5s timeout and state preservation."""
    trace(f"[FEATURE] Reconnecting to BSSID {bssid} (Profile: '{profile}', MAC: {mac}, IP: {local_ip or 'Auto'})")
    log_step(f"Reconnecting to BSSID {bssid} on profile '{profile}'...")
    log_info(f"MAC Address : {mac}")
    if local_ip:
        gw_str = f" (Gateway: {gateway})" if gateway else ""
        log_info(f"IP Address  : {local_ip}/{netmask}{gw_str}")

    # Set BSSID lock and cloned MAC on connection profile
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", bssid], debug=False)
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", mac], debug=False)

    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            log_wait(f"Retry {attempt}/{max_retries} -> Reconnecting to {bssid}...")

        log_wait(f"Bringing up connection '{profile}' (5s timeout)...")
        rc_up, out_up = _run(["nmcli", "connection", "up", profile], timeout=timeout)

        if rc_up == 124:
            log_warning("nmcli connection up timed out after 5s (process terminated). Rescanning Wi-Fi...")
            _run(["nmcli", "device", "wifi", "rescan"], debug=False)
            time.sleep(0.5)
            rc_up, out_up = _run(["nmcli", "connection", "up", profile], timeout=timeout)
        elif rc_up != 0 or "could not be found" in out_up.lower() or "activation failed" in out_up.lower():
            log_warning(f"Connection attempt failed ({'activation failed' if 'activation failed' in out_up.lower() else 'cache miss'}). Rescanning Wi-Fi...")
            _run(["nmcli", "device", "wifi", "rescan"], debug=False)
            time.sleep(0.5)
            rc_up, out_up = _run(["nmcli", "connection", "up", profile], timeout=timeout)

        carrier_ok = wait_for_carrier(interface, timeout=5.0, poll_interval=0.1)
        if not carrier_ok:
            _run(["ip", "link", "set", "dev", interface, "up"], debug=False)
            carrier_ok = wait_for_carrier(interface, timeout=3.0, poll_interval=0.1)

        # Restore static IP and routes if an active IP was captured
        if local_ip:
            _run(["ip", "addr", "flush", "dev", interface, "scope", "global"], debug=False)
            _run(["ip", "-4", "addr", "add", f"{local_ip}/{netmask}", "broadcast", broadcast, "dev", interface], debug=False)
            if gateway:
                _run(["ip", "route", "flush", "dev", interface], debug=False)
                _run(["ip", "route", "replace", "default", "via", gateway, "dev", interface, "onlink"], debug=False)
                send_gratuitous_arp(interface, local_ip, gateway)
                wait_for_gateway_pong(gateway_ip=gateway, interface=interface, timeout=2.0)

        # Verify reconnection
        connected_bssid = get_connected_bssid(interface)
        if connected_bssid and connected_bssid.upper() == bssid.upper():
            trace(f"[FEATURE] Successfully reconnected to BSSID {bssid} with MAC {mac} and IP {local_ip or 'Dynamic'}")
            log_plus(f"Successfully reconnected to BSSID {bssid}!")
            return True
        elif rc_up == 0 and carrier_ok:
            trace(f"[FEATURE] Reconnected profile '{profile}' to BSSID {bssid} (Carrier confirmed active)")
            log_plus(f"Reconnected profile '{profile}' to BSSID {bssid}.")
            return True
        else:
            trace(f"[FEATURE] Reconnect attempt {attempt}/{max_retries} unverified (Connected BSSID: {connected_bssid or 'None'})")
            log_warning(f"Reconnect attempt {attempt}/{max_retries} unverified -> Current: {connected_bssid or 'None'}")
            time.sleep(1.0)

    trace(f"[FEATURE] Failed to reconnect to BSSID {bssid} after {max_retries} attempts")
    log_minus(f"Reconnection failed after {max_retries} attempts.")
    return False


def monitor_and_auto_reconnect(
    profile: str,
    interface: str,
    bssid: str,
    mac: str,
    local_ip: str | None,
    netmask: str,
    broadcast: str,
    gateway: str,
    timeout: float = 5.0,
    max_retries: int = 3,
    check_interval: float = 2.0
) -> bool:
    """
    Continuous auto-reconnect monitoring loop.
    Monitors interface carrier, BSSID association, and internet reachability.
    Triggers reconnection whenever connection drops until interrupted with Ctrl+C.
    """
    trace(f"[FEATURE] Starting auto-reconnect monitor on {interface} for BSSID {bssid}")
    log_step(f"Starting auto-reconnect monitor for BSSID {bssid}...")
    log_info("Press Ctrl+C to stop auto-reconnect.\n")

    # Initial reconnect check
    connected = get_connected_bssid(interface)
    carrier = get_carrier_status(interface)
    if not carrier or not connected or (connected.upper() != bssid.upper()):
        log_wait("Establishing initial connection...")
        perform_reconnect(
            profile=profile,
            interface=interface,
            bssid=bssid,
            mac=mac,
            local_ip=local_ip,
            netmask=netmask,
            broadcast=broadcast,
            gateway=gateway,
            timeout=timeout,
            max_retries=max_retries
        )

    try:
        while True:
            time.sleep(check_interval)
            carrier = get_carrier_status(interface)
            current_bssid = get_connected_bssid(interface)
            internet_ok = has_internet(timeout=1.0, check_speed=False, gateway_ip=gateway, interface=interface, ping_gateway=bool(gateway)) if carrier else False

            needs_reconnect = False
            if not carrier:
                log_warning("Carrier link lost on interface.")
                needs_reconnect = True
            elif not current_bssid or (current_bssid.upper() != bssid.upper()):
                log_warning(f"BSSID disconnected or changed (Current: {current_bssid or 'None'}).")
                needs_reconnect = True
            elif not internet_ok:
                log_warning("Internet connectivity check failed.")
                needs_reconnect = True

            if needs_reconnect:
                log_wait("Auto-reconnecting to network...")
                perform_reconnect(
                    profile=profile,
                    interface=interface,
                    bssid=bssid,
                    mac=mac,
                    local_ip=local_ip,
                    netmask=netmask,
                    broadcast=broadcast,
                    gateway=gateway,
                    timeout=timeout,
                    max_retries=max_retries
                )
    except KeyboardInterrupt:
        log_info("\nAuto-reconnect monitoring stopped by user (Ctrl+C).")
        return True
