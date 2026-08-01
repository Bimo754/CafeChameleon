"""
cafe_chameleon.network.nmcli.bssid - BSSID scanning, BSSID locking, and active BSSID retrieval.
"""

import re
import time

from cafe_chameleon.config import DEFAULT_BSSID
from cafe_chameleon.models import BSSIDTarget
from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_plus, log_warning, log_minus, log_step, log_wait
from .profiles import get_active_profile, get_ssid_for_profile

DIGIT_REGEX = re.compile(r"[^\d]")
CONNECTED_MAC_REGEX = re.compile(r"Connected to\s+([0-9a-fa-f:]+)", re.IGNORECASE)


def scan_bssids_for_ssid(target_ssid: str) -> list[BSSIDTarget]:
    """Scans for available BSSIDs matching the target SSID."""
    trace(f"[FEATURE] Rescanning Wi-Fi and scanning BSSIDs for target SSID '{target_ssid}'")
    log_step(f"Scanning BSSIDs for '{target_ssid}'...")
    log_wait("Triggering Wi-Fi rescan...")
    _run(["nmcli", "device", "wifi", "rescan"])
    rc, out = _run(["nmcli", "-t", "-f", "BSSID,SSID,SIGNAL,CHAN,ACTIVE", "dev", "wifi", "list"])
    results = []
    seen = set()
    for line in out.splitlines():
        if not line:
            continue
        unescaped = line.replace(r"\:", "\x00")
        parts = unescaped.split(":")
        if len(parts) >= 5:
            bssid = parts[0].replace("\x00", ":").strip()
            ssid = parts[1].replace("\x00", ":").strip()
            signal = parts[2].replace("\x00", ":").strip()
            chan = parts[3].replace("\x00", ":").strip()
            active = parts[4].replace("\x00", ":").strip().lower() == "yes"
            if ssid.lower() == target_ssid.lower() and bssid not in seen:
                seen.add(bssid)
                results.append(BSSIDTarget(
                    bssid=bssid,
                    ssid=ssid,
                    signal=signal,
                    chan=chan,
                    active=active
                ))

    def parse_sig(item: BSSIDTarget) -> int:
        clean = DIGIT_REGEX.sub("", str(item.signal))
        return int(clean) if clean else 0

    results.sort(key=parse_sig, reverse=True)
    return results


def get_connected_bssid(interface: str = "wlan0") -> str:
    """Retrieves the currently connected BSSID using kernel iw link, NetworkManager active BSSID, or dev show."""
    rc, iw_out = _run(["iw", "dev", interface, "link"], debug=False)
    if rc == 0 and iw_out:
        m = CONNECTED_MAC_REGEX.search(iw_out)
        if m:
            return m.group(1).upper()

    rc, out = _run(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"], debug=False)
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                bssid = parts[1].replace("\x00", ":").strip()
                if bssid and bssid != "--":
                    return bssid.upper()

    return ""


def lock_bssid(target_bssid: str | None = None, profile: str | None = None, max_retries: int = 3) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        return False

    target_ssid = get_ssid_for_profile(profile)

    if not target_bssid:
        from .ui_status import select_bssid_interactively
        target_bssid = select_bssid_interactively(target_ssid)
        if not target_bssid:
            return False

    trace(f"[FEATURE] Locking profile '{profile}' to BSSID {target_bssid} (Max retries: {max_retries})")
    log_step(f"Locking BSSID -> {target_bssid} (profile: {profile})...")

    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            log_wait(f"Retry {attempt}/{max_retries} -> BSSID: {target_bssid}...")

        rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", target_bssid])
        if rc != 0:
            log_warning(f"Attempt {attempt}/{max_retries}: Failed setting BSSID property for '{profile}'.")
            continue

        log_wait(f"Reconnecting profile '{profile}'...")
        rc_up, out_up = _run(["nmcli", "connection", "up", profile], timeout=15.0)
        if rc_up != 0 or "could not be found" in out_up.lower():
            log_wait("NetworkManager cache miss. Rescanning & reconnecting...")
            _run(["nmcli", "device", "wifi", "rescan"], debug=False)
            time.sleep(1.0)
            _run(["nmcli", "connection", "up", profile], timeout=15.0)

        log_wait(f"Verifying lock to BSSID {target_bssid}...")
        verified = False
        connected_bssid = ""
        for _ in range(5):
            connected_bssid = get_connected_bssid()
            if connected_bssid and connected_bssid.upper() == target_bssid.upper():
                verified = True
                break
            time.sleep(1)

        if verified:
            trace(f"[FEATURE] Successfully locked connection profile '{profile}' to BSSID {target_bssid}")
            log_plus(f"BSSID locked: {target_bssid}")
            return True
        else:
            trace(f"[FEATURE] Attempt {attempt}/{max_retries} failed to lock onto BSSID {target_bssid} (Current: {connected_bssid or 'Unknown'})")
            log_warning(f"Lock attempt {attempt}/{max_retries} failed -> Current: {connected_bssid or 'None'}")

    trace(f"[FEATURE] Failed to lock profile '{profile}' to BSSID {target_bssid} after {max_retries} attempts")
    log_minus(f"Lock failed after {max_retries} attempts -> Skipping {target_bssid}")
    return False
