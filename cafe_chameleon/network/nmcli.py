"""
cafe_chameleon.network.nmcli - Wi-Fi BSSID locking, auto-roaming, and status display via NetworkManager (nmcli).
"""

import sys
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_info, log_plus, log_warning, log_minus, log_step, log_wait
from cafe_chameleon.ui.colors import BOLD, CYAN, GREEN, YELLOW, RESET
from cafe_chameleon.network.mac import is_valid_mac

DEFAULT_BSSID = "08:FA:28:56:27:80"


def get_active_profile() -> str:
    rc, out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
    for line in out.splitlines():
        if line.endswith(":802-11-wireless"):
            return line.split(":")[0]

    rc, out = _run(["nmcli", "-t", "-f", "GENERAL.CONNECTION", "dev", "show"])
    for line in out.splitlines():
        if line.strip():
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                return parts[1].strip()
    return ""


def get_ssid_for_profile(profile: str) -> str:
    """Retrieves the SSID associated with a connection profile."""
    rc, ssid = _run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", profile])
    if ssid:
        return ssid
    rc, out = _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                active_ssid = parts[1].replace("\x00", ":").strip()
                if active_ssid:
                    return active_ssid
    return profile


def scan_bssids_for_ssid(target_ssid: str) -> list[dict]:
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
                results.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "signal": signal,
                    "chan": chan,
                    "active": active
                })

    import re
    results.sort(key=lambda x: int(re.sub(r"[^\d]", "", str(x.get("signal", 0)))) if re.sub(r"[^\d]", "", str(x.get("signal", 0))) else 0, reverse=True)
    return results


def get_connected_bssid(interface: str = "wlan0") -> str:
    """Retrieves the currently connected BSSID using kernel iw link, NetworkManager active BSSID, or dev show."""
    rc, iw_out = _run(f"iw dev {interface} link", debug=False)
    if rc == 0 and iw_out:
        import re
        m = re.search(r"Connected to\s+([0-9a-fa-f:]+)", iw_out, re.IGNORECASE)
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


def select_bssid_interactively(target_ssid: str) -> str | None:
    """Scans and presents an interactive menu for selecting a BSSID."""
    bssids = scan_bssids_for_ssid(target_ssid)
    if not bssids:
        log_warning(f"No BSSIDs found for SSID '{target_ssid}'.")
        return None

    print(f"\nFound {len(bssids)} BSSID(s) for '{target_ssid}':")
    print("=" * 60)
    print(f"{'#':<4} {'BSSID':<20} {'SIGNAL':<8} {'CHAN':<6} {'STATUS'}")
    print("-" * 60)
    for idx, item in enumerate(bssids, start=1):
        status = "[CONNECTED]" if item["active"] else ""
        print(f"{idx:<4} {item['bssid']:<20} {item['signal'] + '%':<8} {item['chan']:<6} {status}")
    print("=" * 60)

    while True:
        try:
            choice = input(f"\nSelect BSSID (1-{len(bssids)}) [or 'q' to cancel]: ").strip()
            if choice.lower() == 'q':
                log_info("Cancelled.")
                sys.exit(0)
            val = int(choice)
            if 1 <= val <= len(bssids):
                return bssids[val - 1]["bssid"]
            else:
                log_warning(f"Enter number 1-{len(bssids)}.")
        except ValueError:
            log_warning("Invalid input.")
        except (KeyboardInterrupt, EOFError):
            log_warning("Aborted.")
            sys.exit(0)


def show_status() -> None:
    profile = get_active_profile()
    trace(f"[FEATURE] Querying Wi-Fi status for active profile '{profile}'")
    print(f"\n{BOLD}{CYAN}=== WI-FI STATUS ==={RESET}")
    if profile:
        print(f"{BOLD}Profile{RESET} : {CYAN}{profile}{RESET}")
        rc, bssid_lock = _run(["nmcli", "-g", "802-11-wireless.bssid", "connection", "show", profile])
        if bssid_lock:
            print(f"{BOLD}Lock{RESET}    : {YELLOW}LOCKED ({bssid_lock}){RESET}")
        else:
            print(f"{BOLD}Lock{RESET}    : {GREEN}AUTO (Roaming){RESET}")
        
        details = {}
        rc, out = _run(["nmcli", "-t", "-f", "active,bssid,ssid,signal", "dev", "wifi"], debug=False)
        for line in out.splitlines():
            if line.startswith("yes:"):
                unescaped = line.replace(r"\:", "\x00")
                parts = unescaped.split(":")
                if len(parts) >= 4:
                    details["Active BSSID"] = parts[1].replace("\x00", ":").strip()
                    details["SSID"] = parts[2].replace("\x00", ":").strip()
                    details["Signal"] = f"{parts[3].strip()}%"
                    break

        for k, v in details.items():
            print(f"{BOLD}{k:<12}{RESET}: {v}")
    else:
        print(f"{YELLOW}No active connection.{RESET}")
    print(f"{CYAN}===================={RESET}\n")


def lock_bssid(target_bssid: str | None = None, profile: str | None = None, max_retries: int = 3) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        return False

    target_ssid = get_ssid_for_profile(profile)

    if not target_bssid:
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

        # Poll for up to 5 seconds to verify BSSID lock
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


def restore_auto(profile: str | None = None) -> None:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        sys.exit(1)

    trace(f"[FEATURE] Restoring profile '{profile}' to auto-roam and default permanent MAC")
    log_step(f"Resetting BSSID lock & MAC on profile '{profile}'...")
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""])
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""])
    log_wait(f"Reconnecting '{profile}' (auto-roam)...")
    rc_up, _ = _run(["nmcli", "connection", "up", profile])
    if rc_up == 0:
        log_plus("Restored auto-roaming & HW MAC.")
    else:
        log_minus("Failed reconnecting profile after reset.")


def reset_mac(profile: str | None = None) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        return False

    trace(f"[FEATURE] Resetting MAC address on profile '{profile}' to original hardware default")
    log_step(f"Resetting cloned MAC on profile '{profile}'...")
    rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""])
    log_wait(f"Reconnecting profile '{profile}'...")
    rc_up, _ = _run(["nmcli", "connection", "up", profile], timeout=15.0)
    if rc_up == 0:
        log_plus("Reset MAC to permanent HW default.")
        return True
    else:
        from cafe_chameleon.scanners.detector import auto_detect_network_params
        from cafe_chameleon.network.mac import reset_mac_address
        params = auto_detect_network_params()
        iface = params.get("interface") or "wlan0"
        if reset_mac_address(iface, profile):
            log_plus("Reset MAC via fallback method.")
            return True
        else:
            log_minus("Failed to reset MAC address.")
            return False


