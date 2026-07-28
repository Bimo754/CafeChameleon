"""
cafe_chameleon.network.nmcli - Wi-Fi BSSID locking, auto-roaming, and status display via NetworkManager (nmcli).
"""

import sys
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_info, log_plus, log_warning, log_minus
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
    log_info(f"Scanning area for BSSIDs of network '{target_ssid}'...")
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
    return results


def get_connected_bssid() -> str:
    """Retrieves the currently connected BSSID."""
    rc, out = _run(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"])
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                bssid = parts[1].replace("\x00", ":").strip()
                if bssid and bssid != "--":
                    return bssid

    rc, out = _run(["nmcli", "-t", "-f", "WIFI.BSSID", "dev", "show"])
    for line in out.splitlines():
        bssid = line.strip()
        if bssid and bssid != "--":
            return bssid

    return ""


def select_bssid_interactively(target_ssid: str) -> str | None:
    """Scans and presents an interactive menu for selecting a BSSID."""
    bssids = scan_bssids_for_ssid(target_ssid)
    if not bssids:
        log_warning(f"No BSSIDs found scanning for SSID '{target_ssid}'.")
        return None

    print(f"\nFound {len(bssids)} BSSID(s) for network '{target_ssid}':")
    print("=" * 60)
    print(f"{'#':<4} {'BSSID':<20} {'SIGNAL':<8} {'CHAN':<6} {'STATUS'}")
    print("-" * 60)
    for idx, item in enumerate(bssids, start=1):
        status = "[CONNECTED]" if item["active"] else ""
        print(f"{idx:<4} {item['bssid']:<20} {item['signal'] + '%':<8} {item['chan']:<6} {status}")
    print("=" * 60)

    while True:
        try:
            choice = input(f"\nSelect a BSSID to lock onto (1-{len(bssids)}) [or 'q' to cancel]: ").strip()
            if choice.lower() == 'q':
                log_info("Operation cancelled by user.")
                sys.exit(0)
            val = int(choice)
            if 1 <= val <= len(bssids):
                return bssids[val - 1]["bssid"]
            else:
                log_warning(f"Please enter a number between 1 and {len(bssids)}.")
        except ValueError:
            log_warning("Invalid input. Please enter a valid number.")
        except (KeyboardInterrupt, EOFError):
            log_warning("Aborted.")
            sys.exit(0)


def show_status() -> None:
    profile = get_active_profile()
    print(f"\n{BOLD}{CYAN}=== WI-FI STATUS ==={RESET}")
    if profile:
        print(f"{BOLD}Profile{RESET} : {CYAN}{profile}{RESET}")
        rc, bssid_lock = _run(["nmcli", "-g", "802-11-wireless.bssid", "connection", "show", profile])
        if bssid_lock:
            print(f"{BOLD}Lock{RESET}    : {YELLOW}LOCKED ({bssid_lock}){RESET}")
        else:
            print(f"{BOLD}Lock{RESET}    : {GREEN}AUTO (Roaming){RESET}")
        
        details = {}
        rc, out = _run(["nmcli", "-f", "GENERAL.CONNECTION,WIFI.BSSID,WIFI.SSID,WIFI.SIGNAL", "dev", "show"])
        for line in out.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                k, v = parts[0].strip(), parts[1].strip()
                if "BSSID" in k and v and v != "--":
                    details["Active BSSID"] = v
                elif "SSID" in k and v and v != "--":
                    details["SSID"] = v
                elif "SIGNAL" in k and v and v != "--":
                    details["Signal"] = f"{v}%"

        for k, v in details.items():
            print(f"{BOLD}{k:<12}{RESET}: {v}")
    else:
        print(f"{YELLOW}No active Wi-Fi connection detected.{RESET}")
    print(f"{CYAN}===================={RESET}\n")


def lock_bssid(target_bssid: str | None = None, profile: str | None = None, max_retries: int = 3) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: Could not auto-detect active Wi-Fi profile. Please specify profile name.")
        return False

    target_ssid = get_ssid_for_profile(profile)

    if not target_bssid:
        target_bssid = select_bssid_interactively(target_ssid)
        if not target_bssid:
            return False

    log_info(f"Locking profile '{profile}' to BSSID: {target_bssid} (max {max_retries} attempts)...")

    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            log_info(f"Retry attempt {attempt}/{max_retries} to lock on BSSID: {target_bssid}...")

        rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", target_bssid])
        if rc != 0:
            log_warning(f"Attempt {attempt}/{max_retries}: Failed to modify connection settings for '{profile}'.")
            continue

        log_info(f"Reconnecting to '{profile}'...")
        _run(["nmcli", "connection", "up", profile])

        # Poll for up to 5 seconds to verify BSSID lock
        verified = False
        connected_bssid = ""
        for _ in range(5):
            connected_bssid = get_connected_bssid()
            if connected_bssid and connected_bssid.upper() == target_bssid.upper():
                verified = True
                break
            time.sleep(1)

        if verified:
            log_plus(f"Successfully locked and verified connection to BSSID {target_bssid}")
            return True
        else:
            log_warning(
                f"Attempt {attempt}/{max_retries} failed to lock onto BSSID {target_bssid}. "
                f"Active BSSID: {connected_bssid or 'Unknown'}"
            )

    log_minus(f"Failed to lock onto BSSID {target_bssid} after {max_retries} attempts. Skipping BSSID...")
    return False


def restore_auto(profile: str | None = None) -> None:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: Could not auto-detect active Wi-Fi profile. Please specify profile name.")
        sys.exit(1)

    log_info(f"Removing BSSID lock and resetting cloned MAC on profile '{profile}'...")
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""])
    _run(["nmcli", "connection", "modify", profile, "802-11-wireless.cloned-mac-address", ""])
    log_info(f"Reconnecting profile '{profile}' (switching to strongest signal & permanent MAC)...")
    rc_up, _ = _run(["nmcli", "connection", "up", profile])
    if rc_up == 0:
        log_plus("Successfully restored auto-roaming and permanent MAC!")
    else:
        log_minus("Failed to reconnect profile after resetting settings.")
