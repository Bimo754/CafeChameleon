"""
Library/wifi.py - Wi-Fi BSSID locking, auto-roaming, status display via NetworkManager (nmcli).
"""

import re
import sys

from .utils import (
    _run,
    log_info,
    log_plus,
    log_warning,
    log_minus
)

DEFAULT_BSSID = "08:FA:28:56:27:80"


def get_active_profile():
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


def get_ssid_for_profile(profile):
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


def scan_bssids_for_ssid(target_ssid):
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


def get_connected_bssid():
    """Retrieves the currently connected BSSID."""
    rc, out = _run(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"])
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                return parts[1].replace("\x00", ":").strip()
    return ""


def select_bssid_interactively(target_ssid):
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


def show_status():
    profile = get_active_profile()
    from .colors.colors import BOLD, CYAN, GREEN, YELLOW, RESET
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




def lock_bssid(target_bssid=None, profile=None):
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: Could not auto-detect active Wi-Fi profile. Please specify profile name.")
        sys.exit(1)

    target_ssid = get_ssid_for_profile(profile)

    if not target_bssid:
        target_bssid = select_bssid_interactively(target_ssid)
        if not target_bssid:
            sys.exit(1)

    log_info(f"Locking profile '{profile}' to BSSID: {target_bssid}...")
    rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", target_bssid])
    if rc == 0:
        log_info(f"Reconnecting to '{profile}'...")
        _run(["nmcli", "connection", "up", profile])
        connected_bssid = get_connected_bssid()
        if connected_bssid and connected_bssid.upper() == target_bssid.upper():
            log_plus(f"Successfully locked and verified connection to BSSID {target_bssid}")
        else:
            log_plus(f"Connection modified. Active BSSID: {connected_bssid or 'Unknown'} (Target BSSID: {target_bssid})")
    else:
        log_minus("Failed to modify connection settings.")
        sys.exit(1)


def restore_auto(profile):
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: Could not auto-detect active Wi-Fi profile. Please specify profile name.")
        sys.exit(1)

    log_info(f"Removing BSSID lock from profile '{profile}'...")
    rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", ""])
    if rc == 0:
        log_info(f"Reconnecting profile '{profile}' (switching to strongest signal)...")
        _run(["nmcli", "connection", "up", profile])
        log_plus("Successfully restored auto-roaming to strongest signal!")
    else:
        log_minus("Failed to reset BSSID lock.")
        sys.exit(1)


def is_valid_mac(val):
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", val)) if val else False


def run_wifi(args):
    if args.status:
        show_status()
    elif args.lock is not None:
        bssid = None
        profile = None
        if len(args.lock) == 1:
            if is_valid_mac(args.lock[0]):
                bssid = args.lock[0]
            else:
                profile = args.lock[0]
        elif len(args.lock) >= 2:
            bssid = args.lock[0]
            profile = args.lock[1]

        lock_bssid(bssid, profile)
    elif args.auto is not None:
        profile = args.auto[0] if len(args.auto) > 0 else None
        restore_auto(profile)
    else:
        log_minus("No wifi action specified. Use --status, --lock, or --auto.")
        sys.exit(1)
