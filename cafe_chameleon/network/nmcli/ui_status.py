"""
cafe_chameleon.network.nmcli.ui_status - Interactive BSSID selection menu and formatted status output.
"""

import sys

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_info, log_warning, get_user_input
from cafe_chameleon.ui.colors import BOLD, CYAN, GREEN, YELLOW, RESET
from .profiles import get_active_profile
from .bssid import scan_bssids_for_ssid


def select_bssid_interactively(target_ssid: str) -> str | None:
    """Scans and presents an interactive menu for selecting a BSSID."""
    bssids = scan_bssids_for_ssid(target_ssid)
    if not bssids:
        log_warning(f"No BSSIDs found for SSID '{target_ssid}'.")
        return None

    print(f"\nFound {len(bssids)} BSSID(s) for '{target_ssid}':")
    print("=" * 72)
    print(f"{'#':<4} {'BSSID':<20} {'SIGNAL':<8} {'CHAN':<6} {'SECURITY':<12} {'STATUS'}")
    print("-" * 72)
    for idx, item in enumerate(bssids, start=1):
        status = "[CONNECTED]" if item["active"] else ""
        sec = item.get("security") or "OPEN"
        print(f"{idx:<4} {item['bssid']:<20} {item['signal'] + '%':<8} {item['chan']:<6} {sec:<12} {status}")
    print("=" * 72)

    while True:
        try:
            choice = get_user_input(f"\nSelect BSSID (1-{len(bssids)}) [or 'q'/Ctrl+C in xterm to cancel]: ").strip()
            if choice.lower() in ('q', 'quit', 'exit'):
                log_info("Cancelled.")
                from cafe_chameleon.utils.signals import restore_and_exit
                restore_and_exit("User cancelled BSSID selection.")
                return None
            val = int(choice)
            if 1 <= val <= len(bssids):
                return bssids[val - 1]["bssid"]
            else:
                log_warning(f"Enter number 1-{len(bssids)}.")
        except ValueError:
            log_warning("Invalid input.")
        except (KeyboardInterrupt, EOFError):
            log_warning("Aborted.")
            from cafe_chameleon.utils.signals import restore_and_exit
            restore_and_exit("Ctrl+C received during BSSID selection.")
            return None


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
        rc, out = _run(["nmcli", "-t", "-f", "active,bssid,ssid,signal,security", "dev", "wifi"], debug=False)
        for line in out.splitlines():
            if line.startswith("yes:"):
                unescaped = line.replace(r"\:", "\x00")
                parts = unescaped.split(":")
                if len(parts) >= 5:
                    details["Active BSSID"] = parts[1].replace("\x00", ":").strip()
                    details["SSID"] = parts[2].replace("\x00", ":").strip()
                    details["Signal"] = f"{parts[3].strip()}%"
                    details["Security"] = parts[4].replace("\x00", ":").strip() or "OPEN"
                    break

        for k, v in details.items():
            print(f"{BOLD}{k:<12}{RESET}: {v}")
    else:
        print(f"{YELLOW}No active connection.{RESET}")
    print(f"{CYAN}===================={RESET}\n")
