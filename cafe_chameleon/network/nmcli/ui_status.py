"""
cafe_chameleon.network.nmcli.ui_status - Interactive BSSID selection menu, nearby Wi-Fi scan display, and formatted status output.
"""

import re
import sys

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_info, log_warning, log_plus, log_step, log_wait, get_user_input
from cafe_chameleon.ui.colors import BOLD, CYAN, GREEN, YELLOW, RED, WHITE, DIM, RESET
from .profiles import get_active_profile
from .bssid import scan_bssids_for_ssid, scan_nearby_wifi_networks


def show_wifi_scan(target_ssid: str | None = None, rescan: bool = True) -> bool:
    """Scans and renders a beautifully formatted table of nearby Wi-Fi networks and BSSIDs."""
    trace(f"[FEATURE] Initiating Wi-Fi scan display (target_ssid={target_ssid}, rescan={rescan})")
    networks = scan_nearby_wifi_networks(target_ssid=target_ssid, rescan=rescan)

    if not networks:
        if target_ssid:
            log_warning(f"No Wi-Fi networks found matching '{target_ssid}'.")
        else:
            log_warning("No nearby Wi-Fi networks detected.")
        return False

    unique_ssids = len(set(n.ssid for n in networks if n.ssid))
    total_bssids = len(networks)
    open_count = sum(1 for n in networks if n.is_open)
    enc_count = total_bssids - open_count

    # Header banner
    if target_ssid:
        banner_title = f"── WI-FI NETWORKS MATCHING '{target_ssid}' ({total_bssids} BSSID{'s' if total_bssids != 1 else ''}) "
    else:
        banner_title = f"── NEARBY WI-FI NETWORKS ({total_bssids} BSSID{'s' if total_bssids != 1 else ''} / {unique_ssids} SSID{'s' if unique_ssids != 1 else ''}) "

    fill_len = max(10, 108 - len(banner_title))
    print(f"\n{BOLD}{CYAN}{banner_title}{'─' * fill_len}{RESET}")
    print(f"{BOLD}{'#':<4} {'STATUS':<9} {'BSSID':<19} {'SSID':<28} {'SIGNAL':<8} {'BARS':<6} {'CHAN':<6} {'RATE':<13} {'SECURITY':<14}{RESET}")
    print(f"{CYAN}{'─' * 108}{RESET}")

    for idx, item in enumerate(networks, start=1):
        status_raw = "[ACTIVE]" if item.active else ""
        bssid_raw = item.bssid
        ssid_raw = item.ssid if item.ssid else "<hidden>"
        signal_raw = f"{item.signal}%"
        bars_raw = item.bars or "--"
        chan_raw = str(item.chan)
        sec_raw = item.security if item.security else "OPEN"
        rate_raw = item.rate or "--"

        # Truncate SSID if overly long for clean alignment
        if len(ssid_raw) > 26:
            ssid_display = ssid_raw[:23] + "..."
        else:
            ssid_display = ssid_raw

        # Format columns with color padding
        status_col = f"{BOLD}{GREEN}{status_raw:<9}{RESET}" if item.active else f"{status_raw:<9}"
        bssid_col = f"{bssid_raw:<19}"
        if item.ssid:
            ssid_col = f"{BOLD}{WHITE}{ssid_display:<28}{RESET}"
        else:
            ssid_col = f"{DIM}{ssid_display:<28}{RESET}"

        try:
            sig_val = int(re.sub(r"[^\d]", "", str(item.signal)))
        except ValueError:
            sig_val = 0

        if sig_val >= 70:
            sig_col = f"{BOLD}{GREEN}{signal_raw:<8}{RESET}"
        elif sig_val >= 40:
            sig_col = f"{BOLD}{YELLOW}{signal_raw:<8}{RESET}"
        else:
            sig_col = f"{RED}{signal_raw:<8}{RESET}"

        bars_col = f"{GREEN}{bars_raw:<6}{RESET}"
        chan_col = f"{chan_raw:<6}"

        if item.is_open:
            sec_col = f"{BOLD}{GREEN}{sec_raw:<14}{RESET}"
        else:
            sec_col = f"{YELLOW}{sec_raw:<14}{RESET}"

        rate_col = f"{rate_raw:<13}"

        print(f"{idx:<4} {status_col} {bssid_col} {ssid_col} {sig_col} {bars_col} {chan_col} {rate_col} {sec_col}")

    print(f"{CYAN}{'─' * 108}{RESET}")
    open_str = f"{BOLD}{GREEN}{open_count} Open/Captive{RESET}" if open_count > 0 else f"{open_count} Open"
    log_plus(f"Scan Complete: {total_bssids} AP(s) found ({open_str}, {enc_count} Encrypted) across {unique_ssids} SSID(s).\n")
    return True


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
