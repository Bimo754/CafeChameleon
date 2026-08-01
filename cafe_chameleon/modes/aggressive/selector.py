"""
cafe_chameleon.modes.aggressive.selector - BSSID ranking display and interactive starting BSSID prompt.
"""

import sys

from cafe_chameleon.ui.console import log_info, log_main
from .ranker import calculate_bssid_score


def display_and_select_bssid(bssids: list[dict], air_clients_map: dict, select_requested: bool) -> list[dict]:
    """Sorts, prints ranked BSSIDs, and handles interactive selection if requested."""
    bssids.sort(key=lambda b: calculate_bssid_score(b, air_clients_map)[0], reverse=True)

    log_main("\n\033[1;38;5;215m── AUTO-RANKED BSSID TARGETS ──────────────────────────────────────────\033[0m")
    for rank, b in enumerate(bssids, start=1):
        score, clients, sig = calculate_bssid_score(b, air_clients_map)
        log_main(f" #{rank:<2} │ \033[1;37mBSSID:\033[0m {b['bssid']} │ \033[1;37mScore:\033[0m {score:<4} │ \033[1;37mClients:\033[0m {clients:<2} │ \033[1;37mSig:\033[0m {sig}% │ \033[1;37mCh:\033[0m {b['chan']}")
    log_main("\033[1;30m────────────────────────────────────────────────────────────────────────\033[0m\n")

    if select_requested:
        log_main("\n\033[1;38;5;215m── BSSID SELECTION LIST ───────────────────────────────────────────────\033[0m")
        for i, b in enumerate(bssids, start=1):
            score, clients, sig = calculate_bssid_score(b, air_clients_map)
            log_main(f"  [{i}] {b['bssid']} (\033[1;37mClients:\033[0m {clients}, \033[1;37mSignal:\033[0m {sig}%, \033[1;37mChannel:\033[0m {b['chan']})")
        log_main("\033[1;30m────────────────────────────────────────────────────────────────────────\033[0m\n")

        selected_idx = 0
        try:
            sys.stdout.write(f"\033[93m[?] Enter starting BSSID number [1-{len(bssids)}, default: 1]: \033[0m")
            sys.stdout.flush()
            val = sys.stdin.readline().strip()
            if val.isdigit():
                num = int(val)
                if 1 <= num <= len(bssids):
                    selected_idx = num - 1
        except (KeyboardInterrupt, EOFError):
            sys.stdout.write("\n")
            pass

        if selected_idx > 0:
            bssids = bssids[selected_idx:] + bssids[:selected_idx]
            log_info(f"Selected starting BSSID: {bssids[0]['bssid']}")
            log_main(f"[+] Selected starting BSSID: {bssids[0]['bssid']}")

    return bssids
