"""
cafe_chameleon.modes.aggressive.selector - BSSID ranking display and target BSSID selection.
"""

import sys

from cafe_chameleon.ui.console import log_info, log_main, log_warning, get_user_input
from cafe_chameleon.utils.signals import restore_and_exit, MainSkipInterrupt, WindowCtrlCInterrupt
from .ranker import calculate_bssid_score, count_active_clients


def parse_target_selection(selection_str: str, max_count: int) -> list[int]:
    """Parses target selection expression into a list of unique 1-based indices within [1, max_count].

    Supports:
        - Single number: '1', '(1)'
        - Comma-separated: '1,2,7', '(1,2,7)'
        - Ranges: '1-10', '(1-10)'
        - Combinations: '1-10,12', '(1-10,12)', '1-3, 5, 7-9'
    """
    if not selection_str or max_count <= 0:
        return []

    cleaned = selection_str.strip().strip("()[]")
    if not cleaned:
        return []

    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]
    indices: list[int] = []

    for token in tokens:
        if "-" in token:
            parts = token.split("-", 1)
            p0, p1 = parts[0].strip(), parts[1].strip()
            if p0.isdigit() and p1.isdigit():
                start = int(p0)
                end = int(p1)
                step = 1 if start <= end else -1
                for n in range(start, end + step, step):
                    if 1 <= n <= max_count:
                        indices.append(n)
        elif token.isdigit():
            n = int(token)
            if 1 <= n <= max_count:
                indices.append(n)

    # Preserve order and eliminate duplicates
    return list(dict.fromkeys(indices))


def display_and_select_bssid(
    bssids: list[dict],
    air_clients_map: dict,
    select_requested: bool | str = False,
    prioritize_clients: bool = False
) -> list[dict]:
    """Sorts, prints ranked BSSIDs, and handles target BSSID selection if requested."""
    if not bssids:
        return []

    bssids.sort(
        key=lambda b: calculate_bssid_score(b, air_clients_map, prioritize_clients=prioritize_clients)[0],
        reverse=True
    )

    has_active_any = any(count_active_clients(b.get("bssid", ""), air_clients_map) > 0 for b in bssids) if air_clients_map else False

    log_main("\n\033[1;38;5;215m── AUTO-RANKED BSSID TARGETS ──────────────────────────────────────────\033[0m")
    for rank, b in enumerate(bssids, start=1):
        score, clients, sig = calculate_bssid_score(b, air_clients_map, prioritize_clients=prioritize_clients)
        active_cnt = count_active_clients(b.get("bssid", ""), air_clients_map)
        sec_str = b.get("security") or "OPEN"
        active_str = f" │ \033[1;37mActive:\033[0m \033[1;32m{active_cnt:<2}\033[0m" if (has_active_any or active_cnt > 0) else ""
        log_main(f" #{rank:<2} │ \033[1;37mBSSID:\033[0m {b['bssid']} │ \033[1;37mScore:\033[0m {score:<4} │ \033[1;37mClients:\033[0m {clients:<2}{active_str} │ \033[1;37mSig:\033[0m {sig}% │ \033[1;37mCh:\033[0m {b['chan']} │ \033[1;37mSec:\033[0m {sec_str}")
    log_main("\033[1;30m────────────────────────────────────────────────────────────────────────\033[0m\n")

    if not select_requested:
        return bssids

    # If direct selection string was provided via CLI (e.g. -s 1,2,7 or -s 1-10,12)
    if isinstance(select_requested, str) and select_requested.strip() and select_requested.strip().lower() not in ("true", "1"):
        selected_indices = parse_target_selection(select_requested, len(bssids))
        if selected_indices:
            selected_bssids = [bssids[i - 1] for i in selected_indices]
            bssid_list_str = ", ".join(b["bssid"] for b in selected_bssids)
            log_info(f"Targeting {len(selected_bssids)} selected BSSID(s): {bssid_list_str}")
            log_main(f"[+] Targeted {len(selected_bssids)} selected BSSID(s) out of {len(bssids)}")
            return selected_bssids
        else:
            log_warning(f"Invalid BSSID selection '{select_requested}'. Falling back to interactive selection.")

    log_main("\n\033[1;38;5;215m── BSSID SELECTION LIST (Press CTRL+C in xterm or 'q' to exit) ────────\033[0m")
    for i, b in enumerate(bssids, start=1):
        score, clients, sig = calculate_bssid_score(b, air_clients_map, prioritize_clients=prioritize_clients)
        active_cnt = count_active_clients(b.get("bssid", ""), air_clients_map)
        sec_str = b.get("security") or "OPEN"
        active_suffix = f", \033[1;32mActive:\033[0m {active_cnt}" if active_cnt > 0 else ""
        log_main(f"  [{i}] {b['bssid']} (\033[1;37mClients:\033[0m {clients}{active_suffix}, \033[1;37mSignal:\033[0m {sig}%, \033[1;37mChannel:\033[0m {b['chan']}, \033[1;37mSecurity:\033[0m {sec_str})")
    log_main("\033[1;30m────────────────────────────────────────────────────────────────────────\033[0m\n")

    while True:
        try:
            prompt_str = f"\033[93m[?] Enter target BSSID(s) [e.g. 1, 1,2,7, 1-10,12, default: 1-{len(bssids)}, 'q' or CTRL+C in xterm to exit]: \033[0m"
            val = get_user_input(prompt_str).strip()
            if val.lower() in ("q", "quit", "exit"):
                restore_and_exit("User requested exit at BSSID selection.")
                return bssids
            if not val:
                log_info(f"Targeting all {len(bssids)} BSSID(s)")
                log_main(f"[+] Targeting all {len(bssids)} BSSID(s)")
                return bssids

            selected_indices = parse_target_selection(val, len(bssids))
            if selected_indices:
                selected_bssids = [bssids[i - 1] for i in selected_indices]
                bssid_list_str = ", ".join(b["bssid"] for b in selected_bssids)
                log_info(f"Selected {len(selected_bssids)} target BSSID(s): {bssid_list_str}")
                log_main(f"[+] Selected {len(selected_bssids)} target BSSID(s) out of {len(bssids)}")
                return selected_bssids
            else:
                log_warning(f"Invalid selection '{val}'. Enter numbers/ranges between 1 and {len(bssids)}.")
        except (KeyboardInterrupt, MainSkipInterrupt, WindowCtrlCInterrupt):
            restore_and_exit("Ctrl+C received at BSSID selection.")
            return bssids
        except EOFError:
            return bssids
