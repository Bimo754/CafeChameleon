"""
cafe_chameleon.modes.aggressive.selector - BSSID ranking display and target BSSID selection.
"""

import re
import sys

from cafe_chameleon.ui.console import log_info, log_main, log_warning, get_user_input
from cafe_chameleon.utils.signals import restore_and_exit, MainSkipInterrupt, WindowCtrlCInterrupt
from .ranker import calculate_bssid_score, count_active_clients

DIGIT_REGEX = re.compile(r"[^\d]")


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


def extract_signal_int(b: dict) -> int:
    """Extracts signal percentage integer safely."""
    sig_raw = b.get("signal") if hasattr(b, "get") else getattr(b, "signal", None)
    if sig_raw is None:
        return 0
    try:
        clean = DIGIT_REGEX.sub("", str(sig_raw))
        return int(clean) if clean else 0
    except (ValueError, TypeError):
        return 0


def format_bssid_table(bssids: list[dict], air_clients_map: dict, header_title: str) -> str:
    """Formats BSSIDs into a compact, non-wrapping table with BSSID, clients, active, and signal."""
    lines = []
    lines.append(f"\033[1;38;5;215m── {header_title} ──────────────────────────────────────\033[0m")
    lines.append(f"{'#':<4} {'BSSID':<19} {'CLIENTS':<9} {'ACTIVE':<8} {'SIGNAL':<8}")
    lines.append("\033[1;30m────────────────────────────────────────────────────────\033[0m")

    for rank, b in enumerate(bssids, start=1):
        bssid_mac = b.get("bssid", "") if isinstance(b, dict) else getattr(b, "bssid", "")
        _score, clients, sig = calculate_bssid_score(b, air_clients_map)
        active_cnt = count_active_clients(bssid_mac, air_clients_map)
        sig_str = f"{sig}%"

        if active_cnt > 0:
            active_str = f"\033[1;32m{active_cnt:<8}\033[0m"
        else:
            active_str = f"{active_cnt:<8}"

        lines.append(f" {rank:<3} {bssid_mac:<19} {clients:<9} {active_str} {sig_str:<8}")

    lines.append("\033[1;30m────────────────────────────────────────────────────────\033[0m\n")
    return "\n".join(lines)


def display_and_select_bssid(
    bssids: list[dict],
    air_clients_map: dict,
    select_requested: bool | str = False,
    prioritize_clients: bool = False,
    is_air_only: bool = False
) -> list[dict]:
    """Sorts BSSIDs from strongest signal (or score if prioritized), renders table, and handles selection."""
    if not bssids:
        return []

    if prioritize_clients:
        bssids.sort(
            key=lambda b: calculate_bssid_score(b, air_clients_map, prioritize_clients=True)[0],
            reverse=True
        )
    else:
        bssids.sort(
            key=lambda b: extract_signal_int(b),
            reverse=True
        )

    if not select_requested:
        if not is_air_only:
            table_output = format_bssid_table(bssids, air_clients_map, "AUTO-RANKED BSSID TARGETS")
            log_main(table_output, clear=True)
        return bssids

    # If direct selection string was provided via CLI (e.g. -s 1,2,7 or -s 1-10,12)
    if isinstance(select_requested, str) and select_requested.strip() and select_requested.strip().lower() != "true":
        selected_indices = parse_target_selection(select_requested, len(bssids))
        if selected_indices:
            selected_bssids = [bssids[i - 1] for i in selected_indices]
            bssid_list_str = ", ".join(b["bssid"] for b in selected_bssids)
            log_info(f"Targeting {len(selected_bssids)} selected BSSID(s): {bssid_list_str}")
            return selected_bssids
        else:
            log_warning(f"Invalid BSSID selection '{select_requested}'. Falling back to interactive selection.")

    table_output = format_bssid_table(bssids, air_clients_map, "BSSID SELECTION LIST")
    log_main(table_output, clear=True)

    while True:
        try:
            prompt_str = f"\033[93m[?] Target BSSID(s) [1-{len(bssids)}, 'q' to exit]: \033[0m"
            val = get_user_input(prompt_str).strip()
            if val.lower() in ("q", "quit", "exit"):
                restore_and_exit("User requested exit at BSSID selection.")
                return bssids
            if not val:
                return bssids

            selected_indices = parse_target_selection(val, len(bssids))
            if selected_indices:
                selected_bssids = [bssids[i - 1] for i in selected_indices]
                bssid_list_str = ", ".join(b["bssid"] for b in selected_bssids)
                log_info(f"Selected {len(selected_bssids)} target BSSID(s): {bssid_list_str}")
                return selected_bssids
            else:
                log_warning(f"Invalid selection '{val}'. Enter numbers/ranges between 1 and {len(bssids)}.")
        except (KeyboardInterrupt, MainSkipInterrupt, WindowCtrlCInterrupt):
            restore_and_exit("Ctrl+C received at BSSID selection.")
            return bssids
        except EOFError:
            return bssids
