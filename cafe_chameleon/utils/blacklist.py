"""
cafe_chameleon.utils.blacklist - Persistent MAC address / BSSID blacklist management and filtering.
"""

import os
from cafe_chameleon.config import BLACKLIST_FILE
from cafe_chameleon.network.mac import is_valid_mac
from cafe_chameleon.ui.colors import BOLD, GREEN, RED, CYAN, YELLOW, RESET, colorize_brackets
from cafe_chameleon.ui.console import log_plus, log_minus, log_info


def normalize_mac(mac: str) -> str:
    """Normalizes MAC string to lowercase colon-separated format."""
    if not mac:
        return ""
    cleaned = mac.strip().lower().replace("-", ":")
    return cleaned


def load_blacklist(filepath: str | None = None) -> set[str]:
    """
    Loads blacklisted MAC addresses from the persistent text file.
    Returns a set of normalized lowercase MAC addresses.
    """
    target_path = filepath or BLACKLIST_FILE
    if not os.path.isfile(target_path):
        return set()

    macs: set[str] = set()
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                norm = normalize_mac(line_str)
                if is_valid_mac(norm):
                    macs.add(norm)
    except Exception:
        pass
    return macs


def save_blacklist(macs: set[str] | list[str], filepath: str | None = None) -> None:
    """
    Saves a collection of MAC addresses to the persistent text file, sorted and normalized.
    """
    target_path = filepath or BLACKLIST_FILE
    norm_macs = {normalize_mac(m) for m in macs if m and is_valid_mac(normalize_mac(m))}
    sorted_macs = sorted(norm_macs)

    with open(target_path, "w", encoding="utf-8") as f:
        for m in sorted_macs:
            f.write(f"{m}\n")


def add_to_blacklist(mac: str, filepath: str | None = None) -> tuple[bool, str]:
    """
    Adds a MAC address to the blacklist permanently.
    Returns (success_flag, status_message).
    """
    norm = normalize_mac(mac)
    if not is_valid_mac(norm):
        return False, f"Invalid MAC address format: '{mac}'"

    current = load_blacklist(filepath)
    if norm in current:
        return True, f"MAC address '{norm}' is already blacklisted."

    current.add(norm)
    save_blacklist(current, filepath)
    return True, f"Added MAC '{norm}' to blacklist."


def remove_from_blacklist(mac: str, filepath: str | None = None) -> tuple[bool, str]:
    """
    Removes a MAC address from the blacklist.
    Returns (success_flag, status_message).
    """
    norm = normalize_mac(mac)
    if not is_valid_mac(norm):
        return False, f"Invalid MAC address format: '{mac}'"

    current = load_blacklist(filepath)
    if norm not in current:
        return False, f"MAC address '{norm}' not found in blacklist."

    current.remove(norm)
    save_blacklist(current, filepath)
    return True, f"Removed MAC '{norm}' from blacklist."


def list_blacklist(filepath: str | None = None) -> list[str]:
    """
    Returns a sorted list of all blacklisted MAC addresses.
    """
    return sorted(load_blacklist(filepath))


def is_blacklisted(mac: str, blacklist: set[str] | None = None, filepath: str | None = None) -> bool:
    """
    Checks if a MAC address / BSSID is present in the blacklist.
    """
    if not mac:
        return False
    norm = normalize_mac(mac)
    if blacklist is None:
        blacklist = load_blacklist(filepath)
    return norm in blacklist


def handle_blacklist_cli(args_list: list[str] | None, filepath: str | None = None) -> int:
    """
    Processes blacklist CLI commands:
      add <mac>    - Adds MAC to blacklist permanently
      remove <mac> - Removes MAC from blacklist
      list         - Displays all blacklisted MACs
    """
    if not args_list:
        print(colorize_brackets(f"{BOLD}{RED}[-] Error: No blacklist action specified.{RESET}"))
        print(colorize_brackets(f"{BOLD}{YELLOW}Usage:{RESET} cafe-chameleon blacklist add <mac> | remove <mac> | list"))
        return 1

    action = args_list[0].strip().lower()
    target_file = filepath or BLACKLIST_FILE

    if action in ("add", "+", "--add", "-a"):
        if len(args_list) < 2:
            print(colorize_brackets(f"{BOLD}{RED}[-] Error: Missing MAC address to add.{RESET}"))
            print(colorize_brackets(f"{BOLD}{YELLOW}Usage:{RESET} cafe-chameleon blacklist add <mac>"))
            return 1
        mac_arg = args_list[1]
        success, msg = add_to_blacklist(mac_arg, filepath=target_file)
        if success:
            print(colorize_brackets(f"{BOLD}{GREEN}[+] {msg}{RESET}"))
            return 0
        else:
            print(colorize_brackets(f"{BOLD}{RED}[-] {msg}{RESET}"))
            return 1

    elif action in ("remove", "rm", "del", "delete", "-", "--remove", "-r"):
        if len(args_list) < 2:
            print(colorize_brackets(f"{BOLD}{RED}[-] Error: Missing MAC address to remove.{RESET}"))
            print(colorize_brackets(f"{BOLD}{YELLOW}Usage:{RESET} cafe-chameleon blacklist remove <mac>"))
            return 1
        mac_arg = args_list[1]
        success, msg = remove_from_blacklist(mac_arg, filepath=target_file)
        if success:
            print(colorize_brackets(f"{BOLD}{GREEN}[+] {msg}{RESET}"))
            return 0
        else:
            print(colorize_brackets(f"{BOLD}{RED}[-] {msg}{RESET}"))
            return 1

    elif action in ("list", "ls", "show", "--list", "-l"):
        entries = list_blacklist(filepath=target_file)
        if not entries:
            print(colorize_brackets(f"{BOLD}{YELLOW}[i] Blacklist is empty (no MAC addresses blacklisted).{RESET}"))
        else:
            print(colorize_brackets(f"\n{BOLD}{CYAN}── BLACKLISTED CLIENT / BSSID MAC ADDRESSES ────────────────────────────{RESET}"))
            for idx, m in enumerate(entries, start=1):
                print(colorize_brackets(f"  [{idx}] {BOLD}{m}{RESET}"))
            print(colorize_brackets(f"{BOLD}{CYAN}────────────────────────────────────────────────────────────────────────{RESET}"))
            print(colorize_brackets(f"{BOLD}{GREEN}[+] Total: {len(entries)} blacklisted MAC address(es) saved in {target_file}{RESET}\n"))
        return 0

    else:
        print(colorize_brackets(f"{BOLD}{RED}[-] Unknown blacklist action: '{action}'.{RESET}"))
        print(colorize_brackets(f"{BOLD}{YELLOW}Usage:{RESET} cafe-chameleon blacklist add <mac> | remove <mac> | list"))
        return 1
