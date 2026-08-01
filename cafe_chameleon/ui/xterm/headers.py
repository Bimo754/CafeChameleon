"""
cafe_chameleon.ui.xterm.headers - Window header and section text generator functions.
"""


def format_main_header(interface: str, profile: str, ssid: str, status: str) -> str:
    line1 = f"\033[1;37mInterface:\033[0m \033[1;38;5;215m{interface}\033[0m | \033[1;37mProfile:\033[0m \033[1;38;5;215m{profile}\033[0m | \033[1;37mSSID:\033[0m \033[1;38;5;215m{ssid}\033[0m\033[K"
    line2 = f"\033[1;37mStatus:\033[0m \033[1;33m{status}\033[0m\033[K"
    line3 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
    return f"{line1}\n{line2}\n{line3}"


def format_air_header(air_mode: str) -> str:
    if air_mode == "Monitor":
        mode_colored = "\033[38;5;208mMonitor\033[0m"
    else:
        mode_colored = "\033[1;32mManaged\033[0m"
    line1 = f"\033[1;37mMode:\033[0m {mode_colored}\033[K"
    line2 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
    return f"{line1}\n{line2}"


def format_hijack_header(hijack_ip: str | None, hijack_technique: str) -> str:
    if hijack_ip:
        ip_str = f"\033[1;32m{hijack_ip}\033[0m"
    else:
        ip_str = "\033[1;31mNot Found\033[0m"

    line1 = f"\033[1;37mIP:\033[0m {ip_str}\033[K"
    line2 = f"\033[1;37mTechnique:\033[0m \033[1;33m{hijack_technique}\033[0m\033[K"
    line3 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
    return f"{line1}\n{line2}\n{line3}"


def format_scan_header(scan_subnet: str, scan_hosts_count: int, scan_type: str) -> str:
    line1 = f"\033[1;37mSubnet:\033[0m \033[1;36m{scan_subnet}\033[0m | \033[1;37mHosts Found:\033[0m \033[1;32m{scan_hosts_count}\033[0m | \033[1;37mActive Scan:\033[0m \033[1;33m{scan_type}\033[0m\033[K"
    line2 = "\033[1;30m───────────────────────────────────────────────────────────────────────\033[0m\033[K"
    return f"{line1}\n{line2}"
