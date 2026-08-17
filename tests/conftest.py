"""
tests/conftest.py - Pytest global configuration and fixtures.
"""

import os
import subprocess
import pytest

from cafe_chameleon.utils import process


# List of binary/command patterns that should NEVER execute against the host machine in tests
MUTATING_NETWORK_PATTERNS = [
    "ip addr flush",
    "ip route flush",
    "ip addr add",
    "ip -4 addr add",
    "ip -6 addr add",
    "ip link set",
    "ip route replace",
    "ip route add",
    "nmcli",
    "macchanger",
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "create_ap",
    "hostapd",
    "dnsmasq",
    "pkill",
    "killall",
    "systemctl",
    "service",
    "sysctl",
    "arping",
    "ping",
    "iw dev",
    "iw list",
    "iptables",
    "nftables",
]


@pytest.fixture(autouse=True)
def guard_host_network(monkeypatch):
    """
    Global safety guard that intercepts any unmocked subprocess / _run calls
    that attempt to execute network-altering or hardware-modifying commands.
    Prevents tests from mutating host networking, dropping Wi-Fi links,
    flushing IP addresses, or sending live radio/packet transmissions.
    """
    orig_run = process._run
    orig_sub_run = subprocess.run
    orig_sub_popen = subprocess.Popen

    def is_dangerous(cmd):
        cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        cmd_lower = cmd_str.lower()
        for pattern in MUTATING_NETWORK_PATTERNS:
            if pattern in cmd_lower:
                return True, cmd_lower
        return False, cmd_lower

    def safe_run(cmd, debug=None, timeout=None):
        dangerous, cmd_lower = is_dangerous(cmd)
        if dangerous:
            if "show" in cmd_lower or "list" in cmd_lower or "info" in cmd_lower or "link" in cmd_lower:
                if "ip -o -4 route" in cmd_lower or "default" in cmd_lower:
                    return 0, "default via 192.168.1.1 dev wlan0"
                if "ip -o -4 addr" in cmd_lower or "ip -0 addr" in cmd_lower:
                    return 0, "2: wlan0    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0"
                if "ip -o link" in cmd_lower or "ip link" in cmd_lower:
                    return 0, "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000"
                if "iw dev" in cmd_lower and "info" in cmd_lower:
                    return 0, "Interface wlan0\n\ttype managed"
                if "iw dev" in cmd_lower and "link" in cmd_lower:
                    return 0, "Connected to 00:11:22:33:44:55 (on wlan0)\n\tSSID: TestWiFi\n\tfreq: 2437"
            # For any mutating command (e.g. flush, add, del, down, up, nmcli, pkill, create_ap)
            return 0, ""
        return orig_run(cmd, debug=debug, timeout=timeout)

    def safe_subprocess_run(cmd, *args, **kwargs):
        dangerous, _ = is_dangerous(cmd)
        if dangerous:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        return orig_sub_run(cmd, *args, **kwargs)

    monkeypatch.setattr(process, "_run", safe_run)
    monkeypatch.setattr(subprocess, "run", safe_subprocess_run)


@pytest.fixture(autouse=True)
def isolate_blacklist_file(tmp_path, monkeypatch):
    """
    Isolates BLACKLIST_FILE to a temporary directory for every test.
    Ensures that test suites never read, mutate, or delete the user's
    persistent blacklist.txt database.
    """
    temp_bl = str(tmp_path / "blacklist.txt")
    monkeypatch.setattr("cafe_chameleon.config.BLACKLIST_FILE", temp_bl)
    monkeypatch.setattr("cafe_chameleon.utils.blacklist.BLACKLIST_FILE", temp_bl)
    yield temp_bl
    if os.path.exists(temp_bl):
        try:
            os.remove(temp_bl)
        except OSError:
            pass
