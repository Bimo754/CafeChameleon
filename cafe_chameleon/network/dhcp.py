"""
cafe_chameleon.network.dhcp - DHCP lease querying module (dhclient & Scapy fallback).
"""

import os
import random
import re
import shutil

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_hijack


def query_dhcp_lease_ip(interface: str, target_mac: str | None = None, timeout: float = 2.0) -> str | None:
    """
    Issues a DHCP Discover packet for a specific hardware MAC address
    to retrieve its leased IPv4 address.
    """
    from cafe_chameleon.network.sysfs import wait_for_carrier
    from cafe_chameleon.ui.console import set_hijack_status

    if target_mac:
        set_hijack_status(mac=target_mac, technique="DHCP Lease Query", clear_section2=True)
    else:
        set_hijack_status(technique="DHCP Lease Query", clear_section2=True)
    log_hijack("[*] Preparing adapter link for DHCP request...")

    # Kill any stale dhclient processes on this interface first
    _run(f"pkill -9 -f 'dhclient.*{interface}'", debug=False)

    # Ensure link is up and carrier active before sending raw frames
    _run(f"ip link set dev {interface} up", debug=False, timeout=2.0)
    wait_for_carrier(interface, timeout=5.0)

    try:
        from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4
        # 1. Primary: Scapy Raw Socket DHCP DISCOVER with target MAC Client-ID & random XID
        try:
            from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp1, get_if_hwaddr
            mac_str = target_mac or get_if_hwaddr(interface)
            mac_bytes = bytes.fromhex(mac_str.replace(":", ""))
            rand_xid = random.randint(1, 0xFFFFFFFF)

            dhcp_discover = (
                Ether(src=mac_str.lower(), dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac_bytes.ljust(16, b"\x00"), xid=rand_xid, flags=0x8000) /
                DHCP(options=[
                    ("message-type", "discover"),
                    ("client_id", b"\x01" + mac_bytes),
                    ("param_req_list", [1, 3, 6, 15]),
                    "end"
                ])
            )
            log_hijack("[*] Transmitting DHCP DISCOVER request...")
            ans = srp1(dhcp_discover, iface=interface, timeout=timeout, verbose=False)
            if ans and ans.haslayer(BOOTP):
                bootp = ans[BOOTP]
                yiaddr = str(getattr(bootp, "yiaddr", "0.0.0.0"))
                ciaddr = str(getattr(bootp, "ciaddr", "0.0.0.0"))
                if is_valid_ipv4(yiaddr):
                    log_hijack(f"\033[92m[+] DHCP offered IP: {yiaddr}\033[0m")
                    return yiaddr
                if is_valid_ipv4(ciaddr):
                    log_hijack(f"\033[92m[+] DHCP offered IP: {ciaddr}\033[0m")
                    return ciaddr
        except Exception:
            pass

        # 2. Secondary Fallback: dhclient in foreground mode (-d -1) without daemonizing
        try:
            if shutil.which("dhclient"):
                log_hijack("[*] Requesting lease via dhclient fallback...")
                pid_file = f"/tmp/dhcp_{interface}.pid"
                lease_file = f"/tmp/dhcp_{interface}.leases"
                conf_file = f"/tmp/dhcp_{interface}.conf"

                for fpath in (pid_file, lease_file, conf_file):
                    if os.path.exists(fpath):
                        try:
                            os.remove(fpath)
                        except Exception:
                            pass

                mac_str = target_mac or "00:11:22:33:44:55"
                with open(conf_file, "w") as f:
                    f.write(f'send dhcp-client-identifier 01:{mac_str.lower()};\n')

                # Force foreground (-d) so dhclient does NOT daemonize in background
                _run(f"dhclient -d -1 -timeout 3 -cf {conf_file} -pf {pid_file} -lf {lease_file} {interface}", debug=False, timeout=4.0)
                _run(f"pkill -9 -f 'dhclient.*{interface}'", debug=False)

                rc, out = _run(f"ip -o -4 addr show dev {interface}", debug=False, timeout=2.0)

                if os.path.exists(pid_file):
                    try:
                        with open(pid_file) as pf:
                            pid = pf.read().strip()
                            if pid.isdigit():
                                _run(f"kill -9 {pid}", debug=False)
                    except Exception:
                        pass

                if out:
                    m = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
                    if m:
                        ip = m.group(1)
                        if is_valid_ipv4(ip):
                            log_hijack(f"\033[92m[+] dhclient assigned IP: {ip}\033[0m")
                            return ip
        except Exception:
            pass
    finally:
        _run(f"pkill -9 -f 'dhclient.*{interface}'", debug=False)

    log_hijack("\033[91m[-] DHCP query timeout / no offer received\033[0m")
    return None


