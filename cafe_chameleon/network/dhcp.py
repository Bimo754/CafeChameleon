"""
cafe_chameleon.network.dhcp - DHCP lease querying module (dhclient & Scapy fallback).
"""

import os
import random
import re
import shutil

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_hijack


def query_dhcp_lease_ip(interface: str, target_mac: str | None = None, timeout: float = 3.0) -> str | None:
    """
    Issues a DHCP Discover/Request packet for a specific hardware MAC address
    to retrieve its exact leased IPv4 address directly from the network's DHCP server.
    Uses Scapy raw socket DISCOVER with explicit hardware Client-ID as the primary method,
    bypassing system dhclient DUID caches. Fallbacks to dhclient with config overrides.
    """
    log_hijack(f"[*] Querying DHCP lease for interface {interface}...")

    # Flush any previous IP configuration on the interface before querying
    _run(f"ip addr flush dev {interface}", debug=False, timeout=2.0)

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
        ans = srp1(dhcp_discover, iface=interface, timeout=timeout, verbose=False)
        if ans and ans.haslayer(BOOTP):
            bootp = ans[BOOTP]
            yiaddr = str(getattr(bootp, "yiaddr", "0.0.0.0"))
            ciaddr = str(getattr(bootp, "ciaddr", "0.0.0.0"))
            if yiaddr not in ("0.0.0.0", "255.255.255.255"):
                log_hijack(f"[+] DHCP server offered IP {yiaddr} for MAC {mac_str}")
                return yiaddr
            if ciaddr not in ("0.0.0.0", "255.255.255.255"):
                log_hijack(f"[+] DHCP server offered IP {ciaddr} for MAC {mac_str}")
                return ciaddr
    except Exception:
        pass

    # 2. Secondary Fallback: dhclient with custom client-id config override
    try:
        if shutil.which("dhclient"):
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

            _run(f"dhclient -r {interface}", debug=False, timeout=2.0)
            _run(f"dhclient -1 -timeout 3 -cf {conf_file} -pf {pid_file} -lf {lease_file} {interface}", debug=False, timeout=4.0)
            rc, out = _run(f"ip -o -4 addr show dev {interface}", debug=False, timeout=2.0)
            if out:
                m = re.search(r"inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
                if m:
                    ip = m.group(1)
                    if ip not in ("0.0.0.0", "127.0.0.1"):
                        return ip
    except Exception:
        pass

    return None
