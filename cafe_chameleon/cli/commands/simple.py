"""
cafe_chameleon.cli.commands.simple - Command handler for 'simple' (Layer 2 ARP host enumeration & takeover).
"""

import ipaddress
import sys
import time

from cafe_chameleon.utils.signals import register_signal_handler, restore_and_exit, ScanSkipInterrupt, HijackSkipInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.ui.console import log_scan, log_main, log_plus, log_warning
from cafe_chameleon.ui.prompts import ask_proceed, ask_restore
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.hijack import hijack, restore
from cafe_chameleon.scanners.detector import auto_detect_network_params, get_interface_details
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from cafe_chameleon.scanners.orchestrator import deep_scan_subnet


def run_simple(args, quiet_header: bool = False) -> bool:
    """Main subcommand handler for 'simple' mode (Layer 2 ARP scan & host takeover)."""
    register_signal_handler()

    interface = getattr(args, "interface", None) or "wlan0"
    wait_for_carrier(interface, timeout=5.0)
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

    profile = getattr(args, "profile", None)
    set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, callback=restore, profile=profile)

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
            try:
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
                    profile = getattr(args, "profile", None)
                    log_scan("Testing discovered hosts for internet access...")
                    for host in unique_hosts:
                        try:
                            is_gw = (gw_ip and host["ip"] == gw_ip) or (gw_mac and host["mac"].lower() == gw_mac.lower())
                            if not is_gw:
                                hijack_success = hijack(interface, host['ip'], host['mac'], netmask, broadcast, gw_ip, profile=profile, bssid=auto_params.get("gateway_mac"))
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
                        except HijackSkipInterrupt:
                            log_scan(f"\033[93m[-] Ctrl+C in Impersonation Engine! Skipping target host {host['ip']}...\033[0m")
                            continue
                else:
                    log_scan(f"[Info] No active user hosts found on block {sub}.")
            except ScanSkipInterrupt:
                log_scan(f"\033[93m[-] Ctrl+C in Subnet Scanner! Skipping subnet block {sub} & stopping impersonations...\033[0m")
                log_main(f"\033[93m[-] Skipping subnet block {sub} (Ctrl+C in Subnet Scanner)...\033[0m")
                continue

    except KeyboardInterrupt:
        if quiet_header:
            raise
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
