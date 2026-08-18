"""
cafe_chameleon.modes.simple.runner - Main execution runner for Simple mode (Layer 2 ARP host discovery & takeover).
"""

from cafe_chameleon.utils.signals import register_signal_handler, restore_and_exit, ScanSkipInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import (
    log_scan,
    log_main,
    log_plus,
    set_scan_status,
    set_main_status
)
from cafe_chameleon.ui.prompts import ask_restore
from cafe_chameleon.network.internet import has_internet
from cafe_chameleon.network.sysfs import wait_for_carrier
from cafe_chameleon.network.mac import get_attack_mac, set_mac_address
from cafe_chameleon.scanners.detector import auto_detect_network_params, get_interface_details
from cafe_chameleon.scanners.arp_scanner import scan_subnet
from cafe_chameleon.scanners.orchestrator import deep_scan_subnet
from cafe_chameleon.scanners.air import is_monitor_mode_active, set_managed_mode

from .subnet_helper import prepare_target_subnet, split_subnets_into_blocks
from .takeover import test_discovered_hosts
from cafe_chameleon.utils.blacklist import is_blacklisted, load_blacklist


def run_simple(args, quiet_header: bool = False) -> bool:
    """Main subcommand handler for 'simple' mode (Layer 2 ARP scan & host takeover)."""
    register_signal_handler()

    interface = getattr(args, "interface", None) or "wlan0"
    profile = getattr(args, "profile", None)
    trace(f"[FEATURE] Initializing Simple mode execution on interface {interface}")
    set_restore_params(interface, "", "", "", "", profile=profile)

    if is_monitor_mode_active(interface):
        trace(f"[FEATURE] Interface {interface} is in monitor mode; restoring to managed mode for subnet scan")
        set_managed_mode(interface)

    wait_for_carrier(interface, timeout=5.0)
    auto_params = auto_detect_network_params(target_iface=interface)
    local_ip, local_mac = get_interface_details(interface)

    subnet_arg = getattr(args, "subnet", None)
    is_deep = bool(subnet_arg)

    network = prepare_target_subnet(args, auto_params, local_ip, quiet_header=quiet_header)
    if not network:
        return False

    target_str = str(network)
    set_scan_status(subnet=target_str, count=0, scan_type="Deep Scan" if is_deep else "Nmap Ping Scan")
    profile = getattr(args, "profile", None)
    set_main_status(interface=interface, profile=profile, ssid=auto_params.get("ssid"), status="Subnet Scanning")

    if not quiet_header:
        log_main(f"[*] Starting Subnet Scanning on {target_str}...")

    subnets = split_subnets_into_blocks(network)

    gw_ip = auto_params.get("gateway_ip", "")
    gw_mac = auto_params.get("gateway_mac", "")
    netmask = auto_params.get("cidr", "").split("/")[1] if auto_params.get("cidr") and "/" in auto_params.get("cidr") else "24"
    broadcast = auto_params.get("broadcast") or ""
    if not broadcast or str(broadcast).strip().lower() in ("none", "", "null"):
        try:
            import ipaddress
            net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            broadcast = str(net.broadcast_address)
        except Exception:
            broadcast = "+"
    ipmask = auto_params.get("cidr", f"{local_ip}/{netmask}")

    set_restore_params(interface, local_mac, ipmask, broadcast, gw_ip, profile=profile)

    attack_mac = get_attack_mac(interface)
    trace(f"[FEATURE] Applying attack MAC {attack_mac} on {interface} for simple mode scan")
    set_mac_address(interface, attack_mac, profile=profile)

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
                set_scan_status(subnet=sub_str, count=len(discovered_devices), scan_type="Deep Scan" if is_deep else "Nmap Ping Scan")

                if is_deep:
                    hosts = deep_scan_subnet(sub, interface, gateway_ip=gw_ip, gateway_mac=gw_mac, local_ip=local_ip, local_mac=local_mac, duration=30)
                else:
                    hosts = scan_subnet(sub, interface, parent_net=network, gateway_ip=gw_ip, gateway_mac=gw_mac)

                unique_hosts = []
                seen_ips = {h["ip"] for h in discovered_devices}
                blacklist = load_blacklist()
                for h in hosts:
                    if h["ip"] == local_ip:
                        continue
                    if is_blacklisted(h.get("mac", ""), blacklist):
                        trace(f"[FEATURE] Skipping blacklisted host MAC: {h['mac']} (IP: {h['ip']})")
                        log_scan(f"  [-] Blacklisted host skipped: {h['ip']} ({h['mac']})")
                        continue
                    if h["ip"] not in seen_ips:
                        seen_ips.add(h["ip"])
                        unique_hosts.append(h)

                if unique_hosts:
                    log_scan(f"[+] Found {len(unique_hosts)} active host(s) on block {sub_str}:")
                    for host in unique_hosts:
                        tag = ""
                        if gw_ip and host["ip"] == gw_ip:
                            tag = " [GATEWAY IP]"
                        elif gw_mac and host["mac"].lower() == gw_mac.lower():
                            tag = " [GATEWAY MAC]"
                        log_scan(f"  -> {host['ip']:<15} {host['mac']}{tag}")
                        discovered_devices.append(host)

                    set_scan_status(count=len(discovered_devices))

                    takeover_success = test_discovered_hosts(unique_hosts, interface, gw_ip, gw_mac, netmask, broadcast, local_mac, ipmask, profile, args)
                    if takeover_success:
                        return True

            except ScanSkipInterrupt:
                log_scan(f"\033[93m[-] Skipping subnet block {sub} (Ctrl+C)...\033[0m")
                log_main(f"\033[93m[-] Skipping subnet block {sub} (Ctrl+C)...\033[0m")
                continue

    except KeyboardInterrupt:
        if is_monitor_mode_active(interface):
            set_managed_mode(interface)
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
            from cafe_chameleon.network.nmcli import release_interface
            release_interface(interface=interface, profile=profile)
        else:
            log_plus("Keeping current MAC and network configuration.")
    else:
        if has_acc:
            log_plus("Internet verified. Preserving working MAC and network configuration.")
    return has_acc
