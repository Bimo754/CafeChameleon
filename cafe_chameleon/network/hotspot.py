"""
cafe_chameleon.network.hotspot - Wi-Fi hotspot creation and repeater sharing using create_ap.
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import time

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import (
    log_plus,
    log_minus,
    log_info,
    log_step,
    log_wait,
    log_warning
)
from cafe_chameleon.scanners.detector import auto_detect_network_params


def check_ap_mode_support(interface: str = "wlan0") -> tuple[bool, str]:
    """
    Checks if the wireless interface/chip supports Access Point (AP) mode
    and AP-STA concurrency using iw list.
    """
    trace(f"[FEATURE] Checking AP mode & concurrency capability on {interface}")
    rc, out = _run(["iw", "list"], debug=False)
    if rc != 0 or not out:
        return False, "Failed to execute 'iw list' to verify wireless capabilities."

    # 1. Check supported interface modes for AP
    supported_modes_match = re.search(r"Supported interface modes:(.*?)(?:valid interface combinations|\Z)", out, re.DOTALL | re.IGNORECASE)
    has_ap_mode = False
    if supported_modes_match:
        modes_section = supported_modes_match.group(1)
        if re.search(r"\bAP\b", modes_section):
            has_ap_mode = True

    if not has_ap_mode:
        # Fallback search anywhere in output
        if "* AP" in out or "AP/VLAN" in out:
            has_ap_mode = True

    if not has_ap_mode:
        return False, f"Interface '{interface}' does not support AP (Access Point) mode."

    # 2. Check valid interface combinations for AP-STA concurrency
    concurrency_match = re.search(r"valid interface combinations:(.*?)(?:HT Capability|\Z)", out, re.DOTALL | re.IGNORECASE)
    has_concurrency = False
    if concurrency_match:
        comb_section = concurrency_match.group(1)
        # Look for combination with both managed (STA) and AP
        if ("managed" in comb_section or "station" in comb_section) and "AP" in comb_section:
            has_concurrency = True

    if has_concurrency:
        return True, f"Interface '{interface}' supports AP mode and AP-STA concurrency."
    else:
        return True, f"Interface '{interface}' supports AP mode (concurrency not explicitly advertised)."


def clean_hotspot_interfaces(ap_iface: str = "ap0", parent_iface: str = "wlan0") -> None:
    """Cleans up leftover hotspot virtual devices and restores NetworkManager settings."""
    trace(f"[FEATURE] Cleaning hotspot interface {ap_iface} and restoring {parent_iface}")
    # Stop create_ap instance if running
    if shutil.which("create_ap"):
        _run(["create_ap", "--stop", ap_iface], debug=False)

    # Delete virtual interface ap0 if it exists
    rc, iw_dev = _run(["iw", "dev"], debug=False)
    if ap_iface in iw_dev:
        _run(["iw", "dev", ap_iface, "del"], debug=False)

    # Restore NetworkManager management
    _run(["nmcli", "device", "set", parent_iface, "managed", "yes"], debug=False)


def get_interface_channel_and_band(interface: str = "wlan0") -> tuple[int | None, str]:
    """Retrieves current connected channel and frequency band (2.4 or 5) for the interface."""
    rc, iw_out = _run(["iw", "dev", interface, "link"], debug=False)
    if rc == 0 and iw_out:
        freq_match = re.search(r"freq:\s*(\d+)", iw_out)
        if freq_match:
            freq = int(freq_match.group(1))
            if 2400 <= freq <= 2500:
                chan = int((freq - 2407) / 5)
                return chan, "2.4"
            elif 5000 <= freq <= 5900:
                chan = int((freq - 5000) / 5)
                return chan, "5"

    rc, out = _run(["nmcli", "-t", "-f", "active,chan,freq", "dev", "wifi"], debug=False)
    for line in out.splitlines():
        if line.startswith("yes:"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1].isdigit():
                chan = int(parts[1])
                band = "5" if chan > 14 else "2.4"
                return chan, band

    return None, "2.4"


def share_wifi_hotspot(
    hotspot_name: str,
    password: str,
    interface: str | None = None,
    channel: int | None = None
) -> bool:
    """
    Shares the active Wi-Fi connection via an AP hotspot using create_ap.
    Verifies hardware AP support, enables IP forwarding, manages ap0 virtual interface,
    and runs create_ap interactively until stopped with Ctrl+C.
    """
    if not shutil.which("create_ap"):
        log_minus("Error: 'create_ap' is not installed on this system.")
        log_info("Please install create_ap (see Desktop/linux-wifi-hotspot/shareWifi.md):")
        log_info("  sudo apt update && sudo apt install -y hostapd dnsmasq iptables iw git")
        log_info("  git clone https://github.com/lakinduakash/linux-wifi-hotspot.git")
        log_info("  cd linux-wifi-hotspot && sudo make -C src/scripts install-cli-only\n")
        return False

    if not hotspot_name or not hotspot_name.strip():
        log_minus("Error: Hotspot name (SSID) cannot be empty.")
        return False

    if password and len(password) < 8:
        log_minus("Error: Hotspot password must be at least 8 characters for WPA2.")
        return False

    params = auto_detect_network_params(target_iface=interface)
    iface = interface or params.get("interface") or "wlan0"

    # Check hardware AP mode capability
    supported, msg = check_ap_mode_support(iface)
    if not supported:
        log_minus(f"Error: {msg}")
        return False

    trace(f"[FEATURE] Starting Wi-Fi hotspot sharing: SSID='{hotspot_name}' on {iface}")
    log_step(f"Preparing Wi-Fi Hotspot on interface '{iface}'...")
    log_info(f"Hardware Check: {msg}")

    # 1. Enable IPv4 packet forwarding
    log_wait("Enabling IPv4 packet forwarding (sysctl net.ipv4.ip_forward=1)...")
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], debug=False)
    try:
        if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
    except Exception:
        pass

    # 2. Clean up lingering virtual interfaces
    clean_hotspot_interfaces(ap_iface="ap0", parent_iface=iface)

    # 3. Tell NetworkManager not to interfere with virtual ap0
    log_wait("Configuring NetworkManager to ignore virtual ap0...")
    _run(["nmcli", "device", "set", "ap0", "managed", "no"], debug=False)

    # 4. Resolve operating channel and frequency band
    current_chan, band = get_interface_channel_and_band(iface)
    use_chan = channel or current_chan

    cmd = ["create_ap"]
    if use_chan:
        cmd.extend(["-c", str(use_chan), "--freq-band", band])
    cmd.extend([iface, iface, hotspot_name, password])

    log_step(f"Launching Wi-Fi Hotspot '{hotspot_name}'...")
    log_info(f"Hotspot SSID : {hotspot_name}")
    log_info(f"Password     : {password}")
    log_info(f"Interface    : {iface} (Upstream & Virtual AP)")
    if use_chan:
        log_info(f"Channel      : {use_chan} ({band} GHz)")
    log_info("Press Ctrl+C to stop the hotspot.\n")

    proc = None
    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
        return proc.returncode == 0
    except KeyboardInterrupt:
        log_info("\nStopping Wi-Fi Hotspot (Ctrl+C)...")
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        return True
    except Exception as e:
        log_minus(f"Hotspot execution error: {e}")
        return False
    finally:
        clean_hotspot_interfaces(ap_iface="ap0", parent_iface=iface)
        log_plus("Hotspot stopped and interface restored.")
