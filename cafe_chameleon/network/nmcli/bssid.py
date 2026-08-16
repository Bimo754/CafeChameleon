"""
cafe_chameleon.network.nmcli.bssid - BSSID scanning, BSSID locking, and active BSSID retrieval.
"""

import re
import shutil
import time

from cafe_chameleon.models import BSSIDTarget
from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace
from cafe_chameleon.ui.console import log_plus, log_warning, log_minus, log_step, log_wait
from .profiles import get_active_profile, get_ssid_for_profile

DIGIT_REGEX = re.compile(r"[^\d]")
CONNECTED_MAC_REGEX = re.compile(r"Connected to\s+([0-9a-fa-f:]+)", re.IGNORECASE)
IW_BSS_MAC_REGEX = re.compile(r"([0-9a-fA-F:]{17})")
IW_CHAN_REGEX = re.compile(r"channel\s*(\d+)")
IW_FREQ_REGEX = re.compile(r"freq:\s*([0-9.]+)")
IW_SIGNAL_REGEX = re.compile(r"signal:\s*([-0-9.]+)\s*dBm")


def freq_to_channel(freq: int) -> int:
    """Converts 802.11 frequency in MHz to standard channel number."""
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    elif freq == 2484:
        return 14
    elif 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    elif 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def dbm_to_signal_percentage(dbm: float) -> int:
    """Converts RSSI in dBm to signal percentage (0-100%)."""
    return max(0, min(100, int(2 * (dbm + 100))))


def trigger_wifi_rescan(target_ssid: str | None = None) -> None:
    """
    Triggers an active 802.11 Wi-Fi rescan via nmcli.
    If target_ssid is provided, first attempts a directed probe request rescan specifically for that SSID.
    """
    if target_ssid:
        try:
            rc, _ = _run(["nmcli", "device", "wifi", "rescan", "ssid", target_ssid], debug=False)
            if rc == 0:
                return
        except StopIteration:
            raise
        except Exception:
            pass
    try:
        _run(["nmcli", "device", "wifi", "rescan"], debug=False)
    except StopIteration:
        raise
    except Exception:
        pass


def parse_nmcli_wifi_list_output(output: str, target_ssid: str | None = None) -> list[BSSIDTarget]:
    """Parses raw text output from `nmcli dev wifi list` into a list of BSSIDTarget."""
    results = []
    seen = set()
    for line in output.splitlines():
        if not line:
            continue
        unescaped = line.replace(r"\:", "\x00")
        parts = unescaped.split(":")
        if len(parts) >= 6:
            bssid = parts[0].replace("\x00", ":").strip()
            ssid = parts[1].replace("\x00", ":").strip()
            signal = parts[2].replace("\x00", ":").strip()
            chan = parts[3].replace("\x00", ":").strip()
            security = parts[4].replace("\x00", ":").strip()
            active = parts[5].replace("\x00", ":").strip().lower() in ("yes", "*", "true")
            bars = parts[6].replace("\x00", ":").strip() if len(parts) >= 7 else ""
            mode = parts[7].replace("\x00", ":").strip() if len(parts) >= 8 else ""
            rate = parts[8].replace("\x00", ":").strip() if len(parts) >= 9 else ""

            if target_ssid:
                if ssid.lower() != target_ssid.lower() and target_ssid.lower() not in ssid.lower():
                    continue

            if bssid and bssid not in seen:
                seen.add(bssid)
                results.append(BSSIDTarget(
                    bssid=bssid,
                    ssid=ssid,
                    signal=signal,
                    chan=chan,
                    security=security,
                    active=active,
                    bars=bars,
                    mode=mode,
                    rate=rate
                ))
        elif len(parts) == 5:
            bssid = parts[0].replace("\x00", ":").strip()
            ssid = parts[1].replace("\x00", ":").strip()
            signal = parts[2].replace("\x00", ":").strip()
            chan = parts[3].replace("\x00", ":").strip()
            security = ""
            active = parts[4].replace("\x00", ":").strip().lower() in ("yes", "*", "true")

            if target_ssid:
                if ssid.lower() != target_ssid.lower() and target_ssid.lower() not in ssid.lower():
                    continue

            if bssid and bssid not in seen:
                seen.add(bssid)
                results.append(BSSIDTarget(
                    bssid=bssid,
                    ssid=ssid,
                    signal=signal,
                    chan=chan,
                    security=security,
                    active=active
                ))
    return results


def query_nmcli_wifi_list(target_ssid: str | None = None) -> list[BSSIDTarget]:
    """Queries `nmcli dev wifi list` with comprehensive and standard format fallbacks."""
    try:
        rc, out = _run(["nmcli", "-t", "-f", "BSSID,SSID,SIGNAL,CHAN,SECURITY,ACTIVE,BARS,MODE,RATE", "dev", "wifi", "list"], debug=False)
        if rc == 0 and out.strip():
            return parse_nmcli_wifi_list_output(out, target_ssid=target_ssid)
    except StopIteration:
        raise
    except Exception:
        pass

    try:
        rc, out = _run(["nmcli", "-t", "-f", "BSSID,SSID,SIGNAL,CHAN,SECURITY,ACTIVE", "dev", "wifi", "list"], debug=False)
        if rc == 0 and out.strip():
            return parse_nmcli_wifi_list_output(out, target_ssid=target_ssid)
    except StopIteration:
        raise
    except Exception:
        pass

    return []


def parse_iw_scan_dump(output: str, target_ssid: str | None = None) -> list[BSSIDTarget]:
    """Parses output from `iw dev <iface> scan dump` into a list of BSSIDTarget objects."""
    bss_blocks = output.split("BSS ")
    results = []
    seen = set()
    for block in bss_blocks:
        if not block.strip():
            continue
        lines = block.splitlines()
        first_line = lines[0]
        mac_m = IW_BSS_MAC_REGEX.search(first_line)
        if not mac_m:
            continue
        bssid = mac_m.group(1).upper()
        active = "associated" in first_line.lower()
        ssid = ""
        chan = ""
        signal = ""
        has_rsn = "RSN:" in block
        has_wpa = "WPA:" in block
        has_privacy = "Privacy" in block or "privacy" in block
        has_sae = "SAE" in block or "sae" in block

        if has_rsn and has_sae:
            security = "WPA3"
        elif has_rsn and has_wpa:
            security = "WPA1 WPA2"
        elif has_rsn:
            security = "WPA2"
        elif has_wpa:
            security = "WPA"
        elif has_privacy:
            security = "WEP"
        else:
            security = ""

        for line in lines[1:]:
            s_line = line.strip()
            if s_line.startswith("SSID:"):
                raw_ssid = s_line[5:].strip()
                try:
                    ssid = raw_ssid.encode("latin1").decode("unicode_escape").encode("latin1").decode("utf-8", errors="ignore")
                except Exception:
                    ssid = raw_ssid
            elif s_line.startswith("DS Parameter set: channel"):
                ch_m = IW_CHAN_REGEX.search(s_line)
                if ch_m:
                    chan = ch_m.group(1)
            elif s_line.startswith("freq:") and not chan:
                fr_m = IW_FREQ_REGEX.search(s_line)
                if fr_m:
                    try:
                        freq_val = int(float(fr_m.group(1)))
                        ch_num = freq_to_channel(freq_val)
                        if ch_num > 0:
                            chan = str(ch_num)
                    except (ValueError, TypeError):
                        pass
            elif s_line.startswith("signal:"):
                sig_m = IW_SIGNAL_REGEX.search(s_line)
                if sig_m:
                    try:
                        dbm = float(sig_m.group(1))
                        signal = str(dbm_to_signal_percentage(dbm))
                    except (ValueError, TypeError):
                        pass

        if target_ssid:
            if ssid.lower() != target_ssid.lower() and target_ssid.lower() not in ssid.lower():
                continue

        if bssid and bssid not in seen:
            seen.add(bssid)
            results.append(BSSIDTarget(
                bssid=bssid,
                ssid=ssid,
                signal=signal or "50",
                chan=chan or "1",
                security=security,
                active=active
            ))
    return results


def query_iw_scan_dump(interface: str | None = None, target_ssid: str | None = None) -> list[BSSIDTarget]:
    """Queries kernel nl80211 BSS table via `iw dev <iface> scan dump`."""
    if not shutil.which("iw"):
        return []
    iface = interface or "wlan0"
    try:
        rc, out = _run(["iw", "dev", iface, "scan", "dump"], debug=False)
        if rc == 0 and out.strip():
            return parse_iw_scan_dump(out, target_ssid=target_ssid)
    except StopIteration:
        raise
    except Exception:
        pass
    return []


def merge_bssid_targets(target_map: dict[str, BSSIDTarget], new_targets: list[BSSIDTarget]) -> None:
    """Merges new BSSID targets into dictionary map preserving most complete properties."""
    def parse_sig(val) -> int:
        clean = DIGIT_REGEX.sub("", str(val))
        return int(clean) if clean else 0

    for item in new_targets:
        if not item or not item.bssid:
            continue
        key = item.bssid.upper()
        if key not in target_map:
            target_map[key] = item
        else:
            existing = target_map[key]
            if parse_sig(item.signal) > parse_sig(existing.signal):
                existing.signal = item.signal
            if not existing.ssid and item.ssid:
                existing.ssid = item.ssid
            if not existing.chan and item.chan:
                existing.chan = item.chan
            if not existing.security and item.security:
                existing.security = item.security
            if item.active:
                existing.active = True
            if getattr(item, "bars", "") and not getattr(existing, "bars", ""):
                existing.bars = item.bars
            if getattr(item, "mode", "") and not getattr(existing, "mode", ""):
                existing.mode = item.mode
            if getattr(item, "rate", "") and not getattr(existing, "rate", ""):
                existing.rate = item.rate


def scan_nearby_wifi_networks(target_ssid: str | None = None, rescan: bool = True) -> list[BSSIDTarget]:
    """Scans and retrieves available nearby Wi-Fi BSSIDs and AP properties via nmcli and kernel BSS cache.

    If target_ssid is specified, filters results to matching SSIDs (case-insensitive).
    Performs multi-pass cumulative discovery to guarantee catching all transmitting BSSIDs.
    """
    trace(f"[FEATURE] Scanning nearby Wi-Fi networks (target_ssid={target_ssid}, rescan={rescan})")
    accumulated: dict[str, BSSIDTarget] = {}

    if rescan:
        log_step("Scanning nearby Wi-Fi networks...")
        log_wait("Triggering Wi-Fi rescan...")
        try:
            trigger_wifi_rescan(target_ssid=target_ssid)
        except StopIteration:
            pass

    # Pass 1: Query nmcli list and kernel BSS table
    try:
        nmcli_targets_1 = query_nmcli_wifi_list(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, nmcli_targets_1)
    except StopIteration:
        pass

    try:
        iw_targets_1 = query_iw_scan_dump(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, iw_targets_1)
    except StopIteration:
        pass

    # Pass 2: When rescanning, allow hardware radio sweep dwell and query again to accumulate late channels
    if rescan:
        try:
            time.sleep(0.8)
            nmcli_targets_2 = query_nmcli_wifi_list(target_ssid=target_ssid)
            merge_bssid_targets(accumulated, nmcli_targets_2)
            iw_targets_2 = query_iw_scan_dump(target_ssid=target_ssid)
            merge_bssid_targets(accumulated, iw_targets_2)
        except StopIteration:
            pass
        except Exception:
            pass

    results = list(accumulated.values())
    if target_ssid:
        results = [item for item in results if item.ssid.lower() == target_ssid.lower() or target_ssid.lower() in item.ssid.lower()]

    def parse_sig(item: BSSIDTarget) -> int:
        clean = DIGIT_REGEX.sub("", str(item.signal))
        return int(clean) if clean else 0

    results.sort(key=lambda item: (parse_sig(item), item.ssid, item.bssid), reverse=True)
    return results


def scan_bssids_for_ssid(target_ssid: str) -> list[BSSIDTarget]:
    """
    Scans for available BSSIDs matching the target SSID with directed probe requests,
    multi-pass accumulation, and kernel BSS table merging to guarantee discovering all BSSIDs.
    """
    trace(f"[FEATURE] Rescanning Wi-Fi and scanning BSSIDs for target SSID '{target_ssid}'")
    log_step(f"Scanning BSSIDs for '{target_ssid}'...")
    log_wait(f"Triggering directed Wi-Fi rescan for '{target_ssid}'...")

    accumulated: dict[str, BSSIDTarget] = {}

    try:
        trigger_wifi_rescan(target_ssid=target_ssid)
    except StopIteration:
        pass

    # Pass 1: Query nmcli list and kernel BSS table
    try:
        nmcli_targets_1 = query_nmcli_wifi_list(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, nmcli_targets_1)
    except StopIteration:
        pass

    try:
        iw_targets_1 = query_iw_scan_dump(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, iw_targets_1)
    except StopIteration:
        pass

    # Pass 2: Allow radio sweep dwell and query again to accumulate late channels
    try:
        time.sleep(0.8)
        nmcli_targets_2 = query_nmcli_wifi_list(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, nmcli_targets_2)
        iw_targets_2 = query_iw_scan_dump(target_ssid=target_ssid)
        merge_bssid_targets(accumulated, iw_targets_2)
    except StopIteration:
        pass
    except Exception:
        pass

    results = [
        item for item in accumulated.values()
        if item.ssid.lower() == target_ssid.lower()
    ]

    def parse_sig(item: BSSIDTarget) -> int:
        clean = DIGIT_REGEX.sub("", str(item.signal))
        return int(clean) if clean else 0

    results.sort(key=parse_sig, reverse=True)
    return results


def get_bssid_security(target_bssid: str) -> str | None:
    """Queries nmcli dev wifi / iw scan dump to get the security of a specific BSSID, or None if not found."""
    if not target_bssid or target_bssid.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return None
    try:
        rc, out = _run(["nmcli", "-t", "-f", "BSSID,SECURITY", "dev", "wifi", "list"], debug=False)
        for line in out.splitlines():
            if not line:
                continue
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                b_mac = parts[0].replace("\x00", ":").strip()
                sec = parts[1].replace("\x00", ":").strip()
                if b_mac.lower() == target_bssid.lower():
                    return sec
    except StopIteration:
        raise
    except Exception:
        pass

    # Fallback to kernel BSS cache
    try:
        iw_targets = query_iw_scan_dump()
        for item in iw_targets:
            if item.bssid.lower() == target_bssid.lower():
                return item.security
    except Exception:
        pass

    return None


def get_connected_bssid(interface: str = "wlan0") -> str:
    """Retrieves the currently connected BSSID using kernel iw link, NetworkManager active BSSID, or dev show."""
    rc, iw_out = _run(["iw", "dev", interface, "link"], debug=False)
    if rc == 0 and iw_out:
        m = CONNECTED_MAC_REGEX.search(iw_out)
        if m:
            return m.group(1).upper()

    rc, out = _run(["nmcli", "-t", "-f", "active,bssid", "dev", "wifi"], debug=False)
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                bssid = parts[1].replace("\x00", ":").strip()
                if bssid and bssid != "--":
                    return bssid.upper()

    return ""


def lock_bssid(target_bssid: str | None = None, profile: str | None = None, max_retries: int = 3) -> bool:
    profile = profile or get_active_profile()
    if not profile:
        log_minus("Error: No active Wi-Fi profile detected.")
        return False

    target_ssid = get_ssid_for_profile(profile)

    if not target_bssid:
        from .ui_status import select_bssid_interactively
        target_bssid = select_bssid_interactively(target_ssid)
        if not target_bssid:
            return False

    trace(f"[FEATURE] Locking profile '{profile}' to BSSID {target_bssid} (Max retries: {max_retries})")
    log_step(f"Locking BSSID -> {target_bssid} (profile: {profile})...")

    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            log_wait(f"Retry {attempt}/{max_retries} -> BSSID: {target_bssid}...")

        rc, _ = _run(["nmcli", "connection", "modify", profile, "802-11-wireless.bssid", target_bssid])
        if rc != 0:
            log_warning(f"Attempt {attempt}/{max_retries}: Failed setting BSSID property for '{profile}'.")
            continue

        log_wait(f"Reconnecting profile '{profile}' (5s timeout)...")
        rc_up, out_up = _run(["nmcli", "connection", "up", profile], timeout=5.0)
        if rc_up != 0 or "could not be found" in out_up.lower() or "activation failed" in out_up.lower():
            log_wait("NetworkManager cache miss / timeout / activation failed. Rescanning & reconnecting...")
            _run(["nmcli", "device", "wifi", "rescan"], debug=False)
            time.sleep(0.5)
            _run(["nmcli", "connection", "up", profile], timeout=5.0)

        log_wait(f"Verifying lock to BSSID {target_bssid}...")
        verified = False
        connected_bssid = ""
        for _ in range(5):
            connected_bssid = get_connected_bssid()
            if connected_bssid and connected_bssid.upper() == target_bssid.upper():
                verified = True
                break
            time.sleep(1)

        if verified:
            trace(f"[FEATURE] Successfully locked connection profile '{profile}' to BSSID {target_bssid}")
            log_plus(f"BSSID locked: {target_bssid}")
            return True
        else:
            trace(f"[FEATURE] Attempt {attempt}/{max_retries} failed to lock onto BSSID {target_bssid} (Current: {connected_bssid or 'Unknown'})")
            log_warning(f"Lock attempt {attempt}/{max_retries} failed -> Current: {connected_bssid or 'None'}")

    trace(f"[FEATURE] Failed to lock profile '{profile}' to BSSID {target_bssid} after {max_retries} attempts")
    log_minus(f"Lock failed after {max_retries} attempts -> Skipping {target_bssid}")
    return False

