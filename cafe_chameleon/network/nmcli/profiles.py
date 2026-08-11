"""
cafe_chameleon.network.nmcli.profiles - Active profile and SSID query logic.
"""

from cafe_chameleon.utils.process import _run


def get_active_profile() -> str:
    rc, out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
    for line in out.splitlines():
        if line.endswith(":802-11-wireless") or line.endswith(":wifi"):
            return line.rsplit(":", 1)[0]

    rc, out = _run(["nmcli", "-t", "-f", "GENERAL.CONNECTION", "dev", "show"])
    for line in out.splitlines():
        if line.strip():
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                return parts[1].strip()
    return ""


def get_ssid_for_profile(profile: str) -> str:
    """Retrieves the SSID associated with a connection profile."""
    rc, ssid = _run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", profile])
    if ssid:
        return ssid
    rc, out = _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])
    for line in out.splitlines():
        if line.startswith("yes:"):
            unescaped = line.replace(r"\:", "\x00")
            parts = unescaped.split(":")
            if len(parts) >= 2:
                active_ssid = parts[1].replace("\x00", ":").strip()
                if active_ssid:
                    return active_ssid
    return profile


def is_open_security(security: str | None) -> bool:
    """Returns True if the security string indicates an open / unencrypted network."""
    if security is None:
        return True
    s = str(security).strip().lower()
    return s in ("", "--", "none", "(none)", "open")


def is_encrypted_security(security: str | None) -> bool:
    """Returns True if the security string indicates encrypted security (WPA2, WPA, WEP, etc.)."""
    return not is_open_security(security)


def get_active_security(profile: str | None = None, interface: str = "wlan0") -> str | None:
    """Queries nmcli dev wifi / active profile to get the security of the current connection, or None if unknown."""
    try:
        rc, out = _run(["nmcli", "-t", "-f", "active,bssid,security", "dev", "wifi"], debug=False)
        for line in out.splitlines():
            if line.startswith("yes:"):
                unescaped = line.replace(r"\:", "\x00")
                parts = unescaped.split(":")
                if len(parts) >= 3:
                    sec = parts[2].replace("\x00", ":").strip()
                    return sec
                elif len(parts) == 2:
                    sec = parts[1].replace("\x00", ":").strip()
                    return sec
    except Exception:
        pass
    prof = profile or get_active_profile()
    if prof:
        try:
            rc, key_mgmt = _run(["nmcli", "-g", "802-11-wireless-security.key-mgmt", "connection", "show", prof], debug=False)
            if rc == 0 and key_mgmt.strip():
                return key_mgmt.strip().upper()
        except Exception:
            pass
    return None

