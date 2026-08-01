"""
cafe_chameleon.network.nmcli.profiles - Active profile and SSID query logic.
"""

from cafe_chameleon.utils.process import _run


def get_active_profile() -> str:
    rc, out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
    for line in out.splitlines():
        if line.endswith(":802-11-wireless"):
            return line.split(":")[0]

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
