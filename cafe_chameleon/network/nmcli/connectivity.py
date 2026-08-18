"""
cafe_chameleon.network.nmcli.connectivity - NetworkManager (nmcli) native connectivity state checker.
"""

from cafe_chameleon.utils.process import _run
from cafe_chameleon.utils.tracing import trace


def get_nmcli_connectivity(force_check: bool = True, timeout: float = 2.0) -> str | None:
    """
    Queries NetworkManager's connectivity state via nmcli.
    Possible states returned by nmcli:
      - 'full': confirmed full access to the internet.
      - 'portal': behind a captive portal (login required).
      - 'limited': network connected, but internet unreachable.
      - 'none': not connected to any network.
      - 'unknown': connectivity state cannot be determined.

    If force_check is True, runs 'nmcli networking connectivity check' to trigger an immediate probe.
    Returns normalized lowercase string state, or None if nmcli is unavailable.
    """
    try:
        cmd = ["nmcli", "networking", "connectivity", "check"] if force_check else ["nmcli", "networking", "connectivity"]
        rc, out = _run(cmd, debug=False, timeout=timeout)
        if rc == 0 and out:
            state = out.strip().lower()
            if state in ("full", "portal", "limited", "none", "unknown"):
                trace(f"[FEATURE] nmcli connectivity check returned: '{state}'")
                return state
    except Exception as e:
        trace(f"[-] nmcli connectivity query failed: {e}")

    # Fallback to general status field query
    try:
        rc, out = _run(["nmcli", "-t", "-f", "CONNECTIVITY", "general"], debug=False, timeout=1.0)
        if rc == 0 and out:
            state = out.strip().lower()
            if state in ("full", "portal", "limited", "none", "unknown"):
                return state
    except Exception:
        pass

    return None
