"""
cafe_chameleon.utils.state - Global application runtime configuration & flag state.
"""

DEBUG: bool = False
QUIET: bool = False
USE_XTERM: bool = True

_RESTORE_PARAMS: dict | None = None
_RESTORE_CALLBACK = None


def set_debug(val: bool) -> None:
    global DEBUG
    DEBUG = val


def get_debug() -> bool:
    return DEBUG


def set_quiet(val: bool) -> None:
    global QUIET
    QUIET = val


def get_quiet() -> bool:
    return QUIET


def set_use_xterm(val: bool) -> None:
    global USE_XTERM
    USE_XTERM = val


def get_use_xterm() -> bool:
    return USE_XTERM


def set_restore_params(interface: str, local_mac: str, ipmask: str, broadcast: str, gw_ip: str, callback=None, profile: str | None = None) -> None:
    global _RESTORE_PARAMS, _RESTORE_CALLBACK
    _RESTORE_PARAMS = {
        "interface": interface,
        "macaddress": local_mac,
        "ipmask": ipmask,
        "broadcast": broadcast,
        "gateway": gw_ip,
        "profile": profile
    }
    if callback:
        _RESTORE_CALLBACK = callback


def get_restore_params() -> dict | None:
    return _RESTORE_PARAMS


def get_restore_callback():
    return _RESTORE_CALLBACK
