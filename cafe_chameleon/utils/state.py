"""
cafe_chameleon.utils.state - Global application runtime configuration & flag state.
"""

DEBUG_COMMANDS: bool = False
DEBUG_TRACING: bool = False
USE_ORIGINAL_MAC: bool = False
QUIET: bool = False
USE_XTERM: bool = True

_RESTORE_PARAMS: dict | None = None
_RESTORE_CALLBACK = None


def set_debug(val: bool | str | list | None) -> None:
    global DEBUG_COMMANDS, DEBUG_TRACING
    if val is True or val == "commands":
        DEBUG_COMMANDS = True
        DEBUG_TRACING = False
    elif val == "tracing":
        DEBUG_COMMANDS = False
        DEBUG_TRACING = True
        try:
            from cafe_chameleon.utils.tracing import init_trace
            init_trace()
        except ImportError:
            pass
    elif isinstance(val, (list, tuple)):
        DEBUG_COMMANDS = "commands" in val or True in val
        DEBUG_TRACING = "tracing" in val
        if DEBUG_TRACING:
            try:
                from cafe_chameleon.utils.tracing import init_trace
                init_trace()
            except ImportError:
                pass
    else:
        DEBUG_COMMANDS = False
        DEBUG_TRACING = False


def get_debug() -> bool:
    return DEBUG_COMMANDS


def get_debug_commands() -> bool:
    return DEBUG_COMMANDS


def get_debug_tracing() -> bool:
    return DEBUG_TRACING


def set_use_original_mac(val: bool) -> None:
    global USE_ORIGINAL_MAC
    USE_ORIGINAL_MAC = val


def get_use_original_mac() -> bool:
    return USE_ORIGINAL_MAC


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
