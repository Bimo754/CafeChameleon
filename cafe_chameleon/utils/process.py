"""
cafe_chameleon.utils.process - Process execution and command running helper functions.
"""

import shlex
import subprocess
from typing import Sequence, Tuple, Union

from .state import get_debug_commands, get_debug_tracing
from .tracing import trace


def _run(cmd: Union[str, Sequence[str]], debug: bool | None = None, timeout: float | None = None) -> Tuple[int, str]:
    """
    Run a shell command safely with optional timeout.
    Returns (returncode, stdout).
    """
    is_debug_cmd = get_debug_commands() if debug is None else debug
    is_debug_trace = get_debug_tracing()

    if isinstance(cmd, str):
        cmd_str = cmd
        cmd_args = shlex.split(cmd)
    else:
        cmd_str = " ".join(cmd)
        if len(cmd) == 1 and isinstance(cmd[0], str) and " " in cmd[0]:
            cmd_args = shlex.split(cmd[0])
        else:
            cmd_args = list(cmd)

    if is_debug_trace:
        trace(f"[CMD] Executing: {cmd_str}")

    if is_debug_cmd:
        print(f"  [RUN] {cmd_str}")

    try:
        result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()

        if is_debug_trace:
            err_msg = f" | stderr: {result.stderr.strip()}" if result.stderr and result.stderr.strip() else ""
            out_msg = f" | stdout: {output}" if output else ""
            trace(f"[CMD] Exit Code {result.returncode}: {cmd_str}{out_msg}{err_msg}")

        if is_debug_cmd:
            if output:
                for line in output.splitlines():
                    print(f"    [OUT] {line}")
            if result.stderr and result.stderr.strip():
                for line in result.stderr.strip().splitlines():
                    print(f"    [ERR] {line}")

        return result.returncode, output
    except subprocess.TimeoutExpired:
        if is_debug_trace:
            trace(f"[CMD] TIMEOUT ({timeout}s): {cmd_str}")
        if is_debug_cmd:
            print(f"  [TIMEOUT] Command timed out after {timeout}s: {cmd_str}")
        return 124, ""
    except Exception as e:
        if is_debug_trace:
            trace(f"[CMD] ERROR ({e}): {cmd_str}")
        if is_debug_cmd:
            print(f"  [ERROR] Command execution error: {e}")
        return 1, ""
