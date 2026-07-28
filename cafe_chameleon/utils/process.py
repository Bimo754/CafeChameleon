"""
cafe_chameleon.utils.process - Process execution and command running helper functions.
"""

import shlex
import subprocess
from typing import Sequence, Tuple, Union

from .state import get_debug


def _run(cmd: Union[str, Sequence[str]], debug: bool | None = None, timeout: float | None = None) -> Tuple[int, str]:
    """
    Run a shell command safely with optional timeout.
    Returns (returncode, stdout).
    """
    is_debug = get_debug() if debug is None else debug

    if isinstance(cmd, str):
        cmd_str = cmd
        cmd_args = shlex.split(cmd)
    else:
        cmd_str = " ".join(cmd)
        cmd_args = list(cmd)

    if is_debug:
        print(f"  [RUN] {cmd_str}")

    try:
        result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()

        if is_debug:
            if output:
                for line in output.splitlines():
                    print(f"    [OUT] {line}")
            if result.stderr and result.stderr.strip():
                for line in result.stderr.strip().splitlines():
                    print(f"    [ERR] {line}")

        return result.returncode, output
    except subprocess.TimeoutExpired:
        if is_debug:
            print(f"  [TIMEOUT] Command timed out after {timeout}s: {cmd_str}")
        return 124, ""
    except Exception as e:
        if is_debug:
            print(f"  [ERROR] Command execution error: {e}")
        return 1, ""
