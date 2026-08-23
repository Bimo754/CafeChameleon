"""
tests/ui/test_animation_resolution.py - Unit tests for animation subprocess PYTHONPATH resolution.
"""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest
from cafe_chameleon.ui.xterm.manager import XtermManager
from cafe_chameleon.ui.animation import spawn_xterm_and_run


def test_play_completion_animation_injects_pythonpath():
    """Verify play_completion_animation adds repo_dir to PYTHONPATH in subprocess env."""
    mgr = XtermManager(enabled=False)
    with patch("subprocess.Popen") as mock_popen:
        mgr.play_completion_animation()
        assert mock_popen.called
        call_args, call_kwargs = mock_popen.call_args
        env = call_kwargs.get("env", {})
        assert "PYTHONPATH" in env
        assert "CafeChameleon" in env["PYTHONPATH"]


def test_spawn_xterm_and_run_injects_pythonpath():
    """Verify spawn_xterm_and_run injects PYTHONPATH into env and xterm inner command."""
    with patch("subprocess.run") as mock_run, \
         patch("cafe_chameleon.ui.xterm.screen.get_screen_resolution", return_value=(1920, 1080)):
        spawn_xterm_and_run()
        assert mock_run.called
        call_args, call_kwargs = mock_run.call_args
        env = call_kwargs.get("env", {})
        assert "PYTHONPATH" in env
        assert "CafeChameleon" in env["PYTHONPATH"]
        xterm_cmd = call_args[0]
        cmd_str = " ".join(xterm_cmd)
        assert "PYTHONPATH=" in cmd_str
