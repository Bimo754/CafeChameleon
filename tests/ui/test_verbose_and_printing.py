"""
tests/ui/test_verbose_and_printing.py - Unit tests for verbose flag and redesigned launcher printing system.
"""

import io
import sys
import pytest

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.utils.state import set_verbose, get_verbose, set_quiet, set_launcher_mode
from cafe_chameleon.ui import colors
from cafe_chameleon.ui.console import (
    log_main,
    log_subnet_scan,
    log_hijack_attempt,
    log_info,
    log_step,
    log_wait,
    log_plus,
    log_minus
)


@pytest.fixture(autouse=True)
def reset_state():
    set_verbose(False)
    set_quiet(False)
    set_launcher_mode(False)
    yield
    set_verbose(False)
    set_quiet(False)
    set_launcher_mode(False)


def test_cli_verbose_flag_parsing():
    """Verify CLI parser handles -v and --verbose flags correctly."""
    args_short = parse_arguments(["simple", "-v"])
    assert getattr(args_short, "verbose", False) is True

    args_long = parse_arguments(["aggressive", "--verbose"])
    assert getattr(args_long, "verbose", False) is True

    args_default = parse_arguments(["simple"])
    assert getattr(args_default, "verbose", False) is False


def test_verbose_state_get_set():
    """Verify set_verbose and get_verbose toggle state correctly."""
    assert get_verbose() is False
    set_verbose(True)
    assert get_verbose() is True
    set_verbose(False)
    assert get_verbose() is False


def test_log_subnet_scan_formatting(capsys):
    """Verify log_subnet_scan formats 'Scanning subnet <subnet>' as expected."""
    log_subnet_scan("192.168.1.0/24")
    captured = capsys.readouterr().out
    assert "Scanning subnet 192.168.1.0/24" in captured


def test_log_hijack_attempt_even_spacing(capsys):
    """Verify log_hijack_attempt formats 'Trying to hijack <ip> - <mac>' with exact column alignment."""
    log_hijack_attempt("10.0.0.1", "00:11:22:33:44:55")
    line1 = capsys.readouterr().out.strip()

    log_hijack_attempt("192.168.1.100", "00:11:22:33:44:55")
    line2 = capsys.readouterr().out.strip()

    log_hijack_attempt("172.16.254.254", "AA:BB:CC:DD:EE:FF")
    line3 = capsys.readouterr().out.strip()

    assert "Trying to hijack 10.0.0.1        - 00:11:22:33:44:55" in line1
    assert "Trying to hijack 192.168.1.100   - 00:11:22:33:44:55" in line2
    assert "Trying to hijack 172.16.254.254  - AA:BB:CC:DD:EE:FF" in line3

    # Check that dash separator (-) is at the exact same character index in all lines
    idx1 = line1.find("-")
    idx2 = line2.find("-")
    idx3 = line3.find("-")

    assert idx1 == idx2 == idx3


def test_log_main_verbose_filtering(capsys):
    """Verify log_main suppresses verbose_only messages when verbose is False, and includes them when True."""
    set_verbose(False)
    log_main("Detailed debug log", verbose_only=True)
    captured = capsys.readouterr().out
    assert captured == ""

    set_verbose(False)
    log_main("Essential status log", verbose_only=False)
    captured_essential = capsys.readouterr().out
    assert "Essential status log" in captured_essential

    set_verbose(True)
    log_main("Detailed debug log", verbose_only=True)
    captured_verbose = capsys.readouterr().out
    assert "Detailed debug log" in captured_verbose


def test_operational_logs_verbose_filtering(capsys):
    """Verify step-by-step operational chatter is suppressed without -v and displayed with -v."""
    set_verbose(False)
    log_step("Setting MAC 00:11:22:33:44:55")
    log_wait("Reconnecting profile")
    log_plus("MAC address changed to 00:11:22:33:44:55", force=True)
    captured_non_verbose = capsys.readouterr().out
    assert "Setting MAC" not in captured_non_verbose
    assert "Reconnecting profile" not in captured_non_verbose
    assert "MAC address changed to 00:11:22:33:44:55" in captured_non_verbose

    set_verbose(True)
    log_step("Setting MAC 00:11:22:33:44:55")
    log_wait("Reconnecting profile")
    captured_verbose = capsys.readouterr().out
    assert "Setting MAC 00:11:22:33:44:55" in captured_verbose
    assert "Reconnecting profile" in captured_verbose
