"""
tests/test_blacklist.py - Comprehensive unit & integration tests for MAC/BSSID blacklisting feature.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from cafe_chameleon.utils.blacklist import (
    normalize_mac,
    load_blacklist,
    save_blacklist,
    add_to_blacklist,
    remove_from_blacklist,
    list_blacklist,
    is_blacklisted,
    handle_blacklist_cli,
)
from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.modes.blacklist.controller import run_blacklist
from cafe_chameleon.modes.aggressive.air_target_handler import filter_valid_air_clients
from cafe_chameleon.modes.aggressive.ranker import (
    calculate_bssid_score,
    count_active_clients,
    get_active_clients_for_bssid,
    is_client_active,
)
from cafe_chameleon.scanners.orchestrator import deep_scan_subnet


@pytest.fixture(autouse=True)
def isolate_blacklist_file(tmp_path, monkeypatch):
    """Isolate BLACKLIST_FILE to temporary path for all tests and ensure cleanup."""
    temp_bl = str(tmp_path / "blacklist.txt")
    monkeypatch.setattr("cafe_chameleon.config.BLACKLIST_FILE", temp_bl)
    monkeypatch.setattr("cafe_chameleon.utils.blacklist.BLACKLIST_FILE", temp_bl)
    yield temp_bl
    if os.path.exists(temp_bl):
        os.remove(temp_bl)
    if os.path.exists("blacklist.txt"):
        os.remove("blacklist.txt")


class TestBlacklistCore:
    """Tests for core blacklist loading, saving, add, remove, and list functionality."""

    def test_normalize_mac(self):
        assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("  00:11:22:33:44:55  ") == "00:11:22:33:44:55"
        assert normalize_mac("") == ""
        assert normalize_mac(None) == ""

    def test_load_and_save_blacklist(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            filepath = tf.name

        try:
            # Initially empty
            assert load_blacklist(filepath) == set()

            # Save some MACs
            save_blacklist(["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "invalid-mac"], filepath)
            loaded = load_blacklist(filepath)
            assert "00:11:22:33:44:55" in loaded
            assert "aa:bb:cc:dd:ee:ff" in loaded
            assert "invalid-mac" not in loaded

            # Check list_blacklist
            assert list_blacklist(filepath) == ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_add_and_remove_blacklist(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            filepath = tf.name

        try:
            # Add valid MAC
            ok, msg = add_to_blacklist("11:22:33:44:55:66", filepath)
            assert ok is True
            assert "Added" in msg
            assert is_blacklisted("11:22:33:44:55:66", filepath=filepath) is True
            assert is_blacklisted("11:22:33:44:55:66".upper(), filepath=filepath) is True

            # Adding duplicate
            ok, msg = add_to_blacklist("11:22:33:44:55:66", filepath)
            assert ok is True
            assert "already blacklisted" in msg

            # Add invalid MAC
            ok, msg = add_to_blacklist("invalid-mac-address", filepath)
            assert ok is False
            assert "Invalid MAC address" in msg

            # Remove existing MAC
            ok, msg = remove_from_blacklist("11:22:33:44:55:66", filepath)
            assert ok is True
            assert "Removed" in msg
            assert is_blacklisted("11:22:33:44:55:66", filepath=filepath) is False

            # Remove non-existing MAC
            ok, msg = remove_from_blacklist("11:22:33:44:55:66", filepath)
            assert ok is False
            assert "not found in blacklist" in msg

            # Remove with invalid format
            ok, msg = remove_from_blacklist("not-a-mac", filepath)
            assert ok is False
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    def test_load_nonexistent_file(self):
        fake_path = "/tmp/non_existent_blacklist_file_12345.txt"
        if os.path.exists(fake_path):
            os.remove(fake_path)
        assert load_blacklist(fake_path) == set()
        assert is_blacklisted("00:11:22:33:44:55", filepath=fake_path) is False


class TestBlacklistCLIHandler:
    """Tests for CLI handler functions."""

    def test_handle_cli_add_and_remove(self, capsys):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            filepath = tf.name

        try:
            # Missing action
            rc = handle_blacklist_cli([], filepath=filepath)
            assert rc == 1

            # Missing MAC on add
            rc = handle_blacklist_cli(["add"], filepath=filepath)
            assert rc == 1

            # Successful add
            rc = handle_blacklist_cli(["add", "00:11:22:33:44:55"], filepath=filepath)
            assert rc == 0
            captured = capsys.readouterr()
            assert "Added MAC '00:11:22:33:44:55' to blacklist" in captured.out

            # Successful list
            rc = handle_blacklist_cli(["list"], filepath=filepath)
            assert rc == 0
            captured = capsys.readouterr()
            assert "00:11:22:33:44:55" in captured.out
            assert "Total: 1 blacklisted" in captured.out

            # Missing MAC on remove
            rc = handle_blacklist_cli(["remove"], filepath=filepath)
            assert rc == 1

            # Successful remove
            rc = handle_blacklist_cli(["remove", "00:11:22:33:44:55"], filepath=filepath)
            assert rc == 0
            captured = capsys.readouterr()
            assert "Removed MAC '00:11:22:33:44:55' from blacklist" in captured.out

            # List when empty
            rc = handle_blacklist_cli(["list"], filepath=filepath)
            assert rc == 0
            captured = capsys.readouterr()
            assert "Blacklist is empty" in captured.out

            # Unknown action
            rc = handle_blacklist_cli(["invalid_action"], filepath=filepath)
            assert rc == 1
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)


class TestBlacklistParser:
    """Tests for CLI parser integration with blacklist subcommand and flags."""

    def test_parse_blacklist_subcommand(self):
        args = parse_arguments(["blacklist", "add", "00:11:22:33:44:55"])
        assert args.command == "blacklist"
        assert args.action_args == ["add", "00:11:22:33:44:55"]
        assert callable(args.func)

        args = parse_arguments(["blacklist", "remove", "00:11:22:33:44:55"])
        assert args.command == "blacklist"
        assert args.action_args == ["remove", "00:11:22:33:44:55"]

        args = parse_arguments(["blacklist", "list"])
        assert args.command == "blacklist"
        assert args.action_args == ["list"]

    def test_parse_blacklist_flags_on_subcommand(self):
        args = parse_arguments(["blacklist", "--add", "00:11:22:33:44:55"])
        assert args.command == "blacklist"
        assert args.add_mac == "00:11:22:33:44:55"

        args = parse_arguments(["blacklist", "--remove", "00:11:22:33:44:55"])
        assert args.command == "blacklist"
        assert args.remove_mac == "00:11:22:33:44:55"

        args = parse_arguments(["blacklist", "--list"])
        assert args.command == "blacklist"
        assert args.list_blacklisted is True

    def test_run_blacklist_controller(self):
        with patch("cafe_chameleon.modes.blacklist.controller.handle_blacklist_cli") as mock_cli:
            mock_cli.return_value = 0
            args = parse_arguments(["blacklist", "add", "00:11:22:33:44:55"])
            rc = run_blacklist(args)
            assert rc == 0
            mock_cli.assert_called_once_with(["add", "00:11:22:33:44:55"])


class TestBlacklistFilteringInModes:
    """Tests that blacklisted MACs are excluded during Simple and Aggressive scans."""

    @patch("cafe_chameleon.modes.aggressive.air_target_handler.load_blacklist")
    def test_air_client_filtering_excludes_blacklisted(self, mock_bl):
        mock_bl.return_value = {"00:11:22:33:44:55"}

        bssid_air_clients = {
            "00:11:22:33:44:55": "192.168.1.100",  # Blacklisted
            "00:22:33:44:55:66": "192.168.1.101",  # Valid
        }
        auto_params = {"gateway_mac": "00:aa:bb:cc:dd:ee", "local_mac": "00:fe:dc:ba:98:76"}
        bssids = [{"bssid": "00:99:88:77:66:55"}]

        filtered = filter_valid_air_clients(bssid_air_clients, tried_macs=set(), auto_params=auto_params, bssids=bssids)
        assert "00:11:22:33:44:55" not in filtered
        assert "00:22:33:44:55:66" in filtered

    @patch("cafe_chameleon.modes.aggressive.ranker.load_blacklist")
    def test_ranker_ignores_blacklisted_clients_and_bssids(self, mock_bl):
        mock_bl.return_value = {"00:11:22:33:44:55", "aa:bb:cc:dd:ee:01"}

        air_clients_map = {
            "aa:bb:cc:dd:ee:01": {"00:22:33:44:55:66": "192.168.1.50"},  # Blacklisted BSSID
            "aa:bb:cc:dd:ee:02": {
                "00:11:22:33:44:55": "192.168.1.100",  # Blacklisted Client
                "00:33:44:55:66:77": "192.168.1.102",  # Valid Client
            }
        }

        # Blacklisted BSSID should return 0 active clients
        assert count_active_clients("aa:bb:cc:dd:ee:01", air_clients_map) == 0
        assert get_active_clients_for_bssid("aa:bb:cc:dd:ee:01", air_clients_map) == []

        # Scoring non-blacklisted BSSID should only count non-blacklisted client
        item = {"bssid": "aa:bb:cc:dd:ee:02", "signal": "80", "chan": "6"}
        score, count, sig = calculate_bssid_score(item, air_clients_map)
        assert count == 1  # only 00:33:44:55:66:77 counted
        assert sig == 80

    @patch("cafe_chameleon.scanners.orchestrator.passive_sniff_subnet")
    @patch("cafe_chameleon.scanners.orchestrator.scan_subnet")
    @patch("cafe_chameleon.scanners.orchestrator.nmap_scan_subnet")
    @patch("cafe_chameleon.scanners.orchestrator.load_blacklist")
    def test_deep_scan_subnet_excludes_blacklisted(self, mock_bl, mock_nmap, mock_arp, mock_passive):
        mock_bl.return_value = {"00:11:22:33:44:55"}
        mock_passive.return_value = [{"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"}]
        mock_arp.return_value = [{"ip": "192.168.1.20", "mac": "00:22:33:44:55:66"}]
        mock_nmap.return_value = []

        hosts = deep_scan_subnet("192.168.1.0/24", "wlan0", duration=1)
        macs = [h["mac"] for h in hosts]
        assert "00:11:22:33:44:55" not in macs
        assert "00:22:33:44:55:66" in macs

    @patch("cafe_chameleon.modes.simple.runner.load_blacklist")
    @patch("cafe_chameleon.modes.simple.runner.scan_subnet")
    @patch("cafe_chameleon.modes.simple.runner.auto_detect_network_params")
    @patch("cafe_chameleon.modes.simple.runner.get_interface_details")
    @patch("cafe_chameleon.modes.simple.runner.prepare_target_subnet")
    @patch("cafe_chameleon.modes.simple.runner.split_subnets_into_blocks")
    @patch("cafe_chameleon.modes.simple.runner.test_discovered_hosts")
    @patch("cafe_chameleon.modes.simple.runner.set_mac_address")
    @patch("cafe_chameleon.modes.simple.runner.get_attack_mac")
    @patch("cafe_chameleon.modes.simple.runner.wait_for_carrier")
    def test_simple_runner_skips_blacklisted_hosts(
        self, mock_wait, mock_atk_mac, mock_set_mac, mock_takeover, mock_split, mock_prep, mock_details, mock_auto, mock_scan, mock_bl
    ):
        mock_bl.return_value = {"00:11:22:33:44:55"}
        mock_auto.return_value = {"gateway_ip": "192.168.1.1", "gateway_mac": "00:aa:bb:cc:dd:ee", "cidr": "192.168.1.0/24"}
        mock_details.return_value = ("192.168.1.5", "00:fe:dc:ba:98:76")
        mock_prep.return_value = "192.168.1.0/24"
        mock_split.return_value = ["192.168.1.0/24"]
        mock_scan.return_value = [
            {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"},  # Blacklisted
            {"ip": "192.168.1.20", "mac": "00:22:33:44:55:66"},  # Valid
        ]
        mock_takeover.return_value = True

        from cafe_chameleon.modes.simple.runner import run_simple
        args = MagicMock()
        args.interface = "wlan0"
        args.subnet = None
        args.force = False
        args.profile = None

        result = run_simple(args, quiet_header=True)
        assert result is True

        # Ensure test_discovered_hosts was only called with non-blacklisted host
        mock_takeover.assert_called_once()
        passed_hosts = mock_takeover.call_args[0][0]
        passed_macs = [h["mac"] for h in passed_hosts]
        assert "00:11:22:33:44:55" not in passed_macs
        assert "00:22:33:44:55:66" in passed_macs

    @patch("cafe_chameleon.modes.aggressive.runner.load_blacklist")
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile")
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet")
    def test_aggressive_runner_filters_all_blacklisted_bssids(
        self, mock_has_net, mock_scan_bssid, mock_ssid, mock_prof, mock_bl
    ):
        mock_bl.return_value = {"00:11:22:33:44:55", "00:22:33:44:55:66"}
        mock_prof.return_value = "TestProfile"
        mock_ssid.return_value = "TestSSID"
        mock_has_net.return_value = False
        mock_scan_bssid.return_value = [
            {"bssid": "00:11:22:33:44:55", "signal": "90", "chan": "1"},
            {"bssid": "00:22:33:44:55:66", "signal": "80", "chan": "6"},
        ]

        from cafe_chameleon.modes.aggressive.runner import run_aggressive
        args = MagicMock()
        args.interface = "wlan0"
        args.profile = "TestProfile"
        args.air = None
        args.air_only = None

        result = run_aggressive(args)
        assert result is False  # All BSSIDs filtered out, cannot proceed

    def test_main_handles_blacklist_subcommand(self):
        with patch("cafe_chameleon.modes.blacklist.controller.handle_blacklist_cli") as mock_cli:
            mock_cli.return_value = 0
            with patch("sys.argv", ["main.py", "blacklist", "add", "00:11:22:33:44:55"]):
                from main import main
                main()
                mock_cli.assert_called_once_with(["add", "00:11:22:33:44:55"])

