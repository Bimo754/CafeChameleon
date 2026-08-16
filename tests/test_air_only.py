"""
tests/test_air_only.py - Unit tests for --air-only flag in aggressive mode.
"""

import sys
import unittest
import argparse
from unittest.mock import patch, MagicMock

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.modes.aggressive.runner import run_aggressive


class TestAirOnlyCLI(unittest.TestCase):
    """Tests CLI argument parsing for --air-only flag."""

    def test_air_only_flag_default(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive", "--air-only"]):
            args = parse_arguments()
            self.assertEqual(args.air_only, -1)
            self.assertIsNone(getattr(args, "air", None))

    def test_air_only_flag_with_duration(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive", "--air-only", "25"]):
            args = parse_arguments()
            self.assertEqual(args.air_only, 25)
            self.assertIsNone(getattr(args, "air", None))

    def test_aggressive_without_air_flags(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive"]):
            args = parse_arguments()
            self.assertIsNone(getattr(args, "air_only", None))
            self.assertIsNone(getattr(args, "air", None))

    def test_aggressive_with_regular_air_flag(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive", "--air", "15"]):
            args = parse_arguments()
            self.assertEqual(args.air, 15)
            self.assertIsNone(getattr(args, "air_only", None))


class TestAirOnlyXtermWindows(unittest.TestCase):
    """Tests active xterm windows selection in main.py for --air-only."""

    @patch("main.init_xterm")
    @patch("main.check_interface_warning", return_value=None)
    def test_aggressive_air_only_window_layout(self, mock_warn, mock_init_xterm):
        import main
        with patch.object(sys, "argv", ["main.py", "aggressive", "--air-only", "10", "--profile", "TestP"]):
            with patch("main.parse_arguments") as mock_parse:
                mock_args = argparse.Namespace(
                    command="aggressive",
                    air=None,
                    air_only=10,
                    debug=None,
                    original_mac=False,
                    quiet=False,
                    interface="wlan0",
                    no_xterm=False,
                    func=MagicMock(return_value=True)
                )
                mock_parse.return_value = mock_args
                main.main()

                mock_init_xterm.assert_called_once_with(active_windows=["main", "air", "hijack"])

    @patch("main.init_xterm")
    @patch("main.check_interface_warning", return_value=None)
    def test_aggressive_regular_air_window_layout(self, mock_warn, mock_init_xterm):
        import main
        with patch.object(sys, "argv", ["main.py", "aggressive", "--air", "10", "--profile", "TestP"]):
            with patch("main.parse_arguments") as mock_parse:
                mock_args = argparse.Namespace(
                    command="aggressive",
                    air=10,
                    air_only=None,
                    debug=None,
                    original_mac=False,
                    quiet=False,
                    interface="wlan0",
                    no_xterm=False,
                    func=MagicMock(return_value=True)
                )
                mock_parse.return_value = mock_args
                main.main()

                mock_init_xterm.assert_called_once_with(active_windows=["main", "air", "scan", "hijack"])


class TestAirOnlyExecution(unittest.TestCase):
    """Tests aggressive execution behavior with --air-only flag."""

    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    @patch("cafe_chameleon.modes.aggressive.runner.run_scan_wrapper")
    def test_air_only_skips_subnet_scanning_on_all_bssids(
        self,
        mock_run_scan_wrapper,
        mock_test_air_targets,
        mock_set_mac,
        mock_wait_carrier,
        mock_lock_bssid,
        mock_sniff_air,
        mock_scan_bssids,
        mock_has_internet,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
            {"bssid": "aa:bb:cc:dd:ee:ff", "signal": "60", "chan": "6", "security": "OPEN"},
        ]
        mock_sniff_air.return_value = {
            "11:22:33:44:55:66": {"00:11:22:33:44:01": "10.0.0.10"},
            "aa:bb:cc:dd:ee:ff": {},
        }
        # Air targets test returns failure (no internet)
        mock_test_air_targets.return_value = (False, False)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=20,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        result = run_aggressive(args)
        self.assertFalse(result)

        # Sniff air clients should be called with duration 20
        mock_sniff_air.assert_called_once()
        self.assertEqual(mock_sniff_air.call_args[1]["duration"], 20)

        # test_air_client_targets should be called for BSSID 1
        mock_test_air_targets.assert_called_once()

        # CRITICAL: run_scan_wrapper MUST NOT be called because --air-only is enabled
        mock_run_scan_wrapper.assert_not_called()

        # Both BSSIDs should have been locked and tried
        self.assertEqual(mock_lock_bssid.call_count, 2)

    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    @patch("cafe_chameleon.modes.aggressive.runner.run_scan_wrapper")
    def test_regular_air_performs_subnet_scanning_when_air_targets_fail(
        self,
        mock_run_scan_wrapper,
        mock_test_air_targets,
        mock_set_mac,
        mock_wait_carrier,
        mock_lock_bssid,
        mock_sniff_air,
        mock_scan_bssids,
        mock_has_internet,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
        ]
        mock_sniff_air.return_value = {
            "11:22:33:44:55:66": {"00:11:22:33:44:01": "10.0.0.10"},
        }
        mock_test_air_targets.return_value = (False, False)
        mock_run_scan_wrapper.return_value = False

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=20,
            air_only=None,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        result = run_aggressive(args)
        self.assertFalse(result)

        # For regular --air, run_scan_wrapper MUST be called if air targets failed
        mock_run_scan_wrapper.assert_called_once()

    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    @patch("cafe_chameleon.modes.aggressive.runner.run_scan_wrapper")
    def test_air_only_succeeds_when_air_target_grants_internet(
        self,
        mock_run_scan_wrapper,
        mock_test_air_targets,
        mock_set_mac,
        mock_wait_carrier,
        mock_lock_bssid,
        mock_sniff_air,
        mock_scan_bssids,
        mock_has_internet,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
        ]
        mock_sniff_air.return_value = {
            "11:22:33:44:55:66": {"00:11:22:33:44:01": "10.0.0.10"},
        }
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=30,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        result = run_aggressive(args)
        self.assertTrue(result)
        mock_run_scan_wrapper.assert_not_called()


if __name__ == "__main__":
    unittest.main()
