"""
tests/test_air_only.py - Unit tests for --air-only flag in aggressive mode.
"""

import sys
import unittest
import argparse
from unittest.mock import patch, MagicMock

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.modes.aggressive.runner import run_aggressive
from cafe_chameleon.scanners.air.sniffer import AirClientsMap


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

    def test_air_only_flag_zero_duration(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive", "--air-only", "0"]):
            args = parse_arguments()
            self.assertEqual(args.air_only, 0)
            self.assertIsNone(getattr(args, "air", None))

    def test_air_flag_zero_duration(self):
        with patch.object(sys, "argv", ["cafe-chameleon", "aggressive", "--air", "0"]):
            args = parse_arguments()
            self.assertEqual(args.air, 0)
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

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
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
        mock_auto_params,
        mock_is_mon
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

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
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
        mock_auto_params,
        mock_is_mon
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

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
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
        mock_auto_params,
        mock_is_mon
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

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet")
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    @patch("cafe_chameleon.modes.aggressive.runner.run_scan_wrapper")
    def test_air_only_zero_continuous_loop_retries_and_succeeds(
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
        mock_auto_params,
        mock_is_mon
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
        ]
        # Cycle 1 returns active client, fails hijack; Cycle 2 returns active client, succeeds hijack
        mock_sniff_air.side_effect = [
            AirClientsMap(
                {"11:22:33:44:55:66": {"00:11:22:33:44:01": "10.0.0.10"}},
                client_metadata={"00:11:22:33:44:01": {"active": True, "bssid": "11:22:33:44:55:66"}}
            ),
            AirClientsMap(
                {"11:22:33:44:55:66": {"00:11:22:33:44:02": "10.0.0.20"}},
                client_metadata={"00:11:22:33:44:02": {"active": True, "bssid": "11:22:33:44:55:66"}}
            )
        ]
        mock_has_internet.return_value = False
        mock_test_air_targets.side_effect = [
            (False, False),  # Cycle 1: hijack unsuccessful
            (True, True)     # Cycle 2: hijack succeeds
        ]

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=0,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        with patch("time.sleep", return_value=None):
            result = run_aggressive(args)

        self.assertTrue(result)
        self.assertEqual(mock_sniff_air.call_count, 2)
        mock_sniff_air.assert_called_with(
            ["11:22:33:44:55:66"],
            interface="wlan0",
            duration=0,
            target_channels=["1"],
            bssids=mock_scan_bssids.return_value,
            bssid_threshold=10,
            ssid="Cafe_SSID",
            enable_stimulation=True,
            trigger_on_active=True,
            active_trigger_duration=30
        )
        mock_run_scan_wrapper.assert_not_called()

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
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
    def test_air_only_zero_ignores_non_active_clients_and_retries_re_captured_active_client(
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
        mock_auto_params,
        mock_is_mon
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
        ]
        # Both cycles have idle client 00:11:22:33:44:99 (active=False) and active client 00:11:22:33:44:01 (active=True).
        # In cycle 1, 00:11:22:33:44:01 fails.
        # In cycle 2, the exact same client 00:11:22:33:44:01 is re-captured and retried, succeeding!
        mock_sniff_air.side_effect = [
            AirClientsMap(
                {
                    "11:22:33:44:55:66": {
                        "00:11:22:33:44:01": "10.0.0.10",
                        "00:11:22:33:44:99": "10.0.0.99"
                    }
                },
                client_metadata={
                    "00:11:22:33:44:01": {"active": True, "bssid": "11:22:33:44:55:66"},
                    "00:11:22:33:44:99": {"active": False, "bssid": "11:22:33:44:55:66"}
                }
            ),
            AirClientsMap(
                {
                    "11:22:33:44:55:66": {
                        "00:11:22:33:44:01": "10.0.0.10",
                        "00:11:22:33:44:99": "10.0.0.99"
                    }
                },
                client_metadata={
                    "00:11:22:33:44:01": {"active": True, "bssid": "11:22:33:44:55:66"},
                    "00:11:22:33:44:99": {"active": False, "bssid": "11:22:33:44:55:66"}
                }
            )
        ]

        # Cycle 1 returns failure, Cycle 2 returns success
        mock_test_air_targets.side_effect = [
            (False, False),
            (True, True)
        ]

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=0,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        with patch("time.sleep", return_value=None):
            result = run_aggressive(args)

        self.assertTrue(result)
        self.assertEqual(mock_test_air_targets.call_count, 2)
        # Verify that ONLY the active client was passed to test_air_client_targets (non-active 00:11:22:33:44:99 was excluded)
        for call_args in mock_test_air_targets.call_args_list:
            tested_clients = call_args[0][0]
            self.assertIn("00:11:22:33:44:01", tested_clients)
            self.assertNotIn("00:11:22:33:44:99", tested_clients)

    @patch("cafe_chameleon.modes.aggressive.runner.set_restore_params")
    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", side_effect=[False, True])
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner._run")
    def test_run_aggressive_registers_restore_params_on_entry(
        self,
        mock_run,
        mock_sniff,
        mock_scan_bssids,
        mock_has_net,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params,
        mock_is_mon,
        mock_set_restore
    ):
        mock_scan_bssids.return_value = [{"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"}]
        mock_sniff.return_value = {}

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=0,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        with patch("time.sleep", return_value=None):
            run_aggressive(args)

        mock_set_restore.assert_called_with("wlan0", "", "", "", "", profile="Cafe_WiFi")

    @patch("cafe_chameleon.modes.aggressive.runner.log_main")
    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet")
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    def test_air_only_minimal_cycle_printing(
        self,
        mock_test_air_targets,
        mock_set_mac,
        mock_wait_carrier,
        mock_lock_bssid,
        mock_sniff_air,
        mock_scan_bssids,
        mock_has_internet,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params,
        mock_is_mon,
        mock_log_main
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "11:22:33:44:55:66", "signal": "80", "chan": "1", "security": "OPEN"},
        ]
        mock_sniff_air.side_effect = [
            AirClientsMap(
                {"11:22:33:44:55:66": {"00:11:22:33:44:01": "10.0.0.10"}},
                client_metadata={"00:11:22:33:44:01": {"active": True, "bssid": "11:22:33:44:55:66"}}
            )
        ]
        mock_has_internet.return_value = False
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=None,
            air_only=0,
            any_bssid=False,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        with patch("time.sleep", return_value=None):
            run_aggressive(args)

        logged_messages = [call.args[0] for call in mock_log_main.call_args_list if call.args]
        
        # Verify minimal cycle string is printed
        self.assertIn("[Cycle #1] Hunting...", logged_messages)
        
        # Verify verbose table / setup messages are NOT printed
        for msg in logged_messages:
            self.assertNotIn("AUTO-RANKED BSSID TARGETS", msg)
            self.assertNotIn("Continuous Air-Only hunting mode active", msg)
            self.assertNotIn("Skipping subnet scanning", msg)


if __name__ == "__main__":
    unittest.main()


