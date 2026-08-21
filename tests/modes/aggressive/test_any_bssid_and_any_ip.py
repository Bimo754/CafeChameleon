import argparse
import unittest
from unittest.mock import patch, MagicMock, call

from cafe_chameleon.cli.parser import parse_arguments
import cafe_chameleon.modes.aggressive.air_target_handler as air_target_handler
from cafe_chameleon.modes.aggressive.runner import run_aggressive


class TestAnyBSSIDAndAnyIP(unittest.TestCase):

    # ---------------------------------------------------------
    # 1. CLI Parsing Tests
    # ---------------------------------------------------------
    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--any-bssid"])
    def test_cli_parser_any_bssid_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.any_bssid)
        self.assertFalse(getattr(args, "any_ip", False))

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--any-ip"])
    def test_cli_parser_any_ip_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.any_ip)
        self.assertFalse(getattr(args, "any_bssid", False))

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--any-bssid", "--any-ip"])
    def test_cli_parser_both_flags(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.any_bssid)
        self.assertTrue(args.any_ip)

    @patch("sys.argv", ["cafe-chameleon", "aggressive"])
    def test_cli_parser_default_flags_false(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertFalse(getattr(args, "any_bssid", False))
        self.assertFalse(getattr(args, "any_ip", False))

    # ---------------------------------------------------------
    # 2. --any-ip Fast Impersonation Logic Tests
    # ---------------------------------------------------------
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.hijack")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.resolve_mac_to_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.query_dhcp_lease_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler._run")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.wait_for_carrier", return_value=True)
    def test_any_ip_skips_ip_resolution_probes(
        self, mock_carrier, mock_run, mock_query_dhcp, mock_resolve_mac, mock_hijack
    ):
        mock_hijack.return_value = True
        mock_run.return_value = (0, "")

        new_air_clients = {"00:11:22:33:44:55": None}
        tried_macs = set()
        auto_params = {
            "local_ip": "192.168.1.50",
            "gateway_ip": "192.168.1.1",
            "cidr": "192.168.1.50/24",
            "broadcast": "192.168.1.255",
            "local_mac": "aa:bb:cc:dd:ee:ff",
        }
        args = argparse.Namespace(any_ip=True, force=False, force_deauth=False)

        success, stop_early = air_target_handler.test_air_client_targets(
            new_air_clients,
            interface="wlan0",
            target_bssid="11:22:33:44:55:66",
            chan=1,
            profile="test_wifi",
            tried_macs=tried_macs,
            auto_params=auto_params,
            args=args
        )

        self.assertTrue(success)
        self.assertTrue(stop_early)
        # Verify resolution probes were NEVER called
        mock_resolve_mac.assert_not_called()
        mock_query_dhcp.assert_not_called()

        # Verify hijack was called with auto_ip ("192.168.1.50") and client MAC
        mock_hijack.assert_called_once()
        call_args = mock_hijack.call_args[0]
        self.assertEqual(call_args[0], "wlan0")
        self.assertEqual(call_args[1], "192.168.1.50")
        self.assertEqual(call_args[2], "00:11:22:33:44:55")

    @patch("cafe_chameleon.modes.aggressive.air_target_handler.hijack")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.resolve_mac_to_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.query_dhcp_lease_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler._run")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.wait_for_carrier", return_value=True)
    def test_default_mode_calls_ip_resolution_when_no_air_ip(
        self, mock_carrier, mock_run, mock_query_dhcp, mock_resolve_mac, mock_hijack
    ):
        mock_resolve_mac.return_value = "192.168.1.120"
        mock_hijack.return_value = True
        mock_run.return_value = (0, "")

        new_air_clients = {"00:11:22:33:44:55": None}
        tried_macs = set()
        auto_params = {
            "local_ip": "192.168.1.50",
            "gateway_ip": "192.168.1.1",
            "cidr": "192.168.1.50/24",
            "broadcast": "192.168.1.255",
            "local_mac": "aa:bb:cc:dd:ee:ff",
        }
        args = argparse.Namespace(any_ip=False, force=False, force_deauth=False)

        success, stop_early = air_target_handler.test_air_client_targets(
            new_air_clients,
            interface="wlan0",
            target_bssid="11:22:33:44:55:66",
            chan=1,
            profile="test_wifi",
            tried_macs=tried_macs,
            auto_params=auto_params,
            args=args
        )

        self.assertTrue(success)
        mock_resolve_mac.assert_called_once()
        mock_hijack.assert_called_once()
        self.assertEqual(mock_hijack.call_args[0][1], "192.168.1.120")

    # ---------------------------------------------------------
    # 3. --any-bssid Client Pooling & Multi-BSSID Execution
    # ---------------------------------------------------------
    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", side_effect=[False, False, True])
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    def test_any_bssid_pools_clients_across_all_bssids(
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
        mock_is_mon
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "10:11:12:13:14:15", "signal": "90", "chan": "1", "security": "OPEN"},
            {"bssid": "20:21:22:23:24:25", "signal": "40", "chan": "6", "security": "OPEN"},
        ]
        # BSSID 1 has client 1, BSSID 2 has client 2 (both valid unicast MACs)
        mock_sniff_air.return_value = {
            "10:11:12:13:14:15": {"00:11:22:33:44:01": "10.0.0.10"},
            "20:21:22:23:24:25": {"00:11:22:33:44:02": "10.0.0.20"},
        }
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=5,
            any_bssid=True,
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

        # Verify test_air_client_targets received BOTH clients on the first locked BSSID (10:11:12:13:14:15)
        mock_test_air_targets.assert_called_once()
        passed_clients = mock_test_air_targets.call_args[0][0]
        self.assertIn("00:11:22:33:44:01", passed_clients)
        self.assertIn("00:11:22:33:44:02", passed_clients)

    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", side_effect=[False, False, True])
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    def test_without_any_bssid_targets_only_associated_clients(
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
        mock_is_mon
    ):
        mock_scan_bssids.return_value = [
            {"bssid": "10:11:12:13:14:15", "signal": "90", "chan": "1", "security": "OPEN"},
            {"bssid": "20:21:22:23:24:25", "signal": "40", "chan": "6", "security": "OPEN"},
        ]
        # BSSID 1 has client 1, BSSID 2 has client 2
        mock_sniff_air.return_value = {
            "10:11:12:13:14:15": {"00:11:22:33:44:01": "10.0.0.10"},
            "20:21:22:23:24:25": {"00:11:22:33:44:02": "10.0.0.20"},
        }
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=5,
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

        # Without --any-bssid, only client 1 associated with BSSID 1 should be passed on BSSID 1
        mock_test_air_targets.assert_called_once()
        passed_clients = mock_test_air_targets.call_args[0][0]
        self.assertIn("00:11:22:33:44:01", passed_clients)
        self.assertNotIn("00:11:22:33:44:02", passed_clients)

    @patch("cafe_chameleon.modes.aggressive.runner.log_main")
    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", side_effect=[False, False, True])
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    def test_any_bssid_suppresses_target_and_testing_log_main(
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
            {"bssid": "10:11:12:13:14:15", "signal": "90", "chan": "1", "security": "OPEN"},
        ]
        mock_sniff_air.return_value = {
            "10:11:12:13:14:15": {"00:11:22:33:44:01": "10.0.0.10"},
        }
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=5,
            any_bssid=True,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        run_aggressive(args)
        logged_messages = [call.args[0] for call in mock_log_main.call_args_list if call.args]

        for msg in logged_messages:
            self.assertNotIn("Target:", msg)
            self.assertNotIn("Testing", msg)


if __name__ == "__main__":
    unittest.main()

