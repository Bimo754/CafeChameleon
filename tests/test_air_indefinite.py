"""
tests/test_air_indefinite.py - Unit tests for 0-second indefinite air sniffing and active triggering.
"""

import sys
import time
import unittest
import argparse
from unittest.mock import patch, MagicMock

from cafe_chameleon.scanners.air.sniffer import (
    AirCountdownTimer,
    format_air_panel,
    sniff_air_clients
)
from cafe_chameleon.modes.aggressive.runner import run_aggressive
from cafe_chameleon.utils.signals import AirSkipInterrupt


class TestAirIndefiniteTimerAndPanel(unittest.TestCase):
    """Tests AirCountdownTimer and panel formatting for indefinite and active-triggered modes."""

    def test_format_air_panel_indefinite(self):
        panel = format_air_panel(
            client_metadata={},
            mode="Monitor",
            remaining="Indefinite",
            duration=0,
            include_banner=True
        )
        self.assertIn("Duration:", panel)
        self.assertIn("Indefinite", panel)

    def test_format_air_panel_waiting(self):
        panel = format_air_panel(
            client_metadata={},
            mode="Monitor",
            remaining="Waiting for active...",
            duration=0,
            include_banner=True
        )
        self.assertIn("Waiting for active...", panel)

    def test_air_countdown_timer_indefinite_start_and_stop(self):
        timer = AirCountdownTimer(duration=0, interval=0.05, waiting_for_active=False)
        timer.start()
        time.sleep(0.1)
        self.assertIsNone(timer._countdown_end)
        timer.stop()

    def test_air_countdown_timer_active_trigger(self):
        timer = AirCountdownTimer(duration=0, interval=0.05, waiting_for_active=True)
        timer.start()
        self.assertTrue(timer.waiting_for_active)
        # Dynamically trigger countdown
        timer.trigger_countdown(duration=30)
        self.assertFalse(timer.waiting_for_active)
        self.assertIsNotNone(timer._countdown_end)
        self.assertEqual(timer._active_triggered_duration, 30)
        timer.stop()


class TestSniffAirClientsIndefinite(unittest.TestCase):
    """Tests sniff_air_clients behavior when duration=0."""

    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode", return_value="wlan0mon")
    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff")
    def test_sniff_air_clients_zero_duration_calls_sniff_with_timeout_none(
        self,
        mock_sniff,
        mock_hopper_cls,
        mock_set_managed,
        mock_set_monitor
    ):
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper

        result = sniff_air_clients(
            target_bssids=["11:22:33:44:55:66"],
            interface="wlan0",
            duration=0,
            trigger_on_active=False
        )

        mock_sniff.assert_called_once()
        self.assertIsNone(mock_sniff.call_args[1]["timeout"])
        self.assertIsNone(mock_sniff.call_args[1]["stop_filter"])
        mock_set_managed.assert_called_with("wlan0")

    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode", return_value="wlan0mon")
    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff")
    def test_sniff_air_clients_handles_air_skip_interrupt_cleanly(
        self,
        mock_sniff,
        mock_hopper_cls,
        mock_set_managed,
        mock_set_monitor
    ):
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        result = sniff_air_clients(
            target_bssids=["11:22:33:44:55:66"],
            interface="wlan0",
            duration=0,
            trigger_on_active=False
        )

        # Should cleanly exit and restore managed mode
        mock_set_managed.assert_called_with("wlan0")
        self.assertIn("11:22:33:44:55:66", result)


class TestAggressiveAirZeroExecution(unittest.TestCase):
    """Tests aggressive exploration execution when --air 0 is passed."""

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
    def test_air_zero_runs_indefinite_sniff_then_scans_subnet(
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
        mock_run_scan_wrapper.return_value = True

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=0,
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
        self.assertTrue(result)

        # sniff_air_clients must be called with duration=0
        mock_sniff_air.assert_called_once()
        self.assertEqual(mock_sniff_air.call_args[1]["duration"], 0)
        self.assertFalse(mock_sniff_air.call_args[1]["trigger_on_active"])

        # Since it's --air 0 (not --air-only), run_scan_wrapper MUST be called
        mock_run_scan_wrapper.assert_called_once()


if __name__ == "__main__":
    unittest.main()
