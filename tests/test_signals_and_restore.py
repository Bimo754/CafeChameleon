import unittest
from unittest.mock import patch, MagicMock, call
import signal
import sys

from cafe_chameleon.utils.signals import restore_and_exit, MainSkipInterrupt, AirSkipInterrupt, WindowCtrlCInterrupt
from cafe_chameleon.utils.state import set_restore_params
from cafe_chameleon.modes.aggressive.selector import display_and_select_bssid
from cafe_chameleon.network.nmcli.ui_status import select_bssid_interactively
from cafe_chameleon.scanners.air.sniffer import sniff_air_clients


class TestSignalsAndRestoreCleanup(unittest.TestCase):

    @patch("os._exit")
    @patch("cafe_chameleon.utils.signals.close_xterm")
    @patch("cafe_chameleon.utils.signals.get_restore_callback")
    @patch("cafe_chameleon.utils.signals.get_restore_params")
    @patch("cafe_chameleon.network.mac.reset_mac_address")
    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.utils.process._run")
    def test_restore_and_exit_shields_sigint_and_runs_fallback(
        self, mock_run, mock_set_managed, mock_is_mon, mock_reset_mac,
        mock_get_params, mock_get_callback, mock_close, mock_exit
    ):
        mock_get_callback.return_value = None
        mock_get_params.return_value = None
        mock_is_mon.return_value = True
        mock_run.return_value = (0, "")
        mock_reset_mac.return_value = True

        restore_and_exit("Testing exit")

        # Verify SIGINT and SIGTERM were shielded (set to SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)

        # Verify monitor mode cleanup
        mock_set_managed.assert_called_with("wlan0")

        # Verify fallback MAC reset and pkill dhclient
        mock_reset_mac.assert_called()
        mock_close.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("os._exit")
    @patch("cafe_chameleon.utils.signals.close_xterm")
    @patch("cafe_chameleon.utils.signals.get_restore_callback")
    @patch("cafe_chameleon.utils.signals.get_restore_params")
    @patch("cafe_chameleon.scanners.air.mode.is_monitor_mode_active")
    @patch("cafe_chameleon.network.mac.reset_mac_address")
    def test_restore_and_exit_with_registered_callback(
        self, mock_reset_mac, mock_is_mon, mock_get_params, mock_get_callback, mock_close, mock_exit
    ):
        mock_callback = MagicMock()
        mock_get_callback.return_value = mock_callback
        mock_get_params.return_value = {
            "interface": "wlan0",
            "macaddress": "00:11:22:33:44:55",
            "ipmask": "10.0.0.5/24",
            "broadcast": "10.0.0.255",
            "gateway": "10.0.0.1",
            "profile": "MyProfile"
        }
        mock_is_mon.return_value = False

        restore_and_exit("Callback test")

        mock_callback.assert_called_once_with(
            "wlan0",
            "00:11:22:33:44:55",
            "10.0.0.5/24",
            "10.0.0.255",
            "10.0.0.1",
            profile="MyProfile"
        )
        mock_close.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("cafe_chameleon.modes.aggressive.selector.restore_and_exit")
    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_exits_on_q(self, mock_input, mock_restore_exit):
        mock_input.return_value = "q"
        bssids = [{"bssid": "00:11:22:33:44:55", "signal": "80", "chan": "1", "security": "WPA2"}]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        mock_restore_exit.assert_called_once_with("User requested exit at BSSID selection.")

    @patch("cafe_chameleon.modes.aggressive.selector.restore_and_exit")
    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_exits_on_keyboard_interrupt(self, mock_input, mock_restore_exit):
        mock_input.side_effect = KeyboardInterrupt()
        bssids = [{"bssid": "00:11:22:33:44:55", "signal": "80", "chan": "1", "security": "WPA2"}]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        mock_restore_exit.assert_called_once_with("Ctrl+C received at BSSID selection.")

    @patch("cafe_chameleon.modes.aggressive.selector.restore_and_exit")
    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_exits_on_main_skip_interrupt(self, mock_input, mock_restore_exit):
        mock_input.side_effect = MainSkipInterrupt()
        bssids = [{"bssid": "00:11:22:33:44:55", "signal": "80", "chan": "1", "security": "WPA2"}]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        mock_restore_exit.assert_called_once_with("Ctrl+C received at BSSID selection.")

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_valid_selection(self, mock_input):
        mock_input.return_value = "2"
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "90", "chan": "1", "security": "WPA2"},
            {"bssid": "00:11:22:33:44:02", "signal": "80", "chan": "6", "security": "WPA2"},
            {"bssid": "00:11:22:33:44:03", "signal": "70", "chan": "11", "security": "WPA2"}
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["bssid"], "00:11:22:33:44:02")

    @patch("cafe_chameleon.network.nmcli.ui_status.scan_bssids_for_ssid")
    @patch("cafe_chameleon.network.nmcli.ui_status.get_user_input")
    @patch("cafe_chameleon.utils.signals.restore_and_exit")
    def test_select_bssid_interactively_exits_on_q_or_ctrl_c(self, mock_restore_exit, mock_input, mock_scan):
        mock_scan.return_value = [{"bssid": "00:11:22:33:44:55", "signal": "80", "chan": "1", "security": "WPA2", "active": True}]
        
        # Test 'q'
        mock_input.return_value = "q"
        select_bssid_interactively("MyWiFi")
        mock_restore_exit.assert_called_with("User cancelled BSSID selection.")

        # Test KeyboardInterrupt
        mock_input.side_effect = KeyboardInterrupt()
        select_bssid_interactively("MyWiFi")
        mock_restore_exit.assert_called_with("Ctrl+C received during BSSID selection.")

    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("cafe_chameleon.scanners.air.sniffer.log_air")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_logs_ctrl_c(self, mock_sniff, mock_log_air, mock_hopper_cls, mock_set_mon, mock_set_managed):
        mock_set_mon.return_value = "wlan0"
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        sniff_air_clients(["00:11:22:33:44:55"], interface="wlan0", duration=5)

        logged_texts = [call_args[0][0] for call_args in mock_log_air.call_args_list]
        self.assertTrue(any("Ctrl+C" in t for t in logged_texts))


if __name__ == "__main__":
    unittest.main()
