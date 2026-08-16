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
    @patch("cafe_chameleon.utils.signals.get_restore_params")
    @patch("cafe_chameleon.network.mac.reset_mac_address")
    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.utils.process._run")
    @patch("cafe_chameleon.network.nmcli.release_interface", side_effect=Exception("Simulated release failure"))
    def test_restore_and_exit_shields_sigint_and_runs_fallback(
        self, mock_release, mock_run, mock_set_managed, mock_is_mon, mock_reset_mac,
        mock_get_params, mock_close, mock_exit
    ):
        mock_get_params.return_value = {"interface": "wlan0", "profile": "MyProfile"}
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
    @patch("cafe_chameleon.utils.signals.get_restore_params")
    @patch("cafe_chameleon.network.nmcli.release_interface")
    def test_restore_and_exit_calls_release_interface_with_params(
        self, mock_release, mock_get_params, mock_close, mock_exit
    ):
        mock_get_params.return_value = {
            "interface": "wlan0",
            "macaddress": "00:11:22:33:44:55",
            "ipmask": "10.0.0.5/24",
            "broadcast": "10.0.0.255",
            "gateway": "10.0.0.1",
            "profile": "MyProfile"
        }

        restore_and_exit("Release test")

        mock_release.assert_called_once_with(interface="wlan0", profile="MyProfile")
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

    def test_xterm_manager_status_reset_and_idle(self):
        from cafe_chameleon.ui.xterm.manager import XtermManager
        mgr = XtermManager(enabled=False)
        
        # Test scan status setting and reset
        mgr.set_scan_status(subnet="10.0.0.0/24", count=5, scan_type="Deep Scan")
        self.assertEqual(mgr.scan_subnet, "10.0.0.0/24")
        self.assertEqual(mgr.scan_hosts_count, 5)
        self.assertEqual(mgr.scan_type, "Deep Scan")

        # Partial update
        mgr.set_scan_status(count=6)
        self.assertEqual(mgr.scan_subnet, "10.0.0.0/24")
        self.assertEqual(mgr.scan_hosts_count, 6)
        self.assertEqual(mgr.scan_type, "Deep Scan")

        # Reset to idle
        mgr.set_scan_status(subnet="N/A", count=0, scan_type="Idle")
        self.assertEqual(mgr.scan_subnet, "N/A")
        self.assertEqual(mgr.scan_hosts_count, 0)
        self.assertEqual(mgr.scan_type, "Idle")

        # Test hijack status setting, clear, and reset
        mgr.set_hijack_status(ip="10.0.0.50", mac="00:11:22:33:44:55", technique="ARP Cache Poisoning")
        self.assertEqual(mgr.hijack_ip, "10.0.0.50")
        self.assertEqual(mgr.hijack_mac, "00:11:22:33:44:55")
        self.assertEqual(mgr.hijack_technique, "ARP Cache Poisoning")

        # Partial update technique only preserves IP and MAC
        mgr.set_hijack_status(technique="Host Impersonation Sweep")
        self.assertEqual(mgr.hijack_ip, "10.0.0.50")
        self.assertEqual(mgr.hijack_mac, "00:11:22:33:44:55")
        self.assertEqual(mgr.hijack_technique, "Host Impersonation Sweep")

        # Reset IP and MAC back to None / Not Found
        mgr.set_hijack_status(ip=None, mac=None, technique="Idle")
        self.assertIsNone(mgr.hijack_ip)
        self.assertIsNone(mgr.hijack_mac)
        self.assertEqual(mgr.hijack_technique, "Idle")

        # Test format_hijack_header with and without MAC
        from cafe_chameleon.ui.xterm.headers import format_hijack_header
        hdr = format_hijack_header("192.168.1.100", "AA:BB:CC:DD:EE:FF", "Host Impersonation Sweep")
        lines = hdr.split("\n")
        self.assertEqual(len(lines), 4)
        self.assertIn("\033[1;37mIP:\033[0m \033[1;32m192.168.1.100\033[0m", lines[0])
        self.assertIn("\033[1;37mMac:\033[0m \033[1;33mAA:BB:CC:DD:EE:FF\033[0m", lines[1])
        self.assertIn("\033[1;37mTechnique:\033[0m \033[1;33mHost Impersonation Sweep\033[0m", lines[2])

        hdr_none = format_hijack_header(None, None, "Idle")
        lines_none = hdr_none.split("\n")
        self.assertEqual(len(lines_none), 4)
        # Test air status setting, remaining timer, and reset
        mgr.set_air_status(mode="Monitor", remaining=15)
        self.assertEqual(mgr.air_mode, "Monitor")
        self.assertEqual(mgr.air_remaining, "15s")

        mgr.set_air_status(remaining=10)
        self.assertEqual(mgr.air_mode, "Monitor")
        self.assertEqual(mgr.air_remaining, "10s")

        mgr.set_air_status(mode="Managed", remaining="N/A")
        self.assertEqual(mgr.air_mode, "Managed")
        self.assertEqual(mgr.air_remaining, "N/A")

        # Test format_air_header with mode and remaining seconds
        from cafe_chameleon.ui.xterm.headers import format_air_header
        hdr_air_mon = format_air_header("Monitor", 25)
        lines_air = hdr_air_mon.split("\n")
        self.assertEqual(len(lines_air), 2)
        self.assertIn("Monitor", lines_air[0])
        self.assertIn("25s", lines_air[0])

        hdr_air_mng = format_air_header("Managed", "N/A")
        lines_air_mng = hdr_air_mng.split("\n")
        self.assertEqual(len(lines_air_mng), 2)
        self.assertIn("Managed", lines_air_mng[0])
        self.assertIn("N/A", lines_air_mng[0])

        # Test AirCountdownTimer
        from cafe_chameleon.scanners.air.sniffer import AirCountdownTimer
        timer = AirCountdownTimer(duration=2, interval=0.1)
        timer.start()
        import time
        time.sleep(0.3)
        timer.stop()

    @patch("os._exit")
    @patch("cafe_chameleon.utils.signals.close_xterm")
    @patch("cafe_chameleon.utils.signals.get_restore_callback")
    @patch("cafe_chameleon.utils.signals.get_restore_params")
    @patch("cafe_chameleon.network.nmcli.release_interface")
    def test_restore_and_exit_calls_release_interface(
        self, mock_release, mock_get_params, mock_get_callback, mock_close, mock_exit
    ):
        mock_get_callback.return_value = None
        mock_get_params.return_value = {"interface": "wlan0", "profile": "MyProfile"}
        restore_and_exit("Testing release interface on exit")

        mock_release.assert_called_once_with(interface="wlan0", profile="MyProfile")
        mock_close.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("cafe_chameleon.network.nmcli.release_interface")
    @patch("main.parse_arguments")
    @patch("main.init_xterm", return_value=False)
    def test_main_calls_release_interface_when_aggressive_or_simple_fails(
        self, mock_init, mock_parse, mock_release
    ):
        from main import main
        mock_args = MagicMock()
        mock_args.debug = False
        mock_args.original_mac = False
        mock_args.quiet = True
        mock_args.interface = "wlan0"
        mock_args.profile = "TestProfile"
        mock_args.no_xterm = True
        mock_args.command = "aggressive"
        mock_args.func.return_value = False
        mock_parse.return_value = mock_args

        main()
        mock_release.assert_called_with(interface="wlan0", profile="TestProfile")


if __name__ == "__main__":
    unittest.main()

