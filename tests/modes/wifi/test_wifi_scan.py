"""
tests.test_wifi_scan - Unit and integration tests for Wi-Fi scanning (`wifi --scan`) functionality.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.models import BSSIDTarget
from cafe_chameleon.network.nmcli.bssid import scan_nearby_wifi_networks
from cafe_chameleon.network.nmcli.ui_status import show_wifi_scan
from cafe_chameleon.modes.wifi.controller import run_wifi


class TestWiFiScan(unittest.TestCase):

    def test_cli_wifi_scan_parsing_no_args(self):
        with patch.object(sys, "argv", ["main.py", "wifi", "--scan"]):
            args = parse_arguments()
            self.assertEqual(args.command, "wifi")
            self.assertEqual(args.scan, [])

    def test_cli_wifi_scan_parsing_with_ssid(self):
        with patch.object(sys, "argv", ["main.py", "wifi", "--scan", "MyTargetNetwork"]):
            args = parse_arguments()
            self.assertEqual(args.command, "wifi")
            self.assertEqual(args.scan, ["MyTargetNetwork"])

    def test_cli_wifi_scan_parsing_multi_word_ssid(self):
        with patch.object(sys, "argv", ["main.py", "wifi", "--scan", "Campus", "Guest", "WiFi"]):
            args = parse_arguments()
            self.assertEqual(args.command, "wifi")
            self.assertEqual(args.scan, ["Campus", "Guest", "WiFi"])

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_scan_nearby_wifi_networks_parses_full_properties(self, mock_run):
        mock_output = (
            r"EE\:C6\:F0\:CD\:0F\:29:ESP32CAM:100:6:WPA2:no:▂▄▆█:Infra:1170 Mbit/s" + "\n"
            r"BC\:99\:30\:C6\:B4\:10:GSBWIFI:55:6::yes:▂▄__:Infra:1170 Mbit/s" + "\n"
            r"BC\:99\:30\:C6\:CE\:E0:GSBWIFI:79:140::no:▂▄▆_:Infra:1170 Mbit/s" + "\n"
            r"3E\:78\:95\:41\:98\:46::37:8:WPA2:no:▂▄__:Infra:1170 Mbit/s" + "\n"
            r"A4\:A9\:30\:54\:17\:EE:Pera\:Office:30:5:WPA1 WPA2:no:▂___:Infra:270 Mbit/s" + "\n"
        )
        mock_run.side_effect = [
            (0, ""),           # rescan
            (0, mock_output)   # list
        ]

        networks = scan_nearby_wifi_networks(rescan=True)
        self.assertEqual(len(networks), 5)

        # 1st (highest signal: 100%)
        self.assertEqual(networks[0].bssid, "EE:C6:F0:CD:0F:29")
        self.assertEqual(networks[0].ssid, "ESP32CAM")
        self.assertEqual(networks[0].signal, "100")
        self.assertEqual(networks[0].chan, "6")
        self.assertEqual(networks[0].security, "WPA2")
        self.assertFalse(networks[0].active)
        self.assertEqual(networks[0].bars, "▂▄▆█")
        self.assertEqual(networks[0].mode, "Infra")
        self.assertEqual(networks[0].rate, "1170 Mbit/s")
        self.assertTrue(networks[0].is_encrypted)

        # 2nd (signal: 79%)
        self.assertEqual(networks[1].bssid, "BC:99:30:C6:CE:E0")
        self.assertEqual(networks[1].ssid, "GSBWIFI")
        self.assertEqual(networks[1].signal, "79")
        self.assertTrue(networks[1].is_open)

        # 3rd (signal: 55%, active=True)
        self.assertEqual(networks[2].bssid, "BC:99:30:C6:B4:10")
        self.assertTrue(networks[2].active)
        self.assertTrue(networks[2].is_open)

        # 4th (hidden SSID)
        self.assertEqual(networks[3].bssid, "3E:78:95:41:98:46")
        self.assertEqual(networks[3].ssid, "")
        self.assertTrue(networks[3].is_encrypted)

        # 5th (escaped colon in SSID "Pera:Office")
        self.assertEqual(networks[4].bssid, "A4:A9:30:54:17:EE")
        self.assertEqual(networks[4].ssid, "Pera:Office")
        self.assertEqual(networks[4].security, "WPA1 WPA2")

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_scan_nearby_wifi_networks_filtering(self, mock_run):
        mock_output = (
            r"EE\:C6\:F0\:CD\:0F\:29:ESP32CAM:100:6:WPA2:no:▂▄▆█:Infra:1170 Mbit/s" + "\n"
            r"BC\:99\:30\:C6\:B4\:10:GSBWIFI:55:6::yes:▂▄__:Infra:1170 Mbit/s" + "\n"
            r"BC\:99\:30\:C6\:CE\:E0:GSBWIFI:79:140::no:▂▄▆_:Infra:1170 Mbit/s" + "\n"
        )
        mock_run.side_effect = [
            (0, ""),           # rescan
            (0, mock_output)   # list
        ]

        filtered = scan_nearby_wifi_networks(target_ssid="gsbwifi", rescan=True)
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(n.ssid == "GSBWIFI" for n in filtered))

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_scan_nearby_wifi_networks_fallback_to_standard_format(self, mock_run):
        mock_standard_output = (
            r"BC\:99\:30\:C6\:B4\:10:GSBWIFI:60:6::yes" + "\n"
            r"EE\:C6\:F0\:CD\:0F\:29:ESP32CAM:90:6:WPA2:no" + "\n"
        )
        mock_run.side_effect = [
            (1, "error"),             # 9-field fails
            (0, mock_standard_output) # 6-field succeeds
        ]

        networks = scan_nearby_wifi_networks(rescan=False)
        self.assertEqual(len(networks), 2)
        self.assertEqual(networks[0].bssid, "EE:C6:F0:CD:0F:29")
        self.assertEqual(networks[1].bssid, "BC:99:30:C6:B4:10")

    @patch("cafe_chameleon.network.nmcli.ui_status.scan_nearby_wifi_networks")
    def test_show_wifi_scan_success(self, mock_scan):
        mock_scan.return_value = [
            BSSIDTarget(bssid="EE:C6:F0:CD:0F:29", ssid="ESP32CAM", signal="100", chan="6", security="WPA2", active=False, bars="▂▄▆█", mode="Infra", rate="1170 Mbit/s"),
            BSSIDTarget(bssid="BC:99:30:C6:B4:10", ssid="GSBWIFI", signal="55", chan="6", security="", active=True, bars="▂▄__", mode="Infra", rate="1170 Mbit/s")
        ]

        res = show_wifi_scan()
        self.assertTrue(res)

    @patch("cafe_chameleon.network.nmcli.ui_status.scan_nearby_wifi_networks")
    def test_show_wifi_scan_empty(self, mock_scan):
        mock_scan.return_value = []
        res = show_wifi_scan()
        self.assertFalse(res)

        res_filtered = show_wifi_scan(target_ssid="NonExistent")
        self.assertFalse(res_filtered)

    @patch("cafe_chameleon.modes.wifi.controller.show_wifi_scan")
    def test_run_wifi_controller_scan_invokes_show_wifi_scan(self, mock_show):
        mock_show.return_value = True

        args = MagicMock()
        args.status = False
        args.scan = ["GSBWIFI"]
        args.lock = None
        args.auto = None
        args.mac = None
        args.reset_mac = None
        args.release = None
        args.reconnect = None
        args.share = None

        run_wifi(args)
        mock_show.assert_called_once_with(target_ssid="GSBWIFI")

    @patch("cafe_chameleon.modes.wifi.controller.show_wifi_scan")
    def test_run_wifi_controller_scan_exits_on_failure(self, mock_show):
        mock_show.return_value = False

        args = MagicMock()
        args.status = False
        args.scan = []
        args.lock = None
        args.auto = None
        args.mac = None
        args.reset_mac = None
        args.release = None
        args.reconnect = None
        args.share = None

        with self.assertRaises(SystemExit) as cm:
            run_wifi(args)
        self.assertEqual(cm.exception.code, 1)

    def test_freq_to_channel_conversions(self):
        from cafe_chameleon.network.nmcli.bssid import freq_to_channel
        # 2.4 GHz
        self.assertEqual(freq_to_channel(2412), 1)
        self.assertEqual(freq_to_channel(2437), 6)
        self.assertEqual(freq_to_channel(2462), 11)
        self.assertEqual(freq_to_channel(2472), 13)
        self.assertEqual(freq_to_channel(2484), 14)
        # 5 GHz
        self.assertEqual(freq_to_channel(5180), 36)
        self.assertEqual(freq_to_channel(5200), 40)
        self.assertEqual(freq_to_channel(5745), 149)
        self.assertEqual(freq_to_channel(5825), 165)
        # Invalid / 0
        self.assertEqual(freq_to_channel(1000), 0)

    def test_dbm_to_signal_percentage(self):
        from cafe_chameleon.network.nmcli.bssid import dbm_to_signal_percentage
        self.assertEqual(dbm_to_signal_percentage(-50.0), 100)
        self.assertEqual(dbm_to_signal_percentage(-30.0), 100)
        self.assertEqual(dbm_to_signal_percentage(-75.0), 50)
        self.assertEqual(dbm_to_signal_percentage(-90.0), 20)
        self.assertEqual(dbm_to_signal_percentage(-100.0), 0)
        self.assertEqual(dbm_to_signal_percentage(-110.0), 0)

    def test_parse_iw_scan_dump_extracts_properties(self):
        from cafe_chameleon.network.nmcli.bssid import parse_iw_scan_dump
        mock_dump = """
BSS 00:11:22:33:44:55(on wlan0) -- associated
\tTSF: 123456 usec
\tfreq: 2437.0
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime
\tsignal: -60.00 dBm
\tSSID: TestNetwork
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tfreq: 5180.0
\tsignal: -80.00 dBm
\tSSID: TestNetwork
\tcapability: ESS
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 2412.0
\tsignal: -70.00 dBm
\tSSID: OtherNet
\tWPA:\t * Version: 1
"""
        targets = parse_iw_scan_dump(mock_dump, target_ssid="TestNetwork")
        self.assertEqual(len(targets), 2)

        # 1st BSSID
        self.assertEqual(targets[0].bssid, "00:11:22:33:44:55")
        self.assertEqual(targets[0].ssid, "TestNetwork")
        self.assertEqual(targets[0].chan, "6")
        self.assertEqual(targets[0].signal, "80")  # 2 * (-60 + 100) = 80%
        self.assertEqual(targets[0].security, "WPA2")
        self.assertTrue(targets[0].active)

        # 2nd BSSID (5GHz freq 5180 -> ch 36, open security)
        self.assertEqual(targets[1].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(targets[1].ssid, "TestNetwork")
        self.assertEqual(targets[1].chan, "36")
        self.assertEqual(targets[1].signal, "40")  # 2 * (-80 + 100) = 40%
        self.assertEqual(targets[1].security, "")
        self.assertFalse(targets[1].active)

    def test_merge_bssid_targets_accumulates_and_updates(self):
        from cafe_chameleon.network.nmcli.bssid import merge_bssid_targets
        target_map = {
            "00:11:22:33:44:55": BSSIDTarget(bssid="00:11:22:33:44:55", ssid="NetA", signal="50", chan="1", security="WPA2", active=False)
        }
        new_targets = [
            # Stronger signal + active update
            BSSIDTarget(bssid="00:11:22:33:44:55", ssid="NetA", signal="85", chan="1", security="WPA2", active=True, bars="▂▄▆█"),
            # Newly discovered AP
            BSSIDTarget(bssid="AA:BB:CC:DD:EE:FF", ssid="NetA", signal="70", chan="6", security="WPA2", active=False)
        ]
        merge_bssid_targets(target_map, new_targets)

        self.assertEqual(len(target_map), 2)
        self.assertEqual(target_map["00:11:22:33:44:55"].signal, "85")
        self.assertTrue(target_map["00:11:22:33:44:55"].active)
        self.assertEqual(target_map["00:11:22:33:44:55"].bars, "▂▄▆█")
        self.assertEqual(target_map["AA:BB:CC:DD:EE:FF"].signal, "70")

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_trigger_wifi_rescan_directed_and_fallback(self, mock_run):
        from cafe_chameleon.network.nmcli.bssid import trigger_wifi_rescan
        # 1. Directed succeeds
        mock_run.return_value = (0, "")
        trigger_wifi_rescan(target_ssid="TargetSSID")
        mock_run.assert_called_with(["nmcli", "device", "wifi", "rescan", "ssid", "TargetSSID"], debug=False)

        # 2. Directed fails -> fallback to general rescan
        mock_run.side_effect = [(1, "Error"), (0, "")]
        trigger_wifi_rescan(target_ssid="TargetSSID")
        self.assertEqual(mock_run.call_count, 3)

        # 3. No SSID -> general rescan
        mock_run.side_effect = None
        mock_run.return_value = (0, "")
        trigger_wifi_rescan(target_ssid=None)
        mock_run.assert_called_with(["nmcli", "device", "wifi", "rescan"], debug=False)


if __name__ == "__main__":
    unittest.main()

