import unittest
from unittest.mock import patch, MagicMock, call
import argparse
import subprocess

from cafe_chameleon.network.hotspot import (
    check_ap_mode_support,
    clean_hotspot_interfaces,
    get_interface_channel_and_band,
    share_wifi_hotspot
)
from cafe_chameleon.modes.wifi.controller import run_wifi
from cafe_chameleon.modes.aggressive.runner import run_aggressive, handle_auto_share_if_requested
from cafe_chameleon.cli.parser import parse_arguments


class TestWifiShare(unittest.TestCase):

    @patch("cafe_chameleon.network.hotspot._run")
    def test_check_ap_mode_support_success(self, mock_run):
        sample_iw_list = """
        Supported interface modes:
                 * IBSS
                 * managed
                 * AP
                 * AP/VLAN
                 * monitor
        valid interface combinations:
                 * #{ managed, P2P-client } <= 2, #{ AP } <= 1, #{ P2P-device } <= 1,
                   total <= 3, #channels <= 1
        """
        mock_run.return_value = (0, sample_iw_list)
        supported, msg = check_ap_mode_support("wlan0")
        self.assertTrue(supported)
        self.assertIn("supports AP mode and AP-STA concurrency", msg)

    @patch("cafe_chameleon.network.hotspot._run")
    def test_check_ap_mode_support_no_ap(self, mock_run):
        sample_iw_list = """
        Supported interface modes:
                 * managed
                 * monitor
        """
        mock_run.return_value = (0, sample_iw_list)
        supported, msg = check_ap_mode_support("wlan0")
        self.assertFalse(supported)
        self.assertIn("does not support AP", msg)

    @patch("cafe_chameleon.network.hotspot._run")
    @patch("shutil.which", return_value="/usr/bin/create_ap")
    def test_clean_hotspot_interfaces(self, mock_which, mock_run):
        mock_run.side_effect = [
            (0, ""), # create_ap --stop ap0
            (0, "Interface ap0\nInterface wlan0"), # iw dev
            (0, ""), # iw dev ap0 del
            (0, ""), # nmcli device set wlan0 managed yes
        ]
        clean_hotspot_interfaces(ap_iface="ap0", parent_iface="wlan0")
        mock_run.assert_any_call(["create_ap", "--stop", "ap0"], debug=False)
        mock_run.assert_any_call(["iw", "dev", "ap0", "del"], debug=False)
        mock_run.assert_any_call(["nmcli", "device", "set", "wlan0", "managed", "yes"], debug=False)

    @patch("cafe_chameleon.network.hotspot._run")
    def test_get_interface_channel_and_band_2ghz(self, mock_run):
        mock_run.return_value = (0, "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tfreq: 2437")
        chan, band = get_interface_channel_and_band("wlan0")
        self.assertEqual(chan, 6)
        self.assertEqual(band, "2.4")

    @patch("cafe_chameleon.network.hotspot.clean_hotspot_interfaces")
    @patch("cafe_chameleon.network.hotspot.get_interface_channel_and_band", return_value=(6, "2.4"))
    @patch("cafe_chameleon.network.hotspot.check_ap_mode_support", return_value=(True, "AP supported"))
    @patch("cafe_chameleon.network.hotspot.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.network.hotspot._run", return_value=(0, ""))
    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/create_ap")
    def test_share_wifi_hotspot_execution(
        self,
        mock_which,
        mock_popen,
        mock_run,
        mock_params,
        mock_check_ap,
        mock_get_chan,
        mock_clean
    ):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = 0
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        result = share_wifi_hotspot(
            hotspot_name="MyRepeater",
            password="SecretPassword123",
            interface="wlan0"
        )
        self.assertTrue(result)
        # Verify sysctl IP forwarding
        mock_run.assert_any_call(["sysctl", "-w", "net.ipv4.ip_forward=1"], debug=False)
        # Verify nmcli ap0 unmanaged
        mock_run.assert_any_call(["nmcli", "device", "set", "ap0", "managed", "no"], debug=False)
        # Verify create_ap command invocation
        mock_popen.assert_called_once_with(["create_ap", "-c", "6", "--freq-band", "2.4", "wlan0", "wlan0", "MyRepeater", "SecretPassword123"])
        # Verify cleanup called
        self.assertTrue(mock_clean.called)

    @patch("shutil.which", return_value=None)
    def test_share_wifi_hotspot_missing_create_ap(self, mock_which):
        result = share_wifi_hotspot("MyHotspot", "SecretPass123", interface="wlan0")
        self.assertFalse(result)

    @patch("shutil.which", return_value="/usr/bin/create_ap")
    def test_share_wifi_hotspot_short_password(self, mock_which):
        result = share_wifi_hotspot("MyHotspot", "1234", interface="wlan0")
        self.assertFalse(result)

    @patch("sys.argv", ["main.py", "wifi", "--share", "CafeHotspot", "Pass123456"])
    def test_cli_parser_wifi_share(self):
        args = parse_arguments()
        self.assertEqual(args.command, "wifi")
        self.assertEqual(args.share, ["CafeHotspot", "Pass123456"])

    @patch("sys.argv", ["main.py", "aggressive", "--share", "AutoHotspot", "SecurePass88"])
    def test_cli_parser_aggressive_share(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.share, ["AutoHotspot", "SecurePass88"])

    @patch("cafe_chameleon.modes.wifi.controller.share_wifi_hotspot", return_value=True)
    def test_wifi_controller_share_dispatch(self, mock_share):
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            mac=None,
            reset_mac=None,
            release=None,
            reconnect=None,
            share=["CafeHotspot", "Pass123456"],
            interface="wlan0"
        )
        run_wifi(args)
        mock_share.assert_called_once_with(
            hotspot_name="CafeHotspot",
            password="Pass123456",
            interface="wlan0"
        )

    @patch("cafe_chameleon.modes.aggressive.runner.share_wifi_hotspot", return_value=True)
    def test_aggressive_handle_auto_share(self, mock_share):
        args = argparse.Namespace(
            share=["AutoHotspot", "SecurePass88"]
        )
        handle_auto_share_if_requested(args, "wlan0")
        mock_share.assert_called_once_with(
            hotspot_name="AutoHotspot",
            password="SecurePass88",
            interface="wlan0"
        )


if __name__ == "__main__":
    unittest.main()
