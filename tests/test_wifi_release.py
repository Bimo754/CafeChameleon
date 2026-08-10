import unittest
from unittest.mock import patch, MagicMock
import argparse

from cafe_chameleon.network.nmcli.restore import release_interface
from cafe_chameleon.modes.wifi.controller import run_wifi
from cafe_chameleon.cli.parser import parse_arguments


class TestWifiRelease(unittest.TestCase):

    @patch("cafe_chameleon.network.sysfs.wait_for_carrier")
    @patch("cafe_chameleon.network.mac.reset_mac_address")
    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.network.nmcli.restore._run")
    @patch("cafe_chameleon.network.nmcli.restore.get_active_profile")
    @patch("cafe_chameleon.scanners.detector.auto_detect_network_params")
    def test_release_interface_full_flow(
        self,
        mock_auto_params,
        mock_get_profile,
        mock_run,
        mock_is_mon,
        mock_set_managed,
        mock_reset_mac,
        mock_wait_carrier
    ):
        mock_auto_params.return_value = {"interface": "wlan0"}
        mock_get_profile.return_value = "TestProfile"
        mock_is_mon.return_value = True
        mock_run.return_value = (0, "")
        mock_reset_mac.return_value = True
        mock_wait_carrier.return_value = True

        result = release_interface(interface="wlan0", profile="TestProfile")
        self.assertTrue(result)

        # 1. Verify dhclient killed
        mock_run.assert_any_call("pkill -9 -f 'dhclient.*wlan0'", debug=False)

        # 2. Verify monitor mode converted back to managed
        mock_set_managed.assert_called_once_with("wlan0")

        # 3. Verify NM profile BSSID and cloned MAC reset
        mock_run.assert_any_call(["nmcli", "connection", "modify", "TestProfile", "802-11-wireless.bssid", ""], debug=False)
        mock_run.assert_any_call(["nmcli", "connection", "modify", "TestProfile", "802-11-wireless.cloned-mac-address", ""], debug=False)

        # 4. Verify MAC reset
        mock_reset_mac.assert_called_once_with("wlan0", profile="TestProfile")

        # 5. Verify device set managed
        mock_run.assert_any_call(["nmcli", "device", "set", "wlan0", "managed", "yes"], debug=False)

        # 6. Verify connection up
        mock_run.assert_any_call(["nmcli", "connection", "up", "TestProfile"], debug=False, timeout=15.0)

    @patch("cafe_chameleon.modes.wifi.controller.release_interface")
    def test_run_wifi_release_action(self, mock_release):
        mock_release.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=[]
        )
        run_wifi(args)
        mock_release.assert_called_once_with(interface=None, profile=None)

    @patch("cafe_chameleon.modes.wifi.controller.release_interface")
    def test_run_wifi_release_with_iface_arg(self, mock_release):
        mock_release.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=["wlan0"]
        )
        run_wifi(args)
        mock_release.assert_called_once_with(interface="wlan0", profile=None)

    @patch("sys.argv", ["main.py", "wifi", "--release"])
    def test_cli_parser_release_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "wifi")
        self.assertEqual(args.release, [])


if __name__ == "__main__":
    unittest.main()
