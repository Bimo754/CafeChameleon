"""
tests.modes.wifi.test_wifi_hard_reset - Unit tests for wifi -hr / wifi --hard-reset hardware card reset.
"""

import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.network.nmcli.restore import get_interface_driver, hard_reset_interface
from cafe_chameleon.modes.wifi.controller import run_wifi


class TestWifiHardReset(unittest.TestCase):

    def test_cli_parser_recognizes_hard_reset_flags(self):
        # Short flag: -hr
        args1 = parse_arguments(["wifi", "-hr", "wlan0"])
        self.assertEqual(args1.command, "wifi")
        self.assertEqual(args1.hard_reset, ["wlan0"])

        # Long flag: --hard-reset
        args2 = parse_arguments(["wifi", "--hard-reset"])
        self.assertEqual(args2.command, "wifi")
        self.assertEqual(args2.hard_reset, [])

    @patch("cafe_chameleon.network.nmcli.restore._run")
    @patch("os.path.islink", return_value=True)
    @patch("os.readlink", return_value="../../../bus/pci/drivers/iwlwifi")
    def test_get_interface_driver_sysfs(self, mock_readlink, mock_islink, mock_run):
        driver = get_interface_driver("wlan0")
        self.assertEqual(driver, "iwlwifi")

    @patch("cafe_chameleon.network.nmcli.restore.get_interface_driver", return_value="iwlwifi")
    @patch("cafe_chameleon.network.nmcli.restore.release_interface", return_value=True)
    @patch("cafe_chameleon.network.nmcli.restore._run", return_value=(0, ""))
    @patch("shutil.which", return_value="/bin/systemctl")
    def test_hard_reset_interface_workflow(self, mock_which, mock_run, mock_release, mock_driver):
        res = hard_reset_interface(interface="wlan0", profile="TestProfile")
        self.assertTrue(res)

        # Verify release_interface was called
        mock_release.assert_called_once_with(interface="wlan0", profile="TestProfile")

        # Verify modprobe commands were called
        run_cmds = [call_item[0][0] for call_item in mock_run.call_args_list if call_item[0]]
        modprobe_calls = [c for c in run_cmds if isinstance(c, list) and len(c) > 0 and c[0] == "modprobe"]
        self.assertGreaterEqual(len(modprobe_calls), 2)
        self.assertIn("-r", modprobe_calls[0])
        self.assertIn("iwlwifi", modprobe_calls[0])
        self.assertIn("iwlwifi", modprobe_calls[1])

    @patch("cafe_chameleon.modes.wifi.controller.hard_reset_interface", return_value=True)
    def test_run_wifi_invokes_hard_reset(self, mock_hard_reset):
        args = MagicMock()
        args.status = False
        args.scan = None
        args.lock = None
        args.auto = None
        args.mac = None
        args.reset_mac = None
        args.release = None
        args.hard_reset = ["wlan0"]
        args.reconnect = None
        args.share = None

        run_wifi(args)
        mock_hard_reset.assert_called_once_with(interface="wlan0", profile=None)


if __name__ == "__main__":
    unittest.main()
