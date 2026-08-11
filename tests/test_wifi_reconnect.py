import unittest
from unittest.mock import patch, MagicMock, call
import argparse

from cafe_chameleon.network.nmcli.reconnect import reconnect_wifi, perform_reconnect, monitor_and_auto_reconnect
from cafe_chameleon.modes.wifi.controller import run_wifi
from cafe_chameleon.cli.parser import parse_arguments


class TestWifiReconnect(unittest.TestCase):

    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_current_mac")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_active_profile")
    @patch("cafe_chameleon.scanners.detector.auto_detect_network_params")
    def test_reconnect_wifi_auto_detection(
        self,
        mock_auto_params,
        mock_active_prof,
        mock_conn_bssid,
        mock_curr_mac,
        mock_perform
    ):
        mock_auto_params.return_value = {
            "interface": "wlan0",
            "local_ip": "192.168.1.100",
            "cidr": "192.168.1.100/24",
            "broadcast": "192.168.1.255",
            "gateway_ip": "192.168.1.1"
        }
        mock_active_prof.return_value = "MyHotspot"
        mock_conn_bssid.return_value = "00:11:22:33:44:55"
        mock_curr_mac.return_value = "aa:bb:cc:dd:ee:ff"
        mock_perform.return_value = True

        res = reconnect_wifi()
        self.assertTrue(res)
        mock_perform.assert_called_once_with(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            timeout=5.0,
            max_retries=3
        )

    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect.send_gratuitous_arp")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_success(
        self,
        mock_run,
        mock_garp,
        mock_wait_carrier,
        mock_conn_bssid
    ):
        mock_run.return_value = (0, "Connection successfully activated")
        mock_wait_carrier.return_value = True
        mock_conn_bssid.return_value = "00:11:22:33:44:55"

        result = perform_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            timeout=5.0,
            max_retries=3
        )
        self.assertTrue(result)

        # Verify BSSID lock and cloned MAC modified
        mock_run.assert_any_call(["nmcli", "connection", "modify", "MyHotspot", "802-11-wireless.bssid", "00:11:22:33:44:55"], debug=False)
        mock_run.assert_any_call(["nmcli", "connection", "modify", "MyHotspot", "802-11-wireless.cloned-mac-address", "aa:bb:cc:dd:ee:ff"], debug=False)

        # Verify connection up with 5.0 timeout
        mock_run.assert_any_call(["nmcli", "connection", "up", "MyHotspot"], timeout=5.0)

        # Verify static IP & route application
        mock_run.assert_any_call(["ip", "addr", "flush", "dev", "wlan0", "scope", "global"], debug=False)
        mock_run.assert_any_call(["ip", "-4", "addr", "add", "192.168.1.100/24", "broadcast", "192.168.1.255", "dev", "wlan0"], debug=False)
        mock_run.assert_any_call(["ip", "route", "flush", "dev", "wlan0"], debug=False)
        mock_run.assert_any_call(["ip", "route", "replace", "default", "via", "192.168.1.1", "dev", "wlan0", "onlink"], debug=False)
        mock_garp.assert_called_once_with("wlan0", "192.168.1.100", "192.168.1.1")

    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_retry_on_cache_miss(
        self,
        mock_run,
        mock_wait_carrier,
        mock_conn_bssid
    ):
        # First connection up fails with cache miss, second succeeds
        mock_run.side_effect = [
            (0, ""), # modify bssid
            (0, ""), # modify cloned-mac
            (1, "Error: connection could not be found"), # up attempt 1
            (0, ""), # wifi rescan
            (0, "Connection successfully activated"), # up attempt 1 retry
            (0, ""), # flush dev
        ]
        mock_wait_carrier.return_value = True
        mock_conn_bssid.return_value = "00:11:22:33:44:55"

        result = perform_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip=None,
            netmask="24",
            broadcast="255.255.255.255",
            gateway="",
            timeout=5.0,
            max_retries=2
        )
        self.assertTrue(result)
        mock_run.assert_any_call(["nmcli", "device", "wifi", "rescan"], debug=False)

    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_loop(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_internet,
        mock_perform
    ):
        # 1. Initial check ok
        # 2. Loop iteration 1: carrier drops -> triggers perform_reconnect
        # 3. Loop iteration 2: KeyboardInterrupt raises
        mock_carrier.side_effect = [True, False, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "", "00:11:22:33:44:55"]
        mock_internet.side_effect = [True, False]
        mock_sleep.side_effect = [None, KeyboardInterrupt]
        mock_perform.return_value = True

        res = monitor_and_auto_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            timeout=5.0,
            check_interval=1.0
        )
        self.assertTrue(res)
        self.assertEqual(mock_perform.call_count, 1)

    @patch("cafe_chameleon.modes.wifi.controller.reconnect_wifi")
    def test_run_wifi_controller_reconnect(self, mock_reconnect):
        mock_reconnect.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            mac=None,
            reset_mac=None,
            release=None,
            reconnect=[]
        )
        run_wifi(args)
        mock_reconnect.assert_called_once_with(profile=None, auto_loop=False)

    @patch("cafe_chameleon.modes.wifi.controller.reconnect_wifi")
    def test_run_wifi_controller_reconnect_auto(self, mock_reconnect):
        mock_reconnect.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            mac=None,
            reset_mac=None,
            release=None,
            reconnect=["auto", "OfficeWiFi"]
        )
        run_wifi(args)
        mock_reconnect.assert_called_once_with(profile="OfficeWiFi", auto_loop=True)

    @patch("sys.argv", ["main.py", "wifi", "--reconnect"])
    def test_cli_parser_reconnect_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "wifi")
        self.assertEqual(args.reconnect, [])

    @patch("sys.argv", ["main.py", "wifi", "-c", "auto"])
    def test_cli_parser_short_reconnect_auto(self):
        args = parse_arguments()
        self.assertEqual(args.command, "wifi")
        self.assertEqual(args.reconnect, ["auto"])


    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_retry_on_timeout_124(
        self,
        mock_run,
        mock_wait_carrier,
        mock_conn_bssid
    ):
        mock_run.side_effect = [
            (0, ""), # modify bssid
            (0, ""), # modify cloned-mac
            (124, ""), # timeout on connection up attempt 1
            (0, ""), # wifi rescan
            (0, "Connection successfully activated"), # up retry
            (0, ""), # flush dev
        ]
        mock_wait_carrier.return_value = True
        mock_conn_bssid.return_value = "00:11:22:33:44:55"

        result = perform_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip=None,
            netmask="24",
            broadcast="255.255.255.255",
            gateway="",
            timeout=5.0,
            max_retries=2
        )
        self.assertTrue(result)
        mock_run.assert_any_call(["nmcli", "device", "wifi", "rescan"], debug=False)

    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_retry_on_network_activation_failed(
        self,
        mock_run,
        mock_wait_carrier,
        mock_conn_bssid
    ):
        mock_run.side_effect = [
            (0, ""), # modify bssid
            (0, ""), # modify cloned-mac
            (1, "Error: Connection activation failed: (5) IP configuration could not be reserved"), # activation failed
            (0, ""), # wifi rescan
            (0, "Connection successfully activated"), # up retry
            (0, ""), # flush dev
        ]
        mock_wait_carrier.return_value = True
        mock_conn_bssid.return_value = "00:11:22:33:44:55"

        result = perform_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip=None,
            netmask="24",
            broadcast="255.255.255.255",
            gateway="",
            timeout=5.0,
            max_retries=2
        )
        self.assertTrue(result)
        mock_run.assert_any_call(["nmcli", "device", "wifi", "rescan"], debug=False)


if __name__ == "__main__":
    unittest.main()
