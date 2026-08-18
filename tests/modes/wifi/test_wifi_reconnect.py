import unittest
from unittest.mock import patch, MagicMock, call
import argparse

from cafe_chameleon.network.nmcli.reconnect import reconnect_wifi, perform_reconnect, monitor_and_auto_reconnect, soft_heal_connection
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
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "00:aa:bb:cc:dd:ee"
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
            gateway_mac="00:aa:bb:cc:dd:ee",
            enable_deauth=False,
            timeout=5.0,
            max_retries=3
        )

    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_gateway_pong", return_value=True)
    @patch("cafe_chameleon.network.nmcli.reconnect.pin_gateway_neighbor")
    @patch("cafe_chameleon.network.nmcli.reconnect.send_deauth")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect.send_gratuitous_arp")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_success_with_deauth_and_pinning(
        self,
        mock_run,
        mock_garp,
        mock_wait_carrier,
        mock_conn_bssid,
        mock_send_deauth,
        mock_pin,
        mock_pong
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
            gateway_mac="00:aa:bb:cc:dd:ee",
            enable_deauth=True,
            timeout=5.0,
            max_retries=3
        )
        self.assertTrue(result)

        # Verify defensive deauth called
        mock_send_deauth.assert_called_once_with("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "wlan0")

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
        mock_pin.assert_called_once_with("192.168.1.1", "00:aa:bb:cc:dd:ee", "wlan0")

    @patch("cafe_chameleon.network.nmcli.reconnect.send_deauth")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_no_deauth_by_default(
        self,
        mock_run,
        mock_wait_carrier,
        mock_conn_bssid,
        mock_send_deauth
    ):
        mock_run.return_value = (0, "Connection successfully activated")
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
            enable_deauth=False
        )
        self.assertTrue(result)
        mock_send_deauth.assert_not_called()

    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_gateway_pong")
    @patch("cafe_chameleon.network.nmcli.reconnect.pin_gateway_neighbor")
    @patch("cafe_chameleon.network.nmcli.reconnect.send_gratuitous_arp")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_soft_heal_connection_success(
        self,
        mock_run,
        mock_garp,
        mock_pin,
        mock_gw_pong,
        mock_internet
    ):
        mock_run.return_value = (0, "")
        mock_gw_pong.return_value = True
        mock_internet.return_value = True

        res = soft_heal_connection(
            interface="wlan0",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            gateway_mac="00:aa:bb:cc:dd:ee"
        )
        self.assertTrue(res)
        mock_garp.assert_called_once_with("wlan0", "192.168.1.100", "192.168.1.1")
        mock_pin.assert_called_once_with("192.168.1.1", "00:aa:bb:cc:dd:ee", "wlan0")
        mock_gw_pong.assert_called_once_with(gateway_ip="192.168.1.1", interface="wlan0", timeout=1.5)
        mock_internet.assert_called_once_with(timeout=1.0, check_speed=False, gateway_ip="192.168.1.1", interface="wlan0", ping_gateway=False)

    @patch("cafe_chameleon.network.nmcli.reconnect.start_background_garp")
    @patch("cafe_chameleon.network.nmcli.reconnect.soft_heal_connection")
    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_hysteresis_and_soft_heal(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_internet,
        mock_perform,
        mock_soft_heal,
        mock_garp_thread
    ):
        mock_stop_event = MagicMock()
        mock_garp_thread.return_value = mock_stop_event

        # 1. Initial check ok (carrier=True, bssid matches)
        # 2. Iteration 1: has_internet returns False (first transient drop -> consecutive=1, no reconnect)
        # 3. Iteration 2: has_internet returns False (consecutive=2 -> triggers soft_heal_connection)
        # 4. soft_heal_connection succeeds -> resets consecutive_failures, no perform_reconnect
        # 5. Iteration 3: KeyboardInterrupt
        mock_carrier.side_effect = [True, True, True, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55"]
        mock_internet.side_effect = [False, False]
        mock_soft_heal.return_value = True
        mock_sleep.side_effect = [None, None, KeyboardInterrupt]

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
        mock_soft_heal.assert_called_once()
        mock_perform.assert_not_called()
        mock_stop_event.set.assert_called_once()

    @patch("cafe_chameleon.network.nmcli.reconnect.start_background_garp")
    @patch("cafe_chameleon.network.nmcli.reconnect.soft_heal_connection")
    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_escalates_to_hard_reconnect_on_soft_fail(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_internet,
        mock_perform,
        mock_soft_heal,
        mock_garp_thread
    ):
        mock_stop_event = MagicMock()
        mock_garp_thread.return_value = mock_stop_event

        # Iteration 1: transient drop (consecutive=1)
        # Iteration 2: confirmed drop (consecutive=2) -> soft_heal fails -> calls perform_reconnect
        mock_carrier.side_effect = [True, True, True, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55"]
        mock_internet.side_effect = [False, False]
        mock_soft_heal.return_value = False
        mock_perform.return_value = True
        mock_sleep.side_effect = [None, None, KeyboardInterrupt]

        res = monitor_and_auto_reconnect(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            enable_deauth=True,
            timeout=5.0,
            check_interval=1.0
        )
        self.assertTrue(res)
        mock_soft_heal.assert_called_once()
        mock_perform.assert_called_once_with(
            profile="MyHotspot",
            interface="wlan0",
            bssid="00:11:22:33:44:55",
            mac="aa:bb:cc:dd:ee:ff",
            local_ip="192.168.1.100",
            netmask="24",
            broadcast="192.168.1.255",
            gateway="192.168.1.1",
            gateway_mac=None,
            enable_deauth=True,
            timeout=5.0,
            max_retries=3
        )

    @patch("cafe_chameleon.network.nmcli.reconnect.start_background_garp")
    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_carrier_loss_after_consecutive_drops(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_perform,
        mock_garp_thread
    ):
        mock_stop_event = MagicMock()
        mock_garp_thread.return_value = mock_stop_event

        # Initial check passes (carrier=True, bssid matches).
        # Iteration 1: transient carrier drop (carrier=False, failures=1 -> no reconnect)
        # Iteration 2: confirmed carrier drop (carrier=False, failures=2 -> hard reconnect)
        # Iteration 3: KeyboardInterrupt
        mock_carrier.side_effect = [True, False, False, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55"]
        mock_perform.return_value = True
        mock_sleep.side_effect = [None, None, KeyboardInterrupt]

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
        mock_perform.assert_called_once()

    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.start_background_garp")
    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_carrier_debounce_ignores_single_blip(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_perform,
        mock_garp_thread,
        mock_internet
    ):
        mock_stop_event = MagicMock()
        mock_garp_thread.return_value = mock_stop_event
        mock_internet.return_value = True

        # Initial check passes (carrier=True, bssid matches).
        # Iteration 1: transient carrier drop (carrier=False, failures=1 -> no reconnect)
        # Iteration 2: carrier recovered (carrier=True, failures reset to 0)
        # Iteration 3: KeyboardInterrupt
        mock_carrier.side_effect = [True, False, True, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55", "00:11:22:33:44:55"]
        mock_sleep.side_effect = [None, None, KeyboardInterrupt]

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
        mock_perform.assert_not_called()

    @patch("cafe_chameleon.network.nmcli.reconnect.has_internet")
    @patch("cafe_chameleon.network.nmcli.reconnect.start_background_garp")
    @patch("cafe_chameleon.network.nmcli.reconnect.perform_reconnect")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.get_carrier_status")
    @patch("time.sleep")
    def test_monitor_and_auto_reconnect_roam_tolerance_when_internet_ok(
        self,
        mock_sleep,
        mock_carrier,
        mock_bssid,
        mock_perform,
        mock_garp_thread,
        mock_internet
    ):
        mock_stop_event = MagicMock()
        mock_garp_thread.return_value = mock_stop_event
        mock_internet.return_value = True

        # Initial check passes (carrier=True, bssid=00:11:22:33:44:55)
        # Iteration 1: Roams to 00:11:22:33:44:66, but has_internet=True -> adopts new BSSID, no reconnect
        # Iteration 2: Connected to 00:11:22:33:44:66, matching target -> continues smoothly
        # Iteration 3: KeyboardInterrupt
        mock_carrier.side_effect = [True, True, True, True]
        mock_bssid.side_effect = ["00:11:22:33:44:55", "00:11:22:33:44:66", "00:11:22:33:44:66", "00:11:22:33:44:66"]
        mock_sleep.side_effect = [None, None, KeyboardInterrupt]

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
        mock_perform.assert_not_called()

    @patch("cafe_chameleon.modes.wifi.controller.reconnect_wifi")
    def test_run_wifi_controller_reconnect_default(self, mock_reconnect):
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
        mock_reconnect.assert_called_once_with(profile=None, auto_loop=False, enable_deauth=False)

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
        mock_reconnect.assert_called_once_with(profile="OfficeWiFi", auto_loop=True, enable_deauth=False)

    @patch("cafe_chameleon.modes.wifi.controller.reconnect_wifi")
    def test_run_wifi_controller_reconnect_deauth(self, mock_reconnect):
        mock_reconnect.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            mac=None,
            reset_mac=None,
            release=None,
            reconnect=["deauth", "OfficeWiFi"]
        )
        run_wifi(args)
        mock_reconnect.assert_called_once_with(profile="OfficeWiFi", auto_loop=True, enable_deauth=True)

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

    @patch("sys.argv", ["main.py", "wifi", "-c", "deauth"])
    def test_cli_parser_short_reconnect_deauth(self):
        args = parse_arguments()
        self.assertEqual(args.command, "wifi")
        self.assertEqual(args.reconnect, ["deauth"])

    @patch("cafe_chameleon.network.nmcli.reconnect.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.reconnect.wait_for_carrier")
    @patch("cafe_chameleon.network.nmcli.reconnect._run")
    def test_perform_reconnect_retry_on_cache_miss(
        self,
        mock_run,
        mock_wait_carrier,
        mock_conn_bssid
    ):
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
    @patch("cafe_chameleon.network.sysfs._run")
    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_carrier_status_operstate_dormant(self, mock_open, mock_exists, mock_run):
        from cafe_chameleon.network.sysfs import get_carrier_status
        # carrier file is 0, operstate is dormant
        def side_exists(p):
            return "operstate" in p or "carrier" in p
        mock_exists.side_effect = side_exists

        import io
        def side_open(p, *args, **kwargs):
            if "carrier" in p:
                return io.StringIO("0\n")
            if "operstate" in p:
                return io.StringIO("dormant\n")
            return io.StringIO("")
        mock_open.side_effect = side_open

        self.assertTrue(get_carrier_status("wlan0"))

    @patch("cafe_chameleon.network.sysfs._run")
    @patch("os.path.exists")
    @patch("builtins.open")
    def test_get_carrier_status_sysfs_carrier_1(self, mock_open, mock_exists, mock_run):
        from cafe_chameleon.network.sysfs import get_carrier_status
        mock_exists.side_effect = lambda p: "carrier" in p
        import io
        mock_open.side_effect = lambda p, *a, **kw: io.StringIO("1\n")
        self.assertTrue(get_carrier_status("wlan0"))


if __name__ == "__main__":
    unittest.main()

