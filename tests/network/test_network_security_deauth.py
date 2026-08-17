import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.models import BSSIDTarget
from cafe_chameleon.network.nmcli import (
    scan_bssids_for_ssid,
    get_bssid_security,
    get_active_security,
    is_open_security,
    is_encrypted_security
)
from cafe_chameleon.network.deauth import send_deauth
from cafe_chameleon.network.hijack.impersonate import hijack
from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.modes.aggressive.air_target_handler import test_air_client_targets as run_test_air_targets
from cafe_chameleon.modes.simple.takeover import test_discovered_hosts as run_test_discovered_hosts


class TestNetworkSecurityAndDeauth(unittest.TestCase):

    def test_bssid_target_model_security_properties(self):
        # Encrypted WPA2 target
        wpa2_target = BSSIDTarget(bssid="00:11:22:33:44:55", ssid="SecureNet", signal="80", chan="6", security="WPA2")
        self.assertEqual(wpa2_target.security, "WPA2")
        self.assertTrue(wpa2_target.is_encrypted)
        self.assertFalse(wpa2_target.is_open)
        self.assertEqual(wpa2_target.to_dict()["security"], "WPA2")
        self.assertEqual(wpa2_target["security"], "WPA2")
        self.assertEqual(wpa2_target.get("security"), "WPA2")

        # Open / unencrypted target
        open_target = BSSIDTarget(bssid="aa:bb:cc:dd:ee:ff", ssid="PublicOpen", signal="90", chan="1", security="")
        self.assertEqual(open_target.security, "")
        self.assertFalse(open_target.is_encrypted)
        self.assertTrue(open_target.is_open)
        self.assertEqual(open_target.to_dict()["security"], "")

    def test_is_open_and_encrypted_security_helpers(self):
        # Open networks
        self.assertTrue(is_open_security(""))
        self.assertTrue(is_open_security(None))
        self.assertTrue(is_open_security("--"))
        self.assertTrue(is_open_security("none"))
        self.assertTrue(is_open_security("(none)"))
        self.assertTrue(is_open_security("open"))
        self.assertTrue(is_open_security(" OPEN "))

        self.assertFalse(is_encrypted_security(""))
        self.assertFalse(is_encrypted_security(None))
        self.assertFalse(is_encrypted_security("--"))
        self.assertFalse(is_encrypted_security("open"))

        # Encrypted networks (WPA2, WPA, WEP, etc.)
        self.assertTrue(is_encrypted_security("WPA2"))
        self.assertTrue(is_encrypted_security("WPA1 WPA2"))
        self.assertTrue(is_encrypted_security("WPA3"))
        self.assertTrue(is_encrypted_security("WEP"))
        self.assertTrue(is_encrypted_security("802.1X"))
        self.assertTrue(is_encrypted_security("WPA2 802.1X"))

        self.assertFalse(is_open_security("WPA2"))
        self.assertFalse(is_open_security("WPA1 WPA2"))
        self.assertFalse(is_open_security("WEP"))

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_scan_bssids_for_ssid_parses_security(self, mock_run):
        mock_output = (
            r"BC\:99\:30\:C6\:CE\:E0:TargetNet:80:56::yes" + "\n"
            r"72\:A8\:F5\:50\:9D\:44:TargetNet:74:13:WPA2:no" + "\n"
            r"2C\:EC\:F7\:36\:11\:FC:TargetNet:32:4:WPA1 WPA2:no" + "\n"
            r"30\:16\:9D\:B7\:1D\:16:OtherNet:25:3:WPA2:no" + "\n"
        )
        mock_run.side_effect = [
            (0, ""),  # rescan
            (0, mock_output)  # list
        ]

        bssids = scan_bssids_for_ssid("TargetNet")
        self.assertEqual(len(bssids), 3)

        # 1st: BC:99:30:C6:CE:E0 (open network)
        self.assertEqual(bssids[0].bssid, "BC:99:30:C6:CE:E0")
        self.assertEqual(bssids[0].security, "")
        self.assertTrue(bssids[0].is_open)

        # 2nd: 72:A8:F5:50:9D:44 (WPA2)
        self.assertEqual(bssids[1].bssid, "72:A8:F5:50:9D:44")
        self.assertEqual(bssids[1].security, "WPA2")
        self.assertTrue(bssids[1].is_encrypted)

        # 3rd: 2C:EC:F7:36:11:FC (WPA1 WPA2)
        self.assertEqual(bssids[2].bssid, "2C:EC:F7:36:11:FC")
        self.assertEqual(bssids[2].security, "WPA1 WPA2")
        self.assertTrue(bssids[2].is_encrypted)

    @patch("cafe_chameleon.network.nmcli.bssid._run")
    def test_get_bssid_security(self, mock_run):
        mock_output = (
            r"BC\:99\:30\:C6\:CE\:E0:" + "\n"
            r"72\:A8\:F5\:50\:9D\:44:WPA2" + "\n"
            r"2C\:EC\:F7\:36\:11\:FC:WPA1 WPA2" + "\n"
        )
        mock_run.return_value = (0, mock_output)

        self.assertEqual(get_bssid_security("72:A8:F5:50:9D:44"), "WPA2")
        self.assertEqual(get_bssid_security("BC:99:30:C6:CE:E0"), "")
        self.assertEqual(get_bssid_security("2C:EC:F7:36:11:FC"), "WPA1 WPA2")
        self.assertIsNone(get_bssid_security("00:00:00:00:00:00"))

    @patch("cafe_chameleon.network.nmcli.profiles._run")
    def test_get_active_security(self, mock_run):
        # 1. Active open network
        mock_run.return_value = (0, r"yes:BC\:99\:30\:C6\:CE\:E0::")
        self.assertEqual(get_active_security(), "")

        # 2. Active WPA2 network
        mock_run.return_value = (0, r"yes:72\:A8\:F5\:50\:9D\:44:WPA2:")
        self.assertEqual(get_active_security(), "WPA2")

    @patch("cafe_chameleon.network.deauth.set_monitor_mode")
    @patch("cafe_chameleon.network.deauth.is_monitor_mode_active")
    @patch("cafe_chameleon.network.deauth._run")
    @patch("shutil.which")
    def test_send_deauth_skips_mdk4_on_open_network_by_default(self, mock_which, mock_run, mock_is_mon, mock_set_mon):
        mock_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd == "mdk4" else None
        mock_is_mon.return_value = False

        # Open network (security="") and force_deauth=False
        result = send_deauth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", interface="wlan0", security="", force_deauth=False)

        # Should return True (skipped cleanly) without engaging monitor mode or executing MDK4
        self.assertTrue(result)
        mock_set_mon.assert_not_called()
        mock_run.assert_not_called()

    @patch("cafe_chameleon.network.deauth.set_managed_mode")
    @patch("cafe_chameleon.network.deauth.set_monitor_mode")
    @patch("cafe_chameleon.network.deauth.is_monitor_mode_active")
    @patch("cafe_chameleon.network.deauth._run")
    @patch("shutil.which")
    def test_send_deauth_runs_mdk4_on_open_network_when_force_deauth_supplied(self, mock_which, mock_run, mock_is_mon, mock_set_mon, mock_set_managed):
        mock_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd == "mdk4" else None
        mock_is_mon.return_value = False
        mock_set_mon.return_value = "wlan0mon"
        mock_run.return_value = (0, "")

        # Open network (security="") BUT force_deauth=True
        result = send_deauth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", interface="wlan0", security="", force_deauth=True)

        self.assertTrue(result)
        mock_set_mon.assert_called_with("wlan0")
        mock_set_managed.assert_called_with("wlan0")

        # Verify mdk4 was invoked
        called_cmds = [call_args[0][0] if isinstance(call_args[0][0], list) else call_args[0][0] for call_args in mock_run.call_args_list]
        flattened = [" ".join(c) if isinstance(c, list) else str(c) for c in called_cmds]
        self.assertTrue(any("mdk4" in s for s in flattened))

    @patch("cafe_chameleon.network.deauth.set_managed_mode")
    @patch("cafe_chameleon.network.deauth.set_monitor_mode")
    @patch("cafe_chameleon.network.deauth.is_monitor_mode_active")
    @patch("cafe_chameleon.network.deauth._run")
    @patch("shutil.which")
    def test_send_deauth_runs_mdk4_on_wpa2_encrypted_network(self, mock_which, mock_run, mock_is_mon, mock_set_mon, mock_set_managed):
        mock_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd == "mdk4" else None
        mock_is_mon.return_value = False
        mock_set_mon.return_value = "wlan0mon"
        mock_run.return_value = (0, "")

        # WPA2 network (security="WPA2") and force_deauth=False
        result = send_deauth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", interface="wlan0", security="WPA2", force_deauth=False)

        self.assertTrue(result)
        mock_set_mon.assert_called_with("wlan0")
        mock_set_managed.assert_called_with("wlan0")

        # Verify mdk4 was invoked
        called_cmds = [call_args[0][0] if isinstance(call_args[0][0], list) else call_args[0][0] for call_args in mock_run.call_args_list]
        flattened = [" ".join(c) if isinstance(c, list) else str(c) for c in called_cmds]
        self.assertTrue(any("mdk4" in s for s in flattened))

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--force-deauth"])
    def test_cli_parser_aggressive_force_deauth(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.force_deauth)

    @patch("sys.argv", ["cafe-chameleon", "simple", "--force-deauth"])
    def test_cli_parser_simple_force_deauth(self):
        args = parse_arguments()
        self.assertEqual(args.command, "simple")
        self.assertTrue(args.force_deauth)

    @patch("sys.argv", ["cafe-chameleon", "aggressive"])
    def test_cli_parser_default_force_deauth_false(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertFalse(getattr(args, "force_deauth", False))

    @patch("cafe_chameleon.network.hijack.impersonate.get_active_profile", return_value="TestProfile")
    @patch("cafe_chameleon.network.hijack.impersonate.start_background_garp")
    @patch("cafe_chameleon.network.hijack.impersonate.send_gratuitous_arp")
    @patch("cafe_chameleon.network.hijack.impersonate.get_carrier_status", return_value=True)
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_gateway_pong", return_value=True)
    @patch("cafe_chameleon.network.hijack.impersonate.send_deauth")
    @patch("cafe_chameleon.network.hijack.impersonate.set_mac_address")
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_carrier")
    @patch("cafe_chameleon.network.hijack.impersonate.has_internet")
    @patch("cafe_chameleon.network.hijack.impersonate.test_internet_speed")
    @patch("cafe_chameleon.network.hijack.impersonate._run")
    def test_hijack_passes_security_and_force_deauth(self, mock_run, mock_speed, mock_internet, mock_carrier, mock_mac, mock_send_deauth, mock_pong, mock_get_carrier, mock_garp, mock_bg_garp, mock_profile):
        mock_send_deauth.return_value = True
        mock_mac.return_value = True
        mock_carrier.return_value = True
        mock_run.return_value = (0, "inet 10.0.0.5/24")
        mock_internet.return_value = True
        mock_speed.return_value = (True, 50.0)

        with patch("builtins.open", unittest.mock.mock_open(read_data="00:11:22:33:44:55")):
            hijack(
                "wlan0", "10.0.0.5", "00:11:22:33:44:55", "24", "10.0.0.255", "10.0.0.1",
                bssid="aa:bb:cc:dd:ee:ff", security="WPA2", force_deauth=True
            )

        mock_send_deauth.assert_called_once_with(
            "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "wlan0", channel=None, security="WPA2", force_deauth=True
        )

    @patch("cafe_chameleon.modes.aggressive.air_target_handler._run")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.hijack")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.resolve_mac_to_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.wait_for_carrier")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.set_restore_params")
    def test_test_air_client_targets_passes_security_and_force_deauth(self, mock_restore_params, mock_carrier, mock_resolve, mock_hijack, mock_run):
        mock_carrier.return_value = True
        mock_resolve.return_value = "10.55.12.162"
        mock_hijack.return_value = True
        mock_run.return_value = (0, "")

        new_air_clients = {"cc:3f:36:46:26:6c": "10.55.12.162"}
        tried_macs = set()
        auto_params = {
            "local_ip": "10.55.12.125",
            "gateway_ip": "10.55.12.1",
            "cidr": "10.55.12.125/22",
            "local_mac": "de:56:7b:47:41:dd",
            "broadcast": "10.55.15.255"
        }
        mock_args = MagicMock()
        mock_args.force = False
        mock_args.force_deauth = True

        success, stop_early = run_test_air_targets(
            new_air_clients,
            interface="wlan0",
            target_bssid="bc:99:30:c6:ce:e0",
            chan=56,
            profile="MyWiFi",
            tried_macs=tried_macs,
            auto_params=auto_params,
            args=mock_args,
            security="WPA2"
        )

        self.assertTrue(success)
        mock_hijack.assert_called_once()
        kwargs = mock_hijack.call_args[1]
        self.assertEqual(kwargs.get("security"), "WPA2")
        self.assertTrue(kwargs.get("force_deauth"))

    @patch("cafe_chameleon.modes.simple.takeover.hijack")
    def test_test_discovered_hosts_passes_security_and_force_deauth(self, mock_hijack):
        mock_hijack.return_value = True
        unique_hosts = [{"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:50"}]
        mock_args = MagicMock()
        mock_args.force = False
        mock_args.force_deauth = True
        mock_args.security = "WPA2"

        run_test_discovered_hosts(
            unique_hosts,
            interface="wlan0",
            gw_ip="10.0.0.1",
            gw_mac="00:11:22:33:44:01",
            netmask="24",
            broadcast="10.0.0.255",
            local_mac="00:11:22:33:44:99",
            ipmask="10.0.0.99/24",
            profile="MyWiFi",
            args=mock_args
        )

        mock_hijack.assert_called_once()
        kwargs = mock_hijack.call_args[1]
        self.assertEqual(kwargs.get("security"), "WPA2")
        self.assertTrue(kwargs.get("force_deauth"))


if __name__ == "__main__":
    unittest.main()
