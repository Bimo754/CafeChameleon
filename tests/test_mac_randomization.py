"""
tests/test_mac_randomization.py - Unit and integration tests for MAC randomization & spoofing.
"""

import re
from unittest.mock import patch, MagicMock
import pytest

from cafe_chameleon.network.mac import (
    generate_random_mac,
    is_valid_mac,
    get_permanent_mac,
    get_current_mac,
    get_attack_mac,
    set_mac_address,
    reset_mac_address,
)
from cafe_chameleon.network.nmcli import change_mac
from cafe_chameleon.utils.state import set_use_original_mac, get_use_original_mac
from cafe_chameleon.cli.parser import parse_arguments


class TestMacValidationAndGeneration:
    def test_is_valid_mac(self):
        assert is_valid_mac("00:11:22:33:44:55") is True
        assert is_valid_mac("de:56:7b:47:41:dd") is True
        assert is_valid_mac("DE:56:7B:47:41:DD") is True
        assert is_valid_mac("00-11-22-33-44-55") is True

        assert is_valid_mac("invalid_mac") is False
        assert is_valid_mac("00:11:22:33:44") is False
        assert is_valid_mac("00:11:22:33:44:55:66") is False
        assert is_valid_mac("") is False
        assert is_valid_mac(None) is False

    def test_generate_random_mac_syntax_and_unicast(self):
        """Verify 500 generated MACs conform to IEEE 802 unicast locally-administered format."""
        generated = set()
        for _ in range(500):
            mac = generate_random_mac()
            assert is_valid_mac(mac), f"Generated MAC '{mac}' is invalid syntax."
            generated.add(mac)

            # Check Unicast bit (LSB of first byte == 0)
            first_byte = int(mac.split(":")[0], 16)
            assert (first_byte & 0x01) == 0, f"MAC '{mac}' is multicast (bit 0 is 1)"

            # Check Locally Administered bit (bit 1 of first byte == 1)
            assert (first_byte & 0x02) == 2, f"MAC '{mac}' is not locally administered (bit 1 is 0)"

        # Ensure high entropy/uniqueness (all 500 should be distinct)
        assert len(generated) == 500, f"Expected 500 unique MACs, got {len(generated)}"


class TestPermanentAndAttackMac:
    def test_get_permanent_mac_sysfs(self, tmp_path):
        """Test reading permanent MAC from sysfs perm_addr."""
        perm_file = tmp_path / "perm_addr"
        perm_file.write_text("00:aa:bb:cc:dd:ee\n")

        with patch("builtins.open", MagicMock(return_value=perm_file.open("r"))):
            with patch("os.path.exists", return_value=True):
                mac = get_permanent_mac("wlan0")
                assert mac == "00:aa:bb:cc:dd:ee"

    def test_get_permanent_mac_macchanger_fallback(self):
        """Test fallback to macchanger output when sysfs is unavailable."""
        macchanger_output = "Permanent MAC: 11:22:33:44:55:66 (vendor)\nCurrent MAC:   66:55:44:33:22:11"
        with patch("builtins.open", side_effect=OSError("No sysfs")):
            with patch("cafe_chameleon.network.mac._run", return_value=(0, macchanger_output)):
                mac = get_permanent_mac("wlan0")
                assert mac == "11:22:33:44:55:66"

    def test_get_attack_mac_random_by_default(self):
        """When -m flag is NOT set, get_attack_mac should return a newly generated random MAC."""
        set_use_original_mac(False)
        assert get_use_original_mac() is False

        mac1 = get_attack_mac("wlan0")
        mac2 = get_attack_mac("wlan0")

        assert is_valid_mac(mac1)
        assert is_valid_mac(mac2)
        assert mac1 != mac2  # Should be newly randomized on each call

    def test_get_attack_mac_original_mac_flag(self):
        """When -m flag IS set, get_attack_mac should return the hardware permanent MAC."""
        set_use_original_mac(True)
        assert get_use_original_mac() is True

        try:
            with patch("cafe_chameleon.network.mac.get_permanent_mac", return_value="aa:bb:cc:dd:ee:ff"):
                mac = get_attack_mac("wlan0")
                assert mac == "aa:bb:cc:dd:ee:ff"
        finally:
            set_use_original_mac(False)


class TestMacSettingAndResetting:
    @patch("cafe_chameleon.network.sysfs.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.network.mac._run")
    def test_set_mac_address_with_profile(self, mock_run, mock_wait):
        """Test setting MAC address via NetworkManager profile."""
        mock_run.return_value = (0, "Success")

        success = set_mac_address("wlan0", "02:11:22:33:44:55", profile="TestWiFi")
        assert success is True

        calls = [c[0][0] for c in mock_run.call_args_list]
        nmcli_mod = ["nmcli", "connection", "modify", "TestWiFi", "802-11-wireless.cloned-mac-address", "02:11:22:33:44:55"]
        assert nmcli_mod in calls

    @patch("cafe_chameleon.network.sysfs.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.network.mac._run")
    def test_reset_mac_address_with_profile(self, mock_run, mock_wait):
        """Test resetting MAC address via NetworkManager profile."""
        mock_run.return_value = (0, "Success")

        success = reset_mac_address("wlan0", profile="TestWiFi")
        assert success is True

        calls = [c[0][0] for c in mock_run.call_args_list]
        nmcli_clear = ["nmcli", "connection", "modify", "TestWiFi", "802-11-wireless.cloned-mac-address", ""]
        assert nmcli_clear in calls

    @patch("cafe_chameleon.network.nmcli.restore._run")
    def test_change_mac_with_explicit_mac(self, mock_run):
        """Test changing MAC address to an explicit MAC via NetworkManager profile."""
        mock_run.return_value = (0, "Success")

        success = change_mac("00:11:22:33:44:55", profile="TestWiFi", loop=False)
        assert success is True

        calls = [c[0][0] for c in mock_run.call_args_list]
        nmcli_mod = ["nmcli", "connection", "modify", "TestWiFi", "802-11-wireless.cloned-mac-address", "00:11:22:33:44:55"]
        nmcli_up = ["nmcli", "connection", "up", "TestWiFi"]
        assert nmcli_mod in calls
        assert nmcli_up in calls

    @patch("cafe_chameleon.network.nmcli.restore._run")
    def test_change_mac_random_when_omitted(self, mock_run):
        """Test changing MAC address with no MAC supplied generates a valid random MAC."""
        mock_run.return_value = (0, "Success")

        success = change_mac(None, profile="TestWiFi", loop=False)
        assert success is True

        calls = [c[0][0] for c in mock_run.call_args_list]
        # Verify nmcli modify was called with a valid MAC
        mod_call = [c for c in calls if len(c) >= 6 and c[0] == "nmcli" and c[2] == "modify"][0]
        applied_mac = mod_call[5]
        assert is_valid_mac(applied_mac)

    def test_change_mac_invalid_mac_fails(self):
        """Test that passing an invalid MAC string fails validation without running nmcli."""
        success = change_mac("invalid_mac", profile="TestWiFi", loop=False)
        assert success is False

    @patch("cafe_chameleon.network.mac.set_mac_address", return_value=True)
    @patch("cafe_chameleon.network.nmcli.restore.get_active_profile", return_value=None)
    @patch("cafe_chameleon.scanners.detector.auto_detect_network_params", return_value={"interface": "wlan0"})
    def test_change_mac_fallback_without_profile(self, mock_detect, mock_get_profile, mock_set_mac):
        """Test that change_mac falls back to set_mac_address when no profile is active."""
        success = change_mac("00:11:22:33:44:55", profile=None, loop=False)
        assert success is True
        mock_set_mac.assert_called_once_with("wlan0", "00:11:22:33:44:55", None)

    @patch("cafe_chameleon.network.nmcli.restore._run")
    def test_change_mac_passes_5s_timeout_and_retries(self, mock_run):
        """Test that change_mac uses 5s timeout and retries on failure before succeeding."""
        # Call 1: modify succeeds (0)
        # Call 2: connection up fails (1)
        # Call 3: rescan succeeds (0)
        # Call 4: connection up succeeds (0)
        mock_run.side_effect = [
            (0, ""),
            (1, "Error: connection failed"),
            (0, ""),
            (0, "Connection successfully activated")
        ]

        success = change_mac("3e:4a:47:f6:c9:02", profile="GSBWIFI 2", loop=False, timeout=5.0)
        assert success is True

        # Check that timeout=5.0 was used in connection up call
        up_call = [call for call in mock_run.call_args_list if call[0][0] == ["nmcli", "connection", "up", "GSBWIFI 2"]][0]
        assert up_call[1].get("timeout") == 5.0

    @patch("cafe_chameleon.network.nmcli.restore._run", side_effect=KeyboardInterrupt)
    def test_change_mac_ctrl_c_handled_gracefully(self, mock_run):
        """Test that change_mac exits gracefully when user presses Ctrl+C."""
        success = change_mac("3e:4a:47:f6:c9:02", profile="GSBWIFI 2", loop=True)
        assert success is False


class TestCliMacFlags:
    def test_cli_simple_original_mac_flag(self):
        with patch("sys.argv", ["main.py", "simple", "-m", "-i", "wlan0"]):
            args = parse_arguments()
            assert getattr(args, "original_mac", False) is True

    def test_cli_simple_default_randomizes_mac(self):
        with patch("sys.argv", ["main.py", "simple", "-i", "wlan0"]):
            args = parse_arguments()
            assert getattr(args, "original_mac", False) is False

    def test_cli_aggressive_original_mac_flag(self):
        with patch("sys.argv", ["main.py", "aggressive", "-m", "-i", "wlan0"]):
            args = parse_arguments()
            assert getattr(args, "original_mac", False) is True

    def test_cli_aggressive_default_randomizes_mac(self):
        with patch("sys.argv", ["main.py", "aggressive", "-i", "wlan0"]):
            args = parse_arguments()
            assert getattr(args, "original_mac", False) is False

    def test_cli_wifi_reset_mac_flag(self):
        with patch("sys.argv", ["main.py", "wifi", "-r"]):
            args = parse_arguments()
            assert getattr(args, "reset_mac", None) is not None

    def test_cli_wifi_mac_flag_no_args(self):
        with patch("sys.argv", ["main.py", "wifi", "-m"]):
            args = parse_arguments()
            assert getattr(args, "mac", None) == []

        with patch("sys.argv", ["main.py", "wifi", "--mac"]):
            args = parse_arguments()
            assert getattr(args, "mac", None) == []

    def test_cli_wifi_mac_flag_with_mac(self):
        with patch("sys.argv", ["main.py", "wifi", "--mac", "00:11:22:33:44:55"]):
            args = parse_arguments()
            assert getattr(args, "mac", None) == ["00:11:22:33:44:55"]

    def test_cli_wifi_mac_flag_with_mac_and_profile(self):
        with patch("sys.argv", ["main.py", "wifi", "-m", "00:11:22:33:44:55", "MyProfile"]):
            args = parse_arguments()
            assert getattr(args, "mac", None) == ["00:11:22:33:44:55", "MyProfile"]


class TestWifiMacController:
    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_random(self, mock_change_mac):
        """Test wifi --mac with no args passes None to change_mac."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=[]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with(None, None)

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_explicit(self, mock_change_mac):
        """Test wifi --mac with specific MAC address."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["00:11:22:33:44:55"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("00:11:22:33:44:55", None)

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_with_profile(self, mock_change_mac):
        """Test wifi --mac with MAC and profile name."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["00:11:22:33:44:55", "TestProfile"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("00:11:22:33:44:55", "TestProfile")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_profile_only(self, mock_change_mac):
        """Test wifi --mac with profile only randomizes MAC on that profile."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["TestProfile"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with(None, "TestProfile")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_with_multiword_profile(self, mock_change_mac):
        """Test wifi --mac 3e:4a:47:f6:c9:02 'GSBWIFI 2'."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["3e:4a:47:f6:c9:02", "GSBWIFI 2"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("3e:4a:47:f6:c9:02", "GSBWIFI 2")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_profile_before_mac(self, mock_change_mac):
        """Test wifi --mac 'GSBWIFI 2' 3e:4a:47:f6:c9:02."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["GSBWIFI 2", "3e:4a:47:f6:c9:02"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("3e:4a:47:f6:c9:02", "GSBWIFI 2")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_unquoted_multiword_profile_after_mac(self, mock_change_mac):
        """Test wifi --mac 3e:4a:47:f6:c9:02 GSBWIFI 2 (unquoted)."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["3e:4a:47:f6:c9:02", "GSBWIFI", "2"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("3e:4a:47:f6:c9:02", "GSBWIFI 2")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_unquoted_multiword_profile_before_mac(self, mock_change_mac):
        """Test wifi --mac GSBWIFI 2 3e:4a:47:f6:c9:02 (unquoted)."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["GSBWIFI", "2", "3e:4a:47:f6:c9:02"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with("3e:4a:47:f6:c9:02", "GSBWIFI 2")

    @patch("cafe_chameleon.modes.wifi.controller.change_mac")
    def test_run_wifi_mac_unquoted_multiword_profile_only(self, mock_change_mac):
        """Test wifi --mac GSBWIFI 2 (unquoted profile only, randomizes MAC)."""
        from cafe_chameleon.modes.wifi.controller import run_wifi
        import argparse

        mock_change_mac.return_value = True
        args = argparse.Namespace(
            status=False,
            lock=None,
            auto=None,
            reset_mac=None,
            release=None,
            mac=["GSBWIFI", "2"]
        )
        run_wifi(args)
        mock_change_mac.assert_called_once_with(None, "GSBWIFI 2")


class TestModeMacIntegration:
    @patch("cafe_chameleon.modes.simple.runner.test_discovered_hosts", return_value=True)
    @patch("cafe_chameleon.modes.simple.runner.scan_subnet", return_value=[])
    @patch("cafe_chameleon.modes.simple.runner.set_mac_address")
    @patch("cafe_chameleon.modes.simple.runner.get_attack_mac", return_value="02:aa:bb:cc:dd:ee")
    @patch("cafe_chameleon.modes.simple.runner.set_restore_params")
    @patch("cafe_chameleon.modes.simple.runner.prepare_target_subnet")
    @patch("cafe_chameleon.modes.simple.runner.get_interface_details", return_value=("192.168.1.50", "11:22:33:44:55:66"))
    @patch("cafe_chameleon.modes.simple.runner.auto_detect_network_params")
    @patch("cafe_chameleon.modes.simple.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.simple.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.simple.runner.register_signal_handler")
    def test_simple_mode_applies_attack_mac(
        self, mock_sig, mock_mon, mock_carrier, mock_detect, mock_iface,
        mock_prep, mock_restore_params, mock_get_attack_mac, mock_set_mac,
        mock_scan, mock_test_hosts
    ):
        import ipaddress
        from cafe_chameleon.modes.simple.runner import run_simple

        mock_detect.return_value = {
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "00:11:22:33:44:00",
            "cidr": "192.168.1.50/24",
            "broadcast": "192.168.1.255",
            "ssid": "TestSSID",
            "internet_access": False
        }
        mock_prep.return_value = ipaddress.ip_network("192.168.1.0/24")

        args = MagicMock()
        args.interface = "wlan0"
        args.subnet = None
        args.profile = "TestProfile"
        args.force = False

        run_simple(args, quiet_header=True)

        mock_get_attack_mac.assert_called_once_with("wlan0")
        mock_set_mac.assert_called_once_with("wlan0", "02:aa:bb:cc:dd:ee", profile="TestProfile")

    @patch("cafe_chameleon.modes.aggressive.runner.run_scan_wrapper", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address")
    @patch("cafe_chameleon.modes.aggressive.runner.get_attack_mac", return_value="02:12:34:56:78:9a")
    @patch("cafe_chameleon.modes.aggressive.runner.display_and_select_bssid")
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="TargetWiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="TargetProfile")
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.is_monitor_mode_active", return_value=False)
    @patch("cafe_chameleon.modes.aggressive.runner.register_signal_handler")
    def test_aggressive_mode_applies_attack_mac_per_bssid(
        self, mock_sig, mock_mon, mock_carrier, mock_get_profile, mock_get_ssid,
        mock_has_net, mock_scan_bssids, mock_select_bssid, mock_get_attack_mac,
        mock_set_mac, mock_lock, mock_scan_wrapper
    ):
        from cafe_chameleon.modes.aggressive.runner import run_aggressive

        mock_scan_bssids.return_value = [
            {"bssid": "00:11:22:33:44:01", "signal": 80, "chan": 1, "security": ""},
            {"bssid": "00:11:22:33:44:02", "signal": 60, "chan": 6, "security": ""},
        ]
        mock_select_bssid.return_value = mock_scan_bssids.return_value

        args = MagicMock()
        args.profile = "TargetProfile"
        args.interface = "wlan0"
        args.air = None
        args.force = False
        args.select_bssid = False
        args.clients = False
        args.prioritize_clients = False

        run_aggressive(args)

        # get_attack_mac and set_mac_address should be called for each BSSID target
        assert mock_get_attack_mac.call_count == 2
        assert mock_set_mac.call_count == 2

