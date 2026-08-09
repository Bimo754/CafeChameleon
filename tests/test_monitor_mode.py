import unittest
from unittest.mock import patch, MagicMock
import os
import signal

from cafe_chameleon.scanners.air import (
    is_monitor_mode_active,
    set_monitor_mode,
    set_managed_mode
)
from cafe_chameleon.network.deauth import send_deauth
from cafe_chameleon.scanners.air.sniffer import sniff_air_clients
from cafe_chameleon.utils.signals import (
    AirSkipInterrupt,
    HijackSkipInterrupt,
    MainSkipInterrupt,
    ScanSkipInterrupt,
    restore_and_exit
)
from cafe_chameleon.network.hijack.restore import restore
from cafe_chameleon.network.nmcli.restore import restore_auto
from cafe_chameleon.scanners.detector.auto_detect import auto_detect_network_params


class TestMonitorModeCleanup(unittest.TestCase):

    @patch("cafe_chameleon.scanners.air.mode._run")
    def test_is_monitor_mode_active(self, mock_run):
        # 1. Test when iw info shows monitor
        mock_run.return_value = (0, "Interface wlan0\n\ttype monitor\n")
        self.assertTrue(is_monitor_mode_active("wlan0"))

        # 2. Test when link show has wlan0mon
        def run_side_effect(cmd, **kwargs):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "info" in cmd_str:
                return (0, "Interface wlan0\n\ttype managed\n")
            if "link" in cmd_str:
                return (0, "1: lo: ...\n2: wlan0mon: ...\n")
            return (0, "")
        mock_run.side_effect = run_side_effect
        self.assertTrue(is_monitor_mode_active("wlan0"))

        # 3. Test when strictly managed
        def run_side_effect_managed(cmd, **kwargs):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            if "info" in cmd_str:
                return (0, "Interface wlan0\n\ttype managed\n")
            if "link" in cmd_str:
                return (0, "1: lo: ...\n2: wlan0: ...\n3: eth0: ...\n")
            return (0, "")
        mock_run.side_effect = run_side_effect_managed
        self.assertFalse(is_monitor_mode_active("wlan0"))

    @patch("cafe_chameleon.scanners.air.mode.wait_for_carrier")
    @patch("cafe_chameleon.scanners.air.mode._run")
    @patch("shutil.which")
    def test_set_managed_mode_cleans_up(self, mock_which, mock_run, mock_carrier):
        mock_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd in ("airmon-ng", "systemctl") else None
        mock_run.return_value = (0, "wlan0 connected")
        set_managed_mode("wlan0")

        called_cmds = [call_args[0][0] if isinstance(call_args[0][0], list) else call_args[0][0] for call_args in mock_run.call_args_list]
        flattened = [" ".join(c) if isinstance(c, list) else str(c) for c in called_cmds]
        
        self.assertTrue(any("iw dev wlan0 set type managed" in s for s in flattened))
        self.assertTrue(any("nmcli device set wlan0 managed yes" in s for s in flattened))
        self.assertTrue(any("systemctl restart NetworkManager" in s for s in flattened))

    @patch("cafe_chameleon.network.deauth.set_managed_mode")
    @patch("cafe_chameleon.network.deauth.set_monitor_mode")
    @patch("cafe_chameleon.network.deauth.is_monitor_mode_active")
    @patch("cafe_chameleon.network.deauth._run")
    @patch("shutil.which")
    def test_send_deauth_restores_managed_on_ctrl_c(self, mock_which, mock_run, mock_is_mon, mock_set_mon, mock_set_managed):
        mock_is_mon.return_value = False
        mock_set_mon.return_value = "wlan0"
        mock_which.side_effect = lambda cmd: "/usr/bin/" + cmd if cmd == "mdk4" else None
        mock_run.side_effect = KeyboardInterrupt("Ctrl+C during deauth")

        with self.assertRaises(KeyboardInterrupt):
            send_deauth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", interface="wlan0")

        mock_set_managed.assert_called_with("wlan0")

    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_restores_managed_on_air_skip(self, mock_sniff, mock_hopper_cls, mock_set_mon, mock_set_managed):
        mock_set_mon.return_value = "wlan0"
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        result = sniff_air_clients(["aa:bb:cc:dd:ee:ff"], interface="wlan0", duration=5)

        mock_hopper.stop.assert_called()
        mock_set_managed.assert_called_with("wlan0")

    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.network.hijack.restore._run")
    @patch("cafe_chameleon.network.hijack.restore.wait_for_carrier")
    def test_restore_checks_and_restores_monitor_mode(self, mock_carrier, mock_run, mock_is_mon, mock_set_managed):
        mock_is_mon.return_value = True
        mock_run.return_value = (0, "")
        restore("wlan0", "00:11:22:33:44:55", "10.0.0.5/24", "10.0.0.255", "10.0.0.1")
        mock_set_managed.assert_called_with("wlan0")

    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.network.nmcli.restore._run")
    @patch("cafe_chameleon.network.nmcli.restore.get_active_profile")
    @patch("cafe_chameleon.scanners.detector.auto_detect_network_params")
    def test_restore_auto_checks_and_restores_monitor_mode(self, mock_auto_params, mock_profile, mock_run, mock_is_mon, mock_set_managed):
        mock_profile.return_value = "MyWiFi"
        mock_auto_params.return_value = {"interface": "wlan0"}
        mock_is_mon.return_value = True
        mock_run.return_value = (0, "")
        restore_auto("MyWiFi")
        mock_set_managed.assert_called_with("wlan0")

    @patch("cafe_chameleon.scanners.air.is_monitor_mode_active")
    @patch("cafe_chameleon.scanners.air.set_managed_mode")
    @patch("cafe_chameleon.scanners.detector.auto_detect._run")
    def test_auto_detect_restores_monitor_interface(self, mock_run, mock_set_managed, mock_is_mon):
        mock_is_mon.return_value = True
        mock_run.return_value = (0, "")
        params = auto_detect_network_params(target_iface="wlan0")
        mock_set_managed.assert_called_with("wlan0")


if __name__ == "__main__":
    unittest.main()
