"""
tests.test_internet_gateway_ping - Unit tests for gateway ping, pong verification, and internet checking integration.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock

from cafe_chameleon.network.internet.gateway import (
    get_default_gateway_ip,
    ping_gateway_once,
    arp_ping_gateway_once,
    wait_for_gateway_pong
)
from cafe_chameleon.network.internet.checker import has_internet
from cafe_chameleon.network.hijack.impersonate import hijack
from cafe_chameleon.cli.parser import parse_arguments


class TestInternetGatewayPing(unittest.TestCase):
    """Test suite for gateway discovery, high-speed pinging, and internet verification integration."""

    def test_get_default_gateway_ip_proc_net_route(self):
        sample_route_data = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "wlan0\t00000000\t010C370A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" # 10.55.12.1 in little-endian hex
            "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"  # 192.168.0.1 in little-endian hex
        )
        with patch("builtins.open", mock_open(read_data=sample_route_data)):
            # Auto interface (first default gateway)
            gw = get_default_gateway_ip()
            self.assertEqual(gw, "10.55.12.1")

            # Specific interface
            gw_eth = get_default_gateway_ip(interface="eth0")
            self.assertEqual(gw_eth, "192.168.0.1")

    @patch("builtins.open", side_effect=OSError("No /proc/net/route"))
    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_get_default_gateway_ip_fallback_ip_route(self, mock_run, mock_file):
        mock_run.return_value = (0, "default via 192.168.1.254 dev wlan0 proto dhcp metric 600")
        gw = get_default_gateway_ip(interface="wlan0")
        self.assertEqual(gw, "192.168.1.254")
        mock_run.assert_called_once_with(["ip", "-o", "-4", "route", "show", "to", "default", "dev", "wlan0"], debug=False)

    @patch("builtins.open", side_effect=OSError("No /proc/net/route"))
    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_get_default_gateway_ip_none(self, mock_run, mock_file):
        mock_run.return_value = (0, "")
        gw = get_default_gateway_ip()
        self.assertIsNone(gw)

    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_ping_gateway_once_success(self, mock_run):
        mock_run.return_value = (0, "64 bytes from 10.55.12.1: icmp_seq=1 ttl=64 time=1.23 ms")
        res = ping_gateway_once("10.55.12.1", interface="wlan0", timeout=0.25)
        self.assertTrue(res)
        mock_run.assert_called_once_with(["ping", "-c", "1", "-n", "-W", "0.25", "-I", "wlan0", "10.55.12.1"], debug=False, timeout=0.75)

    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_ping_gateway_once_failure(self, mock_run):
        mock_run.return_value = (1, "")
        res = ping_gateway_once("10.55.12.1", timeout=0.1)
        self.assertFalse(res)

    def test_ping_gateway_once_invalid_ip(self):
        self.assertFalse(ping_gateway_once(""))
        self.assertFalse(ping_gateway_once("invalid_ip"))
        self.assertFalse(ping_gateway_once(None))

    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_arp_ping_gateway_once_success(self, mock_run):
        mock_run.return_value = (0, "1 packets received")
        res = arp_ping_gateway_once("10.55.12.1", interface="wlan0")
        self.assertTrue(res)
        mock_run.assert_called_once_with(["arping", "-c", "1", "-w", "1", "-I", "wlan0", "10.55.12.1"], debug=False, timeout=1.5)

    @patch("cafe_chameleon.network.internet.gateway._run")
    def test_arp_ping_gateway_once_kernel_cache_fallback(self, mock_run):
        mock_run.return_value = (1, "")
        sample_arp_data = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "10.55.12.1       0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
        )
        with patch("builtins.open", mock_open(read_data=sample_arp_data)):
            res = arp_ping_gateway_once("10.55.12.1", interface="wlan0")
            self.assertTrue(res)

    def test_arp_ping_gateway_once_invalid_ip(self):
        self.assertFalse(arp_ping_gateway_once(""))
        self.assertFalse(arp_ping_gateway_once(None))

    @patch("cafe_chameleon.network.internet.gateway.ping_gateway_once")
    def test_wait_for_gateway_pong_immediate(self, mock_ping):
        mock_ping.return_value = True
        res = wait_for_gateway_pong("10.55.12.1", timeout=1.0)
        self.assertTrue(res)
        self.assertEqual(mock_ping.call_count, 1)

    @patch("cafe_chameleon.network.internet.gateway.ping_gateway_once")
    @patch("time.sleep")
    def test_wait_for_gateway_pong_retry_success(self, mock_sleep, mock_ping):
        # Fails first 2 pings, succeeds on 3rd
        mock_ping.side_effect = [False, False, True]
        res = wait_for_gateway_pong("10.55.12.1", timeout=1.0, poll_interval=0.01)
        self.assertTrue(res)
        self.assertEqual(mock_ping.call_count, 3)

    @patch("cafe_chameleon.network.internet.gateway.arp_ping_gateway_once", return_value=True)
    @patch("cafe_chameleon.network.internet.gateway.ping_gateway_once", return_value=False)
    @patch("time.sleep")
    def test_wait_for_gateway_pong_arp_fallback(self, mock_sleep, mock_ping, mock_arp):
        res = wait_for_gateway_pong("10.55.12.1", timeout=0.05, poll_interval=0.02, allow_arp_fallback=True)
        self.assertTrue(res)
        mock_arp.assert_called_once_with("10.55.12.1", interface=None, timeout=1.0)

    @patch("cafe_chameleon.network.internet.gateway.arp_ping_gateway_once", return_value=False)
    @patch("cafe_chameleon.network.internet.gateway.ping_gateway_once", return_value=False)
    @patch("time.sleep")
    def test_wait_for_gateway_pong_timeout(self, mock_sleep, mock_ping, mock_arp):
        res = wait_for_gateway_pong("10.55.12.1", timeout=0.05, poll_interval=0.02)
        self.assertFalse(res)

    @patch("cafe_chameleon.network.internet.gateway.get_default_gateway_ip", return_value=None)
    def test_wait_for_gateway_pong_no_gateway(self, mock_get_gw):
        res = wait_for_gateway_pong(None)
        self.assertTrue(res)

    @patch("cafe_chameleon.network.internet.checker.wait_for_gateway_pong")
    @patch("cafe_chameleon.network.internet.checker._probe_socket")
    def test_has_internet_gateway_ping_enabled_success(self, mock_probe, mock_gw_pong):
        mock_gw_pong.return_value = True
        mock_probe.return_value = True

        with patch("urllib.request.urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 204
            mock_url.return_value.__enter__.return_value = mock_resp

            result = has_internet(
                timeout=0.5,
                strict=False,
                check_speed=False,
                gateway_ip="10.55.12.1",
                interface="wlan0",
                ping_gateway=True
            )
            self.assertTrue(result)
            mock_gw_pong.assert_called_once_with(gateway_ip="10.55.12.1", interface="wlan0", timeout=2.0)

    @patch("cafe_chameleon.network.internet.checker.wait_for_gateway_pong")
    @patch("cafe_chameleon.network.internet.checker._probe_socket")
    def test_has_internet_gateway_ping_fails_early(self, mock_probe, mock_gw_pong):
        mock_gw_pong.return_value = False
        result = has_internet(
            timeout=0.5,
            gateway_ip="10.55.12.1",
            ping_gateway=True
        )
        self.assertFalse(result)
        mock_probe.assert_not_called()

    @patch("cafe_chameleon.network.hijack.impersonate.send_deauth")
    @patch("cafe_chameleon.network.hijack.impersonate.set_mac_address")
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_carrier")
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_gateway_pong")
    @patch("cafe_chameleon.network.hijack.impersonate.has_internet")
    @patch("cafe_chameleon.network.hijack.impersonate.test_internet_speed")
    @patch("cafe_chameleon.network.hijack.impersonate._run")
    def test_hijack_gateway_pong_flow(
        self,
        mock_run,
        mock_speed,
        mock_internet,
        mock_gw_pong,
        mock_carrier,
        mock_mac,
        mock_deauth
    ):
        mock_deauth.return_value = True
        mock_mac.return_value = True
        mock_carrier.return_value = True
        mock_run.return_value = (0, "inet 10.0.0.5/24")
        mock_gw_pong.return_value = True
        mock_internet.return_value = True
        mock_speed.return_value = (True, 100.0)

        with patch("builtins.open", mock_open(read_data="00:11:22:33:44:55")):
            res = hijack(
                "wlan0", "10.0.0.5", "00:11:22:33:44:55", "24", "10.0.0.255", "10.0.0.1",
                profile="HomeWiFi", bssid="aa:bb:cc:dd:ee:ff"
            )

        self.assertTrue(res)
        mock_gw_pong.assert_called_once_with(gateway_ip="10.0.0.1", interface="wlan0", timeout=3.5)
        mock_internet.assert_called_once_with(
            timeout=1.0, check_speed=False, gateway_ip="10.0.0.1", interface="wlan0", ping_gateway=False
        )

    @patch("cafe_chameleon.network.hijack.impersonate.send_deauth")
    @patch("cafe_chameleon.network.hijack.impersonate.set_mac_address")
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_carrier")
    @patch("cafe_chameleon.network.hijack.impersonate.wait_for_gateway_pong")
    @patch("cafe_chameleon.network.hijack.impersonate.has_internet")
    @patch("cafe_chameleon.network.hijack.impersonate.test_internet_speed")
    @patch("cafe_chameleon.network.hijack.impersonate._run")
    def test_hijack_no_gateway_skips_pong(
        self,
        mock_run,
        mock_speed,
        mock_internet,
        mock_gw_pong,
        mock_carrier,
        mock_mac,
        mock_deauth
    ):
        mock_deauth.return_value = True
        mock_mac.return_value = True
        mock_carrier.return_value = True
        mock_run.return_value = (0, "inet 10.0.0.5/24")
        mock_internet.return_value = True
        mock_speed.return_value = (True, 100.0)

        with patch("builtins.open", mock_open(read_data="00:11:22:33:44:55")):
            res = hijack(
                "wlan0", "10.0.0.5", "00:11:22:33:44:55", "24", "10.0.0.255", "10.0.0.1",
                profile="HomeWiFi", bssid="aa:bb:cc:dd:ee:ff", no_gateway=True
            )

        self.assertTrue(res)
        mock_gw_pong.assert_not_called()
        mock_internet.assert_called_once_with(
            timeout=1.0, check_speed=False, gateway_ip="10.0.0.1", interface="wlan0", ping_gateway=False
        )

    def test_cli_parser_simple_no_gateway(self):
        args = parse_arguments(["simple", "--no-gateway"])
        self.assertTrue(args.no_gateway)

    def test_cli_parser_aggressive_no_gateway(self):
        args = parse_arguments(["aggressive", "--no-gateway"])
        self.assertTrue(args.no_gateway)

    def test_cli_parser_default_no_gateway_false(self):
        args = parse_arguments(["simple"])
        self.assertFalse(getattr(args, "no_gateway", False))


if __name__ == "__main__":
    unittest.main()

