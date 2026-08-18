"""
tests.network.test_internet_verification_guaranteed - Unit tests for guaranteed internet connectivity & captive portal verification.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open

from cafe_chameleon.network.internet.sockets import _probe_dns_resolution, _probe_udp_dns, _probe_socket
from cafe_chameleon.network.internet.checker import (
    _probe_http_endpoint,
    verify_internet_connectivity,
    has_internet,
    ConnectivityState,
    ConnectivityResult
)
from cafe_chameleon.network.internet.gateway import (
    check_gateway_neighbor_table,
    _probe_gateway_tcp,
    arp_ping_gateway_once,
    wait_for_gateway_pong
)
from cafe_chameleon.network.nmcli.connectivity import get_nmcli_connectivity


class TestGuaranteedInternetVerification(unittest.TestCase):
    """Thorough unit tests for guaranteed internet reachability, captive portal detection, and DNS verification."""

    # ---------------- Sockets & DNS Probing ----------------
    @patch("socket.getaddrinfo")
    def test_probe_dns_resolution_success(self, mock_gai):
        mock_gai.return_value = [(2, 1, 6, "", ("142.250.190.46", 80))]
        self.assertTrue(_probe_dns_resolution("google.com", timeout=1.0))

    @patch("socket.getaddrinfo", side_effect=OSError("DNS fail"))
    def test_probe_dns_resolution_failure(self, mock_gai):
        self.assertFalse(_probe_dns_resolution("invalid.domain.test", timeout=0.1))

    @patch("socket.socket")
    def test_probe_udp_dns_success(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        # Header with tx_id=0xAB12, flags=0x8180 (response flag set)
        resp_data = b"\xab\x12\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        mock_sock.recvfrom.return_value = (resp_data, ("8.8.8.8", 53))

        res = _probe_udp_dns("8.8.8.8", domain="google.com", timeout=1.0)
        self.assertTrue(res)

    @patch("socket.socket")
    def test_probe_udp_dns_failure(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError()
        self.assertFalse(_probe_udp_dns("8.8.8.8", domain="google.com", timeout=0.1))

    # ---------------- HTTP Captive Portal Probes ----------------
    @patch("urllib.request.urlopen")
    def test_probe_http_endpoint_204_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.geturl.return_value = "http://connectivitycheck.gstatic.com/generate_204"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ep = {"provider": "Google 204", "url": "http://connectivitycheck.gstatic.com/generate_204", "type": "status_204"}
        auth, portal, prov = _probe_http_endpoint(ep, timeout=1.0)
        self.assertTrue(auth)
        self.assertFalse(portal)
        self.assertEqual(prov, "Google 204")

    @patch("urllib.request.urlopen")
    def test_probe_http_endpoint_204_redirect_captive_portal(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.geturl.return_value = "http://192.168.1.1/login.html"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ep = {"provider": "Google 204", "url": "http://connectivitycheck.gstatic.com/generate_204", "type": "status_204"}
        auth, portal, url = _probe_http_endpoint(ep, timeout=1.0)
        self.assertFalse(auth)
        self.assertTrue(portal)
        self.assertEqual(url, "http://192.168.1.1/login.html")

    @patch("urllib.request.urlopen")
    def test_probe_http_endpoint_apple_token_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.geturl.return_value = "http://captive.apple.com/hotspot-detect.html"
        mock_resp.read.return_value = b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ep = {"provider": "Apple Hotspot Detect", "url": "http://captive.apple.com/hotspot-detect.html", "type": "body_match", "token": "Success"}
        auth, portal, prov = _probe_http_endpoint(ep, timeout=1.0)
        self.assertTrue(auth)
        self.assertFalse(portal)
        self.assertEqual(prov, "Apple Hotspot Detect")

    @patch("urllib.request.urlopen")
    def test_probe_http_endpoint_apple_portal_intercepted(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.geturl.return_value = "http://captive.apple.com/hotspot-detect.html"
        mock_resp.read.return_value = b"<form action='/login'>Please accept terms to access Wi-Fi</form>"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ep = {"provider": "Apple Hotspot Detect", "url": "http://captive.apple.com/hotspot-detect.html", "type": "body_match", "token": "Success"}
        auth, portal, url = _probe_http_endpoint(ep, timeout=1.0)
        self.assertFalse(auth)
        self.assertTrue(portal)

    # ---------------- verify_internet_connectivity ----------------
    @patch("cafe_chameleon.network.internet.checker._probe_http_endpoint")
    @patch("cafe_chameleon.network.internet.checker.wait_for_gateway_pong", return_value=True)
    def test_verify_internet_connectivity_full(self, mock_gw, mock_http):
        mock_http.return_value = (True, False, "Google 204")
        res = verify_internet_connectivity(timeout=1.0, strict=True, gateway_ip="192.168.1.1")
        self.assertEqual(res.state, ConnectivityState.FULL_INTERNET)
        self.assertTrue(res.is_authenticated)
        self.assertEqual(res.http_verified_endpoint, "Google 204")

    @patch("cafe_chameleon.network.internet.checker._probe_http_endpoint")
    @patch("cafe_chameleon.network.internet.checker.wait_for_gateway_pong", return_value=True)
    def test_verify_internet_connectivity_captive_portal(self, mock_gw, mock_http):
        mock_http.return_value = (False, True, "http://192.168.1.1:8080/portal.php")
        res = verify_internet_connectivity(timeout=1.0, strict=True, gateway_ip="192.168.1.1")
        self.assertEqual(res.state, ConnectivityState.CAPTIVE_PORTAL)
        self.assertFalse(res.is_authenticated)
        self.assertTrue(res.portal_detected)
        self.assertEqual(res.portal_url, "http://192.168.1.1:8080/portal.php")

    @patch("cafe_chameleon.network.internet.checker.wait_for_gateway_pong", return_value=False)
    def test_verify_internet_connectivity_no_gateway(self, mock_gw):
        res = verify_internet_connectivity(timeout=1.0, gateway_ip="192.168.1.1", ping_gateway=True)
        self.assertEqual(res.state, ConnectivityState.NO_GATEWAY)
        self.assertFalse(res.gateway_reachable)

    # ---------------- NetworkManager Connectivity ----------------
    @patch("cafe_chameleon.network.nmcli.connectivity._run")
    def test_get_nmcli_connectivity_states(self, mock_run):
        mock_run.return_value = (0, "full\n")
        self.assertEqual(get_nmcli_connectivity(), "full")

        mock_run.return_value = (0, "portal\n")
        self.assertEqual(get_nmcli_connectivity(), "portal")

        mock_run.return_value = (0, "limited\n")
        self.assertEqual(get_nmcli_connectivity(), "limited")

        mock_run.return_value = (1, "")
        mock_run.side_effect = None
        self.assertIsNone(get_nmcli_connectivity())

    # ---------------- Gateway Neighbor & TCP Probing ----------------
    @patch("builtins.open", mock_open(read_data="IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1       0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"))
    def test_check_gateway_neighbor_table_proc_arp(self):
        self.assertTrue(check_gateway_neighbor_table("192.168.1.1", interface="wlan0"))


    @patch("socket.socket")
    def test_probe_gateway_tcp_connect(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # Connect succeeds
        mock_sock.connect.return_value = None
        self.assertTrue(_probe_gateway_tcp("192.168.1.1", ports=[53]))

    @patch("socket.socket")
    def test_probe_gateway_tcp_rst_refused(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # ConnectionRefused indicates gateway host sent RST -> host reachable!
        mock_sock.connect.side_effect = ConnectionRefusedError()
        self.assertTrue(_probe_gateway_tcp("192.168.1.1", ports=[80]))
