"""
tests.scanners.air.test_sniffer_optimizations - Unit tests for sniffing optimizations,
BPF filter application, QoS Null active frame classification, single-channel hopper bypass,
and passive scanner robustness.
"""

import unittest
from unittest.mock import patch, MagicMock
from scapy.all import Dot11, RadioTap, Raw, IP, UDP

from cafe_chameleon.scanners.air.packet_parser import parse_air_packet
from cafe_chameleon.scanners.air.hopper import ChannelHopper
from cafe_chameleon.scanners.air.sniffer import sniff_air_clients, AirClientsMap
from cafe_chameleon.scanners.passive_scanner import passive_sniff_subnet
from cafe_chameleon.utils.signals import AirSkipInterrupt


class TestSnifferOptimizations(unittest.TestCase):

    def setUp(self):
        self.bssid = "00:11:22:33:44:55"
        self.target_bssids = {self.bssid}
        self.ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
        self.client_mac = "aa:bb:cc:dd:ee:ff"

    def test_qos_null_frame_marked_as_active(self):
        """QoS Null frame (subtype 12) with to_ds=1 should be recognized as active station activity."""
        bssid_to_clients = {self.bssid: {}}
        client_metadata = {}

        # Subtype 12 is QoS Null; FCfield=1 is to_ds
        pkt = Dot11(FCfield=1, type=2, subtype=12, addr1=self.bssid, addr2=self.client_mac, addr3=self.bssid)
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client_mac, bssid_to_clients[self.bssid])
        self.assertTrue(client_metadata[self.client_mac]["active"])
        self.assertGreaterEqual(client_metadata[self.client_mac]["data_count"], 1)

    def test_null_data_frame_marked_as_active(self):
        """Null function frame (subtype 4) with to_ds=1 should be recognized as active station activity."""
        bssid_to_clients = {self.bssid: {}}
        client_metadata = {}

        pkt = Dot11(FCfield=1, type=2, subtype=4, addr1=self.bssid, addr2=self.client_mac, addr3=self.bssid)
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client_mac, bssid_to_clients[self.bssid])
        self.assertTrue(client_metadata[self.client_mac]["active"])
        self.assertGreaterEqual(client_metadata[self.client_mac]["data_count"], 1)

    def test_resilient_raw_ipv4_extraction(self):
        """Extracts client IP when raw IPv4 header is present in payload without standard LLC."""
        bssid_to_clients = {self.bssid: {}}
        client_metadata = {}

        # Construct raw IPv4 packet bytes: src 192.168.1.50, dst 1.1.1.1
        # IPv4 version 4, IHL 5 (\x45\x00...), src=192.168.1.50 (\xc0\xa8\x01\x32), dst=1.1.1.1 (\x01\x01\x01\x01)
        raw_ip_header = (
            b"\x45\x00\x00\x28\x12\x34\x00\x00\x40\x11\x00\x00"
            b"\xc0\xa8\x01\x32"  # 192.168.1.50
            b"\x01\x01\x01\x01"  # 1.1.1.1
        )
        pkt = Dot11(FCfield=1, type=2, subtype=8, addr1=self.bssid, addr2=self.client_mac, addr3=self.bssid) / Raw(raw_ip_header)
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client_mac, bssid_to_clients[self.bssid])
        self.assertEqual(bssid_to_clients[self.bssid][self.client_mac], "192.168.1.50")
        self.assertEqual(client_metadata[self.client_mac]["ip"], "192.168.1.50")
        self.assertTrue(client_metadata[self.client_mac]["active"])

    @patch("cafe_chameleon.scanners.air.hopper._run")
    def test_single_channel_hopper_bypasses_thread(self, mock_run):
        """ChannelHopper with 1 channel should set channel once without spawning loop thread."""
        hopper = ChannelHopper("wlan0mon", [6])
        hopper.start()

        mock_run.assert_called_once_with(["iw", "dev", "wlan0mon", "set", "channel", "6"], debug=False)
        self.assertIsNone(hopper._thread)

    @patch("cafe_chameleon.scanners.air.sniffer.AirCountdownTimer")
    @patch("cafe_chameleon.scanners.air.sniffer.auto_detect_network_params", return_value={"interface": "wlan0", "local_mac": "00:11:22:33:44:55"})
    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode", return_value="wlan0mon")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_passes_bpf_filter(
        self, mock_sniff, mock_hopper, mock_set_mon, mock_set_man, mock_auto, mock_timer
    ):
        """sniff_air_clients should invoke scapy sniff with kernel BPF filter."""
        mock_sniff.side_effect = AirSkipInterrupt()

        sniff_air_clients(
            target_bssids=[self.bssid],
            interface="wlan0",
            duration=10,
            target_channels=[6]
        )

        mock_sniff.assert_called()
        call_kwargs = mock_sniff.call_args[1]
        self.assertIn("filter", call_kwargs)
        self.assertIn("type data", call_kwargs["filter"])

    @patch("scapy.all.sniff", create=True)
    def test_passive_scanner_runs_without_name_error(self, mock_sniff):
        """passive_sniff_subnet should execute cleanly without NameError."""
        hosts = passive_sniff_subnet("192.168.1.0/24", "wlan0", duration=1)
        self.assertIsInstance(hosts, list)
        mock_sniff.assert_called()
