"""
tests.scanners.air.test_active_target_discovery_fixes - Unit tests for active target discovery fixes.
"""

import unittest
from unittest.mock import patch, MagicMock
from scapy.all import Dot11, RadioTap, Raw, ARP, Ether

from cafe_chameleon.scanners.air.packet_parser import is_valid_client_mac, match_target_bssid, parse_air_packet
from cafe_chameleon.scanners.orchestrator import deep_scan_subnet
from cafe_chameleon.scanners.arp_scanner import scan_subnet as scapy_scan_subnet
from cafe_chameleon.scanners.passive_scanner import passive_sniff_subnet


class TestActiveTargetDiscoveryFixes(unittest.TestCase):

    def test_laa_mac_starting_with_02_00_00_is_valid(self):
        # Android / iOS randomized MAC starting with 02:00:00 (valid unicast LAA MAC)
        mac_test = "02:00:00:11:22:33"
        self.assertTrue(is_valid_client_mac(mac_test))

    def test_match_target_bssid_exact_and_prefix(self):
        target_bssids = {"00:11:22:33:44:50"}

        # Exact match
        self.assertEqual(match_target_bssid("00:11:22:33:44:50", target_bssids), "00:11:22:33:44:50")

        # Multi-BSSID prefix match (same 5 octets, different last octet e.g. 5GHz virtual interface)
        self.assertEqual(match_target_bssid("00:11:22:33:44:51", target_bssids), "00:11:22:33:44:50")

        # Unrelated BSSID prefix
        self.assertIsNone(match_target_bssid("aa:bb:cc:dd:ee:ff", target_bssids))

    def test_air_packet_parser_accepts_laa_02_00_00_and_multi_bssid(self):
        target_bssids = {"00:11:22:33:44:50"}
        bssid_to_clients = {"00:11:22:33:44:50": {}}
        client_metadata = {}
        ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
        client_mac = "02:00:00:ab:cd:ef"  # LAA randomized MAC

        # Frame directed to 5GHz BSSID 00:11:22:33:44:51 (multi-BSSID of 00:11:22:33:44:50)
        pkt = Dot11(FCfield=1, type=2, subtype=0, addr1="00:11:22:33:44:51", addr2=client_mac, addr3="00:11:22:33:44:51") / Raw(b"web data")
        parse_air_packet(pkt, target_bssids, ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(client_mac, bssid_to_clients["00:11:22:33:44:50"])
        self.assertIn(client_mac, client_metadata)
        self.assertTrue(client_metadata[client_mac]["active"])

    @patch("cafe_chameleon.scanners.orchestrator.passive_sniff_subnet")
    @patch("cafe_chameleon.scanners.orchestrator.scan_subnet")
    @patch("cafe_chameleon.scanners.orchestrator.nmap_scan_subnet")
    def test_orchestrator_retains_devices_sharing_gateway_oui_prefix(self, mock_nmap, mock_arp, mock_passive):
        gateway_ip = "192.168.1.1"
        gateway_mac = "00:11:22:33:44:01"
        phone_ip = "192.168.1.50"
        phone_mac = "00:11:22:33:44:88"  # Shares first 5 octets with gateway

        mock_passive.return_value = [{"ip": phone_ip, "mac": phone_mac}]
        mock_arp.return_value = [{"ip": phone_ip, "mac": phone_mac}]
        mock_nmap.return_value = [{"ip": phone_ip, "mac": phone_mac}]

        hosts = deep_scan_subnet(
            "192.168.1.0/24",
            interface="wlan0",
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            local_ip="192.168.1.100",
            local_mac="aa:bb:cc:dd:ee:ff",
            duration=1
        )

        # Phone MAC sharing gateway OUI prefix must NOT be filtered out
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], phone_ip)
        self.assertEqual(hosts[0]["mac"], phone_mac)

    @patch("scapy.all.srp")
    @patch("cafe_chameleon.scanners.arp_scanner.nmap_scan_subnet")
    def test_scapy_active_arp_scanner(self, mock_nmap_scan, mock_srp):
        mock_nmap_scan.return_value = []

        snd_pkt = MagicMock()
        rcv_pkt = MagicMock()
        rcv_pkt.haslayer.return_value = True

        arp_layer = MagicMock()
        arp_layer.psrc = "192.168.1.200"
        arp_layer.hwsrc = "02:00:00:99:88:77"
        rcv_pkt.__getitem__.return_value = arp_layer

        mock_srp.return_value = ([(snd_pkt, rcv_pkt)], [])

        results = scapy_scan_subnet("192.168.1.0/24", interface="wlan0")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip"], "192.168.1.200")
        self.assertEqual(results[0]["mac"], "02:00:00:99:88:77")

    @patch("scapy.all.srp")
    @patch("cafe_chameleon.scanners.arp_scanner.nmap_scan_subnet")
    def test_scan_subnet_accepts_parent_net_and_silent(self, mock_nmap_scan, mock_srp):
        mock_nmap_scan.return_value = []
        mock_srp.return_value = ([], [])

        # Ensure scan_subnet accepts parent_net and silent kwargs without TypeError
        results = scapy_scan_subnet(
            "192.168.1.0/24",
            interface="wlan0",
            parent_net="192.168.0.0/16",
            silent=True
        )
        self.assertEqual(results, [])
        mock_nmap_scan.assert_called_once_with(
            "192.168.1.0/24",
            "wlan0",
            parent_net="192.168.0.0/16",
            gateway_ip=None,
            gateway_mac=None,
            silent=True
        )


if __name__ == "__main__":
    unittest.main()
