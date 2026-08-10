"""
tests.test_air_association - Unit tests for single-BSSID binding based on data frame priority & RSSI.
"""

import unittest
from unittest.mock import MagicMock
from scapy.all import Dot11, Dot11ProbeResp, Dot11ProbeReq, Dot11Auth, RadioTap, IP, UDP, Raw
from cafe_chameleon.scanners.air.packet_parser import parse_air_packet, extract_packet_rssi


class TestAirAssociationSingleBinding(unittest.TestCase):
    def setUp(self):
        self.bssid1 = "00:11:22:33:44:01"
        self.bssid2 = "00:11:22:33:44:02"
        self.target_bssids = {self.bssid1, self.bssid2}
        self.ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
        self.client_mac = "aa:bb:cc:dd:ee:99"

    def test_extract_packet_rssi(self):
        # Packet with RadioTap dBm_AntSignal = -65
        pkt = RadioTap(dBm_AntSignal=-65) / Dot11(type=2, subtype=0, addr1=self.bssid1, addr2=self.client_mac)
        rssi = extract_packet_rssi(pkt)
        self.assertEqual(rssi, -65)

        # Packet without RadioTap
        pkt_plain = Dot11(type=2, subtype=0, addr1=self.bssid1, addr2=self.client_mac)
        self.assertIsNone(extract_packet_rssi(pkt_plain))

    def test_probe_then_data_frame_migrates_to_data_bssid(self):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Client heard via Probe Response on BSSID 1 (Priority 1)
        pkt_probe = Dot11(type=0, subtype=5, addr1=self.client_mac, addr2=self.bssid1, addr3=self.bssid1) / Dot11ProbeResp()
        parse_air_packet(pkt_probe, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid2])

        # 2. Client sends Uplink Data Frame (to_ds=1) on BSSID 2 (Priority 3)
        # FCfield = 1 (to_ds)
        pkt_data = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client_mac, addr3=self.bssid2)
        parse_air_packet(pkt_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        # Client must be migrated to BSSID 2 and removed from BSSID 1
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid2])

    def test_lower_priority_probe_cannot_dislodge_active_data_frame(self):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Client actively transmitting Data on BSSID 1 (Priority 3)
        pkt_data = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client_mac, addr3=self.bssid1)
        parse_air_packet(pkt_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client_mac, bssid_to_clients[self.bssid1])

        # 2. Client sends Probe Req or AP 2 sends Probe Resp on BSSID 2 (Priority 1)
        pkt_probe = Dot11(type=0, subtype=4, addr1=self.bssid2, addr2=self.client_mac, addr3=self.bssid2) / Dot11ProbeReq()
        parse_air_packet(pkt_probe, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        # Client must remain locked to BSSID 1
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid2])

    def test_rssi_tiebreaker_between_equal_priority_data_frames(self):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Data frame on BSSID 1 with RSSI -75 dBm
        pkt1 = RadioTap(dBm_AntSignal=-75) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client_mac, addr3=self.bssid1)
        parse_air_packet(pkt1, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid1])

        # 2. Weaker data frame on BSSID 2 (-85 dBm) -> should NOT switch
        pkt2_weak = RadioTap(dBm_AntSignal=-85) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client_mac, addr3=self.bssid2)
        parse_air_packet(pkt2_weak, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid2])

        # 3. Significantly stronger data frame on BSSID 2 (-50 dBm) -> SHOULD switch
        pkt2_strong = RadioTap(dBm_AntSignal=-50) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client_mac, addr3=self.bssid2)
        parse_air_packet(pkt2_strong, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid2])

    def test_ip_preservation_on_bssid_migration(self):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Packet on BSSID 1 with parsed IP
        pkt_with_ip = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client_mac, addr3=self.bssid1) / IP(src="10.55.12.88", dst="8.8.8.8") / UDP()
        parse_air_packet(pkt_with_ip, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertEqual(bssid_to_clients[self.bssid1][self.client_mac], "10.55.12.88")

        # 2. Stronger Data frame on BSSID 2 without IP payload
        pkt_strong_data = RadioTap(dBm_AntSignal=-40) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client_mac, addr3=self.bssid2)
        parse_air_packet(pkt_strong_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        # Migrated to BSSID 2 and preserved IP "10.55.12.88"
        self.assertNotIn(self.client_mac, bssid_to_clients[self.bssid1])
        self.assertIn(self.client_mac, bssid_to_clients[self.bssid2])
        self.assertEqual(bssid_to_clients[self.bssid2][self.client_mac], "10.55.12.88")


if __name__ == "__main__":
    unittest.main()
