"""
tests/test_air_sniffer_hygiene.py - Unit tests for air sniffer MAC hygiene, corrupted frame rejection, and probe filtering.
"""

import unittest
from scapy.all import Dot11, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Raw, IP, UDP

from cafe_chameleon.scanners.air.packet_parser import (
    parse_air_packet,
    is_valid_client_mac,
    is_locally_administered_mac,
    extract_packet_rssi
)
from cafe_chameleon.scanners.air.sniffer import AirClientsMap
from cafe_chameleon.modes.aggressive.air_target_handler import filter_valid_air_clients


class TestAirSnifferHygiene(unittest.TestCase):

    def setUp(self):
        self.target_bssid = "00:11:22:33:44:00"
        self.target_bssids = {self.target_bssid}
        self.ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    def test_is_valid_client_mac(self):
        # Valid standard unicast hardware & randomized MACs
        self.assertTrue(is_valid_client_mac("00:11:22:33:44:55"))
        self.assertTrue(is_valid_client_mac("da:a1:19:44:55:66"))
        self.assertTrue(is_valid_client_mac("DE:AD:BE:EF:00:01"))

        # Invalid formats / garbage strings
        self.assertFalse(is_valid_client_mac("invalid_mac"))
        self.assertFalse(is_valid_client_mac("00:11:22:33:44"))
        self.assertFalse(is_valid_client_mac("00:11:22:33:44:55:66"))
        self.assertFalse(is_valid_client_mac("gg:hh:ii:jj:kk:ll"))
        self.assertFalse(is_valid_client_mac(""))
        self.assertFalse(is_valid_client_mac(None))

        # Multicast / Broadcast / Stimulator / Special addresses
        self.assertFalse(is_valid_client_mac("ff:ff:ff:ff:ff:ff"))  # Broadcast
        self.assertFalse(is_valid_client_mac("00:00:00:00:00:00"))  # All zeros
        self.assertFalse(is_valid_client_mac("01:00:5e:00:00:01"))  # IPv4 Multicast
        self.assertFalse(is_valid_client_mac("33:33:00:00:00:01"))  # IPv6 Multicast
        self.assertFalse(is_valid_client_mac("01:80:c2:00:00:00"))  # STP Multicast (bit 0 set)
        self.assertFalse(is_valid_client_mac("02:00:00:7c:4e:01"))  # Internal stimulator prefix

    def test_is_locally_administered_mac(self):
        # OUI Hardware MACs (bit 1 of byte 0 is 0)
        self.assertFalse(is_locally_administered_mac("00:11:22:33:44:55"))
        self.assertFalse(is_locally_administered_mac("dc:a6:32:11:22:33"))

        # Locally Administered / Randomized MACs (bit 1 of byte 0 is 1: e.g., x2, x6, xA, xE)
        self.assertTrue(is_locally_administered_mac("02:11:22:33:44:56"))
        self.assertTrue(is_locally_administered_mac("da:a1:19:33:44:55"))
        self.assertTrue(is_locally_administered_mac("ee:ff:11:22:33:44"))

        # Invalid MAC returns False
        self.assertFalse(is_locally_administered_mac("invalid"))

    def test_bad_fcs_frame_is_discarded(self):
        bssid_to_clients = {self.target_bssid: {}}
        client_metadata = {}
        client_mac = "00:11:22:aa:bb:cc"

        # Frame with RadioTap Flags 0x40 (Bad FCS / CRC error)
        pkt_bad_fcs = (
            RadioTap(Flags=0x40) /
            Dot11(FCfield=1, type=2, subtype=0, addr1=self.target_bssid, addr2=client_mac, addr3=self.target_bssid) /
            Raw(b"corrupted radio data")
        )
        parse_air_packet(pkt_bad_fcs, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        # Client must NOT be registered
        self.assertNotIn(client_mac, bssid_to_clients[self.target_bssid])
        self.assertNotIn(client_mac, client_metadata)

        # Frame with good FCS (Flags=0x00)
        pkt_good_fcs = (
            RadioTap(Flags=0x00) /
            Dot11(FCfield=1, type=2, subtype=0, addr1=self.target_bssid, addr2=client_mac, addr3=self.target_bssid) /
            Raw(b"valid data")
        )
        parse_air_packet(pkt_good_fcs, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        # Client should now be registered
        self.assertIn(client_mac, bssid_to_clients[self.target_bssid])
        self.assertIn(client_mac, client_metadata)

    def test_corrupted_garbage_mac_rejected(self):
        bssid_to_clients = {self.target_bssid: {}}
        client_metadata = {}

        # Frame with multicast or garbage transmitter MAC
        pkt_garbage = Dot11(FCfield=1, type=2, subtype=0, addr1=self.target_bssid, addr2="01:00:5e:12:34:56", addr3=self.target_bssid)
        parse_air_packet(pkt_garbage, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertEqual(len(bssid_to_clients[self.target_bssid]), 0)

    def test_ephemeral_laa_probe_quarantine_and_confirmation(self):
        bssid_to_clients = {self.target_bssid: {}}
        client_metadata = {}
        # Smartphone randomized MAC (LAA)
        probe_mac = "da:a1:19:12:34:56"

        # 1. Device sends unassociated Probe Request
        pkt_probe = Dot11(type=0, subtype=4, addr1=self.target_bssid, addr2=probe_mac, addr3=self.target_bssid) / Dot11ProbeReq()
        parse_air_packet(pkt_probe, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(probe_mac, bssid_to_clients[self.target_bssid])
        meta = client_metadata[probe_mac]
        self.assertTrue(meta["is_laa"])
        self.assertEqual(meta["probe_count"], 1)
        self.assertEqual(meta["data_count"], 0)
        self.assertFalse(meta["active"])

        # AirClientsMap confirms this is unconfirmed probe noise
        air_map = AirClientsMap(bssid_to_clients, client_metadata=client_metadata)
        self.assertFalse(air_map.is_confirmed_client(probe_mac))

        # filter_valid_air_clients removes this unconfirmed probe
        auto_params = {"gateway_mac": "00:aa:bb:cc:dd:ee", "local_mac": "00:fe:dc:ba:98:76"}
        bssids = [{"bssid": self.target_bssid}]
        filtered = filter_valid_air_clients(bssid_to_clients[self.target_bssid], tried_macs=set(), auto_params=auto_params, bssids=bssids, air_clients_map=air_map)
        self.assertNotIn(probe_mac, filtered)

        # 2. Device later sends associated Data frame
        pkt_data = Dot11(FCfield=1, type=2, subtype=0, addr1=self.target_bssid, addr2=probe_mac, addr3=self.target_bssid) / Raw(b"data traffic")
        parse_air_packet(pkt_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertTrue(meta["active"])
        self.assertGreaterEqual(meta["data_count"], 1)
        self.assertTrue(air_map.is_confirmed_client(probe_mac))

        # Now filter_valid_air_clients includes the confirmed client
        filtered_after_data = filter_valid_air_clients(bssid_to_clients[self.target_bssid], tried_macs=set(), auto_params=auto_params, bssids=bssids, air_clients_map=air_map)
        self.assertIn(probe_mac, filtered_after_data)


if __name__ == "__main__":
    unittest.main()
