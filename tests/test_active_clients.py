"""
tests.test_active_clients - Unit tests for 802.11 active client detection, ranking impact, and prioritized impersonation.
"""

import unittest
from unittest.mock import patch, MagicMock, call
from scapy.all import Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, RadioTap, IP, UDP, Raw

from cafe_chameleon.scanners.air.packet_parser import parse_air_packet
from cafe_chameleon.scanners.air.sniffer import AirClientsMap
from cafe_chameleon.modes.aggressive.ranker import (
    calculate_bssid_score,
    is_client_active,
    count_active_clients,
    get_active_clients_for_bssid
)
from cafe_chameleon.modes.aggressive.selector import display_and_select_bssid
from cafe_chameleon.modes.aggressive.air_target_handler import (
    sort_clients_by_activity,
    filter_valid_air_clients,
    test_air_client_targets as exec_test_air_client_targets
)


class TestActiveClientDetection(unittest.TestCase):

    def setUp(self):
        self.bssid1 = "00:11:22:33:44:01"
        self.bssid2 = "00:11:22:33:44:02"
        self.target_bssids = {self.bssid1, self.bssid2}
        self.ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
        self.client1 = "aa:bb:cc:dd:ee:01"
        self.client2 = "aa:bb:cc:dd:ee:02"

    def test_uplink_data_frame_marks_client_active(self):
        bssid_to_clients = {self.bssid1: {}}
        client_metadata = {}

        # Uplink data frame (to_ds=1, from_ds=0, type=2, subtype=0 Data)
        pkt = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Raw(b"test data payload")
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client1, bssid_to_clients[self.bssid1])
        self.assertTrue(client_metadata[self.client1]["active"])
        self.assertGreaterEqual(client_metadata[self.client1]["data_count"], 1)

    def test_probe_request_does_not_mark_client_active(self):
        bssid_to_clients = {self.bssid1: {}}
        client_metadata = {}

        # Probe Request (type=0, subtype=4)
        pkt = Dot11(type=0, subtype=4, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Dot11ProbeReq()
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client1, bssid_to_clients[self.bssid1])
        self.assertFalse(client_metadata[self.client1]["active"])

    @patch("cafe_chameleon.scanners.air.packet_parser.log_air")
    def test_probe_client_upgrades_to_active_on_subsequent_data(self, mock_log_air):
        bssid_to_clients = {self.bssid1: {}}
        client_metadata = {}

        # 1. First seen as Probe Request (idle)
        pkt_probe = Dot11(type=0, subtype=4, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Dot11ProbeReq()
        parse_air_packet(pkt_probe, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertFalse(client_metadata[self.client1]["active"])
        mock_log_air.assert_called_with(f"  [+] Target Client: {self.client1} on BSSID {self.bssid1}")

        # 2. Subsequent uplink data frame (now active)
        pkt_data = Dot11(FCfield=1, type=2, subtype=8, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Raw(b"app traffic")
        parse_air_packet(pkt_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertTrue(client_metadata[self.client1]["active"])
        mock_log_air.assert_called_with(f"  [+] Active client: {self.client1} on BSSID {self.bssid1}")

    @patch("cafe_chameleon.scanners.air.packet_parser.log_air")
    def test_initial_active_client_logs_active_client(self, mock_log_air):
        bssid_to_clients = {self.bssid1: {}}
        client_metadata = {}

        pkt_data = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Raw(b"app traffic")
        parse_air_packet(pkt_data, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertTrue(client_metadata[self.client1]["active"])
        mock_log_air.assert_called_with(f"  [+] Active client: {self.client1} on BSSID {self.bssid1}")

    def test_active_state_preserved_when_client_migrates_to_stronger_bssid(self):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Active data on BSSID 1 with RSSI -70
        pkt1 = RadioTap(dBm_AntSignal=-70) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Raw(b"data")
        parse_air_packet(pkt1, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertTrue(client_metadata[self.client1]["active"])
        self.assertIn(self.client1, bssid_to_clients[self.bssid1])

        # 2. Stronger data on BSSID 2 with RSSI -45
        pkt2 = RadioTap(dBm_AntSignal=-45) / Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client1, addr3=self.bssid2) / Raw(b"data")
        parse_air_packet(pkt2, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertIn(self.client1, bssid_to_clients[self.bssid2])
        self.assertNotIn(self.client1, bssid_to_clients[self.bssid1])
        self.assertTrue(client_metadata[self.client1]["active"])

    @patch("cafe_chameleon.scanners.air.packet_parser.log_air")
    def test_probe_client_upgrades_to_active_on_bssid_migration(self, mock_log_air):
        bssid_to_clients = {self.bssid1: {}, self.bssid2: {}}
        client_metadata = {}

        # 1. Initially seen as idle probe on BSSID 1
        pkt1 = Dot11(type=0, subtype=4, addr1=self.bssid1, addr2=self.client1, addr3=self.bssid1) / Dot11ProbeReq()
        parse_air_packet(pkt1, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertFalse(client_metadata[self.client1]["active"])
        mock_log_air.assert_called_with(f"  [+] Target Client: {self.client1} on BSSID {self.bssid1}")

        # 2. Later sends active data on BSSID 2 (higher priority data frame)
        pkt2 = Dot11(FCfield=1, type=2, subtype=0, addr1=self.bssid2, addr2=self.client1, addr3=self.bssid2) / Raw(b"traffic")
        parse_air_packet(pkt2, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)
        self.assertTrue(client_metadata[self.client1]["active"])
        self.assertIn(self.client1, bssid_to_clients[self.bssid2])
        self.assertNotIn(self.client1, bssid_to_clients[self.bssid1])
        mock_log_air.assert_called_with(f"  [+] Active rebound: {self.client1} -> BSSID {self.bssid2}")

    def test_downlink_data_frame_marks_client_active(self):
        bssid_to_clients = {self.bssid1: {}}
        client_metadata = {}

        # Downlink data frame (from_ds=1, to_ds=0, addr1=client, addr2=bssid, addr3=bssid)
        pkt = Dot11(FCfield=2, type=2, subtype=0, addr1=self.client1, addr2=self.bssid1, addr3=self.bssid1) / Raw(b"downlink data")
        parse_air_packet(pkt, self.target_bssids, self.ignore_macs, bssid_to_clients, client_metadata=client_metadata)

        self.assertIn(self.client1, bssid_to_clients[self.bssid1])
        self.assertTrue(client_metadata[self.client1]["active"])


class TestAirClientsMapAndRanking(unittest.TestCase):

    def test_air_clients_map_helpers(self):
        client_metadata = {
            "aa:bb:cc:01": {"active": True, "bssid": "00:11:22:01", "ip": "10.0.0.2"},
            "aa:bb:cc:02": {"active": False, "bssid": "00:11:22:01", "ip": None},
            "aa:bb:cc:03": {"active": True, "bssid": "00:11:22:02", "ip": "10.0.0.3"},
        }
        bssid_dict = {
            "00:11:22:01": {"aa:bb:cc:01": "10.0.0.2", "aa:bb:cc:02": None},
            "00:11:22:02": {"aa:bb:cc:03": "10.0.0.3"}
        }

        air_map = AirClientsMap(bssid_dict, client_metadata=client_metadata)

        self.assertTrue(air_map.is_client_active("aa:bb:cc:01"))
        self.assertFalse(air_map.is_client_active("aa:bb:cc:02"))
        self.assertTrue(air_map.is_client_active("aa:bb:cc:03"))
        self.assertEqual(air_map.active_clients, {"aa:bb:cc:01", "aa:bb:cc:03"})
        self.assertEqual(air_map.count_active_clients("00:11:22:01"), 1)
        self.assertEqual(air_map.count_active_clients("00:11:22:02"), 1)
        self.assertEqual(air_map.get_active_clients_for_bssid("00:11:22:01"), ["aa:bb:cc:01"])

    def test_calculate_bssid_score_active_vs_idle_default_mode(self):
        # Default ranking: Signal strength (75x), Active client (+300x), Idle client (+80x)
        bssid_ap1 = {"bssid": "00:11:22:01", "signal": "80", "chan": "1"}  # 1 active client
        bssid_ap2 = {"bssid": "00:11:22:02", "signal": "80", "chan": "6"}  # 1 idle client

        client_metadata = {
            "client_act": {"active": True},
            "client_idle": {"active": False}
        }
        air_map = AirClientsMap({
            "00:11:22:01": {"client_act": "10.0.0.1"},
            "00:11:22:02": {"client_idle": None}
        }, client_metadata=client_metadata)

        score1, c1, s1 = calculate_bssid_score(bssid_ap1, air_map, prioritize_clients=False)
        score2, c2, s2 = calculate_bssid_score(bssid_ap2, air_map, prioritize_clients=False)

        self.assertEqual(score1, (80 * 75) + 300)  # 6300
        self.assertEqual(score2, (80 * 75) + 80)   # 6080
        self.assertGreater(score1, score2)

    def test_calculate_bssid_score_active_prioritized_in_clients_mode(self):
        # Prioritize clients mode (-c): Active client (20000x), Idle client (10000x)
        bssid_active = {"bssid": "00:11:22:01", "signal": "20", "chan": "1"}  # 1 active client, 20% sig
        bssid_idle = {"bssid": "00:11:22:02", "signal": "90", "chan": "6"}    # 1 idle client, 90% sig

        client_metadata = {
            "client_act": {"active": True},
            "client_idle": {"active": False}
        }
        air_map = AirClientsMap({
            "00:11:22:01": {"client_act": "10.0.0.1"},
            "00:11:22:02": {"client_idle": None}
        }, client_metadata=client_metadata)

        score_act, c_act, s_act = calculate_bssid_score(bssid_active, air_map, prioritize_clients=True)
        score_idle, c_idle, s_idle = calculate_bssid_score(bssid_idle, air_map, prioritize_clients=True)

        # 1 active client (20000 + 1500 = 21500) MUST beat 1 idle client (10000 + 6750 = 16750)
        self.assertGreater(score_act, score_idle)


class TestPrioritizedActiveImpersonation(unittest.TestCase):

    def test_sort_clients_by_activity_orders_active_first(self):
        client_metadata = {
            "11:11:11:11:11:11": {"active": False, "ip": None},
            "22:22:22:22:22:22": {"active": True, "ip": "10.0.0.22"},
            "33:33:33:33:33:33": {"active": False, "ip": "10.0.0.33"},
            "44:44:44:44:44:44": {"active": True, "ip": None},
        }
        air_map = AirClientsMap({
            "bssid1": {
                "11:11:11:11:11:11": None,
                "22:22:22:22:22:22": "10.0.0.22",
                "33:33:33:33:33:33": "10.0.0.33",
                "44:44:44:44:44:44": None,
            }
        }, client_metadata=client_metadata)

        sorted_clients = sort_clients_by_activity(air_map["bssid1"], air_clients_map=air_map)
        sorted_macs = list(sorted_clients.keys())

        # Active with IP (22) -> Active without IP (44) -> Idle with IP (33) -> Idle without IP (11)
        self.assertEqual(sorted_macs[0], "22:22:22:22:22:22")
        self.assertEqual(sorted_macs[1], "44:44:44:44:44:44")
        self.assertEqual(sorted_macs[2], "33:33:33:33:33:33")
        self.assertEqual(sorted_macs[3], "11:11:11:11:11:11")

    @patch("cafe_chameleon.modes.aggressive.air_target_handler.hijack")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler._run")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.wait_for_carrier", return_value=True)
    def test_test_air_client_targets_executes_active_first(self, mock_carrier, mock_run, mock_hijack):
        # Stop on first successful hijack
        mock_hijack.return_value = True
        mock_run.return_value = (0, "")

        clients = {
            "idle_mac_1": None,
            "active_mac_1": "10.0.0.5",
            "idle_mac_2": "10.0.0.6"
        }
        client_metadata = {
            "active_mac_1": {"active": True, "ip": "10.0.0.5"},
            "idle_mac_1": {"active": False},
            "idle_mac_2": {"active": False, "ip": "10.0.0.6"}
        }
        air_map = AirClientsMap({"test_bssid": clients}, client_metadata=client_metadata)

        auto_params = {
            "local_ip": "10.0.0.100",
            "gateway_ip": "10.0.0.1",
            "cidr": "10.0.0.100/24",
            "broadcast": "10.0.0.255",
            "local_mac": "aa:bb:cc:dd:ee:ff",
        }
        args = MagicMock(any_ip=True, force=False, force_deauth=False)
        tried_macs = set()

        success, stop_early = exec_test_air_client_targets(
            clients,
            interface="wlan0",
            target_bssid="00:11:22:33:44:55",
            chan=1,
            profile="test_profile",
            tried_macs=tried_macs,
            auto_params=auto_params,
            args=args,
            air_clients_map=air_map
        )

        self.assertTrue(success)
        self.assertTrue(stop_early)
        # Verify active_mac_1 was targeted first and succeeded
        mock_hijack.assert_called_once()
        first_targeted_mac = mock_hijack.call_args[0][2]
        self.assertEqual(first_targeted_mac, "active_mac_1")

    @patch("cafe_chameleon.modes.aggressive.runner.auto_detect_network_params", return_value={"interface": "wlan0"})
    @patch("cafe_chameleon.modes.aggressive.runner.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.modes.aggressive.runner.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.modes.aggressive.runner.has_internet", side_effect=[False, False, True])
    @patch("cafe_chameleon.modes.aggressive.runner.scan_bssids_for_ssid")
    @patch("cafe_chameleon.modes.aggressive.runner.sniff_air_clients")
    @patch("cafe_chameleon.modes.aggressive.runner.lock_bssid", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.wait_for_carrier", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.set_mac_address", return_value=True)
    @patch("cafe_chameleon.modes.aggressive.runner.test_air_client_targets")
    def test_any_bssid_pooling_prioritizes_active_clients_across_all_bssids(
        self,
        mock_test_air_targets,
        mock_set_mac,
        mock_wait_carrier,
        mock_lock_bssid,
        mock_sniff_air,
        mock_scan_bssids,
        mock_has_internet,
        mock_get_ssid,
        mock_get_profile,
        mock_auto_params
    ):
        import argparse
        from cafe_chameleon.modes.aggressive.runner import run_aggressive

        mock_scan_bssids.return_value = [
            {"bssid": "10:11:12:13:14:15", "signal": "90", "chan": "1", "security": "OPEN"},
            {"bssid": "20:21:22:23:24:25", "signal": "40", "chan": "6", "security": "OPEN"},
        ]
        # BSSID 1 has idle client 1, BSSID 2 (weaker AP) has ACTIVE client 2
        raw_bssid_dict = {
            "10:11:12:13:14:15": {"00:11:22:33:44:01": "10.0.0.10"},
            "20:21:22:23:24:25": {"00:11:22:33:44:02": "10.0.0.20"},
        }
        client_metadata = {
            "00:11:22:33:44:01": {"active": False, "ip": "10.0.0.10"},
            "00:11:22:33:44:02": {"active": True, "ip": "10.0.0.20"},
        }
        air_map = AirClientsMap(raw_bssid_dict, client_metadata=client_metadata)
        mock_sniff_air.return_value = air_map
        mock_test_air_targets.return_value = (True, True)

        args = argparse.Namespace(
            profile="Cafe_WiFi",
            interface="wlan0",
            air=5,
            any_bssid=True,
            any_ip=False,
            force=False,
            select_bssid=False,
            clients=False,
            threshold=10,
            passive_only=False,
            force_deauth=False
        )

        result = run_aggressive(args)
        self.assertTrue(result)

        # Verify test_air_client_targets received both pooled clients, and active client from BSSID 2 is FIRST
        mock_test_air_targets.assert_called_once()
        passed_clients = mock_test_air_targets.call_args[0][0]
        passed_macs = list(passed_clients.keys())
        self.assertEqual(passed_macs[0], "00:11:22:33:44:02")  # Active client from BSSID 2
        self.assertEqual(passed_macs[1], "00:11:22:33:44:01")  # Idle client from BSSID 1


if __name__ == "__main__":
    unittest.main()
