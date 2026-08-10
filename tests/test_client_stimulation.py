import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.scanners.air.stimulator import (
    ClientStimulator,
    build_probe_req_packet,
    build_null_data_packet,
    build_wakeup_deauth_packet
)
from cafe_chameleon.scanners.air.packet_parser import parse_air_packet
from cafe_chameleon.scanners.air.hopper import ChannelHopper


class TestClientStimulation(unittest.TestCase):

    def test_build_probe_req_packet(self):
        pkt = build_probe_req_packet(ssid="TargetWiFi", target_bssid="00:11:22:33:44:55", channel=6)
        self.assertIsNotNone(pkt)
        from scapy.all import Dot11, Dot11ProbeReq
        self.assertTrue(pkt.haslayer(Dot11))
        self.assertTrue(pkt.haslayer(Dot11ProbeReq))
        dot11 = pkt[Dot11]
        self.assertEqual(dot11.type, 0)
        self.assertEqual(dot11.subtype, 4)
        self.assertEqual(dot11.addr1.lower(), "00:11:22:33:44:55")

    def test_build_null_data_packet(self):
        pkt = build_null_data_packet(target_bssid="00:11:22:33:44:55", to_ds=True)
        self.assertIsNotNone(pkt)
        from scapy.all import Dot11
        self.assertTrue(pkt.haslayer(Dot11))
        dot11 = pkt[Dot11]
        self.assertEqual(dot11.type, 2)
        self.assertEqual(dot11.subtype, 4)
        self.assertEqual(dot11.addr1.lower(), "00:11:22:33:44:55")

    def test_build_wakeup_deauth_packet(self):
        pkt = build_wakeup_deauth_packet(target_bssid="00:11:22:33:44:55", client_mac="ff:ff:ff:ff:ff:ff", reason=7)
        self.assertIsNotNone(pkt)
        from scapy.all import Dot11, Dot11Deauth
        self.assertTrue(pkt.haslayer(Dot11))
        self.assertTrue(pkt.haslayer(Dot11Deauth))
        dot11 = pkt[Dot11]
        self.assertEqual(dot11.type, 0)
        self.assertEqual(dot11.subtype, 12)
        self.assertEqual(dot11.addr2.lower(), "00:11:22:33:44:55")

    @patch("scapy.all.sendp")
    def test_stimulator_stimulate_channel_sends_packets(self, mock_sendp):
        stim = ClientStimulator(
            interface="wlan0mon",
            target_bssids=["00:11:22:33:44:55"],
            ssid="TargetWiFi",
            enabled=True,
            burst_count=1
        )
        count = stim.stimulate_channel(channel=1)
        self.assertGreater(count, 0)
        mock_sendp.assert_called_once()

    @patch("scapy.all.sendp")
    def test_stimulator_disabled_does_not_send(self, mock_sendp):
        stim = ClientStimulator(
            interface="wlan0mon",
            target_bssids=["00:11:22:33:44:55"],
            ssid="TargetWiFi",
            enabled=False
        )
        count = stim.stimulate_channel(channel=1)
        self.assertEqual(count, 0)
        mock_sendp.assert_not_called()

    def test_parse_air_packet_extracts_probe_response(self):
        from scapy.all import Dot11, Dot11ProbeResp
        target_bssid = "00:11:22:33:44:55"
        distant_client = "aa:bb:cc:dd:ee:11"
        bssid_to_clients = {target_bssid: {}}
        ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

        # Probe Response (type 0, subtype 5): AP (addr2=BSSID) sends to Client (addr1=Client)
        pkt_probe_resp = Dot11(type=0, subtype=5, addr1=distant_client, addr2=target_bssid, addr3=target_bssid) / Dot11ProbeResp()
        parse_air_packet(pkt_probe_resp, {target_bssid}, ignore_macs, bssid_to_clients)
        self.assertIn(distant_client, bssid_to_clients[target_bssid])

    def test_parse_air_packet_extracts_auth_and_deauth_frames(self):
        from scapy.all import Dot11, Dot11Auth, Dot11Deauth
        target_bssid = "00:11:22:33:44:55"
        client_auth = "aa:bb:cc:dd:ee:22"
        client_deauth = "aa:bb:cc:dd:ee:33"
        bssid_to_clients = {target_bssid: {}}
        ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

        # Authentication frame (subtype 11): Client (addr2) -> AP (addr1)
        pkt_auth = Dot11(type=0, subtype=11, addr1=target_bssid, addr2=client_auth, addr3=target_bssid) / Dot11Auth()
        parse_air_packet(pkt_auth, {target_bssid}, ignore_macs, bssid_to_clients)
        self.assertIn(client_auth, bssid_to_clients[target_bssid])

        # Deauthentication frame (subtype 12): AP (addr2) -> Client (addr1)
        pkt_deauth = Dot11(type=0, subtype=12, addr1=client_deauth, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
        parse_air_packet(pkt_deauth, {target_bssid}, ignore_macs, bssid_to_clients)
        self.assertIn(client_deauth, bssid_to_clients[target_bssid])

    def test_parse_air_packet_ignores_stimulator_mac(self):
        from scapy.all import Dot11
        target_bssid = "00:11:22:33:44:55"
        stim_mac = "02:00:00:7c:4e:01"
        bssid_to_clients = {target_bssid: {}}
        ignore_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", stim_mac}

        # Frame with stimulator MAC
        pkt = Dot11(type=2, subtype=4, addr1=target_bssid, addr2=stim_mac, addr3=target_bssid)
        parse_air_packet(pkt, {target_bssid}, ignore_macs, bssid_to_clients)
        self.assertNotIn(stim_mac, bssid_to_clients[target_bssid])

    def test_channel_hopper_calls_on_channel_change_callback(self):
        callback_mock = MagicMock()
        hopper = ChannelHopper("wlan0", [1, 6], dwell_times={1: 0.05, 6: 0.05}, on_channel_change=callback_mock)
        with patch("cafe_chameleon.scanners.air.hopper._run"):
            hopper.start()
            import time
            time.sleep(0.12)
            hopper.stop()
        self.assertGreaterEqual(callback_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
