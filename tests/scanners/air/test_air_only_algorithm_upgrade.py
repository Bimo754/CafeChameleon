"""
tests.scanners.air.test_air_only_algorithm_upgrade - Unit tests for --air-only algorithm upgrades.
"""

import time
import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.scanners.air.hopper import ChannelHopper
from cafe_chameleon.scanners.air.packet_parser import parse_air_packet
from cafe_chameleon.scanners.air.sniffer import AirClientsMap
from cafe_chameleon.scanners.air.stimulator import ClientStimulator
from cafe_chameleon.modes.aggressive.ranker import (
    get_client_traffic_velocity,
    calculate_bssid_velocity,
    is_client_active
)


class TestAirOnlyAlgorithmUpgrade(unittest.TestCase):

    def test_channel_hopper_adaptive_dwell_boost(self):
        hopper = ChannelHopper("wlan0", [1, 6, 11], default_dwell=0.20)
        self.assertEqual(hopper._boost_until, 0.0)

        hopper.boost_channel_dwell(1, duration=1.5)
        self.assertGreater(hopper._boost_until, time.time())

        hopper.boost_current_dwell(2.0)
        self.assertGreater(hopper._boost_until, time.time() + 1.0)

    def test_traffic_velocity_tracking_and_calculation(self):
        now = time.time()
        client_metadata = {
            "aa:bb:cc:dd:ee:01": {
                "active": True,
                "bssid": "00:11:22:33:44:00",
                "active_timestamps": [now - 1.0, now - 2.0, now - 3.0]
            },
            "aa:bb:cc:dd:ee:02": {
                "active": True,
                "bssid": "00:11:22:33:44:00",
                "active_timestamps": [now - 20.0]  # Stale timestamp outside 5s window
            }
        }
        air_map = AirClientsMap(
            {"00:11:22:33:44:00": {"aa:bb:cc:dd:ee:01": "10.0.0.5", "aa:bb:cc:dd:ee:02": "10.0.0.6"}},
            client_metadata=client_metadata
        )

        vel1 = get_client_traffic_velocity("aa:bb:cc:dd:ee:01", air_map, window_seconds=5.0)
        vel2 = get_client_traffic_velocity("aa:bb:cc:dd:ee:02", air_map, window_seconds=5.0)

        self.assertGreater(vel1, 0.0)
        self.assertEqual(vel2, 0.0)

        bssid_vel = calculate_bssid_velocity("00:11:22:33:44:00", air_map)
        self.assertEqual(bssid_vel, vel1)

    @patch("scapy.all.sendp")
    def test_stimulate_active_targets_burst(self, mock_sendp):
        stim = ClientStimulator("wlan0mon", ["00:11:22:33:44:00"], enabled=True)
        count = stim.stimulate_active_targets("00:11:22:33:44:00", ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])

        self.assertEqual(count, 2)
        mock_sendp.assert_called_once()


if __name__ == "__main__":
    unittest.main()
