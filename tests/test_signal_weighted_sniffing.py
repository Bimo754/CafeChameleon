import unittest
from unittest.mock import patch, MagicMock

from cafe_chameleon.config import DEFAULT_BSSID_THRESHOLD
from cafe_chameleon.cli.parser import parse_arguments
from cafe_chameleon.models import BSSIDTarget
from cafe_chameleon.scanners.air.sniffer import (
    calculate_channel_signals,
    calculate_channel_dwell_times,
    should_weight_channels_by_signal,
    sniff_air_clients
)
from cafe_chameleon.scanners.air.hopper import ChannelHopper
from cafe_chameleon.utils.signals import AirSkipInterrupt


class TestSignalWeightedSniffing(unittest.TestCase):

    def test_calculate_channel_signals_extracts_max_signal_per_channel(self):
        # Multiple BSSIDs on same channel: should take maximum signal on that channel
        bssids = [
            {"bssid": "00:11:22:33:44:01", "chan": "1", "signal": "90"},
            {"bssid": "00:11:22:33:44:02", "chan": "1", "signal": "60"},
            {"bssid": "00:11:22:33:44:03", "chan": "6", "signal": "40%"},
            {"bssid": "00:11:22:33:44:04", "chan": "11", "signal": "15"},
        ]
        signals = calculate_channel_signals(bssids)
        self.assertEqual(signals[1], 90)
        self.assertEqual(signals[6], 40)
        self.assertEqual(signals[11], 15)

    def test_calculate_channel_signals_handles_bssidtarget_dataclass(self):
        bssids = [
            BSSIDTarget(bssid="00:11:22:33:44:01", ssid="TargetWiFi", signal="85", chan="36"),
            BSSIDTarget(bssid="00:11:22:33:44:02", ssid="TargetWiFi", signal="30", chan="40"),
        ]
        signals = calculate_channel_signals(bssids)
        self.assertEqual(signals[36], 85)
        self.assertEqual(signals[40], 30)

    def test_calculate_channel_signals_handles_empty_or_malformed(self):
        self.assertEqual(calculate_channel_signals(None), {})
        self.assertEqual(calculate_channel_signals([]), {})
        invalid_bssids = [{"bssid": "aa:bb:cc:dd:ee:ff", "chan": "N/A", "signal": "N/A"}]
        self.assertEqual(calculate_channel_signals(invalid_bssids), {})

    def test_should_weight_channels_by_signal_default_threshold(self):
        # Default threshold is 10: only weights when bssids > 10
        self.assertFalse(should_weight_channels_by_signal(10, threshold=10))
        self.assertFalse(should_weight_channels_by_signal(5, threshold=10))
        self.assertTrue(should_weight_channels_by_signal(11, threshold=10))
        self.assertTrue(should_weight_channels_by_signal(20, threshold=10))

    def test_should_weight_channels_by_signal_zero_forces_behavior(self):
        # Threshold of 0 forces the behavior regardless of BSSID count
        self.assertTrue(should_weight_channels_by_signal(1, threshold=0))
        self.assertTrue(should_weight_channels_by_signal(3, threshold=0))
        self.assertTrue(should_weight_channels_by_signal(10, threshold=0))
        self.assertTrue(should_weight_channels_by_signal(15, threshold=0))

    def test_should_weight_channels_by_signal_custom_threshold(self):
        # Custom user-supplied threshold e.g. 5
        self.assertFalse(should_weight_channels_by_signal(4, threshold=5))
        self.assertFalse(should_weight_channels_by_signal(5, threshold=5))
        self.assertTrue(should_weight_channels_by_signal(6, threshold=5))

    def test_calculate_channel_dwell_times_gives_more_time_to_stronger_signals(self):
        channels = [1, 6, 11]
        channel_signals = {1: 95, 6: 40, 11: 15}

        dwell_times = calculate_channel_dwell_times(channels, channel_signals, base_dwell=0.25)

        # Strong signal (ch 1: 95%) must have strictly more time than medium (ch 6: 40%) and weak (ch 11: 15%)
        self.assertGreater(dwell_times[1], dwell_times[6])
        self.assertGreater(dwell_times[6], dwell_times[11])
        self.assertGreater(dwell_times[1], 0.5)

    def test_channel_hopper_uses_dwell_times(self):
        hopper = ChannelHopper("wlan0", [1, 6], dwell_times={1: 0.5, 6: 0.2}, default_dwell=0.25)
        self.assertEqual(hopper.dwell_times[1], 0.5)
        self.assertEqual(hopper.dwell_times[6], 0.2)

    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_applies_weighted_hopping_when_bssids_exceed_10(
        self, mock_sniff, mock_hopper_cls, mock_set_mon, mock_set_managed
    ):
        mock_set_mon.return_value = "wlan0"
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        # 12 BSSIDs (> 10) with varying signal strengths on channels 1, 6, 11
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "chan": 1 if i <= 4 else (6 if i <= 8 else 11), "signal": 90 if i <= 4 else (40 if i <= 8 else 15)}
            for i in range(1, 13)
        ]
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channels = [1, 6, 11]

        sniff_air_clients(
            target_bssid_list,
            interface="wlan0",
            duration=5,
            target_channels=target_channels,
            bssids=bssids,
            bssid_threshold=10
        )

        # Check ChannelHopper was initialized with dwell_times favoring Channel 1
        mock_hopper_cls.assert_called_once()
        call_args, call_kwargs = mock_hopper_cls.call_args
        dwell_times = call_kwargs.get("dwell_times")
        self.assertIsNotNone(dwell_times)
        self.assertGreater(dwell_times[1], dwell_times[6])
        self.assertGreater(dwell_times[6], dwell_times[11])

    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_does_not_weight_when_bssids_equal_or_below_10(
        self, mock_sniff, mock_hopper_cls, mock_set_mon, mock_set_managed
    ):
        mock_set_mon.return_value = "wlan0"
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        # 8 BSSIDs (<= 10) with default threshold 10
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "chan": 1 if i <= 4 else 6, "signal": 90 if i <= 4 else 20}
            for i in range(1, 9)
        ]
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channels = [1, 6]

        sniff_air_clients(
            target_bssid_list,
            interface="wlan0",
            duration=5,
            target_channels=target_channels,
            bssids=bssids,
            bssid_threshold=10
        )

        mock_hopper_cls.assert_called_once()
        call_args, call_kwargs = mock_hopper_cls.call_args
        dwell_times = call_kwargs.get("dwell_times")
        self.assertIsNone(dwell_times)

    @patch("cafe_chameleon.scanners.air.sniffer.set_managed_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.set_monitor_mode")
    @patch("cafe_chameleon.scanners.air.sniffer.ChannelHopper")
    @patch("scapy.all.sniff", create=True)
    def test_sniff_air_clients_forces_weighted_when_threshold_is_zero(
        self, mock_sniff, mock_hopper_cls, mock_set_mon, mock_set_managed
    ):
        mock_set_mon.return_value = "wlan0"
        mock_hopper = MagicMock()
        mock_hopper_cls.return_value = mock_hopper
        mock_sniff.side_effect = AirSkipInterrupt()

        # Only 2 BSSIDs (<= 10), but threshold is 0 (forces behavior)
        bssids = [
            {"bssid": "00:11:22:33:44:01", "chan": 1, "signal": 95},
            {"bssid": "00:11:22:33:44:02", "chan": 6, "signal": 20},
        ]
        target_bssid_list = [b["bssid"] for b in bssids]
        target_channels = [1, 6]

        sniff_air_clients(
            target_bssid_list,
            interface="wlan0",
            duration=5,
            target_channels=target_channels,
            bssids=bssids,
            bssid_threshold=0
        )

        mock_hopper_cls.assert_called_once()
        call_args, call_kwargs = mock_hopper_cls.call_args
        dwell_times = call_kwargs.get("dwell_times")
        self.assertIsNotNone(dwell_times)
        self.assertGreater(dwell_times[1], dwell_times[6])

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "-b", "15"])
    def test_cli_parser_threshold_short_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.threshold, 15)

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "-b", "0"])
    def test_cli_parser_threshold_short_flag_zero(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.threshold, 0)

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--threshold", "0"])
    def test_cli_parser_threshold_long_flag_zero(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.threshold, 0)

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--threshold", "5"])
    def test_cli_parser_threshold_long_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.threshold, 5)

    @patch("sys.argv", ["cafe-chameleon", "aggressive"])
    def test_cli_parser_threshold_default_is_10(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.threshold, 10)


if __name__ == "__main__":
    unittest.main()
