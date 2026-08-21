import unittest
from unittest.mock import patch, MagicMock, call

from cafe_chameleon.modes.aggressive.ranker import calculate_bssid_score
from cafe_chameleon.modes.aggressive.selector import display_and_select_bssid, parse_target_selection
from cafe_chameleon.cli.parser import parse_arguments


class TestBSSIDRanking(unittest.TestCase):

    def test_calculate_bssid_score_default_prioritizes_signal(self):

        # Default ranking: Signal strength (75x) is heavily prioritized over clients (80x)
        bssid_high_sig_no_clients = {"bssid": "aa:bb:cc:dd:ee:01", "signal": "90", "chan": "1"}
        bssid_low_sig_with_client = {"bssid": "aa:bb:cc:dd:ee:02", "signal": "20", "chan": "6"}
        air_clients_map = {
            "aa:bb:cc:dd:ee:02": {"11:22:33:44:55:66": "10.0.0.5"}
        }

        score_high_sig, clients_1, sig_1 = calculate_bssid_score(bssid_high_sig_no_clients, air_clients_map, prioritize_clients=False)
        score_low_sig, clients_2, sig_2 = calculate_bssid_score(bssid_low_sig_with_client, air_clients_map, prioritize_clients=False)

        self.assertEqual(clients_1, 0)
        self.assertEqual(sig_1, 90)
        self.assertEqual(score_high_sig, 90 * 75)  # 6750

        self.assertEqual(clients_2, 1)
        self.assertEqual(sig_2, 20)
        self.assertEqual(score_low_sig, (20 * 75) + 80)  # 1580

        # Under default ranking, high signal AP ranks higher
        self.assertGreater(score_high_sig, score_low_sig)

    def test_calculate_bssid_score_prioritize_clients_ranks_clients_above_signal(self):
        # When prioritize_clients=True, any AP with captured clients ranks above APs with fewer or zero clients
        bssid_0_clients_100_sig = {"bssid": "aa:bb:cc:dd:ee:01", "signal": "100", "chan": "1"}
        bssid_1_client_10_sig = {"bssid": "aa:bb:cc:dd:ee:02", "signal": "10", "chan": "6"}
        bssid_2_clients_10_sig = {"bssid": "aa:bb:cc:dd:ee:03", "signal": "10", "chan": "11"}
        bssid_1_client_90_sig = {"bssid": "aa:bb:cc:dd:ee:04", "signal": "90", "chan": "36"}

        air_clients_map = {
            "aa:bb:cc:dd:ee:02": {"11:22:33:44:55:66": "10.0.0.5"},
            "aa:bb:cc:dd:ee:03": {
                "11:22:33:44:55:66": "10.0.0.5",
                "11:22:33:44:55:77": "10.0.0.6"
            },
            "aa:bb:cc:dd:ee:04": {"11:22:33:44:55:88": "10.0.0.7"},
        }

        score_0_100, c0, s0 = calculate_bssid_score(bssid_0_clients_100_sig, air_clients_map, prioritize_clients=True)
        score_1_10, c1, s1 = calculate_bssid_score(bssid_1_client_10_sig, air_clients_map, prioritize_clients=True)
        score_1_90, c1_90, s1_90 = calculate_bssid_score(bssid_1_client_90_sig, air_clients_map, prioritize_clients=True)
        score_2_10, c2, s2 = calculate_bssid_score(bssid_2_clients_10_sig, air_clients_map, prioritize_clients=True)

        # 1 client with 10% signal MUST beat 0 clients with 100% signal
        self.assertGreater(score_1_10, score_0_100)

        # 2 clients with 10% signal MUST beat 1 client with 90% signal
        self.assertGreater(score_2_10, score_1_90)

        # Same client count (1 client): 90% signal beats 10% signal (secondary tie-breaker)
        self.assertGreater(score_1_90, score_1_10)

    def test_calculate_bssid_score_handles_edge_cases(self):
        # Missing signal or non-digit signal
        bssid_invalid_sig = {"bssid": "AA:BB:CC:DD:EE:FF", "signal": "N/A"}
        score, clients, sig = calculate_bssid_score(bssid_invalid_sig, None, prioritize_clients=True)
        self.assertEqual(sig, 0)
        self.assertEqual(clients, 0)
        self.assertEqual(score, 0)

        # Case-insensitive MAC matching in air_clients_map
        bssid_upper = {"bssid": "AA:BB:CC:DD:EE:99", "signal": "50"}
        air_clients_map = {"aa:bb:cc:dd:ee:99": {"client1": "10.0.0.2"}}
        score, clients, sig = calculate_bssid_score(bssid_upper, air_clients_map, prioritize_clients=True)
        self.assertEqual(clients, 1)
        self.assertEqual(sig, 50)
        self.assertEqual(score, 10000 + (50 * 75))

    def test_display_and_select_bssid_sorts_correctly_with_flag(self):
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "95", "chan": "1"},   # 0 clients, 95% sig
            {"bssid": "00:11:22:33:44:02", "signal": "30", "chan": "6"},   # 2 clients, 30% sig
            {"bssid": "00:11:22:33:44:03", "signal": "40", "chan": "11"},  # 1 client, 40% sig
            {"bssid": "00:11:22:33:44:04", "signal": "80", "chan": "36"},  # 1 client, 80% sig
        ]
        air_clients_map = {
            "00:11:22:33:44:02": {"c1": "10.0.0.2", "c2": "10.0.0.3"},
            "00:11:22:33:44:03": {"c3": "10.0.0.4"},
            "00:11:22:33:44:04": {"c4": "10.0.0.5"},
        }

        # With prioritize_clients=True:
        # 1st: 00:11:22:33:44:02 (2 clients, 30% sig)
        # 2nd: 00:11:22:33:44:04 (1 client, 80% sig)
        # 3rd: 00:11:22:33:44:03 (1 client, 40% sig)
        # 4th: 00:11:22:33:44:01 (0 clients, 95% sig)
        sorted_bssids = display_and_select_bssid(
            list(bssids),
            air_clients_map,
            select_requested=False,
            prioritize_clients=True
        )

        self.assertEqual(sorted_bssids[0]["bssid"], "00:11:22:33:44:02")
        self.assertEqual(sorted_bssids[1]["bssid"], "00:11:22:33:44:04")
        self.assertEqual(sorted_bssids[2]["bssid"], "00:11:22:33:44:03")
        self.assertEqual(sorted_bssids[3]["bssid"], "00:11:22:33:44:01")

        # With prioritize_clients=False (default):
        # 1st: 00:11:22:33:44:01 (95% sig)
        # 2nd: 00:11:22:33:44:04 (80% sig)
        # 3rd: 00:11:22:33:44:03 (40% sig)
        # 4th: 00:11:22:33:44:02 (30% sig)
        default_sorted = display_and_select_bssid(
            list(bssids),
            air_clients_map,
            select_requested=False,
            prioritize_clients=False
        )

        self.assertEqual(default_sorted[0]["bssid"], "00:11:22:33:44:01")
        self.assertEqual(default_sorted[1]["bssid"], "00:11:22:33:44:04")
        self.assertEqual(default_sorted[2]["bssid"], "00:11:22:33:44:03")
        self.assertEqual(default_sorted[3]["bssid"], "00:11:22:33:44:02")

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "-c"])
    def test_cli_parser_short_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.clients)

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--clients"])
    def test_cli_parser_long_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.clients)

    @patch("sys.argv", ["cafe-chameleon", "aggressive"])
    def test_cli_parser_default_without_flag(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertFalse(getattr(args, "clients", False))
        self.assertFalse(getattr(args, "select_bssid", False))

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "-s"])
    def test_cli_parser_select_bssid_flag_only(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertTrue(args.select_bssid)

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "-s", "1,2,7"])
    def test_cli_parser_select_bssid_with_value(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.select_bssid, "1,2,7")

    @patch("sys.argv", ["cafe-chameleon", "aggressive", "--select-bssid", "1-10,12"])
    def test_cli_parser_select_bssid_long_flag_with_value(self):
        args = parse_arguments()
        self.assertEqual(args.command, "aggressive")
        self.assertEqual(args.select_bssid, "1-10,12")

    def test_parse_target_selection_single(self):
        self.assertEqual(parse_target_selection("1", 15), [1])
        self.assertEqual(parse_target_selection("(1)", 15), [1])
        self.assertEqual(parse_target_selection("[1]", 15), [1])

    def test_parse_target_selection_list(self):
        self.assertEqual(parse_target_selection("1,2,7", 15), [1, 2, 7])
        self.assertEqual(parse_target_selection("(1,2,7)", 15), [1, 2, 7])
        self.assertEqual(parse_target_selection(" 1 , 2 , 7 ", 15), [1, 2, 7])

    def test_parse_target_selection_range_and_combinations(self):
        expected_1_10_12 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12]
        self.assertEqual(parse_target_selection("1-10,12", 15), expected_1_10_12)
        self.assertEqual(parse_target_selection("(1-10,12)", 15), expected_1_10_12)
        self.assertEqual(parse_target_selection("1 - 5, 8, 10-12", 15), [1, 2, 3, 4, 5, 8, 10, 11, 12])

    def test_parse_target_selection_bounds_and_deduplication(self):
        # Out of bounds ignored (max 5)
        self.assertEqual(parse_target_selection("1-10,12", 5), [1, 2, 3, 4, 5])
        # Deduplication preserving order
        self.assertEqual(parse_target_selection("3, 1-4, 2", 10), [3, 1, 2, 4])
        # Invalid and empty inputs
        self.assertEqual(parse_target_selection("", 10), [])
        self.assertEqual(parse_target_selection("abc", 10), [])
        self.assertEqual(parse_target_selection("0, -1, 99", 5), [])

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_targets_only_selected_single(self, mock_input):
        mock_input.return_value = "(1)"
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "signal": f"{100-i}", "chan": "1"}
            for i in range(1, 16)
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["bssid"], "00:11:22:33:44:01")

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_targets_list(self, mock_input):
        mock_input.return_value = "(1,2,7)"
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "signal": f"{100-i}", "chan": "1"}
            for i in range(1, 16)
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        self.assertEqual(len(result), 3)
        self.assertEqual([b["bssid"] for b in result], [
            "00:11:22:33:44:01",
            "00:11:22:33:44:02",
            "00:11:22:33:44:07"
        ])

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_targets_range(self, mock_input):
        mock_input.return_value = "(1-10,12)"
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "signal": f"{100-i}", "chan": "1"}
            for i in range(1, 16)
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        expected_indices = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12]
        self.assertEqual(len(result), 11)
        self.assertEqual(
            [b["bssid"] for b in result],
            [f"00:11:22:33:44:{i:02d}" for i in expected_indices]
        )

    def test_display_and_select_bssid_direct_string_param(self):
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "signal": f"{100-i}", "chan": "1"}
            for i in range(1, 16)
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested="1,2,7")
        self.assertEqual(len(result), 3)
        self.assertEqual([b["bssid"] for b in result], [
            "00:11:22:33:44:01",
            "00:11:22:33:44:02",
            "00:11:22:33:44:07"
        ])

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    def test_display_and_select_bssid_default_empty_input(self, mock_input):
        mock_input.return_value = ""  # User presses Enter
        bssids = [
            {"bssid": f"00:11:22:33:44:{i:02d}", "signal": f"{100-i}", "chan": "1"}
            for i in range(1, 5)
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        self.assertEqual(len(result), 4)

    @patch("cafe_chameleon.modes.aggressive.selector.log_main")
    def test_display_and_select_bssid_no_table_logged_when_select_requested_false(self, mock_log_main):
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "90", "chan": "1", "security": "WPA2"}
        ]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested=False)
        logged_texts = [call.args[0] for call in mock_log_main.call_args_list if call.args]
        # Should NOT print AUTO-RANKED BSSID TARGETS
        self.assertFalse(any("AUTO-RANKED BSSID TARGETS" in text for text in logged_texts))

    @patch("cafe_chameleon.modes.aggressive.selector.log_main")
    def test_display_and_select_bssid_no_auto_ranked_when_select_requested_direct(self, mock_log_main):
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "90", "chan": "1", "security": "WPA2"}
        ]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested="1")
        logged_texts = [call.args[0] for call in mock_log_main.call_args_list if call.args]
        # Should NOT print AUTO-RANKED BSSID TARGETS
        self.assertFalse(any("AUTO-RANKED BSSID TARGETS" in text for text in logged_texts))

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    @patch("cafe_chameleon.modes.aggressive.selector.log_main")
    def test_display_and_select_bssid_no_auto_ranked_when_select_requested_interactive(self, mock_log_main, mock_input):
        mock_input.return_value = "1"
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "90", "chan": "1", "security": "WPA2"}
        ]
        display_and_select_bssid(bssids, air_clients_map={}, select_requested=True)
        logged_texts = [call.args[0] for call in mock_log_main.call_args_list if call.args]
        # Should NOT print AUTO-RANKED BSSID TARGETS
        self.assertFalse(any("AUTO-RANKED BSSID TARGETS" in text for text in logged_texts))
        # Should print BSSID SELECTION LIST
        self.assertTrue(any("BSSID SELECTION LIST" in text for text in logged_texts))

    @patch("cafe_chameleon.modes.aggressive.selector.get_user_input")
    @patch("cafe_chameleon.modes.aggressive.selector.log_main")
    def test_display_and_select_bssid_table_contains_required_columns(self, mock_log_main, mock_input):
        mock_input.return_value = "1"
        bssids = [
            {"bssid": "00:11:22:33:44:01", "signal": "90", "chan": "1"},
            {"bssid": "00:11:22:33:44:02", "signal": "60", "chan": "6"}
        ]
        air_clients_map = {
            "00:11:22:33:44:01": {"aa:bb:cc:dd:ee:01": "10.0.0.5"}
        }
        display_and_select_bssid(bssids, air_clients_map=air_clients_map, select_requested=True)
        logged_texts = [call.args[0] for call in mock_log_main.call_args_list if call.args]
        combined = "\n".join(logged_texts)

        self.assertIn("BSSID", combined)
        self.assertIn("CLIENTS", combined)
        self.assertIn("ACTIVE", combined)
        self.assertIn("SIGNAL", combined)
        self.assertIn("00:11:22:33:44:01", combined)
        self.assertIn("00:11:22:33:44:02", combined)
        self.assertIn("90%", combined)
        self.assertIn("60%", combined)
        self.assertNotIn("POWER", combined)

    def test_display_and_select_bssid_orders_by_strongest_signal(self):
        bssids = [
            {"bssid": "00:11:22:33:44:02", "signal": "30"},
            {"bssid": "00:11:22:33:44:01", "signal": "95"},
            {"bssid": "00:11:22:33:44:03", "signal": "70"},
        ]
        result = display_and_select_bssid(bssids, air_clients_map={}, select_requested=False)
        self.assertEqual(result[0]["bssid"], "00:11:22:33:44:01")  # 95%
        self.assertEqual(result[1]["bssid"], "00:11:22:33:44:03")  # 70%
        self.assertEqual(result[2]["bssid"], "00:11:22:33:44:02")  # 30%


if __name__ == "__main__":
    unittest.main()
