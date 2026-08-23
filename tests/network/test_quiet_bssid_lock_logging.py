"""
tests/network/test_quiet_bssid_lock_logging.py - Unit tests for BSSID locking notifications in main controller window when --any-bssid is not supplied and -v is not supplied.
"""

import unittest
from unittest.mock import patch, call

from cafe_chameleon.utils.state import set_verbose, set_launcher_mode, set_quiet
from cafe_chameleon.network.nmcli.bssid import lock_bssid


class TestQuietBSSIDLockLogging(unittest.TestCase):
    def setUp(self):
        set_verbose(False)
        set_quiet(False)
        set_launcher_mode(True)

    def tearDown(self):
        set_verbose(False)
        set_quiet(False)
        set_launcher_mode(False)

    @patch("cafe_chameleon.network.nmcli.bssid._run", return_value=(0, ""))
    @patch("cafe_chameleon.network.nmcli.bssid.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.network.nmcli.bssid.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.network.nmcli.bssid.get_connected_bssid", return_value="11:22:33:44:55:66")
    @patch("cafe_chameleon.network.nmcli.bssid.log_main")
    def test_lock_success_attempt_1_prints_only_locking_message(
        self,
        mock_log_main,
        mock_get_conn_bssid,
        mock_get_ssid,
        mock_get_profile,
        mock_run
    ):
        """When --any-bssid is NOT supplied and -v is NOT supplied, successful lock prints ONLY locking message."""
        result = lock_bssid("11:22:33:44:55:66", "Cafe_WiFi", max_retries=3, any_bssid=False)
        self.assertTrue(result)

        # Should only call log_main once for the locking notification
        self.assertEqual(mock_log_main.call_count, 1)
        logged_msg = mock_log_main.call_args[0][0]
        self.assertIn("11:22:33:44:55:66", logged_msg)
        self.assertNotIn("Lock failed", logged_msg)
        self.assertNotIn("SUCCESS", logged_msg)

    @patch("cafe_chameleon.network.nmcli.bssid._run", return_value=(0, ""))
    @patch("cafe_chameleon.network.nmcli.bssid.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.network.nmcli.bssid.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.network.nmcli.bssid.get_connected_bssid")
    @patch("cafe_chameleon.network.nmcli.bssid.log_main")
    def test_lock_retry_reprints_locking_message(
        self,
        mock_log_main,
        mock_get_conn_bssid,
        mock_get_ssid,
        mock_get_profile,
        mock_run
    ):
        """When an attempt fails, the locking message is re-printed on retry, and success outputs nothing more."""
        # Attempt 1 fails (wrong BSSID), Attempt 2 succeeds
        mock_get_conn_bssid.side_effect = [
            "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF",
            "11:22:33:44:55:66"
        ]

        result = lock_bssid("11:22:33:44:55:66", "Cafe_WiFi", max_retries=3, any_bssid=False)
        self.assertTrue(result)

        # Locking message should be logged twice (attempt 1 + attempt 2 retry)
        self.assertEqual(mock_log_main.call_count, 2)
        msg1 = mock_log_main.call_args_list[0][0][0]
        msg2 = mock_log_main.call_args_list[1][0][0]
        self.assertEqual(msg1, msg2)
        self.assertIn("11:22:33:44:55:66", msg1)

    @patch("cafe_chameleon.network.nmcli.bssid._run", return_value=(0, ""))
    @patch("cafe_chameleon.network.nmcli.bssid.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.network.nmcli.bssid.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.network.nmcli.bssid.get_connected_bssid", return_value="00:00:00:00:00:00")
    @patch("cafe_chameleon.network.nmcli.bssid.log_main")
    def test_lock_exhausted_prints_attempts_plus_fail_message(
        self,
        mock_log_main,
        mock_get_conn_bssid,
        mock_get_ssid,
        mock_get_profile,
        mock_run
    ):
        """When all attempts are exhausted, re-prints locking message for each attempt and finishes with fail message."""
        result = lock_bssid("11:22:33:44:55:66", "Cafe_WiFi", max_retries=3, any_bssid=False)
        self.assertFalse(result)

        # 3 attempt messages + 1 fail message = 4 total calls to log_main
        self.assertEqual(mock_log_main.call_count, 4)

        messages = [c[0][0] for c in mock_log_main.call_args_list]
        locking_messages = messages[:3]
        fail_message = messages[3]

        self.assertEqual(locking_messages[0], locking_messages[1])
        self.assertEqual(locking_messages[1], locking_messages[2])
        self.assertIn("11:22:33:44:55:66", locking_messages[0])

        self.assertIn("Lock failed: 11:22:33:44:55:66", fail_message)

    @patch("cafe_chameleon.network.nmcli.bssid._run", return_value=(0, ""))
    @patch("cafe_chameleon.network.nmcli.bssid.get_active_profile", return_value="Cafe_WiFi")
    @patch("cafe_chameleon.network.nmcli.bssid.get_ssid_for_profile", return_value="Cafe_SSID")
    @patch("cafe_chameleon.network.nmcli.bssid.get_connected_bssid", return_value="11:22:33:44:55:66")
    @patch("cafe_chameleon.network.nmcli.bssid.log_main")
    def test_any_bssid_enabled_logs_locking_message_in_quiet_launcher(
        self,
        mock_log_main,
        mock_get_conn_bssid,
        mock_get_ssid,
        mock_get_profile,
        mock_run
    ):
        """When any_bssid is True, quiet launcher still logs BSSID lock message to log_main."""
        result = lock_bssid("11:22:33:44:55:66", "Cafe_WiFi", max_retries=3, any_bssid=True)
        self.assertTrue(result)
        self.assertEqual(mock_log_main.call_count, 1)
        logged_msg = mock_log_main.call_args[0][0]
        self.assertIn("11:22:33:44:55:66", logged_msg)


if __name__ == "__main__":
    unittest.main()
