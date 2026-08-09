import unittest
from unittest.mock import patch, MagicMock
import ipaddress

from cafe_chameleon.scanners.resolver.kernel_cache import is_valid_ipv4, check_kernel_cache
from cafe_chameleon.scanners.air.packet_parser import parse_air_packet
from cafe_chameleon.scanners.resolver.listener import listen_passive_traffic
from cafe_chameleon.scanners.passive_scanner import passive_sniff_subnet
from cafe_chameleon.modes.aggressive.air_target_handler import test_air_client_targets as run_test_air_client_targets


class TestIPFiltering(unittest.TestCase):

    def test_is_valid_ipv4_private_ips(self):
        # RFC 1918 & CGNAT private IP ranges should be valid local IPs
        self.assertTrue(is_valid_ipv4("10.55.12.162"))
        self.assertTrue(is_valid_ipv4("10.0.0.1"))
        self.assertTrue(is_valid_ipv4("192.168.1.100"))
        self.assertTrue(is_valid_ipv4("172.16.0.50"))
        self.assertTrue(is_valid_ipv4("172.31.255.1"))
        self.assertTrue(is_valid_ipv4("100.64.0.10"))  # CGNAT
        self.assertTrue(is_valid_ipv4(" 192.168.0.1 "))

    def test_is_valid_ipv4_rejects_public_internet_ips(self):
        # Public internet IPs (Google, Facebook, Cloudflare, AWS, etc.) must be rejected
        self.assertFalse(is_valid_ipv4("162.159.192.7"))      # Cloudflare
        self.assertFalse(is_valid_ipv4("142.250.180.206"))    # Google
        self.assertFalse(is_valid_ipv4("157.240.22.35"))      # Facebook
        self.assertFalse(is_valid_ipv4("8.8.8.8"))            # Google DNS
        self.assertFalse(is_valid_ipv4("8.8.4.4"))
        self.assertFalse(is_valid_ipv4("1.1.1.1"))            # Cloudflare DNS
        self.assertFalse(is_valid_ipv4("93.184.216.34"))      # example.com
        self.assertFalse(is_valid_ipv4("204.79.197.200"))     # Microsoft

    def test_is_valid_ipv4_rejects_special_addresses(self):
        # Multicast, loopback, link-local, broadcast, unspecified, etc.
        self.assertFalse(is_valid_ipv4("0.0.0.0"))
        self.assertFalse(is_valid_ipv4("255.255.255.255"))
        self.assertFalse(is_valid_ipv4("127.0.0.1"))          # Loopback
        self.assertFalse(is_valid_ipv4("169.254.1.1"))        # Link-local APIPA
        self.assertFalse(is_valid_ipv4("224.0.0.1"))          # Multicast
        self.assertFalse(is_valid_ipv4("239.255.255.250"))    # SSDP Multicast
        self.assertFalse(is_valid_ipv4("240.0.0.1"))          # Reserved
        self.assertFalse(is_valid_ipv4("::1"))                # IPv6 loopback
        self.assertFalse(is_valid_ipv4("fe80::1"))            # IPv6 link-local
        self.assertFalse(is_valid_ipv4(""))
        self.assertFalse(is_valid_ipv4(None))
        self.assertFalse(is_valid_ipv4("invalid_ip"))

    def test_is_valid_ipv4_with_subnet_cidr(self):
        subnet = "10.55.12.0/22"
        self.assertTrue(is_valid_ipv4("10.55.12.162", subnet_cidr=subnet))
        self.assertTrue(is_valid_ipv4("10.55.15.250", subnet_cidr=subnet))
        self.assertFalse(is_valid_ipv4("10.55.20.1", subnet_cidr=subnet))
        self.assertFalse(is_valid_ipv4("192.168.1.1", subnet_cidr=subnet))
        self.assertFalse(is_valid_ipv4("162.159.192.7", subnet_cidr=subnet))

    def test_parse_air_packet_from_ds_extracts_dst_local_ip(self):
        # Simulate an 802.11 Data frame from AP (BSSID) to Client:
        # from_ds=1, to_ds=0:
        # addr1 = client MAC, addr2 = AP BSSID
        # IP.src = public internet server (162.159.192.7), IP.dst = local client (10.55.12.162)
        mock_pkt = MagicMock()
        mock_dot11 = MagicMock()
        mock_dot11.addr1 = "CC:3F:36:46:26:6C"
        mock_dot11.addr2 = "BC:99:30:C6:CE:E0"
        mock_dot11.addr3 = "00:00:0C:9F:F1:5C"
        mock_dot11.FCfield = 2  # from_ds = True, to_ds = False
        mock_dot11.type = 2
        mock_dot11.payload = None

        mock_ip = MagicMock()
        mock_ip.src = "162.159.192.7"      # Remote public server
        mock_ip.dst = "10.55.12.162"       # Local client IP

        def haslayer_side_effect(layer):
            from scapy.all import Dot11, IP, ARP, BOOTP, DHCP
            if layer == Dot11:
                return True
            if layer == IP:
                return True
            return False

        mock_pkt.haslayer.side_effect = haslayer_side_effect
        mock_pkt.__getitem__.side_effect = lambda layer: mock_dot11 if layer.__name__ == "Dot11" else mock_ip

        bssid_to_clients = {"bc:99:30:c6:ce:e0": {}}
        target_bssids = {"bc:99:30:c6:ce:e0"}
        ignore_macs = {"bc:99:30:c6:ce:e0"}

        parse_air_packet(mock_pkt, target_bssids, ignore_macs, bssid_to_clients)

        client_mac = "cc:3f:36:46:26:6c"
        self.assertIn(client_mac, bssid_to_clients["bc:99:30:c6:ce:e0"])
        # Should be local IP 10.55.12.162, NOT 162.159.192.7!
        self.assertEqual(bssid_to_clients["bc:99:30:c6:ce:e0"][client_mac], "10.55.12.162")

    def test_parse_air_packet_to_ds_extracts_src_local_ip(self):
        # Simulate an 802.11 Data frame from Client to AP:
        # to_ds=1, from_ds=0:
        # addr1 = AP BSSID, addr2 = Client MAC
        # IP.src = local client (10.55.12.162), IP.dst = public server (142.250.180.206 Google)
        mock_pkt = MagicMock()
        mock_dot11 = MagicMock()
        mock_dot11.addr1 = "BC:99:30:C6:CE:E0"
        mock_dot11.addr2 = "CC:3F:36:46:26:6C"
        mock_dot11.addr3 = "00:00:0C:9F:F1:5C"
        mock_dot11.FCfield = 1  # to_ds = True, from_ds = False
        mock_dot11.type = 2
        mock_dot11.payload = None

        mock_ip = MagicMock()
        mock_ip.src = "10.55.12.162"       # Local client IP
        mock_ip.dst = "142.250.180.206"    # Remote Google public IP

        def haslayer_side_effect(layer):
            from scapy.all import Dot11, IP
            if layer == Dot11 or layer == IP:
                return True
            return False

        mock_pkt.haslayer.side_effect = haslayer_side_effect
        mock_pkt.__getitem__.side_effect = lambda layer: mock_dot11 if layer.__name__ == "Dot11" else mock_ip

        bssid_to_clients = {"bc:99:30:c6:ce:e0": {}}
        target_bssids = {"bc:99:30:c6:ce:e0"}
        ignore_macs = {"bc:99:30:c6:ce:e0"}

        parse_air_packet(mock_pkt, target_bssids, ignore_macs, bssid_to_clients)

        client_mac = "cc:3f:36:46:26:6c"
        self.assertIn(client_mac, bssid_to_clients["bc:99:30:c6:ce:e0"])
        self.assertEqual(bssid_to_clients["bc:99:30:c6:ce:e0"][client_mac], "10.55.12.162")

    def test_parse_air_packet_ignores_all_public_ips(self):
        # Both src and dst are public IPs
        mock_pkt = MagicMock()
        mock_dot11 = MagicMock()
        mock_dot11.addr1 = "CC:3F:36:46:26:6C"
        mock_dot11.addr2 = "BC:99:30:C6:CE:E0"
        mock_dot11.addr3 = "00:00:0C:9F:F1:5C"
        mock_dot11.FCfield = 2
        mock_dot11.type = 2
        mock_dot11.payload = None

        mock_ip = MagicMock()
        mock_ip.src = "162.159.192.7"      # Public Cloudflare
        mock_ip.dst = "8.8.8.8"            # Public Google DNS

        def haslayer_side_effect(layer):
            from scapy.all import Dot11, IP
            return layer in (Dot11, IP)

        mock_pkt.haslayer.side_effect = haslayer_side_effect
        mock_pkt.__getitem__.side_effect = lambda layer: mock_dot11 if layer.__name__ == "Dot11" else mock_ip

        bssid_to_clients = {"bc:99:30:c6:ce:e0": {}}
        target_bssids = {"bc:99:30:c6:ce:e0"}
        ignore_macs = {"bc:99:30:c6:ce:e0"}

        parse_air_packet(mock_pkt, target_bssids, ignore_macs, bssid_to_clients)

        client_mac = "cc:3f:36:46:26:6c"
        self.assertIn(client_mac, bssid_to_clients["bc:99:30:c6:ce:e0"])
        # IP should be None, NOT any public IP!
        self.assertIsNone(bssid_to_clients["bc:99:30:c6:ce:e0"][client_mac])

    @patch("scapy.all.sniff")
    def test_listen_passive_traffic_extracts_local_and_ignores_public(self, mock_sniff):
        # 1. When receiving packet with dst=local_ip and src=public_ip
        mock_pkt = MagicMock()
        mock_ether = MagicMock()
        mock_ether.src = "00:00:0C:9F:F1:5C"
        mock_ether.dst = "CC:3F:36:46:26:6C"
        mock_ip = MagicMock()
        mock_ip.src = "162.159.192.7"
        mock_ip.dst = "10.55.12.162"

        def haslayer_side_effect(layer):
            from scapy.all import Ether, IP
            return layer in (Ether, IP)

        mock_pkt.haslayer.side_effect = haslayer_side_effect
        mock_pkt.__getitem__.side_effect = lambda layer: mock_ether if layer.__name__ == "Ether" else mock_ip

        def sniff_side_effect(iface, timeout, prn, store):
            prn(mock_pkt)

        mock_sniff.side_effect = sniff_side_effect

        resolved = listen_passive_traffic("cc:3f:36:46:26:6c", "wlan0", timeout=1, target_subnet="10.55.12.0/22")
        self.assertEqual(resolved, "10.55.12.162")

    @patch("cafe_chameleon.modes.aggressive.air_target_handler.hijack")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.resolve_mac_to_ip")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.wait_for_carrier")
    @patch("cafe_chameleon.modes.aggressive.air_target_handler.set_restore_params")
    def test_test_air_client_targets_ignores_public_air_ip(self, mock_restore_params, mock_carrier, mock_resolve, mock_hijack):
        mock_carrier.return_value = True
        mock_resolve.return_value = "10.55.12.162"  # Correctly resolved local IP
        mock_hijack.return_value = True

        new_air_clients = {"cc:3f:36:46:26:6c": "162.159.192.7"}  # Public IP captured by mistake
        tried_macs = set()
        auto_params = {
            "local_ip": "10.55.12.125",
            "gateway_ip": "10.55.12.1",
            "cidr": "10.55.12.125/22",
            "local_mac": "de:56:7b:47:41:dd",
            "broadcast": "10.55.15.255"
        }
        mock_args = MagicMock()
        mock_args.force = False

        success, stop_early = run_test_air_client_targets(
            new_air_clients,
            interface="wlan0",
            target_bssid="bc:99:30:c6:ce:e0",
            chan=56,
            profile="MyWiFi",
            tried_macs=tried_macs,
            auto_params=auto_params,
            args=mock_args
        )

        self.assertTrue(success)
        mock_resolve.assert_called_with("cc:3f:36:46:26:6c", "wlan0", target_subnet="10.55.12.125/22")
        # Hijack must be called with resolved local IP 10.55.12.162, NEVER with 162.159.192.7!
        mock_hijack.assert_called_once()
        called_target_ip = mock_hijack.call_args[0][1]
        self.assertEqual(called_target_ip, "10.55.12.162")


if __name__ == "__main__":
    unittest.main()
