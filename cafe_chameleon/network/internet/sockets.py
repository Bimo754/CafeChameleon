import concurrent.futures
import socket
import struct


def _probe_socket(endpoint: tuple[str, int], timeout: float = 1.0) -> bool:
    """Low-level socket connection probe across a single (ip, port) tuple."""
    try:
        with socket.create_connection(endpoint, timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def _probe_dns_resolution(domain: str, timeout: float = 1.5) -> bool:
    """
    Standard OS DNS resolution probe using socket.getaddrinfo.
    Returns True if domain resolves to at least one valid IP address.
    Thread-safe without process-wide socket state mutation.
    """
    def _resolve():
        try:
            res = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            return bool(res and len(res) > 0)
        except (socket.gaierror, socket.error, OSError):
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_resolve)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return False


def _probe_udp_dns(server_ip: str, domain: str = "google.com", timeout: float = 1.0) -> bool:
    """
    Direct Layer 4 UDP DNS query to a nameserver (port 53).
    Bypasses OS resolver and TCP restrictions, verifying raw UDP outbound/inbound internet access.
    """
    if not server_ip:
        return False

    try:
        # Build DNS query packet: 12-byte header + question
        tx_id = 0xAB12
        flags = 0x0100  # Standard query, recursion desired
        qdcount = 1
        header = struct.pack(">HHHHHH", tx_id, flags, qdcount, 0, 0, 0)

        # Encode domain name (e.g. google.com -> \x06google\x03com\x00)
        qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.strip(".").split(".")) + b"\x00"
        qtype = 1   # A record
        qclass = 1  # IN class
        question = qname + struct.pack(">HH", qtype, qclass)
        packet = header + question

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server_ip, 53))
            data, _ = s.recvfrom(512)
            if len(data) >= 12:
                resp_id, resp_flags = struct.unpack(">HH", data[:4])
                # Check that response ID matches and QR bit (0x8000) is set
                if resp_id == tx_id and (resp_flags & 0x8000) != 0:
                    return True
    except (socket.error, TimeoutError, OSError):
        return False

    return False
