import threading
import time

from cafe_chameleon.utils.process import _run


def send_gratuitous_arp(interface: str, local_ip: str, target_ip: str) -> None:
    """
    Sends Gratuitous ARP Unsolicited (ARP Request -U) and Gratuitous ARP Answer (ARP Reply -A)
    packets to rapidly update neighbor switches and gateway ARP tables.
    """
    if not local_ip or not target_ip:
        return

    # Gratuitous ARP Request (-U)
    _run(f"arping -c 2 -U -I {interface} -S {local_ip} {target_ip}", debug=False)
    # Gratuitous ARP Reply (-A)
    _run(f"arping -c 2 -A -I {interface} -S {local_ip} {target_ip}", debug=False)


def start_background_garp(interface: str, local_ip: str, gateway_ip: str, interval: float = 1.5) -> threading.Event:
    """
    Starts a continuous background Gratuitous ARP heartbeat thread.
    Returns a threading.Event object to stop the thread when set.
    """
    stop_event = threading.Event()

    def garp_loop():
        while not stop_event.is_set():
            send_gratuitous_arp(interface, local_ip, gateway_ip)
            # Sleep in small increments for fast responsiveness on stop_event
            elapsed = 0.0
            step = 0.1
            while elapsed < interval and not stop_event.is_set():
                time.sleep(step)
                elapsed += step

    t = threading.Thread(target=garp_loop, daemon=True)
    t.start()
    return stop_event


def pin_gateway_neighbor(gateway_ip: str, gateway_mac: str | None, interface: str) -> bool:
    """
    Pins the gateway IP and MAC address in the Linux kernel ARP/neighbor table
    as PERMANENT (nud permanent) to prevent local ARP poisoning from competing clients.
    """
    if not gateway_ip or not gateway_mac or not interface:
        return False
    from cafe_chameleon.network.mac import is_valid_mac
    if not is_valid_mac(gateway_mac) or gateway_mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False

    rc, _ = _run(
        ["ip", "neigh", "replace", gateway_ip, "lladdr", gateway_mac.lower(), "dev", interface, "nud", "permanent"],
        debug=False
    )
    return rc == 0

