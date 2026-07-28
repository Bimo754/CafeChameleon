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


def start_background_garp(interface: str, local_ip: str, gateway_ip: str) -> threading.Event:
    """
    Starts a continuous background Gratuitous ARP storm thread.
    Returns a threading.Event object to stop the thread when set.
    """
    stop_event = threading.Event()

    def garp_loop():
        while not stop_event.is_set():
            send_gratuitous_arp(interface, local_ip, gateway_ip)
            time.sleep(0.4)

    t = threading.Thread(target=garp_loop, daemon=True)
    t.start()
    return stop_event
