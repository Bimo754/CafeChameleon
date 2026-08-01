"""
cafe_chameleon.scanners.air.hopper - Threaded 802.11 channel hopping worker.
"""

import threading
import time

from cafe_chameleon.utils.process import _run


class ChannelHopper:
    """Manages background channel hopping loop over 802.11 monitor interface."""
    def __init__(self, interface: str, channels: list[int]):
        self.interface = interface
        self.channels = channels
        self.stop_event = threading.Event()
        self._thread = None

    def start(self) -> None:
        def channel_hopper_loop():
            idx = 0
            while not self.stop_event.is_set():
                ch = self.channels[idx % len(self.channels)]
                _run(["iw", "dev", self.interface, "set", "channel", str(ch)], debug=False)
                idx += 1
                time.sleep(0.25)

        self._thread = threading.Thread(target=channel_hopper_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
