"""
cafe_chameleon.scanners.air.hopper - Threaded 802.11 channel hopping worker with stimulation callbacks.
"""

import threading
import time
from typing import Callable

from cafe_chameleon.utils.process import _run


class ChannelHopper:
    """Manages background channel hopping loop over 802.11 monitor interface."""
    def __init__(
        self,
        interface: str,
        channels: list[int],
        dwell_times: dict[int, float] | None = None,
        default_dwell: float = 0.20,
        on_channel_change: Callable[[int], None] | None = None
    ):
        self.interface = interface
        self.channels = channels
        self.dwell_times = dwell_times or {}
        self.default_dwell = default_dwell
        self.on_channel_change = on_channel_change
        self.stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.current_channel: int | None = None
        self._boost_until: float = 0.0

    def boost_channel_dwell(self, channel: int, duration: float = 1.5) -> None:
        """Dynamically extends dwell time on `channel` if it matches current channel."""
        with self._lock:
            if self.current_channel is None or self.current_channel == channel:
                target_end = time.time() + duration
                if target_end > self._boost_until:
                    self._boost_until = target_end

    def boost_current_dwell(self, duration: float = 1.5) -> None:
        """Dynamically extends dwell time on whichever channel is currently active."""
        with self._lock:
            target_end = time.time() + duration
            if target_end > self._boost_until:
                self._boost_until = target_end

    def start(self) -> None:
        if not self.channels:
            return
        if len(self.channels) == 1:
            ch = self.channels[0]
            self.current_channel = ch
            _run(["iw", "dev", self.interface, "set", "channel", str(ch)], debug=False)
            if self.on_channel_change:
                try:
                    self.on_channel_change(ch)
                except Exception:
                    pass
            return

        def channel_hopper_loop():
            idx = 0
            while not self.stop_event.is_set():
                ch = self.channels[idx % len(self.channels)]
                with self._lock:
                    self.current_channel = ch

                _run(["iw", "dev", self.interface, "set", "channel", str(ch)], debug=False)
                if self.on_channel_change:
                    try:
                        self.on_channel_change(ch)
                    except Exception:
                        pass

                dwell = self.dwell_times.get(ch, self.default_dwell) if self.dwell_times else self.default_dwell
                step = 0.10
                elapsed = 0.0

                while elapsed < dwell and not self.stop_event.is_set():
                    self.stop_event.wait(step)
                    elapsed += step

                # Check for active channel boost extension
                while not self.stop_event.is_set():
                    with self._lock:
                        now = time.time()
                        if now >= self._boost_until:
                            break
                        rem = min(step, self._boost_until - now)
                    self.stop_event.wait(rem)

                idx += 1

        self._thread = threading.Thread(target=channel_hopper_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)


