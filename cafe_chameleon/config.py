"""
cafe_chameleon.config - Central application constants, timeout budgets, and defaults.
"""

FIFO_DIR: str = "/tmp/captive_xterm_fifos"
EVENT_FILE: str = "/tmp/captive_xterm_fifos/last_ctrl_c.event"
TRACE_FILE: str = "cafe_chameleon_trace.log"
BLACKLIST_FILE: str = "blacklist.txt"

DEFAULT_BSSID_THRESHOLD: int = 10
DEFAULT_AIR_DURATION: int = 45
DEFAULT_CARRIER_TIMEOUT: float = 6.0
DEFAULT_SPEED_MIN_KBPS: float = 5.0

PUBLIC_DNS_ENDPOINTS: list[tuple[str, int]] = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
    ("9.9.9.9", 53),
    ("1.1.1.1", 443)
]

SPEED_TEST_TARGETS: list[str] = [
    "http://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
    "http://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
    "http://www.gstatic.com/webp/gallery/1.sm.webp",
    "http://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"
]

HTTP_HEADERS: dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
