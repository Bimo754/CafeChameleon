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
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("9.9.9.9", 443),
    ("1.1.1.1", 80),
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
    ("9.9.9.9", 53),
]

DNS_TEST_DOMAINS: list[str] = [
    "connectivitycheck.gstatic.com",
    "captive.apple.com",
    "one.one.one.one",
    "dns.google",
    "www.cloudflare.com",
    "www.msftconnecttest.com"
]

CAPTIVE_PORTAL_ENDPOINTS: list[dict[str, str | int]] = [
    {
        "provider": "Google 204",
        "url": "http://connectivitycheck.gstatic.com/generate_204",
        "type": "status_204"
    },
    {
        "provider": "Google Gen 204",
        "url": "http://www.google.com/gen_204",
        "type": "status_204"
    },
    {
        "provider": "Cloudflare 204",
        "url": "http://cp.cloudflare.com/generate_204",
        "type": "status_204"
    },
    {
        "provider": "Apple Hotspot Detect",
        "url": "http://captive.apple.com/hotspot-detect.html",
        "type": "body_match",
        "token": "Success"
    },
    {
        "provider": "Microsoft Connect Test",
        "url": "http://www.msftconnecttest.com/connecttest.txt",
        "type": "body_match",
        "token": "Microsoft Connect Test"
    },
    {
        "provider": "Microsoft NCSI",
        "url": "http://www.msftncsi.com/ncsi.txt",
        "type": "body_match",
        "token": "Microsoft NCSI"
    },
    {
        "provider": "Mozilla Detect Portal",
        "url": "http://detectportal.firefox.com/success.txt",
        "type": "body_match",
        "token": "success"
    },
    {
        "provider": "Ubuntu NM Online",
        "url": "http://connectivity-check.ubuntu.com/",
        "type": "body_match",
        "token": "NetworkManager is online"
    }
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

