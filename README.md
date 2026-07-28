# CafeChameleon

Captive portal session hijacker and network impersonation toolkit.

## Features

- **`simple`**: Layer 2 ARP network enumeration and user device impersonation.
- **`aggressive`**: Sequential multi-BSSID exploration, signal ranking, 802.11 monitor mode over-the-air client discovery and deauthentication, and automatic internet restoration.
- **`wifi`**: Wi-Fi BSSID lock, auto-roaming management, and connection status display via NetworkManager (`nmcli`).

## Modular Package Architecture

```
cafe_chameleon/
├── cli/              # Command line interface parsers and handlers
├── ui/               # ANSI color palette, console logger facade, xterm/tmux multi-window manager
├── network/          # Linux sysfs carrier polling, MAC spoofing, gratuitous ARP, DHCP, internet verification, nmcli
├── scanners/         # Network auto-detection, MAC-to-IP resolution, ARP, passive, Nmap, and 802.11 monitor sniffer
├── aggressive/       # Multi-BSSID auto-selection ranker and exploration engine
└── utils/            # Application state flags, process execution, and signal handlers
```

## Usage Examples

```bash
# Run simple ARP scan on detected network
python3 main.py simple

# Run aggressive multi-BSSID exploration with 802.11 monitor mode sniffing
python3 main.py aggressive --air

# Manage Wi-Fi BSSID locking
python3 main.py wifi --status
python3 main.py wifi --lock 08:FA:28:56:27:80
python3 main.py wifi --auto
```
