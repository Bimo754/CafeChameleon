# CafeChameleon

<p align="center">
  <img src="gif/chameleon_animation.gif" alt="CafeChameleon ASCII Animation" width="100%">
</p>

<p align="center">
  <b>Layer 2 Captive Portal Security Auditing Framework</b>
</p>

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Security](https://img.shields.io/badge/audit-Layer%202-orange.svg)](#overview)

---

## Overview

Public Wi-Fi captive portals frequently enforce internet access control by storing authorized device hardware (MAC) addresses after portal authentication. Because unencrypted 802.11 frame headers expose client MAC addresses in plaintext over the air, relying strictly on MAC filtering creates an unauthenticated Layer 2 security boundary.

CafeChameleon is a Linux network testing framework designed to evaluate captive portal security. It automates client station discovery, over-the-air frame telemetry, channel hopping, and MAC/IP session validation to establish internet access across captive portals without submitting login forms or personal credentials.

---

## How It Works

CafeChameleon operates across two primary discovery mechanisms depending on network environment controls:

- **Subnet Host Discovery (Simple Mode)**: When subnet firewalls and AP client isolation rules are permissive, CafeChameleon sweeps the local CIDR block using ARP and ICMP probes in standard station mode. This discovers active authenticated devices and maps IP/MAC session tuples directly, without requiring monitor mode or over-the-air frame capture.
- **Over-the-Air Telemetry (Aggressive Mode `--air`)**: In environments with strict subnet isolation, CafeChameleon switches the wireless interface into 802.11 monitor mode to passively capture radio frames, extracting active station BSSID associations and RSSI metrics directly from transmission airwaves.

### Execution Workflow

1. **Discovery & Telemetry**: Maps active client IP/MAC session tuples via local subnet sweeps or over-the-air 802.11 monitor mode.
2. **Station & AP Selection**: Ranks discovered targets based on signal strength (RSSI), active traffic, and Access Point density.
3. **Session Takeover & Access**: Updates interface MAC and IP configurations to adopt an authenticated client's session, bypassing captive portal login screens to grant full internet connectivity.
4. **Shielded Restoration**: Executes teardown routines upon exit to restore original hardware MAC addresses, NetworkManager profiles, and system routing tables.

---

## Quick Start

### System Prerequisites

The setup script automatically manages system dependencies (`nmap`, `iw`, `network-manager`, `xterm`, `aircrack-ng`, `macchanger`) and Python requirements (`scapy`).

### Installation

```bash
git clone https://github.com/Bimo754/CafeChameleon.git
cd CafeChameleon

# Execute automated setup
sudo ./setup/setup.sh
```

### Basic Usage

```bash
# Simple subnet host discovery & session audit (no monitor mode required)
sudo cafechameleon simple

# Aggressive multi-BSSID audit with live over-the-air telemetry
sudo cafechameleon aggressive --air

# Inspect Wi-Fi interface status and BSSID lock
sudo cafechameleon wifi --status

# Lock interface to a specific Access Point BSSID
sudo cafechameleon wifi --lock 08:FA:28:56:27:80

# Manage blacklisted MAC addresses
cafechameleon blacklist list

# Play Chameleon ASCII completion animation
sudo cafechameleon animation r
```

For detailed CLI subcommands, options reference, and hardware recovery commands, see [USAGE.md](USAGE.md).

---

## Defensive Mitigations

Because 802.11 MAC addresses can be changed by clients and are visible over the air, MAC filtering cannot serve as a secure access boundary. Network operators should implement standard network defense controls:

- **Layer 7 Session Validation**: Authenticate network access using encrypted browser tokens, TLS session cookies, or client VPN tunnels instead of Layer 2 MAC addresses.
- **Dynamic ARP Inspection (DAI) & DHCP Snooping**: Build dynamic switch state tables that validate physical port/MAC/IP bindings to block forged ARP responses.
- **Duplicate MAC & Anomaly Detection**: Deploy Wireless Intrusion Detection Systems (WIDS) to alert when a single MAC address appears across multiple Access Points or sends conflicting frames.
- **Short Session Timeouts**: Expire cached MAC authorization state when devices go idle to reduce session window availability.
- **Passpoint / Hotspot 2.0 (802.11u)**: Deploy automated per-station WPA2/WPA3-Enterprise encryption for guest networks without relying on unencrypted portal redirects.


---

## License

Distributed under the terms of the [MIT License](LICENSE).
