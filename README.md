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
[![Security](https://img.shields.io/badge/audit-Layer%202-orange.svg)](#notice)

CafeChameleon is an advanced Linux network security testing framework designed to evaluate and audit Layer 2 authentication boundaries in captive portal wireless environments. It automates multi-BSSID discovery, over-the-air station telemetry, adaptive channel hopping, MAC/IP session impersonation, and connection state management within a multi-window terminal UI.

---

## NOTICE

CafeChameleon is developed for authorized security auditing, defensive research, and network infrastructure testing. Users are responsible for adhering to applicable local and international cybersecurity laws and obtaining explicit authorization prior to auditing target networks.

---

## CORE ARCHITECTURE

* **Automated Subnet & Session Hijacking**: Discovers active subnet hosts, maps IP/MAC tuples, and performs rapid Layer 2 session takeover.
* **Aggressive Multi-BSSID Roaming**: Dynamic signal-weighted channel hopping, BSSID density evaluation, and active station targeting across complex enterprise AP deployments.
* **Over-the-Air Telemetry Engine**: Integrated 802.11 monitor mode capture extracting active station associations, RSSI metrics, and probe requests.
* **Wi-Fi Hardware & Profile Controller**: Live BSSID locking, MAC randomization, hardware state recovery, and auto-roam algorithms.
* **Multi-Window Terminal Interface**: Centered multi-window terminal grid separating telemetry, subnet scanning, and hijacking threads via asynchronous non-blocking FIFOs.
* **Shielded Teardown System**: Signal-shielded cleanup routines ensuring complete restoration of network interfaces, routing tables, and NetworkManager profiles.

---

## QUICK START

### Installation

Run the automated setup script to install system dependencies (`nmap`, `iw`, `network-manager`, `xterm`, `aircrack-ng`, `macchanger`), Python package requirements (`scapy`), and global CLI binaries (`cafechameleon`, `cafe-chameleon`):

```bash
git clone https://github.com/Bimo754/CafeChameleon.git
cd CafeChameleon

# Execute automated setup
sudo ./setup/setup.sh
```

### Setup Directory Overview

All installation, setup, and dependency configuration files are centralized inside the `setup/` directory:

* `setup/setup.sh`: Automated Linux package manager and dependency installer.
* `setup/setup.py`: Python setuptools package setup configuration.
* `setup/requirements.txt`: Core Python package requirements (`scapy>=2.5.0`).
* `setup/requirements-dev.txt`: Development dependencies for test suites (`pytest>=7.0.0`).
* `setup/pytest.ini`: Pytest configuration file.



### Basic Usage

```bash
# Simple subnet host discovery & session audit
sudo cafechameleon simple

# Aggressive multi-BSSID audit with live air telemetry
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

For comprehensive CLI arguments, operational workflows, and advanced flags, refer to the [USAGE Guide](USAGE.md).

---

## DEFENSIVE MITIGATIONS

* Deploy **802.1X / WPA3-Enterprise** to enforce cryptographic authentication prior to network access.
* Enable **Layer 2 Client Isolation** to restrict direct station-to-station frame delivery.
* Implement **Dynamic ARP Inspection (DAI)** and **DHCP Snooping** to defend against unauthorized MAC/IP bindings.
* Enforce **802.11w Protected Management Frames (PMF)** to eliminate forged deauthentication frames.

---

## LICENSE

Distributed under the terms of the [MIT License](LICENSE).
