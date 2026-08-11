# CafeChameleon

```text
                                       _       _._
                                _,,-''' ''-,_ }'._''.,_.=._
                             ,-'      _ _    '        (  @)'-,
                           ,'  _..==;;::_::'-     __..----'''}
                          :  .'::_;==''       ,'',: : : '' '}
                         }  '::-'            /   },: : : :_,'
                        :  :'     _..,,_    '., '._-,,,--\'    _
                       :  ;   .-'       :      '-, ';,__\.\_.-'
                      {   '  :    _,,,   :__,,--::',,}___}^}_.-'
                      }        _,'__''',  ;_.-''_.-'
                     :      ,':-''  ';, ;  ;_..-'
                 _.-' }    ,',' ,''',  : ^^
                 _.-''{    { ; ; ,', '  :
    ______      ____  }   } :  ;_,' ;  }  ________                         __
   / ____/___ _/ __/__ {   ',',___,'   ' / ____/ /_  ____ _____ ___  ___  / /__  ____  ____
  / /   / __ `/ /_/ _ \ ',           ,' / /   / __ \/ __ `/ __ `__ \/ _ \/ / _ \/ __ \/ __ \
 / /___/ /_/ / __/  __/   '-,,__,,-'   / /___/ / / / /_/ / / / / / /  __/ /  __/ /_/ / / / /
 \____/\__,_/_/  \___/                 \____/_/ /_/\__,_/_/ /_/ /_/\___/_/\___/\____/_/ /_/

               Layer 2 Captive Portal Security Auditing Framework
```

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Classification](https://img.shields.io/badge/classification-Defensive%20Research-orange.svg)](#disclaimer--legal-notice)

CafeChameleon is a modular Linux network security testing framework and defensive research toolkit developed to audit, demonstrate, and analyze Layer 2 authentication vulnerabilities in captive portal wireless environments.

---

## [ LEGAL DISCLAIMER & ETHICAL USE POLICY ]

> **CRITICAL NOTICE FOR RESEARCHERS AND SECURITY AUDITORS:**
>
> 1. **Academic and Defensive Research Purpose**: This software and its associated documentation are developed strictly for academic research, education, security auditing, and defensive infrastructure hardening. It provides network administrators and security professionals with a platform to evaluate the resilience of captive portal gateways against Layer 2 impersonation attacks.
> 2. **Explicit Authorization Required**: You must **never** execute this tool against any wireless network, access point, client device, or infrastructure without explicit, verifiable, and written authorization from the legitimate network owner. Unauthorized packet capturing, 802.11 frame injection, ARP manipulation, or session hijacking is strictly prohibited by law across domestic and international jurisdictions (including the US Computer Fraud and Abuse Act - CFAA 18 U.S.C. § 1030, the UK Computer Misuse Act 1990, and international cybersecurity statutory frameworks).
> 3. **Limitation of Liability**: The authors, developers, and maintainers of this repository assume **no liability** and accept no responsibility for any misuse, damage, data loss, operational disruption, or legal ramifications resulting from the execution or modification of this code. Users bear sole responsibility for ensuring all testing activities strictly adhere to applicable laws and authorization boundaries.
> 4. **Dual-Use Compliance**: This project constitutes legitimate dual-use educational material published in full compliance with GitHub's Acceptable Use Policies and security research guidelines.

---

## [ SECURITY MODEL & VULNERABILITY ANALYSIS ]

Captive portals deployed on unencrypted wireless networks (802.11 Open/OWE) frequently exhibit architectural weaknesses that compromise access control boundaries:

* **Plaintext Over-the-Air Transmission**: Unencrypted 802.11 frames expose client MAC addresses and transmission metrics to passive radio monitoring.
* **Stateless Layer 2 Session Binding**: Upstream gateways frequently validate authorization by mapping IP/MAC address tuples without cryptographic session tokens or 802.1X enterprise-grade encapsulation.
* **Unauthenticated ARP Resolution**: Standard IPv4 networks trust unsolicited Address Resolution Protocol announcements, leaving networks vulnerable to session state collisions.

CafeChameleon provides a structured testbed to evaluate these attack surfaces and verify whether network defenses successfully isolate and protect authenticated clients.

---

## [ OPERATIONAL CAPABILITIES ]

### Simple Mode (`simple`)
* Automated local subnet detection, gateway discovery, and CIDR parsing.
* Fast adaptive host discovery utilizing Nmap Ping Sweeps (`-sn`) with Wi-Fi RTT timing constraints.
* Subnet block expansion (`-w` / `--wide` flag for `/22` subnet testing).
* Layer 2 session takeover validation and automated internet connectivity verification.

### Aggressive Mode (`aggressive`)
* **Multi-BSSID Discovery**: Enumeration and structured ranking of all Access Points advertising the target ESSID.
* **Signal-Weighted Channel Hopping (`-b` / `--threshold`)**: Dwells adaptively on high-signal channels when dense AP clusters are detected.
* **Client-Focused Targeting (`-c` / `--clients`)**: Prioritizes BSSIDs with confirmed associated client stations regardless of raw RSSI.
* **Global Client Pooling (`--any-bssid`)**: Decouples discovered clients from individual APs, pooling all air clients across all BSSIDs to test against the strongest signal APs.
* **Fast Impersonation (`--any-ip`)**: Connects directly with local subnet IP, skipping multi-stage IP resolution probes and DHCP queries for instant MAC impersonation testing.
* **Interactive & Range Selection (`-s` / `--select-bssid`)**: Allows manual targeting of specific Access Points via interactive prompts or numeric range lists.
* **Security-Aware Deauth Protection**: Inspects AP encryption status; skips 802.11 deauthentication on open networks unless explicitly overridden with `--force-deauth`.
* **802.11 Monitor Mode Telemetry (`--air` / `--air-only`)**: Captures real-time client association frames, signal metrics, and probe requests. Use `--air-only` to skip subnet scanning across BSSIDs and test over-the-air discovered clients exclusively.

### Wi-Fi Controller (`wifi`)
* **BSSID Locking (`-l` / `--lock`)**: Binds NetworkManager connection profiles to a designated physical BSSID.
* **Auto-Roam (`-a` / `--auto`)**: Evaluates available Access Points and roams dynamically to the strongest RSSI source.
* **MAC Spoofing / Randomization (`-m` / `--mac`)**: Sets the MAC address to a specified value, or randomizes it if omitted.
* **MAC Reset (`-r` / `--reset-mac`)**: Restores hardware MAC addresses to permanent factory defaults.
* **Interface Release (`--release`)**: Completely unlocks the wireless interface (teardown monitor mode, terminate DHCP clients, restore NetworkManager).
* **Connection Status (`-s` / `--status`)**: Queries current BSSID lock configurations, active profiles, and link parameters.

### Multi-Window Telemetry Engine
* Centered multi-window terminal layout separating Air Sniffing, Subnet Scanning, and Session Takeover outputs.
* Isolated FIFO communication queues preventing blocking across asynchronous subsystems.
* Targeted interrupt handling (`Ctrl+C` inside an auxiliary window skips only the active sub-process).

### Shielded Process Teardown
* Signal-shielded exit routines that ignore duplicate interrupt signals during state restoration.
* Automated recovery of IP configurations, routing tables, hardware MAC addresses, monitor mode interfaces, and NetworkManager profiles.

### Automated Unit Test Framework
* Comprehensive test suite (`tests/`) covering BSSID scoring algorithms, IP filtering logic, monitor mode transitions, security deauth safeguards, and teardown handlers.

---

## [ REPOSITORY STRUCTURE ]

```text
CafeChameleon/
├── cafe_chameleon/
│   ├── cli/              # CLI argument parsers with custom help formatters
│   ├── config.py         # Centralized configuration, timeout budgets, and defaults
│   ├── models/           # Strongly-typed network and BSSID data models
│   ├── modes/
│   │   ├── aggressive/   # Multi-BSSID roaming, signal ranking, air target handler
│   │   ├── simple/       # Subnet scanner, subnet takeover, ARP impersonator
│   │   └── wifi/         # NetworkManager connection and BSSID controller
│   ├── network/          # Linux sysfs polling, MAC spoofing, DHCP, deauth, and nmcli
│   ├── scanners/         # 802.11 air sniffer, packet parser, channel hopper, Nmap scanner
│   ├── ui/               # ANSI color palette, console facade, xterm multi-window manager
│   └── utils/            # Process execution, state tracking, signals, and trace logs
├── tests/                # Automated pytest unit test suite
├── main.py               # Main CLI entrypoint
├── LICENSE               # MIT License with explicit liability disclaimers
└── README.md             # Project documentation and legal notices
```

---

## [ PREREQUISITES & INSTALLATION ]

### System Requirements
* **Operating System**: Linux (Kali Linux, Debian, Ubuntu, Arch Linux).
* **Python**: Python 3.10 or higher.
* **Required System Packages**:
  ```bash
  sudo apt update
  sudo apt install -y python3-pip nmap iw wireless-tools net-tools network-manager xterm aircrack-ng mdk4
  ```

### Python Setup
```bash
git clone https://github.com/Bimo754/CafeChameleon.git
cd CafeChameleon
pip3 install scapy pytest
```

---

## [ CLI REFERENCE & USAGE EXAMPLES ]

### Simple Subnet Discovery & Session Audit
```bash
# Automated subnet host discovery & session auditing
sudo python3 main.py simple

# Target specific subnet with wide /22 expansion
sudo python3 main.py simple -t 10.0.0.0/24 -w

# Enable 802.11 monitor mode capture with 30s dwell time
sudo python3 main.py simple --air 30
```

### Aggressive Multi-BSSID Auditing
```bash
# Full multi-BSSID exploration with live air sniffing
sudo python3 main.py aggressive --air

# Prioritize BSSIDs with confirmed active client stations
sudo python3 main.py aggressive --air -c

# Interactively select targeted BSSIDs
sudo python3 main.py aggressive -s

# Set BSSID density threshold for signal-weighted channel hopping
sudo python3 main.py aggressive --air -b 15

# Over-the-air client discovery only (skip all subnet scanning across BSSIDs)
sudo python3 main.py aggressive --air-only 30
```

### Wi-Fi Profile & Hardware Management
```bash
# Scan and display all nearby Wi-Fi networks and BSSIDs with formatted stats
python3 main.py wifi --scan

# Scan and filter nearby BSSIDs matching a specific SSID name
python3 main.py wifi --scan "TargetNetwork"

# Inspect current connection profile, BSSID lock, and MAC state
python3 main.py wifi -s

# Lock connection profile to a specific Access Point BSSID
python3 main.py wifi -l 08:FA:28:56:27:80

# Auto-roam to the strongest Access Point on the active profile
python3 main.py wifi -a

# Randomize MAC address on active connection
sudo python3 main.py wifi -m

# Set a specific MAC address on active connection
sudo python3 main.py wifi -m 00:11:22:33:44:55

# Set a specific MAC address on a designated profile
sudo python3 main.py wifi --mac 00:11:22:33:44:55 "MyWiFiProfile"

# Reset interface MAC address to permanent factory default
sudo python3 main.py wifi -r

# Release & unlock interface (teardown monitor mode, stop lingering dhclient, restore NetworkManager)
sudo python3 main.py wifi --release

# Reconnect to already connected BSSID with active MAC and IP address
sudo python3 main.py wifi --reconnect

# Continuously auto-reconnect to BSSID whenever connection drops or disconnects
sudo python3 main.py wifi --reconnect auto
```

### Running Test Suite
```bash
python3 -m pytest tests/
```

---

## [ DEFENSIVE HARDENING RECOMMENDATIONS ]

To protect infrastructure from the Layer 2 vulnerabilities demonstrated by this tool:

1. **Deploy 802.1X / WPA3-Enterprise**: Enforce cryptographic client authentication (EAP-TLS/PEAP) prior to network association.
2. **Enable Layer 2 Client Isolation**: Prevent direct peer-to-peer frame transmission between wireless stations on the same Access Point.
3. **Implement Dynamic ARP Inspection (DAI)**: Intercept and validate ARP packets against DHCP snooping binding databases.
4. **Enforce 802.11w (Protected Management Frames)**: Require PMF across wireless infrastructure to defend against forged deauthentication attacks.
5. **Utilize Private VLANs (PVLAN)**: Segregate client broadcast domains at the switch level.

---

## [ ACKNOWLEDGMENTS & CREDITS ]

* **ASCII Artwork**: Original chameleon ASCII illustration created by artist **pils** (archived on ASCII.co.uk / Usenet).

---

## [ LICENSE ]

This project is licensed under the terms of the [MIT License](LICENSE).
