# CafeChameleon Technical Documentation & User Guide

This guide provides exhaustive technical documentation for **CafeChameleon**, including subcommand specifications, CLI option reference, architecture details, operational workflows, and hardware recovery routines.

---

## TABLE OF CONTENTS

1. [Global Options](#global-options)
2. [Simple Mode (`simple`)](#simple-mode-simple)
3. [Aggressive Mode (`aggressive`)](#aggressive-mode-aggressive)
4. [Wi-Fi Controller (`wifi`)](#wi-fi-controller-wifi)
5. [Blacklist Manager (`blacklist`)](#blacklist-manager-blacklist)
6. [Multi-Window Telemetry Engine](#multi-window-telemetry-engine)
7. [Operational Workflows](#operational-workflows)
8. [Hardware State Recovery](#hardware-state-recovery)
9. [Development & Unit Testing](#development--unit-testing)

---

## GLOBAL OPTIONS

Global flags apply to all subcommands:

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-q`, `--quiet` | None | Suppress non-critical console output messages. |
| `-v`, `--verbose` | None | Enable verbose operation logs in the primary terminal launcher output. |
| `--debug` | `commands` \| `tracing` | Enable execution tracing mode (`commands` for command output, `tracing` for detailed process logs). |
| `-h`, `--help` | None | Display CLI usage reference and options for the given subcommand. |

Example:
```bash
sudo cafechameleon --debug tracing simple -w
```

---

## SIMPLE MODE (`simple`)

Simple mode performs local subnet host discovery, IP/MAC mapping, and rapid session impersonation.

### Syntax

```bash
sudo cafechameleon simple [options]
```

### Options Reference

| Option | Metavar | Description |
| :--- | :--- | :--- |
| `-t`, `--target` | `CIDR` | Explicitly target a specific CIDR subnet (e.g., `10.0.0.0/24`). Defaults to auto-detection. |
| `--subnet` | `CIDR` | Target subnet block override for deep host discovery probes. |
| `-w`, `--wide` | None | Expand host discovery scan to a wider `/22` subnet range. |
| `--air` | `[SECS]` | Enable 802.11 monitor mode capture window in seconds (`0` for continuous execution). |
| `-i`, `--interface` | `IFACE` | Explicitly specify the network interface (e.g., `wlan0`). |
| `-m`, `--original-mac` | None | Retain original hardware MAC address during audit (disables MAC randomization). |
| `--force` | None | Force execution even if active internet connectivity is already established. |
| `--force-deauth` | None | Force 802.11 deauthentication frame delivery on open/unencrypted networks. |
| `--no-gateway` | None | Skip upstream gateway ICMP/ARP validation checks during host impersonation. |
| `--no-xterm` | None | Disable spawning multi-window xterm terminals and direct output to active console. |

### Command Examples

```bash
# Standard simple audit with auto-subnet detection
sudo cafechameleon simple

# Target 192.168.1.0/24 with a /22 expansion scan
sudo cafechameleon simple -t 192.168.1.0/24 -w

# Simple audit with 30-second live air sniffing window
sudo cafechameleon simple --air 30

# Simple audit preserving hardware MAC address
sudo cafechameleon simple -m
```

---

## AGGRESSIVE MODE (`aggressive`)

Aggressive mode targets complex multi-AP enterprise networks, utilizing signal-weighted channel hopping, BSSID density evaluation, and over-the-air station targeting.

### Syntax

```bash
sudo cafechameleon aggressive [options]
```

### Options Reference

| Option | Metavar | Description |
| :--- | :--- | :--- |
| `-p`, `--profile` | `NAME` | Specify active NetworkManager Wi-Fi profile name. Defaults to auto-detection. |
| `-t`, `--target` | `CIDR` | Target CIDR subnet block override. |
| `--subnet` | `CIDR` | Deep subnet host discovery range. |
| `-s`, `--select-bssid` | `[TARGETS]` | Interactively select BSSIDs or specify target range lists (e.g., `1`, `1,2,7`, `1-10,12`). |
| `-c`, `--clients` | None | Prioritize BSSIDs with confirmed associated active client stations. |
| `--any-bssid` | None | Connect to any BSSID offering the strongest RSSI signal, pooling air-discovered stations across all BSSIDs. |
| `--any-ip` | None | Fast connection mode; uses active subnet IP directly, bypassing IP resolution probes and DHCP queries. |
| `-b`, `--threshold` | `NUM` | BSSID density threshold for signal-weighted channel hopping (default: `10`). |
| `--air` | `[SECS]` | Enable 802.11 monitor mode capture window (`0` for continuous execution). |
| `--air-only` | `[SECS]` | Exclusively target stations discovered over-the-air, skipping subnet scanning across BSSIDs. |
| `--passive-only` | None | Disable active probe requests and frame stimulation (pure passive listening mode). |
| `-i`, `--interface` | `IFACE` | Explicit network interface override. |
| `-m`, `--original-mac` | None | Retain hardware MAC address (skip MAC randomization). |
| `--force` | None | Force scan execution even if active internet connectivity is detected. |
| `--force-deauth` | None | Force deauthentication frame delivery on open networks. |
| `--no-gateway` | None | Skip upstream gateway ping verification during host impersonation. |
| `--share` | `NAME PASS` | Automatically host a Wi-Fi access point upon successful session takeover. |
| `--no-xterm` | None | Disable multi-window UI. |

### Command Examples

```bash
# Aggressive multi-BSSID exploration with live air telemetry
sudo cafechameleon aggressive --air

# Prioritize Access Points with confirmed associated clients
sudo cafechameleon aggressive --air -c

# Over-the-air station discovery only (skip subnet scanning across BSSIDs)
sudo cafechameleon aggressive --air-only 30

# Interactively target specific Access Points by list or range
sudo cafechameleon aggressive -s 1,3,5-8

# Fast connection impersonation with hotspot sharing
sudo cafechameleon aggressive --any-ip --share MyHotspot SecretPass123
```

---

## WI-FI CONTROLLER (`wifi`)

The `wifi` subcommand manages wireless hardware states, BSSID binding, MAC address parameters, and connection profiles.

### Syntax

```bash
sudo cafechameleon wifi <action>
```

### Action Reference

| Action | Metavar | Description |
| :--- | :--- | :--- |
| `--scan` | `[SSID]` | Scan and display nearby Wi-Fi networks and BSSIDs with signal metrics. Optional filter by SSID string. |
| `-l`, `--lock` | `[BSSID]` | Lock NetworkManager connection profile to a specific Access Point BSSID. |
| `-a`, `--auto` | `[PROFILE]` | Evaluate available Access Points and auto-roam to the strongest RSSI source. |
| `-s`, `--status` | None | Query current connection profile, BSSID locks, MAC state, and link status. |
| `-m`, `--mac` | `[MODE/MAC]` | Display MAC info (no arg), set specific MAC, randomize (`random`), or reset (`reset`). |
| `-r`, `--release` | `[IFACE]` | Teardown monitor interfaces, stop lingering DHCP processes, and restore NetworkManager. |
| `-hr`, `--hard-reset` | `[IFACE]` | Complete hardware adapter reset (reload kernel driver module, unblock rfkill, flush ARP/route caches). |
| `-c`, `--reconnect` | `[MODE]` | Reconnect using saved session profiles (`auto` for continuous auto-reconnect, `deauth` for continuous with deauth). |
| `--share` | `NAME PASS` | Create and share a Wi-Fi hotspot access point using active network interface. |

### Command Examples

```bash
# Display wireless link, MAC address state, and BSSID lock status
cafechameleon wifi -s

# Scan all nearby Access Points and filter by SSID name
cafechameleon wifi --scan "Corporate-Guest"

# Lock interface to a designated physical BSSID
sudo cafechameleon wifi -l 08:FA:28:56:27:80

# Randomize interface MAC address
sudo cafechameleon wifi -m random

# Reconnect using active session parameters in continuous auto-reconnect mode
sudo cafechameleon wifi -c auto

# Release wireless interface and teardown monitor mode
sudo cafechameleon wifi -r

# Hardware wireless card reset
sudo cafechameleon wifi -hr wlan0
```

---

## BLACKLIST MANAGER (`blacklist`)

The `blacklist` subcommand manages target exclusions for client MAC addresses and BSSIDs across `simple` and `aggressive` auditing modes.

### Syntax

```bash
cafechameleon blacklist <action> [MAC]
```

### Actions

| Action | Command Format | Description |
| :--- | :--- | :--- |
| `add` | `cafechameleon blacklist add 00:11:22:33:44:55` | Permanently add a MAC address to `blacklist.txt`. |
| `remove` | `cafechameleon blacklist remove 00:11:22:33:44:55` | Remove a MAC address from `blacklist.txt`. |
| `list` | `cafechameleon blacklist list` | Display all currently blacklisted MAC addresses and BSSIDs. |

---

## MULTI-WINDOW TELEMETRY ENGINE

CafeChameleon incorporates a multi-window terminal telemetry engine using `xterm` to separate asynchronous operations into distinct console views:

```text
+----------------------------+----------------------------+
|     AIR SNIFFING WINDOW    |   SUBNET SCANNING WINDOW   |
| Real-time 802.11 frame     | Nmap ping sweep metrics,   |
| capture, RSSI telemetry &  | active host discovery &    |
| client association status  | CIDR subnet mapping        |
+----------------------------+----------------------------+
|                SESSION HIJACKING WINDOW                 |
|   ARP/IP session takeover logs, gateway validation,    |
|   internet reachability probes & connectivity status   |
+---------------------------------------------------------+
```

### Key Behaviors
* **Asynchronous Communication**: Inter-process communication is decoupled via non-blocking FIFO queues.
* **Granular Process Isolation**: Pressing `Ctrl+C` inside an auxiliary window terminates only that specific sub-process without interrupting main auditing state machine.
* **Console Fallback**: Suppress multi-window output and execute in standard single terminal view using `--no-xterm`.

---

## OPERATIONAL WORKFLOWS

### Standard Captive Portal Security Audit

1. **Initial Assessment**:
   ```bash
   sudo cafechameleon wifi -s
   ```
2. **Execute Simple Subnet Audit**:
   ```bash
   sudo cafechameleon simple
   ```
3. **Verify Connectivity**:
   If successful, CafeChameleon updates system IP and MAC bindings, verifying internet access through upstream gateway probes.

### Enterprise Multi-BSSID Audit

1. **Scan Target SSID Infrastructure**:
   ```bash
   cafechameleon wifi --scan "TargetNetwork"
   ```
2. **Execute Aggressive Audit with Live Air Telemetry**:
   ```bash
   sudo cafechameleon aggressive --air -c
   ```
3. **Interactive Target Selection (Optional)**:
   Use `-s` flag to manually choose Access Points from ranked RSSI listings.

---

## HARDWARE STATE RECOVERY

In the event of unexpected terminal termination or hardware state locking:

1. **Software Interface Release**:
   ```bash
   sudo cafechameleon wifi -r
   ```
   * Restores NetworkManager control.
   * Stops background `dhclient` / `dhcpcd` instances.
   * Removes virtual monitor interfaces (`wlan0mon`).

2. **Full Hardware Card Reset**:
   ```bash
   sudo cafechameleon wifi -hr
   ```
   * Reloads kernel wireless driver module.
   * Unblocks `rfkill` radio locks.
   * Flushes system ARP and IP routing tables.
   * Restores original permanent hardware MAC address.

---

## DEVELOPMENT & UNIT TESTING

CafeChameleon includes a `pytest` test suite covering BSSID scoring algorithms, IP filtering, monitor mode handling, and teardown handlers.

### Running Tests

```bash
# Install development dependencies
pip install -r setup/requirements-dev.txt

# Execute test suite
python3 -m pytest -c setup/pytest.ini
```
