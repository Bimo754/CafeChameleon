#!/usr/bin/env bash
# CafeChameleon Automated System & Dependency Installer
# Installs all required Linux system tools, Python dependencies, and system binary wrappers.

set -e

BOLD="\033[1m"
GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}────────────────────────────────────────────────────────────────────────${RESET}"
echo -e "${BOLD}${GREEN}          CafeChameleon Security Framework - Installation Setup         ${RESET}"
echo -e "${BOLD}${CYAN}────────────────────────────────────────────────────────────────────────${RESET}"

# Ensure script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${BOLD}${RED}[-] Error: This setup script must be run as root (use sudo ./setup.sh).${RESET}"
    exit 1
fi

echo -e "${BOLD}${YELLOW}[+] Detecting Linux distribution & package manager...${RESET}"

# Package lists
APT_PACKAGES=(
    python3
    python3-pip
    python3-setuptools
    nmap
    iw
    wireless-tools
    net-tools
    network-manager
    xterm
    aircrack-ng
    mdk4
    macchanger
    iproute2
    isc-dhcp-client
    ethtool
    arping
)

PACMAN_PACKAGES=(
    python
    python-pip
    python-setuptools
    nmap
    iw
    wireless_tools
    net-tools
    networkmanager
    xterm
    aircrack-ng
    macchanger
    iproute2
    dhcpcd
    ethtool
    arping
)

DNF_PACKAGES=(
    python3
    python3-pip
    python3-setuptools
    nmap
    iw
    wireless-tools
    net-tools
    NetworkManager
    xterm
    aircrack-ng
    macchanger
    iproute2
    dhcp-client
    ethtool
    iputils
)

# Detect Package Manager
if command -v apt &> /dev/null; then
    echo -e "${BOLD}${GREEN}[+] APT package manager detected (Debian/Ubuntu/Kali).${RESET}"
    apt update -y
    apt install -y "${APT_PACKAGES[@]}"
elif command -v pacman &> /dev/null; then
    echo -e "${BOLD}${GREEN}[+] Pacman package manager detected (Arch Linux).${RESET}"
    pacman -Sy --needed --noconfirm "${PACMAN_PACKAGES[@]}"
elif command -v dnf &> /dev/null; then
    echo -e "${BOLD}${GREEN}[+] DNF package manager detected (Fedora/RHEL).${RESET}"
    dnf install -y "${DNF_PACKAGES[@]}"
else
    echo -e "${BOLD}${YELLOW}[!] Warning: Unknown package manager. Please ensure required network tools are installed manually.${RESET}"
fi

echo -e "\n${BOLD}${YELLOW}[+] Installing Python package dependencies (scapy)...${RESET}"
python3 -m pip install --upgrade scapy --break-system-packages 2>/dev/null || python3 -m pip install --upgrade scapy

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_PATH="${SCRIPT_DIR}/main.py"
BIN_LINK_1="/usr/local/bin/cafechameleon"
BIN_LINK_2="/usr/local/bin/cafe-chameleon"

if [ -f "$MAIN_PATH" ]; then
    chmod +x "$MAIN_PATH"
    echo -e "\n${BOLD}${YELLOW}[+] Creating global CLI symlinks...${RESET}"
    ln -sf "$MAIN_PATH" "$BIN_LINK_1"
    ln -sf "$MAIN_PATH" "$BIN_LINK_2"
    echo -e "    -> ${GREEN}${BIN_LINK_1}${RESET}"
    echo -e "    -> ${GREEN}${BIN_LINK_2}${RESET}"
fi

echo -e "\n${BOLD}${CYAN}────────────────────────────────────────────────────────────────────────${RESET}"
echo -e "${BOLD}${GREEN}[+] CafeChameleon setup completed successfully!${RESET}"
echo -e "${BOLD}${GREEN}[+] You can now run the tool globally using either command:${RESET}"
echo -e "    ${BOLD}sudo cafechameleon wifi --status${RESET}"
echo -e "    ${BOLD}sudo cafe-chameleon simple${RESET}"
echo -e "${BOLD}${CYAN}────────────────────────────────────────────────────────────────────────${RESET}\n"
