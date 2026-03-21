# Blue-Tap

**Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems**

**Author:** Santhosh Ballikonda ([@Indspl0it](https://github.com/Indspl0it))
**Version:** 2.0.0 | **Python:** 3.10+ | **Platform:** Linux (Kali, Ubuntu, Raspberry Pi)
**License:** [GNU General Public License v3.0](LICENSE)

---

## Table of Contents

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Features](#features)
  - [Discovery and Scanning](#1-discovery-and-scanning)
  - [Reconnaissance](#2-reconnaissance)
  - [Vulnerability Assessment](#3-vulnerability-assessment)
  - [Data Extraction](#4-data-extraction-pbap--map--at)
  - [Connection Hijacking](#5-connection-hijacking)
  - [Audio Interception](#6-audio-interception-hfp--a2dp)
  - [AVRCP Media Control](#7-avrcp-media-control)
  - [Protocol Fuzzing](#8-protocol-fuzzing)
  - [Denial of Service](#9-denial-of-service)
  - [MAC Spoofing](#10-mac-address-spoofing)
  - [Automation and Orchestration](#11-automation-and-orchestration)
  - [Session Management and Reporting](#12-session-management-and-reporting)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Workflows](#workflows)
- [Vulnerable IVI Simulator](#vulnerable-ivi-simulator)
- [Troubleshooting](#troubleshooting)
- [Platform Notes](#platform-notes)
- [Legal Disclaimer](#legal-disclaimer)

---

## Purpose

Blue-Tap is a comprehensive Bluetooth and BLE penetration testing toolkit designed specifically for security assessments of **automotive In-Vehicle Infotainment (IVI)** systems. It provides a complete attack lifecycle — from passive device discovery through active exploitation, data extraction, and automated report generation.

### What Blue-Tap Does

- **Discovers** Bluetooth Classic and BLE devices in range, identifying IVI systems by device class, name, and service profile
- **Fingerprints** target devices to determine Bluetooth version, chipset, supported profiles, pairing mode, and IO capabilities
- **Assesses vulnerabilities** with 20+ evidence-based checks covering known CVEs (KNOB, BLURtooth, BIAS, BlueBorne, PerfektBlue, BrakTooth, BLUFFS, Invalid Curve) and configuration weaknesses
- **Extracts data** via PBAP (phonebook, call logs), MAP (SMS/MMS messages), AT commands (device info, phonebook, SMS), and OBEX Object Push
- **Hijacks connections** by impersonating a paired phone via MAC spoofing and identity cloning to access the IVI without re-pairing
- **Intercepts audio** through HFP (call audio capture/injection) and A2DP (media stream capture, mic eavesdropping)
- **Fuzzes protocols** with a multi-protocol campaign engine supporting 8 Bluetooth protocols, 4 mutation strategies, crash database, corpus management, and crash minimization
- **Generates reports** in HTML and JSON formats with vulnerability findings, extracted data, and fuzzing results

### Who It's For

- Automotive security researchers and penetration testers
- OEM/Tier-1 security teams performing Bluetooth stack assessments
- Red teams testing vehicle connectivity systems
- Security researchers studying Bluetooth protocol vulnerabilities

### Authorization Requirement

Blue-Tap is designed exclusively for **authorized security testing**. You must have explicit written permission from the vehicle/device owner before conducting any assessment. Unauthorized use against devices you do not own or have permission to test is illegal.

---

## Architecture

### System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           ATTACKER MACHINE (Kali Linux / Ubuntu)             │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                          Blue-Tap CLI (click)                          │  │
│  │                                                                        │  │
│  │  blue-tap [--session NAME] [--verbose] <command> <subcommand> [args]   │  │
│  │                                                                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │  │
│  │  │  Session Mgr  │  │ LoggedCommand│  │  Report Gen  │                 │  │
│  │  │  (session.py) │  │   (cli.py)   │  │(generator.py)│                 │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                 │  │
│  │         │    Auto-logs every command          │                         │  │
│  │         ▼                                     ▼                         │  │
│  │  sessions/<name>/          HTML/JSON report from session data           │  │
│  │    session.json                                                         │  │
│  │    001_scan.json                                                        │  │
│  │    002_vulnscan.json                                                    │  │
│  │    pbap/ map/ audio/                                                    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         CORE MODULES                                    │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐                 │ │
│  │  │   Scanner     │  │  Fingerprint  │  │   Spoofer    │                 │ │
│  │  │ Classic + BLE │  │  LMP version  │  │  MAC + Name  │                 │ │
│  │  │  (scanner.py) │  │  Chipset/Caps │  │  + DevClass  │                 │ │
│  │  └──────┬───────┘  └──────┬────────┘  └──────┬───────┘                 │ │
│  │         │                  │                   │                         │ │
│  │  ┌──────┴──────┐  ┌───────┴────────┐  ┌──────┴───────┐                 │ │
│  │  │  SDP Browse  │  │  RFCOMM Scan   │  │  L2CAP Scan  │                 │ │
│  │  │  (sdp.py)    │  │ (rfcomm_scan)  │  │ (l2cap_scan) │                 │ │
│  │  └─────────────┘  └────────────────┘  └──────────────┘                 │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐                 │ │
│  │  │  GATT Enum   │  │  HCI Capture  │  │   Sniffer    │                 │ │
│  │  │  (gatt.py)   │  │(hci_capture)  │  │  nRF / USRP  │                 │ │
│  │  └──────────────┘  └───────────────┘  └──────────────┘                 │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        ATTACK MODULES                                   │ │
│  │                                                                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │ │
│  │  │  VulnScan │ │  Hijack  │ │   PBAP   │ │   MAP    │ │   HFP    │     │ │
│  │  │ 20+ checks│ │ Full IVI │ │ Phonebook│ │ Messages │ │Call Audio│     │ │
│  │  │ CVE-based │ │ takeover │ │ + Calls  │ │ SMS/MMS  │ │ SCO link │     │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │ │
│  │                                                                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │ │
│  │  │   A2DP   │ │  AVRCP   │ │   OPP    │ │   BIAS   │ │   DoS    │     │ │
│  │  │ Media/Mic│ │ Media Ctl│ │ File Push│ │CVE-2020- │ │Pair/Name │     │ │
│  │  │CapturInj │ │ Vol Ramp │ │   vCard  │ │  10135   │ │  Flood   │     │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │ │
│  │                                                                         │ │
│  │  ┌──────────┐ ┌──────────┐                                              │ │
│  │  │BlueSnarfr│ │ PIN Brute│                                              │ │
│  │  │ AT Cmds  │ │ Legacy   │                                              │ │
│  │  └──────────┘ └──────────┘                                              │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     PROTOCOL FUZZING ENGINE                             │ │
│  │                                                                         │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    FuzzCampaign (engine.py)                       │   │ │
│  │  │  Orchestrates multi-protocol fuzzing with live dashboard         │   │ │
│  │  │  Protocol rotation • Stats tracking • Crash detection            │   │ │
│  │  └──────────┬───────────────────┬───────────────────┬───────────┘   │   │ │
│  │             │                   │                   │               │   │ │
│  │  ┌──────────▼──────┐ ┌─────────▼────────┐ ┌────────▼─────────┐    │   │ │
│  │  │   Strategies     │ │  Protocol Builders│ │   Transports     │    │   │ │
│  │  │ ┌─────────────┐  │ │ ┌──────────────┐  │ │ ┌─────────────┐ │    │   │ │
│  │  │ │ Random Walk  │  │ │ │ L2CAP Sig    │  │ │ │ L2CAP       │ │    │   │ │
│  │  │ │ Coverage     │  │ │ │ RFCOMM       │  │ │ │ RFCOMM      │ │    │   │ │
│  │  │ │ State Machine│  │ │ │ SDP          │  │ │ │ BLE (bleak) │ │    │   │ │
│  │  │ │ Targeted     │  │ │ │ OBEX         │  │ │ └─────────────┘ │    │   │ │
│  │  │ └─────────────┘  │ │ │ ATT/GATT     │  │ │                  │    │   │ │
│  │  └──────────────────┘ │ │ SMP          │  │ └──────────────────┘    │   │ │
│  │                        │ │ BNEP         │  │                         │   │ │
│  │  ┌──────────────────┐ │ │ AT Commands  │  │ ┌──────────────────┐    │   │ │
│  │  │   Crash DB       │ │ └──────────────┘  │ │   Corpus Mgr     │    │   │ │
│  │  │  SQLite storage  │ │                    │ │  Seed generation │    │   │ │
│  │  │  Severity/Type   │ └────────────────────┘ │  Protocol-tagged │    │   │ │
│  │  │  Reproducibility │                        └──────────────────┘    │   │ │
│  │  └──────────────────┘ ┌──────────────────┐  ┌──────────────────┐    │   │ │
│  │                        │   Minimizer      │  │   PCAP Replay    │    │   │ │
│  │  ┌──────────────────┐ │  Binary search   │  │  btsnoop parser  │    │   │ │
│  │  │   Mutators       │ │  Delta debug     │  │  Frame filter    │    │   │ │
│  │  │ Field/Int/Length  │ │  Field reducer   │  │  Mutation replay │    │   │ │
│  │  │ Protocol/Corpus  │ └──────────────────┘  └──────────────────┘    │   │ │
│  │  └──────────────────┘                                               │   │ │
│  └─────────────────────────────────────────────────────────────────────┘   │ │
│                                                                              │
│  ┌──────────────────────────────┐                                           │
│  │    Bluetooth Adapter (HCI)    │                                           │
│  │    hci0 / hci1                │                                           │
│  │    BlueZ 5.x + D-Bus         │                                           │
│  └──────────────┬───────────────┘                                           │
└─────────────────┼───────────────────────────────────────────────────────────┘
                  │
      ~~~~~~~~~~~~│~~~~~~~~~~~~  Bluetooth Air (2.4 GHz)  ~~~~~~~~~~~~
                  │
    ┌─────────────┴────────────────────────────────────────────────┐
    │                                                              │
    ▼                                                              ▼
┌──────────────────────────────┐       ┌──────────────────────────────────┐
│    TARGET IVI SYSTEM          │       │       VICTIM'S PHONE              │
│                               │       │                                   │
│  Car Infotainment Unit        │       │  Paired to IVI via Bluetooth      │
│  ┌─────────────────────────┐  │       │                                   │
│  │ Bluetooth Stack         │  │       │  Blue-Tap impersonates this       │
│  │  PBAP Server (contacts) │  │       │  phone's MAC address to gain      │
│  │  MAP Server (messages)  │  │       │  access to the IVI without        │
│  │  HFP Audio Gateway      │  │       │  re-pairing (hijack attack).      │
│  │  A2DP Sink (speakers)   │  │       │                                   │
│  │  AVRCP Target           │  │       │  ┌─────────────────────────────┐  │
│  │  OPP Server             │  │       │  │ MAC: AA:BB:CC:DD:EE:FF     │  │
│  │  SPP / DUN / PAN        │  │       │  │ Bonded to IVI              │  │
│  │  BLE GATT Services      │  │       │  │ Has link key stored        │  │
│  └─────────────────────────┘  │       │  └─────────────────────────────┘  │
│                               │       │                                   │
│  SDP Records (8+ services)    │       └──────────────────────────────────┘
│  L2CAP PSMs (SDP,RFCOMM,...)  │
│  RFCOMM Channels (1-30)       │
│  BLE Advertisement + GATT     │
└───────────────────────────────┘
```

### Data Flow: Hijack Attack

```
 Attacker                    IVI (Car)                Phone (Victim)
    │                           │                          │
    │  1. scan classic          │                          │
    │ ─────────────────────────>│  Inquiry Response        │
    │ <─────────────────────────│  "SYNC" / Car Audio      │
    │                           │                          │
    │  2. recon sdp/fingerprint │                          │
    │ ─────────────────────────>│  SDP Browse + LMP Info   │
    │ <─────────────────────────│  Services, BT version    │
    │                           │                          │
    │  3. spoof mac PHONE_MAC   │                          │
    │  (local adapter change)   │                          │
    │                           │                          │
    │  4. hijack IVI PHONE_MAC  │                          │
    │ ─────────────────────────>│  Connects as "phone"     │
    │ <─────────────────────────│  Auto-authorized (bond)  │
    │                           │                          │
    │  5. PBAP GET phonebook    │                          │
    │ ─────────────────────────>│  OBEX PBAP Session       │
    │ <─────────────────────────│  vCards (contacts+calls)  │
    │                           │                          │
    │  6. MAP GET messages      │                          │
    │ ─────────────────────────>│  OBEX MAP Session        │
    │ <─────────────────────────│  bMessages (SMS/MMS)     │
    │                           │                          │
    │  7. HFP SLC setup         │                          │
    │ ─────────────────────────>│  AT command handshake    │
    │ <─────────────────────────│  +BRSF, +CIND, OK        │
    │                           │                          │
    │  8. report                │                          │
    │  (generates HTML/JSON)    │                          │
```

### Internal Module Dependencies

```
cli.py ──────────────────────────────────────────────────────────
  │
  ├── core/
  │   ├── adapter.py      ← hciconfig, btmgmt, bluetoothctl
  │   ├── scanner.py      ← hcitool (Classic), bleak (BLE)
  │   └── spoofer.py      ← bdaddr, hciconfig, btmgmt
  │
  ├── recon/
  │   ├── sdp.py          ← sdptool, raw L2CAP PSM 1
  │   ├── fingerprint.py  ← hcitool info, LMP features
  │   ├── gatt.py         ← bleak (BLE GATT client)
  │   ├── rfcomm_scan.py  ← socket(BTPROTO_RFCOMM)
  │   ├── l2cap_scan.py   ← socket(BTPROTO_L2CAP)
  │   ├── sniffer.py      ← nRF Sniffer, USRP B210
  │   └── hci_capture.py  ← btmon
  │
  ├── attack/
  │   ├── vuln_scanner.py ← recon/* (SDP, RFCOMM, fingerprint)
  │   ├── hijack.py       ← spoofer + pbap + map + hfp
  │   ├── pbap.py         ← socket(RFCOMM) + OBEX binary
  │   ├── map_client.py   ← socket(RFCOMM) + OBEX binary
  │   ├── hfp.py          ← socket(RFCOMM) + AT commands + SCO
  │   ├── a2dp.py         ← PulseAudio (pulsectl)
  │   ├── avrcp.py        ← D-Bus (BlueZ AVRCP interface)
  │   ├── bias.py         ← L2CAP role-switch manipulation
  │   ├── bluesnarfer.py  ← socket(RFCOMM) + AT commands
  │   ├── dos.py          ← pairing flood, l2ping, name flood
  │   ├── opp.py          ← socket(RFCOMM) + OBEX Push
  │   └── pin_brute.py    ← D-Bus pairing agent
  │
  ├── fuzz/
  │   ├── engine.py       ← transport + crash_db + corpus + mutators
  │   ├── transport.py    ← L2CAP/RFCOMM/BLE socket abstractions
  │   ├── crash_db.py     ← SQLite3
  │   ├── corpus.py       ← protocol-tagged seed storage
  │   ├── mutators.py     ← field/integer/length/corpus mutation
  │   ├── minimizer.py    ← binary search + ddmin + field reduction
  │   ├── pcap_replay.py  ← btsnoop v1 parser + replay engine
  │   ├── protocols/      ← 8 protocol-specific builders
  │   └── strategies/     ← 4 campaign strategies
  │
  ├── report/
  │   └── generator.py    ← session data → HTML/JSON reports
  │
  └── utils/
      ├── output.py       ← Rich console (tables, panels, colors)
      ├── session.py      ← JSON-L session logging
      ├── interactive.py  ← Device selection prompts
      └── bt_helpers.py   ← run_cmd, check_tool, MAC validation
```

---

## Features

### 1. Discovery and Scanning

Passive and active discovery of Bluetooth Classic and BLE devices in range.

| Command | Description |
|---------|-------------|
| `blue-tap scan classic` | Bluetooth Classic inquiry scan — discovers BR/EDR devices, shows name, MAC, device class, RSSI |
| `blue-tap scan ble` | BLE scan using bleak — discovers LE advertisers, shows name, MAC, services, manufacturer data |
| `blue-tap scan ble --passive` | Passive BLE scan (no SCAN_REQ sent) — stealthier, only collects advertisement data |
| `blue-tap scan all` | Simultaneous Classic + BLE scan |

**Key capabilities:**
- Device class decoding (identifies Car Audio, Hands-Free, Phone, Computer, etc.)
- RSSI signal strength display for proximity estimation
- JSON output (`-o results.json`) for scripted pipelines
- Configurable scan duration (`-d 30` for 30 seconds)
- Adapter selection (`-i hci1`) for multi-adapter setups

---

### 2. Reconnaissance

Deep service enumeration, device fingerprinting, and radio-level capture.

| Command | Description |
|---------|-------------|
| `blue-tap recon sdp <MAC>` | Browse all SDP service records — profiles, channels, UUIDs, provider strings |
| `blue-tap recon fingerprint <MAC>` | Device fingerprinting — BT version, LMP features, chipset, manufacturer, capabilities |
| `blue-tap recon rfcomm-scan <MAC>` | Brute-force scan RFCOMM channels 1-30 for open/hidden services |
| `blue-tap recon l2cap-scan <MAC>` | Scan well-known L2CAP PSMs for open services; `--dynamic` adds dynamic range |
| `blue-tap recon gatt <MAC>` | BLE GATT service/characteristic enumeration with read/write/notify properties |
| `blue-tap recon ssp <MAC>` | Check if device supports Secure Simple Pairing |
| `blue-tap recon pairing-mode <MAC>` | Detect pairing mode (Legacy PIN vs SSP) and IO capabilities |
| `blue-tap recon capture-start` | Start HCI traffic capture via btmon (saves btsnoop format) |
| `blue-tap recon capture-stop` | Stop btmon capture |

**Advanced radio reconnaissance (requires specialized hardware):**

| Command | Hardware | Description |
|---------|----------|-------------|
| `blue-tap recon nrf-scan` | nRF52840 dongle | BLE advertisement scanning with raw PDU access |
| `blue-tap recon nrf-sniff` | nRF52840 dongle | Sniff BLE pairing exchanges (capture STK/LTK negotiation) |
| `blue-tap recon usrp-scan` | USRP B210 | Scan for BR/EDR piconets at baseband level |
| `blue-tap recon usrp-follow` | USRP B210 | Follow and capture BR/EDR piconet traffic |
| `blue-tap recon usrp-capture` | USRP B210 | Raw IQ capture for offline analysis |
| `blue-tap recon crack-key` | — | Crack BLE pairing key from captured pcap using Crackle |
| `blue-tap recon extract-link-key` | — | Extract BR/EDR link key from captured pairing exchange |
| `blue-tap recon inject-link-key` | — | Inject recovered link key into BlueZ for reconnection |

---

### 3. Vulnerability Assessment

Evidence-based vulnerability scanner with 20+ checks covering known CVEs, protocol weaknesses, and configuration issues. Each finding includes severity, CVE reference, impact description, remediation guidance, status (confirmed/potential/unverified), and confidence rating.

```
blue-tap vulnscan <MAC>
blue-tap vulnscan <MAC> -o findings.json
```

**Vulnerability checks performed:**

| Check | CVE(s) | What It Detects |
|-------|--------|-----------------|
| Service Exposure | — | Sensitive RFCOMM services (PBAP/MAP) reachable without auth challenge |
| KNOB | CVE-2019-9506 | LMP key size negotiation downgrade (BT < 5.1, pause_encryption) |
| BLURtooth / CTKD | CVE-2020-15802 | Cross-transport key derivation overwrite (BT 4.2-5.0, dual-mode) |
| PerfektBlue | CVE-2024-45431/32/33/34 | OpenSynergy BlueSDK vulns (VW/Audi/Mercedes IVI, invalid CID probe) |
| BLUFFS | CVE-2023-24023 | Session key derivation downgrade (BT 4.2-5.4) |
| PIN Pairing Bypass | CVE-2020-26555 | BR/EDR impersonation via PIN response spoofing |
| Invalid Curve | CVE-2018-5383 | ECDH public key validation skip in SSP/SC (BT 4.2-5.0) |
| BIAS | CVE-2020-10135 | Authentication bypass via role-switch during reconnection |
| BlueBorne | CVE-2017-1000251 | L2CAP configuration response buffer overflow (kernel < 4.13.1) |
| Pairing Method | — | Legacy PIN vs SSP Just Works vs MITM-protected |
| Writable GATT | — | BLE characteristics writable without authentication (OTA update, diagnostics) |
| BrakTooth Chipset | — | Chipset identification for BrakTooth family vulnerabilities |
| EATT Support | — | Enhanced ATT channel support and L2CAP CoC configuration |
| Hidden RFCOMM | — | RFCOMM channels open but not advertised in SDP |
| Encryption Enforcement | — | Services accessible without mandatory encryption |
| PIN Lockout | — | Absence of rate limiting on pairing attempts |
| Device Class | — | Identifies Car Audio / Hands-Free device class (IVI indicator) |
| LMP Features | — | Feature flag analysis (encryption, SC, LE, dual-mode) |
| Authorization Model | — | Service authorization policy (trust-on-first-use, per-service, etc.) |
| Automotive Diagnostics | — | OBD/UDS/diagnostic service exposure via Bluetooth |

**Finding classification:**
- **Status:** `confirmed` (directly observed), `potential` (version/heuristic based), `unverified` (requires active exploit)
- **Confidence:** `high`, `medium`, `low`
- **Severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

### 4. Data Extraction (PBAP / MAP / AT)

#### PBAP — Phone Book Access Profile

Download phonebook contacts and call history from the IVI's synced phone data.

```
blue-tap pbap pull <MAC>                     # Pull main phonebook
blue-tap pbap pull <MAC> -p telecom/ich.vcf  # Incoming call history
blue-tap pbap pull <MAC> -p telecom/och.vcf  # Outgoing call history
blue-tap pbap pull <MAC> -p telecom/mch.vcf  # Missed call history
blue-tap pbap pull <MAC> -p telecom/cch.vcf  # Combined call history
blue-tap pbap dump <MAC>                     # Dump ALL: contacts + all call logs + favorites + SIM
blue-tap pbap dump <MAC> -o ./pbap_data/     # Custom output directory
```

**What's extracted:**
- vCard 2.1/3.0 contacts (name, phone numbers, email, address, organization)
- Call history with timestamps, durations, and phone numbers
- SIM phonebook entries (if synced)
- Speed dial / favorites

#### MAP — Message Access Profile

Download SMS and MMS messages stored on the IVI.

```
blue-tap map list <MAC>                    # List messages in inbox
blue-tap map list <MAC> --folder sent      # List sent messages
blue-tap map dump <MAC>                    # Dump all messages from all folders
blue-tap map dump <MAC> -o ./messages/     # Custom output directory
```

**Message folders:** inbox, sent, draft, deleted, outbox

#### AT Command Extraction

Direct data extraction via AT commands over RFCOMM (bluesnarfer-style).

```
blue-tap at connect <MAC>                  # Interactive AT command session
blue-tap at dump <MAC>                     # Dump all: phonebook, SMS, device info
blue-tap at snarf <MAC>                    # External bluesnarfer binary
```

**Data available via AT:**
- `AT+CPBR` — Phonebook entries
- `AT+CMGL` — SMS messages
- `AT+CGSN` — IMEI
- `AT+CIMI` — IMSI
- `AT+CBC` — Battery status
- `AT+CSQ` — Signal strength

---

### 5. Connection Hijacking

Full IVI takeover by impersonating the owner's phone.

```
blue-tap hijack <IVI_MAC> <PHONE_MAC>
blue-tap hijack <IVI_MAC> <PHONE_MAC> --phone-name "John's iPhone"
blue-tap hijack <IVI_MAC> <PHONE_MAC> --bias          # Use BIAS CVE-2020-10135
blue-tap hijack <IVI_MAC> <PHONE_MAC> --recon-only     # Recon phase only
blue-tap hijack <IVI_MAC> <PHONE_MAC> --skip-audio     # Skip HFP setup
```

**Attack phases:**
1. **Recon** — Fingerprint IVI, enumerate SDP services, identify profiles and channels
2. **Impersonate** — Spoof attacker's MAC address, adapter name, and device class to match the phone
3. **Connect** — Connect to IVI as the spoofed phone; IVI sees a bonded device and auto-authorizes
4. **PBAP Extract** — Download phonebook and call history via OBEX PBAP
5. **MAP Extract** — Download SMS/MMS messages via OBEX MAP
6. **Audio Setup** — Establish HFP Service Level Connection for call interception

**BIAS mode (`--bias`):** When the IVI validates link keys and rejects simple MAC spoofing, the BIAS attack (CVE-2020-10135) exploits a role-switch during reconnection to bypass authentication entirely.

---

### 6. Audio Interception (HFP / A2DP)

#### HFP — Hands-Free Profile

Call audio capture and injection over SCO (Synchronous Connection-Oriented) links.

```
blue-tap hfp connect <MAC>                # Establish Service Level Connection (SLC)
blue-tap hfp capture <MAC> -o call.wav    # Capture call audio to WAV
blue-tap hfp inject <MAC> -f audio.wav    # Inject audio into active call
blue-tap hfp at <MAC> -c "AT+COPS?"      # Send raw AT command
blue-tap hfp dtmf <MAC> -t "1234#"       # Send DTMF tones
blue-tap hfp hold <MAC> -a 2             # Call hold/swap
blue-tap hfp redial <MAC>                 # Redial last number
blue-tap hfp voice <MAC> --activate       # Trigger voice assistant
```

#### A2DP — Advanced Audio Distribution

Media stream capture, microphone eavesdropping, and audio injection via PulseAudio.

```
blue-tap audio devices                     # List Bluetooth audio sources/sinks
blue-tap audio profile <MAC> hfp           # Switch to HFP profile (mic access)
blue-tap audio profile <MAC> a2dp          # Switch to A2DP profile (media)
blue-tap audio record-mic <MAC>            # Record from car's Bluetooth microphone
blue-tap audio live <MAC>                  # Live eavesdrop: car mic → laptop speakers
blue-tap audio capture <MAC>               # Capture A2DP media stream to WAV
blue-tap audio play <MAC> file.mp3         # Play file through car speakers
blue-tap audio loopback <MAC>              # Route laptop mic → car speakers
blue-tap audio loopback-stop               # Stop loopback
blue-tap audio diagnose <MAC>              # Diagnose Bluetooth audio issues
blue-tap audio list                        # List captured audio files
blue-tap audio playback <file>             # Play captured file locally
blue-tap audio review                      # Interactive audio file review
```

---

### 7. AVRCP Media Control

Audio/Video Remote Control Profile attacks.

```
blue-tap avrcp play <MAC>                  # Send play command
blue-tap avrcp pause <MAC>                 # Send pause
blue-tap avrcp stop <MAC>                  # Send stop
blue-tap avrcp next <MAC>                  # Skip to next track
blue-tap avrcp prev <MAC>                  # Skip to previous track
blue-tap avrcp volume <MAC> -l 127         # Set volume to max
blue-tap avrcp volume-ramp <MAC> --start 0 --end 127 --step 5
                                           # Gradual volume escalation attack
blue-tap avrcp skip-flood <MAC> -n 100     # Rapid track skip injection
blue-tap avrcp metadata <MAC>              # Show current track metadata
blue-tap avrcp monitor <MAC>               # Monitor track changes in real-time
```

---

### 8. Protocol Fuzzing

Multi-protocol fuzzing engine with campaign management, crash database, corpus management, and crash minimization.

#### Campaign Mode

```
blue-tap fuzz campaign <MAC>                              # Fuzz all protocols
blue-tap fuzz campaign <MAC> -p sdp -p rfcomm             # Specific protocols
blue-tap fuzz campaign <MAC> --strategy targeted           # Vulnerability-targeted
blue-tap fuzz campaign <MAC> --strategy state-machine      # State machine exploration
blue-tap fuzz campaign <MAC> --strategy coverage           # Response-guided coverage
blue-tap fuzz campaign <MAC> --duration 1h --capture       # 1 hour + pcap capture
blue-tap fuzz campaign <MAC> -n 10000 --delay 0.1          # 10K iterations, fast
blue-tap fuzz campaign --resume                            # Resume previous campaign
```

**Supported protocols for campaign mode:**

| Protocol | Transport | What It Fuzzes |
|----------|-----------|----------------|
| `sdp` | L2CAP PSM 1 | SDP service records, continuation state, data elements |
| `rfcomm` | L2CAP PSM 3 | RFCOMM frames, PN/MSC/RPN negotiation, credits |
| `obex-pbap` | RFCOMM | OBEX PBAP headers, app parameters, session state |
| `obex-map` | RFCOMM | OBEX MAP headers, message listing, folder operations |
| `obex-opp` | RFCOMM | OBEX Object Push headers, large payloads |
| `at-hfp` | RFCOMM | HFP AT commands, SLC handshake, codec negotiation |
| `at-phonebook` | RFCOMM | AT+CPBR phonebook access commands |
| `at-sms` | RFCOMM | AT+CMGL/CMGR SMS commands |
| `ble-att` | BLE L2CAP | ATT handles, writes, MTU, prepare writes, unknown opcodes |
| `ble-smp` | BLE L2CAP | SMP pairing, key sizes, ECDH curve, sequencing |
| `bnep` | L2CAP PSM 15 | BNEP setup, ethernet frames, filter lists, extensions |

**Fuzzing strategies:**

| Strategy | Description |
|----------|-------------|
| `random` | Random protocol rotation and mutation selection (default) |
| `targeted` | Prioritizes protocols and mutations known to trigger CVEs |
| `coverage` | Tracks response patterns and favors mutations that produce new responses |
| `state-machine` | Explores protocol state machines by maintaining session state across test cases |

#### Protocol-Specific Fuzzers

Deep protocol fuzzers with mode selection:

```
blue-tap fuzz l2cap-sig <MAC> --mode config          # L2CAP config option parsing
blue-tap fuzz l2cap-sig <MAC> --mode echo             # L2CAP echo request flooding
blue-tap fuzz rfcomm-raw <MAC> --mode pn              # RFCOMM PN negotiation
blue-tap fuzz rfcomm-raw <MAC> --mode credits          # Credit-based flow control
blue-tap fuzz sdp-deep <MAC> --mode continuation       # SDP continuation state (CVE-2017-0785)
blue-tap fuzz sdp-deep <MAC> --mode data-elements      # SDP data element malformation
blue-tap fuzz obex <MAC> -p pbap --mode headers        # OBEX header parsing
blue-tap fuzz obex <MAC> -p map --mode path-traversal  # OBEX path traversal
blue-tap fuzz ble-att <MAC> --mode writes              # BLE ATT write overflow
blue-tap fuzz ble-att <MAC> --mode mtu                 # BLE MTU negotiation
blue-tap fuzz ble-smp <MAC> --mode curve               # Invalid ECDH curve (CVE-2018-5383)
blue-tap fuzz ble-smp <MAC> --mode sequence             # Out-of-sequence SMP
blue-tap fuzz bnep <MAC> --mode setup                   # BNEP setup connection (CVE-2017-0781)
blue-tap fuzz bnep <MAC> --mode filters                 # BNEP filter list overflow
blue-tap fuzz at-deep <MAC> --category injection        # AT command injection patterns
blue-tap fuzz at-deep <MAC> --category hfp-slc          # HFP SLC handshake fuzzing
```

#### CVE Reproduction

```
blue-tap fuzz cve --list                              # List all supported CVE patterns
blue-tap fuzz cve <MAC>                                # Run all CVE patterns
blue-tap fuzz cve <MAC> --cve-id 2017-0785             # BlueBorne SDP overflow
blue-tap fuzz cve <MAC> --cve-id sweyntooth            # SweynTooth BLE patterns
```

#### Crash Management

```
blue-tap fuzz crashes list                             # List all crashes from session
blue-tap fuzz crashes show 1                           # Detailed crash info
blue-tap fuzz crashes replay 1                         # Replay crash to verify
blue-tap fuzz crashes export                           # Export crashes to JSON
```

#### Crash Minimization

Reduce crash payloads to the minimum bytes needed to trigger the bug.

```
blue-tap fuzz minimize 1                               # Auto-select strategy
blue-tap fuzz minimize 3 --strategy ddmin              # Delta debugging
blue-tap fuzz minimize 5 --strategy binary              # Binary search reduction
blue-tap fuzz minimize 2 --strategy field               # Field-level analysis
```

#### Corpus Management

```
blue-tap fuzz corpus generate                          # Generate seed corpus from builders
blue-tap fuzz corpus list                              # Show corpus stats per protocol
blue-tap fuzz corpus minimize                          # Deduplicate by content hash
```

#### PCAP Replay

```
blue-tap fuzz replay capture.btsnoop -t <MAC> --list    # Inspect captured frames
blue-tap fuzz replay capture.btsnoop -t <MAC>            # Replay all frames
blue-tap fuzz replay capture.btsnoop -t <MAC> -p sdp     # Filter by protocol
blue-tap fuzz replay capture.btsnoop -t <MAC> --mutate   # Replay with mutations
```

#### Legacy Single-Protocol Fuzzers

```
blue-tap fuzz l2cap <MAC>                              # Basic L2CAP fuzzing
blue-tap fuzz rfcomm <MAC>                              # Basic RFCOMM fuzzing
blue-tap fuzz at <MAC>                                  # Basic AT command fuzzing
blue-tap fuzz sdp <MAC>                                 # SDP continuation probe (CVE-2017-0785)
blue-tap fuzz bss <MAC>                                 # Bluetooth Stack Smasher (external)
```

---

### 9. Denial of Service

```
blue-tap dos pair-flood <MAC>                          # Flood with pairing requests
blue-tap dos name-flood <MAC>                          # Pair with max-length names (memory exhaustion)
blue-tap dos rate-test <MAC>                           # Detect rate limiting on pairing
blue-tap dos pin-brute <MAC>                           # Brute-force legacy PIN pairing
blue-tap dos l2ping-flood <MAC>                        # L2CAP echo request flood (requires root)
```

---

### 10. MAC Address Spoofing

```
blue-tap spoof mac <TARGET_MAC>                        # Change adapter MAC address
blue-tap spoof clone <MAC>                             # Full identity clone: MAC + name + device class
blue-tap spoof restore                                 # Restore original MAC
```

---

### 11. Automation and Orchestration

#### Auto Mode

Fully automated: discover phone, hijack IVI, extract all data, generate report.

```
blue-tap auto <IVI_MAC>                                # Full auto chain
blue-tap auto <IVI_MAC> -d 30                          # 30-second phone discovery window
blue-tap auto <IVI_MAC> -o ./auto_results/              # Custom output directory
```

#### Run Mode (Playbook)

Execute multiple commands in sequence with a single invocation.

```
# Inline commands
blue-tap -s assessment run \
  "scan classic" \
  "recon fingerprint TARGET" \
  "recon sdp TARGET" \
  "vulnscan TARGET" \
  "report"

# Playbook file (one command per line)
blue-tap -s assessment run --playbook pentest.txt
```

`TARGET` is a placeholder — you'll be prompted to select a discovered device.

**Example playbook (`pentest.txt`):**
```
scan classic
recon fingerprint TARGET
recon sdp TARGET
recon rfcomm-scan TARGET
recon l2cap-scan TARGET
vulnscan TARGET
pbap dump TARGET
map dump TARGET
report
```

---

### 12. Session Management and Reporting

#### Sessions

Every command automatically logs structured output to the active session.

```
blue-tap -s my_assessment scan classic     # Named session
blue-tap -s my_assessment vulnscan <MAC>   # Same session
blue-tap -s my_assessment pbap dump <MAC>  # Same session
blue-tap session list                       # List all sessions
blue-tap session show my_assessment         # Session details
```

**Session directory structure:**
```
sessions/my_assessment/
  session.json              # Metadata + command log
  001_scan_classic.json     # Scan results
  002_vulnscan.json         # Vulnerability findings
  003_pbap_dump.json        # PBAP extraction log
  pbap/                     # vCard files
  map/                      # bMessage files
  audio/                    # WAV captures
  report.html               # Generated report
```

#### Report Generation

```
blue-tap report                             # Report from current session
blue-tap -s my_assessment report             # Report from named session
blue-tap report ./hijack_output              # Report from specific directory
blue-tap report -f json -o report.json       # JSON format
blue-tap report -f html -o report.html       # HTML format (default)
```

**HTML report includes:**
- Executive summary with severity breakdown
- Vulnerability findings table with CVE references, impact, and remediation
- Extracted data summary (contact count, message count, call history)
- Fuzzing campaign results with crash cards (hex dumps, reproducibility status)
- Dark-themed, standalone HTML (no external dependencies)

---

## Quick Start

### Prerequisites

| Requirement | Purpose |
|-------------|---------|
| Linux (Kali recommended) | BlueZ Bluetooth stack |
| Python 3.10+ | Runtime |
| BlueZ 5.x | Bluetooth protocol stack |
| Bluetooth adapter | HCI interface (internal or USB dongle) |
| Root access | Required for raw L2CAP/RFCOMM, adapter control, btmon |

**Recommended adapters:**
- **CSR8510** (~$5 USB dongle) — supports legacy PIN, MAC spoofing, all features
- **BCM20702** — good alternative USB dongle
- **Intel AX200/210** — built-in laptop adapter (SSP enforced, no MAC spoofing)

### Installation

```bash
# 1. Install system dependencies (Kali / Ubuntu / Debian)
sudo apt update
sudo apt install -y bluez bluez-tools python3-pip python3-dev \
  libbluetooth-dev libdbus-1-dev libglib2.0-dev

# 2. Clone the repository
git clone https://github.com/Indspl0it/blue-tap.git
cd blue-tap

# 3. Install Blue-Tap
pip install -e ".[fuzz]"          # With fuzzing support (scapy)
# or
pip install -e ".[fuzz,audio]"    # With fuzzing + audio (scapy + pulsectl)
# or
pip install -e "."                # Core only

# 4. Verify installation
blue-tap --version
blue-tap adapter list
```

### Optional: Enable BlueZ Compatibility Mode

Required for `sdptool` (SDP browsing) and certain SDP fuzzing operations:

```bash
# Add --compat to bluetoothd ExecStart line
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload
sudo systemctl restart bluetooth

# Verify
sdptool browse local   # Should not show "Failed to connect to SDP server"
```

### First Scan

```bash
# Check adapter is available
blue-tap adapter list

# Discover nearby Bluetooth devices
sudo blue-tap scan classic

# If you see a target device:
sudo blue-tap recon sdp <MAC>
sudo blue-tap vulnscan <MAC>
```

---

## Usage Guide

### Global Options

```
blue-tap [OPTIONS] COMMAND [ARGS]...

Options:
  --version           Show version and exit
  -v, --verbose       Verbosity: -v verbose, -vv debug
  -s, --session TEXT  Session name (default: auto-generated timestamp)
  --help              Show help and exit
```

### Command Reference

```
blue-tap --help

Commands:
  adapter   HCI Bluetooth adapter management
  at        AT command data extraction via RFCOMM
  audio     Audio capture, injection, and eavesdropping via PulseAudio
  auto      Automated: discover phone, hijack IVI, dump data, report
  avrcp     AVRCP media control and attacks
  bias      BIAS attack — bypass authentication via role-switch (CVE-2020-10135)
  dos       DoS attacks and pairing abuse
  fuzz      Protocol fuzzing — campaign mode, legacy fuzzers, crash management
  hfp       Hands-Free Profile — call audio interception and injection
  hijack    Full IVI hijack: spoof phone identity and extract data
  map       Message Access Profile — download SMS/MMS messages
  opp       Object Push Profile — push files to IVI
  pbap      Phone Book Access Profile — download phonebook and call logs
  recon     Service enumeration and device fingerprinting
  report    Generate pentest report from the current session
  run       Execute multiple blue-tap commands in sequence
  scan      Discover Bluetooth Classic and BLE devices
  session   Manage assessment sessions
  spoof     MAC address spoofing and device impersonation
  vulnscan  Scan target for vulnerabilities and attack-surface indicators
```

### Getting Help for Any Command

```bash
blue-tap <command> --help                   # Group help
blue-tap <command> <subcommand> --help      # Subcommand help

# Examples:
blue-tap fuzz --help                        # Shows all fuzz subcommands
blue-tap fuzz campaign --help               # Campaign options and examples
blue-tap recon --help                       # All recon subcommands
```

---

## Workflows

### Workflow 1: Quick IVI Assessment

Minimal assessment — discovery, fingerprinting, vulnerability scan.

```bash
# Start a named session
blue-tap -s quick-assessment scan classic
# Note the IVI MAC address from scan results

blue-tap -s quick-assessment recon sdp AA:BB:CC:DD:EE:FF
blue-tap -s quick-assessment recon fingerprint AA:BB:CC:DD:EE:FF
blue-tap -s quick-assessment vulnscan AA:BB:CC:DD:EE:FF
blue-tap -s quick-assessment report
```

### Workflow 2: Full IVI Penetration Test

Comprehensive assessment with data extraction and fuzzing.

```bash
# Phase 1: Discovery and reconnaissance
blue-tap -s full-pentest scan classic
blue-tap -s full-pentest scan ble
blue-tap -s full-pentest recon sdp AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest recon fingerprint AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest recon rfcomm-scan AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest recon l2cap-scan AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest recon gatt AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest recon pairing-mode AA:BB:CC:DD:EE:FF

# Phase 2: Vulnerability assessment
blue-tap -s full-pentest vulnscan AA:BB:CC:DD:EE:FF

# Phase 3: Data extraction
blue-tap -s full-pentest pbap dump AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest map dump AA:BB:CC:DD:EE:FF
blue-tap -s full-pentest at dump AA:BB:CC:DD:EE:FF

# Phase 4: Connection hijack (if phone MAC known)
blue-tap -s full-pentest hijack AA:BB:CC:DD:EE:FF CC:DD:EE:FF:00:11

# Phase 5: Protocol fuzzing
blue-tap -s full-pentest fuzz campaign AA:BB:CC:DD:EE:FF \
  --duration 30m --strategy targeted --capture

# Phase 6: Report
blue-tap -s full-pentest report -f html
```

### Workflow 3: Hijack and Extract

Targeted attack — impersonate the owner's phone and steal data.

```bash
# 1. Find the IVI and paired phone
blue-tap scan classic        # Find "SYNC" or similar car name
blue-tap scan classic        # Run again; note phones near the car

# 2. Enumerate the IVI
blue-tap recon sdp AA:BB:CC:DD:EE:FF
blue-tap recon rfcomm-scan AA:BB:CC:DD:EE:FF

# 3. Execute the hijack
blue-tap hijack AA:BB:CC:DD:EE:FF CC:DD:EE:FF:00:11 \
  --phone-name "John's iPhone"

# All data saved to hijack output directory
```

### Workflow 4: Fuzzing Campaign

Extended protocol fuzzing with crash analysis.

```bash
# Generate seed corpus
blue-tap fuzz corpus generate

# Run a targeted 1-hour campaign with capture
blue-tap -s fuzz-session fuzz campaign AA:BB:CC:DD:EE:FF \
  -p sdp -p rfcomm -p obex-pbap \
  --strategy targeted \
  --duration 1h \
  --capture

# Review crashes
blue-tap fuzz crashes list
blue-tap fuzz crashes show 1

# Minimize a crash
blue-tap fuzz minimize 1 --strategy ddmin

# Replay to verify
blue-tap fuzz crashes replay 1

# Try known CVE patterns
blue-tap fuzz cve AA:BB:CC:DD:EE:FF

# Export results
blue-tap fuzz crashes export
blue-tap -s fuzz-session report
```

### Workflow 5: Playbook Automation

Create a reusable pentest playbook.

**`ivi-pentest.txt`:**
```
scan classic
recon sdp TARGET
recon fingerprint TARGET
recon rfcomm-scan TARGET
recon l2cap-scan TARGET
recon gatt TARGET
vulnscan TARGET
pbap dump TARGET
map dump TARGET
report
```

```bash
blue-tap -s auto-pentest run --playbook ivi-pentest.txt
```

### Workflow 6: Audio Eavesdropping

```bash
# Connect and switch to HFP profile for mic access
blue-tap hfp connect AA:BB:CC:DD:EE:FF
blue-tap audio profile AA:BB:CC:DD:EE:FF hfp

# Live eavesdrop (car mic → laptop speakers)
blue-tap audio live AA:BB:CC:DD:EE:FF

# Or record to file
blue-tap audio record-mic AA:BB:CC:DD:EE:FF

# Capture media stream
blue-tap audio profile AA:BB:CC:DD:EE:FF a2dp
blue-tap audio capture AA:BB:CC:DD:EE:FF

# Review captured audio
blue-tap audio list
blue-tap audio review
```

---

## Vulnerable IVI Simulator

Blue-Tap ships with a companion **Vulnerable IVI Simulator** in the `target/` directory. This is a real Bluetooth target (not a mock) that runs on any Linux machine with a Bluetooth adapter and behaves like an intentionally vulnerable car infotainment system.

### Purpose

- Practice Blue-Tap commands against a real target
- Demonstrate all attack vectors in a controlled environment
- Validate tool functionality without access to a real vehicle

### Quick Setup

Requires a **separate Linux machine** (Kali laptop, Raspberry Pi, or desktop with Bluetooth adapter).

```bash
# Terminal 1 — Configure adapter
cd target/
sudo ./setup_ivi.sh

# Terminal 2 — Start pairing agent
sudo python3 pin_agent.py

# Terminal 3 — Start IVI daemon
sudo python3 ivi_daemon.py

# Optional Terminal 4 — BLE GATT server
sudo python3 ble_gatt.py
```

### Exposed Services

| Service | Channel/PSM | Data |
|---------|-------------|------|
| PBAP (Phonebook) | RFCOMM 15 | 50 contacts, call history |
| MAP (Messages) | RFCOMM 16 | 20 SMS messages |
| OPP (Object Push) | RFCOMM 9 | Accepts any file |
| HFP (Hands-Free) | RFCOMM 10 | Full SLC handshake |
| SPP (Serial Port) | RFCOMM 1 | AT command responder |
| Hidden Debug | RFCOMM 2 | Not in SDP |
| BNEP (PAN) | L2CAP 7 | Fuzz absorber |
| AVCTP (AVRCP) | L2CAP 23 | Fuzz absorber |
| AVDTP (A2DP) | L2CAP 25 | Fuzz absorber |
| BLE GATT | Multiple | Device Info + Battery + Custom IVI |

### Built-in Vulnerabilities

| Vulnerability | What Blue-Tap Command Finds It |
|---------------|-------------------------------|
| Unauthenticated OBEX | `blue-tap vulnscan` → CRITICAL |
| Legacy PIN "1234" | `blue-tap dos pin-brute` |
| Just Works pairing (SSP) | `blue-tap vulnscan` → HIGH |
| No PIN rate limiting | `blue-tap vulnscan` → MEDIUM |
| Hidden RFCOMM channel | `blue-tap vulnscan` → MEDIUM |
| Permissive AT commands | `blue-tap at connect` |
| Unauthenticated BLE writes | `blue-tap recon gatt` |
| Hijack-vulnerable bond | `blue-tap hijack` |

See [`target/README.md`](target/README.md) for detailed setup instructions, architecture diagrams, and platform-specific notes.

---

## Troubleshooting

### Adapter Issues

**"No adapters found" / "Adapter not found"**
```bash
# Check if adapter exists
hciconfig -a

# If rfkill is blocking
rfkill list bluetooth
rfkill unblock bluetooth

# If USB dongle not recognized
lsusb | grep -i bluetooth

# Bring adapter up manually
sudo hciconfig hci0 up
```

**"Operation not permitted"**
```bash
# Most Blue-Tap commands require root
sudo blue-tap scan classic

# Or set capabilities (alternative to sudo)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### Scanning Issues

**"No devices found"**
- Ensure target is discoverable (`hciconfig hci0 | grep PSCAN` on target)
- Increase scan duration: `blue-tap scan classic -d 30`
- Try from closer range (Bluetooth range ~10m)
- Check for RF interference

**BLE scan shows no results**
- Ensure BLE is enabled: `sudo btmgmt le on`
- Try passive mode: `blue-tap scan ble --passive`
- Some adapters need LE explicitly enabled in btmgmt

### Connection Issues

**"Connection refused" on RFCOMM**
- Target service may require pairing first
- Check if the channel is correct: `blue-tap recon rfcomm-scan <MAC>`
- Service may have been deregistered

**"Permission denied" on L2CAP**
- L2CAP PSMs below 4096 require root: `sudo blue-tap ...`
- Check if PSM is blocked by the kernel: `cat /proc/sys/net/bluetooth/l2cap_enable_ertm`

**Pairing failures**
- Check pairing mode: `blue-tap recon pairing-mode <MAC>`
- For SSP devices, PIN brute-force won't work
- Try `blue-tap recon ssp <MAC>` to verify

### SDP Issues

**"Failed to connect to SDP server"**
```bash
# Enable BlueZ compatibility mode
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

### Fuzzing Issues

**"scapy not found"**
```bash
# Install fuzzing dependencies
pip install -e ".[fuzz]"
# or
pip install scapy>=2.5
```

**"No crash database found"**
- Run a fuzz campaign first to create the database
- Specify session: `blue-tap fuzz crashes list -s <session_name>`

**Target becomes unresponsive during fuzzing**
- Increase `--delay` between test cases: `--delay 2.0`
- Increase `--cooldown` after crash: `--cooldown 10`
- Reduce iteration rate with `--timeout 5`
- The target's Bluetooth stack may need manual restart

### Audio Issues

**"PulseAudio: connection refused"**
```bash
# Check PulseAudio/PipeWire is running
pactl info

# Restart audio service
blue-tap audio restart

# Diagnose Bluetooth audio routing
blue-tap audio diagnose <MAC>
```

**No audio sources/sinks visible**
```bash
blue-tap audio devices
# If empty: pair the device first, then switch profile
blue-tap audio profile <MAC> a2dp   # or hfp
```

### MAC Spoofing Issues

**"bdaddr not found"**
```bash
# Install bdaddr (part of bluez-tools or build from source)
sudo apt install bluez-tools
# or
# Build bdaddr from BlueZ source
```

**"Cannot change MAC" / "Operation not supported"**
- Intel adapters typically do not support MAC spoofing
- Use a CSR8510 or BCM20702 USB dongle
- Some adapters require the interface to be down: `sudo hciconfig hci0 down` before spoofing

### Report Issues

**"No session data found"**
- Ensure you used `-s` flag consistently: `blue-tap -s mytest scan classic`
- Check session exists: `blue-tap session list`
- Point to specific directory: `blue-tap report ./my_output_dir/`

---

## Platform Notes

### Kali Linux (Recommended)

- All tools pre-installed (BlueZ, hcitool, sdptool, btmgmt, bluetoothctl)
- May need `--compat` flag for bluetoothd
- Intel laptop adapters enforce SSP (no legacy PIN testing, no MAC spoofing)
- Recommended: add a CSR8510 USB dongle for full feature access

### Ubuntu / Debian

```bash
sudo apt install -y bluez bluez-tools python3-pip python3-dev \
  libbluetooth-dev libdbus-1-dev libglib2.0-dev
```

### Raspberry Pi

- Broadcom BCM43xx adapter supports legacy PIN mode
- Pi 5: BT 5.2 — fewer version-dependent vuln findings
- Pi 4: BT 5.0 — good balance of features
- Pi 3: BT 4.2 — triggers more vuln-scan findings (KNOB, BLURtooth)
- Excellent as IVI simulator target

### WSL (Windows Subsystem for Linux)

- **Not supported** for Bluetooth operations — WSL does not pass through USB Bluetooth adapters
- Use a native Linux installation or VM with USB passthrough

### Adapter Comparison

| Adapter | MAC Spoofing | Legacy PIN | BLE | Price | Best For |
|---------|:----------:|:----------:|:---:|:-----:|----------|
| CSR8510 USB | Yes | Yes | Yes | ~$5 | Full-feature testing |
| BCM20702 USB | Yes | Yes | Yes | ~$10 | Alternative to CSR |
| Intel AX200/210 | No | No (SSP enforced) | Yes | Built-in | BLE + recon only |
| RTL8761B USB | Partial | Partial | Yes | ~$8 | Budget option |
| nRF52840 | N/A | N/A | Sniff only | ~$10 | BLE sniffing |
| USRP B210 | N/A | N/A | Baseband | ~$1500 | Research-grade |

---

## License

Blue-Tap is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

Copyright (C) 2026 Santhosh Ballikonda

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

---

## Legal Disclaimer

Blue-Tap is provided for **authorized security testing and research purposes only**.

- You **must** have explicit written permission from the owner of any device you test
- Unauthorized access to Bluetooth devices is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar laws worldwide
- The authors accept no liability for misuse of this tool
- Always follow your organization's rules of engagement and scope limitations
- Report vulnerabilities responsibly to the affected manufacturer

**Responsible disclosure:** If you discover vulnerabilities in production IVI systems using Blue-Tap, follow coordinated disclosure practices. Contact the vehicle manufacturer's PSIRT (Product Security Incident Response Team) before public disclosure.

---

## Author

**Santhosh Ballikonda** — [@Indspl0it](https://github.com/Indspl0it)
