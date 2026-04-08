<p align="center">
  <img src="assets/banner.svg" alt="Blue-Tap Banner" width="100%"/>
</p>

<p align="center">
  <b>Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems</b><br/>
  <sub>by <a href="https://github.com/Indspl0it">Santhosh Ballikonda</a> · Python 3.10–3.13+ · Linux · <a href="LICENSE">GPLv3</a></sub>
</p>

---

## Table of Contents

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Features](docs/features.md) — Discovery, reconnaissance, 10+ CVE attacks, data extraction, audio interception, protocol fuzzing, DarkFirmware below-HCI attacks, automation
- [Quick Start](#quick-start)
- [Usage Guide](docs/usage-guide.md) — Command reference, global options, 9 pentest workflows
- [Vulnerable IVI Simulator & Demo Mode](docs/ivi-simulator.md) — Practice target setup, exposed services, built-in vulnerabilities
- [Troubleshooting & Platform Notes](docs/troubleshooting.md) — Adapter, scanning, connection, fuzzing, audio, MAC spoofing issues
- [Changelog](docs/CHANGELOG.md)
- [Credits and References](#credits-and-references)
- [Legal Disclaimer](#legal-disclaimer)

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
  │   ├── sniffer.py      ← DarkFirmware LMP capture, nRF Sniffer, USRP B210
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
  │   ├── ctkd.py            ← CVE-2020-15802 cross-transport key derivation
  │   ├── bluffs.py         ← CVE-2023-24023 session key downgrade (DarkFirmware)
  │   └── encryption_downgrade.py ← Beyond-KNOB encryption attacks (DarkFirmware)
  │
  ├── fuzz/
  │   ├── engine.py              ← campaign orchestrator + main loop
  │   ├── transport.py           ← L2CAP/RFCOMM/BLE/LMP/RawACL socket abstractions
  │   ├── crash_db.py            ← SQLite crash storage + dedup
  │   ├── corpus.py              ← protocol-tagged seed management
  │   ├── mutators.py            ← field/integer/length/corpus mutation
  │   ├── minimizer.py           ← binary search + ddmin + field reduction
  │   ├── pcap_replay.py         ← btsnoop v1 parser + replay engine
  │   ├── state_inference.py     ← AFLNet-adapted protocol state graph
  │   ├── field_weight_tracker.py← anomaly-guided field mutation weights
  │   ├── response_analyzer.py   ← 3-layer anomaly detection (struct+time+leak)
  │   ├── health_monitor.py      ← watchdog reboot + degradation detection
  │   ├── lmp_state_tests.py     ← 20 BrakTooth-style LMP state confusion tests
  │   ├── protocols/             ← 10 protocol-specific builders (incl. LMP, raw L2CAP)
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

Full command reference and examples for each feature: **[docs/features.md](docs/features.md)**

### [1. Discovery and Scanning](docs/features.md#1-discovery-and-scanning)
Classic + BLE scanning, device class decoding, manufacturer ID, RSSI distance estimation, fleet-wide scan

### [2. Reconnaissance](docs/features.md#2-reconnaissance)
SDP browse, fingerprinting (BT version, chipset, LMP features), RFCOMM/L2CAP channel scan, GATT enumeration, HCI capture, LMP sniffing

### [3. Vulnerability Assessment](docs/features.md#3-vulnerability-assessment)
20+ CVE checks (KNOB, BIAS, BLUFFS, BlueBorne, BrakTooth, SweynTooth, PerfektBlue, Invalid Curve, CTKD), non-destructive 5-phase assess mode

### [4. Connection Hijacking and BIAS](docs/features.md#4-connection-hijacking-and-bias)
MAC/name/class cloning, BIAS role-switch bypass (CVE-2020-10135), auto-reconnect with per-phase rollback

### [5. KNOB Attack (CVE-2019-9506)](docs/features.md#5-knob-attack-cve-2019-9506)
Negotiate minimum encryption key entropy, then brute force the reduced key space

### [6. SSP Downgrade Attack](docs/features.md#6-ssp-downgrade-attack)
Force SSP to legacy PIN mode, brute force PIN (0000-9999), lockout detection

### [6b. BLUFFS Attack (CVE-2023-24023)](docs/features.md#6b-bluffs-attack-cve-2023-24023)
Session key derivation downgrade via DarkFirmware LMP injection (A1/A3 variants)

### [6c. Encryption Downgrade](docs/features.md#6c-encryption-downgrade)
Disable encryption, force renegotiation, reject Secure Connections — requires DarkFirmware

### [6d. CTKD — Cross-Transport Key Derivation (CVE-2020-15802)](docs/features.md#6d-ctkd--cross-transport-key-derivation-cve-2020-15802)
Detect if Classic BT attack (KNOB) compromises BLE keys via cross-transport key sharing — requires DarkFirmware

### [7. Data Extraction (PBAP / MAP / AT / OPP)](docs/features.md#7-data-extraction-pbap--map--at--opp)
Phonebook, call history, SMS/MMS, AT commands (IMEI/IMSI), OBEX file push

### [8. Audio Interception (HFP / A2DP)](docs/features.md#8-audio-interception-hfp--a2dp)
Call capture/injection/DTMF, media stream capture, mic eavesdropping, audio playback injection

### [9. AVRCP Media Control](docs/features.md#9-avrcp-media-control)
Play/pause/skip/volume, volume ramp, skip flood DoS, metadata surveillance

### [10. Protocol Fuzzing](docs/features.md#10-protocol-fuzzing)
12 protocols, 4 strategies, 6-layer intelligence, live dashboard, crash DB + minimization, PCAP replay, CVE reproduction

### [11. Denial of Service](docs/features.md#11-denial-of-service)
15 protocol-level attacks: pairing flood, L2CAP storm/CID exhaust, SDP continuation/DES bomb, RFCOMM SABM flood, HFP AT flood

### [12. MAC Spoofing and Adapter Management](docs/features.md#12-mac-spoofing-and-adapter-management)
3 spoofing methods with fallback, full identity clone, persistent save/restore, adapter info/up/down/reset

### [13. Session Management and Reporting](docs/features.md#13-session-management-and-reporting)
Auto-logging sessions, HTML/JSON reports with executive summary, SVG charts, crash hexdumps, fuzzing intelligence

### [13b. DarkFirmware and Below-HCI Attacks](docs/features.md#13b-darkfirmware-and-below-hci-attacks)
RTL8761B LMP injection/monitoring, connection table inspection, in-flight LMP modification (6 modes), raw ACL injection, USB watchdog

### [14. Automation and Orchestration](docs/features.md#14-automation-and-orchestration)
9-phase auto pentest, YAML playbooks, run mode for command sequences

---

## Quick Start

### Prerequisites

| Requirement | Purpose |
|-------------|---------|
| Linux (Kali, Ubuntu 22.04+, Debian) | BlueZ Bluetooth stack |
| Python 3.10–3.13+ | Runtime (includes Python 3.13 BLE L2CAP compatibility) |
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

### DarkFirmware (Optional — for below-HCI attacks)

If you have an RTL8761B adapter (TP-Link UB500), Blue-Tap **auto-detects** it at startup and prompts you to install DarkFirmware if not already present. No manual firmware commands needed — just plug in the adapter and run any command:

```bash
sudo blue-tap adapter list
# → "RTL8761B detected on hci1. DarkFirmware not installed. Install now? [y/N]"
```

After installation, Blue-Tap automatically initializes all 4 firmware hooks and starts the USB watchdog for multi-day fuzzing sessions.

Without DarkFirmware, Blue-Tap works normally for all HCI-level attacks (hijack, PBAP, MAP, fuzzing, DoS, etc.). DarkFirmware is only required for BLUFFS, encryption downgrade, LMP fuzzing, and LMP monitoring.

### First Scan

```bash
# Check adapter is available (DarkFirmware status shown automatically)
sudo blue-tap adapter list

# Discover nearby Bluetooth devices
sudo blue-tap scan classic

# If you see a target device:
sudo blue-tap recon sdp <MAC>
sudo blue-tap vulnscan <MAC>
```

> **Note: Why `sudo`?** Most Blue-Tap functions require root privileges. Here's what needs them and why:
>
> | Function | Reason |
> |----------|--------|
> | `scan classic/ble` | Raw HCI socket for device discovery |
> | `recon sdp/fingerprint` | L2CAP raw sockets for SDP/fingerprinting |
> | `vulnscan`, `assess` | Raw L2CAP + HCI for vulnerability probing |
> | `hijack`, `knob`, `bias`, `bluffs` | Raw L2CAP sockets + LMP injection via HCI |
> | `fuzz` (all protocols) | Raw L2CAP/RFCOMM/BLE sockets |
> | `dos` | Raw sockets for flooding |
> | `adapter firmware-*` | HCI VSC commands (raw HCI socket) + writing to `/lib/firmware/` |
> | `adapter spoof` | `bdaddr` tool requires adapter control |
> | DarkFirmware hook init | HCI vendor-specific commands (VSC 0xFC61/0xFC62) for RAM read/write |
>
> **Only these run without root:** `--version`, `--help`, `demo`
>
> Alternatively, grant `CAP_NET_RAW` to avoid full root: `sudo setcap cap_net_raw+eip $(which python3)`

---

## Documentation

| Document | Description |
|----------|-------------|
| **[Features](docs/features.md)** | Full feature documentation — every command, option, and example for all 14 feature categories |
| **[Usage Guide](docs/usage-guide.md)** | Global options, command reference, and 9 complete pentest workflows |
| **[Troubleshooting](docs/troubleshooting.md)** | Adapter, scanning, connection, SDP, fuzzing, audio, MAC spoofing, and report issues + platform notes |
| **[IVI Simulator & Demo](docs/ivi-simulator.md)** | Vulnerable IVI simulator setup, exposed services, built-in vulnerabilities, demo mode |
| **[Changelog](docs/CHANGELOG.md)** | Version history with detailed release notes |

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
