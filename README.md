<p align="center">
  <img src="assets/banner.svg" alt="Blue-Tap Banner" width="100%"/>
</p>

<p align="center">
  <b>Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems</b><br/>
  <sub>by <a href="https://github.com/Indspl0it">Santhosh Ballikonda</a> · Python 3.10–3.13+ · Linux · <a href="LICENSE">GPLv3</a></sub>
</p>

<p align="center">
  <a href="#purpose">Purpose</a> · <a href="#architecture">Architecture</a> · <a href="#features">Features</a> · <a href="#quick-start">Quick Start</a> · <a href="#documentation">Docs</a> · <a href="#credits-and-references">Credits</a> · <a href="#legal-disclaimer">Legal</a>
</p>

---

## Purpose

Blue-Tap is a Bluetooth/BLE penetration testing toolkit built for automotive IVI security assessments. It operates at two layers: standard HCI-level attacks (scanning, hijacking, data extraction, protocol fuzzing) using any Bluetooth adapter, and below-HCI attacks (LMP injection, session key downgrade, encryption manipulation) using DarkFirmware on RTL8761B.

It discovers and fingerprints devices, exploits 10+ CVEs (BIAS, KNOB, BLUFFS, SSP downgrade, encryption downgrade, BlueBorne, BrakTooth, SweynTooth, PerfektBlue, Invalid Curve), extracts phonebooks, messages, and call audio, and fuzzes 12 Bluetooth protocols with a response-guided engine. All findings are logged into sessions and exported as evidence-backed HTML/JSON pentest reports.

**What Blue-Tap does:**

- **Discovers** Bluetooth Classic and BLE devices in range, classifying IVI systems by device class, name heuristics, and service UUIDs. Fleet-wide scanning assesses all nearby devices in one pass.
- **Fingerprints** target devices to determine Bluetooth version, LMP features, chipset manufacturer, supported profiles, pairing mode, IO capabilities, and attack surface.
- **Assesses vulnerabilities** with `vulnscan`, which runs heuristic and OTA behavioral checks for known CVEs plus modular non-CVE exposure and posture checks in one command. Findings and per-check execution logs are exported into the HTML/JSON reporting pipeline with evidence and remediation.
- **Attacks below the HCI boundary** via DarkFirmware on RTL8761B (TP-Link UB500) — live RAM patching for BDADDR spoofing without reset, 17-byte LMP PDU injection/capture, controller memory read/write. Enables BLUFFS session key downgrade (CVE-2023-24023), encryption downgrade, and LMP-level DoS/fuzzing.
- **Extracts data** via PBAP (phonebook, call logs, favorites), MAP (SMS/MMS/email messages), AT commands (IMEI, IMSI, phonebook, SMS), and OBEX Object Push — all without user awareness on the IVI.
- **Hijacks connections** by impersonating a paired phone (MAC + name + device class cloning) to access the IVI without re-pairing. Supports BIAS (CVE-2020-10135) role-switch authentication bypass via software or DarkFirmware LMP injection.
- **Downgrades pairing and encryption** by forcing SSP to legacy PIN mode and brute-forcing the PIN (0000-9999), executing KNOB (CVE-2019-9506) to negotiate minimum key entropy, BLUFFS (CVE-2023-24023) to downgrade session key derivation, or encryption downgrade to disable/weaken link encryption entirely.
- **Intercepts audio** through HFP (call audio capture, DTMF injection, call control) and A2DP (media stream capture, microphone eavesdropping, audio playback injection).
- **Controls media** via AVRCP — play, pause, skip, volume manipulation, metadata surveillance. Skip flooding and volume ramp for DoS demonstration.
- **Fuzzes 12 Bluetooth protocols** (including LMP via DarkFirmware) with a response-guided, state-aware fuzzing engine featuring 6 layers of intelligence: protocol state inference (AFLNet-adapted), anomaly-guided field mutation weights, structural PDU validation, timing-based coverage proxy, entropy-based leak detection, and watchdog reboot detection. 4 strategies: coverage-guided, state-machine, random-walk, and targeted CVE reproduction. Live dashboard with real-time crash tracking.
- **Sniffs LMP traffic** via DarkFirmware — captures incoming LMP packets at the link layer for protocol analysis, pairing negotiation inspection, and security research. Combined BLE + LMP monitoring with nRF52840.
- **Manages crashes** with SQLite-backed crash database, severity classification, reproduction verification, payload minimization (binary search + delta debugging + field-level reduction), and evidence export.
- **Generates reports** in HTML and JSON with executive summary, SVG charts, vulnerability findings with evidence, fuzzing intelligence analysis, crash details with hexdumps and reproduction steps, and data extraction summaries. All session commands are automatically logged as evidence.

**Who it's for:** Automotive security researchers, OEM/Tier-1 security teams, red teams testing vehicle connectivity systems, and security researchers studying Bluetooth protocol vulnerabilities.

> **Authorization requirement:** Blue-Tap is designed exclusively for authorized security testing. You must have explicit written permission from the vehicle/device owner before conducting any assessment. Unauthorized use is illegal.

---

## Architecture

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

---

## Features

Full command reference and examples: **[docs/features.md](docs/features.md)**

- **Discovery and Scanning** — Classic + BLE scanning, device class decoding, manufacturer ID, RSSI distance estimation, fleet-wide scan
- **Reconnaissance** — SDP browse, fingerprinting (BT version, chipset, LMP features), RFCOMM/L2CAP channel scan, GATT enumeration, HCI capture, LMP sniffing
- **Vulnerability Assessment** — 20+ CVE checks (KNOB, BIAS, BLUFFS, BlueBorne, BrakTooth, SweynTooth, PerfektBlue, Invalid Curve, CTKD) plus non-CVE exposure checks, all through `vulnscan`
- **Connection Hijacking and BIAS** — MAC/name/class cloning, BIAS role-switch bypass (CVE-2020-10135), auto-reconnect with per-phase rollback
- **KNOB Attack** — Negotiate minimum encryption key entropy (CVE-2019-9506), then brute force the reduced key space
- **SSP Downgrade** — Force SSP to legacy PIN mode, brute force PIN (0000-9999), lockout detection
- **BLUFFS Attack** — Session key derivation downgrade via DarkFirmware LMP injection (CVE-2023-24023, A1/A3 variants)
- **Encryption Downgrade** — Disable encryption, force renegotiation, reject Secure Connections (requires DarkFirmware)
- **CTKD** — Cross-transport key derivation (CVE-2020-15802), detect if Classic BT attack compromises BLE keys
- **Data Extraction** — PBAP (phonebook, call history), MAP (SMS/MMS), AT commands (IMEI/IMSI), OBEX file push
- **Audio Interception** — HFP call capture/injection/DTMF, A2DP media stream capture, mic eavesdropping, audio playback injection
- **AVRCP Media Control** — Play/pause/skip/volume, volume ramp, skip flood DoS, metadata surveillance
- **Protocol Fuzzing** — 12 protocols, 4 strategies, 6-layer intelligence, live dashboard, crash DB + minimization, PCAP replay, CVE reproduction
- **Denial of Service** — Modular registry-driven DoS runner with sequential execution, transport-aware recovery monitoring for Classic and BLE targets, per-check structured evidence, and manual single-check invocation via `dos run` / `dos check`
- **MAC Spoofing and Adapter Management** — 3 spoofing methods with fallback, full identity clone, persistent save/restore, adapter info/up/down/reset
- **Session Management and Reporting** — Auto-logging sessions, HTML/JSON reports with executive summary, SVG charts, crash hexdumps, fuzzing intelligence
- **DarkFirmware and Below-HCI Attacks** — RTL8761B LMP injection/monitoring, connection table inspection, in-flight LMP modification (6 modes), raw ACL injection, USB watchdog
- **Automation and Orchestration** — 9-phase auto pentest, YAML playbooks, run mode for command sequences

---

## Quick Start

**Prerequisites:** Linux (Kali, Ubuntu 22.04+, Debian), Python 3.10–3.13+, BlueZ 5.x, external USB Bluetooth adapter, root access.

**Recommended hardware:** A dedicated USB Bluetooth adapter is required for full-feature pentesting. Internal laptop adapters enforce Secure Simple Pairing and block MAC spoofing.

- **RTL8761B USB** (TP-Link UB500, ~$8) — Primary adapter. BT 5.0, MAC spoofing via firmware, DarkFirmware for BLUFFS/LMP injection. Handles both HCI and below-HCI attacks.
- **nRF52840 dongle** (~$10) — BLE raw PDU sniffing and pairing capture only.

**Installation:**

```bash
# Install system dependencies (Kali / Ubuntu / Debian)
sudo apt update
sudo apt install -y bluez bluez-tools python3-pip python3-dev python3-venv libbluetooth-dev

# Install Blue-Tap
pip install blue-tap

# Verify
blue-tap --version
blue-tap adapter list
```

Install from source:

```bash
git clone https://github.com/Indspl0it/blue-tap.git
cd blue-tap
pip install -e .
```

**Optional — enable BlueZ compatibility mode** (required for `sdptool` and certain SDP fuzzing):

```bash
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload && sudo systemctl restart bluetooth
sdptool browse local   # Should not show "Failed to connect to SDP server"
```

**Optional — DarkFirmware** (for below-HCI attacks with RTL8761B):

Blue-Tap auto-detects RTL8761B at startup and prompts to install DarkFirmware. Just plug in the adapter and run any command:

```bash
sudo blue-tap adapter list
# → "RTL8761B detected on hci1. DarkFirmware not installed. Install now? [y/N]"
```

Without DarkFirmware, all HCI-level attacks work normally. DarkFirmware is only needed for BLUFFS, encryption downgrade, LMP fuzzing, and LMP monitoring.

**First scan:**

```bash
sudo blue-tap adapter list          # Check adapter (DarkFirmware status shown automatically)
sudo blue-tap scan classic          # Discover nearby Bluetooth devices
sudo blue-tap recon sdp <MAC>       # SDP service discovery on target
sudo blue-tap vulnscan <MAC>        # Run vulnerability checks
```

> **Why `sudo`?** Most Blue-Tap functions require root for raw HCI/L2CAP/RFCOMM sockets, adapter control, btmon, and firmware VSC commands. Only `--version`, `--help`, and `demo` run without root. Alternative: grant `CAP_NET_RAW` with `sudo setcap cap_net_raw+eip $(which python3)`.

---

## Documentation

- **[Features](docs/features.md)** — Every command, option, and example for all feature categories
- **[Vulnscan CVE Matrix](docs/vulnscan-cve-matrix.md)** — Exact CVEs checked by `blue-tap vulnscan`
- **[DoS Guide](docs/dos-guide.md)** — DoS workflow, recovery model, pairing constraints, and reporting format
- **[DoS CVE Matrix](docs/dos-cve-matrix.md)** — Exact CVE-backed destructive checks registered in `blue-tap dos`
- **[Usage Guide](docs/usage-guide.md)** — Global options, command reference, and 9 complete pentest workflows
- **[Troubleshooting](docs/troubleshooting.md)** — Adapter, scanning, connection, SDP, fuzzing, audio, MAC spoofing, and report issues
- **[IVI Simulator and Demo](docs/ivi-simulator.md)** — Vulnerable IVI simulator setup, exposed services, built-in vulnerabilities, demo mode
- **[Changelog](docs/CHANGELOG.md)** — Version history with detailed release notes

---

## Credits and References

Blue-Tap builds on published academic research and open-source tools.

**Research papers:**

- **BLUFFS** — "BLUFFS: Bluetooth Forward and Future Secrecy Attacks and Defenses" — Daniele Antonioli, ACM CCS 2023
- **KNOB** — "The KNOB is Broken: Exploiting Low Entropy in the Encryption Key Negotiation of Bluetooth BR/EDR" — Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen, USENIX Security 2019
- **BIAS** — "BIAS: Bluetooth Impersonation AttackS" — Daniele Antonioli, Nils Ole Tippenhauer, Kasper Rasmussen, IEEE S&P 2020
- **BrakTooth** — "BrakTooth: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing" — Matheus E. Garbelini et al., USENIX Security 2022
- **SweynTooth** — "SweynTooth: Unleashing Mayhem over Bluetooth Low Energy" — Matheus E. Garbelini et al., USENIX ATC 2020
- **AFLNet** — "AFLNet: A Greybox Fuzzer for Network Protocols" — Van-Thuan Pham et al., ICST 2020
- **Invalid Curve** — "Invalid Curve Attack on Bluetooth Secure Simple Pairing" — Eli Biham, Lior Neumann
- **BlueBorne** — "BlueBorne: A New Attack Vector" — Ben Seri, Gregory Vishnepolsky, Armis Labs 2017
- **PerfektBlue** — "PerfektBlue: Bluetooth Vulnerabilities in OpenSynergy BlueSDK" — 2024

**Tools and firmware:**

- [DarkFirmware](https://github.com/darkmentorllc/DarkFirmware_real_i) — RTL8761B firmware patching for LMP injection/monitoring (darkmentorllc)
- [BlueZ](http://www.bluez.org/) — Linux Bluetooth protocol stack
- [Bleak](https://github.com/hbldh/bleak) — BLE GATT client library (Henrik Blidh)
- [InternalBlue](https://github.com/seemoo-lab/internalblue) — Broadcom/Cypress Bluetooth firmware tools (SEEMOO Lab, TU Darmstadt)
- [Crackle](https://github.com/mikeryan/crackle) — BLE pairing key cracking (Mike Ryan)

---

## Legal Disclaimer

Blue-Tap is provided for **authorized security testing and research purposes only**.

- You **must** have explicit written permission from the owner of any device you test
- Unauthorized access to Bluetooth devices is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar laws worldwide
- The authors accept no liability for misuse of this tool
- Always follow your organization's rules of engagement and scope limitations
- Report vulnerabilities responsibly to the affected manufacturer

**Responsible disclosure:** If you discover vulnerabilities in production IVI systems using Blue-Tap, follow coordinated disclosure practices. Contact the vehicle manufacturer's PSIRT before public disclosure.

---

## License

[GNU General Public License v3.0](LICENSE) — Copyright (C) 2026 Santhosh Ballikonda

---

**Santhosh Ballikonda** — [@Indspl0it](https://github.com/Indspl0it)
