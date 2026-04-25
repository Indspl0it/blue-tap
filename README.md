<p align="center">
  <img src="assets/banner.svg" alt="Blue-Tap Banner" width="100%"/>
</p>

<p align="center">
  <b>Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI Systems</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-green" alt="License GPL-3.0"/>
  <img src="https://img.shields.io/badge/version-2.6.2-orange" alt="Version 2.6.2"/>
  <img src="https://img.shields.io/badge/modules-101-cyan" alt="101 Modules"/>
  <img src="https://img.shields.io/badge/CVEs-37-red" alt="37 CVEs"/>
  <img src="https://img.shields.io/badge/platform-Linux%20(Kali)-557C94" alt="Linux"/>
</p>

<p align="center">
  <a href="https://Indspl0it.github.io/blue-tap/">Documentation</a> &middot;
  <a href="https://Indspl0it.github.io/blue-tap/guide/cli-reference/">CLI Reference</a> &middot;
  <a href="https://Indspl0it.github.io/blue-tap/cve/detection-matrix/">CVE Matrix</a> &middot;
  <a href="https://Indspl0it.github.io/blue-tap/changelog/">Changelog</a>
</p>

---

Blue-Tap is a Bluetooth Classic and BLE security assessment framework designed to find both known and unknown vulnerabilities in Bluetooth stacks. It targets automotive IVI systems, mobile devices, IoT endpoints, and embedded firmware — anything with a Bluetooth radio. 101 modules across 6 families cover the full pentest lifecycle from device discovery through 0-day hunting via protocol-aware fuzzing. A DarkFirmware capability on RTL8761B controllers extends testing below the HCI boundary into the Link Manager and Link Controller layers, reaching the 40-45% of the Bluetooth attack surface that host-only tools cannot see.

## Features

**Discovery & Reconnaissance** — Classic and BLE device scanning, SDP/GATT enumeration, L2CAP/RFCOMM channel probing, device fingerprinting, HCI capture, BLE/LMP sniffing, capability detection, and cross-probe correlation. [Guide](https://Indspl0it.github.io/blue-tap/guide/discovery/)

**Vulnerability Assessment** — 25 CVE detections (behavioral + compliance) and 11 non-CVE posture checks covering L2CAP, BNEP, SDP, AVRCP, GATT, HID, SMP, and pairing protocols. [CVE Matrix](https://Indspl0it.github.io/blue-tap/cve/detection-matrix/)

**Exploitation** — KNOB (CVE-2019-9506), BIAS (CVE-2020-10135), BLUFFS (CVE-2023-24023), CTKD (CVE-2020-15802), encryption downgrade, SSP downgrade, connection hijack, and PIN brute-force. [Guide](https://Indspl0it.github.io/blue-tap/guide/exploitation/)

**Denial of Service** — 9 CVE-backed crash probes and 21 protocol stress tests across L2CAP, SDP, RFCOMM, BNEP, HFP, OBEX, LMP, and pairing with automatic recovery monitoring. [DoS Matrix](https://Indspl0it.github.io/blue-tap/cve/dos-matrix/)

**Post-Exploitation** — Phonebook extraction (PBAP), message access (MAP), call audio (HFP), audio streaming (A2DP), media control (AVRCP), file push (OPP), Bluesnarfer (OBEX), and AT command probing. [Guide](https://Indspl0it.github.io/blue-tap/guide/post-exploitation/)

**Protocol Fuzzing** — 16-protocol mutation fuzzer with coverage-guided, state-machine, targeted, and random-walk strategies. Crash database, payload minimization, CVE reproduction, and live Rich dashboard. 6,685+ seeds. [Guide](https://Indspl0it.github.io/blue-tap/guide/fuzzing/)

**DarkFirmware (Below-HCI)** — RTL8761B firmware patching for LMP injection, link-layer monitoring, and controller memory R/W. Reaches the 40-45% of Bluetooth CVEs invisible to host-only tools. [Hardware Setup](https://Indspl0it.github.io/blue-tap/getting-started/hardware-setup/)

**Reporting & Sessions** — Professional HTML and JSON reports with 11 per-module adapters. Persistent sessions for multi-phase assessments. [Guide](https://Indspl0it.github.io/blue-tap/guide/sessions-and-reporting/)

## Installation

### Prerequisites

- Linux (Kali recommended)
- Python 3.10+
- BlueZ 5.50+ (`bluetoothctl`, `hcitool`, `btmon`)
- An **RTL8761B-based USB dongle** (e.g., TP-Link UB500) — Blue-Tap currently gates all live operations behind RTL8761B detection. Stock firmware is fine; DarkFirmware unlocks below-HCI features.
- Root privileges for Bluetooth operations

Inspection commands that work without root and without hardware: `--help`, `--version`, `doctor`, `demo`, `session list/show`, `search`, `info`, `show-options`, `plugins`. Everything else — including `report`, `fuzz crashes/corpus/minimize`, and `run-playbook --list` — currently still goes through the root + RTL8761B gate at startup; run them with `sudo` on a host that has an RTL8761B dongle attached.

```text
$ blue-tap report ./sessions/example
  ✖  Blue-Tap requires root for Bluetooth operations.
```

> Tightening the root gate so the read-only inspection paths above can run unprivileged is on the v2.6.3 backlog.

### Via PyPI

```bash
pip install blue-tap
```

### From Source

```bash
git clone https://github.com/Indspl0it/blue-tap.git
cd blue-tap
pip install -e .
```

### Verify Installation

```bash
blue-tap --version          # prints 'blue-tap, version 2.6.2'
blue-tap doctor             # check prerequisites — no root, no hardware needed
blue-tap session list       # list past sessions — no root, no hardware needed
blue-tap demo               # full pipeline against simulated data — no hardware needed
sudo blue-tap adapter list  # enumerate live HCI adapters (needs root + RTL8761B)
```

See the full [Installation Guide](https://Indspl0it.github.io/blue-tap/getting-started/installation/) for detailed setup, including DarkFirmware flashing.

## Usage

Blue-Tap follows a phase-verb workflow that mirrors a real-world Bluetooth pentest:

```
discover  →  recon  →  vulnscan  →  exploit  →  dos  →  extract  →  fuzz  →  report
```

### Quick Start

```bash
# 1. Find nearby Bluetooth devices
sudo blue-tap discover classic -d 20

# 2. Deep recon on a target
sudo blue-tap recon 4C:4F:EE:17:3A:89 sdp
sudo blue-tap recon 4C:4F:EE:17:3A:89 fingerprint

# 3. Scan for vulnerabilities (25 CVE + 11 posture checks)
sudo blue-tap vulnscan 4C:4F:EE:17:3A:89

# 4. Exploit a confirmed vulnerability
sudo blue-tap exploit 4C:4F:EE:17:3A:89 knob --yes

# 5. Extract data post-exploitation
sudo blue-tap extract 4C:4F:EE:17:3A:89 contacts --all

# 6. Generate HTML report
blue-tap report --format html --output report.html
```

### Automation

```bash
# Full automated assessment against a single target
sudo blue-tap auto 4C:4F:EE:17:3A:89 --yes

# Fleet scan — discover and assess all IVI devices in range
sudo blue-tap fleet --duration 20 --class ivi

# Run a bundled playbook (see `blue-tap run-playbook --list` for all)
sudo blue-tap run-playbook --playbook ivi-attack 4C:4F:EE:17:3A:89
```

### Fuzzing

```bash
# Multi-protocol fuzzing campaign (needs hardware)
sudo blue-tap fuzz campaign 4C:4F:EE:17:3A:89 -p sdp -p rfcomm --duration 2h

# Crash analysis (reads on-disk crash database, but the CLI still asks for
# root + RTL8761B at startup — run with sudo until the gate is loosened)
sudo blue-tap fuzz crashes list --protocol sdp --severity HIGH
sudo blue-tap fuzz crashes show CRASH_ID
sudo blue-tap fuzz crashes export -o crashes.json

# Get help for any fuzz subcommand
blue-tap fuzz crashes --help
blue-tap fuzz campaign --help
```

See the full [CLI Reference](https://Indspl0it.github.io/blue-tap/guide/cli-reference/) for all commands and options.

## Documentation

Full documentation is hosted at **[Indspl0it.github.io/blue-tap](https://Indspl0it.github.io/blue-tap/)**

| Section | Description |
|---------|-------------|
| [Getting Started](https://Indspl0it.github.io/blue-tap/getting-started/installation/) | Installation, hardware setup, quick start |
| [CLI Reference](https://Indspl0it.github.io/blue-tap/guide/cli-reference/) | Every command, option, and example |
| [CVE Detection Matrix](https://Indspl0it.github.io/blue-tap/cve/detection-matrix/) | 37 CVEs across vulnscan, exploitation, and DoS |
| [DoS Matrix](https://Indspl0it.github.io/blue-tap/cve/dos-matrix/) | 30 DoS checks with severity and recovery monitoring |
| [Workflows](https://Indspl0it.github.io/blue-tap/workflows/full-pentest/) | End-to-end pentest recipes |
| [Developer Guide](https://Indspl0it.github.io/blue-tap/developer/architecture/) | Architecture, module system, writing modules, plugins |
| [Troubleshooting](https://Indspl0it.github.io/blue-tap/reference/troubleshooting/) | Common issues and fixes |
| [Changelog](https://Indspl0it.github.io/blue-tap/changelog/) | Release history |

## Legal Disclaimer

Blue-Tap is provided for **authorized security testing and research purposes only**. You must have explicit written permission from the owner of any device you test. Unauthorized access to Bluetooth devices is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar laws worldwide. The authors accept no liability for misuse. Report vulnerabilities responsibly to the affected manufacturer.

## License

[GNU General Public License v3.0](LICENSE)

---

**Santhosh Ballikonda** — [@Indspl0it](https://github.com/Indspl0it)
