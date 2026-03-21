# Vulnerable IVI Simulator

A real Bluetooth target that behaves like an intentionally vulnerable car infotainment
system. Runs on any Linux machine (Kali laptop, Raspberry Pi, Ubuntu desktop) with a
Bluetooth adapter. Designed as the companion test target for [Blue-Tap](../README.md).

This is **not a mock** — it uses real BlueZ Bluetooth stack, broadcasts over the air,
accepts real connections, and speaks real OBEX/AT/GATT protocols.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Architecture](#architecture)
- [Exposed Services](#exposed-services)
- [Intentional Vulnerabilities](#intentional-vulnerabilities)
- [Testing with Blue-Tap](#testing-with-blue-tap)
- [Hijack Test Scenario](#hijack-test-scenario)
- [File Reference](#file-reference)
- [Configuration](#configuration)
- [Platform Notes](#platform-notes)
- [Troubleshooting](#troubleshooting)

---

## Requirements

### Hardware

- Any Linux machine with a Bluetooth adapter (internal or USB)
- A second machine running Blue-Tap (the attacker)
- Both within ~10 meters Bluetooth range

### Software

- Linux kernel with Bluetooth support (all major distros)
- BlueZ 5.x (Bluetooth stack)
- Python 3.10+
- D-Bus Python bindings
- PyGObject (for BLE GATT server only)

### Supported Platforms

| Platform | Architecture | Typical Adapter | Notes |
|----------|-------------|-----------------|-------|
| Kali Linux laptop | x86_64 | Intel AX200/210 | SSP may be enforced (auto-detected) |
| Raspberry Pi 5 | arm64 | Broadcom BCM43xx | SSP usually disableable |
| Raspberry Pi 4 | arm64 | Broadcom BCM43455 | BT 5.0, dual-mode |
| Raspberry Pi 3 | arm64 | Broadcom BCM43438 | BT 4.2, dual-mode |
| Ubuntu/Debian | x86_64 | Any | Internal or USB dongle |
| Any Linux + USB dongle | any | CSR8510, BCM20702 | ~$5 option |

---

## Installation

### 1. Install system dependencies

**Kali / Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y bluez bluez-tools python3-dbus python3-gi
```

**Raspberry Pi OS (Bookworm):**
```bash
sudo apt update
sudo apt install -y bluez python3-dbus python3-gi
# bluez-tools if available:
sudo apt install -y bluez-tools 2>/dev/null || true
```

**Verify tools are available:**
```bash
which hciconfig hcitool sdptool btmgmt bluetoothctl
# All 5 should print paths
```

### 2. Enable BlueZ compatibility mode (required for sdptool)

Modern BlueZ disables the SDP server by default. You need the `--compat` flag:

```bash
# Edit the bluetooth service
sudo nano /lib/systemd/system/bluetooth.service

# Find the ExecStart line and add --compat:
# ExecStart=/usr/libexec/bluetooth/bluetoothd --compat
# (or on some distros: ExecStart=/usr/lib/bluetooth/bluetoothd --compat)

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

Verify it works:
```bash
sdptool browse local
# Should NOT print "Failed to connect to SDP server"
```

### 3. Generate test data

```bash
cd target/
python3 data/gen_data.py
```

This creates 50 contacts, 45 call history entries, 20 SMS messages, and AT command
data files — all from a deterministic seed (reproducible across runs).

---

## Quick Start

You need **3 terminals** on the IVI machine. All commands run from the `target/` directory.

**Terminal 1 — Setup adapter (run once):**
```bash
cd target/
sudo ./setup_ivi.sh
```

**Terminal 2 — Pairing agent (keep running):**
```bash
cd target/
sudo python3 pin_agent.py
```

**Terminal 3 — IVI daemon (keep running):**
```bash
cd target/
sudo python3 ivi_daemon.py
```

**Optional Terminal 4 — BLE GATT server:**
```bash
cd target/
sudo python3 ble_gatt.py
```

The IVI is now live. From the attacker machine:
```bash
blue-tap scan classic
# Should show "SYNC" with device class Car Audio
```

### Stopping

- `Ctrl+C` in each terminal
- To undo adapter changes: `sudo ./setup_ivi.sh reset`

---

## Detailed Usage

### setup_ivi.sh

Configures the Bluetooth adapter to look like a Car Audio device.

```bash
# Auto-detect best profile (recommended)
sudo ./setup_ivi.sh

# Force legacy PIN pairing (if adapter supports SSP-off)
sudo ./setup_ivi.sh legacy

# Force SSP / Just Works pairing
sudo ./setup_ivi.sh ssp

# Dry-run: show what would happen, don't change anything
sudo ./setup_ivi.sh detect

# Undo all changes
sudo ./setup_ivi.sh reset

# Custom phone MAC for hijack testing
sudo ./setup_ivi.sh auto 11:22:33:44:55:66

# Custom adapter
sudo ./setup_ivi.sh auto AA:BB:CC:DD:EE:FF hci1
```

**What it does:**
1. Sets adapter name to "SYNC" and device class to 0x200408 (Car Audio)
2. Makes adapter discoverable + connectable
3. Auto-detects SSP capability and selects legacy or SSP profile
4. Registers 8 SDP service records (PBAP, MAP, OPP, HFP, SP, DUN, NAP, PANU)
5. Enables BLE advertising
6. Creates a pre-paired phone bond for hijack testing
7. Saves config to `.ivi_profile`, `.ivi_adapter`, `.ivi_phone`

### ivi_daemon.py

The main process that listens on all Bluetooth channels.

```bash
# Default
sudo python3 ivi_daemon.py

# With options
sudo python3 ivi_daemon.py --hci hci1          # Different adapter
sudo python3 ivi_daemon.py --verbose            # Show OBEX hex dumps
sudo python3 ivi_daemon.py --quiet              # Suppress info messages
sudo python3 ivi_daemon.py --no-l2cap           # Skip L2CAP listeners
sudo python3 ivi_daemon.py --data-dir /path/to  # Custom data directory
```

**What it listens on:**
- RFCOMM channel 1 (SPP) — AT command responder
- RFCOMM channel 2 (Hidden) — Not in SDP, responds to probes
- RFCOMM channel 9 (OPP) — OBEX file push receiver
- RFCOMM channel 10 (HFP) — AT command responder (HFP SLC)
- RFCOMM channel 15 (PBAP) — OBEX phonebook server
- RFCOMM channel 16 (MAP) — OBEX message server
- L2CAP PSM 7, 23, 25 — Fuzz absorbers

### pin_agent.py

Handles pairing requests from remote devices.

```bash
sudo python3 pin_agent.py
sudo python3 pin_agent.py --hci hci1
```

**Behavior:**
- New devices requesting pairing → responds with PIN "1234"
- SSP confirmations → auto-accepts (Just Works)
- Service authorization → only allows bonded devices
- Spoofed phone MAC → auto-authorized (bonded device reconnecting)

### ble_gatt.py

BLE GATT server for `blue-tap recon gatt` testing.

```bash
sudo python3 ble_gatt.py
sudo python3 ble_gatt.py --hci hci1
```

**Advertises:**
- Device Information Service (0x180A): Manufacturer, Model, Firmware, PnP ID
- Battery Service (0x180F): Level=85%, notifiable
- Custom IVI Service: Vehicle Speed, Diagnostics (read+write), OTA Update (write, no auth)

### data/gen_data.py

Regenerate test data with different parameters.

```bash
python3 data/gen_data.py                    # Default: 50 contacts, 20 messages
python3 data/gen_data.py --seed 99          # Different random seed
python3 data/gen_data.py --contacts 100     # More contacts
python3 data/gen_data.py --messages 30      # More messages
python3 data/gen_data.py --clean            # Delete existing before regenerating
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  IVI Machine (Kali / Pi / Desktop)                           │
│                                                              │
│  setup_ivi.sh          ivi_daemon.py                         │
│  ┌──────────────┐      ┌──────────────────────────────────┐  │
│  │ hciconfig     │      │ RFCOMM Listeners                 │  │
│  │ btmgmt        │      │  ch1  → SPPResponder (AT)        │  │
│  │ sdptool       │      │  ch2  → Hidden absorber          │  │
│  │ bluetoothctl  │      │  ch9  → OPPSession (OBEX)        │  │
│  └──────────────┘      │  ch10 → HFPResponder (AT)        │  │
│                         │  ch15 → PBAPSession (OBEX)       │  │
│  pin_agent.py           │  ch16 → MAPSession (OBEX)        │  │
│  ┌──────────────┐      ├──────────────────────────────────┤  │
│  │ D-Bus Agent   │      │ L2CAP Listeners                  │  │
│  │ PIN: 1234     │      │  PSM 7, 23, 25 → absorbers      │  │
│  │ Bond check    │      └──────────────────────────────────┘  │
│  └──────────────┘                                            │
│                         ble_gatt.py                           │
│  data/                  ┌──────────────────────────────────┐  │
│  ┌──────────────┐      │ Device Info + Battery + Custom    │  │
│  │ phonebook.vcf │      │ LE Advertisement: "SYNC"          │  │
│  │ ich/och/mch   │      └──────────────────────────────────┘  │
│  │ messages/     │                                            │
│  │ at_*.txt      │                                            │
│  └──────────────┘                                            │
└──────────────────────────────────────────────────────────────┘
                    ~~~~ Bluetooth Air ~~~~
┌──────────────────────────────────────────────────────────────┐
│  Attacker Machine                                            │
│  blue-tap scan / recon / pbap / map / hfp / vuln-scan / ...    │
└──────────────────────────────────────────────────────────────┘
```

---

## Exposed Services

| Service | Channel/PSM | Protocol | Canned Data |
|---------|-------------|----------|-------------|
| PBAP (Phonebook) | RFCOMM 15 | OBEX | 50 vCard contacts, call history (ich/och/mch/cch) |
| MAP (Messages) | RFCOMM 16 | OBEX | 20 SMS across inbox/sent/draft/deleted |
| OPP (Object Push) | RFCOMM 9 | OBEX | Accepts any pushed file, saves to `received/` |
| HFP (Hands-Free) | RFCOMM 10 | AT commands | Full SLC handshake, call control, codec negotiation |
| SPP (Serial Port) | RFCOMM 1 | AT commands | Phonebook, SMS, IMEI, IMSI, battery, signal |
| Hidden Debug | RFCOMM 2 | AT probe | Not in SDP — triggers vuln-scan hidden-service finding |
| BNEP (PAN) | L2CAP 7 | Absorb | Accepts + absorbs any data (fuzz target) |
| AVCTP (AVRCP) | L2CAP 23 | Absorb | Accepts + absorbs any data (fuzz target) |
| AVDTP (A2DP) | L2CAP 25 | Absorb | Accepts + absorbs any data (fuzz target) |
| BLE Device Info | GATT 0x180A | BLE | Manufacturer, Model, Firmware, PnP ID |
| BLE Battery | GATT 0x180F | BLE | Level=85%, notifiable |
| BLE Custom IVI | GATT custom | BLE | Speed, Diagnostics (r/w), OTA (write, no auth) |

---

## Intentional Vulnerabilities

| Vulnerability | What it simulates | Blue-Tap command that finds it |
|---------------|-------------------|------------------------------|
| Unauthenticated OBEX | PBAP/MAP accept without auth challenge | `blue-tap vuln-scan` → CRITICAL |
| Legacy PIN "1234" | Weak 4-digit PIN pairing | `blue-tap pin-brute` |
| Just Works pairing | SSP with no confirmation (auto-accept) | `blue-tap vuln-scan` → HIGH |
| No PIN lockout | Unlimited pairing attempts | `blue-tap vuln-scan` → MEDIUM |
| Hidden RFCOMM | Channel 2 open but not in SDP | `blue-tap vuln-scan` → MEDIUM |
| Permissive AT | Unknown AT commands return OK | Bluesnarfer/HFP testing |
| Open BLE writes | OTA Update char writable without auth | `blue-tap recon gatt` |
| Hijack-vulnerable | Pre-paired bond without link key verification | `blue-tap hijack` |

---

## Testing with Blue-Tap

Once the IVI is running, from the **attacker machine**:

### Discovery & Reconnaissance
```bash
blue-tap scan classic                         # Find "SYNC" Car Audio device
blue-tap recon sdp <IVI_MAC>                  # 8+ SDP service records
blue-tap recon fingerprint <IVI_MAC>          # BT version, chipset, profiles
blue-tap recon rfcomm-scan <IVI_MAC>          # Channels 1,2,9,10,15,16 open
blue-tap recon l2cap-scan <IVI_MAC>           # PSMs 1,3,7,23,25 open
blue-tap recon gatt <IVI_MAC>                 # BLE services (requires ble_gatt.py)
```

### Data Extraction
```bash
blue-tap pbap pull <IVI_MAC>                  # Download 50 contacts + call logs
blue-tap map pull <IVI_MAC>                   # Download 20 SMS messages
blue-tap opp push <IVI_MAC> test.vcf          # Push a file (saved in target/received/)
```

### HFP & AT Commands
```bash
blue-tap hfp setup <IVI_MAC>                  # Establish SLC (5-step AT handshake)
# HFP commands: COPS, CNUM, VGS, ATD, etc.
```

### Vulnerability Assessment
```bash
blue-tap vuln-scan <IVI_MAC>                  # Full vulnerability scan (6+ findings)
```

### PIN Brute Force
```bash
blue-tap pin-brute <IVI_MAC>                  # Finds PIN 1234 (legacy mode only)
```

### Fuzzing
```bash
blue-tap fuzz <IVI_MAC>                       # L2CAP + RFCOMM fuzzing
# IVI daemon absorbs all fuzz data without crashing
```

---

## Hijack Test Scenario

The simulator pre-pairs a fake phone (default `AA:BB:CC:DD:EE:FF`) to simulate a
car that has a phone already paired. The hijack attack tests whether spoofing that
phone's MAC address grants access without re-pairing.

### Setup
```bash
# On IVI machine — setup with specific phone MAC
sudo ./setup_ivi.sh auto 11:22:33:44:55:66
sudo python3 pin_agent.py
sudo python3 ivi_daemon.py
```

### Attack (from attacker machine)
```bash
# 1. Discover the IVI
blue-tap scan classic
# → sees "SYNC" at XX:XX:XX:XX:XX:XX

# 2. Spoof the pre-paired phone's MAC
blue-tap spoof mac 11:22:33:44:55:66

# 3. Run full hijack chain
blue-tap hijack XX:XX:XX:XX:XX:XX 11:22:33:44:55:66
# → Recon phase: fingerprint + SDP
# → Impersonate phase: MAC already spoofed
# → Connect phase: IVI sees bonded phone → auto-authorizes
# → Extract phase: PBAP/MAP data pulled without new pairing
```

### What proves the attack works
- Connecting **without** spoofing the phone MAC → service authorization **rejected**
- Connecting **with** the correct spoofed MAC → auto-authorized, data extracted

---

## File Reference

```
target/
├── setup_ivi.sh            # BlueZ adapter configuration (388 lines)
├── ivi_daemon.py           # Main daemon — RFCOMM + L2CAP listeners (482 lines)
├── pin_agent.py            # D-Bus pairing agent — PIN + bond gating (193 lines)
├── ble_gatt.py             # BLE GATT server — 3 services (621 lines)
├── ivi_config.py           # Shared constants — channels, UUIDs, opcodes (190 lines)
├── ivi_log.py              # Colorized thread-safe logger (168 lines)
├── obex_engine.py          # OBEX binary protocol engine (682 lines)
├── obex_servers.py         # PBAP + MAP + OPP session handlers (478 lines)
├── at_engine.py            # HFP + SPP AT command responders (405 lines)
├── received/               # OPP received files land here
├── data/
│   ├── gen_data.py         # Data generator script (589 lines)
│   ├── phonebook.vcf       # 50 vCard 2.1 contacts
│   ├── ich.vcf             # 20 incoming call history entries
│   ├── och.vcf             # 15 outgoing call history entries
│   ├── mch.vcf             # 10 missed call history entries
│   ├── cch.vcf             # 45 combined call history (sorted)
│   ├── at_phonebook.txt    # AT+CPBR format phonebook
│   ├── at_sms.txt          # AT+CMGL format SMS messages
│   └── messages/
│       ├── inbox/          # 10 bMessage files (0001-0010.bmsg)
│       ├── sent/           # 5 bMessage files (0011-0015.bmsg)
│       ├── draft/          # 3 bMessage files (0016-0018.bmsg)
│       ├── deleted/        # 2 bMessage files (0019-0020.bmsg)
│       ├── inbox_listing.xml   # MAP message listing XML
│       ├── sent_listing.xml
│       ├── draft_listing.xml
│       └── deleted_listing.xml
└── README.md               # This file
```

---

## Configuration

### Changing the IVI name
Edit `IVI_NAME` in `ivi_config.py` (default: "SYNC").

### Changing the PIN
Edit `DEFAULT_PIN` in `ivi_config.py` (default: "1234").

### Changing the pre-paired phone MAC
Pass as argument: `sudo ./setup_ivi.sh auto 11:22:33:44:55:66`

### Changing data size
```bash
python3 data/gen_data.py --contacts 100 --messages 50 --clean
```

### Using a different adapter
```bash
sudo ./setup_ivi.sh auto AA:BB:CC:DD:EE:FF hci1
sudo python3 pin_agent.py --hci hci1
sudo python3 ivi_daemon.py --hci hci1
sudo python3 ble_gatt.py --hci hci1
```

---

## Platform Notes

### Intel adapters (most laptops)
- SSP is typically enforced — setup auto-detects and uses Just Works profile
- PIN brute-force won't work (SSP prevents legacy PIN mode)
- All other attacks work normally
- MAC spoofing not supported (but the IVI doesn't need to spoof — only the attacker does)

### Raspberry Pi (Broadcom)
- SSP can usually be disabled — setup auto-detects and uses legacy PIN profile
- All attacks including PIN brute-force work
- BT 4.2 (Pi 3) triggers more vuln-scan findings (KNOB, BLURtooth)
- BT 5.2 (Pi 5) triggers fewer version-dependent findings

### USB dongles
- CSR8510 (~$5): Best for testing — supports legacy PIN, MAC spoofing, all features
- BCM20702: Good alternative
- RTL8761B: Works for most features

---

## Troubleshooting

### "Adapter not found"
```bash
# Check if adapter exists
hciconfig -a

# If blocked by rfkill
rfkill list bluetooth
rfkill unblock bluetooth

# If USB dongle not recognized
lsusb | grep -i bluetooth
```

### "SDP registration failed" / "Failed to connect to SDP server"
BlueZ needs `--compat` mode for sdptool:
```bash
# Find the service file
grep -r "bluetoothd" /lib/systemd/system/ /etc/systemd/system/

# Add --compat to ExecStart line
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service

# Reload
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

### "PSM bind failed: Permission denied"
Must run as root:
```bash
sudo python3 ivi_daemon.py
```

### "PSM already in use"
PSMs 1 (SDP) and 3 (RFCOMM) are held by bluetoothd — this is normal.
The IVI daemon skips them and logs a warning.

### "SSP cannot be disabled"
Intel adapters enforce SSP. The setup script auto-detects this:
```bash
sudo ./setup_ivi.sh detect
# Shows which profile will be selected and expected vuln-scan findings
```

### "No devices found" from attacker
```bash
# On IVI: verify discoverable
hciconfig hci0 | grep PSCAN
# Should show "UP RUNNING PSCAN ISCAN"

# On IVI: verify name
hciconfig hci0 name
# Should show "SYNC"
```

### BLE GATT not working
```bash
# Check LE is enabled
btmgmt info | grep -i le

# Some adapters need LE explicitly enabled
sudo btmgmt le on
```

### Daemon crashes on fuzz
The L2CAP/RFCOMM absorbers catch all exceptions. If the daemon crashes,
it's a bug — please report it.
