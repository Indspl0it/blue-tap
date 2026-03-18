# Vulnerable IVI Simulator — Implementation Plan

## Overview

A real Bluetooth device running on any Linux machine (x86_64 or arm64) that behaves like
an intentionally vulnerable car infotainment system. It broadcasts over the air, registers
real SDP services, accepts connections, and serves canned phonebook/SMS data — so BT-Tap
can attack it end-to-end from another machine.

This is NOT a mock. It's a real BlueZ-powered device that responds to real Bluetooth protocols.

## Platform Support

Runs on any Linux machine with BlueZ and a Bluetooth adapter:

| Platform | Architecture | Typical Adapter | Notes |
|---|---|---|---|
| **Kali laptop** | x86_64 | Intel AX200/210, Qualcomm, Realtek | Internal adapter, no dongle needed |
| **Raspberry Pi 5** | arm64 | Broadcom BCM43xx (built-in) | Built-in BT, no dongle needed |
| **Raspberry Pi 4** | arm64 | Broadcom BCM43455 (built-in) | Built-in BT, supports BLE + Classic |
| **Raspberry Pi 3** | arm64 | Broadcom BCM43438 (built-in) | BT 4.2, BLE + Classic |
| **Ubuntu/Debian desktop** | x86_64 | Varies (internal or USB) | Any adapter works |
| **Any Linux + USB dongle** | any | CSR8510, BCM20702, RTL8761B | Cheap ~$5 option |

**Zero hardware-specific code** — the setup script auto-detects the adapter and its
capabilities. No architecture checks, no chipset-specific paths.

## Hardware Requirements

- **Any Linux machine** with a Bluetooth adapter (internal or USB) running BlueZ
- Python 3.10+ with `dbus-python` and `PyGObject`
- **Second machine** (attacker) running BT-Tap with its own BT adapter
- Both machines within ~10m Bluetooth range

### Adapter Capabilities (auto-detected)

The IVI target only needs to **listen and accept connections** — it doesn't need MAC
spoofing (that's the attacker's job). Every BT adapter supports the operations we need:

| Capability | Required for IVI? | Support |
|---|---|---|
| Device Class change | Yes | All adapters (hciconfig) |
| Name change | Yes | All adapters |
| Discoverable + Connectable | Yes | All adapters |
| RFCOMM/L2CAP listen | Yes | All adapters |
| BLE advertising | Yes (for GATT) | All dual-mode adapters (BT 4.0+) |
| SSP disable | Nice-to-have | Varies — auto-detected |
| MAC spoofing | **No** (attacker does this) | N/A |
| SCO audio | Optional | Kernel `CONFIG_BT_SCO` |

The one variable is SSP. The setup script handles this with auto-detection:
- If SSP can be disabled → legacy PIN mode (more CVE findings)
- If SSP is enforced → Just Works mode (different CVE findings, still valuable)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Linux Machine (Vulnerable IVI) — laptop / Pi / desktop  │
│                                                         │
│  ┌──────────────────┐  ┌─────────────────────────────┐  │
│  │  setup_ivi.sh    │  │  Python IVI Daemon           │  │
│  │  - hciconfig     │  │  ivi_daemon.py               │  │
│  │  - sdptool       │  │                              │  │
│  │  - bluetoothctl  │  │  ┌─────────┐ ┌────────────┐ │  │
│  │  - btmgmt        │  │  │PBAP OBEX│ │MAP OBEX    │ │  │
│  │                  │  │  │Server   │ │Server      │ │  │
│  │  Configures:     │  │  │Ch 15    │ │Ch 16       │ │  │
│  │  - Device class  │  │  └─────────┘ └────────────┘ │  │
│  │  - Name          │  │  ┌─────────┐ ┌────────────┐ │  │
│  │  - SSP off       │  │  │OPP OBEX │ │HFP AT      │ │  │
│  │  - PIN "1234"    │  │  │Server   │ │Responder   │ │  │
│  │  - Page scan     │  │  │Ch 9     │ │Ch 10       │ │  │
│  │  - SDP records   │  │  └─────────┘ └────────────┘ │  │
│  │  - BLE adverts   │  │  ┌─────────┐ ┌────────────┐ │  │
│  └──────────────────┘  │  │SPP AT   │ │L2CAP       │ │  │
│                        │  │Server   │ │Listeners   │ │  │
│                        │  │Ch 1     │ │PSM 1,3,7...│ │  │
│                        │  └─────────┘ └────────────┘ │  │
│                        └─────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  BLE GATT Server (bluetoothctl / Python)         │   │
│  │  - Device Information Service (0x180A)            │   │
│  │  - Battery Service (0x180F)                       │   │
│  │  - Custom IVI Service (vendor UUID)               │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ~~~~ Bluetooth Air Interface ~~~~
┌─────────────────────────────────────────────────────────┐
│  Attacker Machine running BT-Tap                        │
│  bt-tap scan classic / recon sdp / pbap pull / etc.     │
└─────────────────────────────────────────────────────────┘
```

## What We're NOT Doing

- No kernel module hacking or custom BlueZ builds
- No SDR/USRP simulation (those attacks need real hardware)
- No real phone pairing simulation (no actual phone in the loop)
- No A2DP audio streaming sink (PulseAudio/PipeWire setup is too fragile for a test target; HFP AT + SCO is sufficient for audio testing)
- No InternalBlue firmware patching

## Desired End State

Running `sudo ./setup_ivi.sh && sudo python3 ivi_daemon.py` on the target machine turns it into a device that:

1. Is discoverable as "SYNC" (Ford-style) with device class Car Audio (0x200408)
2. Shows up in `bt-tap scan classic` with correct CoD and name
3. Returns 8+ SDP service records via `bt-tap recon sdp`
4. Has open RFCOMM channels 1, 9, 10, 15, 16 detectable by `bt-tap recon rfcomm-scan`
5. Has L2CAP PSMs 1, 3, 7, 23, 25 open for `bt-tap recon l2cap-scan`
6. Responds to PBAP OBEX GET with 50 canned vCard contacts + call history
7. Responds to MAP OBEX GET with 20 canned SMS messages across inbox/sent/draft
8. Accepts OPP OBEX PUT and logs received files
9. Responds to HFP AT commands (BRSF, CIND, CMER, ATD, etc.) with realistic AG responses
10. Responds to SPP/Bluesnarfer AT commands (CPBS, CPBR, CMGL, CGSN, etc.)
11. Accepts L2CAP connections for fuzzing without crashing
12. Uses legacy PIN pairing (PIN=1234) so `bt-tap pin-brute` can find it
13. Advertises BLE GATT services for `bt-tap recon gatt`
14. Allows unauthenticated OBEX Connect so vuln-scanner detects it as CRITICAL

### Verification

From the attacker machine, this full sequence should work:
```bash
bt-tap scan classic                              # sees "SYNC" Car Audio
bt-tap recon fingerprint <IVI_MAC>               # gets BT version, chipset, profiles
bt-tap recon sdp <IVI_MAC>                       # 8+ SDP records
bt-tap recon rfcomm-scan <IVI_MAC>               # channels 1,9,10,15,16 open
bt-tap recon l2cap-scan <IVI_MAC>                # PSMs 1,3,7,23,25 open
bt-tap recon gatt <IVI_MAC>                      # Device Info + Battery + Custom
bt-tap pbap pull <IVI_MAC>                       # downloads 50 contacts + call logs
bt-tap map pull <IVI_MAC>                        # downloads 20 SMS messages
bt-tap opp push <IVI_MAC> test.vcf               # file accepted
bt-tap hfp setup <IVI_MAC>                       # SLC established, AT commands work
bt-tap vuln-scan <IVI_MAC>                       # finds CRITICAL unauthenticated OBEX
bt-tap pin-brute <IVI_MAC>                       # finds PIN 1234
bt-tap fuzz <IVI_MAC>                            # L2CAP/RFCOMM fuzzing accepted
```

---

## Implementation Approach

Two deliverables:
1. **`setup_ivi.sh`** — Shell script that configures BlueZ (adapter name, class, SSP, SDP records, pairing agent, BLE adverts). Idempotent, re-runnable.
2. **`ivi_daemon.py`** — Single Python process that listens on multiple RFCOMM channels + L2CAP PSMs and handles OBEX/AT protocols with canned data.

Both live in a new `target/` directory in the BT-Tap repo.

---

## Phase 1: BlueZ Adapter Configuration (`setup_ivi.sh`)

### Overview
Auto-detect the internal BT adapter, configure it to look like a Car Audio device,
register SDP service records, and set up BLE advertising. Adapts to adapter capabilities.

### File: `target/setup_ivi.sh`

**What it does:**
```bash
#!/bin/bash
set -e

PROFILE="${1:-auto}"     # auto | legacy | ssp
PHONE_MAC="${2:-AA:BB:CC:DD:EE:FF}"
HCI="${3:-hci0}"

# ─── Step 0: Auto-detect adapter ───────────────────────────
echo "[*] Detecting Bluetooth adapter..."
if ! hciconfig "$HCI" > /dev/null 2>&1; then
    echo "[!] No adapter found at $HCI"
    echo "    Available adapters:"
    hciconfig -a | grep "^hci" || echo "    (none)"
    exit 1
fi

ADAPTER_INFO=$(hciconfig "$HCI")
ADAPTER_ADDR=$(echo "$ADAPTER_INFO" | grep -oP '(?<=BD Address: )[0-9A-F:]+')
CHIPSET=$(cat /sys/class/bluetooth/$HCI/device/modalias 2>/dev/null || echo "unknown")
echo "[+] Adapter: $HCI ($ADAPTER_ADDR)"
echo "[+] Chipset: $CHIPSET"

# ─── Step 1: Adapter identity ──────────────────────────────
hciconfig "$HCI" up
hciconfig "$HCI" name "SYNC"                      # Ford-style IVI name
hciconfig "$HCI" class 0x200408                    # Audio/Video: Car Audio
hciconfig "$HCI" piscan                            # Discoverable + connectable
echo "[+] Name=SYNC, Class=0x200408 (Car Audio), Discoverable"

# ─── Step 2: SSP configuration (auto-detect) ───────────────
IDX=$(echo "$HCI" | grep -oP '\d+')

if [ "$PROFILE" = "auto" ]; then
    # Try to disable SSP — if it works, use legacy mode; if not, use SSP/Just Works
    btmgmt --index "$IDX" ssp off 2>/dev/null
    sleep 0.5
    SSP_STATE=$(btmgmt --index "$IDX" info 2>/dev/null | grep -oP '(?<=ssp )(on|off)')
    if [ "$SSP_STATE" = "off" ]; then
        PROFILE="legacy"
        echo "[+] SSP disabled successfully → Legacy PIN mode"
    else
        PROFILE="ssp"
        echo "[!] Adapter enforces SSP (common on Intel) → Just Works mode"
    fi
fi

if [ "$PROFILE" = "legacy" ]; then
    btmgmt --index "$IDX" ssp off
    btmgmt --index "$IDX" bondable on
    echo "[+] Profile: LEGACY — PIN pairing (1234), CVE-2020-26555 testable"
elif [ "$PROFILE" = "ssp" ]; then
    btmgmt --index "$IDX" ssp on
    btmgmt --index "$IDX" io-cap NoInputNoOutput   # Forces Just Works
    btmgmt --index "$IDX" bondable on
    echo "[+] Profile: SSP — Just Works, BIAS/Invalid Curve testable"
fi

# ─── Step 3: Register pairing agent ────────────────────────
# Launched separately: python3 target/pin_agent.py

# ─── Step 4: Register SDP service records ───────────────────
sdptool add --channel=15 PBAP                    # Phonebook Access
sdptool add --channel=16 MAP                     # Message Access
sdptool add --channel=9  OPP                     # Object Push
sdptool add --channel=10 HFP                     # Hands-Free AG
sdptool add --channel=1  SP                      # Serial Port (SPP)
sdptool add --channel=3  DUN                     # Dialup Networking
sdptool add --channel=11 NAP                     # Network Access Point
sdptool add --channel=12 PANU                    # PAN User

# 5. BLE advertising via btmgmt or bluetoothctl
btmgmt --index 0 le on
# Register GATT services via separate Python script or bluetoothctl
```

**Pairing Agent** — `target/pin_agent.py`:
Realistic IVI pairing agent with proper trust gating:
- Implements `org.bluez.Agent1` interface
- Pre-paired "phone" (configurable MAC) is bonded + trusted in BlueZ
- **Legacy mode**: New devices need PIN "1234" to pair
- **SSP mode**: New devices get Just Works pairing (auto-accept, no PIN)
- Service authorization: only bonded devices get service access
- Hijack test: spoofing the pre-paired phone's MAC bypasses auth (the vulnerability)
- Agent adapts behavior based on which profile setup_ivi.sh detected

### Success Criteria

#### Automated:
- [ ] `hciconfig hci0` shows name "SYNC", class 0x200408, UP RUNNING PSCAN ISCAN
- [ ] `sdptool browse local` shows all 8 registered services
- [ ] `btmgmt --index 0 info` shows `le: on` and either `ssp: off` (legacy) or `ssp: on` (auto)
- [ ] `target/.ivi_profile` contains either "legacy" or "ssp"
- [ ] From attacker: `hcitool scan` discovers "SYNC" with correct address

#### Manual:
- [ ] From attacker: `bt-tap scan classic` shows device with Car Audio class
- [ ] From attacker: `bt-tap recon sdp <MAC>` returns 8+ service records

---

## Phase 2: Canned Data — Phonebook, SMS, Call History

### Overview
Create realistic fake data that the OBEX servers will serve.

### File: `target/data/phonebook.vcf`

50 vCard 2.1 contacts:
```
BEGIN:VCARD
VERSION:2.1
N:Smith;John;;;
FN:John Smith
TEL;CELL:+14155550101
TEL;WORK:+14155550102
EMAIL:john.smith@example.com
ADR;HOME:;;123 Main St;Springfield;IL;62701;US
END:VCARD
```

### File: `target/data/call_history.vcf`

Call logs (incoming/outgoing/missed) in vCard format per PBAP spec:
```
BEGIN:VCARD
VERSION:2.1
N:Smith;John
FN:John Smith
TEL:+14155550101
X-IRMC-CALL-DATETIME;RECEIVED:20260315T143022
END:VCARD
```

Separate files: `ich.vcf` (20 incoming), `och.vcf` (15 outgoing), `mch.vcf` (10 missed), `cch.vcf` (all combined).

### File: `target/data/messages/`

20 SMS messages in bMessage format:
```
BEGIN:BMSG
VERSION:1.0
STATUS:READ
TYPE:SMS_GSM
FOLDER:telecom/msg/inbox
BEGIN:VCARD
VERSION:2.1
FN:Jane Doe
TEL:+14155550201
N:Doe;Jane
END:VCARD
BEGIN:BENV
BEGIN:BBODY
CHARSET:UTF-8
LENGTH:45
BEGIN:MSG
Hey, are you picking up the kids today?
END:MSG
END:BBODY
END:BENV
END:BMSG
```

### File: `target/data/gen_data.py`

Script that generates all the above from a seed so it's reproducible.

### Success Criteria

#### Automated:
- [ ] `python3 target/data/gen_data.py` creates all data files without error
- [ ] `wc -l target/data/phonebook.vcf` shows ~50 contacts worth of lines
- [ ] `ls target/data/messages/inbox/` shows 10+ message files
- [ ] Each vCard parses: `python3 -c "open('target/data/phonebook.vcf').read().count('BEGIN:VCARD')"` = 50

---

## Phase 3: OBEX Server — PBAP + MAP + OPP (`ivi_daemon.py`)

### Overview
Python process that listens on RFCOMM channels 9, 15, 16 and speaks OBEX binary protocol, serving the canned data from Phase 2.

### File: `target/ivi_daemon.py` (OBEX portion)

**RFCOMM Listener Architecture:**
- Main thread spawns one `threading.Thread` per RFCOMM channel
- Each thread: `socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)` → `bind(("", channel))` → `listen(1)` → `accept()` loop
- On accept, spawns handler thread for that connection

**OBEX State Machine (per connection):**
```python
class OBEXHandler:
    def handle_connect(self, packet) -> bytes:
        # Parse Target header (0x46) to identify PBAP vs MAP vs OPP
        # Return 0xA0 Success + ConnectionID

    def handle_get(self, packet) -> bytes:
        # Parse Name header -> path (e.g., "telecom/pb.vcf")
        # Parse Type header -> content type
        # Parse AppParams -> max_count, offset, filter
        # Return Body/End-of-Body with vCard or message listing data

    def handle_setpath(self, packet) -> bytes:
        # Navigate folder structure for MAP
        # Return 0xA0 Success

    def handle_put(self, packet) -> bytes:
        # Accept file data for OPP
        # Log to target/received/ directory
        # Return 0xA0 Success

    def handle_disconnect(self, packet) -> bytes:
        # Return 0xA0 Success
```

**PBAP Server (channel 15) — What BT-Tap sends, what we respond:**

| BT-Tap Sends | Server Responds |
|---|---|
| OBEX Connect (0x80) + Target UUID `7961...9a66` | 0xA0 + ConnectionID + Who header |
| OBEX Get (0x83) Name=`telecom/pb.vcf` Type=`x-bt/phonebook` | 0xA0 + End-of-Body with phonebook.vcf content |
| OBEX Get Name=`telecom/ich.vcf` Type=`x-bt/phonebook` | 0xA0 + End-of-Body with ich.vcf |
| OBEX Get Name=`telecom/och.vcf` | 0xA0 + och.vcf |
| OBEX Get Name=`telecom/mch.vcf` | 0xA0 + mch.vcf |
| OBEX Get Name=`telecom/cch.vcf` | 0xA0 + cch.vcf |
| OBEX Disconnect (0x81) | 0xA0 |

For large responses (>4KB), chunk with Body (0x48) + Continue (0x90), final chunk with End-of-Body (0x49) + Success (0xA0).

**MAP Server (channel 16) — Same pattern:**

| BT-Tap Sends | Server Responds |
|---|---|
| OBEX Connect + Target UUID `bb58...9a66` | 0xA0 + ConnectionID |
| SetPath to `telecom/msg/inbox` | 0xA0 |
| Get Type=`x-bt/MAP-msg-listing` | 0xA0 + XML message listing |
| Get Name=`0001` Type=`x-bt/message` | 0xA0 + bMessage content |
| SetPath to `telecom/msg/sent` | 0xA0 |
| ... same pattern for sent/draft/deleted | ... |

**OPP Server (channel 9):**

| BT-Tap Sends | Server Responds |
|---|---|
| OBEX Connect (no Target UUID) | 0xA0 |
| PUT with Name + Body/End-of-Body | 0x90 Continue per chunk, 0xA0 on final |
| Disconnect | 0xA0 |

**Key Implementation Details:**
- All OBEX length fields are big-endian 16-bit, inclusive of header bytes
- Name headers are UTF-16-BE encoded with null terminator
- ConnectionID (0xCB) is a 4-byte big-endian value, echo it back on every response if the client sent one
- Target UUID header length = 3 + 16 = 19 bytes (HI + 2-byte length + 16-byte UUID)
- No authentication challenge — this is the "vulnerable" part

### Success Criteria

#### Automated:
- [ ] `python3 target/ivi_daemon.py &` starts without error
- [ ] `sudo lsof -i -P | grep RFCOMM` shows listening on channels 9, 15, 16
- [ ] From attacker: `bt-tap recon rfcomm-scan <MAC>` shows channels 9, 15, 16 as OPEN (obex)

#### Manual:
- [ ] `bt-tap pbap pull <MAC>` downloads phonebook with 50 contacts
- [ ] `bt-tap map pull <MAC>` downloads messages from inbox/sent
- [ ] `bt-tap opp push <MAC> test.vcf` succeeds, file appears in `target/received/`
- [ ] `bt-tap vuln-scan <MAC>` reports CRITICAL: Unauthenticated OBEX Access

---

## Phase 4: HFP AT Command Responder

### Overview
Listen on RFCOMM channel 10 and respond to AT commands like an HFP Audio Gateway.

### File: `target/ivi_daemon.py` (HFP portion)

**AT Response Table:**

| BT-Tap Sends | Server Responds | Notes |
|---|---|---|
| `AT+BRSF=127\r` | `\r\n+BRSF: 495\r\n\r\nOK\r\n` | AG features = EC/NR + 3-way + CLIP + voice rec + reject + enhanced status + enhanced control + codec neg |
| `AT+CIND=?\r` | `\r\n+CIND: ("service",(0-1)),("call",(0-1)),("callsetup",(0-3)),("callheld",(0-2)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5))\r\n\r\nOK\r\n` | 7 standard indicators |
| `AT+CIND?\r` | `\r\n+CIND: 1,0,0,0,4,0,5\r\n\r\nOK\r\n` | service=1, no call, signal=4, battery=5 |
| `AT+CMER=3,0,0,1\r` | `\r\nOK\r\n` | Enable indicator reporting |
| `AT+CHLD=?\r` | `\r\n+CHLD: (0,1,2,3,4)\r\n\r\nOK\r\n` | All hold features supported |
| `ATD...;\r` | `\r\nOK\r\n` | Accept dial (log the number) |
| `AT+CHUP\r` | `\r\nOK\r\n` | Hangup |
| `ATA\r` | `\r\nOK\r\n` | Answer |
| `AT+CLCC\r` | `\r\nOK\r\n` | No active calls |
| `AT+COPS?\r` | `\r\n+COPS: 0,0,"T-Mobile"\r\n\r\nOK\r\n` | Network operator |
| `AT+CNUM\r` | `\r\n+CNUM: ,"+14155559999",145,,4\r\n\r\nOK\r\n` | Subscriber number |
| `AT+VGS=<n>\r` | `\r\nOK\r\n` | Volume set |
| `AT+VGM=<n>\r` | `\r\nOK\r\n` | Mic volume |
| `AT+NREC=0\r` | `\r\nOK\r\n` | Disable NREC |
| `AT+BVRA=<n>\r` | `\r\nOK\r\n` | Voice recognition |
| `AT+BAC=1,2\r` | `\r\n+BCS:1\r\n\r\nOK\r\n` | Select CVSD codec |
| `AT+CLIP=1\r` | `\r\nOK\r\n` | Enable caller ID |
| `AT+VTS=<d>\r` | `\r\nOK\r\n` | DTMF accepted |
| Unknown `AT+...\r` | `\r\nOK\r\n` | Default: accept everything |

**Implementation:**
```python
class HFPResponder:
    def handle_at(self, command: str) -> str:
        cmd = command.strip()
        if cmd.startswith("AT+BRSF="):
            return "\r\n+BRSF: 495\r\n\r\nOK\r\n"
        elif cmd == "AT+CIND=?":
            return "\r\n+CIND: (\"service\",(0-1)),(\"call\",(0-1)),...\r\n\r\nOK\r\n"
        # ... pattern match each command
        else:
            return "\r\nOK\r\n"  # Accept everything (vulnerable!)
```

### Success Criteria

#### Automated:
- [ ] Channel 10 shows as OPEN (at_modem) in rfcomm-scan

#### Manual:
- [ ] `bt-tap hfp setup <MAC>` establishes SLC successfully
- [ ] `bt-tap hfp` AT commands (COPS, CNUM, VGS) return realistic data

---

## Phase 5: SPP / Bluesnarfer AT Responder

### Overview
Listen on RFCOMM channel 1 (SPP) and respond to AT commands for phonebook/SMS extraction (bluesnarfer attack path).

### File: `target/ivi_daemon.py` (SPP portion)

**AT Response Table:**

| Command | Response | Notes |
|---|---|---|
| `AT+CPBS="ME"\r` | `\r\nOK\r\n` | Select phone memory |
| `AT+CPBR=1,200\r` | `\r\n+CPBR: 1,"+14155550101",145,"John Smith"\r\n+CPBR: 2,...\r\n\r\nOK\r\n` | Return phonebook entries from canned data |
| `AT+CPBS=?\r` | `\r\n+CPBS: ("ME","SM","DC","RC","MC")\r\n\r\nOK\r\n` | Available memories |
| `AT+CMGF=1\r` | `\r\nOK\r\n` | Text mode |
| `AT+CMGL="ALL"\r` | `\r\n+CMGL: 1,"REC READ","+14155550201",,"26/03/15,14:30:22+00"\r\nHey there\r\n...\r\nOK\r\n` | List SMS messages |
| `AT+CGSN\r` | `\r\n351234567890123\r\n\r\nOK\r\n` | Fake IMEI |
| `AT+CIMI\r` | `\r\n310260123456789\r\n\r\nOK\r\n` | Fake IMSI |
| `AT+CNUM\r` | `\r\n+CNUM: ,"+14155559999",145\r\n\r\nOK\r\n` | Phone number |
| `AT+CBC\r` | `\r\n+CBC: 0,85\r\n\r\nOK\r\n` | Battery 85% |
| `AT+CSQ\r` | `\r\n+CSQ: 22,99\r\n\r\nOK\r\n` | Signal strength |
| `AT+COPS?\r` | `\r\n+COPS: 0,0,"T-Mobile"\r\n\r\nOK\r\n` | Operator |

### Success Criteria

#### Manual:
- [ ] Channel 1 shows as OPEN (at_modem) in rfcomm-scan
- [ ] Bluesnarfer module extracts phonebook entries and IMEI

---

## Phase 6: L2CAP Listeners (Fuzz Targets)

### Overview
Accept L2CAP connections on standard PSMs so the fuzzer and L2CAP scanner find them open.

### File: `target/ivi_daemon.py` (L2CAP portion)

**PSMs to listen on:**
- PSM 1 (SDP) — already handled by bluetoothd, no extra listener needed
- PSM 3 (RFCOMM) — already handled by bluetoothd
- PSM 7 (BNEP/PAN) — register via BlueZ or raw listener
- PSM 23 (AVCTP) — listen + accept + absorb data
- PSM 25 (AVDTP) — listen + accept + absorb data

**Implementation:**
```python
def l2cap_listener(psm: int):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.bind(("", psm))
    sock.listen(1)
    while True:
        conn, addr = sock.accept()
        # Absorb all data without crashing (fuzz target)
        threading.Thread(target=absorb_data, args=(conn,)).start()

def absorb_data(conn):
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
    except Exception:
        pass
    finally:
        conn.close()
```

### Success Criteria

#### Automated:
- [ ] `bt-tap recon l2cap-scan <MAC>` shows PSMs 1, 3, 7, 23, 25 as OPEN

#### Manual:
- [ ] `bt-tap fuzz <MAC>` runs L2CAP null flood, malformed packets, oversized MTU without the IVI crashing
- [ ] IVI daemon stays running after fuzz attacks

---

## Phase 7: BLE GATT Server

### Overview
Advertise BLE services using BlueZ D-Bus GATT API so `bt-tap recon gatt` can enumerate them.

### File: `target/ble_gatt.py`

**Services to advertise:**

1. **Device Information Service (0x180A)**
   - Manufacturer Name (0x2A29): "FakeCar Audio Systems"
   - Model Number (0x2A24): "IVI-2026-VULN"
   - Firmware Revision (0x2A26): "1.0.0"
   - Software Revision (0x2A28): "BlueZ 5.66"
   - PnP ID (0x2A50): Source=BT SIG(1), VID=0x0046, PID=0x0001, Ver=0x0100

2. **Battery Service (0x180F)**
   - Battery Level (0x2A19): 85 (uint8, readable, notifiable)

3. **Custom IVI Service (UUID: `12345678-1234-5678-1234-56789abcdef0`)**
   - Vehicle Speed (custom char): 0x00 0x00 (uint16, readable)
   - Diagnostic Data (custom char): readable, writable
   - OTA Update (custom char): writable (intentionally open — attack surface)

**Implementation:**
Uses `org.bluez.GattManager1` and `org.bluez.LEAdvertisingManager1` D-Bus APIs:
```python
# Register GATT application via D-Bus
bus = dbus.SystemBus()
manager = dbus.Interface(
    bus.get_object("org.bluez", "/org/bluez/hci0"),
    "org.bluez.GattManager1"
)
manager.RegisterApplication(app_path, {})

# Start LE advertising
adv_manager = dbus.Interface(
    bus.get_object("org.bluez", "/org/bluez/hci0"),
    "org.bluez.LEAdvertisingManager1"
)
adv_manager.RegisterAdvertisement(adv_path, {})
```

### Success Criteria

#### Manual:
- [ ] `bt-tap recon gatt <MAC>` discovers Device Info, Battery, and Custom services
- [ ] Battery Level reads as 85%
- [ ] Custom characteristics are readable/writable

---

## Phase 8: Pairing Agent + Trust Model

### Overview

The IVI must behave like a real car: it has a **pre-paired "phone"** that it trusts.
Service access is gated by pairing state — not auto-authorized.

**Two-tier trust model:**

| Requester | PIN pairing | Service auth | Why |
|---|---|---|---|
| Pre-paired phone MAC (or spoof of it) | Already bonded — no PIN prompt | Auto-authorized (bonded device) | Real IVIs auto-reconnect bonded phones |
| Unknown device | PIN "1234" required | Must pair first, then services unlock | Simulates legacy PIN vulnerability |
| Wrong MAC, no bond | Rejected | Rejected | Tests that hijack without correct MAC fails |

**This makes three attack paths meaningful:**

1. **pin-brute** — Attacker pairs as new device, brute-forces PIN 1234, gains access.
2. **hijack** — Attacker spoofs the pre-paired phone's MAC. IVI sees a bonded device
   reconnecting and auto-authorizes services without any pairing prompt. This is the
   real attack: the spoofed MAC matches an existing link key (or the IVI doesn't verify
   the link key — the vulnerable behavior).
3. **BIAS** — Attacker exploits CVE-2020-10135 to bypass mutual authentication
   on the existing bond.

### File: `target/pin_agent.py`

```python
# The "phone" that is pre-paired with this IVI.
# setup_ivi.sh creates the bond. Hijack attack must spoof THIS address.
PAIRED_PHONE_MAC = "AA:BB:CC:DD:EE:FF"  # Configurable via CLI arg

class IVIPairingAgent(dbus.service.Object):
    """Realistic IVI pairing agent.

    - Pre-paired phone: auto-authorized (bonded, no prompts)
    - New devices: legacy PIN "1234" required
    - Service authorization: only for bonded devices
    """

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        addr = self._get_address(device)
        print(f"[PIN] PIN request from {addr} — responding with 1234")
        return "1234"

    @dbus.service.method("org.bluez.Agent1", in_signature="ouq", out_signature="")
    def RequestConfirmation(self, device, passkey):
        addr = self._get_address(device)
        print(f"[PAIR] Confirmation request from {addr}, passkey={passkey}")
        # Accept — but this only fires for new pairing, not bonded reconnect
        return

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        return dbus.UInt32(1234)

    @dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        addr = self._get_address(device)
        # Only authorize services for bonded/trusted devices
        if self._is_bonded(addr):
            print(f"[AUTH] Service {uuid} authorized for bonded device {addr}")
            return
        print(f"[AUTH] REJECTED service {uuid} from unbonded device {addr}")
        raise dbus.exceptions.DBusException(
            "org.bluez.Error.Rejected",
            f"Device {addr} is not bonded"
        )

    @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        addr = self._get_address(device)
        if self._is_bonded(addr):
            print(f"[AUTH] Connection authorized for bonded device {addr}")
            return
        print(f"[AUTH] REJECTED connection from unbonded device {addr}")
        raise dbus.exceptions.DBusException(
            "org.bluez.Error.Rejected",
            f"Device {addr} is not bonded"
        )

    def _get_address(self, device_path):
        """Extract MAC from D-Bus device path like /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"""
        return device_path.split("/")[-1].replace("dev_", "").replace("_", ":")

    def _is_bonded(self, addr):
        """Check if device is in BlueZ's bonded device list."""
        try:
            props = dbus.Interface(
                bus.get_object("org.bluez", f"/org/bluez/hci0/dev_{addr.replace(':', '_')}"),
                "org.freedesktop.DBus.Properties"
            )
            return bool(props.Get("org.bluez.Device1", "Paired"))
        except dbus.exceptions.DBusException:
            return False
```

### `setup_ivi.sh` additions for pre-paired phone:

```bash
# Create a fake bond with the "phone" so hijack has something to spoof
PHONE_MAC="${1:-AA:BB:CC:DD:EE:FF}"

# Trust and pair the phone MAC in BlueZ
# This creates /var/lib/bluetooth/<adapter_mac>/<phone_mac>/info
# with a link key, so BlueZ considers it bonded
bluetoothctl << EOF
trust ${PHONE_MAC}
EOF

# For the hijack test to work, we also write a dummy link key
# so BlueZ has an entry for this device.
# The VULNERABILITY is that some IVIs don't verify the link key
# on reconnect — they just check if the MAC is in the bonded list.
ADAPTER_MAC=$(hciconfig hci0 | grep -oP '(?<=BD Address: )[0-9A-F:]+')
INFO_DIR="/var/lib/bluetooth/${ADAPTER_MAC}/${PHONE_MAC}"
mkdir -p "${INFO_DIR}"
cat > "${INFO_DIR}/info" << INFOEOF
[General]
Name=Galaxy S24
Trusted=true
Blocked=false
Services=

[LinkKey]
Key=1234567890ABCDEF1234567890ABCDEF
Type=4
PINLength=0
INFOEOF

# Restart bluetooth to pick up the bond
systemctl restart bluetooth
sleep 2
# Re-apply adapter settings (bluetooth restart resets them)
hciconfig hci0 up
hciconfig hci0 name "SYNC"
hciconfig hci0 class 0x200408
hciconfig hci0 piscan
btmgmt --index 0 ssp off
btmgmt --index 0 bondable on
```

### Hijack Test Flow

```
Attacker machine:
1. bt-tap scan classic                    → sees "SYNC" (IVI) at XX:XX:XX:XX:XX:XX
2. bt-tap spoof mac AA:BB:CC:DD:EE:FF    → now attacker IS the "phone"
3. bt-tap hijack XX:XX:XX:XX:XX:XX AA:BB:CC:DD:EE:FF
   → recon phase: fingerprint + SDP
   → impersonate phase: MAC already spoofed
   → connect phase: bluetoothctl connect XX:XX:XX:XX:XX:XX
   → IVI sees bonded phone reconnecting → auto-authorizes!
   → PBAP/MAP/HFP services accessible without new pairing
```

**What makes this a real test:**
- If attacker connects WITHOUT spoofing the phone MAC → agent rejects service auth
- If attacker spoofs the correct MAC → IVI auto-authorizes (bond exists)
- The link key in the bond file is fake, and the vulnerability is that the IVI
  accepts the reconnection anyway (simulating IVIs that don't do mutual auth)

### Success Criteria

#### Automated:
- [ ] `bluetoothctl paired-devices` on IVI shows `AA:BB:CC:DD:EE:FF Galaxy S24`
- [ ] `/var/lib/bluetooth/<adapter>/<phone>/info` exists with LinkKey entry

#### Manual:
- [ ] `bt-tap pin-brute <IVI_MAC>` discovers PIN 1234 (new device pairing path)
- [ ] After pairing via PIN, RFCOMM services become accessible
- [ ] `bt-tap hijack <IVI_MAC> AA:BB:CC:DD:EE:FF` — full chain works:
  spoofed MAC is auto-authorized, PBAP/MAP data extracted without pairing prompt
- [ ] Connecting with a random un-paired MAC gets service authorization REJECTED

---

## Phase 9: Vuln-Scanner Maximization

### Overview

The vuln-scanner's CVE checks depend on what the target's BT adapter reports at the
firmware/hardware level (LMP version, manufacturer string, features). We can't fake LMP
version — it's burned into firmware. But we CAN configure the IVI to maximize the number
of findings by choosing the right adapter and BlueZ config.

### What the vuln-scanner checks and what triggers each finding:

| Check | CVE | Triggers When | Our IVI Config | Adapter Dependent? |
|---|---|---|---|---|
| KNOB | CVE-2019-9506 | LMP < 5.1 | Depends on adapter's real LMP version | **Yes** — older adapters (BT 4.x) trigger, newer (5.1+) don't |
| BLURtooth | CVE-2020-15802 | BT 4.2-5.0 + dual-mode | Depends on adapter LMP | **Yes** — only BT 4.2-5.0 adapters |
| PIN Pairing Bypass | CVE-2020-26555 | SSP=off + BT ≤ 5.2 | Legacy profile (if adapter allows SSP off) | **Partial** — needs SSP disable support |
| Invalid Curve | CVE-2018-5383 | BT < 5.1 + SSP=on | SSP profile | **Yes** — needs BT < 5.1 adapter |
| BIAS | CVE-2020-10135 | SSP=on | SSP profile → **TRIGGERS** (INFO level) | No — always fires if SSP on |
| BlueBorne | CVE-2017-1000251 | "BlueZ < 5.47" in SDP | Depends on distro's BlueZ version | No — depends on OS, not adapter |
| BrakTooth | various | Manufacturer matches known chipset | Depends on adapter chip (Intel, Qualcomm, etc.) | **Yes** — only matched chipsets |
| Just Works | N/A | Pairing probe sees "Just Works" | SSP profile + NoInputNoOutput → **TRIGGERS** | No — BlueZ config controls this |
| Unauthenticated OBEX | N/A | OBEX Connect returns 0xA0 | Our OBEX servers do this → **ALWAYS TRIGGERS** | No |
| Hidden RFCOMM | N/A | Open channels not in SDP | Channel 2 open, not in SDP → **ALWAYS TRIGGERS** | No |
| Service Exposure | N/A | RFCOMM channels respond without EACCES | Our channels accept → **ALWAYS TRIGGERS** | No |
| PIN Lockout | N/A | PIN brute not locked out | No lockout logic → **ALWAYS TRIGGERS** | No |

**Key insight:** 6 out of 12 checks trigger regardless of adapter hardware. The adapter-dependent
checks (KNOB, BLURtooth, BrakTooth, Invalid Curve) depend on the real LMP version and chipset
burned into the adapter's firmware — we can't fake these, and honestly shouldn't. The setup script
will print what the adapter reports so the user knows which checks to expect.

The setup script's `--detect` flag prints a summary:
```bash
$ sudo ./setup_ivi.sh detect
[*] Adapter: hci0 (XX:XX:XX:XX:XX:XX)
[*] Chipset: Intel AX200 (via modalias)
[*] LMP Version: 5.2
[*] SSP disable: NOT SUPPORTED (Intel enforces SSP)
[*] Profile: SSP (auto-detected)
[*]
[*] Expected vuln-scan findings:
[*]   ✓ BIAS (CVE-2020-10135) — INFO (SSP on)
[*]   ✓ Just Works pairing — HIGH
[*]   ✓ Unauthenticated OBEX — CRITICAL
[*]   ✓ Hidden RFCOMM — MEDIUM
[*]   ✓ Service Exposure — MEDIUM+
[*]   ✓ No PIN lockout — MEDIUM
[*]   ✗ KNOB — won't fire (BT 5.2 >= 5.1)
[*]   ✗ PIN Bypass — won't fire (SSP can't be disabled)
[*]   ✗ BrakTooth — won't fire (Intel not in chipset list)
```

### The SSP dilemma

Some CVEs need SSP=off (PIN bypass, KNOB higher severity), others need SSP=on (BIAS, Invalid Curve).
We can't have both simultaneously.

**Solution: Auto-detect, with manual override:**

```bash
# Auto-detect: tries legacy first, falls back to SSP if adapter enforces it
sudo ./setup_ivi.sh                          # auto (recommended)
sudo ./setup_ivi.sh legacy                   # force legacy (may fail on Intel)
sudo ./setup_ivi.sh ssp                      # force SSP/Just Works
sudo ./setup_ivi.sh detect                   # just print what would happen
```

**Legacy profile** (SSP off — if adapter supports it):
- PIN Pairing Bypass (CVE-2020-26555): **CONFIRMED**
- KNOB (CVE-2019-9506): adapter-dependent
- Unauthenticated OBEX: **CRITICAL**
- Hidden RFCOMM: **MEDIUM**
- No PIN lockout: **MEDIUM**

**SSP profile** (SSP on, NoInputNoOutput = Just Works — always works):
- BIAS (CVE-2020-10135): **INFO** (unverified, needs active testing)
- Invalid Curve (CVE-2018-5383): adapter-dependent
- Just Works pairing: **HIGH**
- All the same service exposure findings as Legacy

**On Intel adapters** (common in laptops), SSP is typically enforced, so `auto`
will select the SSP profile. **On Raspberry Pi** (Broadcom), SSP can usually
be disabled, so `auto` will select legacy. Either way you get 6+ findings
including the CRITICAL unauthenticated OBEX.

### `setup_ivi.sh` SSP handling:

Already handled in Phase 1's auto-detect logic. The `PROFILE` variable (`legacy` or `ssp`)
is written to `target/.ivi_profile` so `pin_agent.py` and `ivi_daemon.py` can read it
and adapt behavior accordingly.

```bash
# At end of setup_ivi.sh:
echo "$PROFILE" > "$(dirname "$0")/.ivi_profile"
echo "[+] Profile saved to target/.ivi_profile"
```

### BlueBorne version string in SDP

Add a fake SDP provider string that includes an old BlueZ version so the BlueBorne
check triggers. This goes in the sdptool registration:

```bash
# Register SPP with provider string containing old BlueZ version
sdptool add --channel=1 SP
# Override provider via raw SDP XML if sdptool doesn't support it directly,
# OR set the BlueZ version in main.conf:
# /etc/bluetooth/main.conf → no direct version override available
# Alternative: The BlueZ version comes from the running bluetoothd binary.
# On older distros/Pi with BlueZ < 5.47, the check triggers naturally.
# On modern distros (BlueZ 5.55+), it correctly won't fire.
```

Note: The BlueBorne check reads the raw SDP output for "BlueZ X.XX" strings. This
comes from the local bluetoothd version, which we can't easily fake. On older
distros or Raspberry Pi OS with older BlueZ, this will trigger naturally. On
modern systems (BlueZ 5.55+), it correctly won't fire — honest behavior.

### Hidden RFCOMM channel

Open an extra RFCOMM channel (e.g., channel 2) that is NOT registered in SDP.
The vuln-scanner's `_check_hidden_rfcomm` diffs open channels vs SDP-advertised ones.

```python
# In ivi_daemon.py — add a "hidden debug" channel
listen_rfcomm(channel=2)  # Not in SDP → hidden service finding
```

### Success Criteria

#### Manual:
- [ ] `bt-tap vuln-scan <MAC>` in legacy mode finds:
  - CRITICAL: Unauthenticated OBEX Access
  - HIGH: Legacy PIN Pairing Auth Bypass (CVE-2020-26555)
  - MEDIUM: KNOB Susceptibility (CVE-2019-9506)
  - MEDIUM: Hidden RFCOMM service on channel 2
  - MEDIUM: No PIN lockout detected
  - At least 6+ total findings

- [ ] `bt-tap vuln-scan <MAC>` in SSP mode finds:
  - CRITICAL: Unauthenticated OBEX Access (still, OBEX doesn't need pairing)
  - HIGH: Just Works pairing method
  - MEDIUM: Invalid Curve Attack Susceptibility (CVE-2018-5383)
  - INFO: BIAS requires active validation
  - At least 5+ total findings

---

## File Structure

```
target/
  setup_ivi.sh            # Phase 1: BlueZ adapter configuration
  ivi_daemon.py           # Phases 3-6: OBEX servers + AT responders + L2CAP listeners
  pin_agent.py            # Phase 8: Legacy PIN pairing agent
  ble_gatt.py             # Phase 7: BLE GATT server
  data/
    gen_data.py           # Phase 2: Data generator
    phonebook.vcf         # 50 contacts
    ich.vcf               # Incoming call history
    och.vcf               # Outgoing call history
    mch.vcf               # Missed call history
    cch.vcf               # Combined call history
    messages/
      inbox/              # 10 bMessage files
      sent/               # 5 bMessage files
      draft/              # 3 bMessage files
      deleted/            # 2 bMessage files
  received/               # OPP received files land here
  README.md               # Setup instructions
```

## Implementation Order

1. **Phase 2** first (gen_data.py) — no external deps, testable immediately
2. **Phase 1** (setup_ivi.sh) — gets the adapter configured
3. **Phase 8** (pin_agent.py) — needed before anything connects
4. **Phase 3** (OBEX servers) — the biggest piece, PBAP first, then MAP, then OPP
5. **Phase 4** (HFP responder) — can test SLC independently
6. **Phase 5** (SPP/bluesnarfer) — reuses AT command pattern from Phase 4
7. **Phase 6** (L2CAP listeners) — simple accept loops
8. **Phase 7** (BLE GATT) — independent, can be done in parallel

## Dependencies

Works on any Debian/Ubuntu-based Linux (x86_64 or arm64):

```bash
# Kali / Ubuntu / Debian desktop:
sudo apt install bluez bluez-tools python3-dbus python3-gi

# Raspberry Pi OS (Bookworm):
sudo apt install bluez python3-dbus python3-gi
# bluez-tools may need: sudo apt install bluez-tools
# or use bluetoothctl equivalents (setup_ivi.sh handles both)

# Arch / Fedora / other:
# Install: bluez, python-dbus, python-gobject (package names vary)
```

**Required system tools** (provided by bluez/bluez-tools):
`bluetoothd`, `hciconfig`, `hcitool`, `sdptool`, `btmgmt`, `bluetoothctl`

**Required Python** (3.10+): `dbus-python`, `PyGObject` (system packages, no pip needed)

**Architecture-independent**: Pure Python + BlueZ CLI. No compiled extensions,
no architecture-specific code. Same scripts run on x86_64 and arm64.

## Risk: What Might Not Work

1. **SSP cannot be disabled on some adapters** — Intel (laptops) often enforces SSP.
   Broadcom (Pi) usually allows SSP off. The setup script auto-detects and adapts.
   PIN brute-force won't work if SSP is enforced, but hijack/OBEX/vuln-scan still do.
2. **BlueZ may refuse to register certain SDP records** — sdptool service names are limited.
   May need `sdptool add --handle=0x10001 --channel=15` with raw XML for custom records.
3. **SCO audio requires kernel support** — Kernel needs `CONFIG_BT_SCO`. Most distro kernels
   have this. Kali and Raspberry Pi OS both include it.
4. **BLE + Classic simultaneously** — Requires dual-mode adapter (BT 4.0+). All Pi models
   with built-in BT are dual-mode. Laptops from ~2014+ are dual-mode.
   Check with `btmgmt info | grep le`.
5. **L2CAP raw PSM binding requires root** — PSMs < 4097 require `CAP_NET_RAW` or root.
   The daemon must run as root (`sudo python3 ivi_daemon.py`).
6. **Adapter-dependent vuln-scan findings** — KNOB, BLURtooth, BrakTooth, Invalid Curve depend
   on the real LMP version and chipset — can't and shouldn't be faked.
   The `detect` subcommand tells you upfront which findings to expect.
7. **Raspberry Pi 3 has BT 4.2 only** — Still works for everything. BT 4.2 actually
   *increases* vuln-scan findings (KNOB, BLURtooth triggers). Pi 5 has BT 5.2.
