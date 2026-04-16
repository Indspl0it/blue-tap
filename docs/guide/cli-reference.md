# CLI Reference

Entry point: `blue-tap = blue_tap.interfaces.cli.main:main`

!!! warning "Root Required"
    Most active commands require root privileges. Exceptions: `--help`, `doctor`, `demo`, `search`, `info`, `show-options`, `plugins`.

---

## Quick Start

Blue-Tap follows an **assessment workflow** that mirrors a real-world Bluetooth security engagement. Each command maps to a phase:

```
discover  -->  recon  -->  vulnscan  -->  exploit  -->  dos  -->  extract  -->  fuzz  -->  report
  Find         Enumerate     Scan for       Attack      Stress      Pull data    Protocol    Generate
  targets      services      vulns                      test                     fuzzing     findings
```

A typical engagement looks like this:

```bash
sudo blue-tap discover classic            # 1. Find nearby Bluetooth devices
sudo blue-tap recon 4C:4F:EE:17:3A:89 sdp      # 2. Enumerate services on target
sudo blue-tap vulnscan 4C:4F:EE:17:3A:89       # 3. Run all vulnerability checks
sudo blue-tap exploit 4C:4F:EE:17:3A:89 knob   # 4. Exploit confirmed vuln
sudo blue-tap extract 4C:4F:EE:17:3A:89 contacts  # 5. Extract data
blue-tap report --format html             # 6. Generate assessment report
```

---

## Global Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-v, --verbose` | count | `0` | `-v` = verbose, `-vv` = debug |
| `-s, --session` | string | auto | Session name (auto: `blue-tap_YYYYMMDD_HHMMSS`) |
| `--version` | flag | --- | Show version and exit |

!!! tip "Sessions"
    Every command automatically logs to the active session. Use `-s mytest` to name a session for later reference, or let Blue-Tap auto-generate one. All session data is used by `report` to produce findings.

    ```
    $ sudo blue-tap -s ivi-audit vulnscan 4C:4F:EE:17:3A:89
    Session: ivi-audit
    ```

---

## Assessment Workflow

### discover

Scan for nearby Bluetooth devices. This is the starting point of any engagement --- find what is in radio range before targeting anything specific.

```bash
blue-tap discover [classic|ble|all]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-d, --duration` | int | `10` | Scan duration in seconds |
| `-a, --adapter` | string | auto | HCI adapter (e.g., `hci0`) |
| `-p, --passive` | flag | --- | Passive scan, BLE only (no `SCAN_REQ`) |

!!! example "Example: Find IVI systems in a parking lot"
    ```
    $ sudo blue-tap discover classic -d 20
    Session: blue-tap_20260416_143022

    ┌─────────────────────┬──────────────────┬────────────────┬───────┬──────────────────┐
    │ Address             │ Name             │ Class          │ RSSI  │ Vendor           │
    ├─────────────────────┼──────────────────┼────────────────┼───────┼──────────────────┤
    │ 4C:4F:EE:17:3A:89  │ MY-CAR-AUDIO     │ Car Audio      │ -45   │ Harman Intl.     │
    │ F8:27:93:A1:D4:12  │ Galaxy S24       │ Smartphone     │ -62   │ Samsung          │
    │ DC:A6:32:8F:11:C0  │ Jabra Elite 85t  │ Headphones     │ -71   │ GN Audio         │
    └─────────────────────┴──────────────────┴────────────────┴───────┴──────────────────┘

    Found 3 devices (1 IVI flagged)
    ```

For details on scan modes, output fields, and dual-mode correlation, see the [Discovery guide](discovery.md).

### recon

Deep reconnaissance against a specific target. Run this after discovery to enumerate what services, channels, and capabilities the target exposes.

```bash
blue-tap recon TARGET [sdp|gatt|l2cap|rfcomm|fingerprint|capture|sniff|auto|capabilities|analyze|correlate|interpret]
```

=== "sdp"
    SDP service discovery. `--retries` for retry count.

=== "gatt"
    BLE GATT enumeration. No additional options.

=== "l2cap"
    L2CAP PSM scan.

    | Option | Default | Description |
    |--------|---------|-------------|
    | `--start-psm` | `1` | First PSM to probe |
    | `--end-psm` | `4097` | Last PSM to probe |
    | `--timeout` | `1000` | Per-probe timeout (ms) |

=== "rfcomm"
    RFCOMM channel scan.

    | Option | Default | Description |
    |--------|---------|-------------|
    | `--start-channel` | `1` | First channel |
    | `--end-channel` | `30` | Last channel |
    | `--timeout` | `2000` | Per-probe timeout (ms) |

=== "fingerprint"
    Device identification and fingerprinting. No additional options.

=== "capture"
    HCI packet capture. `-d` duration, `-o` output file.

=== "sniff"
    Passive Bluetooth sniffing.

    | Option | Default | Description |
    |--------|---------|-------------|
    | `-m, --mode` | `ble` | `ble`, `ble_connection`, `ble_pairing`, `lmp`, `combined` |
    | `-d, --duration` | --- | Capture duration |
    | `-o, --output` | --- | Output file path |

=== "auto"
    Run all reconnaissance collectors against the target. The campaign module determines which probes to run based on target type.

=== "capabilities"
    Detect target capabilities — supported profiles, transports, and features. No additional options.

=== "analyze"
    Analyze a captured pcap file for protocol breakdown and anomalies.

    | Option | Default | Description |
    |--------|---------|-------------|
    | `--pcap` | latest capture | Path to pcap file |

=== "correlate"
    Correlate findings from multiple collectors into a unified profile. No additional options.

=== "interpret"
    Interpret Bluetooth spec data — feature flags, version strings, class codes. No additional options.

For probe details, example output, and security implications, see the [Reconnaissance guide](reconnaissance.md).

### vulnscan

Vulnerability assessment against a target. Runs all registered checks (25 CVEs + 11 posture checks) and produces a unified report.

```bash
blue-tap vulnscan TARGET
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--cve` | string | --- | Run a single CVE check by ID |
| `--active / --no-active` | flag | `--no-active` | Enable active (intrusive) checks |
| `--phone` | string | --- | Phone address for relay attacks |
| `--yes` | flag | --- | Skip confirmation prompts |

!!! example "Example: Scan a single CVE"
    ```
    $ sudo blue-tap vulnscan 4C:4F:EE:17:3A:89 --cve CVE-2019-9506
    Session: blue-tap_20260416_143511

    [CVE-2019-9506] KNOB Key Negotiation
      execution_status: completed
      module_outcome:   confirmed
      evidence:         Target accepted key_size=1 (min_key_length=1)
      severity:         CRITICAL
    ```

For the full CVE table, detection techniques, and how to read results, see the [Vulnerability Assessment guide](vulnerability-assessment.md).

### exploit

Active exploitation of known vulnerabilities. Only use after `vulnscan` confirms the target is vulnerable.

```bash
blue-tap exploit TARGET [knob|bias|bluffs|ctkd|enc-downgrade|ssp-downgrade|hijack|pin-brute]
```

Each sub-command has attack-specific options. See [Exploitation guide](exploitation.md) for prerequisites, expected output, and attack chain details.

!!! danger "Intrusive"
    All exploitation commands modify target state. They require `--yes` or interactive confirmation. 5 of 8 attacks require DarkFirmware (RTL8761B).

### dos

Denial-of-service and resilience testing. Runs 30 checks across CVE-backed crash probes and protocol stress tests, with automatic recovery monitoring after each check.

```bash
blue-tap dos TARGET
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--checks` | string | all | Comma-separated check IDs |
| `--recovery-timeout` | int | 180 | Seconds to wait for device recovery |
| `--yes` | flag | --- | Skip confirmation prompts |

**CVE-backed crash probes (9):**

| Check ID | CVE | Protocol |
|----------|-----|----------|
| `dos_cve_2020_0022` | CVE-2020-0022 | Raw ACL (DarkFirmware) |
| `dos_cve_2017_0781` | CVE-2017-0781 | BNEP heap overflow |
| `dos_cve_2017_0782` | CVE-2017-0782 | BNEP underflow |
| `dos_cve_2019_19192` | CVE-2019-19192 | BLE ATT deadlock |
| `dos_cve_2019_19196` | CVE-2019-19196 | BLE SMP key overflow |
| `dos_cve_2022_39177` | CVE-2022-39177 | AVDTP SETCONF crash |
| `dos_cve_2023_27349` | CVE-2023-27349 | AVRCP event OOB |
| `dos_cve_2025_0084` | CVE-2025-0084 | SDP race condition |
| `dos_cve_2025_48593` | CVE-2025-48593 | HFP reconnect race |

**Protocol stress tests (21):** L2CAP (storm, CID exhaust, data flood, l2ping), SDP (continuation, DES bomb), RFCOMM (SABM, mux), OBEX (session flood), HFP (AT flood, SLC confusion), LMP (detach, switch, features, opcode, encryption, timing), Pairing (pair flood, name flood, rate test).

!!! warning
    DoS checks will disrupt the target's Bluetooth stack. Some checks may require a power cycle to recover. Always verify you have authorization and physical access to the target.

### extract

Post-exploitation data extraction. Requires an established connection to the target (typically after a successful exploit or pairing).

```bash
blue-tap extract TARGET [contacts|messages|audio|stream|media|push|snarf|at]
```

Each sub-command uses a different Bluetooth profile:

| Command | Profile | What it extracts |
|---------|---------|-----------------|
| `contacts` | PBAP | Phonebook entries |
| `messages` | MAP | SMS/MMS messages |
| `audio` | HFP | Call audio control |
| `stream` | A2DP | Audio streaming — capture, inject, route |
| `media` | AVRCP | Media control and playback |
| `push` | OPP | Send files to target |
| `snarf` | OBEX | Pull files from target |
| `at` | AT Commands | Modem AT command interface |

### fuzz

Protocol fuzzing campaigns. Generates malformed packets to discover crashes and undefined behavior in Bluetooth stacks.

```bash
blue-tap fuzz [campaign|sdp-deep|l2cap-sig|rfcomm-raw|ble-att|ble-smp|bnep|obex|at-deep|crashes|minimize|cve|replay|corpus]
```

| Sub-command group | Commands | Purpose |
|-------------------|----------|---------|
| **Protocols** | `campaign`, `sdp-deep`, `l2cap-sig`, `rfcomm-raw`, `ble-att`, `ble-smp`, `bnep`, `obex`, `at-deep` | Run fuzzing against specific protocol layers |
| **Analysis** | `crashes`, `minimize`, `cve`, `replay` | Analyze crashes, minimize test cases, check CVE repros |
| **Corpus** | `corpus` | Manage the seed corpus |

### report

Generate assessment reports from session data.

```bash
blue-tap report [DUMP_DIR]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--format` | choice | `html` | `html` or `json` |
| `--output` | string | --- | Output file path |

!!! tip "Report Generation"
    When called without arguments, `report` uses the most recent session. To generate a report from a specific session, pass the session's dump directory. HTML reports include color-coded severity, sortable tables, and executive summary sections.

    ```bash
    blue-tap report --format html --output audit-report.html
    blue-tap report sessions/blue-tap_20260416_143022/ --format json
    ```

---

## Automation

### auto

Automated full-chain assessment. Runs discovery, recon, vulnscan, and optionally exploitation in sequence against a single target. This is the "push one button" mode for a complete assessment.

```bash
blue-tap auto TARGET
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--skip` | string | --- | Phases to skip (comma-separated) |
| `--yes` | flag | --- | Skip all confirmation prompts |

!!! example "Example: Full auto-assessment, skip exploitation"
    ```bash
    sudo blue-tap auto 4C:4F:EE:17:3A:89 --skip exploit
    ```

### fleet

Multi-target fleet scanning. Discovers all devices in range, then runs assessment against each. Useful for auditing environments with many Bluetooth devices (e.g., parking lots, offices, showrooms).

```bash
blue-tap fleet
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--duration` | int | --- | Scan duration |
| `--class` | string | --- | Filter by device class (e.g., `ivi`, `phone`, `headset`) |

!!! example "Example: Scan all IVI systems in range"
    ```bash
    sudo blue-tap fleet --duration 20 --class ivi
    ```

---

## Utilities

### adapter

Manage Bluetooth adapters. List available adapters, bring them up/down, reset, or change properties.

```bash
blue-tap adapter [list|info|up|down|reset|set-name|set-class]
```

!!! example "Common adapter operations"
    ```bash
    blue-tap adapter list                    # Show all HCI adapters
    blue-tap adapter info hci0               # Details for hci0
    sudo blue-tap adapter reset hci0         # Reset adapter
    sudo blue-tap adapter set-name hci0 "MyDevice"  # Change BT name
    ```

### session

View and manage sessions. Every Blue-Tap command is automatically logged to a session.

```bash
blue-tap session [list|show]
```

```
$ blue-tap session list
┌──────────────────────────────┬────────┬──────────────────────┐
│ Session                      │ Cmds   │ Created              │
├──────────────────────────────┼────────┼──────────────────────┤
│ blue-tap_20260416_143022     │ 4      │ 2026-04-16 14:30:22  │
│ ivi-audit                    │ 12     │ 2026-04-16 10:15:01  │
└──────────────────────────────┴────────┴──────────────────────┘
```

### doctor

Check system prerequisites and environment health. Run this first if you are having issues.

```bash
blue-tap doctor
```

```
$ blue-tap doctor
[+] Python 3.11.2 ................... OK
[+] BlueZ 5.66 ..................... OK
[+] hcitool ....................... OK
[+] bleak 0.21.1 .................. OK
[+] Root privileges ................ OK
[+] HCI adapter (hci0) ............ OK
[-] DarkFirmware dongle ............ NOT FOUND (optional)
```

### spoof

Spoof the adapter's Bluetooth MAC address. Useful for impersonation attacks and testing how targets respond to specific addresses.

```bash
blue-tap spoof NEW_MAC
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--method` | choice | `auto` | `auto`, `bdaddr`, `spooftooph`, `btmgmt`, `rtl8761b` |

!!! warning
    MAC spoofing changes persist until adapter reset. Always reset after testing.

---

## Playbooks

### run-playbook

Execute a sequence of commands from a playbook YAML file. Playbooks encode repeatable assessment workflows that can be shared between testers.

```bash
blue-tap run-playbook [COMMANDS...]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--playbook` | string | --- | Path to playbook YAML file |
| `--list` | flag | --- | List available playbooks |

!!! example "Example: Run the IVI assessment playbook"
    ```bash
    blue-tap run-playbook --list                     # See available playbooks
    sudo blue-tap run-playbook --playbook ivi-full-audit.yaml
    ```

---

## Power-User Commands (Hidden)

These commands do not appear in `--help` but are available for advanced use. They provide direct access to the module registry, which is useful for plugin development and scripting.

```bash
blue-tap run MODULE_ID [KEY=VALUE...]    # Run any registered module directly
blue-tap search QUERY                     # Search modules by keyword
blue-tap info MODULE_ID                   # Show module metadata
blue-tap show-options MODULE_ID           # Show module parameters
blue-tap plugins                          # List loaded plugins
```

!!! example "Registry exploration"
    ```
    $ blue-tap search "l2cap"
    reconnaissance.l2cap_scan    L2CAP PSM Scan       Classic
    assessment.cve_2022_42896    CVE-2022-42896       BLE L2CAP
    assessment.cve_2022_42895    CVE-2022-42895       L2CAP
    fuzzing.l2cap_sig            L2CAP Signaling Fuzz Classic

    $ blue-tap info assessment.cve_2022_42896
    Module:      assessment.cve_2022_42896
    Family:      assessment
    Name:        CVE-2022-42896 LE PSM=0
    Protocols:   BLE
    Intrusive: No
    Pairing:     No

    $ blue-tap run reconnaissance.l2cap_scan target=4C:4F:EE:17:3A:89 start_psm=1 end_psm=100
    ```

---

## Common Patterns

### Full IVI Assessment

```bash
# Discover IVI targets
sudo blue-tap discover classic -d 20

# Full recon on target
sudo blue-tap recon 4C:4F:EE:17:3A:89 sdp
sudo blue-tap recon 4C:4F:EE:17:3A:89 l2cap
sudo blue-tap recon 4C:4F:EE:17:3A:89 rfcomm
sudo blue-tap recon 4C:4F:EE:17:3A:89 fingerprint
sudo blue-tap recon 4C:4F:EE:17:3A:89 capabilities
sudo blue-tap recon 4C:4F:EE:17:3A:89 correlate

# Vulnerability assessment
sudo blue-tap vulnscan 4C:4F:EE:17:3A:89

# Generate report
blue-tap report --format html --output ivi-audit.html
```

### Quick BLE Audit

```bash
sudo blue-tap discover ble --passive -d 15
sudo blue-tap recon DE:AD:BE:EF:CA:FE gatt
sudo blue-tap vulnscan DE:AD:BE:EF:CA:FE --cve CVE-2023-45866
```

### Automated Fleet Scan (Non-Intrusive)

```bash
sudo blue-tap fleet --duration 30 --class ivi
blue-tap report --format html --output fleet-report.html
```

### Fuzzing Campaign

```bash
sudo blue-tap fuzz campaign 4C:4F:EE:17:3A:89 --protocol l2cap --duration 3600
blue-tap fuzz crashes --list
blue-tap fuzz minimize CRASH_ID
```

---

## Output Formats

| Format | When to use | Command |
|--------|-------------|---------|
| **CLI** | Interactive use --- Rich terminal tables with color-coded severity and status | Default for all commands |
| **JSON** | Scripting and programmatic consumption --- structured `RunEnvelope` output | `--format json` on supported commands |
| **HTML** | Stakeholder reports --- full assessment with executive summary, sortable tables | `blue-tap report --format html` |
| **Session logs** | Audit trail --- every command is automatically logged | Always active, view with `session show` |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BT_TAP_DARKFIRMWARE_HCI` | HCI device for DarkFirmware dongle (auto-detected if not set) |
| `BT_TAP_ADAPTER` | Default HCI adapter |
| `BT_TAP_SESSION_DIR` | Directory for session storage |

## What's Next?

- [Discovery guide](discovery.md) --- understand scan modes and device identification
- [Reconnaissance guide](reconnaissance.md) --- deep enumeration techniques
- [Vulnerability Assessment guide](vulnerability-assessment.md) --- CVE detection and posture checks
- [Exploitation guide](exploitation.md) --- active attacks and attack chains
