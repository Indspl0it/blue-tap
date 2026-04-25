# Sessions and Reporting

---

## Sessions

A session is a named directory that accumulates all command outputs from a Blue-Tap run. Sessions are auto-created with the format `blue-tap_YYYYMMDD_HHMMSS`.

Every command you run --- discovery, recon, vulnscan, extraction, fuzzing, DoS --- writes its results as a JSON envelope into the session directory. This gives you a complete, timestamped record of everything that happened during an assessment, which feeds directly into report generation.

### Directory Structure

```
sessions/
  my-assessment/
    session.json              # Session metadata (name, targets, command log)
    001_scan_classic.json     # Command output #1 (RunEnvelope wrapper)
    002_recon_sdp.json        # Command output #2
    003_vulnscan.json         # Command output #3
    004_dos.json              # Command output #4
    005_fuzz_ble-att.json     # Command output #5
    fuzz/                     # Fuzzing artifacts
      crashes.db              # Crash database (SQLite)
      corpus/                 # Seed corpus by protocol
        sdp/
        ble-att/
        bnep/
    report.html               # Generated report
    report.json               # JSON export
```

Command output files follow the naming convention `{seq:03d}_{command}.json` -- a zero-padded sequence number followed by the command name (spaces and slashes replaced with underscores, max 40 characters). Subdirectories are created on demand by modules that produce artifacts (fuzzing corpus, crash databases, extracted data).

Additional subdirectories may appear depending on which modules you run -- `pbap/` for extracted contacts, `map/` for messages, `audio/` for recordings. These are created via the session store's `save_raw()` method when the corresponding extraction or capture module writes data.

### session.json

The `session.json` file is the session's metadata record. It tracks what was done, when, and against which targets.

```json
{
  "name": "my-assessment",
  "created": "2026-04-16T14:30:22.705014",
  "last_updated": "2026-04-16T16:45:10.312847",
  "adapter": "hci0",
  "targets": ["AA:BB:CC:DD:EE:FF"],
  "commands": [
    {
      "seq": 1,
      "command": "scan_classic",
      "category": "scan",
      "target": "",
      "timestamp": "2026-04-16T14:30:22.705014+00:00",
      "file": "001_scan_classic.json"
    },
    {
      "seq": 2,
      "command": "recon_sdp",
      "category": "recon",
      "target": "AA:BB:CC:DD:EE:FF",
      "timestamp": "2026-04-16T14:31:02.112340+00:00",
      "file": "002_recon_sdp.json"
    },
    {
      "seq": 3,
      "command": "vulnscan",
      "category": "vuln",
      "target": "AA:BB:CC:DD:EE:FF",
      "timestamp": "2026-04-16T14:34:00.881523+00:00",
      "file": "003_vulnscan.json"
    }
  ],
  "files": [
    {
      "path": "fuzz/crashes.db",
      "timestamp": "2026-04-16T15:12:30.445012+00:00",
      "size": 8192,
      "artifact_type": "fuzz"
    }
  ]
}
```

Each command output file wraps the module's `RunEnvelope` with additional metadata:

```json
{
  "command": "vulnscan",
  "category": "vuln",
  "target": "AA:BB:CC:DD:EE:FF",
  "timestamp": "2026-04-16T14:34:00.881523+00:00",
  "data": { /* RunEnvelope contents */ },
  "validation": {
    "checked_at_write_time": true,
    "valid": true,
    "errors": []
  }
}
```

### Storage Location

Session directory is resolved in priority order:

1. `BT_TAP_SESSIONS_DIR` environment variable
2. `./sessions` relative to the current working directory
3. `~/.blue-tap` in the user's home directory

### Atomic Writes

All session file writes use atomic operations: write to a temporary file, `fsync`, then `os.replace` to the target path. This prevents corrupted session data if the process is interrupted.

### Timestamps

All session timestamps are written as **UTC ISO-8601** strings (e.g. `2026-04-16T14:30:22.705014+00:00`). Earlier builds used naive local time, which meant a session that started before DST and ended after it would sort out of order and compute negative durations. Report-time formatters render UTC timestamps in the operator's local timezone.

### Adapter exit codes

`blue-tap adapter up/down/reset/info/set-name` now raise `click.ClickException` on failure, producing exit code `1`. Prior versions printed an error and returned `0`, which silently broke shell pipelines and CI checks. Automation that relied on the old behavior should wrap those invocations in the appropriate error handling.

### Managing Sessions Across Multiple Days

Real assessments often span multiple days. Blue-Tap creates a new session for each invocation, but you can consolidate work in several ways.

**Continue a session.** Set the `BT_TAP_SESSIONS_DIR` environment variable to point to the same directory across days. Each invocation creates a new session, but all sessions are co-located for reporting.

**Generate a combined report.** The `report` command can aggregate multiple sessions:

```bash
# Report from the current session — only valid when a session is active
# (e.g. when invoked from a playbook step). Without `-s`, plain
# `blue-tap report` exits 1 with: ✖ No session active and no dump
# directory specified.
sudo blue-tap report --format html

# Report from a specific named session — pass the session name to the
# global -s flag, then call `report` (the report command itself has no
# --session flag).
sudo blue-tap -s blue-tap_20260416_143022 report --format html

# Report from a directory of session artefacts (e.g. an exported
# session bundle). The positional argument points the report at any
# directory of run-envelope JSON files. The hardware (RTL8761B) gate
# is skipped for this form, but the startup root gate still fires —
# `sudo` is required even for offline regeneration.
sudo blue-tap report ./sessions/blue-tap_20260416_143022 --format html
```

!!! tip "Multi-Day Assessments"
    Name your session directory after the engagement: `export BT_TAP_SESSIONS_DIR=./sessions/client-ivi-audit-2026`. All days of testing write to the same parent directory, and the final report aggregates everything.

### CLI

```bash
# List all sessions
blue-tap session list
```

```
$ blue-tap session list

Sessions  3 total
──────────────────────────────────────────────────────────────────────
  blue-tap_20260416_143022     8 cmds  2026-04-16 14:30  AA:BB:CC:DD:EE:FF
  blue-tap_20260415_091500    12 cmds  2026-04-15 09:15
  blue-tap_20260414_160000     5 cmds  2026-04-14 16:00  AA:BB:CC:DD:EE:FF
```

`blue-tap session list` does **not** require root — it's a directory walk
against the sessions root. A session is identified by its directory name;
the displayed columns are command count, ISO timestamp (truncated), and the
first target seen during the session.

```bash
# Show session details
blue-tap session show blue-tap_20260416_143022
```

```
$ blue-tap session show blue-tap_20260425_191205

Session Details
──────────────────────────────────────────────────
  Name                blue-tap_20260425_191205
  Created             2026-04-25T13:42:05.229784+00:00
  Last Updated        2026-04-25T13:42:22.845143+00:00
  Commands Run        5
  Targets             AA:BB:CC:DD:EE:FF
  Categories          fuzz
  Files Saved         0
  Directory           ./sessions/blue-tap_20260425_191205


Command Log:
  2026-04-25T13:42:20  fuzz_at_deep  (fuzz)  AA:BB:CC:DD:EE:FF
  2026-04-25T13:42:20  fuzz_sdp  (fuzz)  AA:BB:CC:DD:EE:FF
  2026-04-25T13:42:20  fuzz_sdp  (fuzz)  AA:BB:CC:DD:EE:FF
  2026-04-25T13:42:22  fuzz_sdp  (fuzz)  AA:BB:CC:DD:EE:FF
  2026-04-25T13:42:22  fuzz_l2cap-sig  (fuzz)  AA:BB:CC:DD:EE:FF
```

---

## Reporting

### Generate a Report

```bash
# HTML report (default)
blue-tap report --format html --output report.html

# JSON export
blue-tap report --format json --output report.json
```

### HTML Report

Professional styled report designed to be handed directly to stakeholders. The report is a single self-contained HTML file --- no external dependencies, no JavaScript, no CDN links. It can be opened in any browser, emailed as an attachment, or printed to PDF.

**Characteristics:**

- **Print-friendly**: clean layout when printed or exported to PDF
- **Inline SVG charts**: donut charts for vulnerability distribution, bar charts for severity breakdown
- **Responsive CSS**: renders well on screens of any width
- **Color-coded severity badges**: `CRITICAL` (red), `HIGH` (orange), `MEDIUM` (yellow), `LOW` (blue), `INFO` (gray)

### Report Sections

The HTML report is organized into sections that follow the assessment lifecycle. Here's what each section contains and how it looks.

**Executive Summary** --- the first page. Designed for non-technical stakeholders.

```
┌─────────────────────────────────────────────────────────┐
│  BLUE-TAP SECURITY ASSESSMENT REPORT                     │
│                                                          │
│  Overall Risk: ██ CRITICAL                               │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Devices  │  │ Vulns    │  │ Checks   │  │ Crashes │ │
│  │    1     │  │   4      │  │  47/52   │  │   3     │ │
│  │  found   │  │  found   │  │  passed  │  │  found  │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                          │
│  The target IVI system (MyCarAudio) has 4 confirmed      │
│  vulnerabilities including 1 CRITICAL (CVE-2020-0022)    │
│  and 2 HIGH severity findings. The fuzzing campaign      │
│  discovered 3 unique crashes, one of which causes a      │
│  permanent denial of service requiring a power cycle.    │
│  PBAP data extraction revealed 847 contacts from the     │
│  current pairing and 2 stale phonebook caches from       │
│  previous pairings.                                      │
└─────────────────────────────────────────────────────────┘
```

| Section | Contents |
|---------|----------|
| **Executive Summary** | Overall risk rating, narrative summary, metric cards (devices found, vulnerabilities, checks passed/failed) |
| **Scope and Methodology** | Target list, adapter, scan modes, modules executed |
| **Timeline** | Chronological sequence of commands with timestamps |
| **Discovered Devices** | All devices found during discovery, with CoD, name, RSSI, vendor |
| **Vulnerabilities** | CVE findings with severity, description, evidence, remediation |
| **Attacks** | Exploitation results with success/failure status and evidence |
| **Fuzzing Campaigns** | Campaign statistics, crash summaries, fuzzing intelligence metrics |
| **LMP Captures** | LMP frame captures (if DarkFirmware was used) |
| **Reconnaissance** | Service enumeration, profile details, version information |
| **DoS Tests** | Denial-of-service check results with recovery status |
| **Data Extraction** | Extracted contacts, messages, files, AT command results |
| **Audio** | Audio capture/injection results with file references |
| **Appendix** | Analyst notes, raw command outputs, configuration details |

!!! info "Section Visibility"
    Sections are only included if the corresponding module was executed. A quick scan-and-vulnscan assessment won't have fuzzing, DoS, or extraction sections. The report adapts to what was actually done.

### Vulnerability Section Detail

Each vulnerability entry in the report includes:

```
┌───────────────────────────────────────────────────────────────┐
│  CVE-2020-0022 (BlueFrag)                     ██ CRITICAL    │
│                                                               │
│  Description: ACL fragment reassembly buffer overflow in      │
│  Android Bluetooth stack. Crafted L2CAP fragments trigger     │
│  an integer overflow in reassembly buffer calculation.        │
│                                                               │
│  Evidence:                                                    │
│  - Target responded to crafted ACL fragment with connection   │
│    reset (matching known-vulnerable behavior)                 │
│  - Android version: 9.0 (within affected range 8.0-9.0)      │
│                                                               │
│  Affected versions: Android 8.0 - 9.0                        │
│  Remediation: Update to Android 10+ or apply patch level      │
│  2020-02-05 or later.                                         │
│                                                               │
│  References:                                                  │
│  - https://nvd.nist.gov/vuln/detail/CVE-2020-0022            │
│  - https://insinuator.net/2020/04/cve-2020-0022/             │
└───────────────────────────────────────────────────────────────┘
```

### JSON Report

Structured export for integration with other tools, dashboards, or vulnerability management systems.

| Key | Description |
|-----|-------------|
| `generated` | ISO 8601 timestamp of report generation |
| `tool` | Tool name and version |
| `version` | Report schema version |
| `risk_rating` | Overall risk rating (CRITICAL / HIGH / MEDIUM / LOW / INFO) |
| `scope` | Target devices, adapter, scan parameters |
| `summary` | Narrative summary and metric counts |
| `timeline` | Array of timestamped command entries |
| `modules` | Module execution metadata |
| `executions` | All ExecutionRecord envelopes |
| `vulnerabilities` | Vulnerability findings with severity and evidence |
| `fuzzing` | Fuzzing campaign results and crash data |
| `notes` | Analyst notes and annotations |

### Report Adapter Pipeline

Understanding how data flows from module execution to report output helps when interpreting results or troubleshooting missing sections.

```
Module execution
    │
    ▼
RunEnvelope (JSON)          ← Module writes structured results
    │
    ▼
Session store               ← Envelope saved to session directory
    │
    ▼
Report generator            ← Reads all envelopes from session
    │
    ├──▶ Discovery adapter  ← Transforms scan envelopes → device table
    ├──▶ Vulnscan adapter   ← Transforms check results → vulnerability cards
    ├──▶ Attack adapter     ← Transforms exploit results → attack summary
    ├──▶ Data adapter       ← Transforms PBAP/MAP/AT → extraction summary
    ├──▶ Audio adapter      ← Transforms HFP/A2DP/AVRCP → audio summary
    ├──▶ DoS adapter        ← Transforms check results → DoS table
    ├──▶ Fuzz adapter       ← Transforms campaign data → crash report
    ├──▶ Recon adapter      ← Transforms enumeration → service tables
    ├──▶ Firmware adapter   ← Transforms DarkFirmware ops → firmware section
    ├──▶ LMP capture adapter← Transforms LMP frames → capture table
    └──▶ Spoof adapter      ← Transforms spoofing ops → spoof summary
    │
    ▼
HTML renderer               ← Assembles sections, applies CSS, generates SVG charts
    │
    ▼
report.html                 ← Single self-contained file
```

Each adapter implements the `ReportAdapter` contract from `blue_tap.framework.contracts.report_contract`. The adapter receives the raw `RunEnvelope` data and transforms it into `SectionBlock` objects that the renderer knows how to display.

### Report Adapters

11 adapters transform module-specific envelope data into report sections:

| Adapter | Module Data |
|---------|-------------|
| `discovery` | Scan results, device list |
| `vulnscan` | Vulnerability check results |
| `attack` | Exploitation outcomes |
| `data` | PBAP, MAP, OPP, AT extraction |
| `audio` | HFP, A2DP, AVRCP operations |
| `dos` | DoS check results and recovery |
| `firmware` | DarkFirmware operations |
| `fuzz` | Fuzzing campaigns and crashes |
| `lmp_capture` | LMP frame captures |
| `recon` | Reconnaissance enumerations |
| `spoof` | MAC/name spoofing operations |

!!! info "Custom Adapters"
    Each adapter implements the `ReportAdapter` contract from `blue_tap.framework.contracts.report_contract`. To add reporting for a new module, create an adapter in `blue_tap/framework/reporting/adapters/` and register it. See the [Report Adapters developer guide](../developer/report-adapters.md) for implementation details.

---

## Next Steps

- **Automate report generation**: Include `report --format html` as the last step in an [auto mode](automation.md) run or [playbook](automation.md#playbooks).
- **Custom playbooks**: Define assessment sequences that produce consistent reports across engagements. See [Automation](automation.md).
- **Developer integration**: For adding reporting to custom modules, see [Writing a Module](../developer/writing-a-module.md) and [Report Adapters](../developer/report-adapters.md).
