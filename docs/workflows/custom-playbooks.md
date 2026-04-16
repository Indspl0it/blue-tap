# Custom Playbooks Workflow

## Scenario

You've run several engagements and developed a consistent methodology. Instead of typing commands manually each time, you want to encode your assessment workflow into a reusable, shareable playbook. Playbooks chain Blue-Tap commands into repeatable sequences with metadata, making your methodology consistent across team members and engagements.

This workflow covers the playbook format, running playbooks, and includes a step-by-step tutorial for building your first playbook from scratch, plus three complete example playbooks for common scenarios.

**Time estimate:** 5 minutes to create, varies to run
**Risk level:** Depends on included commands

!!! note "Prerequisites"
    - **Blue-Tap installed** and working
    - **Text editor** for writing YAML
    - Understanding of which Blue-Tap commands you want to chain
    - For playbooks that include exploitation/DoS: all the prerequisites those commands need (root, adapter, DarkFirmware, etc.)

---

## Tutorial: Building Your First Playbook

Let's build a playbook step by step. The scenario: you do automotive IVI assessments regularly and want a standardized non-intrusive recon + vuln scan workflow that any team member can run.

### 1. Define Requirements

Before writing YAML, answer these questions:

- **What's the goal?** Non-intrusive triage of an automotive head unit.
- **What commands do you run?** Discovery, SDP, L2CAP, RFCOMM, fingerprint, vulnscan.
- **What's the risk level?** Low -- no exploitation, no DoS.
- **How long does it take?** About 5 minutes.
- **Does it need a target MAC?** Yes, after discovery.

### 2. Write the YAML

Create a file called `ivi-triage.yaml`:

```yaml
name: Automotive IVI Triage
description: >
  Non-intrusive assessment of automotive infotainment systems.
  Covers discovery, full reconnaissance, and vulnerability scanning.
  No exploitation or DoS -- safe to run without specific authorization
  for intrusive testing.
duration: ~5 minutes
risk: low
steps:
  - command: discover classic -d 15
    description: Find nearby Classic Bluetooth devices (IVIs are typically Classic)

  - command: recon {target} sdp
    description: Enumerate all SDP services and check for unauthenticated access

  - command: recon {target} l2cap
    description: Scan L2CAP PSMs including hidden vendor-specific channels

  - command: recon {target} rfcomm
    description: Scan RFCOMM channels for open serial ports

  - command: recon {target} fingerprint
    description: Identify chipset vendor, firmware version, and BT capabilities

  - command: vulnscan {target}
    description: Run all registered CVE and posture checks (passive mode)
```

### 3. Validate with Dry Run

Test the playbook without executing anything:

```bash
$ sudo blue-tap playbook run --file ivi-triage.yaml \
    --target AA:BB:CC:DD:EE:FF --dry-run
[*] Playbook: Automotive IVI Triage
[*] Risk: low
[*] Duration: ~5 minutes
[*] Mode: DRY RUN (no commands will execute)

  Step 1: discover classic -d 15
          Find nearby Classic Bluetooth devices (IVIs are typically Classic)

  Step 2: recon AA:BB:CC:DD:EE:FF sdp
          Enumerate all SDP services and check for unauthenticated access

  Step 3: recon AA:BB:CC:DD:EE:FF l2cap
          Scan L2CAP PSMs including hidden vendor-specific channels

  Step 4: recon AA:BB:CC:DD:EE:FF rfcomm
          Scan RFCOMM channels for open serial ports

  Step 5: recon AA:BB:CC:DD:EE:FF fingerprint
          Identify chipset vendor, firmware version, and BT capabilities

  Step 6: vulnscan AA:BB:CC:DD:EE:FF
          Run all registered CVE and posture checks (passive mode)

[+] 6 steps validated. No errors.
```

**What happened:** Blue-Tap parsed the YAML, resolved the `{target}` placeholder to the MAC you provided, and printed each step without executing it. This lets you verify the command sequence and catch typos before running against a real target.

**Decision point:**

- **If all steps look correct** -- proceed to run for real.
- **If a command is wrong** -- edit the YAML and re-run `--dry-run`.
- **If you see "unknown command"** -- check the [Module-to-CLI Mapping](#module-to-cli-mapping) table below.

### 4. Run for Real

```bash
$ sudo blue-tap playbook run --file ivi-triage.yaml --target AA:BB:CC:DD:EE:FF
[*] Playbook: Automotive IVI Triage
[*] Target: AA:BB:CC:DD:EE:FF
[*] Risk: low

  Step 1/6: discover classic -d 15
  [+] Found 3 devices in 15.0s

  Step 2/6: recon AA:BB:CC:DD:EE:FF sdp
  [+] 9 services found. 2 without authentication.

  Step 3/6: recon AA:BB:CC:DD:EE:FF l2cap
  [+] 6 PSMs probed. 3 open without auth.

  Step 4/6: recon AA:BB:CC:DD:EE:FF rfcomm
  [+] 6 channels open.

  Step 5/6: recon AA:BB:CC:DD:EE:FF fingerprint
  [+] Qualcomm QCC5171, BT 5.2, FW 2.1.3

  Step 6/6: vulnscan AA:BB:CC:DD:EE:FF
  [+] 7 confirmed, 0 inconclusive, 12 not_applicable

[+] Playbook complete. 6/6 steps succeeded.
[+] Duration: 4m 38s
```

**What happened:** Each step executed sequentially. Results are stored in the session and available for report generation.

### 5. Iterate

Based on results, you might want to add GATT enumeration for dual-mode targets, or add `--active` to vulnscan. Edit the YAML and re-run. Playbooks are living documents -- refine them as your methodology evolves.

---

## Playbook Formats

Blue-Tap supports two playbook formats: **YAML** (structured, with metadata) and **plain text** (quick and simple).

### YAML Playbook Schema

```yaml
name: Targeted IVI Assessment
description: Non-intrusive assessment for automotive IVI systems
duration: ~15 minutes
risk: low
steps:
  - command: discover classic -d 10
    description: Find nearby Classic Bluetooth devices

  - command: recon {target} sdp
    description: Enumerate SDP services

  - command: recon {target} l2cap
    description: Scan L2CAP PSMs

  - command: recon {target} rfcomm
    description: Scan RFCOMM channels

  - command: vulnscan {target}
    description: Run vulnerability checks

  - module: reconnaissance.campaign
    args: "{target}"
    description: Full reconnaissance campaign
```

**Top-level fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable playbook name |
| `description` | Yes | What this playbook does |
| `duration` | No | Estimated run time |
| `risk` | No | Risk level: `low`, `medium`, `high` |
| `steps` | Yes | Ordered list of steps |

**Step fields -- command-based:**

| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | CLI command (without `sudo blue-tap` prefix) |
| `description` | No | What this step does |

**Step fields -- module-based:**

| Field | Required | Description |
|-------|----------|-------------|
| `module` | Yes | Module ID (e.g., `reconnaissance.campaign`) |
| `args` | No | Arguments string passed to the module |
| `description` | No | What this step does |

### Plain-Text Playbook Format

One command per line, no metadata:

```
discover classic -d 10
recon {target} sdp
recon {target} l2cap
recon {target} rfcomm
vulnscan {target}
```

Lines starting with `#` are comments. Empty lines are ignored.

!!! tip
    Plain-text playbooks are fast to write but lack metadata (name, description, risk level). Use YAML for anything you'll share or reuse across engagements.

---

## Placeholders

Playbooks support these placeholders, resolved at runtime:

| Placeholder | Resolves to |
|-------------|-------------|
| `{target}` or `TARGET` | Selected target device MAC address |
| `{hci}` or `{adapter}` | Active Bluetooth adapter (e.g., `hci0`) |

Example:

```yaml
- command: recon {target} sdp
  # Becomes: recon AA:BB:CC:DD:EE:FF sdp
```

---

## Running Playbooks

### Inline Commands

Run a quick sequence without a file:

```bash
$ sudo blue-tap playbook run --inline \
    "discover classic -d 10" \
    "recon {target} sdp" \
    "vulnscan {target}"
[*] Running inline playbook (3 steps)...

  Step 1/3: discover classic -d 10
  [+] Found 2 devices.

  Step 2/3: recon AA:BB:CC:DD:EE:FF sdp
  [+] 7 services found.

  Step 3/3: vulnscan AA:BB:CC:DD:EE:FF
  [+] 4 confirmed vulnerabilities.

[+] Inline playbook complete. 3/3 steps succeeded.
```

### From a File

```bash
$ sudo blue-tap playbook run --file ./my-assessment.yaml --target AA:BB:CC:DD:EE:FF
```

### Bundled Playbooks

Blue-Tap ships with built-in playbooks:

```bash
$ sudo blue-tap playbook --list
[*] Available playbooks:

  Name               | Risk   | Duration   | Description
 --------------------|--------|------------|----------------------------------
  quick-recon        | low    | ~3 min     | Passive reconnaissance only
  full-recon         | low    | ~10 min    | All recon modules + fingerprint
  vuln-assessment    | medium | ~15 min    | Recon + active vulnerability scan
  full-pentest       | high   | ~1-4 hrs   | All 9 phases end to end
  audio-attack       | high   | ~10 min    | HFP/A2DP audio attack chain
  enc-downgrade      | high   | ~20 min    | Full encryption downgrade chain
  data-extraction    | high   | ~10 min    | PBAP + MAP + OBEX extraction

[+] 7 bundled playbooks available.
```

Run a bundled playbook by name:

```bash
$ sudo blue-tap playbook run quick-recon --target AA:BB:CC:DD:EE:FF
```

### Common Flags

| Flag | Description |
|------|-------------|
| `--target MAC` | Set the target device MAC |
| `--adapter hciX` | Override the Bluetooth adapter |
| `--yes` | Skip confirmation prompts for intrusive steps |
| `--dry-run` | Print commands without executing |
| `--stop-on-error` | Halt playbook on first failure (default: continue) |

---

## Example Playbooks

### Example 1: Passive Reconnaissance Only

**Use case:** Initial information gathering on a target you haven't been authorized to actively test. No packets are sent that could trigger alerts or modify state.

```yaml
name: Passive Recon
description: >
  Non-invasive information gathering. Safe to run without
  explicit authorization for active testing. Collects device
  information, advertised services, and BLE characteristics
  through standard protocol queries only.
duration: ~3 minutes
risk: low
steps:
  - command: discover all -d 10
    description: Discover nearby Classic and BLE devices

  - command: recon {target} sdp
    description: SDP service enumeration (standard protocol query)

  - command: recon {target} gatt
    description: BLE GATT enumeration (read advertised characteristics)

  - command: recon {target} fingerprint
    description: Device fingerprinting via LMP feature exchange
```

Run it:

```bash
$ sudo blue-tap playbook run --file passive-recon.yaml --target AA:BB:CC:DD:EE:FF
[*] Playbook: Passive Recon
[*] Risk: low

  Step 1/4: discover all -d 10
  [+] Found 4 devices.

  Step 2/4: recon AA:BB:CC:DD:EE:FF sdp
  [+] 9 services found.

  Step 3/4: recon AA:BB:CC:DD:EE:FF gatt
  [+] 3 BLE services, 12 characteristics found.

  Step 4/4: recon AA:BB:CC:DD:EE:FF fingerprint
  [+] Qualcomm QCC5171, BT 5.2

[+] Playbook complete. 4/4 steps succeeded. Duration: 2m 51s
```

---

### Example 2: Automotive Head Unit Full Assessment

**Use case:** Comprehensive assessment of an automotive IVI system under a formal engagement. Covers recon through exploitation, fuzzing, and DoS. Requires written authorization for intrusive testing.

```yaml
name: Automotive IVI Full Test
description: >
  Complete assessment of automotive infotainment system.
  Includes active vulnerability scanning, SSP enforcement
  probing, protocol fuzzing, and DoS resilience testing.
  REQUIRES written authorization for intrusive phases.
duration: ~45 minutes
risk: high
steps:
  - command: discover classic -d 15
    description: Find Classic BT devices (IVI typically Classic)

  - command: recon {target} sdp
    description: Enumerate all advertised services

  - command: recon {target} l2cap
    description: Scan L2CAP channels including hidden vendor PSMs

  - command: recon {target} rfcomm
    description: Scan RFCOMM channels for open serial ports

  - command: recon {target} fingerprint
    description: Identify chipset, firmware, and capabilities

  - command: vulnscan {target} --active
    description: Active vulnerability assessment with crafted probes

  - command: exploit {target} ssp-downgrade --method probe
    description: Check whether SSP is enforced or bypassable

  - command: fuzz campaign {target} --protocols sdp,l2cap,rfcomm --duration 30m
    description: 30-minute fuzzing campaign across core protocols

  - command: dos {target} --recovery-timeout 30 --yes
    description: DoS resilience testing with 30s recovery window
```

Run it:

```bash
$ sudo blue-tap playbook run --file ivi-full.yaml \
    --target AA:BB:CC:DD:EE:FF --yes
[*] Playbook: Automotive IVI Full Test
[*] Risk: high
[*] --yes flag: intrusive steps will proceed without confirmation

  Step 1/9: discover classic -d 15
  [+] Found 3 devices.

  Step 2/9: recon AA:BB:CC:DD:EE:FF sdp
  [+] 9 services found. 2 unauthenticated.

  Step 3/9: recon AA:BB:CC:DD:EE:FF l2cap
  [+] 6 PSMs. 3 open without auth.

  Step 4/9: recon AA:BB:CC:DD:EE:FF rfcomm
  [+] 6 channels open.

  Step 5/9: recon AA:BB:CC:DD:EE:FF fingerprint
  [+] Qualcomm QCC5171, BT 5.2, FW 2.1.3

  Step 6/9: vulnscan AA:BB:CC:DD:EE:FF --active
  [+] 7 confirmed, 0 inconclusive.

  Step 7/9: exploit AA:BB:CC:DD:EE:FF ssp-downgrade --method probe
  [+] SSP not enforced. Legacy PIN pairing accepted.

  Step 8/9: fuzz campaign AA:BB:CC:DD:EE:FF --protocols sdp,l2cap,rfcomm --duration 30m
  [+] 30m campaign: 1 crash (MEDIUM).

  Step 9/9: dos AA:BB:CC:DD:EE:FF --recovery-timeout 30 --yes
  [+] 2/4 vectors caused extended disruption.

[+] Playbook complete. 9/9 steps succeeded. Duration: 42m 15s
```

---

### Example 3: Post-Exploitation Data Extraction

**Use case:** You've already established a pairing (via SSP downgrade or other means) and need to extract all accessible data to demonstrate impact. This playbook grabs everything: contacts, messages, audio, and files.

```yaml
name: Data Extraction
description: >
  Extract all accessible data from a paired target.
  Requires an active Bluetooth pairing with the target.
  Downloads phonebook, call history, messages, records
  microphone audio, and attempts OBEX file transfer.
duration: ~10 minutes
risk: high
steps:
  - command: extract {target} contacts --all
    description: Download full phonebook and call history via PBAP

  - command: extract {target} messages
    description: Download SMS/MMS inbox and sent folders via MAP

  - command: extract {target} audio --action record -d 120
    description: Record 2 minutes of cabin microphone audio via HFP

  - command: extract {target} audio --action capture-media
    description: Capture A2DP media stream (press Ctrl+C after 30s)

  - command: extract {target} data
    description: OBEX file transfer (browse and download accessible files)
```

Run it:

```bash
$ sudo blue-tap playbook run --file data-extraction.yaml \
    --target AA:BB:CC:DD:EE:FF
[*] Playbook: Data Extraction
[*] Risk: high

  Step 1/5: extract AA:BB:CC:DD:EE:FF contacts --all
  [+] 847 contacts + 1,204 call records extracted.

  Step 2/5: extract AA:BB:CC:DD:EE:FF messages
  [+] 234 messages extracted (189 inbox, 45 sent).

  Step 3/5: extract AA:BB:CC:DD:EE:FF audio --action record -d 120
  [+] 120s recording saved (3.76 MB, mSBC 16 kHz).

  Step 4/5: extract AA:BB:CC:DD:EE:FF audio --action capture-media
  [*] Capturing media stream... (manual Ctrl+C required)
  ^C
  [+] 45s media capture saved (7.8 MB, SBC 44.1 kHz stereo).

  Step 5/5: extract AA:BB:CC:DD:EE:FF data
  [+] OBEX browse: 12 files accessible. 8 downloaded (2.3 MB total).

[+] Playbook complete. 5/5 steps succeeded. Duration: 6m 22s
```

---

## Module-to-CLI Mapping

When writing playbooks, you can use either CLI commands or module IDs. This table maps between them:

| Module ID | CLI Command | Family |
|-----------|-------------|--------|
| `discovery.classic` | `discover classic` | Discovery |
| `discovery.ble` | `discover ble` | Discovery |
| `discovery.all` | `discover all` | Discovery |
| `reconnaissance.sdp` | `recon TARGET sdp` | Reconnaissance |
| `reconnaissance.gatt` | `recon TARGET gatt` | Reconnaissance |
| `reconnaissance.l2cap` | `recon TARGET l2cap` | Reconnaissance |
| `reconnaissance.rfcomm` | `recon TARGET rfcomm` | Reconnaissance |
| `reconnaissance.fingerprint` | `recon TARGET fingerprint` | Reconnaissance |
| `reconnaissance.campaign` | `recon TARGET campaign` | Reconnaissance |
| `assessment.vulnscan` | `vulnscan TARGET` | Assessment |
| `exploitation.knob` | `exploit TARGET knob` | Exploitation |
| `exploitation.ssp_downgrade` | `exploit TARGET ssp-downgrade` | Exploitation |
| `exploitation.bluffs` | `exploit TARGET bluffs` | Exploitation |
| `exploitation.enc_downgrade` | `exploit TARGET enc-downgrade` | Exploitation |
| `exploitation.dos` | `dos TARGET` | Exploitation |
| `post_exploitation.contacts` | `extract TARGET contacts` | Post-exploitation |
| `post_exploitation.messages` | `extract TARGET messages` | Post-exploitation |
| `post_exploitation.audio` | `extract TARGET audio` | Post-exploitation |
| `post_exploitation.data` | `extract TARGET data` | Post-exploitation |
| `fuzzing.campaign` | `fuzz campaign TARGET` | Fuzzing |
| `fuzzing.cve` | `fuzz cve TARGET` | Fuzzing |

---

## Creating Your Own

Step-by-step summary:

1. **Define your goal** -- what are you trying to accomplish, and what's the risk level?
2. **List the commands** -- write out the Blue-Tap commands you'd run manually.
3. **Write the YAML** -- follow the schema above. Use `{target}` for the target MAC.
4. **Dry-run first** -- always test with `--dry-run` before running live:
   ```bash
   $ sudo blue-tap playbook run --file my-playbook.yaml \
       --target AA:BB:CC:DD:EE:FF --dry-run
   ```
5. **Run for real** -- once dry-run looks correct:
   ```bash
   $ sudo blue-tap playbook run --file my-playbook.yaml \
       --target AA:BB:CC:DD:EE:FF
   ```
6. **Iterate** -- refine based on results. Add steps, adjust durations, tune flags.

!!! tip
    Store playbooks in a `playbooks/` directory in your project. Share them across team members for consistent assessment methodology.

!!! warning
    Playbooks containing exploitation or DoS steps should always be reviewed before running. Use `--dry-run` to verify the command sequence. The `--stop-on-error` flag is recommended for intrusive playbooks so a failed step doesn't cascade into unexpected territory.

---

## Summary

Playbooks encode your methodology into repeatable, shareable YAML files:

- **Consistency** -- every team member runs the same assessment steps in the same order
- **Efficiency** -- no more typing 10+ commands manually per engagement
- **Documentation** -- the playbook itself documents your methodology
- **Safety** -- `--dry-run` catches errors before they hit a target; `--stop-on-error` prevents cascading failures

Start with the bundled playbooks (`sudo blue-tap playbook --list`), customize them for your environment, and build your own library over time.

---

## What's Next?

- [Quick Assessment](quick-assessment.md) -- the workflow that the `quick-recon` bundled playbook automates
- [Full Penetration Test](full-pentest.md) -- the workflow that the `full-pentest` bundled playbook automates
- [Audio Eavesdropping](audio-eavesdropping.md) -- audio attack chain that can be encoded as a playbook
- [Fuzzing Campaign](fuzzing-campaign.md) -- fuzzing workflows for inclusion in assessment playbooks
- [Encryption Downgrade](encryption-downgrade.md) -- exploitation chain that benefits from playbook repeatability
