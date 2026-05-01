# Custom Playbooks Workflow

## Scenario

You've run several engagements and developed a consistent methodology. Instead of typing commands manually each time, you want to encode your assessment workflow into a reusable, shareable playbook. Playbooks chain Blue-Tap commands into repeatable sequences with metadata, making your methodology consistent across team members and engagements.

This workflow covers the playbook format, running playbooks, and includes a step-by-step tutorial for building your first playbook from scratch.

**Time estimate:** 5 minutes to create, varies to run
**Risk level:** Depends on included commands

!!! note "Prerequisites"
    - **Blue-Tap installed** and working
    - **Text editor** for writing YAML
    - Understanding of which Blue-Tap commands you want to chain
    - For playbooks that include exploitation/DoS: all the prerequisites those commands need (root, adapter, DarkFirmware, etc.)

---

## The Real Command

Playbooks run through `blue-tap run-playbook`. The full surface is small:

```bash
# Run a playbook by file path or bundled name
sudo blue-tap -s mysession run-playbook --playbook ivi-triage.yaml
sudo blue-tap -s mysession run-playbook --playbook quick-recon

# Run an inline sequence (positional args, one per command)
sudo blue-tap -s mysession run-playbook "discover classic -d 10" "vulnscan {target}"

# List bundled playbooks
sudo blue-tap run-playbook --list
```

Placeholders inside commands are substituted at runtime: `{target}` (or the legacy bare `TARGET`) is replaced with the device MAC, and `{hci}` is replaced with the adapter selected via the root `--hci` flag. If a step references the target and none is set in the session, you'll be prompted to pick one from the most recent discovery.

To preview a playbook without touching hardware, prefix the root command with `--dry-run` (or set `BLUE_TAP_DRY_RUN=1`). Every step is dispatched with the dry-run flag inherited from the parent context, so the runner prints the resolved plan for each step and exits cleanly — destructive steps are previewed without their `--yes` / CONFIRM gate. There is no `--target`, `--inline`, `--yes`, or `--stop-on-error` flag on `run-playbook` itself; the session (`-s`), adapter (`--hci`), and `--dry-run` flags belong to the root `blue-tap` command and apply to every step.

---

## Tutorial: Building Your First Playbook

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
    description: Run all registered CVE and vulnerability checks
```

### 3. Run It

```bash
sudo blue-tap -s ivi-triage-1 run-playbook --playbook ivi-triage.yaml
```

Each step executes sequentially. Results are logged into the session and become available for `blue-tap report` afterwards. If a step needs `TARGET` and the session has no target yet, Blue-Tap prompts you to pick a device from the most recent discovery.

### 4. Iterate

Based on results, you might want to add GATT enumeration for dual-mode targets, or add `--active` to vulnscan. Edit the YAML and re-run. Playbooks are living documents -- refine them as your methodology evolves.

---

## Playbook Formats

Blue-Tap supports two playbook formats: **YAML** (structured, with metadata) and **plain text** (quick and simple).

### YAML Schema

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

  - command: vulnscan {target}
    description: Run vulnerability checks

  - module: reconnaissance.campaign
    args: "{target}"
    description: Full reconnaissance campaign
```

**Top-level fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | No | Human-readable playbook name (used by `--list`) |
| `description` | No | What this playbook does (used by `--list`) |
| `duration` | No | Estimated run time (used by `--list`) |
| `risk` | No | Risk level: `low`, `medium`, `high` (used by `--list`) |
| `steps` | **Yes** | Ordered list of steps -- the loader rejects playbooks without it |

**Step fields -- `command:` style:**

| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | CLI command (without `sudo blue-tap` prefix) |
| `description` | No | What this step does (currently informational only) |

**Step fields -- `module:` style:**

| Field | Required | Description |
|-------|----------|-------------|
| `module` | Yes | Module ID (e.g., `reconnaissance.campaign`) |
| `args` | No | Arguments string appended after the resolved command |
| `description` | No | What this step does |

The loader translates `module:` keys via a small mapping table (`assessment.vuln_scanner` → `vulnscan`, `discovery.scanner` → `discover all`, `reconnaissance.campaign` → `recon auto`); other module IDs default to the part after the last dot. For unmapped modules, prefer the `command:` form so the resolved CLI is explicit.

### Plain-Text Format

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

| Placeholder | Resolves to |
|-------------|-------------|
| `{target}` | Selected target device MAC address (prompted if not set) |
| `{hci}` | Adapter selected via the root `--hci` flag (e.g. `hci0`) |
| `TARGET` | Legacy synonym for `{target}` -- bare token, matched on word boundary |

The bundled playbooks use `{target}` and `{hci}` -- prefer this form for new playbooks. `TARGET` (uppercase, no braces) remains supported for compatibility with older files.

```yaml
- command: recon {target} sdp
  # Becomes: recon AA:BB:CC:DD:EE:FF sdp

- command: vulnscan {target} -a {hci}
  # Becomes: vulnscan AA:BB:CC:DD:EE:FF -a hci0
```

---

## Bundled Playbooks

Blue-Tap ships with several ready-to-run playbooks under `blue_tap/playbooks/`:

```bash
$ sudo blue-tap run-playbook --list
```

Current bundle:

| Name | Description |
|------|-------------|
| `quick-recon` | Fast non-destructive reconnaissance pass |
| `passive-recon` | Listen-only discovery and BLE advertising capture |
| `full-assessment` | Discovery + recon + vulnerability scan |
| `ble-assessment` | BLE-only sweep -- advertisement scan, GATT enumeration, BLE CVE checks |
| `dos-campaign` | Discovery + vulnscan + full DoS check series (intrusive -- requires `--yes`) |
| `post-exploit-data` | Post-pairing extraction: PBAP, MAP, OBEX file system, AT channel |
| `ivi-attack` | Automotive IVI exploitation chain (intrusive -- requires authorization) |
| `lmp-fuzzing` | LMP-layer fuzzing campaign (requires DarkFirmware) |

Run a bundled playbook by name (no path, no extension):

```bash
sudo blue-tap -s mytest run-playbook --playbook quick-recon
```

The loader resolves bundled names from `blue_tap.playbooks` if no file separator is in the argument and no local file matches.

---

## Example: Inline Quick Sequence

For one-off sequences you don't want to commit to a file:

```bash
sudo blue-tap -s adhoc run-playbook \
    "discover classic -d 10" \
    "recon {target} sdp" \
    "vulnscan {target}"
```

Each positional argument is parsed with `shlex.split` and dispatched as a separate `blue-tap` invocation. The session captures every step's envelope, so you can still run `blue-tap report` afterwards.

---

## Example: Full Assessment from File

```yaml
name: Automotive IVI Full Test
description: >
  Complete assessment of automotive infotainment system.
  Includes active vulnerability scanning, SSP probing,
  protocol fuzzing, and DoS resilience testing.
  REQUIRES written authorization for intrusive phases.
duration: ~45 minutes
risk: high
steps:
  - command: discover classic -d 15
  - command: recon {target} sdp
  - command: recon {target} l2cap
  - command: recon {target} rfcomm
  - command: recon {target} fingerprint
  - command: vulnscan {target} --active
  - command: exploit {target} ssp-downgrade --method probe
  - command: fuzz campaign {target} -p sdp -p rfcomm --duration 30m
  - command: dos {target} --recovery-timeout 30
```

```bash
sudo blue-tap -s ivi-full run-playbook --playbook ivi-full.yaml
```

If a step fails (non-zero exit, error envelope), the runner logs it and continues with the next step. There is no built-in `--stop-on-error` flag; if you need stop-on-error semantics, split the run into two playbooks at the boundary.

---

## Example: Post-Exploitation Data Extraction

```yaml
name: Data Extraction
description: >
  Extract all accessible data from a paired target.
  Requires an active Bluetooth pairing.
duration: ~10 minutes
risk: high
steps:
  - command: extract {target} contacts --all
  - command: extract {target} messages
  - command: extract {target} audio --action record -d 120
  - command: extract {target} snarf
```

```bash
sudo blue-tap -s data-pull run-playbook --playbook data-extraction.yaml
```

---

## Module-to-CLI Mapping

When writing playbooks, you can use either `command:` (literal CLI) or `module:` (module ID, translated by the loader). The translation table lives in `blue_tap/interfaces/playbooks/__init__.py`:

| Module ID | CLI Command |
|-----------|-------------|
| `assessment.vuln_scanner` | `vulnscan` |
| `assessment.fleet` | `fleet` |
| `reconnaissance.campaign` | `recon auto` |
| `discovery.scanner` | `discover all` |

For module IDs not in the table, the loader uses the part after the last dot (`exploitation.knob` → `knob`). This is a fallback heuristic, not a guarantee -- prefer `command:` for clarity in any playbook you intend to share.

---

## Creating Your Own

1. **Define your goal** -- what are you trying to accomplish, and what's the risk level?
2. **List the commands** -- write out the Blue-Tap commands you'd run manually.
3. **Write the YAML** -- follow the schema above. Use bare `TARGET` for the target MAC.
4. **Run** with a dedicated session name so the artefacts cluster cleanly:
   ```bash
   sudo blue-tap -s engagement-NN run-playbook --playbook my-playbook.yaml
   ```
5. **Iterate** -- refine based on results. Add steps, adjust durations, tune flags.

!!! tip
    Store playbooks in a `playbooks/` directory in your project. Share them across team members for consistent assessment methodology.

!!! warning
    Playbooks containing exploitation or DoS steps should always be reviewed before running. The runner does not currently enforce a confirmation prompt for destructive checks at the playbook level -- the per-module destructive gates still apply, but a long YAML can mask a single intrusive step. Review the file before executing.

---

## Summary

Playbooks encode your methodology into repeatable, shareable YAML or plain-text files:

- **Consistency** -- every team member runs the same assessment steps in the same order
- **Efficiency** -- no more typing 10+ commands manually per engagement
- **Documentation** -- the playbook itself documents your methodology
- **Replayable** -- every step is logged into the session and surfaces in the report

Start with a bundled playbook (`sudo blue-tap run-playbook --list`), customize it for your environment, and build your own library over time.

---

## What's Next?

- [Quick Assessment](quick-assessment.md) -- the workflow that the `quick-recon` bundled playbook automates
- [Full Penetration Test](full-pentest.md) -- the workflow that the `full-assessment` bundled playbook automates
- [Audio Eavesdropping](audio-eavesdropping.md) -- audio attack chain that can be encoded as a playbook
- [Fuzzing Campaign](fuzzing-campaign.md) -- fuzzing workflows for inclusion in assessment playbooks
- [Encryption Downgrade](encryption-downgrade.md) -- exploitation chain that benefits from playbook repeatability
