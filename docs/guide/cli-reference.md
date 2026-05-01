# CLI Reference

Entry point: `blue-tap = blue_tap.interfaces.cli.main:main`

!!! warning "Root + RTL8761B Required for Live Operations"
    Live commands require root privileges (raw HCI sockets) **and** an
    RTL8761B-based USB dongle (the tool gates live commands behind
    chipset detection — `No RTL8761B / TP-Link UB500 dongle detected`
    otherwise). Both the root check and the chipset check share one
    skip predicate, so the no-root list and the no-hardware list are
    the same:

    - `--help`, `--version`
    - `doctor`
    - `demo`
    - `session list`, `session show <name>`
    - `report` (including `report <dump-dir>`)
    - `fuzz crashes list / show / export`
    - `fuzz corpus list / minimize`
    - `fuzz minimize`
    - `fuzz campaign --dry-run` and `fuzz benchmark --dry-run`
    - `run-playbook --list`
    - `search`, `info`, `show-options`, `plugins`

    Anything not on this list needs `sudo` and a plugged-in RTL8761B
    dongle. The root and hardware gates share a single skip-set, so the
    no-root list and the no-hardware list are always identical.

---

## Quick Start

Blue-Tap follows an **assessment workflow** that mirrors a real-world Bluetooth security engagement. Each command maps to a phase:

```
discover  -->  recon  -->  vulnscan  -->  exploit  -->  dos  -->  extract  -->  fuzz  -->  report
  Find         Enumerate     Scan for       Attack      Stress      Pull data    Protocol    Generate
  targets      services      vulns                      test                     fuzzing     findings

auto  (runs: SDP recon → vulnscan → KNOB exploit → PBAP extract → report — a 4-module shortcut)
fleet (discovers all nearby devices, then assesses each)
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
| `--config` | path | --- | Path to a TOML config file (overrides `~/.config/blue-tap/config.toml` and `$BLUE_TAP_CONFIG`) |
| `--dry-run` | flag | --- | Print the resolved plan and exit without touching hardware or sending packets. Honored by every subcommand; bypasses destructive `CONFIRM=yes` gates and skips session writes. Equivalent to `BLUE_TAP_DRY_RUN=1`. |
| `--version` | flag | --- | Show version and exit |

!!! tip "Sessions"
    Every command that touches hardware automatically logs to the active
    session. Inspection commands (`--help`, `doctor`, `demo`, `session
    list/show`, `report`, `fuzz crashes/corpus/minimize`, `run-playbook
    --list`, `search`, `info`, `show-options`, `plugins`) do **not**
    create sessions, so help and inspection never pollute `~/.blue-tap`.
    Those same commands also skip the root + RTL8761B gates, so they
    work on a machine with no Bluetooth hardware at all.

    Use `-s mytest` to name a session for later reference, or let
    Blue-Tap auto-generate one (`blue-tap_YYYYMMDD_HHMMSS`).

    ```
    $ sudo blue-tap -s ivi-audit vulnscan 4C:4F:EE:17:3A:89
      ●  Session: ivi-audit
    ```

!!! tip "Subcommand --help when TARGET is a positional"
    `recon`, `exploit`, and `extract` accept TARGET as a positional argument
    *and* have subcommands. To get help for a specific subcommand without
    passing TARGET, the dispatcher peeks for a known subcommand name and
    skips target resolution:

    ```
    $ blue-tap exploit knob --help        # works — no TARGET, no scan, no banner
    $ blue-tap recon sdp --help           # works — same shortcut
    $ blue-tap extract contacts --help    # works — same shortcut
    ```

---

## Assessment Workflow

!!! tip "Interactive Target Selection"
    Most commands that accept a target address (`vulnscan`, `recon`, `exploit`, `extract`, `dos`) can be run without one. When omitted, Blue-Tap scans for nearby devices and presents an interactive picker --- select by number, rescan with `r`, or quit with `q`. Exceptions: `auto` and `fleet` require the target upfront since they run non-interactively.

### discover

Scan for nearby Bluetooth devices. This is the starting point of any engagement --- find what is in radio range before targeting anything specific.

```bash
blue-tap discover [classic|ble|all]
```

All sub-commands share:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-d, --duration` | int | `10` | Scan duration in seconds |
| `-a, --hci` | string | auto | HCI adapter (e.g., `hci0`) |

BLE-only:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-p, --passive` | flag | --- | Passive scan (no `SCAN_REQ`) |

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
blue-tap recon [TARGET] [sdp|gatt|l2cap|rfcomm|fingerprint|capture|sniff|auto|capabilities|analyze|correlate|interpret] [--hci/-a ADAPTER]
```

The `--hci/-a` option applies to all recon sub-commands.

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
blue-tap vulnscan [TARGET]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-a, --hci` | string | auto | HCI adapter (e.g., `hci0`) |
| `--cve` | string | --- | Run a single check by ID. Accepts CVE IDs (`CVE-2020-0022`) or posture check short names (`service_exposure`, `hidden_rfcomm`, `encryption_enforcement`, `writable_gatt`, `eatt_support`, `pairing_method`, `pin_lockout`, `device_class`, `lmp_features`, `authorization_model`, `automotive_diagnostics`). |
| `--active / --no-active` | flag | --- | Include active (intrusive) checks |
| `--phone` | string | --- | Phone address for impersonation checks |
| `--yes` | flag | --- | Skip confirmation prompts |

!!! example "Example: Scan a single CVE"
    ```
    $ sudo blue-tap vulnscan 4C:4F:EE:17:3A:89 --cve CVE-2020-0022
    Session: blue-tap_20260416_143511

    [CVE-2020-0022] BlueFrag ACL Fragment Boundary
      execution_status: completed
      module_outcome:   confirmed
      evidence:         Target accepts ACL fragments crossing L2CAP boundary
      severity:         CRITICAL
    ```

For the full CVE table, detection techniques, and how to read results, see the [Vulnerability Assessment guide](vulnerability-assessment.md).

### exploit

Active exploitation of known vulnerabilities. Only use after `vulnscan` confirms the target is vulnerable.

```bash
blue-tap exploit [TARGET] [knob|bias|bluffs|ctkd|enc-downgrade|ssp-downgrade|hijack|pin-brute] [--hci/-a ADAPTER] [--yes]
```

The `--hci/-a` and `--yes` options apply to all exploit sub-commands. Each sub-command has additional attack-specific options. See [Exploitation guide](exploitation.md) for prerequisites, expected output, and attack chain details.

!!! danger "Intrusive"
    All exploitation commands modify target state. They require `--yes` or interactive confirmation. 5 of 8 attacks require DarkFirmware (RTL8761B).

### dos

Denial-of-service and resilience testing. Runs 30 checks across CVE-backed crash probes and protocol stress tests, with automatic recovery monitoring after each check.

```bash
blue-tap dos [TARGET]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-a, --hci` | string | auto | HCI adapter (e.g., `hci0`) |
| `-c, --checks` | string | all | Comma-separated check IDs |
| `--recovery-timeout` | int | --- | Seconds to wait for device recovery |
| `--yes` | flag | --- | Skip confirmation prompts |

**CVE-backed crash probes (9):**

| Check ID | CVE | Protocol |
|----------|-----|----------|
| `cve_2020_0022_bluefrag` | CVE-2020-0022 | Raw ACL (DarkFirmware) |
| `cve_2017_0781_bnep_heap` | CVE-2017-0781 | BNEP heap overflow |
| `cve_2017_0782_bnep_underflow` | CVE-2017-0782 | BNEP underflow |
| `cve_2019_19192_att_deadlock` | CVE-2019-19192 | BLE ATT deadlock |
| `cve_2019_19196_key_size` | CVE-2019-19196 | BLE SMP key overflow |
| `cve_2022_39177_avdtp_setconf` | CVE-2022-39177 | AVDTP SETCONF crash |
| `cve_2023_27349_avrcp_event` | CVE-2023-27349 | AVRCP event OOB |
| `cve_2025_0084_sdp_race` | CVE-2025-0084 | SDP race condition |
| `cve_2025_48593_hfp_reconnect` | CVE-2025-48593 | HFP reconnect race |

**Protocol stress tests (21):** L2CAP (storm, CID exhaust, data flood, l2ping), SDP (continuation, DES bomb), RFCOMM (SABM, mux), OBEX (session flood), HFP (AT flood, SLC confusion), LMP (detach, switch, features, opcode, encryption, timing), Pairing (pair flood, name flood, rate test).

!!! warning
    DoS checks will disrupt the target's Bluetooth stack. Some checks may require a power cycle to recover. Always verify you have authorization and physical access to the target.

### extract

Post-exploitation data extraction. Requires an established connection to the target (typically after a successful exploit or pairing).

```bash
blue-tap extract [TARGET] [contacts|messages|audio|stream|media|push|snarf|at] [--hci/-a ADAPTER]
```

The `--hci/-a` option applies to all extract sub-commands. Each sub-command uses a different Bluetooth profile:

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
| **Crash Analysis** | `crashes list`, `crashes show`, `crashes replay`, `crashes export` | List, inspect, replay, and export discovered crashes |
| **Analysis** | `minimize`, `cve`, `replay` | Minimize test cases, reproduce known CVE patterns, replay captures |
| **Corpus** | `corpus generate`, `corpus list`, `corpus minimize` | Generate, list, and minimize the seed corpus |

#### fuzz campaign

```bash
blue-tap fuzz campaign [ADDRESS] [--protocol/-p PROTO]... [--strategy/-s STRATEGY] [--duration/-d SPAN] [--resume]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-p, --protocol` | repeatable choice | `all` | One of `sdp`, `rfcomm`, `bnep`, `obex-pbap`, `obex-map`, `obex-opp`, `at-hfp`, `at-phonebook`, `at-sms`, `ble-att`, `ble-smp`, or `all`. Repeat the flag for multiple protocols. |
| `-s, --strategy` | choice | `coverage_guided` | `coverage_guided`, `random`, `state_machine`, `targeted` |
| `-d, --duration` | duration | `1h` | e.g. `30s`, `5m`, `1h`, `24h`, `7d` |
| `-n, --iterations` | int | --- | Cap total test cases (overrides duration) |
| `--delay` | float | `0.5` | Seconds between test cases |
| `--capture / --no-capture` | flag | `--no-capture` | Record a btsnoop pcap during the run |
| `--resume` | flag | --- | Resume the previous campaign from `session_dir/fuzz/campaign_state.json`. Resumes stats, corpus, crash DB, and coverage state. Falls back to a fresh run if the state file is missing or unreadable. |
| `--dry-run` | flag | --- | Run the full pipeline against an in-process mock transport — no hardware, no l2ping. Disables `--capture`. Cannot be combined with `--resume`. |
| `--seed N` | int | --- | Seed for byte-level reproducible mutations. Falls back to `BLUE_TAP_FUZZ_SEED`. Cannot be combined with `--resume`. |
| `--trajectory-interval SECONDS` | float (>0) | --- | Trajectory sampling cadence; required for `CampaignResult.to_csv` to produce non-empty rows. |

!!! tip "Protocol aliases"
    Short names like `pbap`, `hfp`, `opp`, `att`, `smp` are accepted whenever protocols are passed as option strings (module `PROTOCOLS=`), and are normalized to canonical keys (`obex-pbap`, `at-hfp`, `obex-opp`, `ble-att`, `ble-smp`). The `fuzz campaign --protocol` flag itself uses strict Click choices — pass the canonical name there.

#### fuzz benchmark

Run N independent trials of the same configuration, aggregate per-metric stats, and optionally write a round-trippable JSON plus per-trial trajectory CSVs. Use it to compare strategies on the same target with proper variance handling, or to drive variance-aware experiments from CI.

```bash
blue-tap fuzz benchmark [ADDRESS] [--protocol/-p PROTO]... [--strategy/-s STRATEGY] \
    [--trials/-t N] (--duration/-d SPAN | --iterations/-n N) \
    [--base-seed N] [--label TEXT] [-o BENCH.json] [--csv-dir DIR] \
    [--cooldown N] [--dry-run] [--trajectory-interval SECONDS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-p, --protocol` | repeatable choice | `all` | Protocols to fuzz per trial. For variance studies on a single attack surface, narrow to one (e.g. `-p sdp`). |
| `-s, --strategy` | choice | `coverage_guided` | `coverage_guided`, `random`, `state_machine`, `targeted` |
| `-t, --trials` | int (≥1) | `5` | Number of independent trials. |
| `-d, --duration` | duration | --- | Per-trial time budget. Mutually exclusive with `-n`. |
| `-n, --iterations` | int (≥1) | --- | Per-trial test-case cap. Mutually exclusive with `-d`. |
| `--base-seed N` | int | --- | Trial *i* uses seed `base_seed + i`. Falls back to `BLUE_TAP_FUZZ_SEED`. |
| `--label TEXT` | string | `<strategy>@<trials>` | Human label stored in `BenchmarkResult.label`. |
| `-o, --output FILE` | path | --- | Write the full `BenchmarkResult` JSON (round-trippable). |
| `--csv-dir DIR` | path | --- | Write each trial's trajectory CSV as `trial_{i}.csv`. |
| `--cooldown N` | int (≥0) | `10` | Seconds between trials. |
| `--dry-run` | flag | --- | Run every trial against `MockTransport`. Pairs with `--base-seed` for deterministic CI. |
| `--trajectory-interval SECONDS` | float (>0) | --- | Per-trial sampling cadence — required for `--csv-dir` to produce non-empty rows. |

The summary table reports `(n, mean, stdev, min, max)` for `crashes`, `crashes_per_kpkt`, `iterations`, `packets_sent`, `runtime_seconds`, `states_discovered`. Aborted / errored trials are kept in `BenchmarkResult.trials` and counted separately so callers can decide whether to discard them.

#### fuzz crashes replay

```bash
blue-tap fuzz crashes replay CRASH_ID [--session/-s NAME] [--capture/--no-capture]
```

Replays a stored crash against the target. Multi-packet crashes (where `packet_sequence_json` was saved at discovery time) are replayed in full packet order, so state-machine crashes that require a setup sequence are correctly reproduced. Single-packet legacy records fall back to replaying `payload_hex` alone.

### report

Generate assessment reports from session data.

```bash
blue-tap report [DUMP_DIR]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-f, --format` | choice | `html` | `html` or `json` |
| `-o, --output` | string | --- | Output file path |

!!! tip "Report Generation"
    When called without arguments, `report` uses the most recent session. To generate a report from a specific session, pass the session's dump directory. HTML reports include color-coded severity, sortable tables, and executive summary sections.

    ```bash
    blue-tap report --format html --output audit-report.html
    blue-tap report sessions/blue-tap_20260416_143022/ --format json
    ```

---

## Automation

### auto

Four-phase assessment shortcut against a single target:

1. `recon` → `reconnaissance.sdp` (SDP service enumeration only)
2. `vulnscan` → `assessment.vuln_scanner` (all CVE + posture checks)
3. `exploit` → `exploitation.knob` (KNOB key negotiation attack)
4. `extract` → `post_exploitation.pbap` (phonebook pull)

This is **not** a full pentest — just a fixed 4-module pipeline plus report generation. For wider coverage use the individual commands (`recon`, `vulnscan`, `exploit`, `extract`) or a playbook via `run-playbook`.

```bash
blue-tap auto TARGET
```

!!! warning "Target Required"
    Unlike interactive commands, `auto` requires the target address upfront — it runs non-interactively and does not launch the device picker.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-a, --hci` | string | auto | HCI adapter (e.g., `hci0`) |
| `--skip` | string (repeatable) | --- | Phase to skip: `recon`, `vulnscan`, `exploit`, `extract` |
| `--yes` | flag | --- | Skip all confirmation prompts |

!!! example "Example: Skip exploitation and extraction, run only recon + vulnscan"
    ```bash
    sudo blue-tap auto 4C:4F:EE:17:3A:89 --skip exploit --skip extract
    ```

### fleet

Multi-target fleet scanning. Discovers all devices in range, then runs assessment against each. Useful for auditing environments with many Bluetooth devices (e.g., parking lots, offices, showrooms).

```bash
blue-tap fleet
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-a, --hci` | string | auto | HCI adapter (e.g., `hci0`) |
| `-d, --duration` | int | `10` | Discovery scan duration in seconds |
| `--class` | string | --- | Filter by device class (e.g., `ivi`, `phone`, `headset`) |

!!! example "Example: Scan all IVI systems in range"
    ```bash
    sudo blue-tap fleet --duration 20 --class ivi
    ```

---

## Utilities

### adapter

Manage Bluetooth adapters, DarkFirmware, and connection state.

```bash
blue-tap adapter [list|info|up|down|reset|set-name|set-class|firmware-status|firmware-install|firmware-init|firmware-spoof|firmware-set|firmware-dump|connections|connection-inspect]
```

=== "Adapter Management"

    | Command | Description |
    |---------|-------------|
    | `list` | Show all HCI adapters with chipset, features, spoofing support |
    | `info` | Detailed adapter info (auto-detects adapter, or `--hci`) |
    | `up` | Bring adapter up (`--hci`) |
    | `down` | Bring adapter down (`--hci`) |
    | `reset` | Reset adapter (`--hci`) |
    | `set-name NAME` | Set Bluetooth name for impersonation (`--hci`) |
    | `set-class DEVICE_CLASS` | Set device class. Accepts a preset name or raw hex (`--hci`) |

    `set-class` presets: `phone`, `laptop`, `headset`, `headphones`, `speaker`, `keyboard`, `mouse`, `gamepad`, `car`, `watch`, `tablet`, `printer`, `camera`.

=== "DarkFirmware"

    | Command | Description |
    |---------|-------------|
    | `firmware-status` | Check DarkFirmware status on RTL8761B |
    | `firmware-install` | Install DarkFirmware (`--source`, `--restore`) |
    | `firmware-init` | Initialize DarkFirmware hooks (activate Hooks 3+4) |
    | `firmware-spoof [ADDRESS]` | Spoof BDADDR via firmware patch (`--restore`) |
    | `firmware-set SETTING VALUE` | Configure firmware params: `lmp-size`, `lmp-slot` |
    | `firmware-dump` | Dump controller memory (`--region`, `--start`/`--end`, `-o`) |

=== "Connection Inspection"

    | Command | Description |
    |---------|-------------|
    | `connections` | List firmware connection table (12 slots). `--dump` for hex |
    | `connection-inspect` | Read live connection security state from controller RAM. `--watch` for continuous |

!!! example "Common adapter operations"
    ```bash
    blue-tap adapter list                              # Show all HCI adapters
    blue-tap adapter info --hci hci0                   # Details for hci0
    sudo blue-tap adapter reset --hci hci0             # Reset adapter
    sudo blue-tap adapter set-name "Galaxy S24"        # Change BT name
    sudo blue-tap adapter set-class phone              # Impersonate a phone
    sudo blue-tap adapter set-class 0x5a020c           # Raw hex device class
    sudo blue-tap adapter firmware-install              # Install DarkFirmware
    sudo blue-tap adapter firmware-spoof AA:BB:CC:DD:EE:FF  # Spoof BDADDR
    sudo blue-tap adapter connection-inspect            # Scan all 12 connection slots
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
| `-a, --hci` | string | auto | HCI adapter to spoof (e.g., `hci0`) |
| `-m, --method` | choice | `auto` | `auto`, `bdaddr`, `spooftooph`, `btmgmt`, `rtl8761b` |

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

!!! example "Example: Run a bundled playbook"
    ```bash
    blue-tap run-playbook --list                            # See available playbooks (no root, no hardware)
    sudo blue-tap run-playbook --playbook ivi-attack 4C:4F:EE:17:3A:89
    ```

    Bundled playbook names (resolved without a path): `ble-assessment`,
    `dos-campaign`, `full-assessment`, `ivi-attack`, `lmp-fuzzing`,
    `passive-recon`, `post-exploit-data`, `quick-recon`. `--list` walks
    the on-disk playbook directory only and skips both the root and
    RTL8761B gates; running an actual playbook still needs `sudo` and a
    dongle for the live steps inside it.

---

## Power-User Commands (Hidden)

These commands do not appear in `--help` but are available for advanced use. They provide direct access to the module registry, which is useful for plugin development and scripting.

```bash
blue-tap run MODULE_ID [KEY=VALUE...]         # Run any registered module directly
blue-tap search TERM [--family F]             # Search modules by keyword
blue-tap info MODULE_ID                       # Show module metadata
blue-tap show-options MODULE_ID               # Show module parameters
blue-tap plugins [list|info|refresh|doctor]   # Plugin management
```

**`run` options:**

| Option | Type | Description |
|--------|------|-------------|
| `-r, --rhost` | string | Target Bluetooth address (alias for `RHOST`) |
| `-a, --hci` | string | HCI adapter (alias for `HCI`) |
| `-s, --session` | string | Session name |
| `--yes` | flag | Bypass destructive confirmation |

Options can also be passed as positional `KEY=VALUE` pairs after the module ID.

!!! note "Exit Codes"
    `run` exits with status **1** when the module execution fails (execution_status `failed`, `error`, or `timeout`), and **0** on success. This makes it safe to use in scripts and automation pipelines (e.g., `blue-tap run module && echo OK || echo FAILED`).

**`search` options:**

| Option | Type | Description |
|--------|------|-------------|
| `-f, --family` | string | Filter by module family |
| `--destructive` | flag | Show only destructive modules |
| `--non-destructive` | flag | Show only non-destructive modules |
| `--requires-pairing` | flag | Show only modules that require pairing |

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

    $ blue-tap run reconnaissance.l2cap_scan -r 4C:4F:EE:17:3A:89 START_PSM=1 END_PSM=100
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
sudo blue-tap fuzz campaign 4C:4F:EE:17:3A:89 -p sdp --duration 1h
blue-tap fuzz crashes list
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
