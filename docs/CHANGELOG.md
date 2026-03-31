# Changelog

All notable changes to Blue-Tap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2026-03-31

### Added

- **10 protocol-level DoS attacks** targeting L2CAP, SDP, RFCOMM, OBEX, and HFP
- **Link key harvest and persistent access** (`keys` command group)
- **SSP downgrade attack** (`ssp-downgrade` command group)
- **KNOB attack execution** (`knob` command group, CVE-2019-9506)
- **Fleet-wide assessment** (`fleet` command group)
- **Full 9-phase automated pentest** (`auto` command): discovery, fingerprinting, recon, vuln assessment, pairing attacks, exploitation, coverage-guided fuzzing (1hr default), DoS testing, report generation
- **Comprehensive CLI logging** across all 100+ commands: every operation now logs start, progress, result, and errors with context
- Changelog file (`docs/CHANGELOG.md`)

### Changed

- **Report overhaul**: modern UI with Inter/JetBrains Mono fonts, Tailwind-inspired color palette, rounded cards, soft severity badges, pentest narrative text in every section, support for v2.1.1 findings (key harvest, SSP downgrade, KNOB, fleet, protocol DoS)
- **Auto command** rewritten from 4-phase (discover, vulnscan, hijack, report) to 9-phase pentest methodology with coverage-guided fuzzing and DoS testing. New options: `--fuzz-duration`, `--skip-fuzz`, `--skip-dos`, `--skip-exploit`

### Fixed

- L2CAP DoS attacks use valid socket operations (not raw signaling)
- DoS result dict key mismatch with CLI
- KNOB probe missing `internalblue_available` field
- Fleet assess crash on invalid MAC address
- Report collector namespaces new attack types (key_harvest, ssp_downgrade, knob_attack)
- DoS grouping keywords cover all protocol-level attacks

## [2.1.0] - 2026-03-31

### Added

- **Response-guided intelligent fuzzing engine** with 6 layers of analysis:
  - Phase 1: Protocol state inference adapted from AFLNet — state extractors for all 8 BT protocols (SDP, ATT, L2CAP, RFCOMM, SMP, OBEX, BNEP, AT), directed state graph with AFLNet scoring formula, state-aware seed selection
  - Phase 2: Anomaly-guided field mutation weights inspired by BrakTooth — per-field anomaly/crash tracking, adaptive mutation probabilities, field-aware mutator using protocol field maps for all 13 protocol variants
  - Phase 3: Structural response validation for all 13 protocols — PDU self-consistency checks (length fields, error codes, FCS), cross-protocol confusion detection, response code regression tracking, size oscillation detection
  - Phase 4: Timing-based coverage proxy — per-opcode latency profiling (p50/p90/p99), online timing cluster detection as code path signal, latency spike/drop detection with consecutive spike escalation
  - Phase 5: Entropy-based information leak detection — Shannon and Renyi entropy analysis, sliding window entropy for localized leak detection, heap pattern scanning (DEADBEEF, BAADF00D, etc.), request echo detection, per-protocol expected entropy baselines, composite leak scoring with confidence levels
  - Phase 6: Watchdog reboot detection adapted from Defensics — target health monitoring, exponential backoff reconnection probing, reboot cycle detection, zombie state detection, latency degradation analysis, crash candidate ranking with confidence scores, adaptive cooldown
- **Full engine integration** of all 6 phases into the campaign main loop with persistence and feedback
- **Live dashboard intelligence panel** showing target health status, states discovered per protocol, timing clusters, anomaly counts by type, and hot mutation fields ranked by weight
- **Fuzzing intelligence section in reports** — state coverage graph, field weight analysis with bar charts, target response baselines, health event timeline (HTML and JSON)
- **Link key harvest and persistent access** (`keys` command group) — capture pairing exchanges, extract link keys via tshark, persistent key database (JSON), reconnect using stored keys without re-pairing, key verification
- **SSP downgrade attack** (`ssp-downgrade` command group) — probe SSP capabilities, force legacy PIN mode via IO capability manipulation and SSP disable, automated PIN brute force (0000-9999) with lockout detection
- **KNOB attack execution** (`knob` command group) — CVE-2019-9506 vulnerability probe, minimum encryption key negotiation (InternalBlue LMP injection or btmgmt fallback), demonstrative key brute force
- **Fleet-wide assessment** (`fleet` command group) — discover and classify all nearby devices (IVI/phone/headset/computer/wearable), per-device vulnerability assessment, consolidated fleet report with overall risk rating
- GPL v3 license
- SVG banner for README
- `requirements.txt` for fresh Kali/Ubuntu installs
- 129 unit tests covering all new fuzzing modules (state inference, field weights, response analyzer, health monitor)

### Changed

- **Fuzzing engine** (`engine.py`): strategy dispatch now instantiates real strategy classes (RandomWalk, CoverageGuided, StateMachine) instead of ignoring the `--strategy` flag; coverage-guided feedback loop wired (calls `strategy.feedback()` after every send/recv); crash payloads automatically added back to corpus as seeds; adaptive protocol scheduling weights toward high-crash-rate protocols; multi-packet sequence support for state-machine strategy
- **Response fingerprinting** improved from `sha256(response[:32])` to `sha256(len_bucket:opcode:err_byte:prefix)` — catches different error codes that share leading bytes
- **AVRCP module** (`avrcp.py`): rewritten from `dbus-python`/`PyGObject` to `dbus-fast` (pure Python, pre-built wheels) — `pip install` now works without system C headers
- **Dependencies**: replaced `dbus-python` and `PyGObject` (C extensions, no wheels on PyPI) with `dbus-fast` (pure Python); moved `scapy` and `pulsectl` from optional to hard dependencies; all deps now install via `pip` without `apt`
- **Report generator** (`generator.py`): complete rewrite with professional dark-theme HTML, table of contents, executive summary with SVG donut/bar charts, overall risk rating badge, metric dashboard, assessment timeline, structured recon tables, finding cards with evidence blocks, crash reproduction steps, print-friendly CSS
- **CLI version display**: now reads from single source `__version__` instead of hardcoded strings (CLI `--version`, banner, report footer)
- **README**: comprehensive rewrite of Protocol Fuzzing section with architecture diagram, intelligence layer documentation, research citations; added sections for link key harvest, SSP downgrade, KNOB, fleet assessment; updated "What Blue-Tap Does" to reflect all current capabilities; streamlined installation instructions

### Fixed

- **Campaign duration reset on resume** — `prior_elapsed` field added to `CampaignStats` so resumed campaigns continue timing from where they left off instead of restarting the clock
- **Stub API mismatches** — `_StubMutator.mutate()` return type aligned with `CorpusMutator` (returns `bytes` not `tuple`); `_StubTransport` changed from `.is_connected()` method to `.connected` property; `_StubCrashDB.log_crash()` returns `int`; `_StubCorpus.add_seed()` returns `None`
- **`response_analyzer.py` monitor bug** — `props.on_properties_changed()` replaced with correct `dbus-fast` API (`bus.add_message_handler()` + `AddMatch` rule)
- **Banner SVG spacing** — tightened gap between "BLUE" and "TAP" text
- Missing system dependency documentation for `libcairo2-dev`, `libgirepository1.0-dev`, `gir1.2-glib-2.0`

## [2.0.1] - 2026-03-30

### Fixed

- Duration limit reset on campaign resume
- Stub API mismatches (mutator, transport, crash_db, corpus return types)
- Version display hardcoded in CLI and banner (now reads from `__version__`)

### Changed

- Moved `dbus-python` and `PyGObject` to optional dependencies (later reverted to hard deps, then replaced with `dbus-fast`)

## [2.0.0] - 2026-03-29

### Added

- Initial public release
- Bluetooth Classic and BLE device discovery
- SDP, GATT, RFCOMM, L2CAP service enumeration
- Device fingerprinting (BT version, chipset, manufacturer)
- Vulnerability scanner with 20+ CVE checks
- PBAP phonebook extraction
- MAP message extraction
- AT command interface and data extraction
- OBEX Object Push
- Connection hijacking via MAC spoofing and identity cloning
- BIAS attack (CVE-2020-10135)
- HFP call control and audio interception
- A2DP media stream capture
- AVRCP media control and DoS
- DoS attacks (pairing flood, name flood, L2ping flood, PIN brute force)
- Multi-protocol fuzzing engine (SDP, L2CAP, ATT, RFCOMM, SMP, OBEX, AT, BNEP)
- 4 fuzzing strategies (random walk, coverage-guided, state-machine, targeted)
- Crash database with deduplication and reproduction
- Crash minimization (binary search, delta debugging, field reducer)
- btsnoop pcap replay with mutation
- CVE reproduction patterns (CVE-2017-0785, CVE-2017-0781, SweynTooth, CVE-2018-5383, CVE-2024-24746)
- Session management with auto-logging
- HTML and JSON report generation
- Automated attack chain (`auto` command)
- Command sequencing (`run` command with playbook support)
- Rich terminal UI with styled output, tables, panels
- Live fuzzing dashboard with keyboard controls

[2.1.1]: https://github.com/Indspl0it/blue-tap/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.1.0
[2.0.1]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Indspl0it/blue-tap/releases/tag/v2.0.0
