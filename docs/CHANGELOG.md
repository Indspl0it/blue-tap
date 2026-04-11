# Changelog

All notable changes to Blue-Tap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-04-11

### Summary

Blue-Tap 2.5.0 is the **Standardized Framework** release. Every module now produces structured `RunEnvelope` output with typed `ExecutionRecord` entries, evidence blocks, and artifact references. The report pipeline has been rewritten around module-owned `ReportAdapter` classes. The CLI emits structured lifecycle events throughout all operations. Session logging validates envelope shape. This release lays the groundwork for the upcoming modular framework architecture (Metasploit-style module families, registry, and plugin system).

### Added — Standardized Result Schema

#### Core Framework Contracts

- **`RunEnvelope` schema** (`core/result_schema.py`) — canonical output container for every module invocation with required fields: `schema`, `schema_version`, `module`, `run_id`, `target`, `adapter`, `started_at`/`completed_at`, `operator_context`, `summary`, `executions`, `artifacts`, `module_data`
- **`ExecutionRecord` model** — normalized unit of work within a run with two-layer status taxonomy: `execution_status` (lifecycle: completed/failed/error/skipped/timeout) and `module_outcome` (semantic: confirmed/inconclusive/recovered/observed/etc.)
- **`EvidenceRecord` model** — structured observation container with `summary`, `confidence`, `observations`, `packets`, `state_changes`, `module_evidence`, and `capability_limitations`
- **`ArtifactRef` model** — typed pointer to saved files (pcap, log, HTML, JSON) with `artifact_id`, `kind`, `label`, `path`, `execution_id`
- **`validate_run_envelope()`** — schema shape validator for envelope integrity
- **`looks_like_run_envelope()`** — fast heuristic check for session logging
- **Envelope helper functions** — `build_run_envelope()`, `make_execution()`, `make_evidence()`, `make_artifact()`, `envelope_executions()`, `envelope_module_data()`

#### Structured CLI Event System

- **`emit_cli_event()`** (`core/cli_events.py`) — structured event emitter with required fields: `event_type`, `module`, `run_id`, `target`, `adapter`, `timestamp`, `message`, `details`
- **13 defined event types** — `run_started`, `phase_started`, `execution_started`, `execution_result`, `execution_skipped`, `pairing_required`, `recovery_wait_started`, `recovery_wait_progress`, `recovery_wait_finished`, `artifact_saved`, `run_completed`, `run_aborted`, `run_error`
- **Every CLI command** now emits lifecycle events — operators always know what started, what's running, and when it's done

#### Report Adapter Architecture

- **`ReportAdapter` ABC** (`core/report_contract.py`) — module-owned report interface with `accepts()`, `ingest()`, `build_sections()`, `build_json_section()`
- **`SectionModel`/`SectionBlock`** data models — typed report section containers replacing raw HTML string generation
- **12 report adapters** — one per module type:
  - `DiscoveryReportAdapter` — scan result tables with device properties, risk indicators
  - `VulnscanReportAdapter` — CVE/non-CVE finding cards with evidence, execution logs
  - `AttackReportAdapter` — attack outcome cards with phase tracking, evidence
  - `AutoReportAdapter` — 9-phase pentest summary with per-phase execution records
  - `DataReportAdapter` — PBAP/MAP/OPP/AT extraction summaries with artifact links
  - `AudioReportAdapter` — HFP/A2DP/AVRCP session summaries with capture artifacts
  - `DosReportAdapter` — DoS check results with recovery probe outcomes
  - `FirmwareReportAdapter` — DarkFirmware operations with KNOB detection cards
  - `FuzzReportAdapter` — per-protocol campaign runs with crash details and corpus stats
  - `LmpCaptureReportAdapter` — LMP sniff session summaries
  - `ReconReportAdapter` — reconnaissance campaign results with correlation analysis
  - `SpoofReportAdapter` — spoof operations with before/after MAC evidence
- **Block renderer system** (`report/renderers/`) — `BlockRendererRegistry` with typed block renderers for tables, paragraphs, text, and custom block types
- **`render_sections()`** — converts `SectionModel` lists into HTML via block renderers

#### Report Generator Refactor

- **Adapter-driven report generation** — `generator.py` now orchestrates via `REPORT_ADAPTERS` registry: dispatches envelopes to matching adapters, collects `SectionModel` output, renders HTML/JSON through shared renderers
- **Generator no longer contains module-specific logic** — all CVE interpretation, evidence formatting, and finding classification moved to adapters
- **Unified ingestion pipeline** — both HTML and JSON reports consume the same adapter output, preventing report format divergence

### Added — Module Envelope Builders

Each module family has a dedicated envelope builder in `core/`:

- **`attack_framework.py`** — `build_attack_result()` for exploitation modules (BIAS, KNOB, BLUFFS, hijack, SSP/encryption downgrade, CTKD)
- **`audio_framework.py`** — `build_audio_result()` for HFP/A2DP/AVRCP sessions
- **`auto_framework.py`** — `build_auto_result()` with `build_auto_phase_execution()` for 9-phase auto pentest
- **`data_framework.py`** — `build_data_result()` for PBAP/MAP/OPP/AT data extraction
- **`firmware_framework.py`** — `build_firmware_status_result()`, `build_firmware_dump_result()`, `build_connection_inspect_result()`, `build_firmware_operation_result()` for DarkFirmware operations
- **`fuzz_framework.py`** — `build_fuzz_result()` for fuzzing campaign runs
- **`recon_framework.py`** — `build_recon_result()` for reconnaissance operations
- **`scan_framework.py`** — `build_scan_result()` for discovery scans
- **`spoof_framework.py`** — `build_spoof_result()` with MAC before/after evidence, method verification

### Added — Module Standardization

#### Discovery & Scan

- **Scan commands produce `RunEnvelope`** — `scan classic`, `scan ble`, `scan combined`, `scan all`, `scan inquiry`, `scan watch` all log full envelopes to session
- **Campaign correlation output** wrapped in scan envelopes with correlation evidence
- **Fleet scan** logs actual scan envelope instead of raw device list

#### Reconnaissance

- **All 13 recon commands** produce envelopes via `build_recon_result()` — auto, sdp, gatt, fingerprint, ssp, rfcomm, l2cap, capture, capture-analyze, pairing-mode, ble-sniff, lmp-capture, lmp-intercept, combined-sniff, crackle, extract-keys, wireshark-keys
- **Recon CLI helpers** — `_recon_cli_context()`, `_recon_emit()`, `_recon_start()`, `_recon_result()`, `_recon_skip()` for consistent event emission
- **Capture analysis** wrapped in recon correlation envelopes
- **HCI capture** — improved parser, stale PID detection, capture analysis integration

#### Vulnerability Assessment

- **Vulnscan produces structured envelope** (`blue_tap.vulnscan.result`) with scanner metadata, per-check execution logs, finding summaries, and evidence
- **CVE check execution tracking** — each check records execution_status + module_outcome + evidence
- **Fleet assessment** builds reports from standardized scan and vuln envelopes

#### Exploitation

- **BIAS** — per-phase `ExecutionRecord` entries (spoof, connect, inject, verify) with structured evidence
- **KNOB** — probe and brute-force phases produce typed execution records with key-size evidence
- **BLUFFS** — per-variant (A1 LSC downgrade, A3 SC→LSC) execution records with DarkFirmware capability reporting
- **SSP downgrade** — execution tracking across SSP probe, legacy force, PIN brute phases with lockout evidence
- **Hijack** — 4-phase tracking (spoof, connect, monitor, exploit) with per-phase success/failure evidence
- **CTKD** — probe result standardization with MAC normalization and cross-transport key evidence
- **Encryption downgrade** — 3 method variants (disable, toggle, SC-reject) produce execution records with LMP evidence
- **DoS** — all checks wrapped in `RunEnvelope` with recovery probe outcomes, timing evidence, and severity

#### Post-Exploitation

- **PBAP/MAP** — structured data envelopes with extraction counts, artifact refs, parsed entry metadata
- **HFP** — all 8 subcommands (call, answer, hangup, volume, dtmf, sco, codec, diagnostics) log audio envelopes
- **A2DP** — capture/record/eavesdrop/play/stream/loopback produce audio envelopes with duration, codec, sample rate evidence
- **AVRCP** — all 10 subcommands (play, pause, next, prev, volume, info, shuffle, repeat, monitor, flood) log structured envelopes
- **AT commands** — extraction responses parsed into structured device artifacts with field-level evidence
- **OPP** — transfer diagnostics across dbus and raw fallback paths with artifact tracking
- **Bluesnarfer** — extraction operations produce data envelopes

#### Fuzzing

- **Per-protocol `RunEnvelope`** — each protocol fuzz run produces its own envelope with crash/corpus/timing evidence
- **Run IDs** — every fuzz campaign gets a stable run_id carried through all events and artifacts
- **Crash lifecycle events** — `execution_result` emitted for each crash with severity and reproduction steps
- **Utility commands** (list-crashes, replay, import-pcap) emit structured events
- **Legacy fuzz commands removed** — all fuzzing routes through the standardized engine

#### Adapter & Firmware

- **Adapter commands** (up, down, reset, set-name, set-class) log general envelopes to session
- **Firmware status/install/init/dump** emit lifecycle events and log envelopes
- **Connection inspect** builds envelope with per-slot KNOB detection findings
- **Spoof commands** produce spoof envelopes with before/after MAC proof and method verification

#### Auto Pentest

- **9-phase `RunEnvelope`** with per-phase `ExecutionRecord` entries (discover, fingerprint, recon, vulnscan, pair, exploit, fuzz, dos, report)
- **Phase skip tracking** — skipped phases produce execution records with skip reason evidence
- **Summary counters** — per-phase success/fail/skip counts in envelope summary

#### Playbook / Run Mode

- **Playbook execution** produces `RunEnvelope` with per-step execution records
- **Lifecycle events** emitted per playbook step (run_started, execution_started, execution_result, run_completed)

### Added — Shared OBEX Client

- **`core/obex_client.py`** — unified dbus-fast OBEX client for PBAP, MAP, and OPP with shared session management, error handling, and transfer tracking
- **`PBAPSession`** — PBAP phonebook access with folder navigation, vCard pull, property filtering
- **`MAPSession`** — MAP message access with folder listing, message pull, notification registration
- **`OPPSession`** — OPP file push with progress tracking and transfer validation
- **Shared OBEX error hierarchy** — `ObexError`, transport-level vs protocol-level error distinction

### Added — DoS Expansion

- **Modular CVE-backed DoS probes** for BLE, AVRCP, and AVDTP paths
- **Recovery probe validation** — real ATT request validation instead of simple ping
- **DoS guide** (`docs/dos-guide.md`) — workflow documentation
- **DoS CVE matrix** (`docs/dos-cve-matrix.md`) — coverage mapping
- **Structured DoS metadata** in report generation

### Added — Profile Environment Doctor

- **`env-doctor` command** — prerequisite checker for BlueZ, OBEX, PulseAudio, and audio subsystem readiness
- **OBEX capability detection** — validates dbus-fast OBEX transport availability
- **Audio prerequisites** — PulseAudio module availability, Bluetooth source/sink detection

### Added — Framework Architecture Plan

- **Modular framework architecture plan** (`thoughts/plans/2026-04-11-blue-tap-framework-architecture-plan.md`) — 13-phase migration plan to Metasploit-style module families with registry, contracts, and plugin system
- **Framework architecture rules** (`.claude/rules/blue-tap-architecture.md`) — enforced development rules for all agents: import paths, family classification, registry requirements, schema rules, migration protocol

### Added — Testing

- **36 new envelope tests** across 3 test files:
  - `test_spoof_envelope.py` (11 tests) — envelope shape, validation, success/failure/restore outcomes, MAC evidence, adapter round-trip
  - `test_firmware_envelope.py` (17 tests) — status/dump/inspect/operation builders, KNOB detection, partial hooks, artifact refs
  - `test_auto_envelope.py` (8 tests) — per-phase executions, skip/fail evidence, summary counters, validation
- **Fuzz envelope tests** — l2cap-sig transport map, transport overrides, raw frame format, connect failure finalization
- **Report adapter regression tests** — standardized rendering validation
- **Attack envelope regression tests** — BIAS/KNOB/BLUFFS/hijack/SSP/CTKD/encryption downgrade envelope validation
- **Discovery regression tests** — scan envelope shape validation
- **Media/data regression tests** — HFP/A2DP/AVRCP/PBAP/MAP envelope validation
- **PBAP/MAP/media regression fixtures** — structured test data

### Changed

- **Report generator** completely refactored — adapter-driven architecture replaces monolithic parsing; generator orchestrates layout and dispatch only
- **Session logging** now validates envelope shape — non-envelope data logged at debug level for audit traceability
- **`clone_device_identity()` return type** changed from `bool` to `dict` with `success`, `method`, `original_mac`, `target_mac`, `verified`, `error` fields
- **`spoof_address()`/`bdaddr()`/`spooftooph()`/`btmgmt()`/`rtl8761b()` return types** changed from `bool` to structured dicts with per-operation evidence
- **`restore_original_mac()` return type** changed from `bool` to dict with `restored_mac` and `method`
- **Adapter input validation** — `device_class` hex format/range validation (0x000000-0xFFFFFF), `device_name` length validation (max 248 bytes UTF-8)
- **DarkFirmware detection** — failures logged instead of silenced; adapter power recovery when stuck DOWN after SSP toggle
- **DarkFirmware CLI bootstrap** — smart skip for non-hardware commands (scan/report/session); partial hook status downgraded from info to warning
- **Fuzz engine** — `transport_overrides` parameter for per-protocol channel/hci_dev override; extracted `_finalize_single_run()` for consistent envelope construction on error paths
- **Crash replay** — removed `_StubTransport` fallback, added `RawACLTransport` support
- **L2CAP-sig fuzzing** — rewired to raw ACL via DarkFirmware instead of standard L2CAP socket
- **AT deep fuzzing** — context-aware injection corpus with RFCOMM surface autodiscovery, batch runner across hfp/phonebook/sms/injection channels
- **Transport hardening** — DarkFirmware presence check in LMP and RawACL `connect()` returns False instead of crashing
- **DoS probe timeouts** — hardened timeout handling for unresponsive targets
- **Attack cleanup** — improved cleanup paths in attack modules and recon transport retries
- **Fleet reports** — built from standardized scan and vuln envelopes instead of ad hoc data
- **Demo report data** — standardized around run envelopes

### Fixed

- **`clone_device_identity` callers** — `bias.py` and `hijack.py` used `if not clone_device_identity(...)` which always evaluated False after the bool→dict migration (non-empty dicts are truthy); fixed to check `result.get("success", False)`
- **Recon capture-stop** — `HCICapture.stop()` returns a string path, not a dict; two stray copy-paste blocks called `result.get("success")` on the string, raising `AttributeError`
- **Recon lmp-sniff** — `artifacts` variable referenced in `build_recon_result()` but never initialized, causing `NameError` on every execution
- **Recon nrf-sniff** — same `NameError` — `artifacts` undefined before `build_recon_result()`
- **RAM BDADDR patching** — corrected controller spoofing memory write for RTL8761B
- **HFP reconnect socket leak** — fixed socket resource leak in HFP reconnection path
- **DoS result/report normalization** — aligned DoS result keys with report adapter expectations
- **Report merge conflict marker** — removed leftover `<<<<<<< HEAD` marker from `generator.py`
- **btmgmt public-addr errors** — `btmgmt public-addr` call errors now handled safely instead of crashing

### Removed

- **Legacy fuzz commands** — all standalone fuzz protocol commands removed; all fuzzing routes through the unified engine
- **`_StubTransport` fallback** in crash replay — replaced with proper transport selection

---

## [2.3.2] - 2026-04-09

### Added — Structured Vulnerability Scanner Framework

This release turns `vulnscan` into the single end-to-end vulnerability assessment entry point, adds modular OTA CVE detection coverage, and extends the report pipeline to preserve per-check execution evidence for both CVE and non-CVE checks.

#### CVE Detection Framework

- **Shared CVE result framework** (`attack/cve_framework.py`) — centralized finding builder, status constants, per-check summary helpers, structured `CveCheck` / `CveSection` metadata, and vulnscan result envelope generation
- **Structured vulnscan envelope** — `blue_tap.vulnscan.result` now carries scanner metadata, finding summaries, CVE execution logs, and non-CVE execution logs for report generation and downstream parsing
- **Per-check execution logging** — scanner records primary status, finding count, status counts, and evidence samples for each check instead of only emitting a flat findings list

#### Modular OTA CVE Probe Coverage

- **Airoha RACE checks** (`attack/cve_checks_airoha.py`) — OTA detection for:
  - `CVE-2025-20700` unauthenticated RACE over GATT
  - `CVE-2025-20701` unauthenticated RACE over BR/EDR
  - `CVE-2025-20702` link-key disclosure over confirmed RACE transport
- **AVRCP checks** (`attack/cve_checks_avrcp.py`) — OTA behavioral probes for:
  - `CVE-2021-0507`
  - `CVE-2022-39176`
- **BNEP checks** (`attack/cve_checks_bnep.py`) — OTA probes for:
  - `CVE-2017-0783`
  - `CVE-2017-13258`
  - `CVE-2017-13260`
  - `CVE-2017-13261`
  - `CVE-2017-13262`
- **BLE SMP checks** (`attack/cve_checks_ble_smp.py`) — pairing-aware OTA checks for:
  - `CVE-2024-34722`
  - `CVE-2018-9365`
- **GATT / ATT checks** (`attack/cve_checks_gatt.py`) — OTA differential checks for:
  - `CVE-2022-0204`
  - `CVE-2023-35681`
- **HID / HOGP checks** (`attack/cve_checks_hid.py`) — OTA checks for:
  - `CVE-2020-0556`
  - `CVE-2023-45866`
- **L2CAP checks** (`attack/cve_checks_l2cap.py`) — OTA differential checks for:
  - `CVE-2019-3459`
  - `CVE-2018-9359`
  - `CVE-2018-9360`
  - `CVE-2018-9361`
  - `CVE-2020-12352`
  - `CVE-2022-42896`
  - `CVE-2022-20345`
  - `CVE-2022-42895`
  - `CVE-2026-23395`
- **BR/EDR pairing checks** (`attack/cve_checks_pairing.py`) — pairing-driven probes for:
  - `CVE-2020-26558`
  - `CVE-2022-25837`
  - `CVE-2019-2225`
- **Raw ACL check** (`attack/cve_checks_raw_acl.py`) — DarkFirmware-backed BlueFrag boundary probe for `CVE-2020-0022`
- **SDP continuation check** (`attack/cve_checks_sdp.py`) — OTA continuation-state replay probe for `CVE-2017-0785`

#### Non-CVE Modular Scanner Coverage

- **RFCOMM / OBEX non-CVE module** (`attack/non_cve_checks_rfcomm.py`) with structured checks for:
  - sensitive RFCOMM profile reachability
  - hidden RFCOMM channels
  - low-security RFCOMM acceptance
  - OBEX authorization posture
  - automotive diagnostics and serial responder detection
- **BLE non-CVE module** (`attack/non_cve_checks_ble.py`) with structured checks for:
  - writable GATT surface classification
  - sensitive writable BLE control/DFU/debug surfaces
  - EATT capability posture
  - pairing-method posture with IO-capability context
- **Security-posture module** (`attack/non_cve_checks_posture.py`) with structured checks for:
  - legacy PIN lockout / throttling behavior
  - device-class posture and corroboration
  - LMP feature posture and prerequisites

#### Reporting and Documentation

- **Dedicated vulnscan matrix** (`docs/vulnscan-cve-matrix.md`) listing the CVEs actually checked by `blue-tap vulnscan` plus the modular non-CVE checks that are part of the same scan path
- **HTML report enhancement** — report generator now renders Non-CVE and CVE check execution tables with richer finding metadata
- **JSON report enhancement** — exported vulnerability report data now preserves structured vulnscan runs

### Changed

- **`vulnscan` command model** — runs the full scanner in one invocation; `--active` no longer required
- **BIAS input handling** — `--phone` remains available as optional paired-phone context
- **Non-CVE finding semantics** — exposure and posture checks now distinguish reachable transport vs actual unauthenticated access
- **Writable GATT analysis** — separates generic writable characteristics from sensitive writable surfaces
- **EATT reporting** — treated as protocol capability / posture instead of implicit weakness
- **PIN lockout analysis** — stronger retry sampling and timing interpretation
- **Device class and LMP feature reporting** — serve as scanner posture/context signals

### Fixed

- **Airoha false positives** — GATT RACE detection requires valid unauthenticated RACE response
- **Airoha RFCOMM overclaim** — BR/EDR RACE detection no longer guesses RFCOMM channel 1
- **Airoha link-key confirmation** — chains from confirmed RACE transport
- **L2CAP patched-response handling** — `CVE-2022-20345` accepts documented patched reject outcomes
- **L2CAP duplicate-identifier logic** — `CVE-2026-23395` evaluates second duplicate response
- **LE credit-based response parsing** — corrected in `CVE-2022-42896` and `CVE-2023-35681`
- **Off-by-one L2CAP response guard** — requires full 12-byte buffer
- **Pairing CVE overclaims** — `CVE-2019-2225` and `CVE-2022-25837` no longer overclaim from weak evidence
- **BlueFrag confirmation heuristic** — stays conservative unless boundary probe produces defensible evidence
- **Android GATT CVE overclaims** — removed incomplete coverage for `CVE-2023-40129`, `CVE-2024-0039`, `CVE-2024-49748`
- **Parallel active-probe nondeterminism** — transport-mutating checks executed in deterministic sequence
- **Report/rendering mismatch** — understands structured vulnscan envelope instead of assuming legacy flat findings

### Removed

- **Top-level `assess` command** — `vulnscan` is now the single CLI entry point
- **`vulnscan --active` public workflow** — no longer advertised
- **Stale assess-based playbooks and docs**

## [2.3.1] - 2026-04-08

### Added — Deep DarkFirmware Integration

This release completes the DarkFirmware integration with full bidirectional LMP traffic parsing, connection table inspection, in-flight packet modification, and new attack modules.

#### DarkFirmware HCI Infrastructure

- **Bidirectional traffic parsing** — TXXX (outgoing LMP), ACLX (outgoing ACL), RXLC (incoming LC) marker parsers added to HCI VSC socket alongside existing AAAA (incoming LMP)
- **Complete LMP opcode tables** — 61 standard + 22 extended opcodes per BT Core Spec v5.4 with human-readable decode helper
- **In-flight LMP modification** — `set_mod_mode()`/`clear_mod_mode()` for Hook 2 modes: passthrough, modify, drop, opcode-drop, persistent-modify, auto-respond
- **Raw ACL injection** — `send_raw_acl()` bypasses BlueZ L2CAP stack for below-stack packet injection
- **Oversize LMP PDUs** — TX max raised from 17 to 28 bytes for BrakTooth-style oversize packet testing
- **read_memory quirk fix** — RTL8761B returns 4 bytes only with size=0x20 (not size=4)

#### Hook Management & Connection Inspection

- **Hook initialization** — `init_hooks()` writes Hook 3/4 backup pointers to RAM and verifies all 4 hooks active
- **ConnectionInspector** — Read/write controller RAM for encryption state, key material, auth flags, Secure Connections flag across all 12 connection slots
- **DarkFirmwareWatchdog** — Dual detection (udevadm monitor + periodic health check) with 5s debounce and 3s settle for multi-day fuzzing
- **Firmware-level detection** — Replaced MAC-based DarkFirmware detection with hook backup probe + LMP TX echo verification
- **CONNECTION_SLOT_SIZE fix** — Corrected from 500 to 0x2B8 (696 bytes) per reverse engineering findings

#### Below-HCI Attack Modules

- **CTKD attack** (`attack/ctkd.py`) — CVE-2020-15802 cross-transport key derivation probe: snapshots key material before/after Classic attack, detects shared keys across slots
- **KNOB RAM verification** — ConnectionInspector confirms actual key_size in controller memory after KNOB negotiation injection
- **20 LMP state confusion tests** — BrakTooth-style test cases as vulnerability scanner seeds
- **Raw L2CAP builders** (`fuzz/protocols/l2cap_raw.py`) — Frame builders + 15 malformed fuzz tests for below-stack injection

#### Fuzzing Transports

- **LMPTransport.send_and_collect()** — Send packet, wait for responses from rx_queue and lmp_log_buffer
- **LMPTransport.check_alive()** — HCI Read BD Addr probe to detect dongle crash during fuzzing
- **RawACLTransport** — Full transport class routing send() through send_raw_acl(), ACL handle resolution, ACLX/RXLC event monitoring

#### CLI Integration

- **Root privilege check** on startup (allows --help/--version/demo without root)
- **Startup hardware detection** — Probe dongle, check DarkFirmware, init hooks, start watchdog (non-blocking)
- **`adapter firmware-init`** — Manual hook initialization command
- **`adapter connection-inspect`** — Dump connection table from controller RAM
- **`ctkd` command** — Cross-transport key derivation attack with probe and monitor modes

### Fixed

- **OBEX PUT opcode** — `OBEX_PUT` was 0x82 (PUT-Final) instead of 0x02 (PUT), breaking multi-part OPP file transfers
- **_read_bytes() alignment bug** — Unaligned addresses truncated reads; rewrote to track actual bytes extracted per iteration

### Changed

- **README restructured** — Split 1876-line README into focused docs: features, usage guide, troubleshooting, IVI simulator. README retains purpose, architecture, quick start with hyperlinks to detailed docs.
- **Memory read/write logging** — Changed from `info()` to `logger.debug()` to reduce noise during fuzzing

---

## [2.3.0] - 2026-04-05

### Added — DarkFirmware Below-HCI Attack Platform

This release extends Blue-Tap below the HCI boundary with a custom firmware platform for RTL8761B (TP-Link UB500). The DarkFirmware integration enables direct LMP packet injection and monitoring — capabilities that no standard BlueZ tool provides.

**Key breakthrough:** Live RAM patching of the RTL8761B controller — BDADDR spoofing and 17-byte LMP PDU injection/capture work without adapter reset, by writing directly to the running firmware's SRAM via HCI VSC 0xFC61/0xFC62. The original DarkFirmware research supported basic injection; Blue-Tap extends this with live RAM patching, full 17-byte LMP PDU support (not just 10-byte), and structured LMP log parsing.

#### DarkFirmware Core (4 new modules, 1,772 lines)

- **`core/hci_vsc.py`** (584 lines) — Raw HCI socket interface for vendor-specific commands: LMP injection (VSC 0xFE22), controller memory read (0xFC61), memory write (0xFC62), background LMP monitor thread with structured 56-byte log parsing
- **`core/firmware.py`** (788 lines) — DarkFirmware lifecycle management: RTL8761B detection, firmware install/restore with automatic backup, live RAM BDADDR patching (no reset), firmware status verification via memory read, controller memory dump, USB reset
- **Runtime detection** — CLI auto-detects RTL8761B and DarkFirmware at startup, shows green "active" status or warning with install command
- **Firmware CLI commands** — `adapter firmware-status`, `firmware-install`, `firmware-spoof`, `firmware-set`, `firmware-dump`, `connections`

#### Below-HCI Attacks (2 new modules, 771 lines)

- **BLUFFS attack** (`attack/bluffs.py`, 408 lines) — CVE-2023-24023 session key derivation downgrade with probe/A1 (LSC key-downgrade)/A3 (SC→LSC downgrade) variants via DarkFirmware LMP injection
- **Encryption downgrade** (`attack/encryption_downgrade.py`, 363 lines) — 3 attack methods beyond KNOB: `LMP_ENCRYPTION_MODE_REQ(mode=0)` to disable encryption, stop/start toggle for weaker renegotiation, SC PDU rejection to force Legacy SC

#### LMP Protocol Support

- **LMP protocol builder** (`fuzz/protocols/lmp.py`, 2,020 lines) — Full LMP PDU construction for 30+ opcodes
- **LMP fuzzing** — 12th protocol added to campaign engine via HCI VSC injection
- **LMP sniffing** — `recon lmp-sniff`, `lmp-monitor`, `combined-sniff`
- **LMP DoS** — `dos lmp` with configurable method, count, and delay

#### Other New Features

- **TargetedStrategy wired into engine** — `--strategy targeted` now works in fuzz campaigns
- **Session adapter tracking** — `set_adapter()` auto-records which HCI adapter is used
- **Protocol DoS expansion** — LMP-level DoS attacks via DarkFirmware
- **BIAS LMP injection mode** — BIAS attack can now use DarkFirmware for LMP-level role-switch manipulation
- **KNOB LMP negotiation** — KNOB attack uses DarkFirmware for direct LMP key-size manipulation
- **Sniffer rewrite** — Replaced USRP B210 SDR integration with DarkFirmware LMP capture
- **Playbooks module** — `blue_tap/playbooks/` for reusable assessment sequences
- **UI dashboard** — `blue_tap/ui/dashboard.py` for live attack monitoring

### Improved

- **README overhauled** — BLUFFS, encryption downgrade, DarkFirmware sections; RTL8761B as primary adapter
- **Hardware recommendations** — RTL8761B (TP-Link UB500) promoted to primary adapter
- **Fuzz engine** — Baseline learning with explicit `recv_timeout=5.0`; field weight tracker logs exceptions
- **SDP parser** — PSM channel fallback returns `0` (int) for type consistency
- **CLI command grouping** — Added bluffs, encryption-downgrade to Rich-Click groups

### Fixed

- **fleet_assess NameError** — `risk_color` undefined when `results` is empty
- **_StubCorpus missing `get_all_seeds()`** — Baseline learning silently skipped
- **Silent field tracker exceptions** — `except: pass` now logs warnings
- **Baseline recv timeout** — Passes explicit timeout instead of relying on transport default

### Removed

- **USRP B210 SDR integration** — Replaced by DarkFirmware LMP capture
- **CSR8510 from recommended hardware** — Superseded by RTL8761B
- **All mock-based test files** (26 files, 21K lines) — Replaced with real hardware validation workflows

## [2.2.0] - 2026-04-04

### Added

- **Active BIAS vulnerability probe** in vulnscan with `--active --phone` flags
- **Parallel vulnerability analysis** — ThreadPoolExecutor cuts scan time ~60%
- **KNOB real brute-force** — XOR decryption against captured ACL data with L2CAP header validation
- **ACL traffic capture** for KNOB — 60-second capture windows via hcidump
- **IVI confidence scoring** in fingerprint — normalized 0.0-1.0 confidence float
- **Codec auto-detection** in HFP — detects CVSD (8kHz) vs mSBC (16kHz)
- **Sample rate auto-detection** in A2DP — queries PulseAudio source info
- **PulseAudio loopback tracking** — module ID stored for reliable cleanup
- **Session logging** added to all CLI commands
- **2,109 unit tests** across 13 new test files (66% line coverage)

### Improved

- Scanner, SDP, GATT, RFCOMM/L2CAP, HCI Capture, Fingerprint, Vuln Scanner, Hijack, SSP Downgrade, BIAS, HFP, A2DP, AVRCP, MAC Spoofing, Auto Pentest, Fleet, CLI (rich-click migration), README

### Fixed

- 12 specific bug fixes across scanner, spoofer, hijack, BIAS, HFP, A2DP, RFCOMM, fleet, encryption enforcement

### Removed

- **Link Key Harvest** feature

## [2.1.1] - 2026-03-31

### Added

- **10 protocol-level DoS attacks** targeting L2CAP, SDP, RFCOMM, OBEX, and HFP
- **Link key harvest and persistent access**
- **SSP downgrade attack**
- **KNOB attack execution** (CVE-2019-9506)
- **Fleet-wide assessment**
- **Full 9-phase automated pentest** (`auto` command)
- Changelog file

### Changed

- **Report overhaul**: modern UI, pentest narrative
- **Auto command** rewritten from 4-phase to 9-phase methodology

### Fixed

- L2CAP DoS socket operations, DoS result dict key mismatch, KNOB probe missing fields, fleet assess crash, report collector namespaces, DoS grouping keywords

## [2.1.0] - 2026-03-31

### Added

- **Response-guided intelligent fuzzing engine** with 6 layers of analysis (state inference, anomaly-guided mutation, structural validation, timing coverage, entropy leak detection, watchdog reboot detection)
- **Full engine integration** of all 6 phases into the campaign main loop
- **Live dashboard intelligence panel**
- **Fuzzing intelligence section in reports**
- **Link key harvest and persistent access**
- **SSP downgrade attack**
- **KNOB attack execution**
- **Fleet-wide assessment**
- GPL v3 license, SVG banner, `requirements.txt`, 129 unit tests

### Changed

- Fuzzing engine strategy dispatch, response fingerprinting, AVRCP rewritten to `dbus-fast`, dependency overhaul, report generator complete rewrite

### Fixed

- Campaign duration reset on resume, stub API mismatches, response_analyzer monitor bug, banner SVG spacing

## [2.0.1] - 2026-03-30

### Fixed

- Duration limit reset on campaign resume
- Stub API mismatches
- Version display hardcoded in CLI

## [2.0.0] - 2026-03-29

### Added

- Initial public release with full Bluetooth Classic and BLE penetration testing toolkit
- Device discovery, service enumeration, fingerprinting
- Vulnerability scanner with 20+ CVE checks
- PBAP, MAP, AT, OPP data extraction
- Connection hijacking, BIAS, HFP, A2DP, AVRCP
- DoS attacks, multi-protocol fuzzing engine
- 4 fuzzing strategies, crash database, minimization
- Session management, HTML/JSON reports, auto pentest, playbooks

[2.5.0]: https://github.com/Indspl0it/blue-tap/compare/v2.3.2...v2.5.0
[2.3.2]: https://github.com/Indspl0it/blue-tap/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/Indspl0it/blue-tap/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/Indspl0it/blue-tap/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Indspl0it/blue-tap/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Indspl0it/blue-tap/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.1.0
[2.0.1]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Indspl0it/blue-tap/releases/tag/v2.0.0
