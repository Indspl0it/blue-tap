# BT-Tap Fuzzing

This document describes the current fuzzing subsystem as implemented in the repository. It is not a speculative build plan. The source of truth remains the code under `bt_tap/fuzz/`, the CLI help output, and the regression tests.

## Role in the project

The fuzzing subsystem exists to support practical Bluetooth protocol testing inside the same session and reporting model as the rest of BT-Tap. That means fuzzing artifacts are treated as first-class assessment evidence rather than as one-off scripts.

In practical terms, the fuzzing stack is designed around:

- protocol-specific entry points instead of a single opaque fuzzer
- resumable and evidence-preserving campaign workflows
- crash capture and replay
- corpus and minimization support
- report ingestion from the active session

## Current command surface

`bt-tap fuzz` currently exposes:

- campaign and orchestration:
  - `campaign`
  - `cve`
  - `replay`
  - `minimize`
  - `bss`
- crash and corpus management:
  - `crashes`
  - `corpus`
- protocol-focused fuzzers:
  - `l2cap`
  - `l2cap-sig`
  - `rfcomm`
  - `rfcomm-raw`
  - `sdp`
  - `sdp-deep`
  - `obex`
  - `bnep`
  - `ble-att`
  - `ble-smp`
  - `at`
  - `at-deep`

The command surface is intentionally mixed. Some commands are legacy single-protocol fuzzers, some are campaign-oriented, and some are utilities for replay or reduction after a failure has already been captured.

## Implemented architecture

The active fuzzing code lives under `bt_tap/fuzz/` and is split into a few distinct layers:

- transport and execution:
  - transport helpers
  - campaign engine
  - replay and minimization
- state and evidence:
  - crash database
  - corpus management
  - campaign state and stats
- protocol builders:
  - `l2cap`
  - `rfcomm`
  - `sdp`
  - `obex`
  - `bnep`
  - `att`
  - `smp`
  - `at_commands`
- strategy layer:
  - random walk
  - targeted mutations
  - state-machine oriented strategies
  - coverage-guided support hooks

This structure is materially different from the older one-file fuzzing model and is the main reason this document exists separately from the top-level README.

## Session integration

Fuzzing is wired into the same session model as the rest of the CLI:

- command execution is logged through the CLI command wrapper
- crashes can be stored in SQLite databases under the session
- campaign state and stats can be loaded back into report generation
- evidence files under `sessions/<name>/fuzz/` are reportable artifacts

The report generator already looks for:

- `fuzz/crashes.db`
- `fuzz/*_crashes.db`
- `fuzz/campaign_stats.json`
- `fuzz/campaign_state.json`
- `fuzz/corpus/`
- `fuzz/evidence/`
- `fuzz/capture.btsnoop`

That means fuzz output is not just stored; it is consumable by the reporting layer without manual post-processing.

## Operational constraints

The fuzzing subsystem is intentionally pragmatic and inherits the realities of Linux Bluetooth testing:

- not every protocol mutation described in the Bluetooth specs is reachable through normal user-space sockets
- some low-level attack surfaces require raw HCI, firmware hooks, SDR workflows, or external tooling
- adapter behavior differs by chipset and firmware
- optional third-party tooling is not guaranteed to exist on the host

This is why the project separates protocol theory from implementation reality. The protocol reference in [lessons-from-bluetooth-specifications.md](/mnt/c/Users/santh/Desktop/Projects/personal/BT-Tap/lessons-from-bluetooth-specifications.md) should be read together with the fuzzing code, not instead of it.

## Practical expectations

What the fuzzing subsystem is good for right now:

- running protocol-specific fuzzers from one CLI surface
- preserving crash evidence in-session
- replaying and minimizing previously captured failures
- generating operator-friendly artifacts for later reporting
- supporting both one-shot tests and longer campaign-oriented runs

What should not be assumed:

- complete raw baseband or LMP mutation coverage
- identical behavior across adapters and kernels
- complete independence from external Bluetooth tooling

## Maintenance guidance

When updating the fuzzing subsystem:

- keep CLI help, this document, and actual behavior aligned
- document new evidence files if the report generator should ingest them
- prefer adding regression coverage for crash handling, replay, and workflow wiring
- avoid documenting planned features here as implemented behavior

## Verification

Useful checks when touching the fuzzing stack:

```bash
python3 -m bt_tap.cli fuzz --help
python3 -m bt_tap.cli fuzz campaign --help
python3 -m bt_tap.cli fuzz crashes --help
python3 -m bt_tap.cli fuzz corpus --help
pytest -q
ruff check bt_tap target
```
