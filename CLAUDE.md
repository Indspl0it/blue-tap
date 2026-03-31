# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Install (editable, from source)
pip install -e .

# Run all tests
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_fuzz_state_inference.py -v

# Run a single test
python3 -m pytest tests/test_fuzz_response_analyzer.py::TestSDPValidator::test_length_mismatch -v

# Lint (current ruff config only checks critical rules)
python3 -m ruff check blue_tap/

# Lint with expanded rules (unused imports, vars, type annotations)
python3 -m ruff check blue_tap --select F401,F841,F821,F632,B,UP

# Syntax check a single file
python3 -m py_compile blue_tap/fuzz/engine.py

# Verify CLI loads
python3 -c "from blue_tap.cli import main; print('OK')"

# Build PyPI package
python3 -m build
```

## Architecture

Blue-Tap is a Click-based CLI (`blue_tap/cli.py`, ~3500 lines) that registers 20+ command groups with 100+ subcommands. All commands are defined in `cli.py` with lazy imports to the module that does the actual work.

### Module Layout

- **`blue_tap/cli.py`** — All CLI commands. Each command handler resolves the target address, imports the relevant module, calls it, logs to session, and displays output via Rich. This is the only entry point.
- **`blue_tap/core/`** — Foundation: adapter management, Classic+BLE scanning, MAC spoofing.
- **`blue_tap/recon/`** — Service enumeration (SDP, GATT, RFCOMM, L2CAP), fingerprinting, HCI capture, nRF/USRP stubs.
- **`blue_tap/attack/`** — Attack modules. Each is standalone (hijack, PBAP, MAP, HFP, A2DP, AVRCP, BIAS, DoS, protocol DoS, vuln scanner, key harvest, SSP downgrade, KNOB, fleet assessment, auto pentest).
- **`blue_tap/fuzz/`** — The fuzzing engine (see below).
- **`blue_tap/report/`** — HTML/JSON report generator with inline SVG charts.
- **`blue_tap/utils/`** — Shared utilities: Rich output helpers, session management, BT helpers.

### Fuzzing Engine Architecture

The fuzzer has multiple layers that compose at runtime:

1. **`engine.py`** — `FuzzCampaign` orchestrates the main loop. It owns transports, corpus, mutator, and wires in the intelligence modules.
2. **`strategies/`** — Four strategies (random_walk, coverage_guided, state_machine, targeted) each implement `generate(protocol) -> (bytes, list[str])`. State machine returns `list[bytes]` for multi-packet sequences.
3. **`state_inference.py`** — Extracts protocol state IDs from responses, builds a directed state graph (AFLNet-adapted), scores states for selection.
4. **`field_weight_tracker.py`** — Parses packets into typed fields per protocol, tracks which fields produce anomalies, adjusts mutation weights.
5. **`response_analyzer.py`** — Three-layer anomaly detection: structural PDU validation, timing deviation, entropy-based leak detection.
6. **`health_monitor.py`** — Watchdog reboot detection, degradation, zombie state.
7. **`protocols/`** — 8 protocol builders (SDP, L2CAP, ATT, RFCOMM, SMP, OBEX, AT, BNEP) that generate seed corpus.
8. **`cli_commands.py`** — Live Rich dashboard for campaigns, crash management CLI.

### Session & Report Flow

Every command logs structured results via `log_command(name, data, category, target)` from `utils/session.py`. The report command (`report/generator.py`) reads all session JSON files, feeds them into section builders, and produces HTML/JSON. The report uses Inter + JetBrains Mono fonts (Google Fonts CDN), Tailwind-inspired colors, and inline SVG charts.

### Key Design Patterns

- **Conditional imports with feature flags**: Modules that may not be installed (transport, crash_db, corpus, strategies) are imported in `try/except` blocks with `_HAS_*` flags. Stub classes provide fallback behavior.
- **Session skip for read-only commands**: `main()` uses `click.get_current_context().invoked_subcommand` to skip session creation for `session`, `report`, `adapter` commands.
- **LoggedCommand**: Custom Click command class — currently a passthrough (auto-logging was removed to prevent double-counting; each command logs its own results).
- **Lazy module imports**: CLI command handlers import their attack/recon module inside the function body, not at module level. This keeps `cli.py` import fast.

## Version Management

Single source of truth: `blue_tap/__init__.py:__version__`. Also update `pyproject.toml:version` and `VERSION` file. The CLI and report read `__version__` at runtime. Do not hardcode version strings elsewhere.

## Important Constraints

- All BT protocol fields: SDP/OBEX are big-endian, L2CAP/ATT/SMP are little-endian, RFCOMM follows TS 07.10.
- `bluetoothctl` commands must include `select <hci>` before `pair`/`trust`/`connect` in multi-adapter setups.
- MAP message handles from remote devices must be sanitized with `os.path.basename()` before using as filenames (path traversal risk).
- The fuzzing engine's `_generate_fuzz_case()` returns either `bytes` or `list[bytes]` (for state-machine multi-packet sequences). The main loop normalizes to a list.
- Response analyzer's structural validators must handle truncated/empty responses without crashing — every validator starts with length checks.
