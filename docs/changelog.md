# Changelog

All notable changes to Blue-Tap are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.5] - 2026-05-01

### Summary

Blue-Tap 2.6.5 brings a global, modular **dry-run** capability across every command. A single root-level `--dry-run` flag (or `$BLUE_TAP_DRY_RUN=1`) makes any command print the resolved plan and exit without touching hardware or sending packets — destructive modules are previewed without their CONFIRM=yes gate and session writes are skipped. Future modules inherit this for free: the framework `Invoker` short-circuits any module that doesn't opt into a richer dry-run path. The fuzzer's existing seed-replay dry-run is preserved (it remains the canonical opt-in via `supports_dry_run = True`). The release also ships a TOML-based user config loader, a static dependency graph for registered modules, three new bundled playbooks, a third-party plugin template, OBEX-style import/export for the on-disk fuzz corpus, and copy-paste remediation hints in `blue-tap doctor`.

### Added — Global dry-run

- **Root `--dry-run` flag** on `blue-tap`. Honored by every workflow command (`discover`, `recon`, `vulnscan`, `exploit`, `dos`, `extract`, `fuzz`, `auto`, `fleet`, `run-playbook`, `run`).
- **`$BLUE_TAP_DRY_RUN=1`** environment-variable equivalent for CI usage and to scope dry-run across `run-playbook` step re-invocations.
- **`RunContext.dry_run`** field threaded from `Invoker.invoke(..., dry_run=True)` into every module call. Single source of truth — modules read `ctx.dry_run`, never raw flags.
- **`Module.supports_dry_run`** class attribute (default `False`). When `False`, `Invoker` short-circuits with a synthesized "planned" envelope (`module_outcome="not_applicable"`, `module_data["dry_run"]=True`) before instantiating the module — so every existing module inherits dry-run automatically. When a module sets it to `True`, the `Invoker` calls `run()` with `ctx.dry_run=True` and the module owns the dry-run path (e.g. `fuzzing.engine` uses MockTransport).
- **Destructive-gate bypass in dry-run.** Destructive modules (KNOB, BIAS, BLUFFS, CTKD, all DoS checks, fuzzing) preview cleanly without `CONFIRM=yes` — the synthesized envelope still surfaces `destructive=true` so the operator sees the danger label.
- **Session-write skipping.** `Invoker.invoke_with_logging(..., dry_run=True)` no longer persists the run envelope to the session log — a no-op preview is not worth saving.
- **`dry_run_planned`** added to the canonical CLI event taxonomy.
- **Hardware-direct command guards** for every command that bypasses `Invoker`: `adapter list/info/up/down/reset/set-name/set-class/firmware-install/firmware-init/firmware-spoof/firmware-set/firmware-status/firmware-dump/connection-inspect/connections`, `spoof`, `doctor`, `report`, `fuzz cve`, `fuzz replay`, `fuzz minimize`, `fuzz corpus generate/minimize/import`, and `fuzz crashes replay`. Each prints "would do X" and exits cleanly without opening raw HCI sockets, probing the environment, or writing seed files.
- **Playbook executor propagation.** `run-playbook` scopes `BLUE_TAP_DRY_RUN=1` across each step's re-entered `make_context` call (try/finally so the prior value is always restored). Target/HCI resolution is short-circuited to a placeholder so dry-run never blocks on the interactive picker.
- **Fuzz back-compat.** `fuzz campaign --dry-run` and `fuzz benchmark --dry-run` keep working with their existing semantics; both now also OR-honor the root flag and env var. Seed-replay byte-level reproducibility invariant preserved.
- **Per-protocol fuzz dry-run.** `fuzz sdp-deep`, `l2cap-sig`, `rfcomm-raw`, `ble-att`, `ble-smp`, `bnep`, `obex`, and `at-deep` route through a single `_run_via_engine()` seam that swaps the real transport for `MockTransport` when dry-run is active — adding a new per-protocol subcommand inherits dry-run without further wiring.
- **Dry-run wall-clock cap.** `fuzz campaign --duration 1h --dry-run` would otherwise loop `MockTransport` for the full hour. The engine now caps dry-run runs to **5 seconds** and **100 iterations** (whichever comes first). Both caps are env-overridable via `BT_TAP_DRY_RUN_MAX_DURATION_SECONDS` and `BT_TAP_DRY_RUN_MAX_ITERATIONS` for CI tuning.

### Added — User config loader

- **`~/.config/blue-tap/config.toml`** — operators no longer have to repeat `--hci hci0 -s mysession` on every invocation. Resolution order: `--config /path/to/file.toml` → `$BLUE_TAP_CONFIG` → `$XDG_CONFIG_HOME/blue-tap/config.toml` → `~/.config/blue-tap/config.toml`. CLI flags always override config values (Click's `default_map` precedence). No file present → behaviour identical to prior versions.
- **Schema (minimal):** `[default]` section with `hci` and `session` keys. Unknown sections or keys raise `ConfigError` at load time with the offending path and key name in the message — no silent typos. Validation lives at the file boundary; the rest of the CLI consumes the parsed `BlueTapConfig` dataclass.

### Added — Module dependency graph

- **`blue_tap.framework.registry.dependency_graph`** — best-effort static graph of which other registered modules each module imports, computed lazily from the `entry_point`-referenced source file plus every `.py` in the same package. `blue-tap info <module>` is the first consumer and now lists `Depends on:` and `Used by:` per module.
- **Detection limits surfaced in code, not hidden.** Only `from blue_tap.modules.<family>.<name>[.subpath]` imports count; string-based dispatch (`importlib.import_module`, entry points, `getattr`) is invisible. `try/except ImportError` and `if TYPE_CHECKING` imports still count as *potential* runtime dependencies. Self-imports inside the same package are excluded.

### Added — Plugin template

- **`examples/plugin-template/`** — minimal working example of a third-party Blue-Tap plugin. Copy the directory, rename the package, edit the module body, and `pip install .` to register an out-of-tree module. Demonstrates the `blue_tap.modules` entry-point group, the `Module` subclass shape, family/outcome wiring, and the `RunEnvelope` return contract. `pyproject.toml` pins `blue-tap >= 2.6.5` so plugin authors get a clear failure if they install against an older release.

### Added — Bundled playbooks

- **`ble-assessment.yaml`** — BLE-only sweep. Advertisement scan → GATT enumeration → BLE-specific CVE checks. ~5 minutes, low risk (active GATT probing only after a target is selected).
- **`dos-campaign.yaml`** — Structured denial-of-service and resilience testing. Discovery → vulnscan → full DoS check series with per-check recovery wait. ~10 minutes, **high risk** (may render target unresponsive; requires `--yes`).
- **`post-exploit-data.yaml`** — Post-pairing extraction. Re-enumerate SDP → pull contacts (PBAP) → pull messages (MAP) → pull files (OPP/OBEX) → AT-channel responses. ~15 minutes, medium risk (requires existing bond).

### Added — Fuzz corpus archive support

- **`Corpus.export_to_tarball(output_path, protocol=None)`** — bundles the on-disk corpus into a gzipped tarball whose layout mirrors `base_dir` exactly (top-level entries are protocol directories, each with `*.bin` seeds and an optional `interesting/` subdirectory). Raises `FileNotFoundError` if the corpus directory doesn't exist; `ValueError` if a non-existent protocol is requested. Returns `{output_path, size_bytes, seeds_exported, protocols}`.
- **`Corpus.import_from_tarball(tarball_path)`** — counterpart importer. Rejects path-traversal entries (`..`, absolute paths) before extraction and uses `tarfile`'s `filter="data"` mode as defence-in-depth. Returns `{seeds_imported, protocols, size_bytes}`.
- **`fuzz corpus export TARBALL [-p PROTOCOL]` and `fuzz corpus import TARBALL`** — CLI surfaces for the above. Both honour `--dry-run` (preview the operation without writing or extracting). Failed seed-generation passes now log via the standard `logging` channel instead of swallowing the exception silently.

### Added — `blue-tap doctor` remediation hints

- **`→ fix:` lines** under every missing tool, service, or capability limitation. The hint is a copy-paste shell command (`sudo apt install bluez bluez-tools`, `sudo systemctl enable --now bluetooth`, `systemctl --user enable --now pipewire pipewire-pulse`, etc.). Hint dictionaries (`TOOL_FIX_HINTS`, `SERVICE_FIX_HINTS`) live alongside the detector so adding a new check naturally pairs with adding its remediation.
- **`limitation_hints` dict** added to `detect_profile_environment()` output (alongside the existing `tools`, `services`, `adapters`, `obex`, `summary` keys — backward compatible). Each capability limitation message maps to its remediation command (empty string when no automatic fix is meaningful).

### Tests

- **`tests/test_dry_run_rollout.py`** (17 tests) — framework hooks, `Invoker` short-circuit, destructive-gate bypass, `supports_dry_run` opt-in, env-var propagation, per-family smoke tests across discovery / reconnaissance / assessment / exploitation / fuzzing.
- **`tests/test_config_loader.py`** — TOML loader: precedence chain, unknown-key rejection with path in error message, malformed TOML, missing file, env-var override.
- **`tests/test_dependency_graph.py`** — graph builder: known-good imports counted, string-based dispatch ignored, self-imports excluded, lazy build, cache stability.
- **`tests/test_fuzz_corpus_io.py`** — tarball round-trip: layout preservation, path-traversal rejection, single-protocol filter, missing-source error.
- **`tests/test_doctor_fix_hints.py`** — every documented tool/service has a hint; hints are non-empty strings; `limitation_hints` dict shape.
- **`tests/test_playbook_dispatch.py`** — three new bundled playbooks parse cleanly, list under `run-playbook --list`, and dispatch the expected step sequence.
- **`tests/test_plugin_template_smoke.py`** — the bundled plugin template installs, registers its module, and produces a valid `RunEnvelope`.
- **Test counts:** 456 → 581 passing, 0 failing. Lint (`ruff`) clean.

## [2.6.4] - 2026-04-30

### Summary

Blue-Tap 2.6.4 turns the fuzzer into a research-grade tool: a typed Python API (`run_campaign`, `benchmark`, `MockTransport`, `CampaignResult`, `BenchmarkResult`) for driving campaigns from notebooks and CI, byte-level reproducibility through a `ContextVar`-scoped random source, an in-process mock transport that lets the full mutation/strategy/state-tracker pipeline run with zero hardware, and a new `fuzz benchmark` subcommand that runs N independent trials and aggregates per-metric statistics. Three CLI bugs are fixed along the way (sub-help dispatcher under target subcommand groups, `run-playbook` exit code on failure, and a root-gate bypass for test runners).

> **Researchers / scripting users:** the new programmatic surface lives at `blue_tap.modules.fuzzing` (`run_campaign`, `benchmark`, `compare_campaigns`, `compare_benchmarks`, `CampaignResult`, `BenchmarkResult`, `MockTransport`). It bypasses RunContext / RunEnvelope, so it's a *thin* wrapper for ablation studies and not a replacement for the CLI / playbook flow.

### Added — Programmatic research API

- **`run_campaign(target, protocols, *, strategy, duration, max_iterations, session_dir, cooldown, seed, dry_run, random_source, trajectory_interval_seconds, ...) -> CampaignResult`** — drives a single `FuzzCampaign` and returns a typed result. Catches `KeyboardInterrupt` (records `aborted=True`) and any other exception (records `error=...`) so batch experiments survive single bad runs. Surfaces engine-side terminal failures (`{"result": "error", "reason": "..."}`) into `CampaignResult.error` rather than returning an all-zero "successful" result.
- **`benchmark(target, protocols, *, strategy, trials, base_seed, ...) -> BenchmarkResult`** — runs N independent trials with seeds `base_seed, base_seed+1, …`, aggregates `crashes`, `crashes_per_kpkt`, `iterations`, `packets_sent`, `runtime_seconds`, and `states_discovered` into per-metric `(n, mean, stdev, median, min, max)` dicts. Errored / aborted trials are kept in `BenchmarkResult.trials` and counted separately so callers can decide whether to discard them.
- **`compare_campaigns(a, b) -> CampaignDelta`** — per-metric delta (positive = `b > a`).
- **`compare_benchmarks(a, b) -> BenchmarkComparison`** — Cohen's d on the per-trial `crashes_per_kpkt` series with pooled stdev plus a conventional effect-size label (`negligible` / `small` / `medium` / `large`).
- **`CampaignResult.to_csv(path)`** — atomically writes trajectory rows (`elapsed_seconds`, `iterations`, `packets_sent`, `crashes`, `errors`, `states`, `transitions`) as CSV. Empty trajectory still produces a header-only file. Fixed column order, missing keys become empty cells, extra keys are dropped.
- **`CampaignResult.to_json()` / `from_json()` and `BenchmarkResult.to_json()` / `from_json()`** — round-trip every field except `raw_summary` (which is omitted from `to_dict` by design). `BenchmarkResult.from_dict` rejects compact-form payloads (no `trials` key) — aggregate stats alone can't reconstruct per-trial state.
- **`MockTransport`** — in-process subclass of `BluetoothTransport` used under `dry_run=True`. Bounded `collections.deque` for sent payloads (default 64), validates `send_buffer_len ≥ 1`, rejects non-`bytes` sends, validates that response factories return `bytes`, swallows factory exceptions and surfaces them as `recv() → None`. Documented thread-safety contract.
- **`list_strategies()` / `list_protocols()`** — typed introspection of registered strategies and protocols for menu-driven UIs.

### Added — Engine reproducibility plumbing

- **`blue_tap.modules.fuzzing._random`** module — canonical random-source mechanism for the fuzzing tree. Holds the active source in a `contextvars.ContextVar` so concurrent campaigns in different threads / async contexts don't cross-contaminate.
    - `random_bytes(n)` — replaces every `os.urandom(n)` call site in `mutators.py`, `engine.py`, `protocols/{att,bnep,lmp,smp}.py`, and `strategies/{coverage_guided,random_walk,state_machine,targeted}.py`. Validates `n ≥ 0` at the boundary.
    - `set_random_source(callable)` context manager — installs a pluggable `Callable[[int], bytes]` for the lifetime of the with-block. Restores on exit (including exception paths). Validates that the source is callable.
    - `derive_random_source_from_seed(seed)` — canonical seed → byte-source mapping shared by both `run_campaign(seed=…)` and the `fuzz campaign --seed` CLI flag, so the two entry points are guaranteed to produce identical streams for the same seed.
- **Byte-level reproducibility contract.** `seed=N` (or `BLUE_TAP_FUZZ_SEED=N`) seeds the global `random` module *and* installs a `random.Random(N).randbytes`-backed source through the ContextVar. Every strategy / mutator / protocol builder reads bytes through that single source — two runs with the same seed produce byte-identical fuzz payloads, not just statistically similar ones. Wall-clock fields (`runtime_seconds`, `packets_per_second`) are explicitly *not* part of the contract.
- **`l2cap_raw.py` two-layer split.** `_STRUCTURAL_L2CAP_RAW_FUZZ_TESTS` is a module-level constant (built once at import); `_random_l2cap_raw_fuzz_tests()` is a function that re-evaluates the random-data entries against the *currently active* random source. `generate_all_l2cap_sig_fuzz_cases()` takes one coherent snapshot of the test list and threads it through a new `_frames_matching_in(tests, prefixes)` helper, so the dedup pass keeps exactly one `echo_oversized` variant per call instead of multiple independently-randomised variants.

### Added — `fuzz campaign` flags

- **`--dry-run`** — runs the full mutation / strategy / state-tracker pipeline against `MockTransport`. Bypasses the pre-loop `l2ping` reachability check, skips crash-recovery liveness probes, pins response latency to `0.0` (so the response analyzer's clustering is also deterministic), and accepts a placeholder target if none is supplied. Intended for CI smoke tests and reproducibility sweeps. Disables `--capture` automatically and is rejected in combination with `--resume`.
- **`--seed N`** — integer seed for byte-level reproducible mutations. Falls back to `BLUE_TAP_FUZZ_SEED` if unset. Rejected in combination with `--resume` (seed isn't part of the persisted campaign state, and silently ignoring it would mislead the operator). Hex (`0x2a`), octal (`0o52`), and decimal literals are all accepted.
- **`--trajectory-interval SECONDS`** — samples `(elapsed_seconds, iterations, packets_sent, crashes, errors, states, transitions)` at most once per `N` seconds inside the main loop; results land in `CampaignResult.trajectory`. Required for non-empty `to_csv` output.

### Added — `fuzz benchmark` subcommand

- **`blue-tap fuzz benchmark TARGET [-p PROTO]... [-s STRATEGY] -t TRIALS (-d DURATION | -n ITERATIONS) [--base-seed N] [--label TEXT] [-o BENCH.json] [--csv-dir DIR] [--cooldown N] [--dry-run] [--trajectory-interval SECONDS]`** — runs N independent trials of the same configuration and aggregates per-metric stats. Prints a Rich summary table (`crashes`, `crashes_per_kpkt`, `iterations`, `packets_sent`, `runtime_seconds`, `states_discovered`; one row each as `n / mean / stdev / min / max`), atomically writes the round-trippable `BenchmarkResult` JSON when `-o` is given, and writes per-trial `trial_{i}.csv` trajectory files into `--csv-dir` (paired with `--trajectory-interval` to make the rows non-empty). Aborted / errored trials still appear in the aggregate but are also surfaced as a separate operator warning. Logs to the active session under `category="fuzz"`.

### Added — Environment variables

- **`BLUE_TAP_FUZZ_SEED`** — default seed for `run_campaign`, `fuzz campaign --seed`, and `fuzz benchmark --base-seed` when no explicit value is passed. Accepts decimal, `0x`-hex, or `0o`-octal. Validated at the boundary in both Python (`ValueError`) and the CLI (`click.BadParameter`). For `benchmark`, the env var resolves to `base_seed` so successive trials still get distinct seeds (`base, base+1, base+2, …`) instead of the same seed being applied identically to every trial.
- **`BLUE_TAP_SKIP_ROOT_CHECK=1`** — bypasses the root and RTL8761B chipset gates in the CLI. Intended for test runners and CI smoke tests under `--dry-run`. Picked up by both `_check_privileges()` and `_check_rtl_dongle()` in `interfaces/cli/main.py` and pre-set in `tests/conftest.py` so the pytest suite can run without `sudo`.

### Fixed — CLI

- **`TargetSubcommandGroup` no longer mis-parses target + subcommand combinations.** `blue-tap recon AA:BB:CC:DD:EE:FF sdp --help` previously produced `No such command ''.` because the empty-`TARGET` placeholder was injected even after a real positional target had been seen, pushing the subcommand into the wrong slot. The peeker now tracks `seen_positional` and only injects the placeholder when the subcommand name is the *first* positional. Value-flag detection runs before the positional check so `--protocol sdp recon` no longer treats `sdp` as a positional. Verified: `recon` / `exploit` / `extract` sub-help dispatches now exit 0 with the correct help text.
- **`run-playbook` exit code on partial failure.** A 1-of-1 failed playbook used to print `✖ Failed: 1` and exit 0 because the `log_command` call swallowed the failure. The runner now raises `SystemExit(1)` after logging when any step fails, so CI can rely on the exit code.

### Changed — CLI defaults

- **`fuzz campaign` and `fuzz benchmark` share the same default protocol set.** Both default to `-p all` (all 16 registered protocols). Earlier benchmark drafts defaulted to `-p sdp` for variance-on-one-surface use cases — that choice is left to the operator (`-p sdp -p rfcomm`) rather than baked into the CLI default, matching the existing `fuzz campaign` behaviour.

### Tests

- **`tests/test_fuzzing_research_api.py`** (new) — 52 tests covering the research API surface: `CampaignResult` / `CampaignDelta` / `BenchmarkResult` / `BenchmarkComparison` shape and round-trip; `MockTransport` validation; `dry_run` end-to-end via `run_campaign` and `benchmark`; engine-error → `CampaignResult.error` propagation; `set_random_source` restore-on-exception; `random_bytes` non-negative-length validation; byte-level reproducibility (same seed → same protocol breakdown across runs, different seeds → different breakdowns); `BLUE_TAP_FUZZ_SEED` env-var resolution including precedence over and conflict with explicit seed kwargs; `derive_random_source_from_seed` determinism; `to_csv` empty/full trajectory, fixed column order, atomic write (no temp leftovers), missing-parent-dir error.
- **`tests/test_fuzz_cli_v2_6_4.py`** (new) — CLI integration tests for the new flags: `--dry-run` + `--seed` reproducibility through the real Click command, `--resume` × `--dry-run` rejection, `--resume` × `--seed` rejection, `--dry-run` automatically disabling `--capture`, env-var seed (`0xdeadbeef`) flowing through to `Seed locked: ...`, env-var validation rejecting non-integer values, full `fuzz benchmark` round-trip (JSON + per-trial CSVs + summary table), `--csv-dir` warning when `--trajectory-interval` is missing, mutually-exclusive `--duration` / `--iterations` validation, env-base-seed driving aggregate-stat reproducibility across two benchmark runs, `--label` flowing through to `BenchmarkResult.label`.
- **Test counts:** 442 → 456 passing, 1 skipped, 0 failing. Lint (`ruff`) clean.

---

## [2.6.3] - 2026-04-25

### Summary

Blue-Tap 2.6.3 makes `module_id` a mandatory field on every envelope, adds the `HARDWARE` outcome family for adapter / firmware operations, hardens the session atomic-write path against `SIGKILL`-induced debris on Linux, fixes two RTL8761B reliability bugs (post-USB-reset firmware-load wait, sub-word memory reads), and ships a batch of CLI usability fixes — the most visible of which is that read-only inspection commands (`report`, `fuzz crashes/corpus/minimize`, `run-playbook --list`) now actually run unprivileged, matching what the docs already promised.

> **Plugin authors:** if your module called `make_execution()` or `build_run_envelope()` without the `module_id=` kwarg, that now raises `ValueError` at construction. Add the family-prefixed id (e.g. `module_id="assessment.my_check"`). The previous "skip outcome validation when module_id is missing" backward-compat path is gone.

### Changed — Framework contracts

- **`module_id` is now mandatory on `make_execution()` and `build_run_envelope()`** — both builders validate the id against `^[a-z0-9_]+(\.[a-z0-9_]+)+$` and raise `ValueError` at construction if the id is missing, malformed, or has an unknown family prefix. The earlier "skip outcome validation when `module_id` isn't supplied" backward-compat path is gone, so misshapen envelopes can no longer reach disk.
- **`FAMILY_OUTCOMES` is the single source of truth.** The redundant `VALID_OUTCOMES_BY_FAMILY` dict in `framework/contracts/result_schema.py` was removed; all outcome validation now goes through `framework/registry/families.py → FAMILY_OUTCOMES`. An unknown family string raises `ValueError` instead of silently no-opping.
- **New `HARDWARE` outcome family** added to `ModuleFamily` for adapter and firmware envelopes (`hardware.adapter_up`, `hardware.firmware_status`, `hardware.firmware_operation`, etc.). Allowed outcomes: `completed`, `installed`, `hooks_active`, `hooks_partial`, `not_loaded`, `prerequisite_missing`, `spoofed`, `rejected`, `restored`, `method_unavailable`, `not_applicable`. Note: `hardware` is an envelope-only family — there is no `modules/hardware/` tree.
- **Per-module `module_id` migration.** Every envelope builder in `framework/envelopes/` (attack/audio/data/firmware/fuzz/recon/scan/spoof) now requires `module_id` from its caller. CLI-side adapter operations migrated from the legacy `module="general"` to typed ids like `hardware.adapter_up`, `hardware.adapter_reset`, `hardware.adapter_set_name`, `hardware.firmware_status`, `hardware.firmware_operation`. The DoS framework's status-to-outcome mapping was refactored from two parallel dicts into a single `_dos_canonical_pair()` function.

### Fixed — Hardware

- **`usb_reset_and_wait()` now waits for firmware load to complete.** After USB reset the kernel can publish the new `hciX` sysfs entry several seconds before the RTL firmware blob finishes loading; VSCs issued in that window bind to stale state. The new `_wait_for_hci_ready()` polls `hciconfig` until the adapter is `UP RUNNING` with a non-zero BDADDR before returning. Default `ready_timeout=6.0s` on top of the existing re-enumeration timeout.
- **`HCIVSCSocket.read_memory()` honours the requested `size`.** The RTL8761B firmware always returns a 4-byte word for VSC `0xFC61`; the wrapper now slices the response to the caller's requested 1–4 bytes (with a `ValueError` for out-of-range sizes) instead of always returning four. This keeps sub-word reads correct at addresses near the end of a memory range.

### Fixed — Sessions

- **Atomic write hardened against `SIGKILL` debris.** On Linux `Session.log_command()` now writes through an `O_TMPFILE` inode that the kernel reaps on process death — a `SIGKILL` mid-write leaves no orphan tempfile on disk. The unnamed inode is materialised via `link()` + `os.replace()` in a microsecond-scale window. Non-Linux platforms (and filesystems that refuse `O_TMPFILE`/`/proc` linkat — 9p, some FUSE, some NFS) fall back to a per-PID named tempfile (`<file>.tmp.<pid>`), so concurrent writers can't clobber each other's tempfiles. Parent-directory `fsync()` after rename guarantees the directory entry survives a power loss right after `os.replace()` returns.

### Fixed — CLI usability

- **Sub-help dispatcher** — `blue-tap recon sdp --help`, `blue-tap exploit knob --help`, and `blue-tap extract contacts --help` now show the subcommand's help instead of the parent's. The new `TargetSubcommandGroup` peeks at args before Click parses and injects an empty `TARGET` placeholder when a bare positional matches a registered subcommand name. Exit code 0 instead of 255.
- **`--help` no longer creates sessions** — `~/.blue-tap/sessions/` (or `./sessions/`) used to accumulate one zero-command directory per `--help` invocation. Help / inspection commands are now session-free.
- **Privilege + hardware gates moved into the Click callback** — Click now resolves the subcommand and validates required arguments *before* the root or RTL8761B gates fire, so `blue-tap garbage` returns Click's native `No such command 'garbage'` (exit 2) instead of the misleading "requires root" message.
- **`session list / show` no longer requires root** — listing/inspecting on-disk sessions is pure file I/O. (Verified end-to-end without `sudo`.)
- **Root + RTL8761B gates now share one skip predicate.** Previously the hardware gate was loosened for `report <dump-dir>`, `fuzz crashes list / show / export`, `fuzz corpus list / minimize`, `fuzz minimize`, and `run-playbook --list`, but the root gate wasn't — so those paths still demanded `sudo` even though they never touched the Bluetooth stack. The two gates now consult the same `_subcommand_needs_hw()` predicate, so the no-root list and the no-hardware list are identical: anything in `_NO_HW_INVOKED` (or matched by `_NO_HW_SUBCOMMANDS`, or `run-playbook --list`) skips both checks. Verified: `blue-tap report ./sessions/...`, `blue-tap fuzz crashes list`, and `blue-tap run-playbook --list` all run end-to-end without `sudo` on a machine with no Bluetooth adapter attached.
- **`report` returns non-zero on error** — the no-session path was returning exit code 0 despite printing `✖ No session active and no dump directory specified`. Same fix applied to `session show <missing>` and the `run-playbook` error paths.
- **`doctor` no longer says "Environment ready" when no adapter is present** — split verdicts: `Environment ready` (tools + adapter), `partially ready` (limitations reported), or `NOT ready` (no adapter).
- **Banner suppressed for `--help` invocations** — was showing the ASCII banner and module-load count even on help-only calls.
- **`run-playbook` listed in the top-level help** — was hidden, now visible under the *Automation* group.
- **`scan classic` corrected to `discover classic`** in `run-playbook` help examples (the `scan` command was renamed during the CLI rework but the docs lagged).
- **`-v / --verbose` no longer reports `INTEGER RANGE`** as its parameter type — clarified as a count flag.

### Tests

- End-to-end smoke verification: `--version`, `--help`, `doctor` (with and without an adapter present), `session list/show`, `demo` (full 9-phase pipeline), `report` (no-session error path), `fuzz crashes list`, and `run-playbook --list` all run cleanly without `sudo` on a machine with no Bluetooth hardware. Hardware-using paths still surface the `No RTL8761B / TP-Link UB500 dongle detected` message and exit 1 cleanly when invoked under `sudo` against an empty machine. Invalid commands surface Click's native `No such command` and exit 2. Zero crashes observed across the matrix.

---

## [2.6.2] - 2026-04-17

### Summary

Blue-Tap 2.6.2 is a small follow-up to 2.6.1 that fixes post-USB-reset verification on RTL8761B adapters and wires up automated GitHub Pages deployment for the docs site.

### Fixed — Hardware

- **`DarkFirmwareManager.usb_reset_and_wait()`** — new method that resets the RTL8761B, waits for teardown, then polls `find_rtl8761b_hci()` until the adapter re-enumerates and returns the new `hciX` name. The kernel can re-enumerate the adapter under a different index after reset (e.g. `hci8 → hci0`); callers that verified post-reset state (`is_darkfirmware_loaded`, `get_current_bdaddr`) were probing the pre-reset name and reporting "verification inconclusive" even when install/patch succeeded
- **`firmware-install` (install + restore)**, **`patch_bdaddr`**, and the startup auto-install prompt now use the re-enumerated `hci` for verification and user-facing messages

### Build

- **Version** bumped to `2.6.2`
- **`.github/workflows/docs.yml`** — new workflow auto-builds MkDocs site with `--strict` and deploys to GitHub Pages on every push to `main`
- **`pyproject.toml`** — license metadata format fixed to satisfy PEP 639 (SPDX expression only, no classifier duplication)

---

## [2.6.1] - 2026-04-17

### Summary

Blue-Tap 2.6.1 is a **stability, ergonomics, and correctness** release on top of 2.6.0. The CLI now supports interactive target selection across every target-taking command (omit the address to get a device picker); the hardware layer picks up a second RTL8761B dongle variant and hardens the DarkFirmware watchdog against concurrent HCI access; several modules that silently "succeeded" while producing wrong results now return honest envelopes; and the module loader can actually unregister + re-import plugin classes instead of leaking descriptors on reload.

### Added — CLI Ergonomics

- **Interactive target picker** — `vulnscan`, `recon`, `exploit`, `extract`, `dos`, `fleet`, `adapter info` now accept `TARGET` as optional. When omitted (or when the argument doesn't match a MAC), a device scan runs and presents a numbered picker
- **`invoke_or_exit()`** (`interfaces/cli/_module_runner.py`) — new helper used by all facade commands; failed module runs now exit with status `1` instead of `0`, so `blue-tap` works correctly in shell pipelines and CI
- **Command-name-aware proxy usage hints** — `dos-<check>`, `vuln-cve-*`, `vuln-<check>`, `recon-hci-capture`, `recon-sniffer` proxy commands now print the exact real-command invocation (e.g. `blue-tap dos TARGET --checks bluefrag` or `blue-tap vulnscan TARGET --cve CVE-2020-0022`) instead of a generic "`<group> <subcommand>`" template
- **`fuzz cve`** — registered proxy command for replaying a known CVE fuzz pattern
- **`run-playbook`** added to no-session command allow-list so `blue-tap run-playbook --list` works without an active session
- **`auto`** — docstring rewritten to state explicitly that this is a 4-module shortcut (SDP recon → vuln_scanner → KNOB exploit → PBAP extract → report), not a "full pentest"; report generation now uses the active session's data correctly and writes `report.html` into the session directory

### Added — Framework

- **`ReportAdapter.priority`** — adapters now carry an integer priority (lower = runs first). Plugin adapters default to `50`; the built-in `vulnscan` fallback adapter is pinned to `200` so third-party adapters are always tried first
- **`get_report_adapters()`** — returns adapters sorted by priority, unifying built-in + plugin-registered adapters; `interfaces/reporting/generator.py` now iterates through this function instead of the static `REPORT_ADAPTERS` tuple (plugin adapters were previously ignored during report generation)
- **`ModuleRegistry.unregister(module_id)`** — returns `True` if the descriptor was present; used by the loader to clean up on `reload=True`
- **`ModuleLoader.load_plugins(reload=True)`** — now unregisters previously-loaded descriptors and evicts cached modules from `sys.modules` before re-importing, so plugin upgrades no longer leak stale classes
- **`function_module()` decorator** — the generated `_FunctionModule` class is now injected into the calling module's namespace so its `entry_point` string resolves at import time; this previously failed silently for any module defined via `@function_module`
- **Recon outcome taxonomy** — `VALID_OUTCOMES_BY_FAMILY["reconnaissance"]` extended with `undetermined`, `partial_observation`, `auth_required`, `not_found`, `not_connectable`, `timeout`, `no_results` to cover the actual envelopes recon modules were already emitting
- **`build_recon_execution(module_id=...)`** — new optional argument so recon executions can record their fully-qualified module ID (e.g. `reconnaissance.campaign`) instead of just `reconnaissance`
- **Session timestamps in UTC** — `framework/sessions/store.py` now uses `datetime.now(timezone.utc).isoformat()` via a single `_now_iso_utc()` helper; prevents naïve-local timestamps from drifting across hosts
- **`OptPath.validate()`** — returns `None` for optional paths with no default instead of raising `OptionError`, letting modules distinguish "path was given" from "path was not set"
- **Plugin discovery diagnostics** — `ModuleRegistry.load_entry_points()` now logs a warning with traceback when discovery fails instead of swallowing the exception silently

### Added — Hardware

- **Second RTL8761B dongle variant** — `firmware.py` now detects both `2357:0604` (TP-Link UB500) and `0bda:8771` (generic Realtek) via a new `RTL8761B_VID_PIDS` tuple; `is_darkfirmware_loaded()` and USB presence checks iterate both VID:PIDs
- **DarkFirmware watchdog thread safety** — `DarkFirmwareWatchdog` now uses a `threading.Lock` around `_reinit_count`, `_last_reinit`, and a new `_reinit_in_progress` flag; prevents double-reinit races when a USB event fires during an in-flight reinit
- **HCIVSCSocket.recv_event() concurrency guard** — raises `RuntimeError` if called from an external thread while the LMP monitor loop is running on the same socket; two concurrent readers were causing event-frame corruption
- **`adapter_up`, `adapter_down`, `adapter_reset`** — now auto-resolve `hci=None` via `resolve_active_hci()` and return a structured error dict if no adapter can be discovered, instead of NPE-ing downstream
- **L2CAP DoS socket binding** — `_l2cap_raw_socket()` now binds to the requested HCI's local address before connecting, so DoS traffic goes out the intended adapter in multi-dongle setups

### Fixed — Hardware

- **MAC spoofer fallback** — `spoof_rtl8761b()` now falls through from RAM patch to firmware-file patch when RAM patch reports success but the adapter still reports the wrong BDADDR (previously returned `verified=False` with `success=True`, confusing the caller)
- **MAC spoofer file-write permission** — `save_original_mac()` now catches `PermissionError` and emits a user-facing warning pointing at the root-owned state file, instead of raising into the caller
- **Firmware RAM-patch length check** — `patch_bdaddr_ram()` now requires exactly 4 bytes back from `vsc.read_memory()` before attempting the file-patch fallback, instead of accepting any byte count ≥4
- **Firmware file-read leak** — `is_darkfirmware_loaded()` now uses `with open(...)` for modalias probes (previously leaked file descriptors in the multi-adapter loop)

### Fixed — Modules

- **`assessment.fleet`** — UUID matching now canonicalizes short form, `0x` prefix, and full 128-bit Base UUID; previously only matched exact `"0x111f"` literal, so IVIs advertising `"111f"`, `"0000111f-0000-1000-8000-00805f9b34fb"`, or uppercase variants were misclassified as generic headsets
- **`assessment.vuln_scanner._check_blueborne`** — removed the `bluetoothd --version` probe (it reports the local stack version, not the target's); now relies on SDP-extracted `BlueZ X.Y` strings only. Removes a class of false-positive BlueBorne findings on assessments run from a Kali attacker
- **`exploitation.encryption_downgrade`** — `results["success"]` now reflects whether at least one downgrade method actually worked; previously hardcoded `True` even when the target rejected every method
- **`exploitation.hijack`** — bails out of the attack chain when recon fails; was previously entering SSP/pairing with no target data
- **`reconnaissance.sdp.search_services_batch`** — UUID matching normalizes `0x`-prefixed hex and checks the full `class_id_uuids` list against candidate service records; previously missed services whose class IDs used a different textual form than the filter UUID
- **`reconnaissance.fingerprint`** — `vendor` derivation now uses `manufacturer` (the actual output field) instead of a non-existent `chipset.vendor` nested key, so `has_signal` correctly flips on vendor-only fingerprints
- **`reconnaissance.hci_capture`** — capture loop uses a clamped `remaining` time slice and exits cleanly when `remaining <= 0`, preventing a hang at the boundary of `duration`
- **`reconnaissance.campaign`** — `_cleanup_tmp_artifact()` unlinks the tempfile on all four capture-step failure paths (was leaking empty PCAPs into the session dir)
- **`reconnaissance.prerequisites`** — prerequisite `missing` list now filters by a new `applicable` flag per check, so a BLE-only target no longer reports DarkFirmware/LMP prerequisites as "missing"
- **`post_exploitation.pbap`** — `extract_all` now deduplicates `PBAP_PATH_ALIASES` to 9 unique canonical paths instead of pulling the same phonebook 28 times (one for every alias key)
- **`post_exploitation.map_client`** — all `self.sock.send()` calls go through a `_send()` helper that raises if not connected; adds `None` guards on `_setpath_root`, `_setpath_down`, `_recv_response`; message body `LENGTH:` header now reflects byte length of the UTF-8 encoded body, not character count
- **`post_exploitation.bluesnarfer`** — auto-discovers the AT RFCOMM channel via SDP (tries `Dial-up Networking`, `Serial Port`, `DUN`, `SPP`) instead of raising `OptionError` when CHANNEL was not supplied; also preserves original case on raw AT commands (was uppercasing vendor-specific payloads and breaking them)
- **`post_exploitation.a2dp`** — `record` action now uses `capture_a2dp()` (was calling an undefined `record_car_mic()`); `bytes` field in result reflects actual on-disk size after capture; `set_sink_volume()` failure is now a warning instead of an uncaught exception
- **`post_exploitation.hfp`** — codec-negotiation response now distinguishes `ERROR` (rejected) from silent fallback; `dial`/`answer`/`hangup` success flags reflect `"ERROR" not in response` rather than truthy-ness alone; `silent_call()` guards on socket being connected before issuing ATD
- **`fuzzing.engine`** — protocol names now run through `canonical_protocol()` which maps operator aliases (`pbap`, `map`, `opp`, `att`, `smp`, `hfp`, `phonebook`, `sms`) to canonical transport keys; mutator fallback generates fresh random bytes when the mutator returns an empty payload; strategy-unavailable path now updates `self.strategy` so the envelope records what actually ran; `CrashDB` is closed in a `finally` block in `_finalize()`
- **`fuzzing.health_monitor`** — removed unused `_check_zombie(protocol_responses)` and replaced it with a per-protocol consecutive-failure tracker (`_protocol_consecutive_fails`); a target is declared `ZOMBIE` when ≥2 tracked protocols have ≥3 consecutive failures while L2CAP is still alive; `update()` now accepts `protocol=` to identify which protocol's response was observed
- **`fuzzing.campaign`** — `CONTINUE=true` resumes an existing `fuzz/campaign_state.json` (falls back to a fresh campaign if the file is missing or corrupt); transport overrides are rebuilt from the resumed protocol list, not the CLI `PROTOCOLS` option
- **`fuzzing.cli_commands` (replay)** — delegates to `CrashDB.reproduce_crash(transport)` instead of duplicating the recv/timeout logic inline; multi-packet crashes now report packet count before replay
- **`fuzzing.state_inference`** — replaces non-deterministic `hash(indicator)` with `md5(...)[:2]` so AT state IDs are stable across Python interpreter runs (was breaking state-machine convergence on restart)
- **`fuzzing.lmp_state_tests`** — the `key_size_after_start_enc` test now uses a fixed 16-byte hex seed instead of `os.urandom(16)` so the test is reproducible
- **`fuzzing.transport`** — `LMPTransport._establish_acl()` closes the probe socket in a `finally` block instead of relying on successful-path cleanup
- **`utils.bt_helpers.get_adapter_state`** — escapes `hci` before embedding it in the `pgrep` regex; previously vulnerable to weird adapter names injecting regex metacharacters

### Fixed — CLI

- **`blue-tap run <module>`** — missing / destructive / option-error conditions now exit with status `1` instead of falling through to status `0`; "see available modules" hint now points at `blue-tap search` (the real command) instead of the removed `list-modules`
- **`blue-tap run-playbook`** — no longer replaces the lowercase literal `target` inside command strings (broke any module that had `target` as a legitimate substring in an argument); only the uppercase `TARGET` sentinel and the explicit `{target}` placeholder are substituted
- **`adapter up/down/reset/set-name`** — raise `ClickException` on failure so exit status matches; `info` raises `ClickException` instead of silently returning when the adapter doesn't exist
- **`_module_runner.resolve_target`** — validates the `TARGET` argument shape with a MAC regex; if the first positional token is a subcommand name (e.g. `blue-tap recon sdp`) the picker fires instead of treating the subcommand as an address

### Fixed — Playbooks

- **`full-assessment.yaml`** — updated to v2.6 CLI grammar: `recon {target} rfcomm` instead of `recon rfcomm-scan {target}`, `sniff -m lmp` instead of `lmp-sniff`, `-a` instead of `-i`
- **`ivi-attack.yaml`** — exploit commands now use the `exploit {target} <sub>` form; `-a` instead of `-i`
- **`lmp-fuzzing.yaml`** — removed the deprecated standalone `fuzz lmp` step; campaign uses the `-p <proto>` repeatable flag (matches current CLI) and `coverage_guided` (underscore form)
- **`passive-recon.yaml`**, **`quick-recon.yaml`** — `scan classic/ble` replaced with `discover classic/ble`; recon subcommands reordered to `recon {target} <sub>` form

### Fixed — Tests

- `test_cli_facades` — `vulnscan` / `dos` "requires target" tests replaced with "interactive picker when no target" to reflect the new optional-target behavior
- `test_userflow_dos`, `test_userflow_exploitation_bias`, `test_userflow_exploitation_knob` — expect exit code `1` for unknown modules and blocked destructive runs (previously accepted `0` due to the silent-failure bug)

### Fixed — Docs

- **CLI reference** — rewritten to show `[TARGET]` as optional across `vulnscan`, `recon`, `exploit`, `extract`, `dos`; options table updated (`-a, --hci` replaces the old `-a, --adapter` / `-i, --adapter` forms); added interactive-picker callout
- **Navigation** — mkdocs sidebar renames "Reference" to "Technical Reference"
- **Guide pages** — `reconnaissance`, `vulnerability-assessment`, `denial-of-service`, `fuzzing`, `post-exploitation`, `sessions-and-reporting`, `automation`, `exploitation` updated to match the v2.6 command grammar; `docs/developer/architecture.md` expanded with framework-layer details
- **README** and **target/README** — all example invocations updated to `discover` / `recon {target} <sub>` / `-a` grammar; fuzz examples use `-p` repeatable and `fuzz crashes list`

### Build

- **Version** bumped to `2.6.1`
- `pyproject.toml` — removed stray `asyncio_default_fixture_loop_scope` (no async tests in the suite)
- `.gitignore` — adds `site/` (mkdocs build), `fuzz/` (corpus + crashes.db), `map_dump/`, `x/`, `hci_capture.pcap`, `tmp_dos_review.*` to avoid committing operator artifacts

---

## [2.6.0] - 2026-04-16

### Summary

Blue-Tap 2.6.0 is the **Modular Framework** release — every module now implements the `Module` protocol, produces typed `RunEnvelope` output, and is auto-registered in a global `ModuleRegistry`. The CLI was redesigned around the assessment workflow (`discover → recon → vulnscan → exploit → extract → fuzz → report`). The hardware layer gained a unified `resolve_active_hci()` resolver. The report pipeline is fully adapter-driven with per-family outcome validation enforced at call time.

### Added — Module Protocol (`framework/module`)

- **`Module` abstract base class** — defines `run(ctx: RunContext) → RunEnvelope`; `__init_subclass__` hook auto-registers every subclass in the global `ModuleRegistry` without a manual `ModuleDescriptor` block
- **`RunContext` dataclass** — single typed argument to `Module.run()`: `target`, `adapter`, `options`, `session_id`, `dry_run`; replaces ad-hoc kwargs scattered across entry points
- **Typed option descriptors** — `OptAddress`, `OptPort`, `OptBool`, `OptInt`, `OptStr`, `OptChoice`, `OptFlag`; each validates its value at resolution time and raises `ValueError` on invalid input
- **`OptionsContainer`** — ordered dict of `Option` instances; resolves CLI args + env-var overrides at invocation time before `Module.run()` is called
- **`ModuleInvoker`** — resolves `module_id` from the registry, builds `RunContext` from CLI params, calls `Module.run()`, and streams `CliEvents` to the operator console
- **`ModuleLoader`** — imports `Module` classes from `entry_point` strings (`package.module:Class`); caches loaded classes to avoid repeated imports
- **`autoload.py`** — imports all family `__init__.py` files so subclass auto-registration fires before the registry is queried for the first time

### Added — Phase-Verb CLI Architecture (`interfaces/cli`)

- **`discover`** — `classic / ble / all` sub-verbs wrapping `DiscoveryScanner` via `ModuleInvoker`; replaces the flat `scan` command with an explicit workflow step
- **`recon`** — `sdp / rfcomm / gatt / hci-capture / sniffer / lmp-sniff` sub-verbs consolidating the former `recon` + `capture` families into one phase command
- **`exploit`** — sub-commands: `bias`, `bluffs`, `knob`, `ctkd`, `enc-downgrade`, `ssp-downgrade`, `hijack`, `pin-brute`; grouped under Crypto/Key Attacks and Full Chain
- **`extract`** — sub-commands: `contacts`, `messages`, `audio`, `media`, `push`, `snarf`, `at`; covers all post-exploitation data paths in one place
- **`dos`** — `BLE / Classic / Raw-ACL` sub-commands forwarded to the DoS runner with protocol grouping
- **`fuzz`** — `campaign` + 9 protocol sub-commands (`sdp-deep`, `l2cap-sig`, `rfcomm-raw`, `ble-att`, `ble-smp`, `bnep`, `obex`, `at-deep`, `lmp`) plus `crashes / minimize / replay / corpus` analysis commands
- **`doctor`** — hardware diagnostics: adapter list, DarkFirmware probe, USB dongle detection by VID:PID, HCI sanity check
- **`auto`** — orchestrated `discover → recon → vulnscan → exploit` chain with `--dry-run` support and per-phase skip/abort handling
- **`fleet`** — multi-target orchestration; per-target error isolation so one failure no longer aborts the full run
- **`runner`** / **`plugins`** — generic `blue-tap run <module_id>` entry point; `plugins` lists registered modules and shows descriptor info
- **`_module_runner.py`** — single shared helper for all family CLIs: resolves module, builds `RunContext`, streams events, writes session envelope

### Added — Outcome Validation Taxonomy

- **`VALID_OUTCOMES_BY_FAMILY`** (`framework/contracts/result_schema.py`) — per-family `frozenset` of allowed `module_outcome` values; `make_execution()` raises `ValueError` on any unlisted value so bugs surface in tests not in production envelopes
- **Family outcome sets** — discovery (`observed / merged / correlated / partial / not_applicable`); assessment (`confirmed / inconclusive / pairing_required / not_applicable / not_detected`); exploitation (`success / unresponsive / recovered / aborted / not_applicable`); post_exploitation (`extracted / connected / streamed / transferred / partial`); fuzzing (`crash_found / timeout / corpus_grown / no_findings / crash_detected / reproduced`)
- **`_infer_family_from_module_id()`** — extracts the family prefix from `<family>.<name>` module IDs; unknown families skip validation for backward compatibility with pre-2.6 modules

### Added — Registry Extensions

- **`ModuleDescriptor.category`** — optional sub-family grouping field (e.g. `"pairing"`, `"l2cap"`, `"ble"`) for DoS and CVE check sub-classification within a family
- **`ModuleDescriptor.references`** — `tuple[str, ...]` of external references (CVEs, RFCs, specs) associated with the module; surfaced in `blue-tap plugins info <module>` output
- **`ModuleRegistry.try_get(module_id)`** — returns `ModuleDescriptor | None`; avoids `KeyError` when probing for optional or plugin-provided modules

### Added — Hardware Adapter Resolution

- **`resolve_active_hci(explicit=None)`** (`hardware/adapter.py`) — priority-ordered HCI resolution: explicit arg → `BT_TAP_DARKFIRMWARE_HCI` env var → RTL8761B USB VID:PID probe → first UP adapter from `hciconfig` → `"hci0"` as last resort
- **Process-lifetime cache** — result stored in `_ACTIVE_HCI_CACHE` after first hardware probe; `reset_active_hci_cache()` clears it on hot-plug or adapter-list refresh
- **RTL8761B identified by VID:PID** (`0bda:8771`) not HCI slot position — fixes false "DarkFirmware unavailable" in multi-adapter setups where the scan adapter ≠ firmware dongle

### Added — Native Module Classes

- **`CveCheckModule`** (`modules/assessment/base.py`) — wraps legacy check functions into the `Module` protocol; subclasses declare `check_fn` and `module_id` without duplicating envelope construction
- **`VulnScanModule`** (`modules/assessment/vulnscan_module.py`) — thin `Module` subclass delegating to `vuln_scanner.run()` and wrapping the result in a canonical `RunEnvelope`
- **`DiscoveryScanner`** (`modules/discovery/scanner.py`) — `Module` class for Classic/BLE/combined scans; registered as `"discovery.scanner"` via auto-registration
- **`_e0.py`** (`modules/exploitation/`) — E0 encryption-mode downgrade probe helper shared by `knob.py` and `bias.py`
- **`DoSCheckModule`** (`modules/exploitation/dos/base.py`) — shared base for BLE / Classic / Raw-ACL DoS checks; handles timing evidence, recovery probe wiring, and envelope construction
- **`FuzzCampaign`** (`modules/fuzzing/campaign.py`) — `Module` wrapping the full engine lifecycle: seed corpus, run, collect crashes, finalize `RunEnvelope`; supports campaign resume and crash export
- **`ReconCampaign`** (`modules/reconnaissance/campaign.py`) — `Module` wrapping the multi-collector recon pipeline into a single `RunEnvelope`; registered as `"reconnaissance.campaign"`

### Added — Documentation Site (MkDocs)

- **`mkdocs.yml`** — Material theme configuration with structured nav tree, light/dark mode, code block highlights
- **`docs/getting-started/`** — installation, hardware setup (single/dual adapter), quick start, IVI simulator
- **`docs/guide/`** — per-phase operator guides: discovery, recon, vulnerability assessment, exploitation, DoS, fuzzing, post-exploitation, sessions and reporting, automation
- **`docs/workflows/`** — end-to-end scenario walkthroughs: full pentest, quick assessment, fuzzing campaign, encryption downgrade, audio eavesdropping, custom playbooks
- **`docs/developer/`** — architecture overview, module system, writing a module, report adapters, plugin entry-points
- **`docs/reference/`** — hardware compatibility matrix, platform notes, troubleshooting reference
- **`docs/cve/`** — CVE detection matrix, DoS CVE matrix, expansion roadmap; CVE specs moved from flat `cve-detection-specs/` → `cve/specs/`

### Added — Testing

- **`conftest.py`** — shared fixtures: mock adapter, target MAC, tmp session directory, registry reset between tests
- **13 `test_userflow_*.py`** — end-to-end operator workflow coverage: discover→recon→report, vulnscan fleet, BIAS, KNOB, DoS runner, fuzzing campaign, PBAP/OPP, A2DP/AVRCP, report generation, session resume, console output, playbook execution
- **`test_cli_facades.py`** — Click command registration smoke tests for every phase-verb subcommand; catches missing imports and mis-wired groups
- **`test_outcome_validator.py`** — `VALID_OUTCOMES_BY_FAMILY` enforcement: valid outcomes pass, invalid ones raise `ValueError`
- **`test_module_runtime_e2e.py`** — `Module.run()` → `RunEnvelope` round-trip for one module per family; validates schema, run_id, and outcome fields
- **`test_hci_vsc_concurrency.py`** — `HciVscClient` concurrent command safety under multi-thread access
- **`test_dos_migration.py`** — DoS adapter post-migration regression: `accepts()` family-prefix matching, `ingest()`, section output shape

### Changed

- **Report adapter `accepts()`** — all adapters match both legacy module name strings and modern `"family.name"` prefixes; `DiscoveryReportAdapter` additionally accepts any `"discovery.*"` prefix
- **Envelope module label** — renamed `"attack"` → `"exploitation"` across all envelope builders to align with module family taxonomy
- **Session store** — atomic JSON writes via write-to-temp + `os.replace()`, correlation IDs on every operation, session-resume by name lookup, path configurable via `BT_TAP_SESSIONS_DIR`
- **Module `__init__.py` files** — all family `__init__.py` dropped manual `ModuleDescriptor` blocks; `__init_subclass__` auto-registration handles all modules
- **`_check_darkfirmware_available()`** — identifies RTL8761B by USB VID:PID and reads `BT_TAP_DARKFIRMWARE_HCI` env var; scan adapter no longer assumed to be the firmware dongle
- **All recon collectors** — call `resolve_active_hci()` instead of hardcoding `"hci0"`; structured WARNING-level logging on socket errors
- **All post-exploitation modules** — `resolve_active_hci()` used in PBAP/MAP/OPP/A2DP/AVRCP/HFP paths
- **`set_verbosity()`** — propagates to root logger so `-v` / `-vv` flags apply consistently across all modules
- **`run_cmd()`** — explicit `timeout=` on all subprocess calls; stderr captured to avoid dangling file descriptors
- **`parse_sdp_records()`** — handles malformed XML with a logged warning instead of raising `ParseError`
- **`confirm_destructive()`** — accepts `dry_run` kwarg; logs the operator confirmation prompt to the audit log
- **Fleet scan** — per-target errors captured in envelope without aborting the full run
- **`vuln_scanner._run_hcitool_info()`** — calls `resolve_active_hci()` instead of defaulting to `"hci0"`
- **Report generator** — accepts explicit session path; no module-specific logic remains in generator
- **`output.py`** — added `channel_table()`, `bare_table()`, `print_table()` helpers; demo runner uses shared formatters
- **README** — condensed to focused project summary with badge row and quick-start matching the phase-verb CLI

### Fixed

- **`clone_device_identity` callers** — `bias.py` / `hijack.py` checked `if not clone_device_identity(...)` which evaluated `False` after bool→dict migration; fixed to `result.get("success", False)`
- **Recon capture-stop** — `HCICapture.stop()` returns a path string; two copy-paste blocks called `.get("success")` on it raising `AttributeError`
- **Recon lmp-sniff / nrf-sniff** — `artifacts` variable referenced in `build_recon_result()` but never initialized; `NameError` on every execution
- **L2CAP checks** — two `_check_ecred_*` functions had unreachable `return []` after `finally` blocks; removed dead code preventing results from being returned
- **`btmgmt public-addr` errors** — handled safely instead of crashing the adapter command
- **DoS result/report normalization** — aligned DoS result dict keys with report adapter field expectations
- **HFP reconnect socket leak** — socket closed in `finally` block during reconnection
- **RAM BDADDR patching** — corrected controller memory write sequence for RTL8761B

### Removed

- **Deprecated top-level packages** — `blue_tap/attack/`, `blue_tap/cli.py`, `blue_tap/core/`, `blue_tap/fuzz/`, `blue_tap/recon/`, `blue_tap/report/` (all were deprecation-notice stubs with no active consumers)
- **Auto envelope builder** — `framework/envelopes/auto.py`; auto-pentest uses phase-verb CLI with per-phase family envelopes
- **Auto report adapter** — `framework/reporting/adapters/auto.py` removed alongside the auto envelope
- **`AutoPentest` module** — `modules/exploitation/auto.py` retired; superseded by `blue-tap auto` CLI command
- **Flat family CLI files** — `interfaces/cli/assessment.py`, `discovery.py`, `exploitation.py`, `fuzzing.py`, `post_exploitation.py`, `reconnaissance.py` replaced by phase-verb commands
- **Retired test files** — `test_auto_envelope.py`, `test_cli_events_coverage.py`, `test_cli_startup_bootstrap.py`, `test_discovery_regressions.py`, `test_media_data_regressions.py`, `test_recon_revamp.py`; replaced by userflow tests

---

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

[2.6.5]: https://github.com/Indspl0it/blue-tap/compare/v2.6.4...v2.6.5
[2.6.4]: https://github.com/Indspl0it/blue-tap/compare/v2.6.3...v2.6.4
[2.6.3]: https://github.com/Indspl0it/blue-tap/compare/v2.6.2...v2.6.3
[2.6.2]: https://github.com/Indspl0it/blue-tap/compare/v2.6.1...v2.6.2
[2.6.1]: https://github.com/Indspl0it/blue-tap/compare/v2.6.0...v2.6.1
[2.6.0]: https://github.com/Indspl0it/blue-tap/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/Indspl0it/blue-tap/compare/v2.3.2...v2.5.0
[2.3.2]: https://github.com/Indspl0it/blue-tap/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/Indspl0it/blue-tap/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/Indspl0it/blue-tap/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Indspl0it/blue-tap/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Indspl0it/blue-tap/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.1.0
[2.0.1]: https://github.com/Indspl0it/blue-tap/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Indspl0it/blue-tap/releases/tag/v2.0.0
