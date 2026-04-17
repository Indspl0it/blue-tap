# Architecture Reference

This document describes the internal architecture of Blue-Tap: package layout, design principles, data flow, core abstractions, and the status taxonomy.

---

## Design Philosophy

Blue-Tap's architecture separates **what the tool can do** (modules), **how it's structured** (framework), and **how users interact with it** (interfaces). This three-layer split exists for concrete reasons:

- **Framework stays stable.** The contracts (`RunEnvelope`, `ExecutionRecord`, `ReportAdapter`) change rarely. When they do, every module and interface must update. Keeping framework code isolated means you can add 50 modules without touching the envelope schema once.
- **Modules stay independent.** A CVE check for L2CAP should never import from the fuzzer, and the fuzzer should never import from the CLI. Cross-family imports create hidden coupling that makes modules untestable in isolation.
- **Interfaces are replaceable.** The CLI is one interface. A REST API, a GUI, or a CI/CD integration would be another. None of them contain business logic -- they delegate to modules and framework.

### If You're Coming from Metasploit

| Metasploit Concept | Blue-Tap Equivalent | Key Difference |
|---|---|---|
| Module (exploit/auxiliary/post) | Module in `modules/<family>/` | Blue-Tap modules return structured `RunEnvelope` data, not session objects |
| Datastore options | `run()` kwargs + CLI options | No global mutable datastore; explicit parameter passing |
| Module mixins | Framework envelope builders | Composition over inheritance; builders are functions, not base classes |
| `report_*` methods | Report adapters | Adapters are separate classes, not mixed into the module |
| Session (Meterpreter) | `framework/sessions/store.py` | Blue-Tap sessions are JSON logs, not interactive shells |
| `db_*` commands | Session directory + JSON files | File-based, no external database required |
| Module ranking | `ModuleDescriptor.destructive` | Binary flag rather than a ranking scale |

---

## Package Layout

```
blue_tap/
  framework/                   # Stable contracts, registry, envelopes, reporting, sessions
    contracts/                 # result_schema.py, report_contract.py
    runtime/                   # cli_events.py
    envelopes/                 # Family-specific envelope builders
    registry/                  # ModuleDescriptor, ModuleFamily, ModuleRegistry
    reporting/
      adapters/                # 11 report adapters (one per module type)
      renderers/               # html.py, blocks.py, registry.py, sections.py
    sessions/                  # store.py (atomic persistence)
  modules/                     # Domain behavior (101 modules across 6 families)
    discovery/                 # 1 module -- target scanning
    reconnaissance/            # 13 modules -- deep enumeration
    assessment/                # 43 modules -- vulnerability checks (25 CVE + 11 posture + meta)
    exploitation/              # 38 modules (8 attacks + dos_runner + 29 DoS checks)
    post_exploitation/         # 8 modules -- data extraction, media control
    fuzzing/                   # 3 registered + engine, transport, corpus, crash_db
  interfaces/                  # User-facing integration surfaces
    cli/                       # Click commands (LoggedCommand / LoggedGroup)
    reporting/                 # ReportGenerator orchestration
    playbooks/                 # PlaybookLoader
  hardware/                    # Low-level primitives
    adapter.py                 # HCI management, chipset detection
    scanner.py                 # Classic + BLE scanning
    spoofer.py                 # MAC spoofing (4 methods)
    firmware.py                # DarkFirmware (RTL8761B)
    hci_vsc.py                 # Vendor-specific HCI commands
    obex_client.py             # OBEX D-Bus client
  utils/                       # Shared helpers (bt_helpers, output, interactive, env_doctor)
```

---

## Design Principles

| Layer | Rule | Rationale |
|---|---|---|
| `framework/` | Infrastructure only. **Never** imports from `modules/`. | Framework is the foundation -- it must not depend on the things built on top of it. |
| `modules/` | Business logic. Imports `framework/` and `hardware/`. **No cross-family imports.** | Modules must be independently testable. A bug in the fuzzer must never break the vulnerability scanner. |
| `interfaces/` | Presentation. Imports `modules/` and `framework/`. | Interfaces wire modules to user input/output. They contain no detection logic. |
| `hardware/` | Low-level primitives. Used by `modules/`. | Hardware abstraction isolates platform-specific code (HCI sockets, USB, D-Bus). |

Old paths (`core/`, `attack/`, `recon/`, `fuzz/`, `report/`) contain deprecation notices only. Never import from them.

### Layered Architecture

The diagram below shows every major component grouped by layer, with dependency arrows pointing in the direction of allowed imports. Framework never imports from modules. Modules never cross-import between families. Interfaces contain no business logic.

```mermaid
graph TD
    subgraph interfaces_layer["interfaces/ — User-Facing"]
        CLI["CLI<br/>(Click commands)"]
        RepGen["ReportGenerator"]
        PBLoader["PlaybookLoader"]
    end

    subgraph modules_layer["modules/ — Domain Behavior (101 modules)"]
        disc["discovery<br/>(1 module)"]
        recon["reconnaissance<br/>(13 modules)"]
        assess["assessment<br/>(43 modules)"]
        exploit["exploitation<br/>(38 modules)"]
        postex["post_exploitation<br/>(8 modules)"]
        fuzz["fuzzing<br/>(3 + engine)"]
    end

    subgraph framework_layer["framework/ — Stable Infrastructure"]
        contracts["contracts<br/>(result_schema,<br/>report_contract)"]
        registry["registry<br/>(ModuleDescriptor,<br/>ModuleFamily,<br/>ModuleRegistry)"]
        envelopes["envelopes<br/>(family builders)"]
        reporting["reporting<br/>(11 adapters,<br/>4 renderers)"]
        sessions["sessions<br/>(atomic store)"]
        runtime["runtime<br/>(cli_events)"]
    end

    subgraph hardware_layer["hardware/ — Low-Level Primitives"]
        adapter["adapter<br/>(HCI mgmt,<br/>chipset detect)"]
        scanner["scanner<br/>(Classic + BLE)"]
        spoofer["spoofer<br/>(4 methods)"]
        firmware["firmware<br/>(DarkFirmware<br/>RTL8761B)"]
        hci_vsc["hci_vsc<br/>(vendor HCI)"]
        obex["obex_client<br/>(D-Bus OBEX)"]
    end

    CLI --> disc & recon & assess & exploit & postex & fuzz
    CLI --> registry & runtime
    RepGen --> reporting & sessions
    PBLoader --> registry

    disc & recon & assess & exploit & postex & fuzz --> contracts & envelopes & runtime
    disc & recon --> scanner
    exploit & fuzz --> adapter & spoofer & firmware & hci_vsc
    postex --> obex & adapter

    style interfaces_layer fill:#5c3a1a,stroke:#b97029,color:#fff
    style modules_layer fill:#1a3a5c,stroke:#2980b9,color:#fff
    style framework_layer fill:#2d5016,stroke:#4a8c2a,color:#fff
    style hardware_layer fill:#3a1a5c,stroke:#7029b9,color:#fff

    style CLI fill:#5c3a1a,stroke:#b97029,color:#fff
    style RepGen fill:#5c3a1a,stroke:#b97029,color:#fff
    style PBLoader fill:#5c3a1a,stroke:#b97029,color:#fff

    style disc fill:#1a3a5c,stroke:#2980b9,color:#fff
    style recon fill:#1a3a5c,stroke:#2980b9,color:#fff
    style assess fill:#1a3a5c,stroke:#2980b9,color:#fff
    style exploit fill:#1a3a5c,stroke:#2980b9,color:#fff
    style postex fill:#1a3a5c,stroke:#2980b9,color:#fff
    style fuzz fill:#1a3a5c,stroke:#2980b9,color:#fff

    style contracts fill:#2d5016,stroke:#4a8c2a,color:#fff
    style registry fill:#2d5016,stroke:#4a8c2a,color:#fff
    style envelopes fill:#2d5016,stroke:#4a8c2a,color:#fff
    style reporting fill:#2d5016,stroke:#4a8c2a,color:#fff
    style sessions fill:#2d5016,stroke:#4a8c2a,color:#fff
    style runtime fill:#2d5016,stroke:#4a8c2a,color:#fff

    style adapter fill:#3a1a5c,stroke:#7029b9,color:#fff
    style scanner fill:#3a1a5c,stroke:#7029b9,color:#fff
    style spoofer fill:#3a1a5c,stroke:#7029b9,color:#fff
    style firmware fill:#3a1a5c,stroke:#7029b9,color:#fff
    style hci_vsc fill:#3a1a5c,stroke:#7029b9,color:#fff
    style obex fill:#3a1a5c,stroke:#7029b9,color:#fff
```

No arrow from `framework` to `modules` means framework code never imports module code. No arrow between module families means no cross-family imports.

---

## Module Registration Flow

Every module declares itself via a `ModuleDescriptor` in its family `__init__.py`. The registry is the single source of truth for what modules exist, what they need, and how to load them. CLI commands never hard-code module references -- they discover modules through the registry at runtime.

```mermaid
flowchart LR
    subgraph registration["Registration (import time)"]
        init["Family __init__.py"]
        reg["get_registry().register()"]
        desc["ModuleDescriptor<br/>(id, family, entry_point,<br/>protocols, requires)"]
    end

    subgraph discovery["Discovery (CLI startup)"]
        cli["CLI command"]
        lookup["registry.get(module_id)"]
        resolve["resolve entry_point<br/>→ Module class"]
    end

    subgraph execution["Execution (runtime)"]
        run["Module.run()<br/>(target, adapter, ...)"]
        envelope["→ RunEnvelope"]
    end

    init --> desc --> reg
    cli --> lookup --> resolve --> run --> envelope

    style registration fill:#2d5016,stroke:#4a8c2a,color:#fff
    style discovery fill:#5c3a1a,stroke:#b97029,color:#fff
    style execution fill:#1a3a5c,stroke:#2980b9,color:#fff
```

The `entry_point` string (e.g. `"blue_tap.modules.assessment.checks.cve_2020_26555:CVE2020_26555"`) is resolved via Python's import machinery. This means modules are loaded lazily -- only when a user actually runs a command that needs them.

---

## Envelope Lifecycle

A `RunEnvelope` is the universal data container that flows through the entire pipeline: from module execution to session persistence to report generation. The diagram below traces its lifecycle end to end.

```mermaid
flowchart LR
    subgraph mod["Module Layer"]
        direction TB
        run["Module.run()"]
        builder["EnvelopeBuilder<br/>.build()"]
    end

    subgraph persist["Persistence Layer"]
        direction TB
        log["Session.log_command()"]
        atomic["atomic write<br/>(tmp + os.replace)"]
        disk["sessions/NNN_cmd.json"]
    end

    subgraph report["Report Layer"]
        direction TB
        load["ReportGenerator<br/>.load()"]
        adapt["ReportAdapter<br/>.ingest()"]
        section["SectionModel"]
        render["Renderer"]
        html["HTML report"]
    end

    run --> builder --> log --> atomic --> disk --> load --> adapt --> section --> render --> html

    style mod fill:#1a3a5c,stroke:#2980b9,color:#fff
    style persist fill:#2d5016,stroke:#4a8c2a,color:#fff
    style report fill:#5c3a1a,stroke:#b97029,color:#fff
```

Key design points: the envelope dict is pure data (no methods, no classes) so it serializes cleanly to JSON. The atomic write in the persistence layer ensures a crash mid-write never corrupts the session directory. Report adapters are matched to envelopes by schema prefix, so adding a new module type only requires registering a new adapter.

---

## Data Flow

### Module Execution Flow

```mermaid
sequenceDiagram
    participant CLI as CLI Command
    participant Reg as ModuleRegistry
    participant Mod as Module.run()
    participant Env as Envelope Builder
    participant Evt as CLI Events
    participant Sess as Session Store

    CLI->>Reg: get(module_id)
    Reg-->>CLI: ModuleDescriptor
    CLI->>Mod: run(target, adapter, ...)
    Mod->>Evt: emit(run_started)
    loop For each check/probe
        Mod->>Evt: emit(execution_started)
        Mod->>Mod: Detection logic
        Mod->>Evt: emit(execution_result)
    end
    Mod->>Env: build_run_envelope(...)
    Env-->>Mod: RunEnvelope dict
    Mod->>Evt: emit(run_completed)
    Mod-->>CLI: RunEnvelope
    CLI->>Sess: log_command(envelope)
```

### Report Generation Flow

```mermaid
sequenceDiagram
    participant CLI as report command
    participant Gen as ReportGenerator
    participant Sess as Session Store
    participant Adp as Report Adapters
    participant Blk as BlockRendererRegistry

    CLI->>Gen: generate(session)
    Gen->>Sess: load all envelope files
    Sess-->>Gen: list[RunEnvelope]
    loop For each envelope
        Gen->>Adp: adapter.accepts(envelope)?
        Adp-->>Gen: True/False
        Gen->>Adp: adapter.ingest(envelope, state)
    end
    loop For each adapter with data
        Gen->>Adp: adapter.build_sections(state)
        Adp-->>Gen: list[SectionModel]
    end
    loop For each SectionBlock
        Gen->>Blk: render(block)
        Blk-->>Gen: HTML string
    end
    Gen-->>CLI: Complete HTML report
```

### Narrative Data Flow

1. A Click command resolves its module via `ModuleRegistry`.
2. The module executes, building a `RunEnvelope` through the family envelope builder.
3. CLI events are emitted during execution for real-time operator feedback.
4. The envelope is logged to the active session (atomic JSON writes).
5. At report time, each report adapter ingests matching envelopes, produces `SectionModel` objects, and the renderer converts them to HTML.

---

## Core Abstractions

### RunEnvelope

The universal output container for every module run. Built by `build_run_envelope()` in `blue_tap.framework.contracts.result_schema`.

| Field | Type | Description |
|---|---|---|
| `schema` | `str` | Module schema identifier, e.g. `"blue_tap.vulnscan.result"` |
| `schema_version` | `int` | Always `2` (constant `SCHEMA_VERSION`) |
| `module` | `str` | Module name |
| `run_id` | `str` | Unique run identifier (UUID or `{module}-{uuid}`) |
| `target` | `str` | Target address |
| `adapter` | `str` | HCI adapter used |
| `started_at` | `str` | ISO 8601 timestamp |
| `completed_at` | `str` | ISO 8601 timestamp |
| `operator_context` | `dict` | Operator-supplied context |
| `summary` | `dict` | Module-specific summary |
| `executions` | `list[dict]` | List of `ExecutionRecord` dicts |
| `artifacts` | `list[dict]` | List of `ArtifactRef` dicts |
| `module_data` | `dict` | Module-specific payload |

### ExecutionRecord

One execution within a run. Built by `make_execution()`.

| Field | Type | Description |
|---|---|---|
| `execution_id` | `str` | Unique within the run (UUID) |
| `kind` | `str` | `"check"`, `"collector"`, `"probe"`, `"phase"`, or `"operation"` |
| `id` | `str` | Stable machine identifier |
| `title` | `str` | Human-readable title |
| `module` | `str` | Module name |
| `protocol` | `str` | Protocol used |
| `execution_status` | `str` | Lifecycle status (see taxonomy below) |
| `module_outcome` | `str` | Semantic result (family-specific, see below) |
| `severity` | `str \| None` | Optional severity level |
| `destructive` | `bool` | Whether the execution modifies target state |
| `requires_pairing` | `bool` | Whether pairing is mandatory |
| `started_at` | `str` | ISO 8601 timestamp |
| `completed_at` | `str` | ISO 8601 timestamp |
| `evidence` | `dict` | `EvidenceRecord` dict |
| `notes` | `list[str]` | Operator notes |
| `tags` | `list[str]` | Machine tags |
| `artifacts` | `list[dict]` | Execution-level artifacts |
| `module_data` | `dict` | Execution-level module data |
| `error` | `str \| None` | Error message (present only on failure) |

### EvidenceRecord

Frozen dataclass capturing evidence from a single execution. Built by `make_evidence()`.

| Field | Type | Default |
|---|---|---|
| `summary` | `str` | *(required)* |
| `confidence` | `str` | `"medium"` -- one of `high`, `medium`, `low` |
| `observations` | `tuple[str, ...]` | `()` |
| `packets` | `tuple[dict, ...]` | `()` |
| `responses` | `tuple[str, ...]` | `()` |
| `state_changes` | `tuple[str, ...]` | `()` |
| `artifacts` | `tuple[dict, ...]` | `()` |
| `capability_limitations` | `tuple[str, ...]` | `()` |
| `module_evidence` | `dict[str, Any]` | `{}` |

### ArtifactRef

Frozen dataclass referencing a saved artifact. Built by `make_artifact()`.

| Field | Type | Default |
|---|---|---|
| `artifact_id` | `str` | *(required)* -- UUID |
| `kind` | `str` | *(required)* -- e.g. `"pcap"`, `"log"`, `"json"` |
| `label` | `str` | *(required)* -- human-readable label |
| `path` | `str` | *(required)* -- filesystem path |
| `description` | `str` | `""` |
| `created_at` | `str` | `""` |
| `execution_id` | `str` | `""` |

---

## Module Families and Outcomes

| Family | Purpose | Allowed `module_outcome` values |
|---|---|---|
| **discovery** | Nearby target inventory | `observed`, `merged`, `correlated`, `partial`, `not_applicable` |
| **reconnaissance** | Deep per-target analysis | `observed`, `merged`, `correlated`, `partial`, `not_applicable`, `unsupported_transport`, `collector_unavailable`, `prerequisite_missing`, `artifact_collected`, `hidden_surface_detected`, `no_relevant_traffic` |
| **assessment** | Vulnerability checks | `confirmed`, `inconclusive`, `pairing_required`, `not_applicable`, `not_detected` |
| **exploitation** | Active attacks | `success`, `unresponsive`, `recovered`, `not_applicable`, `aborted`, `confirmed` |
| **post_exploitation** | Data extraction, media | `extracted`, `connected`, `streamed`, `transferred`, `not_applicable`, `partial`, `completed`, `failed`, `aborted` |
| **fuzzing** | Protocol mutation/stress | `crash_found`, `timeout`, `corpus_grown`, `no_findings`, `completed`, `crash_detected`, `degraded`, `aborted`, `pairing_required`, `not_applicable`, `reproduced` |

The canonical outcomes (first 4-5 per family) match the architecture rule in `.claude/rules/blue-tap-architecture.md`. The extended values accommodate legacy envelope builders and cross-phase checks.

---

## Status Taxonomy

Blue-Tap uses two distinct status fields. **Never conflate them.**

### `execution_status` -- Lifecycle

Answers: *"Did the execution run to completion?"*

| Value | Meaning |
|---|---|
| `completed` | Ran to completion (result may be positive or negative) |
| `failed` | Ran but encountered an expected failure condition |
| `error` | Unexpected error / exception |
| `skipped` | Intentionally not run (prerequisite missing, not applicable) |
| `timeout` | Exceeded time limit |

### `module_outcome` -- Semantic

Answers: *"What did we learn?"*

Family-specific. See the outcomes table above. A `completed` execution can have any outcome -- `execution_status=completed` with `module_outcome=not_detected` means "we checked successfully and found nothing."

### Why Two Fields?

A single `status` field conflates "did it run?" with "what did it find?" -- making it impossible to distinguish "the check crashed" from "the check ran and found nothing." The two-field design means:

- Reporting can filter by `execution_status` to find errors/timeouts (operational issues).
- Reporting can filter by `module_outcome` to find confirmed vulnerabilities (security findings).
- The combination tells the full story: `completed` + `confirmed` = found it; `completed` + `not_detected` = checked and clear; `error` + (anything) = something broke.

---

## CLI Events

All modules emit structured CLI events via `emit_cli_event()` from `blue_tap.framework.runtime.cli_events`. There are 14 canonical event types:

| Event Type | Color | Description |
|---|---|---|
| `run_started` | info (blue) | Run begins |
| `run_completed` | success (green) | Run finishes successfully |
| `run_aborted` | warning (yellow) | Run intentionally stopped early |
| `run_error` | error (red) | Unrecoverable error |
| `phase_started` | info (blue) | Named phase within a run begins |
| `execution_started` | info (blue) | Single execution/check begins |
| `execution_result` | success (green) | Execution completes with a result |
| `execution_skipped` | warning (yellow) | Execution intentionally not run |
| `execution_observation` | verbose (dim) | Informational observation during execution |
| `pairing_required` | warning (yellow) | Target requires pairing to proceed |
| `recovery_wait_started` | warning (yellow) | Waiting for target to recover |
| `recovery_wait_progress` | warning (yellow) | Recovery wait in progress |
| `recovery_wait_finished` | verbose (dim) | Recovery wait concluded |
| `artifact_saved` | success (green) | Artifact (pcap, log, JSON) saved |

Non-canonical event types trigger a `logger.warning` at runtime. Always use one of the 14 types above.

### `emit_cli_event()` Signature

```python
def emit_cli_event(
    *,
    event_type: str,      # One of the 14 canonical types
    module: str,           # Module name
    run_id: str,           # Run ID for correlation
    message: str,          # Human-readable message
    target: str = "",
    adapter: str = "",
    execution_id: str = "",
    details: dict[str, Any] | None = None,
    echo: bool = True,     # Print to terminal
) -> dict[str, Any]:
```

### CLI Event Flow

Events are emitted by modules during execution, routed through the event system for terminal display, and captured in the session log for later replay or reporting.

```mermaid
flowchart TD
    subgraph module["Module Execution"]
        run["Module.run()"]
    end

    emit["emit_cli_event()"]

    subgraph routing["Event Router (by event_type)"]
        direction LR
        info_ev["info()<br/>run_started<br/>phase_started<br/>execution_started"]
        success_ev["success()<br/>execution_result<br/>run_completed<br/>artifact_saved"]
        warning_ev["warning()<br/>execution_skipped<br/>pairing_required<br/>recovery_wait_*<br/>run_aborted"]
        error_ev["error()<br/>run_error"]
        verbose_ev["verbose()<br/>execution_observation<br/>recovery_wait_finished"]
    end

    subgraph output["Output Destinations"]
        terminal["Terminal<br/>(Rich formatted)"]
        event_dict["Event dict<br/>(returned to caller)"]
    end

    run --> emit --> routing
    info_ev & success_ev & warning_ev & error_ev & verbose_ev --> terminal
    emit --> event_dict

    style module fill:#1a3a5c,stroke:#2980b9,color:#fff
    style routing fill:#2d5016,stroke:#4a8c2a,color:#fff
    style output fill:#5c3a1a,stroke:#b97029,color:#fff
```

The `echo=True` flag controls whether the event prints to terminal. When `echo=False`, the event dict is still returned to the caller (useful for programmatic consumers). Non-canonical event types emit a `logger.warning` before routing.

---

## Session Persistence

Sessions are managed by `blue_tap.framework.sessions.store`. All writes are atomic (temp file + `os.replace`).

### Session Directory Structure

```
sessions/<session_name>/
    session.json              # Metadata (name, targets, command log, files)
    001_scan_classic.json     # Command output #1 (envelope wrapper)
    002_recon_sdp.json        # Command output #2
    003_vulnscan.json         # Command output #3
    fuzz/                     # Fuzzing artifacts (crashes.db, corpus/)
    report.html               # Generated report
```

Command files use `{seq:03d}_{command}.json` naming. Each wraps the module's `RunEnvelope` with metadata (`command`, `category`, `target`, `timestamp`, `validation`). Subdirectories are created on demand by modules that produce artifacts. The `report` command collects all envelopes from the session directory at generation time.

### Session Data Flow

Each command writes its envelope through the atomic write pipeline: content goes to a temp file, `os.fsync()` ensures it hits disk, then `os.replace()` atomically swaps it into place. A crash at any point leaves either the old file intact or no file -- never a partial write.

```mermaid
flowchart TD
    subgraph commands["Commands (sequential)"]
        scan["blue-tap scan"]
        recon["blue-tap recon sdp"]
        vuln["blue-tap vulnscan"]
        dos["blue-tap dos"]
        exploit["blue-tap exploit"]
    end

    subgraph write_pipeline["Atomic Write Pipeline"]
        log["log_command(envelope)"]
        tmp["write → NNN_cmd.json.tmp"]
        fsync["os.fsync()"]
        replace["os.replace() → NNN_cmd.json"]
    end

    subgraph session_dir["sessions/my-assessment/"]
        meta["session.json<br/>(metadata, command log)"]
        f1["001_scan_classic.json"]
        f2["002_recon_sdp.json"]
        f3["003_vulnscan.json"]
        f4["004_dos_runner.json"]
        f5["005_exploit.json"]
        artifacts["fuzz/ pbap/ map/ audio/"]
    end

    subgraph report_gen["Report Generation"]
        collect["collect all *.json envelopes"]
        match["match → ReportAdapters"]
        render["render → HTML / JSON"]
    end

    scan & recon & vuln & dos & exploit --> log
    log --> tmp --> fsync --> replace
    replace --> f1 & f2 & f3 & f4 & f5
    meta ~~~ f1
    f1 & f2 & f3 & f4 & f5 --> collect --> match --> render

    style commands fill:#5c3a1a,stroke:#b97029,color:#fff
    style write_pipeline fill:#2d5016,stroke:#4a8c2a,color:#fff
    style session_dir fill:#1a3a5c,stroke:#2980b9,color:#fff
    style report_gen fill:#3a1a5c,stroke:#7029b9,color:#fff
```

---

## DarkFirmware Architecture

DarkFirmware is custom firmware for the RTL8761B (TP-Link UB500) that extends Blue-Tap below the HCI boundary. Stock Bluetooth stacks only see HCI-level traffic; DarkFirmware installs four hooks in the controller's MIPS16e firmware to intercept, log, and modify packets at the Link Controller and LMP layers.

```mermaid
flowchart TD
    subgraph host["Host (Linux)"]
        bt["Blue-Tap<br/>modules"]
        hci_vsc["hci_vsc.py<br/>(VSC sender)"]
        firmware_py["firmware.py<br/>(detection,<br/>BDADDR patch)"]
    end

    subgraph hci_boundary["HCI Boundary"]
        cmd["HCI Commands"]
        evt["HCI Events"]
        acl_hci["ACL Data"]
    end

    subgraph controller["RTL8761B Controller (MIPS16e)"]
        subgraph hooks["DarkFirmware Hooks"]
            h1["Hook 1: HCI CMD<br/>Intercepts VSC 0xFE22<br/>→ LMP injection"]
            h2["Hook 2: LMP RX<br/>Logs incoming LMP<br/>+ modification modes 0-5"]
            h3["Hook 3: tLC_TX<br/>Logs outgoing<br/>LMP + ACL"]
            h4["Hook 4: tLC_RX<br/>Logs all incoming<br/>LC packets"]
        end
        baseband["Baseband<br/>Processing"]
    end

    subgraph air["Over-the-Air"]
        target["Remote<br/>Target"]
    end

    bt --> hci_vsc --> cmd
    firmware_py --> cmd
    cmd --> h1
    evt --> bt
    h1 -->|"inject LMP<br/>(VSC 0xFE22)"| baseband
    h2 -->|"log + modify"| baseband
    h3 -->|"log outgoing"| baseband
    h4 -->|"log incoming"| baseband
    baseband <-->|"LMP / ACL / SCO"| target
    h2 & h3 & h4 -->|"HCI Event 0xFF<br/>(vendor feedback)"| evt

    style host fill:#1a3a5c,stroke:#2980b9,color:#fff
    style hci_boundary fill:#2d5016,stroke:#4a8c2a,color:#fff
    style controller fill:#3a1a5c,stroke:#7029b9,color:#fff
    style hooks fill:#4a2a6c,stroke:#9040d0,color:#fff
    style air fill:#5c3a1a,stroke:#b97029,color:#fff
```

### VSC Command Reference

| VSC | Purpose | Direction |
|---|---|---|
| `0xFE22` | LMP packet injection (payload sent as raw LMP over the air) | Host → Controller |
| `0xFC61` | Controller memory read (inspect hook state, backup addresses) | Host → Controller |
| `0xFC62` | Controller memory write (install hooks, set modification mode) | Host → Controller |
| `0xFF` (event) | Vendor event carrying hook output (logged LMP/ACL packets) | Controller → Host |

### Hook Modification Modes (Hook 2)

Hook 2 supports six modes controlled by writing to `MOD_FLAG_ADDR` (0x80133FF0):

| Mode | Name | Behavior |
|---|---|---|
| 0 | Passthrough | Log only, no modification |
| 1 | Modify | Overwrite one byte in packet (one-shot, auto-clears) |
| 2 | Drop | Drop next incoming LMP packet entirely (one-shot) |
| 3 | Opcode Drop | Drop packets matching a target opcode (persistent) |
| 4 | Persistent Modify | Same as Modify but does not auto-clear |
| 5 | Auto Respond | Send pre-loaded response when trigger opcode seen |
