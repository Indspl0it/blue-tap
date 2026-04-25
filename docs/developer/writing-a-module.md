# Writing a Module

Step-by-step guide to creating a new Blue-Tap module, from implementation to registration. This is the primary reference for contributors adding new detection capabilities.

---

## Overview

Adding a module involves up to 6 steps:

1. Create the implementation file
2. Use envelope builders to produce structured output
3. Emit CLI events for operator feedback
4. Register the module descriptor
5. Add a report adapter (optional)
6. Add a CLI command (optional)

---

## Complete Working Example

Before diving into individual steps, here is a complete, working assessment module that checks whether a target device accepts L2CAP connections on a non-standard PSM without authentication. This module demonstrates every required pattern.

```python
"""
Assessment check: unauthenticated L2CAP PSM access.

Tests whether the target accepts L2CAP connections on non-standard PSMs
without requiring authentication. This indicates a potential attack surface
for protocol-level exploits.

Location: blue_tap/modules/assessment/l2cap_open_psm.py
"""

from __future__ import annotations

import logging
import socket
import time
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    EXECUTION_ERROR,
    build_run_envelope,
    make_evidence,
    make_execution,
    make_run_id,
)
from blue_tap.framework.runtime.cli_events import emit_cli_event

logger = logging.getLogger(__name__)

# PSMs to test (non-standard range, above 0x1001)
TARGET_PSMS = (0x1001, 0x1003, 0x1005, 0x1007, 0x1009)

# Connection timeout per PSM probe
PSM_PROBE_TIMEOUT_SECONDS = 5


class L2capOpenPsmModule:
    """Checks whether the target accepts L2CAP connections on non-standard PSMs."""

    def run(
        self,
        *,
        target: str,
        adapter: str,
        timeout: int = PSM_PROBE_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        run_id = make_run_id("assessment")
        module_id = "assessment.l2cap_open_psm"
        open_psms: list[int] = []
        executions: list[dict] = []

        logger.info(
            "Starting L2CAP open PSM check",
            extra={"target": target, "adapter": adapter, "psm_count": len(TARGET_PSMS)},
        )

        emit_cli_event(
            event_type="run_started",
            module="assessment",
            run_id=run_id,
            message=f"Checking {len(TARGET_PSMS)} non-standard L2CAP PSMs on {target}",
            target=target,
            adapter=adapter,
        )

        for psm in TARGET_PSMS:
            emit_cli_event(
                event_type="execution_started",
                module="assessment",
                run_id=run_id,
                message=f"Probing PSM 0x{psm:04X}",
                target=target,
            )

            try:
                accepted = self._probe_psm(target, psm, timeout)

                if accepted:
                    open_psms.append(psm)
                    outcome = "confirmed"
                    confidence = "high"
                    detail = f"PSM 0x{psm:04X} accepted connection without authentication"
                    status = EXECUTION_COMPLETED
                else:
                    outcome = "not_detected"
                    confidence = "high"
                    detail = f"PSM 0x{psm:04X} rejected or not listening"
                    status = EXECUTION_COMPLETED

                evidence = make_evidence(
                    summary=detail,
                    confidence=confidence,
                    observations=[detail],
                    module_evidence={"psm": psm, "accepted": accepted},
                )

                execution = make_execution(
                    kind="check",
                    id=f"l2cap_psm_0x{psm:04X}",
                    title=f"L2CAP PSM 0x{psm:04X}",
                    module="assessment",
                    protocol="L2CAP",
                    execution_status=status,
                    module_outcome=outcome,
                    evidence=evidence,
                    module_id=module_id,
                )
                executions.append(execution)

                emit_cli_event(
                    event_type="execution_result",
                    module="assessment",
                    run_id=run_id,
                    message=f"PSM 0x{psm:04X}: {outcome}",
                    details={"psm": psm, "outcome": outcome},
                )

            except Exception as exc:
                logger.error(
                    "PSM probe failed",
                    extra={"psm": psm, "error": str(exc)},
                    exc_info=True,
                )

                evidence = make_evidence(
                    summary=f"Probe error: {exc}",
                    confidence="low",
                )

                execution = make_execution(
                    kind="check",
                    id=f"l2cap_psm_0x{psm:04X}",
                    title=f"L2CAP PSM 0x{psm:04X}",
                    module="assessment",
                    protocol="L2CAP",
                    execution_status=EXECUTION_ERROR,
                    module_outcome="not_applicable",
                    evidence=evidence,
                    module_id=module_id,
                    error=str(exc),
                )
                executions.append(execution)

                emit_cli_event(
                    event_type="execution_result",
                    module="assessment",
                    run_id=run_id,
                    message=f"PSM 0x{psm:04X}: error -- {exc}",
                )

        # Build the final envelope
        total = len(executions)
        found = len(open_psms)

        emit_cli_event(
            event_type="run_completed",
            module="assessment",
            run_id=run_id,
            message=f"L2CAP PSM check complete: {found}/{total} open",
            details={"open_psms": open_psms},
        )

        logger.info(
            "L2CAP open PSM check complete",
            extra={"target": target, "open_count": found, "total": total},
        )

        return build_run_envelope(
            schema="blue_tap.l2cap_open_psm.result",
            module="assessment",
            module_id=module_id,
            target=target,
            adapter=adapter,
            summary={
                "total_psms_tested": total,
                "open_psms": open_psms,
                "vulnerable": found > 0,
            },
            executions=executions,
            module_data={
                "psms_tested": list(TARGET_PSMS),
                "open_psms": open_psms,
            },
        )

    def _probe_psm(self, target: str, psm: int, timeout: int) -> bool:
        """Attempt an L2CAP connection to the given PSM. Returns True if accepted."""
        sock = socket.socket(
            socket.AF_BLUETOOTH,
            socket.SOCK_SEQPACKET,
            socket.BTPROTO_L2CAP,
        )
        try:
            sock.settimeout(timeout)
            sock.connect((target, psm))
            return True
        except (ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()
```

---

## Step 1: Create the Implementation File

Place your module at `blue_tap/modules/<family>/<name>.py`.

```python
"""Example posture check -- demonstration module."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ExampleCheckModule:
    """Checks whether the target exposes an example weakness."""

    def run(
        self,
        *,
        target: str,
        adapter: str,
        timeout: int = 10,
    ) -> dict[str, Any]:
        logger.info("Starting example check", extra={"target": target, "adapter": adapter})

        # ... your detection logic here ...
        is_vulnerable = False
        detail = "Target does not expose the example weakness"

        return self._build_envelope(
            target=target,
            adapter=adapter,
            is_vulnerable=is_vulnerable,
            detail=detail,
        )

    def _build_envelope(
        self,
        *,
        target: str,
        adapter: str,
        is_vulnerable: bool,
        detail: str,
    ) -> dict[str, Any]:
        from blue_tap.framework.contracts.result_schema import (
            EXECUTION_COMPLETED,
            build_run_envelope,
            make_evidence,
            make_execution,
        )

        outcome = "confirmed" if is_vulnerable else "not_detected"
        confidence = "high" if is_vulnerable else "medium"

        evidence = make_evidence(
            summary=detail,
            confidence=confidence,
            observations=[detail],
        )

        execution = make_execution(
            kind="check",
            id="example_check",
            title="Example Posture Check",
            module="assessment",
            protocol="Classic",
            execution_status=EXECUTION_COMPLETED,
            module_outcome=outcome,
            evidence=evidence,
            module_id="assessment.example_check",
        )

        return build_run_envelope(
            schema="blue_tap.example_check.result",
            module="assessment",
            module_id="assessment.example_check",
            target=target,
            adapter=adapter,
            summary={"vulnerable": is_vulnerable, "detail": detail},
            executions=[execution],
            module_data={"check_id": "example_check"},
        )
```

---

## Step 2: Use Envelope Builders

For common families, use the pre-built envelope builders instead of calling `build_run_envelope` directly. They handle boilerplate like run IDs, timestamps, and evidence construction.

### Assessment (via raw schema helpers)

Assessment modules typically build envelopes directly with `make_execution` + `build_run_envelope` as shown above, since each check has unique structure.

### Exploitation (via `build_attack_result`)

```python
from blue_tap.framework.envelopes.attack import build_attack_result

envelope = build_attack_result(
    target="AA:BB:CC:DD:EE:FF",
    adapter="hci0",
    operation="bias_attack",
    title="BIAS Authentication Bypass",
    protocol="Classic",
    module_data={"role_switch": True, "auth_bypass": True},
    observations=["Role switch accepted", "Authentication bypassed"],
    module_outcome="success",
)
```

### Reconnaissance (via `build_recon_result`)

```python
from blue_tap.framework.envelopes.recon import build_recon_result
from blue_tap.framework.contracts.result_schema import now_iso

envelope = build_recon_result(
    target="AA:BB:CC:DD:EE:FF",
    adapter="hci0",
    operation="sdp_services",
    title="SDP Service Discovery",
    protocol="SDP",
    entries=[{"name": "OBEX Push", "channel": 9}],
    observations=["Found 3 SDP services"],
    started_at=now_iso(),
)
```

### Fuzzing (via `build_fuzz_result`)

```python
from blue_tap.framework.envelopes.fuzz import build_fuzz_result

envelope = build_fuzz_result(
    target="AA:BB:CC:DD:EE:FF",
    adapter="hci0",
    command="l2cap_fuzz",
    protocol="L2CAP",
    result={"sent": 50000, "crashes": 2, "errors": 0, "elapsed": 120.5, "total_cases": 50000},
)
```

---

## Step 3: Emit CLI Events

Use `emit_cli_event()` to provide real-time feedback to the operator during execution. Always use one of the 14 canonical event types.

```python
from blue_tap.framework.contracts.result_schema import make_run_id
from blue_tap.framework.runtime.cli_events import emit_cli_event

run_id = make_run_id("assessment")

# Signal the start of the run
emit_cli_event(
    event_type="run_started",
    module="assessment",
    run_id=run_id,
    message="Starting example check against AA:BB:CC:DD:EE:FF",
    target="AA:BB:CC:DD:EE:FF",
    adapter="hci0",
)

# Report a result
emit_cli_event(
    event_type="execution_result",
    module="assessment",
    run_id=run_id,
    message="Example check: not vulnerable",
    details={"outcome": "not_detected", "check_id": "example_check"},
)

# Signal completion
emit_cli_event(
    event_type="run_completed",
    module="assessment",
    run_id=run_id,
    message="Example check completed (1 check, 0 findings)",
)
```

### Event Types Quick Reference

| Phase | Event Type | When |
|---|---|---|
| Start | `run_started` | Once at the beginning |
| Progress | `phase_started` | Start of a named phase |
| Progress | `execution_started` | Before each check/probe |
| Result | `execution_result` | After each check completes |
| Result | `execution_skipped` | When a check is skipped |
| Info | `execution_observation` | Informational note |
| Pairing | `pairing_required` | Target requires pairing |
| Recovery | `recovery_wait_started` / `progress` / `finished` | Target recovery |
| Artifact | `artifact_saved` | File saved to disk |
| End | `run_completed` | Success |
| End | `run_aborted` | Intentional early stop |
| End | `run_error` | Unrecoverable error |

---

## Step 4: Register the Module

Add a `ModuleDescriptor` registration in your family's `__init__.py`.

For `blue_tap/modules/assessment/__init__.py`:

```python
from blue_tap.framework.registry import get_registry, ModuleDescriptor, ModuleFamily

_registry = get_registry()

def _register_once(descriptor: ModuleDescriptor) -> None:
    """Idempotent registration -- safe to import multiple times."""
    try:
        _registry.get(descriptor.module_id)
    except KeyError:
        _registry.register(descriptor)

_register_once(ModuleDescriptor(
    module_id="assessment.l2cap_open_psm",
    family=ModuleFamily.ASSESSMENT,
    name="L2CAP Open PSM Check",
    description="Checks for unauthenticated L2CAP PSM access on non-standard channels",
    protocols=("Classic", "L2CAP"),
    requires=("adapter", "classic_target"),
    destructive=False,
    requires_pairing=False,
    schema_prefix="blue_tap.l2cap_open_psm.result",
    has_report_adapter=False,
    entry_point="blue_tap.modules.assessment.l2cap_open_psm:L2capOpenPsmModule",
    category="l2cap",
))
```

!!! note "Required field: `module_id` format"
    The `module_id` must match `^[a-z0-9_]+(\.[a-z0-9_]+)+$` (lowercase snake_case, dot-separated, at least one dot — dotted hierarchies like `assessment.cve.knob` are accepted). The first segment must be a registered `ModuleFamily` value. `"assessment.l2cap_open_psm"` is valid; `"l2cap_open_psm"` (no dot) and `"Assessment.L2capOpenPsm"` (uppercase) raise `ValueError` at descriptor construction. The first-segment family check is what `make_execution()` uses to pick the outcome taxonomy.

---

## Step 5: Add a Report Adapter (Optional)

If your module should appear in generated reports, create an adapter in `blue_tap/framework/reporting/adapters/`.

```python
"""Report adapter for l2cap_open_psm module."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import (
    ReportAdapter,
    SectionBlock,
    SectionModel,
)


class L2capOpenPsmReportAdapter(ReportAdapter):
    module = "l2cap_open_psm"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("schema", "").startswith("blue_tap.l2cap_open_psm.")

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        """Extract data from the envelope into report_state."""
        checks = report_state.setdefault("l2cap_open_psm_checks", [])
        for execution in envelope.get("executions", []):
            checks.append({
                "title": execution.get("title", ""),
                "outcome": execution.get("module_outcome", ""),
                "summary": execution.get("evidence", {}).get("summary", ""),
            })

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        """Build HTML-renderable sections from ingested data."""
        checks = report_state.get("l2cap_open_psm_checks", [])
        if not checks:
            return []

        rows = [[c["title"], c["outcome"], c["summary"]] for c in checks]
        table_block = SectionBlock(
            block_type="table",
            data={"headers": ["Check", "Outcome", "Summary"], "rows": rows},
        )

        return [SectionModel(
            section_id="l2cap_open_psm",
            title="L2CAP Open PSM Checks",
            summary=f"{len(checks)} PSM(s) tested",
            blocks=(table_block,),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        """Build a JSON-serializable section for JSON report output."""
        return {"l2cap_open_psm_checks": report_state.get("l2cap_open_psm_checks", [])}
```

Then register it in `blue_tap/framework/reporting/adapters/__init__.py` by adding it to the `REPORT_ADAPTERS` tuple. Set `has_report_adapter=True` on the `ModuleDescriptor`.

---

## Step 6: Add a CLI Command (Optional)

Add a Click command in `blue_tap/interfaces/cli/<family>.py` using `LoggedCommand`:

```python
import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command(cls=LoggedCommand)
@click.argument("address")
@click.option("--hci", default="hci0", help="HCI adapter")
@click.option("--timeout", default=5, type=int, help="Per-PSM probe timeout in seconds")
@click.pass_context
def l2cap_open_psm(ctx, address: str, hci: str, timeout: int):
    """Check for unauthenticated L2CAP PSM access."""
    from blue_tap.modules.assessment.l2cap_open_psm import L2capOpenPsmModule

    module = L2capOpenPsmModule()
    result = module.run(target=address, adapter=hci, timeout=timeout)

    # Session logging is handled automatically by LoggedCommand
    open_psms = result["summary"].get("open_psms", [])
    if open_psms:
        click.echo(f"Open PSMs: {', '.join(f'0x{p:04X}' for p in open_psms)}")
    else:
        click.echo("No open non-standard PSMs detected")
```

`LoggedCommand` automatically sets the active HCI adapter on the session when the `--hci` option is present.

---

## Common Mistakes

!!! failure "Using bare `print()` instead of `logger` and `emit_cli_event`"
    Modules must use `logging.getLogger(__name__)` for structured logging and `emit_cli_event()` for operator-visible output. Bare `print()` bypasses both systems -- it won't appear in log files, won't be captured by session recording, and won't respect the CLI's verbosity settings.

!!! failure "Returning raw dicts instead of using `build_run_envelope`"
    Every module must return a `RunEnvelope`-shaped dict built by `build_run_envelope()` or a family envelope builder. Hand-constructed dicts will miss required fields (`schema_version`, `run_id`, timestamps) and fail validation.

!!! failure "Using the wrong `module_outcome` for the family"
    Assessment modules must use outcomes from the assessment set (`confirmed`, `not_detected`, `inconclusive`, `pairing_required`, `not_applicable`). Using an exploitation outcome like `success` in an assessment module raises `ValueError` at `make_execution()` time — the family is derived from the `module_id` prefix and validated against `FAMILY_OUTCOMES` (single source of truth in `framework/registry/families.py`).

!!! failure "Forgetting to pass `module_id` to `make_execution()` / `build_run_envelope()`"
    `module_id` is **required** on both builders. Omitting it raises `ValueError` immediately, so this failure mode is now caught the first time the module runs in tests rather than silently shipping a malformed envelope.

!!! failure "Catching exceptions silently"
    Never use bare `except: pass`. If a probe fails, log the error, create an `EXECUTION_ERROR` record with the error message, and continue to the next check. The error must be visible in both logs and the envelope.

!!! failure "Hardcoding the adapter name"
    Always accept `adapter` as a parameter. Never hardcode `"hci0"` -- the operator may be using a different adapter, especially when DarkFirmware is on `hci1`.

---

## Complete Checklist

- [ ] Implementation file at `modules/<family>/<name>.py`
- [ ] Returns a valid `RunEnvelope` dict
- [ ] Passes `module_id=...` to both `make_execution()` and `build_run_envelope()` (required — omitting raises `ValueError`)
- [ ] Emits CLI events (`run_started`, `execution_result`, `run_completed`)
- [ ] Registered via `ModuleDescriptor` in `modules/<family>/__init__.py`
- [ ] `module_outcome` values are from the family's allowed set
- [ ] Report adapter (if needed) in `framework/reporting/adapters/`
- [ ] CLI command (if exposed) in `interfaces/cli/<family>.py`
- [ ] Uses `logging.getLogger(__name__)` (no bare `print()`)
- [ ] Handles errors per-execution (logs error, records `EXECUTION_ERROR`, continues)
- [ ] Accepts `adapter` as a parameter (no hardcoded adapter names)
- [ ] Accepts `timeout` where relevant (no hardcoded timeouts in probe logic)
- [ ] Closes sockets/resources in `finally` blocks
