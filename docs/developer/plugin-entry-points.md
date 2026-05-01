# Plugin Entry Points

Third-party packages can extend Blue-Tap by registering modules via Python's `setuptools` entry points. This document covers the plugin system: configuration, validation, adapter integration, and a complete example.

---

## Overview

Blue-Tap discovers external modules through the `blue_tap.modules` entry point group. At startup (or when `load_plugins()` is called), the `ModuleRegistry` iterates over all advertised entry points, loads each one, validates it, and registers it alongside built-in modules.

```python
from blue_tap.framework.registry import load_plugins

loaded_ids = load_plugins()  # Returns list of registered module_id strings
```

---

## Complete pip-Installable Example

This section provides a full, working plugin that you can use as a starting template. It includes the directory structure, all source files, and the `pyproject.toml` configuration.

### Directory Structure

```
bt-tap-ivi-checks/
    pyproject.toml
    README.md
    src/
        bt_tap_ivi_checks/
            __init__.py
            checks.py              # Module implementation + DESCRIPTOR
            adapters.py            # Report adapter
    tests/
        test_ivi_checks.py
```

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "bt-tap-ivi-checks"
version = "0.1.0"
description = "Automotive IVI Bluetooth security checks for Blue-Tap"
requires-python = ">=3.10"
dependencies = ["blue-tap"]

[project.entry-points."blue_tap.modules"]
ivi_diag_check = "bt_tap_ivi_checks.checks:DESCRIPTOR"

[tool.setuptools.packages.find]
where = ["src"]
```

### `src/bt_tap_ivi_checks/__init__.py`

```python
"""Automotive IVI Bluetooth security checks for Blue-Tap."""
```

### `src/bt_tap_ivi_checks/checks.py`

```python
"""
IVI Diagnostic Interface Check.

Detects whether an automotive In-Vehicle Infotainment (IVI) system exposes
a diagnostic RFCOMM channel without authentication. This is a common
misconfiguration in aftermarket head units that allows unauthenticated
access to vehicle diagnostic commands.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily
from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_ERROR,
    build_run_envelope,
    make_evidence,
    make_execution,
    make_run_id,
)
from blue_tap.framework.runtime.cli_events import emit_cli_event

logger = logging.getLogger(__name__)

# Known diagnostic RFCOMM channels used by IVI systems
IVI_DIAG_CHANNELS = (1, 3, 5, 17, 22)
PROBE_TIMEOUT_SECONDS = 8


class IviDiagCheckModule:
    """Checks whether an IVI system exposes diagnostic RFCOMM channels."""

    def run(
        self,
        *,
        target: str,
        adapter: str,
        timeout: int = PROBE_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        run_id = make_run_id("assessment")
        module_id = "assessment.ivi_diag_check"
        open_channels: list[int] = []
        executions: list[dict] = []

        logger.info(
            "Starting IVI diagnostic check",
            extra={"target": target, "adapter": adapter},
        )

        emit_cli_event(
            event_type="run_started",
            module="assessment",
            run_id=run_id,
            message=f"Checking IVI diagnostic channels on {target}",
            target=target,
            adapter=adapter,
        )

        for channel in IVI_DIAG_CHANNELS:
            emit_cli_event(
                event_type="execution_started",
                module="assessment",
                run_id=run_id,
                message=f"Probing RFCOMM channel {channel}",
            )

            try:
                accepted = self._probe_rfcomm(target, channel, timeout)
                outcome = "confirmed" if accepted else "not_detected"

                if accepted:
                    open_channels.append(channel)

                detail = (
                    f"RFCOMM channel {channel}: {'open without auth' if accepted else 'closed/auth required'}"
                )

                evidence = make_evidence(
                    summary=detail,
                    confidence="high" if accepted else "medium",
                    observations=[detail],
                    module_evidence={"channel": channel, "accepted": accepted},
                )

                execution = make_execution(
                    kind="check",
                    id=f"ivi_diag_ch{channel}",
                    title=f"IVI Diagnostic Channel {channel}",
                    module="assessment",
                    protocol="RFCOMM",
                    execution_status=EXECUTION_COMPLETED,
                    module_outcome=outcome,
                    evidence=evidence,
                    module_id=module_id,
                )
                executions.append(execution)

                emit_cli_event(
                    event_type="execution_result",
                    module="assessment",
                    run_id=run_id,
                    message=f"Channel {channel}: {outcome}",
                    details={"channel": channel, "outcome": outcome},
                )

            except Exception as exc:
                logger.error(
                    "RFCOMM probe failed",
                    extra={"channel": channel, "error": str(exc)},
                    exc_info=True,
                )

                evidence = make_evidence(summary=f"Probe error: {exc}", confidence="low")
                execution = make_execution(
                    kind="check",
                    id=f"ivi_diag_ch{channel}",
                    title=f"IVI Diagnostic Channel {channel}",
                    module="assessment",
                    protocol="RFCOMM",
                    execution_status=EXECUTION_ERROR,
                    module_outcome="not_applicable",
                    evidence=evidence,
                    module_id=module_id,
                    error=str(exc),
                )
                executions.append(execution)

        found = len(open_channels)

        emit_cli_event(
            event_type="run_completed",
            module="assessment",
            run_id=run_id,
            message=f"IVI diagnostic check complete: {found} open channel(s)",
        )

        return build_run_envelope(
            schema="blue_tap.ivi_diag_check.result",
            module="assessment",
            module_id=module_id,
            target=target,
            adapter=adapter,
            summary={
                "channels_tested": len(IVI_DIAG_CHANNELS),
                "open_channels": open_channels,
                "vulnerable": found > 0,
            },
            executions=executions,
            module_data={"open_channels": open_channels},
        )

    def _probe_rfcomm(self, target: str, channel: int, timeout: int) -> bool:
        """Attempt an RFCOMM connection. Returns True if accepted without auth."""
        sock = socket.socket(
            socket.AF_BLUETOOTH,
            socket.SOCK_STREAM,
            socket.BTPROTO_RFCOMM,
        )
        try:
            sock.settimeout(timeout)
            sock.connect((target, channel))
            return True
        except (ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()


# --- Entry Point Descriptor ---
# This is what the setuptools entry point resolves to.
# It must be a ModuleDescriptor instance at module scope.

DESCRIPTOR = ModuleDescriptor(
    module_id="assessment.ivi_diag_check",
    family=ModuleFamily.ASSESSMENT,
    name="IVI Diagnostic Channel Check",
    description="Detects unauthenticated diagnostic RFCOMM channels on automotive IVI systems",
    protocols=("Classic", "RFCOMM"),
    requires=("adapter", "classic_target"),
    destructive=False,
    requires_pairing=False,
    schema_prefix="blue_tap.ivi_diag_check.result",
    has_report_adapter=True,
    report_adapter_path="bt_tap_ivi_checks.adapters:IviDiagReportAdapter",
    entry_point="bt_tap_ivi_checks.checks:IviDiagCheckModule",
    category="automotive",
    references=(),
)
```

### `src/bt_tap_ivi_checks/adapters.py`

```python
"""Report adapter for IVI diagnostic check plugin."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import (
    ReportAdapter,
    SectionBlock,
    SectionModel,
)


class IviDiagReportAdapter(ReportAdapter):
    module = "ivi_diag_check"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("schema", "").startswith("blue_tap.ivi_diag_check.")

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        checks = report_state.setdefault("ivi_diag_checks", [])
        for ex in envelope.get("executions", []):
            checks.append({
                "title": ex.get("title", ""),
                "outcome": ex.get("module_outcome", ""),
                "summary": ex.get("evidence", {}).get("summary", ""),
                "channel": ex.get("evidence", {}).get("module_evidence", {}).get("channel", ""),
            })

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        checks = report_state.get("ivi_diag_checks", [])
        if not checks:
            return []

        rows = [[c["title"], str(c["channel"]), c["outcome"], c["summary"]] for c in checks]
        return [SectionModel(
            section_id="ivi_diag_check",
            title="IVI Diagnostic Channel Exposure",
            summary=f"{len(checks)} channel(s) tested",
            blocks=(
                SectionBlock(
                    block_type="table",
                    data={
                        "headers": ["Check", "Channel", "Outcome", "Detail"],
                        "rows": rows,
                    },
                ),
            ),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {"ivi_diag_checks": report_state.get("ivi_diag_checks", [])}
```

### `tests/test_ivi_checks.py`

```python
"""Tests for the IVI diagnostic check plugin."""

from bt_tap_ivi_checks.checks import DESCRIPTOR, IviDiagCheckModule


def test_descriptor_is_valid():
    """Descriptor construction validates via __post_init__."""
    assert DESCRIPTOR.module_id == "assessment.ivi_diag_check"
    assert DESCRIPTOR.family.value == "assessment"
    assert DESCRIPTOR.entry_point == "bt_tap_ivi_checks.checks:IviDiagCheckModule"


def test_descriptor_loads_through_registry():
    """Verify the module can be loaded through the registry."""
    from blue_tap.framework.registry import get_registry

    registry = get_registry()
    loaded = registry.load_plugins()
    assert "assessment.ivi_diag_check" in loaded


def test_module_produces_valid_envelope(mocker):
    """Module produces a valid RunEnvelope."""
    from blue_tap.framework.contracts.result_schema import validate_run_envelope

    # Mock socket to avoid needing a real Bluetooth adapter
    mock_sock = mocker.MagicMock()
    mock_sock.connect.side_effect = ConnectionRefusedError
    mocker.patch("socket.socket", return_value=mock_sock)

    module = IviDiagCheckModule()
    envelope = module.run(target="AA:BB:CC:DD:EE:FF", adapter="hci0")

    errors = validate_run_envelope(envelope)
    assert not errors, f"Validation errors: {errors}"
    assert envelope["schema"] == "blue_tap.ivi_diag_check.result"
    assert len(envelope["executions"]) == 5  # One per channel
```

### Installation and Testing

```bash
# Install the plugin in development mode
cd bt-tap-ivi-checks/
pip install -e .

# Verify the descriptor is valid
python -c "
from bt_tap_ivi_checks.checks import DESCRIPTOR
print(f'module_id: {DESCRIPTOR.module_id}')
print(f'family: {DESCRIPTOR.family}')
print(f'entry_point: {DESCRIPTOR.entry_point}')
"

# Verify it loads through the registry
python -c "
from blue_tap.framework.registry import get_registry
registry = get_registry()
loaded = registry.load_plugins()
print(f'Loaded: {loaded}')
desc = registry.try_get('assessment.ivi_diag_check')
print(f'Found: {desc}')
"

# Run the tests
pytest tests/ -v

# Run the check against a target
sudo blue-tap vulnscan AA:BB:CC:DD:EE:FF --cve ivi_diag_check
```

---

## pyproject.toml Configuration

Advertise your module by pointing an entry point at a `ModuleDescriptor` instance:

```toml
[project]
name = "my-bt-tap-plugin"
version = "0.1.0"
dependencies = ["blue-tap"]

[project.entry-points."blue_tap.modules"]
my_check = "my_package.checks:DESCRIPTOR"
```

The entry point value (`"my_package.checks:DESCRIPTOR"`) must resolve to a `ModuleDescriptor` instance at module scope.

---

## Plugin Validation

When a plugin is loaded, `validate_plugin(descriptor)` runs the following checks and returns a list of warnings (not hard errors -- the module is still registered):

| Check | Warning if |
|---|---|
| `entry_point` is empty | Module cannot be invoked at runtime |
| `schema_prefix` is empty | Rendering/adapter matching may fail |
| `entry_point` module is not importable | The module path before `:` cannot be imported |

In addition, the `ModuleDescriptor.__post_init__()` validation runs on construction:

| Check | Raises `ValueError` if |
|---|---|
| `module_id` format | Does not match `^[a-z0-9_]+(\.[a-z0-9_]+)+$` (lowercase snake_case, dot-separated, dotted hierarchies allowed) |
| `family` type | Not a `ModuleFamily` enum instance |
| `module_id` prefix | Does not start with `{family.value}.` |
| `name` | Empty string |
| `protocols` type | Not a `tuple` |
| `requires` type | Not a `tuple` |

If `__post_init__` raises, the entry point is logged as an error and skipped. If `validate_plugin` returns warnings, they are logged but the module is still registered.

---

## Constraints

| Constraint | Detail |
|---|---|
| Must follow `ModuleDescriptor` schema | All required fields, valid `module_id` format, correct family prefix |
| Must return valid `RunEnvelope` | Passes `validate_run_envelope()` |
| Cannot override built-in modules | `register()` raises `ValueError` on duplicate `module_id` |
| `module_outcome` must be valid | `module_id` is required on `make_execution()` and `build_run_envelope()`; the outcome is validated against `FAMILY_OUTCOMES[family]` and a mismatch raises `ValueError` at construction |
| Entry point must be importable | `validate_plugin()` warns if the module path cannot be imported |

---

## Loading Behavior

- `load_plugins()` uses `importlib.metadata.entry_points(group="blue_tap.modules")`.
- Each entry point is loaded via `ep.load()`, which must return a `ModuleDescriptor` instance.
- Non-`ModuleDescriptor` return values are logged as warnings and skipped.
- Import errors or registration failures are logged as errors and skipped (other plugins continue loading).
- `load_plugins()` returns a list of successfully registered `module_id` strings.

```python
from blue_tap.framework.registry import get_registry

registry = get_registry()
loaded = registry.load_plugins()
print(f"Loaded {len(loaded)} plugin(s): {loaded}")
```

---

## Testing Your Plugin

```bash
# Verify the descriptor is valid
python -c "
from my_package.checks import DESCRIPTOR
print(f'module_id: {DESCRIPTOR.module_id}')
print(f'family: {DESCRIPTOR.family}')
print(f'entry_point: {DESCRIPTOR.entry_point}')
"

# Verify it loads through the registry
python -c "
from blue_tap.framework.registry import get_registry
registry = get_registry()
loaded = registry.load_plugins()
print(f'Loaded: {loaded}')
desc = registry.try_get('assessment.my_check')
print(f'Found: {desc}')
"

# Verify the module produces a valid envelope
python -c "
from my_package.checks import MyCheckModule
from blue_tap.framework.contracts.result_schema import validate_run_envelope

module = MyCheckModule()
envelope = module.run(target='AA:BB:CC:DD:EE:FF', adapter='hci0')
errors = validate_run_envelope(envelope)
if errors:
    print(f'Validation errors: {errors}')
else:
    print('Envelope is valid')
"
```
