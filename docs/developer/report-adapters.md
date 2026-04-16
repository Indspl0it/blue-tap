# Report Adapters

This document covers the report adapter contract, section models, block types, the rendering pipeline, and how to write a custom adapter.

---

## ReportAdapter Abstract Interface

Every report adapter implements the `ReportAdapter` ABC from `blue_tap.framework.contracts.report_contract`:

```python
from abc import ABC, abstractmethod
from typing import Any


class ReportAdapter(ABC):
    module: str = ""

    @abstractmethod
    def accepts(self, envelope: dict[str, Any]) -> bool:
        """Return True if this adapter can handle the given envelope."""
        ...

    @abstractmethod
    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        """Extract relevant data from envelope into report_state.

        Called once per matching envelope. Accumulate data in report_state
        (a shared dict that persists across multiple ingest calls).
        """
        ...

    @abstractmethod
    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        """Build renderable sections from the accumulated report_state.

        Called once after all envelopes have been ingested.
        """
        ...

    @abstractmethod
    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        """Build a JSON-serializable dict for JSON report output."""
        ...
```

### Key Contract Points

- `accepts()` is called with a minimal probe dict (at least `{"schema": "..."}`) to check if the adapter handles a given schema.
- `ingest()` may be called multiple times (once per envelope). Use `report_state.setdefault()` to accumulate.
- `build_sections()` is called once after all envelopes are ingested. It returns a list of `SectionModel` instances.
- `build_json_section()` produces the JSON report equivalent.

---

## Section Models

### SectionModel

```python
@dataclass(frozen=True)
class SectionModel:
    section_id: str                              # Unique section identifier
    title: str                                   # Section heading
    summary: str = ""                            # Brief summary text
    blocks: tuple[SectionBlock, ...] = ()        # Renderable content blocks
```

### SectionBlock

```python
@dataclass(frozen=True)
class SectionBlock:
    block_type: str                              # One of the registered block types
    data: dict[str, Any] = field(default_factory=dict)  # Block-specific payload
```

---

## Block Types

The `BlockRendererRegistry` ships with 9 built-in block types:

| Block Type | `data` Keys | Description |
|---|---|---|
| `table` | `headers: list[str]`, `rows: list[list \| dict]` | HTML table. Rows can be lists or dicts (keyed by header). |
| `paragraph` | `text: str` | Single `<p>` element. |
| `text` | `text: str` | Preformatted `<pre>` element. |
| `card_list` | `cards: list[dict]` | Cards with `title`, `status`, and key-value details. |
| `key_value` | `pairs: dict` (or flat dict) | Key-value pair display. |
| `badge_group` | `badges: list[dict]` | Group of status badges. |
| `status_summary` | *(flat dict)* | Status summary with counts and indicators. |
| `timeline` | `events: list[dict]` | Chronological event timeline. |
| `html_raw` | `html: str` | Raw HTML pass-through (no escaping). |

### Block Construction Examples

```python
from blue_tap.framework.contracts.report_contract import SectionBlock

# Table
table = SectionBlock(
    block_type="table",
    data={
        "headers": ["CVE", "Severity", "Status"],
        "rows": [
            ["CVE-2020-26555", "High", "confirmed"],
            ["CVE-2023-24023", "Medium", "not_detected"],
        ],
    },
)

# Card list
cards = SectionBlock(
    block_type="card_list",
    data={
        "cards": [
            {"title": "BIAS Attack", "status": "success", "protocol": "Classic"},
            {"title": "KNOB Attack", "status": "failed", "protocol": "Classic"},
        ],
    },
)

# Key-value pairs
kv = SectionBlock(
    block_type="key_value",
    data={"pairs": {"Target": "AA:BB:CC:DD:EE:FF", "Adapter": "hci0", "Duration": "12.3s"}},
)

# Badge group
badges = SectionBlock(
    block_type="badge_group",
    data={"badges": [{"label": "Classic", "value": "supported"}, {"label": "BLE", "value": "not tested"}]},
)
```

---

## Built-in Adapters

Blue-Tap ships with 11 adapters in `blue_tap.framework.reporting.adapters`:

| Adapter | Module | Handles Schema |
|---|---|---|
| `DiscoveryReportAdapter` | discovery | `blue_tap.scan.*` |
| `VulnscanReportAdapter` | vulnscan | `blue_tap.vulnscan.*` |
| `AttackReportAdapter` | attack | `blue_tap.attack.*` |
| `DataReportAdapter` | data | `blue_tap.data.*` |
| `AudioReportAdapter` | audio | `blue_tap.audio.*` |
| `DosReportAdapter` | dos | `blue_tap.dos.*` |
| `FirmwareReportAdapter` | firmware | `blue_tap.firmware.*` |
| `FuzzReportAdapter` | fuzz | `blue_tap.fuzz.*` |
| `LmpCaptureReportAdapter` | lmp_capture | `blue_tap.lmp_capture.*` |
| `ReconReportAdapter` | recon | `blue_tap.recon.*` |
| `SpoofReportAdapter` | spoof | `blue_tap.spoof.*` |

All are instantiated in the `REPORT_ADAPTERS` tuple and returned by `get_report_adapters()`.

---

## Adapter Discovery

`get_report_adapters()` returns a tuple combining:

1. **Built-in adapters** from the static `REPORT_ADAPTERS` tuple.
2. **Plugin adapters** discovered via `ModuleDescriptor.report_adapter_path` on registered modules.

Plugin adapters are loaded lazily at call time. Deduplication is by class identity -- a plugin pointing to a built-in adapter class is not loaded twice.

```python
from blue_tap.framework.reporting.adapters import get_report_adapters

all_adapters = get_report_adapters()
```

To find adapters that handle a specific schema:

```python
from blue_tap.framework.reporting.adapters import get_adapters_for_report

adapters = get_adapters_for_report("blue_tap.vulnscan.result")
```

---

## Rendering Pipeline

```
RunEnvelope(s)
    |
    v
adapter.accepts(envelope)        <-- match by schema
    |
    v
adapter.ingest(envelope, state)  <-- accumulate data (called per envelope)
    |
    v
adapter.build_sections(state)    <-- produce SectionModel list (called once)
    |
    v
BlockRendererRegistry.render()   <-- each SectionBlock -> HTML string
    |
    v
HTML output
```

The `BlockRendererRegistry` (from `blue_tap.framework.reporting.renderers.registry`) maps `block_type` strings to renderer functions. Unknown block types fall back to `render_unknown_block()` which produces a `<pre>` dump of the block data.

### Coercion

The registry coerces loose block representations into `SectionBlock` instances via `coerce_block()`:

- `SectionBlock` instance: passed through
- `dict` with `block_type` key: converted to `SectionBlock`
- Any other value: wrapped as `SectionBlock(block_type="text", data={"text": str(value)})`

---

## Complete Working Adapter

Here is a full adapter for a hypothetical "network exposure" module, showing every method with realistic data handling and multiple block types in the output.

### Implementation

```python
"""Adapter for network_exposure module.

Location: blue_tap/framework/reporting/adapters/network_exposure.py
"""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import (
    ReportAdapter,
    SectionBlock,
    SectionModel,
)


class NetworkExposureReportAdapter(ReportAdapter):
    module = "network_exposure"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("schema", "").startswith("blue_tap.network_exposure.")

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        """Accumulate exposure data from one or more envelopes."""
        exposures = report_state.setdefault("network_exposures", [])
        summary = report_state.setdefault("network_exposure_summary", {
            "total_services": 0,
            "unauthenticated": 0,
            "encrypted": 0,
            "unencrypted": 0,
        })

        for execution in envelope.get("executions", []):
            evidence = execution.get("evidence", {})
            module_evidence = evidence.get("module_evidence", {})

            entry = {
                "service": execution.get("title", "Unknown"),
                "protocol": execution.get("protocol", ""),
                "outcome": execution.get("module_outcome", ""),
                "auth_required": module_evidence.get("auth_required", True),
                "encrypted": module_evidence.get("encrypted", False),
                "channel": module_evidence.get("channel", ""),
                "summary": evidence.get("summary", ""),
            }
            exposures.append(entry)

            summary["total_services"] += 1
            if not entry["auth_required"]:
                summary["unauthenticated"] += 1
            if entry["encrypted"]:
                summary["encrypted"] += 1
            else:
                summary["unencrypted"] += 1

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        """Build sections with summary badges, a service table, and risk notes."""
        exposures = report_state.get("network_exposures", [])
        summary = report_state.get("network_exposure_summary", {})
        if not exposures:
            return []

        # Block 1: Summary badges
        badges_block = SectionBlock(
            block_type="badge_group",
            data={
                "badges": [
                    {"label": "Services Found", "value": str(summary["total_services"])},
                    {"label": "No Auth Required", "value": str(summary["unauthenticated"])},
                    {"label": "Unencrypted", "value": str(summary["unencrypted"])},
                ],
            },
        )

        # Block 2: Detailed service table
        rows = []
        for exp in exposures:
            rows.append([
                exp["service"],
                exp["protocol"],
                exp["channel"],
                "No" if not exp["auth_required"] else "Yes",
                "Yes" if exp["encrypted"] else "No",
                exp["outcome"],
            ])

        table_block = SectionBlock(
            block_type="table",
            data={
                "headers": ["Service", "Protocol", "Channel", "Auth", "Encrypted", "Status"],
                "rows": rows,
            },
        )

        # Block 3: Risk paragraph (if unauthenticated services found)
        blocks = [badges_block, table_block]
        if summary["unauthenticated"] > 0:
            risk_block = SectionBlock(
                block_type="paragraph",
                data={
                    "text": (
                        f"{summary['unauthenticated']} service(s) are accessible without "
                        f"authentication. These represent direct attack surface for "
                        f"unauthenticated remote exploitation."
                    ),
                },
            )
            blocks.append(risk_block)

        return [SectionModel(
            section_id="network_exposure",
            title="Network Service Exposure",
            summary=f"{summary['total_services']} services, {summary['unauthenticated']} unauthenticated",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "network_exposures": report_state.get("network_exposures", []),
            "summary": report_state.get("network_exposure_summary", {}),
        }
```

### Rendered HTML Structure

The adapter above produces an HTML section that renders approximately as:

```
+------------------------------------------------------------------+
| Network Service Exposure                                          |
| 5 services, 2 unauthenticated                                    |
|                                                                   |
| [Services Found: 5] [No Auth Required: 2] [Unencrypted: 3]      |
|                                                                   |
| Service          | Protocol | Channel | Auth | Encrypted | Status |
| -----------------+----------+---------+------+-----------+--------|
| OBEX Push        | RFCOMM   | 9       | No   | No        | confirmed |
| Serial Port      | RFCOMM   | 3       | No   | No        | confirmed |
| Audio Gateway    | RFCOMM   | 7       | Yes  | Yes       | observed  |
| A2DP Sink        | AVDTP    | --      | Yes  | Yes       | observed  |
| HID Control      | L2CAP    | 0x0011  | Yes  | No        | observed  |
|                                                                   |
| 2 service(s) are accessible without authentication. These         |
| represent direct attack surface for unauthenticated remote        |
| exploitation.                                                     |
+------------------------------------------------------------------+
```

The actual HTML uses styled `<table>`, `<div class="badge">`, and `<p>` elements with the Blue-Tap CSS theme.

---

## Writing a Custom Adapter

### 1. Create the Adapter Class

Place it in `blue_tap/framework/reporting/adapters/<name>.py`:

```python
"""Adapter for my_module."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import (
    ReportAdapter,
    SectionBlock,
    SectionModel,
)


class MyModuleAdapter(ReportAdapter):
    module = "my_module"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("schema", "").startswith("blue_tap.my_module.")

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        results = report_state.setdefault("my_module_results", [])
        for ex in envelope.get("executions", []):
            results.append({
                "title": ex.get("title", ""),
                "outcome": ex.get("module_outcome", ""),
                "evidence": ex.get("evidence", {}).get("summary", ""),
            })

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        results = report_state.get("my_module_results", [])
        if not results:
            return []

        rows = [[r["title"], r["outcome"], r["evidence"]] for r in results]
        return [SectionModel(
            section_id="my_module",
            title="My Module Results",
            summary=f"{len(results)} result(s)",
            blocks=(
                SectionBlock(
                    block_type="table",
                    data={"headers": ["Title", "Outcome", "Evidence"], "rows": rows},
                ),
            ),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {"my_module": report_state.get("my_module_results", [])}
```

### 2. Register the Adapter

**For built-in adapters:** Add the adapter instance to the `REPORT_ADAPTERS` tuple in `blue_tap/framework/reporting/adapters/__init__.py`, and import the class at the top of the file.

**For plugin adapters:** Set `report_adapter_path` on the `ModuleDescriptor`:

```python
ModuleDescriptor(
    module_id="assessment.my_module",
    # ... other fields ...
    has_report_adapter=True,
    report_adapter_path="my_package.adapters:MyModuleAdapter",
)
```

The adapter will be discovered automatically by `get_report_adapters()`.

### 3. Verify

```bash
# Check that the adapter is discovered
python -c "
from blue_tap.framework.reporting.adapters import get_adapters_for_report
adapters = get_adapters_for_report('blue_tap.my_module.result')
print(f'Found {len(adapters)} adapter(s)')
for a in adapters:
    print(f'  - {type(a).__name__}')
"
```

---

## Custom Block Types

You can register custom block types on the `BlockRendererRegistry`:

```python
from blue_tap.framework.contracts.report_contract import SectionBlock
from blue_tap.framework.reporting.renderers.registry import get_default_block_renderer_registry

def render_my_block(block: SectionBlock) -> str:
    data = block.data
    return f'<div class="my-block">{data.get("content", "")}</div>'

registry = get_default_block_renderer_registry()
registry.register("my_block", render_my_block)
```

After registration, any `SectionBlock(block_type="my_block", ...)` will use your renderer.
