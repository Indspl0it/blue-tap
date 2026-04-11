"""Shared firmware result envelope helpers."""

from __future__ import annotations

from typing import Any

from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    EXECUTION_SKIPPED,
    build_run_envelope,
    make_artifact,
    make_evidence,
    make_execution,
    make_run_id,
    now_iso,
)

FIRMWARE_MODULE_OUTCOMES = (
    "completed",
    "installed",
    "hooks_active",
    "hooks_partial",
    "not_loaded",
    "prerequisite_missing",
)


def make_firmware_run_id() -> str:
    return make_run_id("firmware")


def build_firmware_status_result(
    *,
    adapter: str,
    status: dict[str, Any],
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Build envelope for firmware status check."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()

    installed = bool(status.get("installed"))
    loaded = bool(status.get("loaded"))
    hooks = status.get("hooks", {})
    active_hooks = [k for k, v in hooks.items() if v]
    failed_hooks = [k for k, v in hooks.items() if not v]

    if loaded and len(active_hooks) == len(hooks):
        module_outcome = "hooks_active"
    elif loaded and active_hooks:
        module_outcome = "hooks_partial"
    elif loaded:
        module_outcome = "not_loaded"
    elif installed:
        module_outcome = "completed"
    else:
        module_outcome = "prerequisite_missing"

    observations = [
        f"Firmware installed: {installed}",
        f"DarkFirmware loaded: {loaded}",
    ]
    if status.get("bdaddr"):
        observations.append(f"BDADDR: {status['bdaddr']}")
    if active_hooks:
        observations.append(f"Active hooks: {', '.join(active_hooks)}")
    if failed_hooks:
        observations.append(f"Failed hooks: {', '.join(failed_hooks)}")

    capability_limitations = []
    if not installed:
        capability_limitations.append("RTL8761B firmware not installed — LMP injection unavailable")
    elif not loaded:
        capability_limitations.append("DarkFirmware not loaded — restart adapter or run firmware-init")
    if failed_hooks:
        capability_limitations.append(f"Hooks not active: {', '.join(failed_hooks)}")

    evidence = make_evidence(
        summary=f"DarkFirmware on {adapter}: {'active' if loaded else 'not loaded'}",
        confidence="high",
        observations=observations,
        capability_limitations=capability_limitations,
        module_evidence=status,
    )

    execution = make_execution(
        kind="collector",
        id="firmware_status",
        title="DarkFirmware Status Check",
        module="firmware",
        protocol="HCI",
        execution_status=EXECUTION_COMPLETED,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["firmware", "status"],
        module_data=status,
    )

    return build_run_envelope(
        schema="blue_tap.firmware.result",
        module="firmware",
        target=adapter,
        adapter=adapter,
        operator_context={"operation": "status"},
        summary={"operation": "status", "installed": installed, "loaded": loaded, "hooks_active": len(active_hooks)},
        executions=[execution],
        artifacts=[],
        module_data={"operation": "status", **status},
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def build_firmware_dump_result(
    *,
    adapter: str,
    start_addr: int,
    end_addr: int,
    output_path: str,
    success: bool,
    file_size: int = 0,
    invalid_regions: list[tuple[int, int]] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Build envelope for firmware memory dump."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    dump_size = end_addr - start_addr
    regions = list(invalid_regions or [])

    observations = [
        f"Range: 0x{start_addr:08X}-0x{end_addr:08X} ({dump_size:,} bytes)",
        f"Output: {output_path}",
    ]
    if file_size:
        observations.append(f"File size: {file_size:,} bytes")
    if regions:
        observations.append(f"Invalid regions (DEADBEEF): {len(regions)}")
        for i, (rstart, rend) in enumerate(regions[:5]):
            observations.append(f"  Region {i+1}: 0x{rstart:08X}-0x{rend:08X}")

    artifacts = []
    if success and output_path:
        artifacts.append(make_artifact(
            kind="raw",
            label=f"Memory dump 0x{start_addr:08X}",
            path=output_path,
            description=f"Firmware memory dump ({dump_size:,} bytes)",
        ))

    evidence = make_evidence(
        summary=f"Memory dump {'completed' if success else 'failed'}: {dump_size:,} bytes from 0x{start_addr:08X}",
        confidence="high" if success else "low",
        observations=observations,
        artifacts=artifacts,
        module_evidence={
            "start_addr": f"0x{start_addr:08X}",
            "end_addr": f"0x{end_addr:08X}",
            "dump_size": dump_size,
            "file_size": file_size,
            "invalid_region_count": len(regions),
        },
    )

    execution = make_execution(
        kind="collector",
        id="firmware_dump",
        title="Firmware Memory Dump",
        module="firmware",
        protocol="HCI",
        execution_status=EXECUTION_COMPLETED if success else EXECUTION_FAILED,
        module_outcome="completed" if success else "not_loaded",
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["firmware", "dump", "memory"],
        artifacts=artifacts,
        module_data={
            "start_addr": f"0x{start_addr:08X}",
            "end_addr": f"0x{end_addr:08X}",
            "output_path": output_path,
            "success": success,
            "invalid_regions": [{"start": f"0x{s:08X}", "end": f"0x{e:08X}"} for s, e in regions],
        },
    )

    return build_run_envelope(
        schema="blue_tap.firmware.result",
        module="firmware",
        target=adapter,
        adapter=adapter,
        operator_context={"operation": "dump"},
        summary={"operation": "dump", "success": success, "bytes": dump_size},
        executions=[execution],
        artifacts=artifacts,
        module_data={"operation": "dump", "start_addr": f"0x{start_addr:08X}", "end_addr": f"0x{end_addr:08X}", "output": output_path},
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def build_connection_inspect_result(
    *,
    adapter: str,
    connections: list[dict[str, Any]],
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Build envelope for connection table inspection."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    active = [c for c in connections if c.get("active")]
    knob_vulnerable = [c for c in active if c.get("key_size") == 1]

    observations = [f"Active connections: {len(active)}/{len(connections)} slots"]
    for conn in active:
        addr = conn.get("address", "?")
        enc = "encrypted" if conn.get("encryption_enabled") else "NOT encrypted"
        ks = conn.get("key_size", "?")
        sc = "SC" if conn.get("secure_connections") else "legacy"
        knob = " [KNOB VULNERABLE]" if conn.get("key_size") == 1 else ""
        observations.append(f"  {addr}: {enc}, key_size={ks}, {sc}{knob}")

    severity = None
    if knob_vulnerable:
        severity = "high"
        observations.append(f"KNOB-vulnerable connections: {len(knob_vulnerable)}")

    evidence = make_evidence(
        summary=f"Inspected {len(active)} active connection(s), {len(knob_vulnerable)} KNOB-vulnerable",
        confidence="high",
        observations=observations,
        module_evidence={
            "total_slots": len(connections),
            "active_connections": len(active),
            "knob_vulnerable": len(knob_vulnerable),
            "connections": connections,
        },
    )

    execution = make_execution(
        kind="collector",
        id="connection_inspect",
        title="Connection Table Inspection",
        module="firmware",
        protocol="HCI",
        execution_status=EXECUTION_COMPLETED,
        module_outcome="completed",
        severity=severity,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["firmware", "connection", "inspection"],
        module_data={"connections": connections},
    )

    return build_run_envelope(
        schema="blue_tap.firmware.result",
        module="firmware",
        target=adapter,
        adapter=adapter,
        operator_context={"operation": "connection_inspect"},
        summary={"operation": "connection_inspect", "active": len(active), "knob_vulnerable": len(knob_vulnerable)},
        executions=[execution],
        artifacts=[],
        module_data={"operation": "connection_inspect", "connections": connections},
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def build_firmware_operation_result(
    *,
    adapter: str,
    operation: str,
    title: str,
    success: bool,
    observations: list[str] | None = None,
    module_data: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    capability_limitations: list[str] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Generic envelope builder for firmware operations (install, init, spoof, set)."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()

    if operation == "install":
        module_outcome = "installed" if success else "prerequisite_missing"
    elif operation == "init":
        module_outcome = "hooks_active" if success else "hooks_partial"
    else:
        module_outcome = "completed" if success else "not_loaded"

    evidence = make_evidence(
        summary=f"Firmware {operation}: {'success' if success else 'failed'}",
        confidence="high" if success else "medium",
        observations=list(observations or []),
        capability_limitations=list(capability_limitations or []),
        artifacts=list(artifacts or []),
        module_evidence=dict(module_data or {}),
    )

    execution = make_execution(
        kind="probe",
        id=f"firmware_{operation}",
        title=title,
        module="firmware",
        protocol="HCI",
        execution_status=EXECUTION_COMPLETED if success else EXECUTION_FAILED,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["firmware", operation],
        artifacts=list(artifacts or []),
        module_data={"operation": operation, **dict(module_data or {})},
    )

    return build_run_envelope(
        schema="blue_tap.firmware.result",
        module="firmware",
        target=adapter,
        adapter=adapter,
        operator_context={"operation": operation},
        summary={"operation": operation, "success": success},
        executions=[execution],
        artifacts=list(artifacts or []),
        module_data={"operation": operation, **dict(module_data or {})},
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )
