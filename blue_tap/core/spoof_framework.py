"""Shared spoof result envelope helpers."""

from __future__ import annotations

from typing import Any

from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    build_run_envelope,
    make_artifact,
    make_evidence,
    make_execution,
    make_run_id,
    now_iso,
)

SPOOF_MODULE_OUTCOMES = (
    "spoofed",
    "rejected",
    "restored",
    "method_unavailable",
    "not_applicable",
)


def make_spoof_run_id() -> str:
    return make_run_id("spoof")


def build_spoof_result(
    *,
    target: str,
    adapter: str,
    operation: str,
    result: dict[str, Any],
    operator_context: dict[str, Any] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    success_flag = bool(result.get("success", False))

    if operation == "restore":
        module_outcome = "restored" if success_flag else "rejected"
    elif success_flag:
        module_outcome = "spoofed"
    elif result.get("error") and "not found" in result.get("error", ""):
        module_outcome = "method_unavailable"
    else:
        module_outcome = "rejected"

    execution_status = EXECUTION_COMPLETED if success_flag else EXECUTION_FAILED

    observations = []
    if result.get("original_mac"):
        observations.append(f"Original MAC: {result['original_mac']}")
    if result.get("target_mac"):
        observations.append(f"Target MAC: {result['target_mac']}")
    if result.get("method_used"):
        observations.append(f"Method: {result['method_used']}")
    elif result.get("method"):
        observations.append(f"Method: {result['method']}")
    if result.get("methods_tried"):
        observations.append(f"Methods tried: {', '.join(result['methods_tried'])}")
    if result.get("verified"):
        observations.append("Verification: MAC change confirmed")
    elif success_flag:
        observations.append("Verification: not performed")
    if result.get("error"):
        observations.append(f"Error: {result['error']}")

    # Clone-specific observations
    if result.get("mac_spoofed") is not None:
        observations.append(f"MAC spoofed: {result['mac_spoofed']}")
    if result.get("name_set") is not None:
        observations.append(f"Name set: {result['name_set']}")
    if result.get("class_set") is not None:
        observations.append(f"Device class set: {result['class_set']}")

    evidence = make_evidence(
        summary=_build_summary(operation, result),
        confidence="high" if result.get("verified") else "medium",
        observations=observations,
        module_evidence=result,
    )

    execution = make_execution(
        kind="probe",
        id=f"spoof_{operation}",
        title=f"Spoof: {operation}",
        module="spoof",
        protocol="HCI",
        execution_status=execution_status,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["spoof", operation],
        module_data=result,
    )

    return build_run_envelope(
        schema="blue_tap.spoof.result",
        module="spoof",
        target=target,
        adapter=adapter,
        operator_context={"operation": operation, **dict(operator_context or {})},
        summary={
            "operation": operation,
            "success": success_flag,
            "method": result.get("method_used") or result.get("method", ""),
        },
        executions=[execution],
        artifacts=[],
        module_data={"operation": operation, **result},
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def _build_summary(operation: str, result: dict[str, Any]) -> str:
    success_flag = result.get("success", False)
    if operation == "mac":
        method = result.get("method_used", "unknown")
        if success_flag:
            return f"MAC spoofed to {result.get('target_mac', '?')} via {method}"
        return f"MAC spoof failed (tried: {', '.join(result.get('methods_tried', ['?']))})"
    elif operation == "clone":
        parts = []
        if result.get("mac_spoofed"):
            parts.append("MAC")
        if result.get("name_set"):
            parts.append("name")
        if result.get("class_set"):
            parts.append("class")
        if parts:
            return f"Identity cloned ({', '.join(parts)} set) as {result.get('target_name', '?')}"
        return "Identity clone failed"
    elif operation == "restore":
        if success_flag:
            return f"Original MAC restored: {result.get('restored_mac', '?')}"
        return "MAC restore failed"
    return f"Spoof {operation}: {'success' if success_flag else 'failed'}"
