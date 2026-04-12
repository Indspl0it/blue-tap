"""Shared auto-mode result envelope helpers."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    EXECUTION_SKIPPED,
    build_run_envelope,
    make_evidence,
    make_execution,
    make_run_id,
    now_iso,
)

AUTO_MODULE_OUTCOMES = (
    "complete",
    "partial",
    "aborted",
)

_PHASE_TITLES = {
    "discovery": "Device Discovery",
    "fingerprint": "Fingerprinting",
    "recon": "Reconnaissance",
    "vuln_assessment": "Vulnerability Assessment",
    "pairing_attacks": "Pairing Attacks",
    "exploitation": "Exploitation",
    "fuzzing": "Protocol Fuzzing",
    "dos_testing": "DoS Testing",
    "report": "Report Generation",
}

_PHASE_PROTOCOLS = {
    "discovery": "Classic",
    "fingerprint": "multi",
    "recon": "multi",
    "vuln_assessment": "multi",
    "pairing_attacks": "Classic",
    "exploitation": "multi",
    "fuzzing": "multi",
    "dos_testing": "multi",
    "report": "Posture",
}


def make_auto_run_id() -> str:
    return make_run_id("auto")


def build_auto_phase_execution(
    *,
    phase_name: str,
    phase_result: dict[str, Any],
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Build an ExecutionRecord from a single auto phase result."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    status = str(phase_result.get("status", "unknown"))

    if status in ("success", "complete"):
        execution_status = EXECUTION_COMPLETED
        module_outcome = "complete"
    elif status == "skipped":
        execution_status = EXECUTION_SKIPPED
        module_outcome = "partial"
    else:
        execution_status = EXECUTION_FAILED
        module_outcome = "partial"

    observations = []
    elapsed = phase_result.get("_elapsed_seconds")
    if elapsed is not None:
        observations.append(f"Elapsed: {elapsed:.1f}s")
    if status == "skipped":
        reason = phase_result.get("reason", "not specified")
        observations.append(f"Skipped: {reason}")
    if status == "failed":
        err = phase_result.get("error", "unknown error")
        observations.append(f"Error: {err}")

    # Extract phase-specific metrics
    for key in ("findings", "vulnscan", "sdp_services", "rfcomm_open",
                "phone_address", "packets_sent", "crashes"):
        val = phase_result.get(key)
        if val is not None:
            observations.append(f"{key}={val}")

    evidence = make_evidence(
        summary=f"{_PHASE_TITLES.get(phase_name, phase_name)}: {status}",
        confidence="high" if status in ("success", "complete") else "medium",
        observations=observations,
        module_evidence={k: v for k, v in phase_result.items() if not k.startswith("_")},
    )

    return make_execution(
        kind="phase",
        id=f"auto_{phase_name}",
        title=_PHASE_TITLES.get(phase_name, phase_name),
        module="auto",
        protocol=_PHASE_PROTOCOLS.get(phase_name, "multi"),
        execution_status=execution_status,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["auto", phase_name],
        module_data=phase_result,
    )


def build_auto_result(
    *,
    target: str,
    adapter: str,
    results: dict[str, Any],
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Build parent RunEnvelope for auto mode with per-phase executions."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    phases = results.get("phases", {})

    executions = []
    for phase_name, phase_result in phases.items():
        if not isinstance(phase_result, dict):
            continue
        executions.append(build_auto_phase_execution(
            phase_name=phase_name,
            phase_result=phase_result,
        ))

    passed = sum(1 for e in executions if e.get("execution_status") == EXECUTION_COMPLETED)
    failed = sum(1 for e in executions if e.get("execution_status") == EXECUTION_FAILED)
    skipped = sum(1 for e in executions if e.get("execution_status") == EXECUTION_SKIPPED)
    total_time = results.get("total_time_seconds", 0)

    overall_status = results.get("status", "unknown")
    if overall_status == "complete" and failed == 0:
        module_outcome = "complete"
    elif passed > 0:
        module_outcome = "partial"
    else:
        module_outcome = "aborted"

    return build_run_envelope(
        schema="blue_tap.auto.result",
        module="auto",
        target=target,
        adapter=adapter,
        operator_context={
            "methodology": "9-phase-auto",
            "skip_flags": {k: v for k, v in results.items() if k.startswith("skip_")},
        },
        summary={
            "status": overall_status,
            "phases_passed": passed,
            "phases_failed": failed,
            "phases_skipped": skipped,
            "total_time_seconds": total_time,
        },
        executions=executions,
        artifacts=[],
        module_data=results,
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )
