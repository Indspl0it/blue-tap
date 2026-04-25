"""Shared fuzz result envelope helpers."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    build_run_envelope,
    make_artifact,
    make_evidence,
    make_execution,
    make_run_id,
    now_iso,
)

# Canonical module outcomes for fuzz operations.
FUZZ_MODULE_OUTCOMES = (
    "completed",          # Fuzz run finished normally, no crashes
    "crash_detected",     # One or more crashes found
    "degraded",           # Target showed degradation (rising latency, partial failures)
    "aborted",            # Run stopped early (operator interrupt, target permanently down)
    "pairing_required",   # Protocol requires pairing that wasn't established
    "not_applicable",     # Protocol not supported on target
)


def make_fuzz_run_id() -> str:
    """Generate a stable run ID for a fuzz operation."""
    return make_run_id("fuzz")


def _iso_from_epoch(ts: float | None) -> str:
    if not ts:
        return now_iso()
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _existing_artifact(
    *,
    kind: str,
    label: str,
    path: str | None,
    description: str,
    execution_id: str = "",
) -> dict[str, Any] | None:
    if not path:
        return None
    if not os.path.exists(path):
        return None
    return make_artifact(
        kind=kind,
        label=label,
        path=path,
        description=description,
        execution_id=execution_id,
    )


def _count_by_key(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts


def build_fuzz_result(
    *,
    target: str,
    adapter: str,
    command: str,
    protocol: str,
    module_id: str,
    result: dict[str, Any],
    operator_context: dict[str, Any] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    started = started_at or result.get("started_at") or now_iso()
    finished = completed_at or result.get("completed_at") or now_iso()
    sent = int(result.get("sent", 0) or 0)
    crashes = int(result.get("crashes", 0) or 0)
    errors = int(result.get("errors", 0) or 0)
    elapsed = float(result.get("elapsed", 0.0) or 0.0)
    total_cases = int(result.get("total_cases", sent) or sent)
    crash_db_path = str(result.get("crash_db_path", "") or "")

    if crashes > 0:
        execution_status = EXECUTION_COMPLETED
        module_outcome = "crash_detected"
    elif sent > 0:
        execution_status = EXECUTION_COMPLETED
        module_outcome = "degraded" if errors > 0 else "completed"
    else:
        execution_status = EXECUTION_FAILED
        module_outcome = "not_applicable"

    artifacts = []
    if crash_db_path:
        artifacts.append(
            make_artifact(
                kind="crash_db",
                label="Crash database",
                path=crash_db_path,
                description=f"Crash database for {command}",
            )
        )

    evidence = make_evidence(
        summary=(
            f"{command} sent {sent}/{total_cases} case(s), "
            f"detected {crashes} crash(es), and recorded {errors} error(s)"
        ),
        confidence="medium",
        observations=[
            f"command={command}",
            f"protocol={protocol}",
            f"cases_sent={sent}",
            f"cases_generated={total_cases}",
            f"crashes={crashes}",
            f"errors={errors}",
            f"elapsed_seconds={elapsed:.3f}",
        ],
        artifacts=artifacts,
        module_evidence={
            "command": command,
            "protocol": protocol,
            "metrics": {
                "sent": sent,
                "crashes": crashes,
                "errors": errors,
                "elapsed_seconds": elapsed,
                "total_cases": total_cases,
            },
        },
    )

    execution = make_execution(
        kind="probe",
        id=command,
        title=f"Fuzz command: {command}",
        module="fuzzing",
        module_id=module_id,
        protocol=protocol,
        execution_status=execution_status,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["fuzz", protocol, command],
        artifacts=artifacts,
        module_data={
            "command": command,
            "protocol": protocol,
            "metrics": {
                "sent": sent,
                "crashes": crashes,
                "errors": errors,
                "elapsed_seconds": elapsed,
                "total_cases": total_cases,
            },
            "crash_db_path": crash_db_path,
        },
    )

    return build_run_envelope(
        schema="blue_tap.fuzz.result",
        module="fuzzing",
        module_id=module_id,
        target=target,
        adapter=adapter,
        operator_context={"run_type": "single_protocol_run", "command": command, **dict(operator_context or {})},
        summary={
            "run_type": "single_protocol_run",
            "command": command,
            "protocol": protocol,
            "sent": sent,
            "crashes": crashes,
            "errors": errors,
            "elapsed_seconds": elapsed,
            "total_cases": total_cases,
        },
        executions=[execution],
        artifacts=artifacts,
        module_data={
            "run_type": "single_protocol_run",
            "command": command,
            "protocol": protocol,
            "result": {
                "sent": sent,
                "crashes": crashes,
                "errors": errors,
                "elapsed": elapsed,
                "total_cases": total_cases,
                "crash_db_path": crash_db_path,
            },
        },
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def campaign_started_at_from_stats(start_time: float | None) -> str:
    return _iso_from_epoch(start_time)


def build_fuzz_protocol_execution(
    *,
    protocol: str,
    packets_sent: int,
    crashes: int,
    errors: int,
    module_id: str,
    crash_types: dict[str, int] | None = None,
    anomalies: int = 0,
    states_discovered: int = 0,
    health_events: int = 0,
    started_at: str | None = None,
    completed_at: str | None = None,
    state_coverage: dict[str, Any] | None = None,
    field_weights: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ExecutionRecord for a single protocol within a campaign."""
    started = started_at or now_iso()
    finished = completed_at or now_iso()

    if crashes > 0:
        module_outcome = "crash_detected"
        execution_status = EXECUTION_COMPLETED
    elif errors > 0 and packets_sent == 0:
        # Transport failure — nothing was sent
        module_outcome = "not_applicable"
        execution_status = EXECUTION_FAILED
    elif errors > 0:
        # Some packets landed but others errored — degraded, not clean
        module_outcome = "degraded"
        execution_status = EXECUTION_COMPLETED
    else:
        # Clean run, no crashes observed
        module_outcome = "completed"
        execution_status = EXECUTION_COMPLETED

    observations = [
        f"Sent {packets_sent:,} packets to {protocol}",
        f"Detected {crashes} crash(es)" if crashes else "No crashes detected",
    ]
    if anomalies:
        observations.append(f"Recorded {anomalies} anomalies")
    if states_discovered:
        observations.append(f"Discovered {states_discovered} unique protocol states")
    if crash_types:
        for ct, count in sorted(crash_types.items(), key=lambda x: -x[1]):
            observations.append(f"Crash type {ct}: {count}")

    module_evidence: dict[str, Any] = {
        "packets_sent": packets_sent,
        "crashes": crashes,
        "errors": errors,
        "anomalies": anomalies,
        "states_discovered": states_discovered,
        "crash_types": dict(crash_types or {}),
    }
    if state_coverage:
        module_evidence["state_coverage"] = state_coverage
    if field_weights:
        module_evidence["field_weights"] = field_weights

    evidence = make_evidence(
        summary=(
            f"Fuzzed {protocol}: {packets_sent:,} packets, "
            f"{crashes} crash(es), {anomalies} anomalies"
        ),
        confidence="high" if packets_sent > 100 else "medium",
        observations=observations,
        module_evidence=module_evidence,
    )

    return make_execution(
        kind="probe",
        id=f"fuzz_{protocol}",
        title=f"Fuzz protocol: {protocol}",
        module="fuzzing",
        module_id=module_id,
        protocol=protocol,
        execution_status=execution_status,
        module_outcome=module_outcome,
        severity="high" if crashes > 0 else None,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        tags=["fuzz", protocol, "campaign"],
        module_data={
            "protocol": protocol,
            "packets_sent": packets_sent,
            "crashes": crashes,
            "errors": errors,
            "anomalies": anomalies,
            "states_discovered": states_discovered,
            "crash_types": dict(crash_types or {}),
        },
    )


def build_fuzz_campaign_result(
    *,
    target: str,
    adapter: str,
    campaign_summary: dict[str, Any],
    crashes: list[dict[str, Any]],
    session_fuzz_dir: str,
    module_id: str,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
    protocol_executions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    protocol_breakdown = dict(campaign_summary.get("protocol_breakdown", {}) or {})
    crash_count = len(crashes)
    execution_id = "campaign"
    artifacts = [
        item
        for item in (
            _existing_artifact(
                kind="json",
                label="Campaign Stats",
                path=os.path.join(session_fuzz_dir, "campaign_stats.json"),
                description="Serialized fuzz campaign statistics.",
                execution_id=execution_id,
            ),
            _existing_artifact(
                kind="json",
                label="Campaign State",
                path=os.path.join(session_fuzz_dir, "campaign_state.json"),
                description="Resumable fuzz campaign state snapshot.",
                execution_id=execution_id,
            ),
            _existing_artifact(
                kind="database",
                label="Crash Database",
                path=campaign_summary.get("crash_db_path"),
                description="SQLite database of recorded crashes.",
                execution_id=execution_id,
            ),
            _existing_artifact(
                kind="directory",
                label="Corpus Directory",
                path=campaign_summary.get("corpus_dir"),
                description="Generated fuzzing corpus directory.",
                execution_id=execution_id,
            ),
        )
        if item is not None
    ]
    evidence = make_evidence(
        summary=(
            f"Fuzz campaign completed: packets_sent={campaign_summary.get('packets_sent', 0)}, "
            f"crashes={campaign_summary.get('crashes', 0)}, protocols={len(protocol_breakdown)}"
        ),
        confidence="high",
        observations=[
            f"strategy={campaign_summary.get('strategy', '')}",
            f"runtime_seconds={campaign_summary.get('runtime_seconds', 0)}",
            f"iterations={campaign_summary.get('iterations', 0)}",
            f"packets_sent={campaign_summary.get('packets_sent', 0)}",
            f"crashes={campaign_summary.get('crashes', 0)}",
        ],
        artifacts=artifacts,
        module_evidence={
            "protocol_breakdown": protocol_breakdown,
            "crash_summary": {
                "count": crash_count,
                "severity_counts": _count_by_key(crashes, "severity"),
                "protocol_counts": _count_by_key(crashes, "protocol"),
            },
            "state_coverage": campaign_summary.get("state_coverage", {}),
            "field_weights": campaign_summary.get("field_weights", {}),
            "health_monitor": campaign_summary.get("health_monitor", {}),
        },
    )
    execution = make_execution(
        kind="phase",
        id="campaign",
        title="Fuzz Campaign",
        module="fuzzing",
        module_id=module_id,
        protocol="multi",
        execution_status=EXECUTION_COMPLETED,
        module_outcome="crash_detected" if crash_count else "completed",
        severity="high" if crash_count else "info",
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        artifacts=artifacts,
        tags=["fuzz", "campaign"],
        module_data={
            "run_type": "campaign",
            "protocols": list(campaign_summary.get("protocols", []) or []),
            "strategy": campaign_summary.get("strategy", ""),
            "session_fuzz_dir": session_fuzz_dir,
            "packets_sent": campaign_summary.get("packets_sent", 0),
            "crashes": crash_count,
        },
        execution_id=execution_id,
    )
    return build_run_envelope(
        schema="blue_tap.fuzz.result",
        module="fuzzing",
        module_id=module_id,
        target=target,
        adapter=adapter,
        operator_context={
            "run_type": "campaign",
            "strategy": campaign_summary.get("strategy", ""),
            "protocols": list(campaign_summary.get("protocols", []) or []),
        },
        summary={
            "run_type": "campaign",
            "protocols": list(campaign_summary.get("protocols", []) or []),
            "packets_sent": campaign_summary.get("packets_sent", 0),
            "crashes": crash_count,
            "errors": campaign_summary.get("errors", 0),
            "runtime_seconds": campaign_summary.get("runtime_seconds", 0),
        },
        executions=[execution] + list(protocol_executions or []),
        artifacts=artifacts,
        module_data={
            "run_type": "campaign",
            "campaign_stats": campaign_summary,
            "crashes": crashes,
            "session_fuzz_dir": session_fuzz_dir,
            "artifacts_index": artifacts,
        },
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )


def build_fuzz_operation_result(
    *,
    target: str,
    adapter: str,
    operation: str,
    title: str,
    module_id: str,
    protocol: str = "",
    module_outcome: str = "completed",
    summary_data: dict[str, Any] | None = None,
    observations: list[str] | None = None,
    module_data: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    evidence = make_evidence(
        summary=title,
        confidence="high",
        observations=list(observations or []),
        artifacts=list(artifacts or []),
        module_evidence=dict(module_data or {}),
    )
    execution = make_execution(
        kind="probe",
        id=operation,
        title=title,
        module="fuzzing",
        module_id=module_id,
        protocol=protocol,
        execution_status=EXECUTION_COMPLETED,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        artifacts=list(artifacts or []),
        tags=["fuzz", operation],
        module_data={
            "run_type": "operation",
            "operation": operation,
            **dict(module_data or {}),
        },
    )
    return build_run_envelope(
        schema="blue_tap.fuzz.result",
        module="fuzzing",
        module_id=module_id,
        target=target,
        adapter=adapter,
        operator_context={"run_type": "operation", "operation": operation},
        summary={"run_type": "operation", **dict(summary_data or {})},
        executions=[execution],
        artifacts=list(artifacts or []),
        module_data={
            "run_type": "operation",
            "operation": operation,
            **dict(module_data or {}),
        },
        started_at=started,
        completed_at=finished,
        run_id=run_id,
    )
