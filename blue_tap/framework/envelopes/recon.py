"""Shared reconnaissance result envelope helpers."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    make_evidence,
    make_execution,
    build_run_envelope,
    now_iso,
)


def summarize_recon_entries(entries: list[dict], operation: str) -> dict[str, Any]:
    return {
        "operation": operation,
        "entry_count": len(entries),
    }


def build_recon_result(
    *,
    target: str,
    adapter: str,
    operation: str,
    title: str,
    protocol: str,
    entries: list[dict],
    module_id: str,
    fingerprint: dict[str, Any] | None = None,
    module_data_extra: dict[str, Any] | None = None,
    operator_context: dict[str, Any] | None = None,
    evidence_summary: str | None = None,
    observations: list[str] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    execution_artifacts: list[dict[str, Any]] | None = None,
    module_outcome: str = "observed",
    execution_status: str = EXECUTION_COMPLETED,
    confidence: str | None = None,
    started_at: str,
    completed_at: str | None = None,
    execution_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    finished = completed_at or now_iso()
    extra = dict(module_data_extra or {})
    if evidence_summary:
        resolved_evidence_summary = evidence_summary
    elif entries:
        resolved_evidence_summary = (
            f"{len(entries)} result entr{'y' if len(entries) == 1 else 'ies'} collected for {operation}"
        )
    elif fingerprint:
        resolved_evidence_summary = f"{title} completed with fingerprint data"
    elif "capture_result" in extra:
        capture_result = extra.get("capture_result", {})
        success_flag = capture_result.get("success")
        resolved_evidence_summary = f"{title} completed ({'success' if success_flag else 'unsuccessful'})"
    elif "ssp_supported" in extra:
        resolved_evidence_summary = f"{title} completed"
    elif "pairing_probe" in extra:
        resolved_evidence_summary = f"{title} completed"
    elif "capture_started" in extra or "capture_stopped" in extra:
        resolved_evidence_summary = f"{title} completed"
    else:
        resolved_evidence_summary = f"{title} completed"
    execution = build_recon_execution(
        operation=operation,
        title=title,
        protocol=protocol,
        entries=entries,
        module_id=module_id,
        fingerprint=fingerprint,
        module_data_extra=extra,
        observations=observations,
        evidence_summary=resolved_evidence_summary,
        artifacts=artifacts,
        execution_artifacts=execution_artifacts,
        module_outcome=module_outcome,
        execution_status=execution_status,
        confidence=confidence,
        started_at=started_at,
        completed_at=finished,
        execution_id=execution_id,
    )
    return build_run_envelope(
        schema="blue_tap.recon.result",
        module="reconnaissance",
        module_id=module_id,
        target=target,
        adapter=adapter,
        operator_context={"operation": operation, **dict(operator_context or {})},
        summary={
            **summarize_recon_entries(entries, operation),
            **({"has_fingerprint": True} if fingerprint else {}),
        },
        executions=[execution],
        artifacts=artifacts or [],
        module_data={
            "operation": operation,
            "entries": entries,
            **({"fingerprint": fingerprint} if fingerprint else {}),
            **extra,
        },
        started_at=started_at,
        completed_at=finished,
        run_id=run_id,
    )


def build_recon_execution(
    *,
    operation: str,
    title: str,
    protocol: str,
    entries: list[dict],
    module_id: str,
    fingerprint: dict[str, Any] | None = None,
    module_data_extra: dict[str, Any] | None = None,
    observations: list[str] | None = None,
    evidence_summary: str | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    execution_artifacts: list[dict[str, Any]] | None = None,
    module_outcome: str = "observed",
    execution_status: str = EXECUTION_COMPLETED,
    confidence: str | None = None,
    started_at: str,
    completed_at: str | None = None,
    execution_id: str | None = None,
) -> dict[str, Any]:
    finished = completed_at or now_iso()
    extra = dict(module_data_extra or {})
    evidence = make_evidence(
        summary=evidence_summary or f"{title} completed",
        confidence=confidence or _recon_confidence(module_outcome, entries, fingerprint, extra),
        observations=observations or [
            f"operation={operation}",
            f"entry_count={len(entries)}",
            *([f"fingerprint_name={fingerprint.get('name', '')}"] if fingerprint else []),
        ],
        artifacts=execution_artifacts or artifacts or [],
        module_evidence={"operation": operation, **({"fingerprint": True} if fingerprint else {})},
    )
    return make_execution(
        kind="collector",
        id=operation,
        title=title,
        module="reconnaissance",
        module_id=module_id,
        protocol=protocol,
        execution_status=execution_status,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started_at,
        completed_at=finished,
        execution_id=execution_id,
        tags=["recon", operation],
        artifacts=execution_artifacts or artifacts or [],
        module_data={
            "entry_count": len(entries),
            "operation": operation,
            **({"fingerprint": fingerprint} if fingerprint else {}),
            **extra,
        },
    )


def _recon_confidence(
    module_outcome: str,
    entries: list[dict],
    fingerprint: dict[str, Any] | None,
    module_data_extra: dict[str, Any],
) -> str:
    if module_outcome in {"unsupported_transport", "collector_unavailable", "prerequisite_missing"}:
        return "high"
    if entries or fingerprint:
        return "medium"
    if module_data_extra.get("gatt_result", {}).get("error"):
        return "low"
    return "low"
