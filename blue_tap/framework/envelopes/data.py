"""Shared data-exfiltration result envelope helpers."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    build_run_envelope,
    make_artifact,
    make_evidence,
    make_execution,
    now_iso,
)


def build_data_result(
    *,
    target: str,
    adapter: str,
    family: str,
    operation: str,
    title: str,
    module_data: dict[str, Any],
    summary_data: dict[str, Any] | None = None,
    observations: list[str] | None = None,
    capability_limitations: list[str] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    module_outcome: str = "completed",
) -> dict[str, Any]:
    started = started_at or now_iso()
    finished = completed_at or now_iso()
    evidence = make_evidence(
        summary=title,
        confidence="high",
        observations=list(observations or []),
        capability_limitations=list(capability_limitations or []),
        artifacts=list(artifacts or []),
        module_evidence=dict(module_data),
    )
    execution = make_execution(
        kind="operation",
        id=operation,
        title=title,
        module="data",
        protocol=family.upper(),
        execution_status=EXECUTION_COMPLETED,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        artifacts=list(artifacts or []),
        tags=["data", family, operation],
        module_data=dict(module_data),
    )
    return build_run_envelope(
        schema="blue_tap.data.result",
        module="data",
        target=target,
        adapter=adapter,
        operator_context={"family": family, "operation": operation},
        summary={"family": family, "operation": operation, **dict(summary_data or {})},
        executions=[execution],
        artifacts=list(artifacts or []),
        module_data={"family": family, "operation": operation, **dict(module_data)},
        started_at=started,
        completed_at=finished,
    )


def artifact_if_path(path: str, *, kind: str, label: str, description: str) -> dict[str, Any] | None:
    import os

    if not path or not os.path.exists(path):
        return None
    return make_artifact(kind=kind, label=label, path=path, description=description)
