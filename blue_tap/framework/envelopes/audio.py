"""Shared audio/media result envelope helpers."""

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


def build_audio_result(
    *,
    target: str,
    adapter: str,
    operation: str,
    title: str,
    protocol: str = "Audio",
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
        module="audio",
        protocol=protocol,
        execution_status=EXECUTION_COMPLETED,
        module_outcome=module_outcome,
        evidence=evidence,
        started_at=started,
        completed_at=finished,
        artifacts=list(artifacts or []),
        tags=["audio", operation],
        module_data=dict(module_data),
    )
    return build_run_envelope(
        schema="blue_tap.audio.result",
        module="audio",
        target=target,
        adapter=adapter,
        operator_context={"operation": operation, "protocol": protocol},
        summary={"operation": operation, "protocol": protocol, **dict(summary_data or {})},
        executions=[execution],
        artifacts=list(artifacts or []),
        module_data={"operation": operation, "protocol": protocol, **dict(module_data)},
        started_at=started,
        completed_at=finished,
    )


def artifact_if_file(path: str, *, kind: str, label: str, description: str) -> dict[str, Any] | None:
    import os

    if not path or not os.path.exists(path):
        return None
    return make_artifact(kind=kind, label=label, path=path, description=description)
