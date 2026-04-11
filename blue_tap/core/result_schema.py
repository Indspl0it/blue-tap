"""Shared result schema for module run envelopes, executions, evidence, and artifacts.

Validation helpers in this module intentionally stay permissive: they verify
container shape and required metadata without constraining target-derived
payloads in ``module_evidence`` or other raw evidence fields.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SCHEMA_VERSION = 2

EXECUTION_COMPLETED = "completed"
EXECUTION_FAILED = "failed"
EXECUTION_ERROR = "error"
EXECUTION_SKIPPED = "skipped"
EXECUTION_TIMEOUT = "timeout"


@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    kind: str
    label: str
    path: str
    description: str = ""
    created_at: str = ""
    execution_id: str = ""


@dataclass(frozen=True)
class EvidenceRecord:
    # Schema v3 consideration: split operator-facing notes (human summary,
    # triage hints) from technical/raw evidence (packets, hex, machine fields).
    # For now the record stays permissive to avoid breaking varied target-derived
    # data captured by existing modules. When splitting, introduce an
    # OperatorNotes dataclass alongside EvidenceRecord.
    summary: str
    confidence: str = "medium"
    observations: tuple[str, ...] = field(default_factory=tuple)
    packets: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    responses: tuple[str, ...] = field(default_factory=tuple)
    state_changes: tuple[str, ...] = field(default_factory=tuple)
    artifacts: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    capability_limitations: tuple[str, ...] = field(default_factory=tuple)
    module_evidence: dict[str, Any] = field(default_factory=dict)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_run_id(module: str) -> str:
    return f"{module}-{uuid4()}"


def make_artifact(
    *,
    kind: str,
    label: str,
    path: str,
    description: str = "",
    execution_id: str = "",
    created_at: str | None = None,
) -> dict[str, Any]:
    return {
        "artifact_id": str(uuid4()),
        "kind": kind,
        "label": label,
        "path": path,
        "description": description,
        "created_at": created_at or now_iso(),
        "execution_id": execution_id,
    }


def make_evidence(
    *,
    summary: str,
    confidence: str = "medium",
    observations: list[str] | tuple[str, ...] | None = None,
    packets: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    responses: list[str] | tuple[str, ...] | None = None,
    state_changes: list[str] | tuple[str, ...] | None = None,
    artifacts: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    capability_limitations: list[str] | tuple[str, ...] | None = None,
    module_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "summary": summary,
        "confidence": confidence,
        "observations": list(observations or []),
        "packets": list(packets or []),
        "responses": list(responses or []),
        "state_changes": list(state_changes or []),
        "artifacts": list(artifacts or []),
        "capability_limitations": list(capability_limitations or []),
        "module_evidence": dict(module_evidence or {}),
    }


def make_execution(
    *,
    kind: str,
    id: str,
    title: str,
    module: str,
    protocol: str,
    execution_status: str,
    module_outcome: str,
    evidence: dict[str, Any],
    severity: str | None = None,
    destructive: bool = False,
    requires_pairing: bool = False,
    started_at: str | None = None,
    completed_at: str | None = None,
    notes: list[str] | None = None,
    tags: list[str] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    module_data: dict[str, Any] | None = None,
    execution_id: str | None = None,
) -> dict[str, Any]:
    return {
        "execution_id": execution_id or str(uuid4()),
        "kind": kind,
        "id": id,
        "title": title,
        "module": module,
        "protocol": protocol,
        "execution_status": execution_status,
        "module_outcome": module_outcome,
        "severity": severity,
        "destructive": destructive,
        "requires_pairing": requires_pairing,
        "started_at": started_at or now_iso(),
        "completed_at": completed_at or now_iso(),
        "evidence": evidence,
        "notes": list(notes or []),
        "tags": list(tags or []),
        "artifacts": list(artifacts or []),
        "module_data": dict(module_data or {}),
    }


def build_run_envelope(
    *,
    schema: str,
    module: str,
    target: str,
    adapter: str,
    operator_context: dict[str, Any],
    summary: dict[str, Any],
    executions: list[dict[str, Any]],
    module_data: dict[str, Any],
    artifacts: list[dict[str, Any]] | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "schema_version": SCHEMA_VERSION,
        "module": module,
        "run_id": run_id or make_run_id(module),
        "target": target,
        "adapter": adapter,
        "started_at": started_at or now_iso(),
        "completed_at": completed_at or now_iso(),
        "operator_context": dict(operator_context),
        "summary": dict(summary),
        "executions": list(executions),
        "artifacts": list(artifacts or []),
        "module_data": dict(module_data),
    }


def envelope_module_data(envelope: dict[str, Any]) -> dict[str, Any]:
    return dict(envelope.get("module_data", {}))


def envelope_executions(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    return list(envelope.get("executions", []))


def summarize_execution_outcomes(executions: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("module_outcome", "unknown")) for item in executions)
    return dict(counts)


def looks_like_run_envelope(payload: Any) -> bool:
    """Best-effort check for a standardized run envelope candidate."""
    if not isinstance(payload, dict):
        return False
    if "schema_version" in payload or "run_id" in payload:
        return True
    if payload.get("schema") and payload.get("module") and "executions" in payload:
        return True
    return False


def validate_evidence_record(evidence: Any) -> list[str]:
    """Validate evidence container shape without restricting raw payloads."""
    errors: list[str] = []
    if not isinstance(evidence, dict):
        return ["evidence must be a dict"]

    if not evidence.get("summary"):
        errors.append("evidence.summary is required")

    list_fields = (
        "observations",
        "packets",
        "responses",
        "state_changes",
        "artifacts",
        "capability_limitations",
    )
    for field_name in list_fields:
        value = evidence.get(field_name, [])
        if value is not None and not isinstance(value, list):
            errors.append(f"evidence.{field_name} must be a list when present")

    module_evidence = evidence.get("module_evidence", {})
    if module_evidence is not None and not isinstance(module_evidence, dict):
        errors.append("evidence.module_evidence must be a dict when present")

    return errors


def validate_execution_record(execution: Any) -> list[str]:
    """Validate execution metadata container shape."""
    errors: list[str] = []
    if not isinstance(execution, dict):
        return ["execution must be a dict"]

    required = (
        "execution_id",
        "kind",
        "id",
        "title",
        "module",
        "protocol",
        "execution_status",
        "module_outcome",
        "started_at",
        "completed_at",
        "evidence",
    )
    for field_name in required:
        if field_name not in execution:
            errors.append(f"execution.{field_name} is required")

    if "evidence" in execution:
        errors.extend(validate_evidence_record(execution.get("evidence")))

    for field_name in ("notes", "tags", "artifacts"):
        value = execution.get(field_name, [])
        if value is not None and not isinstance(value, list):
            errors.append(f"execution.{field_name} must be a list when present")

    module_data = execution.get("module_data", {})
    if module_data is not None and not isinstance(module_data, dict):
        errors.append("execution.module_data must be a dict when present")

    return errors


def validate_run_envelope(envelope: Any) -> list[str]:
    """Validate run envelope metadata while allowing flexible module payloads."""
    errors: list[str] = []
    if not isinstance(envelope, dict):
        return ["envelope must be a dict"]

    required = (
        "schema",
        "schema_version",
        "module",
        "run_id",
        "target",
        "adapter",
        "started_at",
        "completed_at",
        "operator_context",
        "summary",
        "executions",
        "module_data",
    )
    for field_name in required:
        if field_name not in envelope:
            errors.append(f"envelope.{field_name} is required")

    for dict_field in ("operator_context", "summary", "module_data"):
        value = envelope.get(dict_field, {})
        if value is not None and not isinstance(value, dict):
            errors.append(f"envelope.{dict_field} must be a dict when present")

    executions = envelope.get("executions", [])
    if executions is not None and not isinstance(executions, list):
        errors.append("envelope.executions must be a list when present")
    elif isinstance(executions, list):
        for idx, execution in enumerate(executions):
            for err in validate_execution_record(execution):
                errors.append(f"executions[{idx}]: {err}")

    artifacts = envelope.get("artifacts", [])
    if artifacts is not None and not isinstance(artifacts, list):
        errors.append("envelope.artifacts must be a list when present")

    return errors
