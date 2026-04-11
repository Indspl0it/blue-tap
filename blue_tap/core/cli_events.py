"""Shared CLI event emission helpers for long-running module execution.

Canonical event types (all modules must use only these):

    run_started            — emitted once when a run begins
    phase_started          — emitted at the start of a named phase within a run
    execution_started      — emitted when a single execution/check begins
    execution_result       — emitted when an execution completes with a result
    execution_skipped      — emitted when an execution is intentionally not run
    pairing_required       — emitted when the target requires pairing to proceed
    recovery_wait_started  — emitted when waiting for a target to recover
    recovery_wait_progress — emitted during an in-progress recovery wait
    recovery_wait_finished — emitted when recovery wait concludes
    artifact_saved         — emitted when an artifact (pcap, log, JSON) is saved
    run_completed          — emitted once when a run finishes successfully
    run_aborted            — emitted when a run is intentionally stopped early
    run_error              — emitted on unrecoverable module/tool/runtime error

Non-canonical event_type strings trigger a logger.warning at runtime.
"""

from __future__ import annotations

import logging
from typing import Any

from blue_tap.core.result_schema import now_iso
from blue_tap.utils.output import error, info, success, verbose, warning

logger = logging.getLogger(__name__)

CANONICAL_EVENT_TYPES: frozenset[str] = frozenset({
    "run_started",
    "phase_started",
    "execution_started",
    "execution_result",
    "execution_skipped",
    "pairing_required",
    "recovery_wait_started",
    "recovery_wait_progress",
    "recovery_wait_finished",
    "artifact_saved",
    "run_completed",
    "run_aborted",
    "run_error",
})


def emit_cli_event(
    *,
    event_type: str,
    module: str,
    run_id: str,
    message: str,
    target: str = "",
    adapter: str = "",
    execution_id: str = "",
    details: dict[str, Any] | None = None,
    echo: bool = True,
) -> dict[str, Any]:
    if event_type not in CANONICAL_EVENT_TYPES:
        logger.warning(
            "Non-canonical CLI event type %r emitted by module %r (run_id=%s). "
            "Use one of: %s",
            event_type,
            module,
            run_id,
            ", ".join(sorted(CANONICAL_EVENT_TYPES)),
        )
    event = {
        "event_type": event_type,
        "module": module,
        "run_id": run_id,
        "execution_id": execution_id,
        "target": target,
        "adapter": adapter,
        "timestamp": now_iso(),
        "message": message,
        "details": dict(details or {}),
    }
    if echo:
        if event_type == "run_error":
            error(message)
        elif event_type in {"execution_skipped", "pairing_required", "recovery_wait_started", "recovery_wait_progress", "run_aborted"}:
            warning(message)
        elif event_type in {"execution_result", "run_completed", "artifact_saved"}:
            success(message)
        elif event_type in {"phase_started", "execution_started", "run_started"}:
            info(message)
        else:
            verbose(message)
    return event
