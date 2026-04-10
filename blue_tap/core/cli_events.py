"""Shared CLI event emission helpers for long-running module execution."""

from __future__ import annotations

from typing import Any

from blue_tap.core.result_schema import now_iso
from blue_tap.utils.output import error, info, success, verbose, warning

# TODO: Normalize event taxonomy and severity across modules once report
# consumers are ready for a smaller canonical event set. Keep emission
# permissive for now so varied module workflows and target responses are not
# discarded or over-normalized.


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
        if event_type in {"run_error", "execution_error"}:
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
