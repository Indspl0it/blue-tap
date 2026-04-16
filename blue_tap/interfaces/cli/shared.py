"""Shared CLI helpers for command normalization, recon events, and JSON output."""

from __future__ import annotations

import json

import rich_click as click

from blue_tap.framework.contracts.result_schema import make_run_id
from blue_tap.framework.runtime.cli_events import emit_cli_event


def _normalize_command_path(ctx: click.Context) -> str:
    """Normalize Click command path into blue-tap subcommand form."""
    parts = ctx.command_path.split()
    if "blue-tap" in parts:
        return " ".join(parts[parts.index("blue-tap"):])

    names = []
    node = ctx
    while node is not None:
        cmd = getattr(node, "command", None)
        name = getattr(cmd, "name", "")
        if name and name != "main":
            names.append(name)
        node = node.parent
    names.reverse()
    if not names:
        return "blue-tap"
    return f"blue-tap {' '.join(names)}"


def _extract_target_param(params: dict) -> str:
    """Best-effort target extraction for session metadata."""
    candidate_keys = (
        "address",
        "ivi_address",
        "phone_address",
        "target",
        "target_mac",
        "ivi_mac",
        "mac",
        "remote_mac",
    )
    for key in candidate_keys:
        value = params.get(key, "")
        if isinstance(value, str) and value:
            return value
    return ""


def _infer_category(command_path: str) -> str:
    """Infer a report category from click command path."""
    parts = command_path.split()
    if len(parts) < 2:
        return "general"
    root = parts[1]
    _CATEGORY_MAP = {
        "discover": "scan",
        "recon": "recon",
        "vulnscan": "vuln",
        "exploit": "attack",
        "dos": "dos",
        "extract": "data",
        "fuzz": "fuzz",
        "fleet": "vuln",
        "auto": "attack",
        "spoof": "attack",
        # Legacy command names (backward compat for session logs)
        "scan": "scan",
        "pbap": "data",
        "map": "data",
        "at": "data",
        "opp": "data",
        "hfp": "audio",
        "audio": "audio",
        "hijack": "attack",
        "bias": "attack",
        "bluffs": "attack",
        "knob": "attack",
        "encryption-downgrade": "attack",
        "ssp-downgrade": "attack",
        "avrcp": "attack",
    }
    return _CATEGORY_MAP.get(root, "general")


def _recon_cli_context(
    operation: str,
    target: str = "",
    adapter: str = "",
    details: dict | None = None,
) -> dict:
    return {
        "run_id": make_run_id("recon"),
        "events": [],
        "operation": operation,
        "target": target,
        "adapter": adapter,
        "details": dict(details or {}),
    }


def _recon_emit(
    ctx: dict,
    *,
    event_type: str,
    message: str,
    execution_id: str = "",
    details: dict | None = None,
) -> dict:
    event = emit_cli_event(
        event_type=event_type,
        module="recon",
        run_id=ctx["run_id"],
        target=ctx.get("target", ""),
        adapter=ctx.get("adapter", ""),
        execution_id=execution_id,
        message=message,
        details=details or {},
        echo=False,
    )
    ctx["events"].append(event)
    return event


def _recon_module_data(extra: dict | None, ctx: dict) -> dict:
    data = dict(extra or {})
    data["cli_events"] = ctx["events"]
    data["run_id"] = ctx["run_id"]
    return data


def _recon_start(ctx: dict, *, execution_id: str, message: str, details: dict | None = None) -> None:
    _recon_emit(ctx, event_type="run_started", execution_id=execution_id, message=message, details=details)
    _recon_emit(ctx, event_type="execution_started", execution_id=execution_id, message=message, details=details)


def _recon_result(ctx: dict, *, execution_id: str, message: str, details: dict | None = None) -> None:
    _recon_emit(ctx, event_type="execution_result", execution_id=execution_id, message=message, details=details)
    _recon_emit(ctx, event_type="run_completed", execution_id=execution_id, message=message, details=details)


def _recon_skip(ctx: dict, *, execution_id: str, message: str, details: dict | None = None) -> None:
    _recon_emit(ctx, event_type="execution_skipped", execution_id=execution_id, message=message, details=details)
    _recon_emit(ctx, event_type="run_aborted", execution_id=execution_id, message=message, details=details)


def _recon_error(ctx: dict, *, execution_id: str, message: str, details: dict | None = None) -> None:
    _recon_emit(ctx, event_type="run_error", execution_id=execution_id, message=message, details=details)


def _recon_artifact(ctx: dict, *, execution_id: str, message: str, details: dict | None = None) -> None:
    _recon_emit(ctx, event_type="artifact_saved", execution_id=execution_id, message=message, details=details)


def _recon_finalize_payload(payload: dict, ctx: dict) -> dict:
    module_data = payload.setdefault("module_data", {})
    module_data["cli_events"] = list(ctx["events"])
    module_data["run_id"] = ctx["run_id"]
    return payload


def _recon_persist(command: str, payload: dict, ctx: dict, *, target: str = "", output: str | None = None) -> None:
    from blue_tap.framework.sessions.store import log_command

    _recon_finalize_payload(payload, ctx)
    log_command(command, payload, category="recon", target=target)
    if output:
        _save_json(payload, output)


def _save_json(data, filepath):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    from blue_tap.utils.output import success

    success(f"Saved JSON to {filepath}")


class LoggedCommand(click.RichCommand):
    """Click command with automatic session logging for every invocation."""

    def invoke(self, ctx):
        hci = ctx.params.get("hci")
        if hci:
            from blue_tap.framework.sessions.store import set_adapter
            set_adapter(hci)
        return super().invoke(ctx)




class LoggedGroup(click.RichGroup):
    """Click group that propagates logged command/group classes."""

    command_class = LoggedCommand
    group_class = None


LoggedGroup.group_class = LoggedGroup


__all__ = [
    "_extract_target_param",
    "_infer_category",
    "_normalize_command_path",
    "_recon_artifact",
    "_recon_cli_context",
    "_recon_emit",
    "_recon_error",
    "_recon_finalize_payload",
    "_recon_module_data",
    "_recon_persist",
    "_recon_result",
    "_recon_skip",
    "_recon_start",
    "_save_json",
    "LoggedCommand",
    "LoggedGroup",
]
