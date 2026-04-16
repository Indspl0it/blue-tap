"""Reporting CLI — pentest reports, automated pentest, playbook runner, session management."""

from __future__ import annotations

import json
import os
import re

import rich_click as click
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup, _save_json
from blue_tap.utils.output import info, success, error, warning, console, summary_panel, bare_table, print_table
from blue_tap.utils.interactive import resolve_address


# ── Helpers ───────────────────────────────────────────────────────────────────

def _current_adapter() -> str:
    from blue_tap.framework.sessions.store import get_session
    session = get_session()
    if session is None:
        return ""
    return str(session.metadata.get("adapter", "") or "")


def _log_standardized_operation(
    *,
    module: str,
    command: str,
    title: str,
    protocol: str,
    target: str = "",
    result: dict | None = None,
    category: str | None = None,
    observations: list[str] | None = None,
    artifact_paths: list[dict[str, str]] | None = None,
    operator_context: dict | None = None,
    module_outcome: str = "completed",
    capability_limitations: list[str] | None = None,
):
    from blue_tap.framework.sessions.store import log_command
    if module == "attack":
        from blue_tap.framework.envelopes.attack import build_attack_result, artifact_if_file

        artifacts = [
            item
            for item in (
                artifact_if_file(
                    item.get("path", ""),
                    kind=item.get("kind", "file"),
                    label=item.get("label", item.get("path", "")),
                    description=item.get("description", ""),
                )
                for item in (artifact_paths or [])
            )
            if item is not None
        ]
        envelope = build_attack_result(
            target=target,
            adapter=_current_adapter(),
            operation=command,
            title=title,
            protocol=protocol,
            module_data=dict(result or {}),
            summary_data=dict(operator_context or {}),
            observations=observations,
            capability_limitations=capability_limitations,
            artifacts=artifacts,
            module_outcome=module_outcome,
        )
    elif module == "data":
        from blue_tap.framework.envelopes.data import build_data_result, artifact_if_path

        artifacts = [
            item
            for item in (
                artifact_if_path(
                    item.get("path", ""),
                    kind=item.get("kind", "file"),
                    label=item.get("label", item.get("path", "")),
                    description=item.get("description", ""),
                )
                for item in (artifact_paths or [])
            )
            if item is not None
        ]
        envelope = build_data_result(
            target=target,
            adapter=_current_adapter(),
            family=str((result or {}).get("family", protocol.lower() or "data")),
            operation=command,
            title=title,
            module_data=dict(result or {}),
            summary_data=dict(operator_context or {}),
            observations=observations,
            capability_limitations=capability_limitations,
            artifacts=artifacts,
            module_outcome=module_outcome,
        )
    elif module == "audio":
        from blue_tap.framework.envelopes.audio import build_audio_result, artifact_if_file

        artifacts = [
            item
            for item in (
                artifact_if_file(
                    item.get("path", ""),
                    kind=item.get("kind", "file"),
                    label=item.get("label", item.get("path", "")),
                    description=item.get("description", ""),
                )
                for item in (artifact_paths or [])
            )
            if item is not None
        ]
        envelope = build_audio_result(
            target=target,
            adapter=_current_adapter(),
            operation=command,
            title=title,
            protocol=protocol,
            module_data=dict(result or {}),
            summary_data=dict(operator_context or {}),
            observations=observations,
            capability_limitations=capability_limitations,
            artifacts=artifacts,
            module_outcome=module_outcome,
        )
    else:
        raise ValueError(f"Unsupported standardized operation module: {module}")
    log_command(command, envelope, category=category or module, target=target)


# ============================================================================
# REPORT - Pentest Report Generation
# ============================================================================

@click.command("report", cls=LoggedCommand)
@click.argument("dump_dir", required=False, default=None)
@click.option("-f", "--format", "fmt", default="html",
              type=click.Choice(["html", "json"]))
@click.option("-o", "--output", default=None, help="Output file")
def report_cmd(dump_dir, fmt, output):
    """Generate pentest report from the current session.

    \b
    Auto-collects all data from the active session. Pass a directory
    to report from a specific location instead.

    Examples:
      blue-tap report                              # current session
      blue-tap -s mytest report                    # named session
      blue-tap report ./hijack_output              # specific directory
    """
    from blue_tap.interfaces.reporting.generator import ReportGenerator
    from blue_tap.framework.sessions.store import get_session

    report = ReportGenerator()
    session = get_session()

    if session:
        # Auto-collect from session
        session_data = session.get_all_data()
        info(f"Collecting data from session '{session.name}'...")

        # Dispatch every run envelope through the adapter pipeline.
        # ``add_run_envelope`` picks the right adapter based on schema, so
        # categories are just a routing hint — we no longer hardcode the
        # list here (the earlier version missed ``assessment``/``vulnscan``
        # because it only iterated ``vuln``). Non-envelope entries that have
        # a ``command_path`` become operator notes instead.
        for category_name, entries in session_data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("data", {})
                ingested = False
                if isinstance(data, dict):
                    ingested = report.add_run_envelope(data)
                if not ingested and isinstance(data, dict) and data.get("command_path"):
                    status = data.get("status", "unknown")
                    report.add_note(
                        f"Command: {data['command_path']} | "
                        f"Category: {category_name} | Status: {status}"
                    )

        # Pass full session metadata for timeline, scope, and methodology
        report.add_session_metadata(session.metadata)

        # Add session metadata as a note
        meta = session.metadata
        report.add_note(
            f"Session: {meta.get('name')} | "
            f"Commands: {len(meta.get('commands', []))} | "
            f"Targets: {', '.join(meta.get('targets', []))}"
        )

        out_dir = session.dir
    elif dump_dir:
        report.load_from_directory(dump_dir)
        out_dir = dump_dir
    else:
        error("No session active and no dump directory specified.")
        error("Use: blue-tap -s <session> report  OR  blue-tap report <dir>")
        return

    if fmt == "html":
        out = output or os.path.join(out_dir, "report.html")
        report.generate_html(out)
    else:
        out = output or os.path.join(out_dir, "report.json")
        report.generate_json(out)

    summary = session.summary() if session else {}
    if summary:
        info(f"Session included {summary.get('total_commands', 0)} commands across "
             f"{len(summary.get('categories', []))} categories")


# ============================================================================
# RUN - Execute Multiple Commands
# ============================================================================

@click.command("run-playbook", cls=LoggedCommand)
@click.argument("commands", nargs=-1)
@click.option("--playbook", default=None, help="Playbook file (YAML or text, one command per line)")
@click.option("--list", "list_playbooks_flag", is_flag=True, help="List available bundled playbooks")
def run_playbook_cmd(commands, playbook, list_playbooks_flag):
    """Execute multiple blue-tap commands in sequence.

    \b
    Each argument is a command string (quote if it has spaces):
      blue-tap -s mytest run-playbook "scan classic" "recon fingerprint TARGET" "vulnscan TARGET" "report"

    Use TARGET as a placeholder — you'll be prompted to select a device.

    \b
    Use a playbook file (YAML or plain text):
      blue-tap -s mytest run-playbook --playbook quick-recon.yaml
      blue-tap -s mytest run-playbook --playbook quick-recon   # searches bundled playbooks

    \b
    List available bundled playbooks:
      blue-tap run-playbook --list
    """
    import shlex
    from blue_tap.framework.sessions.store import get_session

    # ── List bundled playbooks ────────────────────────────────────────
    if list_playbooks_flag:
        from blue_tap.interfaces.playbooks import PlaybookLoader
        import yaml

        pb_names = PlaybookLoader.list_bundled()
        if not pb_names:
            info("No bundled playbooks found")
            return

        pb_table = bare_table()
        pb_table.title = "[bold]Bundled Playbooks[/bold]"
        pb_table.add_column("Playbook", style="bold")
        pb_table.add_column("Description", style="bt.dim")
        pb_table.add_column("Duration")
        pb_table.add_column("Risk")

        for pb_name in pb_names:
            path = PlaybookLoader.get_bundled_path(pb_name)
            try:
                with open(path) as f:
                    pb = yaml.safe_load(f)
                pb_table.add_row(
                    pb_name.replace(".yaml", ""),
                    pb.get("description", ""),
                    pb.get("duration", ""),
                    pb.get("risk", ""),
                )
            except Exception:
                pb_table.add_row(pb_name, "(error loading)", "", "")

        print_table(pb_table)
        return

    # ── Load playbook via PlaybookLoader ─────────────────────────────────
    if playbook:
        from blue_tap.interfaces.playbooks import PlaybookLoader
        loader = PlaybookLoader()
        resolved_path = loader._resolve_path(playbook)

        if not os.path.exists(resolved_path):
            error(f"Playbook not found: {playbook}")
            return

        if resolved_path != playbook:
            info(f"Using bundled playbook: {resolved_path}")

        # Show playbook metadata for YAML files before loading commands
        if resolved_path.endswith((".yaml", ".yml")):
            import yaml
            with open(resolved_path) as f:
                pb_meta = yaml.safe_load(f)
            info(f"Playbook: [bold]{pb_meta.get('name', playbook)}[/bold] - "
                 f"{pb_meta.get('description', '')}")
            if pb_meta.get("risk"):
                info(f"Risk level: {pb_meta['risk']}")

        try:
            commands = loader.load(resolved_path)
        except ValueError as exc:
            error(str(exc))
            return

    if not commands:
        error("No commands specified. Usage: blue-tap run \"scan classic\" \"vulnscan TARGET\"")
        return

    # Resolve TARGET / {target} / {hci} placeholders
    from blue_tap.hardware.adapter import resolve_active_hci
    target_addr = None
    hci_adapter = resolve_active_hci()
    has_target_placeholder = any(
        "TARGET" in cmd.upper() or "{target}" in cmd for cmd in commands
    )

    if has_target_placeholder:
        target_addr = resolve_address(None, prompt="Select target for workflow")
        if not target_addr:
            error("Target selection cancelled")
            return

    from blue_tap.framework.runtime.cli_events import emit_cli_event
    from blue_tap.framework.contracts.result_schema import (
        now_iso,
        make_run_id,
        make_execution,
        make_evidence,
        build_run_envelope,
    )

    playbook_name = playbook or "inline"
    run_id = make_run_id("playbook")
    started_at = now_iso()

    console.rule("[bold]Blue-Tap Workflow[/bold]", style="bt.dim")
    info(f"Executing {len(commands)} command(s)")
    for i, cmd in enumerate(commands, 1):
        info(f"  {i}. {cmd}")
    console.print()

    emit_cli_event(
        event_type="run_started",
        module="playbook",
        run_id=run_id,
        message=f"Playbook started: {len(commands)} step(s)",
        details={"step_count": len(commands), "playbook": playbook_name},
        echo=False,
    )

    results = []
    active_session = get_session()
    session_prefix = []
    if active_session:
        # Force subcommands to use the current session instead of spawning auto sessions.
        session_prefix = ["-s", active_session.name]
    for i, cmd_str in enumerate(commands, 1):
        # Replace TARGET / {target} placeholder
        if target_addr:
            cmd_str = re.sub(r'\bTARGET\b', target_addr, cmd_str)
            cmd_str = re.sub(r'\btarget\b', target_addr, cmd_str)
            cmd_str = cmd_str.replace("{target}", target_addr)
        # Replace {hci} placeholder
        cmd_str = cmd_str.replace("{hci}", hci_adapter)

        console.rule(f"[bold]Step {i}/{len(commands)}: {cmd_str}", style="dim")

        step_started_at = now_iso()
        emit_cli_event(
            event_type="execution_started",
            module="playbook",
            run_id=run_id,
            message=f"Step {i}: {cmd_str}",
            details={"step": i, "command": cmd_str},
            echo=False,
        )

        try:
            # Parse the command string and invoke via Click
            args = shlex.split(cmd_str)
            if args and args[0] == "run":
                error("Nested 'run' command is not supported inside workflows")
                step_completed_at = now_iso()
                emit_cli_event(
                    event_type="execution_result",
                    module="playbook",
                    run_id=run_id,
                    message=f"Step {i} failed: {cmd_str}",
                    details={"step": i, "status": "failed", "error": "nested_run_not_supported"},
                    echo=False,
                )
                results.append({
                    "step": i,
                    "command": cmd_str,
                    "status": "error",
                    "error": "nested_run_not_supported",
                    "started_at": step_started_at,
                    "completed_at": step_completed_at,
                })
                continue
            # Import main lazily to avoid circular imports at module load time
            from blue_tap.interfaces.cli.main import cli as main_cli
            ctx = main_cli.make_context("blue-tap", session_prefix + list(args), parent=click.get_current_context())
            with ctx:
                main_cli.invoke(ctx)
            step_completed_at = now_iso()
            emit_cli_event(
                event_type="execution_result",
                module="playbook",
                run_id=run_id,
                message=f"Step {i} complete: {cmd_str}",
                details={"step": i, "status": "success"},
                echo=False,
            )
            results.append({
                "step": i,
                "command": cmd_str,
                "status": "success",
                "started_at": step_started_at,
                "completed_at": step_completed_at,
            })
        except KeyboardInterrupt:
            step_completed_at = now_iso()
            warning("Workflow interrupted by user")
            emit_cli_event(
                event_type="run_aborted",
                module="playbook",
                run_id=run_id,
                message=f"Playbook interrupted at step {i}",
                details={"step": i, "command": cmd_str},
                echo=False,
            )
            results.append({
                "step": i,
                "command": cmd_str,
                "status": "interrupted",
                "started_at": step_started_at,
                "completed_at": step_completed_at,
            })
            break
        except SystemExit as e:
            step_completed_at = now_iso()
            status = "success" if e.code in (None, 0) else "error"
            emit_cli_event(
                event_type="execution_result",
                module="playbook",
                run_id=run_id,
                message=f"Step {i} {'complete' if status == 'success' else 'failed'}: {cmd_str}",
                details={"step": i, "status": status, "exit_code": e.code},
                echo=False,
            )
            results.append({
                "step": i,
                "command": cmd_str,
                "status": status,
                "started_at": step_started_at,
                "completed_at": step_completed_at,
            })
        except click.exceptions.UsageError as e:
            step_completed_at = now_iso()
            error(f"Invalid command: {e}")
            emit_cli_event(
                event_type="execution_result",
                module="playbook",
                run_id=run_id,
                message=f"Step {i} failed: {cmd_str}",
                details={"step": i, "status": "failed", "error": str(e)},
                echo=False,
            )
            results.append({
                "step": i,
                "command": cmd_str,
                "status": "error",
                "error": str(e),
                "started_at": step_started_at,
                "completed_at": step_completed_at,
            })
        except Exception as e:
            step_completed_at = now_iso()
            error(f"Command failed: {e}")
            emit_cli_event(
                event_type="execution_result",
                module="playbook",
                run_id=run_id,
                message=f"Step {i} failed: {cmd_str}",
                details={"step": i, "status": "failed", "error": str(e)},
                echo=False,
            )
            results.append({
                "step": i,
                "command": cmd_str,
                "status": "error",
                "error": str(e),
                "started_at": step_started_at,
                "completed_at": step_completed_at,
            })

    console.rule("[bold]Workflow Complete[/bold]", style="bt.dim")
    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] in ("error", "interrupted"))
    info(f"Results: {succeeded} succeeded, {failed} failed out of {len(results)}")

    emit_cli_event(
        event_type="run_completed",
        module="playbook",
        run_id=run_id,
        message=f"Playbook complete: {succeeded}/{len(results)} steps succeeded",
        details={"passed": succeeded, "failed": failed, "total": len(results)},
        echo=False,
    )

    # Build structured RunEnvelope
    executions = []
    for step_result in results:
        step_status = step_result["status"]
        execution_status = "completed" if step_status == "success" else ("skipped" if step_status == "interrupted" else "failed")
        module_outcome = "completed" if step_status == "success" else "partial"
        obs = [f"status={step_status}"]
        if step_result.get("error"):
            obs.append(f"error={step_result['error']}")
        executions.append(make_execution(
            kind="phase",
            id=f"step_{step_result['step']}",
            title=step_result["command"],
            module="playbook",
            protocol="multi",
            execution_status=execution_status,
            module_outcome=module_outcome,
            evidence=make_evidence(
                summary=f"Step {step_result['step']}: {step_result['command']} — {step_status}",
                confidence="high",
                observations=obs,
            ),
            started_at=step_result.get("started_at", started_at),
            completed_at=step_result.get("completed_at", now_iso()),
            tags=["playbook"],
            module_data=step_result,
        ))

    envelope = build_run_envelope(
        schema="blue_tap.playbook.result",
        module="playbook",
        target=target_addr or "",
        adapter=hci_adapter,
        operator_context={"playbook": playbook_name, "step_count": len(commands)},
        summary={"passed": succeeded, "failed": failed, "total": len(commands)},
        executions=executions,
        artifacts=[],
        module_data={"steps": results},
        started_at=started_at,
        run_id=run_id,
    )

    from blue_tap.framework.sessions.store import log_command
    log_command("playbook_run", envelope, category="general")


# ============================================================================
# SESSION - Session Management
# ============================================================================

@click.group(cls=LoggedGroup)
def session():
    """Manage assessment sessions."""


@session.command("list")
def session_list():
    """List all sessions."""
    from blue_tap.framework.sessions.store import Session, resolve_sessions_base_dir
    sessions_dir = os.path.join(resolve_sessions_base_dir(), Session.SESSIONS_DIR)
    if not os.path.isdir(sessions_dir):
        info(f"No sessions found in {sessions_dir}")
        return

    sessions = []
    for name in sorted(os.listdir(sessions_dir)):
        meta_file = os.path.join(sessions_dir, name, "session.json")
        if os.path.exists(meta_file):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                sessions.append((name, meta))
            except (json.JSONDecodeError, OSError):
                sessions.append((name, {}))

    if not sessions:
        info("No sessions found.")
        return

    console.print()
    console.print(f"[bold]Sessions[/bold]  [bt.dim]{len(sessions)} total[/bt.dim]")
    console.print(f"[bt.dim]{'─' * 70}[/bt.dim]")
    for name, meta in sessions:
        created = meta.get("created", "")[:16].replace("T", " ")
        cmd_count = len(meta.get("commands", []))
        targets = ", ".join(meta.get("targets", []))[:35]
        cmd_str = f"[bt.dim]{cmd_count} cmd{'s' if cmd_count != 1 else ''}[/bt.dim]"
        target_str = f"  [bt.dim]{targets}[/bt.dim]" if targets else ""
        created_str = f"  [bt.dim]{created}[/bt.dim]" if created else ""
        console.print(f"  [bt.cyan]{name:<30}[/bt.cyan]{cmd_str}{created_str}{target_str}")
    console.print()


@session.command("show")
@click.argument("name")
def session_show(name):
    """Show details of a session."""
    import os as _os
    from blue_tap.framework.sessions.store import Session, resolve_sessions_base_dir
    meta_path = _os.path.join(
        resolve_sessions_base_dir(), Session.SESSIONS_DIR, name, "session.json"
    )
    if not _os.path.exists(meta_path):
        error(f"Session '{name}' not found")
        return
    try:
        s = Session(name)
        smry = s.summary()
        summary_panel("Session Details", {
            "Name": smry["name"],
            "Created": smry["created"],
            "Last Updated": smry["last_updated"],
            "Commands Run": str(smry["total_commands"]),
            "Targets": ", ".join(smry["targets"]) or "None",
            "Categories": ", ".join(smry["categories"]) or "None",
            "Files Saved": str(smry["files"]),
            "Directory": smry["directory"],
        })

        # Show command log
        if s.metadata.get("commands"):
            console.print("\n[bold]Command Log:[/bold]")
            for cmd in s.metadata["commands"]:
                console.print(
                    f"  [dim]{cmd.get('timestamp', '')[:19]}[/dim]  "
                    f"[bt.cyan]{cmd.get('command', '')}[/bt.cyan]  "
                    f"[dim]({cmd.get('category', '')})[/dim]  "
                    f"{cmd.get('target', '')}"
                )
    except Exception as e:
        error(f"Cannot load session: {e}")


__all__ = ["report_cmd", "run_playbook_cmd", "session"]
