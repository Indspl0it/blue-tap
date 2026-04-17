"""CLI facade for automated full-chain assessment."""

from __future__ import annotations

import logging

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand

logger = logging.getLogger(__name__)


@click.command("auto", cls=LoggedCommand)
@click.argument("target")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.option("--skip", multiple=True,
              help="Skip phases: recon, vulnscan, exploit, extract")
@click.option("--yes", "confirm", is_flag=True, help="Bypass destructive confirmation")
def auto(target, hci, skip, confirm):
    """Four-phase assessment shortcut: SDP recon → vuln_scanner → KNOB → PBAP → report.

    Runs exactly four modules in sequence against TARGET and then writes an
    HTML report to the active session directory. It is not a "full pentest"
    — it's a fixed-pipeline shortcut. For broader coverage use individual
    commands (``recon``, ``vulnscan``, ``exploit``, ``extract``) or a
    playbook via ``blue-tap run-playbook``.

    TARGET is required — auto runs non-interactively and needs a known address.

    \b
    Modules run:
      recon    → reconnaissance.sdp
      vulnscan → assessment.vuln_scanner
      exploit  → exploitation.knob
      extract  → post_exploitation.pbap

    \b
    Examples:
      blue-tap auto AA:BB:CC:DD:EE:FF --yes
      blue-tap auto AA:BB:CC:DD:EE:FF --skip exploit --skip extract
    """
    from blue_tap.utils.output import info, error, success

    skip_set = set(skip)
    base_opts: dict[str, str] = {"RHOST": target}
    if hci:
        base_opts["HCI"] = hci

    phases = [
        ("recon", "reconnaissance.sdp", {**base_opts}),
        ("vulnscan", "assessment.vuln_scanner", {**base_opts}),
        ("exploit", "exploitation.knob", {**base_opts}),
        ("extract", "post_exploitation.pbap", {**base_opts}),
    ]

    for phase_name, module_id, opts in phases:
        if phase_name in skip_set:
            info(f"Skipping phase: {phase_name}")
            continue
        info(f"[bold]Phase: {phase_name}[/bold]")
        result = invoke(module_id, dict(opts), confirm_destructive=confirm)
        if result is None:
            logger.warning("Phase %s returned no result", phase_name)

    # Generate report
    info("[bold]Generating report...[/bold]")
    try:
        import os
        from blue_tap.interfaces.reporting.generator import ReportGenerator
        from blue_tap.framework.sessions.store import get_session

        report = ReportGenerator()
        session = get_session()
        if not session:
            error("No active session — cannot generate report.")
            return

        session_data = session.get_all_data()
        for category_name, entries in session_data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("data", {})
                if isinstance(data, dict):
                    report.add_run_envelope(data)

        report.add_session_metadata(session.metadata)
        out = os.path.join(session.dir, "report.html")
        report.generate_html(out)
        success(f"Assessment complete — report saved to {out}")
    except Exception as e:
        error(f"Report generation failed: {e}")
        logger.exception("Report generation failed")
