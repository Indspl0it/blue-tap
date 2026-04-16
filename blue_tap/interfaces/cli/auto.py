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
    """Full automated assessment: recon → vulnscan → exploit → extract → report.

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
        from blue_tap.interfaces.reporting.generator import generate_report
        generate_report()
        success("Assessment complete — report generated.")
    except Exception as e:
        error(f"Report generation failed: {e}")
