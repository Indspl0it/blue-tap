"""CLI facade for vulnerability scanning."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("vulnscan", cls=LoggedCommand)
@click.argument("target")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.option("--cve", default=None, help="Run a specific CVE check (e.g. CVE-2020-0022)")
@click.option("--active/--no-active", default=None, help="Include active probing checks")
@click.option("--phone", default=None, help="Phone address for impersonation checks")
@click.option("--yes", "confirm", is_flag=True, help="Bypass destructive confirmation")
def vulnscan(target, hci, cve, active, phone, confirm):
    """Scan target for vulnerabilities — CVE checks and security posture."""
    if cve:
        # Map CVE ID to module: CVE-2020-0022 → assessment.cve_2020_0022
        module_id = f"assessment.{cve.lower().replace('-', '_')}"
        opts: dict[str, str] = {"RHOST": target}
        if hci:
            opts["HCI"] = hci
        invoke(module_id, opts, confirm_destructive=confirm)
    else:
        opts = {"RHOST": target}
        if hci:
            opts["HCI"] = hci
        if active is not None:
            opts["ACTIVE"] = str(active).lower()
        if phone:
            opts["PHONE"] = phone
        invoke("assessment.vuln_scanner", opts, confirm_destructive=confirm)
