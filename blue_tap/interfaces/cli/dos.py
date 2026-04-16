"""CLI facade for denial-of-service and resilience testing."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("dos", cls=LoggedCommand)
@click.argument("target")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.option("--checks", "-c", default=None,
              help="Comma-separated check IDs to run (default: all)")
@click.option("--recovery-timeout", default=None, type=int,
              help="Seconds to wait for device recovery between checks")
@click.option("--yes", "confirm", is_flag=True, help="Bypass destructive confirmation")
def dos(target, hci, checks, recovery_timeout, confirm):
    """Denial-of-service and resilience testing.

    \b
    Examples:
      blue-tap dos AA:BB:CC:DD:EE:FF --yes              # Run all DoS checks
      blue-tap dos AA:BB:CC:DD:EE:FF --checks bluefrag   # Run specific check
      blue-tap dos AA:BB:CC:DD:EE:FF --checks "l2cap_storm,sdp_flood" --yes
    """
    opts: dict[str, str] = {"RHOST": target}
    if hci:
        opts["HCI"] = hci
    if checks:
        opts["CHECKS"] = checks
    if recovery_timeout is not None:
        opts["RECOVERY_TIMEOUT"] = str(recovery_timeout)
    invoke("exploitation.dos_runner", opts, confirm_destructive=confirm)
