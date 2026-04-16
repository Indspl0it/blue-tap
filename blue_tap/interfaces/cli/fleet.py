"""CLI facade for fleet-wide device assessment."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("fleet", cls=LoggedCommand)
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.option("--duration", "-d", default=10, type=int, help="Discovery scan duration in seconds")
@click.option("--class", "device_class", default=None,
              help="Filter by device class: ivi, phone, headset, speaker, laptop, etc.")
def fleet(hci, duration, device_class):
    """Scan, classify, and assess all nearby Bluetooth devices."""
    opts: dict[str, str] = {"DURATION": str(duration)}
    if hci:
        opts["HCI"] = hci
    if device_class:
        opts["CLASS"] = device_class
    invoke("assessment.fleet", opts)
