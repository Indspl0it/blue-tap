"""CLI facade for Bluetooth device discovery."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup


@click.group(cls=LoggedGroup)
def discover():
    """Find nearby Bluetooth targets."""


@discover.command("classic", cls=LoggedCommand)
@click.option("--duration", "-d", default=10, type=int, help="Scan duration in seconds")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
def discover_classic(duration, hci):
    """Scan for Bluetooth Classic (BR/EDR) devices."""
    opts = {"MODE": "classic", "DURATION": str(duration)}
    if hci:
        opts["HCI"] = hci
    invoke("discovery.scanner", opts)


@discover.command("ble", cls=LoggedCommand)
@click.option("--duration", "-d", default=10, type=int, help="Scan duration in seconds")
@click.option("--passive", "-p", is_flag=True, help="Use passive scanning (no scan requests)")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
def discover_ble(duration, passive, hci):
    """Scan for Bluetooth Low Energy (BLE) devices."""
    opts = {"MODE": "ble", "DURATION": str(duration)}
    if passive:
        opts["PASSIVE"] = "true"
    if hci:
        opts["HCI"] = hci
    invoke("discovery.scanner", opts)


@discover.command("all", cls=LoggedCommand)
@click.option("--duration", "-d", default=10, type=int, help="Scan duration in seconds")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
def discover_all(duration, hci):
    """Scan for both Classic and BLE devices."""
    opts = {"MODE": "all", "DURATION": str(duration)}
    if hci:
        opts["HCI"] = hci
    invoke("discovery.scanner", opts)
