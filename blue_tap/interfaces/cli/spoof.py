"""CLI facade for MAC address spoofing."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("spoof", cls=LoggedCommand)
@click.argument("new_mac")
@click.option("--hci", "-a", default=None, help="HCI adapter to spoof (e.g. hci0)")
@click.option("--method", "-m", default=None,
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt", "rtl8761b"]),
              help="Spoofing method (default: auto)")
def spoof(new_mac, hci, method):
    """Spoof the local adapter's MAC address.

    \b
    Examples:
      blue-tap spoof AA:BB:CC:DD:EE:FF
      blue-tap spoof AA:BB:CC:DD:EE:FF --hci hci1 --method rtl8761b
    """
    from blue_tap.hardware.adapter import resolve_active_hci
    from blue_tap.hardware.spoofer import spoof_address
    from blue_tap.utils.output import info, error, success

    _hci = hci or resolve_active_hci()
    kwargs = {"hci": _hci, "target_mac": new_mac}
    if method:
        kwargs["method"] = method

    info(f"Spoofing {_hci} → [bold]{new_mac}[/bold]")
    result = spoof_address(**kwargs)

    if result.get("success"):
        success(f"MAC spoofed to {new_mac} via {result.get('method', 'unknown')}")
        if result.get("verified"):
            success("Address verified active.")
    else:
        error(f"Spoofing failed: {result}")
