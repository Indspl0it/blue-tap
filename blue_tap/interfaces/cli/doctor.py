"""CLI facade for environment diagnostics."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("doctor", cls=LoggedCommand)
def doctor():
    """Check host environment readiness for Bluetooth operations."""
    from blue_tap.utils.env_doctor import detect_profile_environment
    from blue_tap.utils.output import console, info, warning, success

    results = detect_profile_environment()

    console.print()
    console.print("[bold]Environment Diagnostics[/bold]")
    console.print("─" * 40)

    # Tools
    tools = results.get("tools", {})
    for tool, available in tools.items():
        status = "[green]✓[/green]" if available else "[red]✗[/red]"
        console.print(f"  {status}  {tool}")

    # Adapters
    adapters = results.get("adapters", [])
    if adapters:
        info(f"{len(adapters)} Bluetooth adapter(s) detected")
    else:
        warning("No Bluetooth adapters found")

    # Capabilities
    limitations = results.get("limitations", [])
    if limitations:
        console.print()
        warning("Limitations:")
        for lim in limitations:
            console.print(f"  • {lim}")

    console.print()
    if not adapters:
        warning("Environment NOT ready: no Bluetooth adapter present.")
    elif limitations:
        warning("Environment partially ready — see limitations above.")
    else:
        success("Environment ready for Bluetooth operations.")
    console.print()
