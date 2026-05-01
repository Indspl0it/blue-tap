"""CLI facade for environment diagnostics."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand


@click.command("doctor", cls=LoggedCommand)
def doctor():
    """Check host environment readiness for Bluetooth operations."""
    from blue_tap.interfaces.cli._module_runner import _is_dry_run
    from blue_tap.utils.env_doctor import detect_profile_environment, fix_hint_for_tool
    from blue_tap.utils.output import console, info, warning, success

    if _is_dry_run():
        info("[bt.yellow]Dry-run:[/bt.yellow] would probe environment "
             "(adapters, BlueZ services, tool versions, capabilities). "
             "Re-run without --dry-run to actually diagnose.")
        return

    results = detect_profile_environment()

    console.print()
    console.print("[bold]Environment Diagnostics[/bold]")
    console.print("─" * 40)

    # Tools — show ✓/✗, plus a ``→ fix:`` line under each missing tool when
    # a canned install hint is available.
    tools = results.get("tools", {})
    for tool, available in tools.items():
        status = "[green]✓[/green]" if available else "[red]✗[/red]"
        console.print(f"  {status}  {tool}")
        if not available:
            hint = fix_hint_for_tool(tool)
            if hint:
                console.print(f"       [bt.dim]→ fix:[/bt.dim] {hint}")

    # Adapters
    adapters = results.get("adapters", [])
    if adapters:
        info(f"{len(adapters)} Bluetooth adapter(s) detected")
    else:
        warning("No Bluetooth adapters found")

    # Capability limitations live under ``summary.capability_limitations``
    # per the env_doctor contract. Pair each with its hint from the
    # ``limitation_hints`` dict that env_doctor populates.
    summary = results.get("summary", {})
    limitations = summary.get("capability_limitations") or results.get("limitations") or []
    hints = results.get("limitation_hints", {})
    if limitations:
        console.print()
        warning("Limitations:")
        for lim in limitations:
            console.print(f"  • {lim}")
            fix = hints.get(lim, "")
            if fix:
                console.print(f"       [bt.dim]→ fix:[/bt.dim] {fix}")

    console.print()
    if not adapters:
        warning("Environment NOT ready: no Bluetooth adapter present.")
    elif limitations:
        warning("Environment partially ready — see limitations above.")
    else:
        success("Environment ready for Bluetooth operations.")
    console.print()
