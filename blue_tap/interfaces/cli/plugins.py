"""Plugin management commands — list, info, refresh.

Provides visibility into installed plugins and their registered modules.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

import rich_click as click
from rich.table import Table
from rich.panel import Panel

from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup
from blue_tap.utils.output import info, error, warning, success, console

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@click.group("plugins", cls=LoggedGroup)
def plugins():
    """Manage Blue-Tap plugins.

    \b
    Plugins are external packages that register additional modules.
    Install via pip, then they auto-load at startup.

    \b
    Examples:
      blue-tap plugins list                # show installed plugins
      blue-tap plugins info my_plugin      # show plugin details
      blue-tap plugins refresh             # reload plugins
    """
    pass


@plugins.command("list", cls=LoggedCommand)
@click.option("--verbose", "-v", is_flag=True, help="Show module counts per family")
def list_plugins(verbose: bool) -> None:
    """List all installed plugins with their module counts.

    Shows both built-in module packages and external plugins.
    """
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.module.loader import get_plugin_registry

    registry = get_registry()
    plugin_registry = get_plugin_registry()

    # Built-in module families
    builtin_families = {
        "discovery": "blue_tap.modules.discovery",
        "reconnaissance": "blue_tap.modules.reconnaissance",
        "assessment": "blue_tap.modules.assessment",
        "exploitation": "blue_tap.modules.exploitation",
        "post_exploitation": "blue_tap.modules.post_exploitation",
        "fuzzing": "blue_tap.modules.fuzzing",
    }

    # Count modules by source
    from collections import defaultdict
    family_counts = defaultdict(int)
    for desc in registry.list_all():
        family_counts[desc.family.value] += 1

    # Built-in families
    console.print()
    console.print("[bold]Built-in Families[/bold]  [bt.dim](use with: plugins info <family>)[/bt.dim]")
    console.print(f"[bt.dim]{'─' * 50}[/bt.dim]")
    for family in sorted(builtin_families):
        count = family_counts.get(family, 0)
        status = "[bt.green]loaded[/bt.green]" if count > 0 else "[bt.dim]empty[/bt.dim]"
        console.print(f"  [bt.cyan]{family:<25}[/bt.cyan][bt.dim]{count:>3} modules[/bt.dim]  {status}")

    # External plugins
    if plugin_registry:
        console.print()
        console.print("[bold]External Plugins[/bold]")
        console.print(f"[bt.dim]{'─' * 50}[/bt.dim]")
        for plugin_name, plugin_info in sorted(plugin_registry.items()):
            count = plugin_info.get("module_count", 0)
            if plugin_info.get("error"):
                status = f"[bt.red]error: {plugin_info['error'][:30]}[/bt.red]"
            elif plugin_info.get("loaded"):
                status = "[bt.green]loaded[/bt.green]"
            else:
                status = "[bt.red]error[/bt.red]"
            console.print(f"  [bt.cyan]{plugin_name:<25}[/bt.cyan][bt.dim]{count:>3} modules[/bt.dim]  {status}")

    console.print()
    total_modules = sum(family_counts.values())
    total_plugins = len(plugin_registry)
    info(f"Total: {total_modules} modules from {len(builtin_families)} built-in families" +
         (f" + {total_plugins} external plugins" if total_plugins else ""))

    if verbose:
        console.print()
        console.print("[bold]Module counts by family[/bold]")
        console.print(f"[bt.dim]{'─' * 30}[/bt.dim]")
        for family, count in sorted(family_counts.items()):
            console.print(f"  [bt.dim]{family:<25}[/bt.dim]{count}")


@plugins.command("info", cls=LoggedCommand)
@click.argument("plugin_name")
def plugin_info(plugin_name: str) -> None:
    """Show details about a specific plugin.

    Lists the modules registered by the plugin with their metadata.
    """
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.module.loader import get_plugin_registry

    plugin_registry = get_plugin_registry()

    # Check if it's an external plugin
    if plugin_name in plugin_registry:
        plugin_data = plugin_registry[plugin_name]
        if plugin_data.get("error"):
            error(f"Plugin '{plugin_name}' failed to load: {plugin_data['error']}")
            return

        modules = plugin_data.get("modules", [])
        if not modules:
            info(f"Plugin '{plugin_name}' has no registered modules")
            return

        console.print()
        console.print(f"[bold]{plugin_name}[/bold]  [bt.dim]{len(modules)} modules[/bt.dim]")
        console.print(f"[bt.dim]{'─' * 60}[/bt.dim]")
        registry = get_registry()
        for module_id in sorted(modules):
            try:
                desc = registry.get(module_id)
                destr = " [bt.red]✱[/bt.red]" if desc.destructive else ""
                console.print(f"  [bt.cyan]{module_id:<40}[/bt.cyan]{desc.name}{destr}")
            except KeyError:
                console.print(f"  [bt.cyan]{module_id:<40}[/bt.cyan][bt.dim]not found[/bt.dim]")
        console.print()
        return

    # Check if it's a built-in family (accept both family name and package path)
    _package_to_family = {
        "blue_tap.modules.discovery": "discovery",
        "blue_tap.modules.reconnaissance": "reconnaissance",
        "blue_tap.modules.assessment": "assessment",
        "blue_tap.modules.exploitation": "exploitation",
        "blue_tap.modules.post_exploitation": "post_exploitation",
        "blue_tap.modules.fuzzing": "fuzzing",
    }
    builtin_families = set(_package_to_family.values())

    if plugin_name in _package_to_family:
        plugin_name = _package_to_family[plugin_name]

    if plugin_name in builtin_families or plugin_name.replace("_", " ") in builtin_families:
        family_name = plugin_name.replace(" ", "_")
        registry = get_registry()

        modules = [
            desc for desc in registry.list_all()
            if desc.family.value == family_name
        ]

        if not modules:
            info(f"Family '{family_name}' has no registered modules")
            return

        console.print()
        console.print(f"[bold]{family_name}[/bold]  [bt.dim]{len(modules)} modules[/bt.dim]")
        console.print(f"[bt.dim]{'─' * 60}[/bt.dim]")
        for desc in sorted(modules, key=lambda x: x.module_id):
            destr = " [bt.red]✱[/bt.red]" if desc.destructive else ""
            console.print(f"  [bt.cyan]{desc.module_id:<40}[/bt.cyan]{desc.name}{destr}")
        console.print()
        return

    error(f"Plugin or family not found: {plugin_name}")
    info("Run [bold]blue-tap plugins list[/bold] to see available plugins.")


@plugins.command("refresh", cls=LoggedCommand)
def refresh_plugins() -> None:
    """Reload all plugins (useful after pip install without restart).

    Note: Built-in modules are always loaded. This reloads external plugins.
    """
    from blue_tap.framework.module.loader import load_plugins, get_plugin_registry

    info("Refreshing external plugins...")

    # Clear existing plugin registry
    plugin_registry = get_plugin_registry()
    old_count = len(plugin_registry)

    try:
        loaded, failed = load_plugins(reload=True)

        if loaded:
            success(f"Loaded {len(loaded)} plugin(s): {', '.join(loaded)}")
        if failed:
            for plugin_name, err in failed.items():
                warning(f"Failed to load '{plugin_name}': {err}")

        new_count = len(get_plugin_registry())
        info(f"Plugin count: {old_count} -> {new_count}")

    except Exception as e:
        error(f"Plugin refresh failed: {e}")
        logger.exception("Plugin refresh error")


@plugins.command("doctor", cls=LoggedCommand)
def plugin_doctor() -> None:
    """Diagnose plugin loading issues.

    Shows detailed information about plugin discovery and loading.
    """
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.module.loader import (
        get_plugin_registry,
        discover_plugins,
    )

    info("[bold]Plugin Doctor[/bold] - Diagnosing plugin system...")
    console.print()

    # Step 1: Check entry points
    info("[1/4] Checking entry points...")
    try:
        discovered = discover_plugins()
        if discovered:
            for ep_name, ep_value in discovered.items():
                console.print(f"  [bt.green]found[/bt.green] {ep_name}: {ep_value}")
        else:
            console.print("  [dim]No external plugins discovered via entry points[/dim]")
    except Exception as e:
        console.print(f"  [bt.red]Error discovering plugins: {e}[/bt.red]")

    console.print()

    # Step 2: Check loaded plugins
    info("[2/4] Checking loaded plugins...")
    plugin_registry = get_plugin_registry()
    if plugin_registry:
        for name, data in plugin_registry.items():
            status = "[bt.green]OK[/bt.green]" if data.get("loaded") else f"[bt.red]FAILED: {data.get('error', 'unknown')}[/bt.red]"
            console.print(f"  {name}: {status}")
    else:
        console.print("  [dim]No external plugins loaded[/dim]")

    console.print()

    # Step 3: Check registry state
    info("[3/4] Checking module registry...")
    registry = get_registry()
    all_modules = registry.list_all()
    console.print(f"  Total modules registered: {len(all_modules)}")

    from collections import defaultdict
    by_family = defaultdict(int)
    for m in all_modules:
        by_family[m.family.value] += 1

    for family, count in sorted(by_family.items()):
        console.print(f"    {family}: {count}")

    console.print()

    # Step 4: Check for common issues
    info("[4/4] Checking for issues...")
    issues = []

    # Check for modules with missing entry points
    for desc in all_modules:
        if not desc.entry_point:
            issues.append(f"Module {desc.module_id} has no entry point")

    # Check for duplicate IDs (shouldn't happen, but just in case)
    seen_ids = set()
    for desc in all_modules:
        if desc.module_id in seen_ids:
            issues.append(f"Duplicate module ID: {desc.module_id}")
        seen_ids.add(desc.module_id)

    if issues:
        for issue in issues:
            console.print(f"  [bt.yellow]WARNING[/bt.yellow] {issue}")
    else:
        console.print("  [bt.green]No issues detected[/bt.green]")

    console.print()
    success("Plugin doctor complete")
