"""Generic module runner commands — run, show-options, search, info.

Provides a uniform interface for invoking any registered module via its
module_id. Modeled on Metasploit's `use <module>` / `set` / `run` flow, but
without Metasploit's `check` verb — Blue-Tap modules are probe-or-attack, not
probe-before-attack, so a separate check command adds no value.
"""

from __future__ import annotations

import logging

import rich_click as click
from rich.table import Table

from blue_tap.framework.sessions.store import Session
from blue_tap.interfaces.cli.shared import LoggedCommand
from blue_tap.utils.output import info, error, warning, console

logger = logging.getLogger(__name__)

__all__ = ["run_cmd", "show_options_cmd", "search_cmd", "info_cmd"]


# ── run command ───────────────────────────────────────────────────────────────

@click.command("run", cls=LoggedCommand)
@click.argument("module_id")
@click.argument("options", nargs=-1, required=False)
@click.option("--rhost", "-r", help="Target Bluetooth address (alias for RHOST option)")
@click.option("--hci", "-a", help="HCI adapter (alias for HCI option)")
@click.option("--session", "-s", "session_name", default=None, help="Session name")
@click.option("--yes", "confirm", is_flag=True, help="Bypass destructive confirmation")
def run_cmd(module_id: str, options: tuple[str, ...], rhost: str | None, hci: str | None,
            session_name: str | None, confirm: bool) -> None:
    """Run a module by ID with KEY=VALUE options.

    \b
    Examples:
      blue-tap run exploitation.knob RHOST=AA:BB:CC:DD:EE:FF KEY_SIZE=1
      blue-tap run assessment.cve_2017_0785 RHOST=AA:BB:CC:DD:EE:FF
      blue-tap run discovery.scanner MODE=classic DURATION=10

    \b
    Options can be passed as KEY=VALUE pairs after the module ID.
    Well-known options have short flags:
      --rhost / -r   for RHOST
      --hci   / -a   for HCI

    For destructive modules, add CONFIRM=yes to options or use --yes flag.
    """
    from blue_tap.framework.module import (
        DestructiveConfirmationRequired,
        EntryPointResolutionError,
        Invoker,
        ModuleNotFound,
        NotAModule,
    )
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.sessions.store import get_session, set_session
    from blue_tap.hardware.adapter import resolve_active_hci

    # Parse KEY=VALUE options
    raw_options = {}
    for opt in options:
        if "=" in opt:
            key, value = opt.split("=", 1)
            raw_options[key.strip()] = value.strip()

    # Apply well-known option aliases
    if rhost:
        raw_options["RHOST"] = rhost
    if hci:
        raw_options["HCI"] = hci
    if confirm:
        raw_options["CONFIRM"] = "yes"

    # Get or create session
    session = get_session()
    if not session and session_name:
        session = Session(session_name)
        set_session(session)

    # Resolve module and get descriptor
    registry = get_registry()
    descriptor = registry.try_get(module_id)
    if not descriptor:
        error(f"Module not found: {module_id}")
        info("Run [bold]blue-tap list-modules[/bold] to see available modules.")
        return

    # If the module needs a target and RHOST was not supplied, offer interactive picker
    if "RHOST" not in raw_options:
        _target_requires = {"classic_target", "ble_target", "target"}
        if _target_requires & set(descriptor.requires):
            from blue_tap.utils.interactive import resolve_address
            _hci = raw_options.get("HCI") or hci or resolve_active_hci()
            resolved = resolve_address(None, prompt=f"Select target for {descriptor.name}", hci=_hci)
            if not resolved:
                return
            raw_options["RHOST"] = resolved

    # Show what we're running
    info(f"Running module: [bold cyan]{descriptor.name}[/bold cyan] ({module_id})")
    if descriptor.destructive and not confirm and raw_options.get("CONFIRM") != "yes":
        warning("[bt.red]Destructive module![/bt.red] Add CONFIRM=yes to proceed.")
        return

    # Invoke the module
    invoker = Invoker(safety_override=confirm)
    try:
        envelope = invoker.invoke_with_logging(module_id, raw_options, session=session)

        # Show summary
        summary = envelope.get("summary", {})
        if summary:
            info(f"Result: {summary}")

    except ModuleNotFound as e:
        error(str(e))
        info("Run [bold]blue-tap list-modules[/bold] to see available modules.")
    except DestructiveConfirmationRequired as e:
        error(str(e))
    except (EntryPointResolutionError, NotAModule) as e:
        error(f"Module error: {e}")
    except Exception as e:
        from blue_tap.framework.module.options import OptionError
        if isinstance(e, OptionError):
            error(f"Missing required option: {e}")
            info(f"Run [bold]blue-tap show-options {module_id}[/bold] to see all options.")
        else:
            error(f"Module execution failed: {e}")
            logger.exception("Module execution error")


# ── show-options command ───────────────────────────────────────────────────────

@click.command("show-options", cls=LoggedCommand)
@click.argument("module_id")
def show_options_cmd(module_id: str) -> None:
    """Show the options schema for a module.

    \b
    Example:
      blue-tap show-options exploitation.knob
    """
    from blue_tap.framework.module import (
        EntryPointResolutionError,
        Invoker,
        ModuleNotFound,
        NotAModule,
    )
    from blue_tap.framework.registry import get_registry

    registry = get_registry()
    descriptor = registry.try_get(module_id)
    if not descriptor:
        error(f"Module not found: {module_id}")
        return

    # Import the module class to get options
    invoker = Invoker()
    try:
        module_path, class_name = descriptor.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)
    except (ImportError, ValueError, AttributeError) as e:
        error(f"Failed to load module: {e}")
        return

    import inspect
    # Entry point may be a class or a plain function (e.g. dos_runner)
    module_options = getattr(cls, "options", None)
    if module_options is None and inspect.isfunction(cls):
        # Bare function — derive options from signature
        sig = inspect.signature(cls)
        module_options = []
        for pname, param in sig.parameters.items():
            if pname in ("self",):
                continue
            default = "" if param.default is inspect.Parameter.empty else str(param.default)
            module_options.append(type("_Opt", (), {
                "name": pname.upper(),
                "required": param.default is inspect.Parameter.empty,
                "default": None if param.default is inspect.Parameter.empty else param.default,
                "description": "",
                "__class__": type("OptString", (), {"__name__": "OptString"})(),
            })())

    console.print(f"\n[bold]{module_id}[/bold]  [bt.dim]options[/bt.dim]")
    console.print(f"[bt.dim]{'─' * 60}[/bt.dim]")

    if not module_options:
        console.print("[bt.dim]  No options defined.[/bt.dim]\n")
    else:
        for opt in module_options:
            opt_type = opt.__class__.__name__.replace("Opt", "").lower()
            req_tag = " [bt.red]required[/bt.red]" if opt.required else ""
            default_str = f"  [bt.dim]default: {opt.default}[/bt.dim]" if opt.default is not None else ""
            desc = f"  {opt.description}" if opt.description else ""
            console.print(
                f"  [bt.cyan]{opt.name:<20}[/bt.cyan]"
                f"[bt.dim]{opt_type:<10}[/bt.dim]"
                f"{req_tag}{default_str}{desc}"
            )
        console.print("")


# ── search command ─────────────────────────────────────────────────────────────

@click.command("search", cls=LoggedCommand)
@click.argument("term")
@click.option("--family", "-f", help="Filter by module family")
@click.option("--destructive", "show_destructive", is_flag=True, help="Show only destructive modules")
@click.option("--non-destructive", "show_non_destructive", is_flag=True, help="Show only non-destructive modules")
@click.option("--requires-pairing", "show_pairing", is_flag=True, help="Show only modules that require pairing")
def search_cmd(term: str, family: str | None, show_destructive: bool,
               show_non_destructive: bool, show_pairing: bool) -> None:
    """Search for modules by ID, name, description, or CVE reference.

    \b
    Examples:
      blue-tap search knob
      blue-tap search CVE-2019-9506
      blue-tap search l2cap --family exploitation
      blue-tap search dos --destructive
    """
    from blue_tap.framework.registry import get_registry

    term_lower = term.lower()
    registry = get_registry()

    # Filter modules
    modules = []
    for desc in registry.list_all():
        # Skip internal modules unless explicitly asked
        if getattr(desc, "internal", False):
            continue

        # Family filter
        if family and desc.family.value != family:
            continue

        # Destructive filter
        if show_destructive and not desc.destructive:
            continue
        if show_non_destructive and desc.destructive:
            continue

        # Pairing filter
        if show_pairing and not desc.requires_pairing:
            continue

        # Text search across multiple fields
        search_fields = [
            desc.module_id.lower(),
            desc.name.lower(),
            desc.description.lower(),
            " ".join(desc.protocols).lower(),
            " ".join(desc.references).lower(),
        ]
        if any(term_lower in field for field in search_fields):
            modules.append(desc)

    if not modules:
        info(f"No modules found matching '{term}'")
        return

    from blue_tap.utils.output import CYAN, GREEN, RED, DIM, YELLOW
    from rich.style import Style
    from collections import defaultdict

    sorted_modules = sorted(modules, key=lambda x: (x.family.value, x.module_id))

    # Column widths scaled to terminal
    term_width = min(console.width or 120, 140)
    id_col = min(max(len(m.module_id) for m in sorted_modules), 48)
    fam_col = 18
    desc_col = max(20, term_width - id_col - fam_col - 6)

    console.print()
    console.print(
        f"  [dim]{'─' * min(term_width - 4, 100)}[/dim]"
    )
    console.print(
        f"  [dim]{'MODULE ID'.ljust(id_col + 2)}{'FAMILY'.ljust(fam_col)}DESCRIPTION[/dim]"
    )
    console.print(
        f"  [dim]{'─' * min(term_width - 4, 100)}[/dim]"
    )

    prev_family = None
    for desc in sorted_modules:
        if desc.family.value != prev_family:
            if prev_family is not None:
                console.print()
            prev_family = desc.family.value

        flag = "[bt.red]✱[/bt.red] " if desc.destructive else "  "
        mod_id = desc.module_id.ljust(id_col)
        family_label = desc.family.value.ljust(fam_col)
        short_desc = desc.description
        if len(short_desc) > desc_col:
            short_desc = short_desc[:desc_col - 1].rsplit(" ", 1)[0] + "…"

        console.print(
            f"  [bt.cyan]{mod_id}[/bt.cyan]"
            f"{flag}"
            f"[bt.dim]{family_label}[/bt.dim]"
            f"{short_desc}",
            no_wrap=True,
        )

    console.print(
        f"  [dim]{'─' * min(term_width - 4, 100)}[/dim]"
    )
    info(f"{len(modules)} module(s) matched  [dim]·  ✱ = destructive[/dim]")


# ── info command (alias for module-info using registry) ───────────────────────

@click.command("info", cls=LoggedCommand)
@click.argument("module_id")
def info_cmd(module_id: str) -> None:
    """Show detailed metadata for a registered module (includes plugins).

    This is the registry-aware version of module-info.
    """
    from blue_tap.framework.registry import get_registry

    registry = get_registry()
    descriptor = registry.try_get(module_id)

    if not descriptor:
        error(f"Module not found: {module_id}")
        info("Run [bold]blue-tap list-modules[/bold] to see available modules.")
        return

    from blue_tap.utils.output import CYAN

    console.print()
    console.print(
        f"  [bold]{descriptor.name}[/bold]  "
        f"[bt.dim]{descriptor.module_id}[/bt.dim]"
    )
    console.print(f"  [bt.dim]{'─' * 62}[/bt.dim]")
    console.print()

    rows = [
        ("family",    descriptor.family.value),
        ("description", descriptor.description),
        ("protocols", ", ".join(descriptor.protocols) if descriptor.protocols else "—"),
        ("requires",  ", ".join(descriptor.requires) if descriptor.requires else "—"),
        ("destructive", "[bt.red]yes[/bt.red]" if descriptor.destructive else "[bt.dim]no[/bt.dim]"),
        ("pairing",   "yes" if descriptor.requires_pairing else "[bt.dim]no[/bt.dim]"),
    ]
    if descriptor.references:
        rows.append(("references", "  ".join(descriptor.references)))
    if getattr(descriptor, "category", None):
        rows.append(("category", descriptor.category))
    rows.append(("report adapter", "yes" if descriptor.has_report_adapter else "[bt.dim]no[/bt.dim]"))

    key_width = 16
    for key, val in rows:
        console.print(f"  [bt.dim]{key.ljust(key_width)}[/bt.dim]  {val}")

    console.print()
    console.print(f"  [bt.dim]run:[/bt.dim]  blue-tap run {descriptor.module_id} RHOST=...")
    console.print()
