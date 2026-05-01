"""Shared module invocation helper for CLI facade commands."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_MAC_ADDRESS_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def _is_dry_run() -> bool:
    """Resolve dry-run state from Click context or ``$BLUE_TAP_DRY_RUN``."""
    import os
    try:
        import rich_click as click
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            obj = ctx.find_object(dict) or {}
            if obj.get("dry_run"):
                return True
    except Exception:
        pass
    return os.environ.get("BLUE_TAP_DRY_RUN", "").lower() in ("1", "true", "yes")


def invoke(
    module_id: str,
    options: dict[str, str],
    *,
    confirm_destructive: bool = False,
) -> dict | None:
    from blue_tap.framework.module import (
        DestructiveConfirmationRequired,
        EntryPointResolutionError,
        Invoker,
        ModuleNotFound,
        NotAModule,
    )
    from blue_tap.framework.module.options import OptionError
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.sessions.store import get_session
    from blue_tap.hardware.adapter import resolve_active_hci
    from blue_tap.utils.output import error, info, warning

    dry_run = _is_dry_run()
    session = None if dry_run else get_session()

    registry = get_registry()
    descriptor = registry.try_get(module_id)
    if not descriptor:
        error(f"Module not found: {module_id}")
        return None

    if "RHOST" not in options:
        _target_requires = {"classic_target", "ble_target", "target"}
        if _target_requires & set(descriptor.requires):
            if dry_run:
                # Don't block on interactive picker during a no-op preview.
                options["RHOST"] = "AA:BB:CC:DD:EE:FF"
            else:
                from blue_tap.utils.interactive import resolve_address

                _hci = options.get("HCI") or resolve_active_hci()
                resolved = resolve_address(
                    None, prompt=f"Select target for {descriptor.name}", hci=_hci
                )
                if not resolved:
                    return None
                options["RHOST"] = resolved

    if "HCI" not in options and not dry_run:
        try:
            options["HCI"] = resolve_active_hci()
        except Exception:
            pass  # Some modules don't need HCI

    if dry_run:
        info(f"[bt.yellow]Dry-run:[/bt.yellow] would run [bold cyan]{descriptor.name}[/bold cyan]")
    else:
        info(f"Running: [bold cyan]{descriptor.name}[/bold cyan]")

    if descriptor.destructive and not confirm_destructive and not dry_run:
        warning("[bt.red]Destructive module![/bt.red] Use --yes to confirm.")
        return None

    invoker = Invoker(safety_override=confirm_destructive or dry_run)
    try:
        envelope = invoker.invoke_with_logging(
            module_id, options, session=session, dry_run=dry_run,
        )
        summary = envelope.get("summary", {})
        if summary:
            info(f"Result: {summary}")
        return envelope
    except ModuleNotFound as e:
        error(str(e))
    except DestructiveConfirmationRequired as e:
        error(str(e))
    except (EntryPointResolutionError, NotAModule) as e:
        error(f"Module error: {e}")
    except Exception as e:
        if isinstance(e, OptionError):
            error(f"Missing required option: {e}")
        else:
            error(f"Module execution failed: {e}")
            logger.exception("Module execution error")
    return None


def invoke_or_exit(
    module_id: str,
    options: dict[str, str],
    *,
    confirm_destructive: bool = False,
) -> dict:
    """Invoke a module; raise SystemExit(1) if it fails.

    Use this in CLI facade commands (vulnscan, dos, exploit, etc.) where
    a failed module run should result in a non-zero exit code.  The
    ``auto`` command uses plain ``invoke()`` instead because it handles
    partial failures across multiple phases.
    """
    result = invoke(module_id, options, confirm_destructive=confirm_destructive)
    if result is None:
        raise SystemExit(1)
    return result


def resolve_target(
    target: str | None,
    *,
    hci: str | None = None,
    prompt: str = "Select target",
) -> str | None:
    """Resolve a target address, offering interactive picker if None or not a MAC."""
    if target and _MAC_ADDRESS_RE.match(target):
        return target
    from blue_tap.utils.interactive import resolve_address
    from blue_tap.hardware.adapter import resolve_active_hci

    _hci = hci or resolve_active_hci()
    return resolve_address(None, prompt=prompt, hci=_hci)
