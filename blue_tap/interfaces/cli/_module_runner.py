"""Shared module invocation helper for CLI facade commands."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


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

    session = get_session()

    registry = get_registry()
    descriptor = registry.try_get(module_id)
    if not descriptor:
        error(f"Module not found: {module_id}")
        return None

    if "RHOST" not in options:
        _target_requires = {"classic_target", "ble_target", "target"}
        if _target_requires & set(descriptor.requires):
            from blue_tap.utils.interactive import resolve_address

            _hci = options.get("HCI") or resolve_active_hci()
            resolved = resolve_address(
                None, prompt=f"Select target for {descriptor.name}", hci=_hci
            )
            if not resolved:
                return None
            options["RHOST"] = resolved

    if "HCI" not in options:
        try:
            options["HCI"] = resolve_active_hci()
        except Exception:
            pass  # Some modules don't need HCI

    info(f"Running: [bold cyan]{descriptor.name}[/bold cyan]")

    if descriptor.destructive and not confirm_destructive:
        warning("[bt.red]Destructive module![/bt.red] Use --yes to confirm.")
        return None

    invoker = Invoker(safety_override=confirm_destructive)
    try:
        envelope = invoker.invoke_with_logging(module_id, options, session=session)
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


def resolve_target(
    target: str | None,
    *,
    hci: str | None = None,
    prompt: str = "Select target",
) -> str | None:
    """Resolve a target address, offering interactive picker if None."""
    if target:
        return target
    from blue_tap.utils.interactive import resolve_address
    from blue_tap.hardware.adapter import resolve_active_hci

    _hci = hci or resolve_active_hci()
    return resolve_address(None, prompt=prompt, hci=_hci)
