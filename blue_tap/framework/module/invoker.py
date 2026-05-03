"""Module invoker: resolves module_id to class, validates options, and runs."""

from __future__ import annotations

import importlib
import logging
import signal
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from blue_tap.framework.module.base import Module

from blue_tap.framework.registry import get_registry

logger = logging.getLogger(__name__)


class ModuleTimeout(Exception):
    """Raised when ``Module.run()`` exceeds its descriptor's ``default_timeout``.

    On the production path (Linux + main thread) this is delivered via
    ``SIGALRM`` from inside the module's own call stack — ``finally`` blocks,
    context managers, and ``Module.cleanup(ctx)`` all run normally as the
    exception unwinds, so sockets/D-Bus connections are released.

    The threaded-watchdog fallback (non-Linux, or invocation from a non-main
    thread) cannot truly interrupt the worker — Python forbids forcibly
    killing threads. In that mode the worker is abandoned (it remains a
    daemon thread that will die with the process) and any resources it holds
    leak until then. ``Invoker._run_with_timeout`` logs a warning when this
    fallback is engaged so operators are not surprised.
    """

    def __init__(self, module_id: str, timeout: float) -> None:
        self.module_id = module_id
        self.timeout = timeout
        super().__init__(f"Module {module_id!r} exceeded {timeout}s timeout")


class ModuleNotFound(Exception):
    """Raised when a module_id is not in the registry."""

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id
        super().__init__(f"Module not found: {module_id}")


class EntryPointResolutionError(Exception):
    """Raised when the entry_point cannot be imported or resolved."""

    def __init__(self, entry_point: str, reason: str) -> None:
        self.entry_point = entry_point
        self.reason = reason
        super().__init__(f"Cannot resolve '{entry_point}': {reason}")


class NotAModule(Exception):
    """Raised when entry_point resolves to a non-Module class."""

    def __init__(self, entry_point: str, actual_type: str) -> None:
        self.entry_point = entry_point
        self.actual_type = actual_type
        super().__init__(f"'{entry_point}' is {actual_type}, not a Module subclass")


class DestructiveConfirmationRequired(Exception):
    """Raised when a destructive module is invoked without CONFIRM=yes."""

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id
        super().__init__(f"Module '{module_id}' is destructive. Add CONFIRM=yes to proceed.")


@dataclass(slots=True)
class Invoker:
    """Resolves and invokes modules by module_id.

    Usage:
        invoker = Invoker()
        envelope = invoker.invoke("exploitation.knob", {"RHOST": "AA:BB:CC:DD:EE:FF"})
    """

    safety_override: bool = False

    def resolve(self, module_id: str) -> type[Module]:
        """Resolve module_id to a Module class.

        Returns:
            The Module subclass.

        Raises:
            ModuleNotFound: If module_id is not registered.
            EntryPointResolutionError: If import fails.
            NotAModule: If resolved class is not a Module subclass.
        """
        from blue_tap.framework.module.base import Module

        desc = get_registry().try_get(module_id)
        if desc is None:
            raise ModuleNotFound(module_id)

        try:
            module_path, class_name = desc.entry_point.split(":")
            module_obj = importlib.import_module(module_path)
            cls = getattr(module_obj, class_name)
        except ImportError as e:
            raise EntryPointResolutionError(desc.entry_point, f"import failed: {e}")
        except (ValueError, AttributeError) as e:
            raise EntryPointResolutionError(desc.entry_point, str(e))

        if not isinstance(cls, type):
            raise NotAModule(desc.entry_point, type(cls).__name__)
        # Accept Module subclasses or duck-typed classes with _is_blue_tap_module
        from blue_tap.framework.module.base import Module as _Module
        if not (issubclass(cls, _Module) or getattr(cls, "_is_blue_tap_module", False)):
            raise NotAModule(desc.entry_point, type(cls).__name__)

        return cls

    def invoke(
        self,
        module_id: str,
        raw_options: dict[str, Any] | None = None,
        *,
        session: Any = None,
        dry_run: bool = False,
    ) -> dict:
        """Invoke a module by ID.

        Args:
            module_id: Module identifier (e.g., "exploitation.knob").
            raw_options: Dict of option values (strings from CLI or native types).
            session: Optional Session for artifact storage.
            dry_run: If True, return a synthesized "planned" envelope without
                executing the module's run() (unless the module sets
                ``supports_dry_run = True``, in which case run() is invoked
                with ``ctx.dry_run = True`` and the module is responsible for
                honoring it).

        Returns:
            RunEnvelope dict produced by the module's ``run()``.

        Raises:
            ModuleNotFound: If module_id is not registered.
            EntryPointResolutionError: If entry_point cannot be resolved.
            NotAModule: If resolved class is not a Module.
            DestructiveConfirmationRequired: If destructive without CONFIRM=yes.
                Bypassed when ``dry_run=True``.
            OptionError: If option validation fails.
        """
        from blue_tap.framework.module.context import RunContext
        from blue_tap.framework.module.options_container import OptionsContainer
        from blue_tap.hardware.adapter import resolve_active_hci

        raw_options = dict(raw_options or {})

        # Get descriptor for metadata
        desc = get_registry().try_get(module_id)
        if desc is None:
            raise ModuleNotFound(module_id)

        # Destructive safety gate — bypassed in dry-run since the run is a no-op.
        if desc.destructive and not self.safety_override and not dry_run:
            confirm = str(raw_options.get("CONFIRM", "")).lower()
            if confirm not in ("yes", "true", "1"):
                raise DestructiveConfirmationRequired(module_id)

        # Inject the active HCI (RTL8761B / DarkFirmware-aware) into raw_options
        # when the caller didn't pass one. Module-level OptString defaults are
        # now empty, so the real dongle HCI (e.g. hci4) is injected here.
        # Skip in dry-run — synthesized envelope shouldn't probe hardware.
        if not raw_options.get("HCI") and not dry_run:
            raw_options["HCI"] = resolve_active_hci()

        # Resolve and instantiate
        cls = self.resolve(module_id)
        instance = cls()

        # Second-pass injection for module-specific adapter option names
        # (e.g. CLASSIC_HCI in reconnaissance.prerequisites).
        schema_names = {opt.name for opt in getattr(instance, "options", ())}
        if "CLASSIC_HCI" in schema_names and not raw_options.get("CLASSIC_HCI"):
            raw_options["CLASSIC_HCI"] = raw_options.get("HCI", "")

        # Build options container and validate
        options = OptionsContainer.from_schema(instance.options)
        options.populate(raw_options)

        adapter = options.get("HCI") or raw_options.get("HCI", "")
        target = raw_options.get("RHOST", "")

        ctx = RunContext.create(
            options=options,
            module_id=module_id,
            session=session,
            adapter=str(adapter),
            target=str(target),
            dry_run=dry_run,
        )

        # Default-modular dry-run: short-circuit modules that haven't opted in
        # to ``supports_dry_run``. Synthesize a "planned" envelope from the
        # descriptor + resolved options. The module is never executed.
        if dry_run and not getattr(instance, "supports_dry_run", False):
            envelope = _build_planned_envelope(desc, ctx, raw_options)
            ctx.emit_event(
                "dry_run_planned",
                f"Dry-run: would invoke {module_id}",
                details={"module_id": module_id, "destructive": desc.destructive},
            )
            return envelope

        ctx.emit_run_started()
        timeout = float(desc.default_timeout or 0)
        try:
            if timeout > 0:
                envelope = _run_with_timeout(instance, ctx, module_id, timeout)
            else:
                envelope = instance.run(ctx)
            ctx.emit_run_completed()
            return envelope
        except Exception as e:
            ctx.emit_run_error(e)
            raise
        finally:
            try:
                instance.cleanup(ctx)
            except Exception as cleanup_err:
                logger.warning("Cleanup error for %s: %s", module_id, cleanup_err)

    def invoke_with_logging(
        self,
        module_id: str,
        raw_options: dict[str, Any] | None = None,
        *,
        session: Any = None,
        dry_run: bool = False,
    ) -> dict:
        """Invoke a module and log the result to the session.

        Session logging is skipped entirely when ``dry_run=True`` — a no-op
        preview is not worth persisting to artefact storage.
        """
        envelope = self.invoke(module_id, raw_options, session=session, dry_run=dry_run)

        if session and envelope and not dry_run:
            try:
                from blue_tap.framework.sessions.store import get_session, set_session

                cmd = f"run {module_id}"
                previous = get_session()
                set_session(session)
                try:
                    session.log(
                        cmd,
                        envelope,
                        category=_infer_log_category(envelope),
                        target=str(envelope.get("target", "")),
                    )
                finally:
                    set_session(previous)
            except Exception as e:
                logger.warning("Failed to log command: %s", e)

        return envelope


def _can_use_sigalrm() -> bool:
    """Return True iff SIGALRM-based timeout is available in the current context.

    Requires: a Unix-like platform with SIGALRM, an importable ``setitimer``,
    and the caller running on the main thread (signal handlers are
    main-thread-only in CPython).
    """
    return (
        hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )


def _run_with_sigalrm(instance: Any, ctx: Any, module_id: str, timeout: float) -> dict:
    """Run ``instance.run(ctx)`` under a SIGALRM-based timer.

    On overrun the alarm handler raises :class:`ModuleTimeout` from inside
    ``run``'s own call stack, so ``finally`` blocks, context managers, and
    ``Module.cleanup(ctx)`` (invoked by the caller) all execute against the
    correct frames and release resources.
    """
    def _on_alarm(signum, frame):
        raise ModuleTimeout(module_id, timeout)

    old_handler = signal.signal(signal.SIGALRM, _on_alarm)
    # ``setitimer`` accepts sub-second precision; ``alarm`` does not.
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return instance.run(ctx)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


def _run_with_thread_watchdog(instance: Any, ctx: Any, module_id: str, timeout: float) -> dict:
    """Fallback timeout for non-Linux or non-main-thread invocation.

    Python cannot forcibly kill a thread, so on timeout the worker is left
    as a daemon thread that will die with the process. Any sockets or
    D-Bus connections it holds leak until then. A warning is logged so this
    is visible.
    """
    logger.warning(
        "Module %s: SIGALRM-based timeout unavailable in current context; "
        "using thread watchdog (hung worker will leak resources until process exit)",
        module_id,
    )

    holder: dict[str, Any] = {}

    def _worker() -> None:
        try:
            holder["envelope"] = instance.run(ctx)
        except BaseException as exc:  # noqa: BLE001 — propagate any failure mode
            holder["exc"] = exc

    worker = threading.Thread(
        target=_worker,
        name=f"blue-tap-module-{module_id}",
        daemon=True,
    )
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        raise ModuleTimeout(module_id, timeout)

    if "exc" in holder:
        raise holder["exc"]
    return holder["envelope"]


def _run_with_timeout(instance: Any, ctx: Any, module_id: str, timeout: float) -> dict:
    """Dispatch to the strongest timeout mechanism available."""
    if _can_use_sigalrm():
        return _run_with_sigalrm(instance, ctx, module_id, timeout)
    return _run_with_thread_watchdog(instance, ctx, module_id, timeout)


def _build_planned_envelope(desc: Any, ctx: Any, raw_options: dict[str, Any]) -> dict:
    """Synthesize a planned envelope (outcome=not_applicable) for default-modular dry-run."""
    from blue_tap.framework.contracts.result_schema import (
        build_run_envelope,
        make_evidence,
        make_execution,
    )

    # Hide CONFIRM and any value containing "secret"/"password"/"key" from logs.
    safe_options = {
        k: v for k, v in raw_options.items()
        if k.upper() not in {"CONFIRM"}
        and not any(s in k.lower() for s in ("secret", "password", "passwd"))
    }

    schema_prefix = desc.schema_prefix or f"blue_tap.{desc.family.value}.result"
    module_short = desc.module_id.split(".", 1)[-1]

    execution = make_execution(
        kind="phase",
        id="dry_run",
        title=f"Planned invocation of {desc.name}",
        module=module_short,
        module_id=desc.module_id,
        protocol=desc.protocols[0] if desc.protocols else "",
        execution_status="skipped",
        module_outcome="not_applicable",
        evidence=make_evidence(
            summary=f"Dry-run: {desc.name} would have been invoked.",
            confidence="high",
            observations=[
                f"target={ctx.target or '(none)'}",
                f"adapter={ctx.adapter or '(none)'}",
                f"destructive={desc.destructive}",
                f"requires_pairing={desc.requires_pairing}",
            ],
            module_evidence={"resolved_options": safe_options},
        ),
        destructive=desc.destructive,
        requires_pairing=desc.requires_pairing,
        started_at=ctx.started_at,
    )

    return build_run_envelope(
        schema=schema_prefix,
        module=module_short,
        module_id=desc.module_id,
        target=ctx.target,
        adapter=ctx.adapter,
        operator_context={"dry_run": True},
        summary={
            "outcome": "not_applicable",
            "dry_run": True,
            "destructive": desc.destructive,
        },
        executions=[execution],
        artifacts=[],
        module_data={
            "dry_run": True,
            "module_id": desc.module_id,
            "family": desc.family.value,
        },
        run_id=ctx.run_id,
        started_at=ctx.started_at,
    )


def _infer_log_category(envelope: dict) -> str:
    """Best-effort category inference from a run envelope."""
    schema = str(envelope.get("schema", ""))
    if not schema:
        return "general"
    # schema prefix convention: blue_tap.<category>.result
    parts = schema.split(".")
    if len(parts) >= 2:
        return parts[1]
    return "general"
