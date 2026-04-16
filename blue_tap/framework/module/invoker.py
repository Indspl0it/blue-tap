"""Module invoker: resolves module_id to class, validates options, and runs."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from blue_tap.framework.module.base import Module

from blue_tap.framework.registry import get_registry

logger = logging.getLogger(__name__)


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
    ) -> dict:
        """Invoke a module by ID.

        Args:
            module_id: Module identifier (e.g., "exploitation.knob").
            raw_options: Dict of option values (strings from CLI or native types).
            session: Optional Session for artifact storage.

        Returns:
            RunEnvelope dict produced by the module's ``run()``.

        Raises:
            ModuleNotFound: If module_id is not registered.
            EntryPointResolutionError: If entry_point cannot be resolved.
            NotAModule: If resolved class is not a Module.
            DestructiveConfirmationRequired: If destructive without CONFIRM=yes.
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

        # Destructive safety gate
        if desc.destructive and not self.safety_override:
            confirm = str(raw_options.get("CONFIRM", "")).lower()
            if confirm not in ("yes", "true", "1"):
                raise DestructiveConfirmationRequired(module_id)

        # Inject the active HCI (RTL8761B / DarkFirmware-aware) into raw_options
        # when the caller didn't pass one. Module-level OptString defaults are
        # now empty, so the real dongle HCI (e.g. hci4) is injected here.
        if not raw_options.get("HCI"):
            raw_options["HCI"] = resolve_active_hci()

        # Resolve and instantiate
        cls = self.resolve(module_id)
        instance = cls()

        # Second-pass injection for module-specific adapter option names
        # (e.g. CLASSIC_HCI in reconnaissance.prerequisites).
        schema_names = {opt.name for opt in getattr(instance, "options", ())}
        if "CLASSIC_HCI" in schema_names and not raw_options.get("CLASSIC_HCI"):
            raw_options["CLASSIC_HCI"] = raw_options["HCI"]

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
        )

        ctx.emit_run_started()
        try:
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
    ) -> dict:
        """Invoke a module and log the result to the session."""
        envelope = self.invoke(module_id, raw_options, session=session)

        if session and envelope:
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
