"""Module registry for Blue-Tap framework."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blue_tap.framework.registry.descriptors import ModuleDescriptor

from blue_tap.framework.registry.families import ModuleFamily

logger = logging.getLogger(__name__)


class ModuleRegistry:
    """Central registry of all Blue-Tap modules."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleDescriptor] = {}

    def register(self, descriptor: ModuleDescriptor) -> None:
        if descriptor.module_id in self._modules:
            raise ValueError(f"Duplicate module_id: {descriptor.module_id!r}")
        self._modules[descriptor.module_id] = descriptor
        logger.debug("Registered module %s", descriptor.module_id)

    def get(self, module_id: str) -> ModuleDescriptor:
        return self._modules[module_id]

    def try_get(self, module_id: str) -> "ModuleDescriptor | None":
        return self._modules.get(module_id)

    def list_all(self) -> list[ModuleDescriptor]:
        return sorted(self._modules.values(), key=lambda d: d.module_id)

    def list_family(self, family: ModuleFamily) -> list[ModuleDescriptor]:
        return [d for d in self.list_all() if d.family == family]

    def list_families(self) -> list[ModuleFamily]:
        return sorted({d.family for d in self._modules.values()}, key=lambda f: f.value)

    def find_by_protocol(self, protocol: str) -> list[ModuleDescriptor]:
        return [d for d in self.list_all() if protocol in d.protocols]

    def find_destructive(self) -> list[ModuleDescriptor]:
        return [d for d in self.list_all() if d.destructive]

    def load_plugins(self) -> list[str]:
        """Load and register modules from 'blue_tap.modules' entry points.

        Returns list of module_ids successfully registered.
        Third-party packages advertise modules via:
            [project.entry-points."blue_tap.modules"]
            my-module = "my_package:DESCRIPTOR"
        where DESCRIPTOR is a ModuleDescriptor instance.
        """
        import importlib.metadata

        from blue_tap.framework.registry.descriptors import ModuleDescriptor as _ModuleDescriptor

        loaded = []
        try:
            eps = importlib.metadata.entry_points(group="blue_tap.modules")
        except Exception:
            return loaded
        for ep in eps:
            try:
                descriptor = ep.load()
                if not isinstance(descriptor, _ModuleDescriptor):
                    logger.warning(
                        "Plugin entry point %r did not return a ModuleDescriptor (got %s)",
                        ep.name,
                        type(descriptor).__name__,
                    )
                    continue
                warnings = validate_plugin(descriptor)
                for w in warnings:
                    logger.warning("Plugin %r: %s", descriptor.module_id, w)
                self.register(descriptor)
                loaded.append(descriptor.module_id)
                logger.info("Loaded plugin module %s from entry point %r", descriptor.module_id, ep.name)
            except Exception as exc:
                logger.error("Failed to load plugin entry point %r: %s", ep.name, exc)
        return loaded


_global_registry: ModuleRegistry | None = None


def get_registry() -> ModuleRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = ModuleRegistry()
    return _global_registry


def validate_plugin(descriptor: ModuleDescriptor) -> list[str]:
    """Validate a plugin descriptor. Returns list of warnings (not errors)."""
    warnings = []
    if not descriptor.entry_point:
        warnings.append("entry_point is empty — module cannot be invoked")
    if not descriptor.schema_prefix:
        warnings.append("schema_prefix is empty — report generation may fail")
    if descriptor.entry_point:
        module_path = descriptor.entry_point.split(":")[0]
        try:
            __import__(module_path)
        except ImportError:
            warnings.append(f"entry_point module '{module_path}' is not importable")
    return warnings
