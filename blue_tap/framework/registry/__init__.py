"""Module discovery, metadata descriptors, and family registration."""

from blue_tap.framework.registry.descriptors import ModuleDescriptor
from blue_tap.framework.registry.families import FAMILY_OUTCOMES, ModuleFamily
from blue_tap.framework.registry.registry import ModuleRegistry, get_registry, validate_plugin

__all__ = [
    "FAMILY_OUTCOMES",
    "ModuleDescriptor",
    "ModuleFamily",
    "ModuleRegistry",
    "get_registry",
    "load_plugins",
    "validate_plugin",
]


def load_plugins() -> list[str]:
    """Convenience wrapper: load plugins into the global registry."""
    return get_registry().load_plugins()
