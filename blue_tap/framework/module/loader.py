"""Plugin loader — discovers and loads external plugin modules.

Plugins are external packages that register Module subclasses via
the `blue_tap.modules` entry point group.

Example plugin pyproject.toml:
    [project.entry-points."blue_tap.modules"]
    my_plugin = "my_plugin.modules"

When loaded, the plugin's module is imported, triggering __init_subclass__
registration for any Module subclasses defined within.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Plugin registry: tracks loaded plugins and their state
_plugin_registry: dict[str, dict[str, Any]] = {}


def get_plugin_registry() -> dict[str, dict[str, Any]]:
    """Get the plugin registry (loaded plugins and their metadata).

    Returns:
        Dict mapping plugin names to their metadata:
        {
            "plugin_name": {
                "loaded": bool,
                "error": str | None,
                "module_count": int,
                "modules": list[str],  # module_ids
                "entry_point": str,
            }
        }
    """
    return _plugin_registry


def discover_plugins() -> dict[str, str]:
    """Discover available plugins via entry points.

    Returns:
        Dict mapping plugin names to their entry point values.
    """
    try:
        import importlib.metadata as importlib_metadata
    except ImportError:
        import importlib_metadata  # type: ignore

    discovered = {}

    try:
        for ep in importlib_metadata.entry_points(group="blue_tap.modules"):
            discovered[ep.name] = ep.value
    except Exception as e:
        logger.debug("Failed to discover plugins: %s", e)

    return discovered


def load_plugins(reload: bool = False) -> tuple[list[str], dict[str, str]]:
    """Load plugins from entry points.

    Args:
        reload: If True, clear existing plugin registry and reload all.

    Returns:
        Tuple of (loaded_names, failed_dict) where failed_dict maps
        plugin names to error messages.
    """
    global _plugin_registry

    try:
        import importlib.metadata as importlib_metadata
    except ImportError:
        import importlib_metadata  # type: ignore

    if reload:
        _plugin_registry.clear()

    from blue_tap.framework.registry import get_registry

    loaded = []
    failed = {}

    try:
        entry_points = list(importlib_metadata.entry_points(group="blue_tap.modules"))
    except Exception as e:
        logger.debug("No plugin entry points found: %s", e)
        return loaded, failed

    for ep in entry_points:
        if ep.name in _plugin_registry and not reload:
            continue

        # Track modules registered by this plugin
        registry = get_registry()
        before_ids = {d.module_id for d in registry.list_all()}

        try:
            # Load the plugin module
            module = ep.load()

            # Find new modules registered by this plugin
            after_ids = {d.module_id for d in registry.list_all()}
            new_ids = after_ids - before_ids

            _plugin_registry[ep.name] = {
                "loaded": True,
                "error": None,
                "module_count": len(new_ids),
                "modules": sorted(new_ids),
                "entry_point": ep.value,
            }

            loaded.append(ep.name)
            logger.info("Loaded plugin '%s' with %d module(s)", ep.name, len(new_ids))

        except Exception as e:
            error_msg = str(e)
            _plugin_registry[ep.name] = {
                "loaded": False,
                "error": error_msg,
                "module_count": 0,
                "modules": [],
                "entry_point": ep.value,
            }

            failed[ep.name] = error_msg
            logger.warning("Failed to load plugin '%s': %s", ep.name, e)

    return loaded, failed


def get_plugin_for_module(module_id: str) -> str | None:
    """Get the plugin name that registered a specific module.

    Returns:
        Plugin name, or None if the module was not registered by a plugin.
    """
    for plugin_name, plugin_data in _plugin_registry.items():
        if module_id in plugin_data.get("modules", []):
            return plugin_name
    return None
