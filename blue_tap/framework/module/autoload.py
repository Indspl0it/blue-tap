"""Module autoloader — registers built-in modules on import.

Importing each family package triggers __init_subclass__ registration
for all Module subclasses defined within that family.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Track which families have been autoloaded
_autoloaded_families: set[str] = set()


def autoload_builtin_modules() -> int:
    """Import every built-in family package to trigger Module auto-registration.

    Returns:
        Number of modules registered during this call (excluding re-registered ones).

    This function is idempotent — safe to call multiple times.
    """
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.module.loader import load_plugins

    # Count modules before autoloading
    before_count = len(get_registry().list_all())

    # Import each family package (their __init__.py import module files)
    # which triggers __init_subclass__ registration for Module subclasses
    families = [
        "blue_tap.modules.discovery",
        "blue_tap.modules.reconnaissance",
        "blue_tap.modules.assessment",
        "blue_tap.modules.exploitation",
        "blue_tap.modules.post_exploitation",
        "blue_tap.modules.fuzzing",
    ]

    for family in families:
        if family in _autoloaded_families:
            continue
        try:
            __import__(family)
            _autoloaded_families.add(family)
            logger.debug("Autoloaded family: %s", family)
        except ImportError as e:
            logger.warning("Failed to autoload family %s: %s", family, e)

    # Load external plugins
    loaded, failed = load_plugins()
    if failed:
        for plugin_name, error in failed.items():
            logger.warning("Plugin '%s' failed to load: %s", plugin_name, error)

    # Count modules after
    after_count = len(get_registry().list_all())

    logger.info("Autoload complete: %d modules registered", after_count)
    return after_count - before_count


def get_autoloaded_families() -> set[str]:
    """Return the set of families that have been autoloaded."""
    return _autoloaded_families.copy()


