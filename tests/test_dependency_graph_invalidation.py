import sys
import types

# Stub fcntl on Windows so registry imports cleanly.
if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.ModuleType("fcntl")


def test_register_invalidates_dependency_graph_cache():
    """A late register() call must invalidate the graph cache so the new module appears."""
    from blue_tap.framework.module import autoload_builtin_modules
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.registry.dependency_graph import _cache, get_dependencies, reset_cache
    from blue_tap.framework.registry.descriptors import ModuleDescriptor
    from blue_tap.framework.registry.families import ModuleFamily

    autoload_builtin_modules()
    reset_cache()

    # Build the cache once.
    get_dependencies("nonexistent.module")
    assert _cache.built is True

    # Register a new descriptor — the cache must be invalidated.
    descriptor = ModuleDescriptor(
        module_id="assessment.test_invalidation",
        family=ModuleFamily.ASSESSMENT,
        name="test_invalidation",
        description="cache invalidation probe",
        protocols=(),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="assessment",
        has_report_adapter=False,
        entry_point="blue_tap.framework.module.base:Module",
    )

    registry = get_registry()
    try:
        registry.register(descriptor)
        assert _cache.built is False, "register() must reset dependency graph cache"
    finally:
        registry.unregister("assessment.test_invalidation")


def test_unregister_invalidates_dependency_graph_cache():
    """unregister() must also invalidate the graph cache."""
    from blue_tap.framework.module import autoload_builtin_modules
    from blue_tap.framework.registry import get_registry
    from blue_tap.framework.registry.dependency_graph import _cache, get_dependencies, reset_cache
    from blue_tap.framework.registry.descriptors import ModuleDescriptor
    from blue_tap.framework.registry.families import ModuleFamily

    autoload_builtin_modules()
    reset_cache()

    descriptor = ModuleDescriptor(
        module_id="assessment.test_unreg",
        family=ModuleFamily.ASSESSMENT,
        name="test_unreg",
        description="unregister probe",
        protocols=(),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="assessment",
        has_report_adapter=False,
        entry_point="blue_tap.framework.module.base:Module",
    )

    registry = get_registry()
    registry.register(descriptor)
    get_dependencies("nonexistent.module")  # rebuild cache
    assert _cache.built is True

    registry.unregister("assessment.test_unreg")
    assert _cache.built is False, "unregister() must reset dependency graph cache"
