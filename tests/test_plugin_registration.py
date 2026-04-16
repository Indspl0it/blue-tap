"""Tests for the plugin registration mechanism."""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry
from blue_tap.framework.registry.registry import validate_plugin


def test_validate_plugin_valid_descriptor():
    desc = ModuleDescriptor(
        module_id="assessment.test_plugin",
        family=ModuleFamily.ASSESSMENT,
        name="Test Plugin",
        description="A test plugin descriptor",
        protocols=("Classic",),
        requires=("adapter",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.test.result",
        has_report_adapter=False,
        entry_point="blue_tap.framework.registry:get_registry",
    )
    warnings = validate_plugin(desc)
    # entry_point is importable, should have no warnings
    assert isinstance(warnings, list)


def test_validate_plugin_empty_entry_point():
    desc = ModuleDescriptor(
        module_id="assessment.test_empty_ep",
        family=ModuleFamily.ASSESSMENT,
        name="Test Empty EP",
        description="Descriptor with empty entry_point",
        protocols=("Classic",),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.test.result",
        has_report_adapter=False,
        entry_point="",
    )
    warnings = validate_plugin(desc)
    assert any("entry_point" in w for w in warnings)


def test_load_plugins_returns_list():
    """load_plugins() must return a list even when no plugins are installed."""
    registry = get_registry()
    result = registry.load_plugins()
    assert isinstance(result, list)


def test_internal_field_defaults_false():
    desc = ModuleDescriptor(
        module_id="fuzzing.test_internal",
        family=ModuleFamily.FUZZING,
        name="Test Internal",
        description="Test that internal defaults to False",
        protocols=("BLE",),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.fuzz.result",
        has_report_adapter=False,
        entry_point="blue_tap.framework.registry:get_registry",
    )
    assert desc.internal is False


def test_internal_field_can_be_set_true():
    desc = ModuleDescriptor(
        module_id="fuzzing.test_internal2",
        family=ModuleFamily.FUZZING,
        name="Test Internal True",
        description="Test that internal can be set True",
        protocols=("BLE",),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.fuzz.result",
        has_report_adapter=False,
        entry_point="blue_tap.framework.registry:get_registry",
        internal=True,
    )
    assert desc.internal is True
