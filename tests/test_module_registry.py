"""Tests for Blue-Tap module registry (Phase 3)."""

import importlib

import pytest

from blue_tap.framework.registry.descriptors import ModuleDescriptor
from blue_tap.framework.registry.families import ModuleFamily
from blue_tap.framework.registry.registry import ModuleRegistry


def _make_descriptor(**overrides):
    defaults = {
        "module_id": "exploitation.test",
        "family": ModuleFamily.EXPLOITATION,
        "name": "Test Module",
        "description": "A test module",
        "protocols": ("Classic",),
        "requires": ("adapter",),
        "destructive": False,
        "requires_pairing": False,
        "schema_prefix": "blue_tap.test.result",
        "has_report_adapter": False,
        "entry_point": "blue_tap.modules.exploitation.test:TestModule",
    }
    defaults.update(overrides)
    return ModuleDescriptor(**defaults)


def test_register_and_get_module():
    registry = ModuleRegistry()
    desc = _make_descriptor()
    registry.register(desc)
    result = registry.get("exploitation.test")
    assert result.module_id == "exploitation.test"
    assert result.family == ModuleFamily.EXPLOITATION
    assert result.name == "Test Module"
    assert result.description == "A test module"
    assert result.protocols == ("Classic",)
    assert result.requires == ("adapter",)
    assert result.destructive is False
    assert result.requires_pairing is False
    assert result.schema_prefix == "blue_tap.test.result"
    assert result.has_report_adapter is False
    assert result.entry_point == "blue_tap.modules.exploitation.test:TestModule"


def test_duplicate_registration_raises():
    registry = ModuleRegistry()
    desc = _make_descriptor()
    registry.register(desc)
    with pytest.raises(ValueError, match="Duplicate module_id"):
        registry.register(desc)


def test_list_family_returns_only_family_modules():
    registry = ModuleRegistry()
    registry.register(_make_descriptor(module_id="exploitation.test", family=ModuleFamily.EXPLOITATION))
    registry.register(_make_descriptor(module_id="assessment.check_one", family=ModuleFamily.ASSESSMENT))
    registry.register(_make_descriptor(module_id="fuzzing.engine", family=ModuleFamily.FUZZING))

    exploitation_modules = registry.list_family(ModuleFamily.EXPLOITATION)
    assert len(exploitation_modules) == 1
    assert exploitation_modules[0].module_id == "exploitation.test"

    assessment_modules = registry.list_family(ModuleFamily.ASSESSMENT)
    assert len(assessment_modules) == 1
    assert assessment_modules[0].module_id == "assessment.check_one"

    fuzzing_modules = registry.list_family(ModuleFamily.FUZZING)
    assert len(fuzzing_modules) == 1
    assert fuzzing_modules[0].module_id == "fuzzing.engine"


def test_find_by_protocol():
    registry = ModuleRegistry()
    registry.register(_make_descriptor(
        module_id="exploitation.test",
        family=ModuleFamily.EXPLOITATION,
        protocols=("Classic", "L2CAP"),
    ))
    registry.register(_make_descriptor(
        module_id="assessment.check_one",
        family=ModuleFamily.ASSESSMENT,
        protocols=("BLE", "GATT"),
    ))
    registry.register(_make_descriptor(
        module_id="fuzzing.engine",
        family=ModuleFamily.FUZZING,
        protocols=("Classic",),
    ))

    classic_matches = registry.find_by_protocol("Classic")
    assert len(classic_matches) == 2
    ids = {d.module_id for d in classic_matches}
    assert ids == {"exploitation.test", "fuzzing.engine"}

    ble_matches = registry.find_by_protocol("BLE")
    assert len(ble_matches) == 1
    assert ble_matches[0].module_id == "assessment.check_one"

    no_matches = registry.find_by_protocol("OBEX")
    assert no_matches == []


def test_find_destructive():
    registry = ModuleRegistry()
    registry.register(_make_descriptor(module_id="exploitation.test", family=ModuleFamily.EXPLOITATION, destructive=True))
    registry.register(_make_descriptor(module_id="assessment.check_one", family=ModuleFamily.ASSESSMENT, destructive=False))
    registry.register(_make_descriptor(module_id="fuzzing.engine", family=ModuleFamily.FUZZING, destructive=True))

    destructive = registry.find_destructive()
    assert len(destructive) == 2
    ids = {d.module_id for d in destructive}
    assert ids == {"exploitation.test", "fuzzing.engine"}


def test_invalid_module_id_format_raises():
    with pytest.raises(ValueError, match="module_id must be"):
        _make_descriptor(module_id="noDot", family=ModuleFamily.EXPLOITATION)

    with pytest.raises(ValueError, match="module_id must be"):
        _make_descriptor(module_id="has.Upper.Case", family=ModuleFamily.EXPLOITATION)

    with pytest.raises(ValueError, match="module_id must be"):
        _make_descriptor(module_id="", family=ModuleFamily.EXPLOITATION)


def test_module_id_allows_digits_in_snake_case():
    descriptor = _make_descriptor(
        module_id="assessment.cve_l2cap",
        family=ModuleFamily.ASSESSMENT,
    )

    assert descriptor.module_id == "assessment.cve_l2cap"


def test_module_id_must_match_family():
    with pytest.raises(ValueError, match="must start with family"):
        _make_descriptor(module_id="assessment.knob", family=ModuleFamily.EXPLOITATION)


def test_list_families():
    registry = ModuleRegistry()
    assert registry.list_families() == []

    registry.register(_make_descriptor(module_id="exploitation.test", family=ModuleFamily.EXPLOITATION))
    registry.register(_make_descriptor(module_id="assessment.check_one", family=ModuleFamily.ASSESSMENT))

    families = registry.list_families()
    assert ModuleFamily.EXPLOITATION in families
    assert ModuleFamily.ASSESSMENT in families
    assert ModuleFamily.FUZZING not in families
    assert len(families) == 2


def test_get_unknown_raises_keyerror():
    registry = ModuleRegistry()
    with pytest.raises(KeyError):
        registry.get("nonexistent.module")


def test_list_all_sorted():
    registry = ModuleRegistry()
    registry.register(_make_descriptor(module_id="fuzzing.engine", family=ModuleFamily.FUZZING))
    registry.register(_make_descriptor(module_id="assessment.check_one", family=ModuleFamily.ASSESSMENT))
    registry.register(_make_descriptor(module_id="exploitation.test", family=ModuleFamily.EXPLOITATION))

    all_modules = registry.list_all()
    ids = [d.module_id for d in all_modules]
    assert ids == sorted(ids)


def test_assessment_package_registers_modules():
    """Verify assessment modules are registered when the package is imported.

    Note: This test verifies the global registry state after import, not reload.
    Module auto-registration via __init_subclass__ only happens once at class
    definition time.
    """
    from blue_tap.framework.registry import get_registry, ModuleFamily

    # Import to ensure modules are loaded (Module classes now live in checks/ files)
    import blue_tap.modules.assessment  # noqa: F401

    registry = get_registry()
    registered_ids = {
        descriptor.module_id
        for descriptor in registry.list_family(ModuleFamily.ASSESSMENT)
    }

    # Core descriptors
    assert "assessment.vuln_scanner" in registered_ids
    assert "assessment.fleet" in registered_ids
    # Individual CVE modules (now one per CVE, not grouped)
    assert "assessment.cve_2017_0785" in registered_ids  # SDP
    assert "assessment.cve_2019_2225" in registered_ids  # JustWorks
    assert "assessment.cve_2025_20700" in registered_ids  # Airoha
    # Non-CVE modules
    assert "assessment.service_exposure" in registered_ids
    assert "assessment.pairing_method" in registered_ids
    # Total: 2 core + 25 CVE + 11 non-CVE = 38 modules
    assert len(registered_ids) >= 35, f"Expected at least 35 modules, got {len(registered_ids)}"


def test_post_exploitation_package_registers_modules():
    """Verify post-exploitation modules are registered when the package is imported.

    Note: This test verifies the global registry state after import, not reload.
    Module auto-registration via __init_subclass__ only happens once at class
    definition time. The former ``post_exploitation/modules/`` wrapper layer was
    collapsed on 2026-04-12; the package's ``__init__`` now imports each native
    sub-package directly.
    """
    from blue_tap.framework.registry import get_registry, ModuleFamily

    # Import to ensure modules are loaded
    import blue_tap.modules.post_exploitation  # noqa: F401

    registry = get_registry()
    descriptors = list(registry.list_family(ModuleFamily.POST_EXPLOITATION))
    registered_ids = {d.module_id for d in descriptors}

    expected = {
        "post_exploitation.pbap",
        "post_exploitation.map",
        "post_exploitation.bluesnarfer",
        "post_exploitation.opp",
        "post_exploitation.hfp",
        "post_exploitation.a2dp",
        "post_exploitation.avrcp",
    }
    assert expected.issubset(registered_ids), f"Missing: {expected - registered_ids}"

    # Every native entry point must point at a co-located class (no `.modules.` infix).
    for descriptor in descriptors:
        assert "post_exploitation.modules." not in descriptor.entry_point, (
            f"Wrapper path survived: {descriptor.entry_point}"
        )


def test_exploitation_package_registers_modules():
    """Verify exploitation modules are registered when the package is imported."""
    from blue_tap.framework.registry import get_registry, ModuleFamily

    # Import to trigger auto-registration (native files, no wrapper)
    import blue_tap.modules.exploitation  # noqa: F401

    registry = get_registry()
    registered_ids = {
        descriptor.module_id
        for descriptor in registry.list_family(ModuleFamily.EXPLOITATION)
    }

    expected = {
        "exploitation.bias",
        "exploitation.bluffs",
        "exploitation.ctkd",
        "exploitation.dos_runner",
        "exploitation.encryption_downgrade",
        "exploitation.hijack",
        "exploitation.knob",
        "exploitation.pin_brute",
        "exploitation.ssp_downgrade",
    }
    assert expected.issubset(registered_ids), f"Missing: {expected - registered_ids}"


def test_fuzzing_package_registers_modules():
    """Verify fuzzing modules are registered when the package is imported.

    Note: This test verifies the global registry state after import, not reload.
    Module auto-registration via __init_subclass__ only happens once at class
    definition time.
    """
    from blue_tap.framework.registry import get_registry, ModuleFamily

    # Import to ensure modules are loaded (native Module classes, no wrapper layer)
    import blue_tap.modules.fuzzing  # noqa: F401

    registry = get_registry()
    registered_ids = {
        descriptor.module_id
        for descriptor in registry.list_family(ModuleFamily.FUZZING)
    }

    expected = {
        "fuzzing.engine",
        "fuzzing.transport",
        "fuzzing.minimizer",
    }
    assert expected.issubset(registered_ids), f"Missing: {expected - registered_ids}"


# NOTE: test_reconnaissance_package_registers_modules and
# test_discovery_package_registers_modules were removed on 2026-04-12 when
# the modules/reconnaissance/modules/ and modules/discovery/modules/ wrapper
# packages were deleted. Replacement coverage (native Module behavior, not
# import-path smoke) is scheduled to be written by the independent test
# agent as tracked in the production-readiness fix plan.
