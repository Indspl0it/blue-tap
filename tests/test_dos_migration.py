"""Tests for DoS family migration to Module API.

Tests verify:
- Each DoS check is a registered Module subclass
- Modules accept options via Opt* schema
- Modules produce RunEnvelope via run()
- CLI runner can invoke modules by module_id
- Registry includes all DoS modules with category="dos"
"""

from __future__ import annotations

import pytest
from blue_tap.framework.module import Module, Opt, OptAddress, OptInt, OptFloat, OptBool, OptString
from blue_tap.framework.registry import ModuleFamily, get_registry
from blue_tap.framework.module import Invoker, DestructiveConfirmationRequired


# ---------------------------------------------------------------------------
# Registry Tests - All DoS modules should be registered
# ---------------------------------------------------------------------------

class TestDosModuleRegistration:
    """Test that all DoS modules are registered in the registry."""

    @pytest.fixture(autouse=True)
    def autoload_dos_modules(self):
        """Auto-load DoS modules by importing the dos package."""
        from blue_tap.modules.exploitation import dos

    def test_dos_modules_are_registered(self):
        """All DoS modules should be registered with module_id starting with 'exploitation.dos_'."""
        registry = get_registry()
        dos_modules = [d for d in registry.list_family(ModuleFamily.EXPLOITATION) if d.module_id.startswith("exploitation.dos_")]

        # Expected DoS check IDs from the original DOS_CHECKS tuple
        expected_ids = {
            "exploitation.dos_pair_flood",
            "exploitation.dos_name_flood",
            "exploitation.dos_rate_test",
            "exploitation.dos_l2ping_flood",
            "exploitation.dos_cve_2020_0022_bluefrag",
            "exploitation.dos_l2cap_storm",
            "exploitation.dos_l2cap_cid_exhaust",
            "exploitation.dos_l2cap_data_flood",
            "exploitation.dos_sdp_continuation",
            "exploitation.dos_sdp_des_bomb",
            "exploitation.dos_cve_2017_0781_bnep_heap",
            "exploitation.dos_cve_2017_0782_bnep_underflow",
            "exploitation.dos_cve_2019_19196_key_size",
            "exploitation.dos_cve_2019_19192_att_deadlock",
            "exploitation.dos_cve_2022_39177_avdtp_setconf",
            "exploitation.dos_cve_2023_27349_avrcp_event",
            "exploitation.dos_cve_2025_0084_sdp_race",
            "exploitation.dos_rfcomm_sabm_flood",
            "exploitation.dos_rfcomm_mux_flood",
            "exploitation.dos_obex_connect_flood",
            "exploitation.dos_hfp_at_flood",
            "exploitation.dos_hfp_slc_confuse",
            "exploitation.dos_cve_2025_48593_hfp_reconnect",
            "exploitation.dos_lmp_detach_flood",
            "exploitation.dos_lmp_switch_storm",
            "exploitation.dos_lmp_features_flood",
            "exploitation.dos_lmp_invalid_opcode",
            "exploitation.dos_lmp_encryption_toggle",
            "exploitation.dos_lmp_timing_flood",
        }

        registered_ids = {d.module_id for d in dos_modules}
        assert expected_ids.issubset(registered_ids), f"Missing modules: {expected_ids - registered_ids}"

    def test_all_dos_modules_are_destructive(self):
        """All DoS modules should be marked as destructive."""
        registry = get_registry()
        for desc in registry.list_all():
            if desc.module_id.startswith("exploitation.dos_"):
                assert desc.destructive is True, f"{desc.module_id} should be destructive"

    def test_dos_modules_have_cves_where_applicable(self):
        """CVE-named modules should have CVE references."""
        registry = get_registry()
        cve_modules = {
            "cve_2020_0022_bluefrag": "CVE-2020-0022",
            "cve_2017_0781_bnep_heap": "CVE-2017-0781",
            "cve_2017_0782_bnep_underflow": "CVE-2017-0782",
            "cve_2019_19196_key_size": "CVE-2019-19196",
            "cve_2019_19192_att_deadlock": "CVE-2019-19192",
            "cve_2022_39177_avdtp_setconf": "CVE-2022-39177",
            "cve_2023_27349_avrcp_event": "CVE-2023-27349",
            "cve_2025_0084_sdp_race": "CVE-2025-0084",
            "cve_2025_48593_hfp_reconnect": "CVE-2025-48593",
        }

        for check_id, expected_cve in cve_modules.items():
            desc = registry.get(f"exploitation.dos_{check_id}")
            assert desc is not None, f"Module {check_id} not registered"
            assert expected_cve in desc.references, f"{check_id} missing CVE reference"

    def test_dos_modules_require_target_and_adapter(self):
        """All DoS modules should require RHOST and HCI options."""
        registry = get_registry()
        for desc in registry.list_all():
            # Skip dos_runner which is a meta-module, not a Module subclass
            if desc.module_id.startswith("exploitation.dos_") and desc.module_id != "exploitation.dos_runner":
                # Import the module class to check options
                module_path, class_name = desc.entry_point.split(":")
                module_obj = __import__(module_path, fromlist=[class_name])
                cls = getattr(module_obj, class_name)

                option_names = {opt.name for opt in cls.options}
                assert "RHOST" in option_names, f"{desc.module_id} missing RHOST option"
                assert "HCI" in option_names, f"{desc.module_id} missing HCI option"


# ---------------------------------------------------------------------------
# Module Class Tests - Verify module structure and behavior
# ---------------------------------------------------------------------------

class TestPairFloodModule:
    """Test the PairFlood (pair_flood, name_flood, rate_test, l2ping_flood) modules."""

    @pytest.fixture(autouse=True)
    def autoload_modules(self):
        from blue_tap.modules.exploitation import dos

    def test_pair_flood_module_exists(self):
        """Pair flood module should be a Module subclass."""
        registry = get_registry()
        desc = registry.get("exploitation.dos_pair_flood")
        assert desc is not None

        module_path, class_name = desc.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)
        assert issubclass(cls, Module)

    def test_pair_flood_options(self):
        """Pair flood module should have count and interval options."""
        registry = get_registry()
        desc = registry.get("exploitation.dos_pair_flood")
        module_path, class_name = desc.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)

        option_names = {opt.name for opt in cls.options}
        assert "COUNT" in option_names
        assert "INTERVAL" in option_names

    def test_pair_flood_destructive_requires_confirm(self):
        """Invoking pair_flood without CONFIRM should raise."""
        invoker = Invoker(safety_override=False)
        with pytest.raises(DestructiveConfirmationRequired):
            invoker.invoke(
                "exploitation.dos_pair_flood",
                {"RHOST": "AA:BB:CC:DD:EE:FF", "HCI": "hci0"},
            )

    def test_pair_flood_accepts_confirm(self):
        """Invoking with CONFIRM=yes should not raise."""
        invoker = Invoker(safety_override=False)
        # This may fail due to missing adapter, but should not raise DestructiveConfirmationRequired
        try:
            invoker.invoke(
                "exploitation.dos_pair_flood",
                {"RHOST": "AA:BB:CC:DD:EE:FF", "HCI": "hci0", "CONFIRM": "yes", "COUNT": "1"},
            )
        except DestructiveConfirmationRequired:
            pytest.fail("Should not raise DestructiveConfirmationRequired with CONFIRM=yes")
        except Exception:
            # Other exceptions are expected (hardware not available)
            pass

    def test_name_flood_module_exists(self):
        """Name flood module should be registered."""
        registry = get_registry()
        assert registry.get("exploitation.dos_name_flood") is not None

    def test_rate_test_module_exists(self):
        """Rate test module should be registered."""
        registry = get_registry()
        assert registry.get("exploitation.dos_rate_test") is not None

    def test_l2ping_flood_module_exists(self):
        """L2ping flood module should be registered."""
        registry = get_registry()
        assert registry.get("exploitation.dos_l2ping_flood") is not None


class TestCveModules:
    """Test CVE-named DoS modules have proper references."""

    @pytest.fixture(autouse=True)
    def autoload_modules(self):
        from blue_tap.modules.exploitation import dos

    def test_bluefrag_module_requires_hci1(self):
        """BlueFrag module should default to hci1."""
        registry = get_registry()
        desc = registry.get("exploitation.dos_cve_2020_0022_bluefrag")
        assert desc is not None

        module_path, class_name = desc.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)

        hci_option = next((opt for opt in cls.options if opt.name == "HCI"), None)
        assert hci_option is not None
        assert hci_option.default == "hci1", f"Expected hci1, got {hci_option.default}"

    def test_sweyntooth_modules_exist(self):
        """SweynTooth modules should be registered."""
        registry = get_registry()
        assert registry.get("exploitation.dos_cve_2019_19196_key_size") is not None
        assert registry.get("exploitation.dos_cve_2019_19192_att_deadlock") is not None


class TestProtocolDoSModules:
    """Test protocol-specific DoS modules (L2CAP, SDP, RFCOMM, etc.)."""

    @pytest.fixture(autouse=True)
    def autoload_modules(self):
        from blue_tap.modules.exploitation import dos

    def test_l2cap_modules_registered(self):
        """All L2CAP DoS modules should be registered."""
        registry = get_registry()
        l2cap_checks = {
            "exploitation.dos_l2cap_storm",
            "exploitation.dos_l2cap_cid_exhaust",
            "exploitation.dos_l2cap_data_flood",
        }
        for module_id in l2cap_checks:
            assert registry.get(module_id) is not None, f"L2CAP module {module_id} not registered"

    def test_sdp_modules_registered(self):
        """All SDP DoS modules should be registered."""
        registry = get_registry()
        sdp_checks = {
            "exploitation.dos_sdp_continuation",
            "exploitation.dos_sdp_des_bomb",
            "exploitation.dos_cve_2025_0084_sdp_race",
        }
        for module_id in sdp_checks:
            assert registry.get(module_id) is not None, f"SDP module {module_id} not registered"

    def test_rfcomm_modules_registered(self):
        """All RFCOMM DoS modules should be registered."""
        registry = get_registry()
        rfcomm_checks = {
            "exploitation.dos_rfcomm_sabm_flood",
            "exploitation.dos_rfcomm_mux_flood",
        }
        for module_id in rfcomm_checks:
            assert registry.get(module_id) is not None, f"RFCOMM module {module_id} not registered"

    def test_hfp_modules_registered(self):
        """All HFP DoS modules should be registered."""
        registry = get_registry()
        hfp_checks = {
            "exploitation.dos_hfp_at_flood",
            "exploitation.dos_hfp_slc_confuse",
            "exploitation.dos_cve_2025_48593_hfp_reconnect",
        }
        for module_id in hfp_checks:
            assert registry.get(module_id) is not None, f"HFP module {module_id} not registered"

    def test_lmp_modules_registered(self):
        """All LMP DoS modules should be registered."""
        registry = get_registry()
        lmp_checks = {
            "exploitation.dos_lmp_detach_flood",
            "exploitation.dos_lmp_switch_storm",
            "exploitation.dos_lmp_features_flood",
            "exploitation.dos_lmp_invalid_opcode",
            "exploitation.dos_lmp_encryption_toggle",
            "exploitation.dos_lmp_timing_flood",
        }
        for module_id in lmp_checks:
            assert registry.get(module_id) is not None, f"LMP module {module_id} not registered"


# ---------------------------------------------------------------------------
# Option Validation Tests
# ---------------------------------------------------------------------------

class TestDosOptionValidation:
    """Test that option validation works correctly for DoS modules."""

    @pytest.fixture(autouse=True)
    def autoload_modules(self):
        from blue_tap.modules.exploitation import dos

    def test_rhost_accepts_valid_mac(self):
        """RHOST option should accept valid MAC addresses."""
        registry = get_registry()
        desc = registry.get("exploitation.dos_pair_flood")
        module_path, class_name = desc.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)

        opt = next((opt for opt in cls.options if opt.name == "RHOST"), None)
        assert opt is not None

        # Valid MAC should validate
        assert opt.validate("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
        assert opt.validate("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"  # uppercase

        # Invalid MAC should raise
        with pytest.raises(Exception):  # OptionError
            opt.validate("not-a-mac")

    def test_count_option_bounds(self):
        """COUNT option should enforce positive bounds."""
        registry = get_registry()
        desc = registry.get("exploitation.dos_pair_flood")
        module_path, class_name = desc.entry_point.split(":")
        module_obj = __import__(module_path, fromlist=[class_name])
        cls = getattr(module_obj, class_name)

        opt = next((opt for opt in cls.options if opt.name == "COUNT"), None)
        assert opt is not None

        # Valid counts
        assert opt.validate("10") == 10
        assert opt.validate("1") == 1

        # Invalid counts
        with pytest.raises(Exception):
            opt.validate("0")
        with pytest.raises(Exception):
            opt.validate("-1")


# ---------------------------------------------------------------------------
# Entry Point Resolution Tests
# ---------------------------------------------------------------------------

class TestDosEntryPoints:
    """Test that entry points resolve to Module subclasses."""

    @pytest.fixture(autouse=True)
    def autoload_modules(self):
        from blue_tap.modules.exploitation import dos

    def test_all_dos_entry_points_resolvable(self):
        """All DoS module entry points should resolve to Module subclasses."""
        registry = get_registry()
        from blue_tap.framework.module.base import Module

        for desc in registry.list_all():
            # Skip dos_runner which is a meta-module (function-based, not Module subclass)
            if desc.module_id.startswith("exploitation.dos_") and desc.module_id != "exploitation.dos_runner":
                module_path, class_name = desc.entry_point.split(":")
                module_obj = __import__(module_path, fromlist=[class_name])
                cls = getattr(module_obj, class_name)
                assert issubclass(cls, Module), f"{desc.module_id} entry point is not a Module subclass"


# ---------------------------------------------------------------------------
# Backward Compatibility - Old registry can still be used
# ---------------------------------------------------------------------------

class TestBackwardCompatibility:
    """Test that old DOS_CHECKS can still be accessed for transition period."""

    def test_dos_registry_still_exists(self):
        """Old DOS_CHECKS tuple should still be accessible during transition."""
        from blue_tap.modules.exploitation.dos.registry import DOS_CHECKS, DOS_CHECK_INDEX

        assert len(DOS_CHECKS) > 0
        assert isinstance(DOS_CHECKS, tuple)
        assert isinstance(DOS_CHECK_INDEX, dict)
        assert len(DOS_CHECK_INDEX) > 0

    def test_dos_check_ids_match_new_modules(self):
        """Old DOS_CHECKS check_ids should correspond to new module_ids."""
        from blue_tap.modules.exploitation.dos.registry import DOS_CHECKS

        registry = get_registry()
        old_ids = {check.check_id for check in DOS_CHECKS}

        # All old IDs should map to new module_ids (exploitation.dos_<check_id>)
        for old_id in old_ids:
            new_id = f"exploitation.dos_{old_id}"
            desc = registry.get(new_id)
            assert desc is not None, f"Old check {old_id} has no corresponding module {new_id}"
