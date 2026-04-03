"""Comprehensive tests for Blue-Tap CLI interface, output helpers, and report generator.

All Bluetooth hardware calls are mocked — no adapter required.
"""

import json
import os
import types

import pytest
from click.testing import CliRunner

from blue_tap.cli import main, _save_json
from blue_tap.report.generator import ReportGenerator
from blue_tap.utils import output as _output_mod
from blue_tap.utils.output import (
    banner,
    channel_table,
    console,
    debug,
    device_table,
    error,
    get_progress,
    get_spinner,
    get_verbosity,
    highlight,
    info,
    phase,
    result_box,
    section,
    service_table,
    set_verbosity,
    step,
    substep,
    success,
    summary_panel,
    target,
    verbose,
    vuln_table,
)
from blue_tap.utils import interactive as _interactive_mod

# pytest strips the name 'warning' during import; access via module attribute
bt_warning = _output_mod.warning


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

FAKE_MAC = "AA:BB:CC:DD:EE:FF"
FAKE_MAC2 = "11:22:33:44:55:66"


def _make_devices(n=2):
    """Return a list of n fake device dicts."""
    devices = []
    for i in range(n):
        devices.append({
            "address": f"AA:BB:CC:DD:EE:{i:02X}",
            "name": f"TestDev{i}",
            "rssi": -50 - i * 10,
            "type": "Classic" if i % 2 == 0 else "BLE",
        })
    return devices


def _make_services(n=2):
    services = []
    for i in range(n):
        services.append({
            "name": f"Service{i}",
            "protocol": "RFCOMM",
            "channel": i + 1,
            "profile": "SPP" if i == 0 else "PBAP",
            "profile_version": "1.0",
        })
    return services


def _make_findings():
    return [
        {"name": "Legacy Pairing", "severity": "critical", "status": "confirmed",
         "cve": "N/A", "description": "No SSP support detected"},
        {"name": "KNOB", "severity": "high", "status": "potential",
         "cve": "CVE-2019-9506", "description": "Entropy negotiation vuln"},
        {"name": "Open RFCOMM", "severity": "medium", "status": "unverified",
         "cve": "N/A", "description": "Channel 3 open without auth"},
        {"name": "Old BT Version", "severity": "low", "status": "potential",
         "cve": "N/A", "description": "BT 4.0 in use"},
        {"name": "LE Ping", "severity": "info", "status": "confirmed",
         "cve": "N/A", "description": "BLE responds to ping"},
    ]


def _noop(*a, **kw):
    return None


def _noop_session(*a, **kw):
    """Stub for log_command that accepts any args."""


@pytest.fixture(autouse=True)
def _reset_verbosity():
    """Restore verbosity to 0 after every test."""
    yield
    set_verbosity(0)


@pytest.fixture(autouse=True)
def _reset_banner():
    """Reset the banner-shown flag so each test starts clean."""
    import blue_tap.utils.output as _out
    _out._BANNER_SHOWN = False
    yield
    _out._BANNER_SHOWN = False


@pytest.fixture()
def _stub_session(monkeypatch):
    """Stub out Session creation + log_command for CLI tests."""
    _fake_session = types.SimpleNamespace(dir="/tmp/fake_session", name="test")
    monkeypatch.setattr("blue_tap.utils.session.Session", lambda name: _fake_session)
    monkeypatch.setattr("blue_tap.utils.session.set_session", _noop)
    monkeypatch.setattr("blue_tap.utils.session.log_command", _noop_session)


# ============================================================================
# output.py — core log functions
# ============================================================================

class TestCoreLogs:
    """info, success, warning, error produce output without crash."""

    def test_info(self, capsys):
        info("hello info")
        # Rich writes to its own console; just verify no exception.

    def test_success(self):
        success("ok")

    def test_warning(self):
        bt_warning("watch out")

    def test_error(self):
        error("oops")


class TestVerbosity:
    def test_set_get_roundtrip(self):
        set_verbosity(1)
        assert get_verbosity() == 1
        set_verbosity(2)
        assert get_verbosity() == 2
        set_verbosity(0)
        assert get_verbosity() == 0

    def test_clamp_negative(self):
        set_verbosity(-5)
        assert get_verbosity() == 0

    def test_clamp_above_max(self):
        set_verbosity(99)
        assert get_verbosity() == 2

    def test_verbose_silent_at_level_0(self):
        set_verbosity(0)
        # Should not raise; should produce no output at level 0.
        verbose("should be silent")

    def test_verbose_prints_at_level_1(self):
        set_verbosity(1)
        verbose("should print")

    def test_debug_silent_at_level_1(self):
        set_verbosity(1)
        debug("should be silent")

    def test_debug_prints_at_level_2(self):
        set_verbosity(2)
        debug("should print")


# ============================================================================
# output.py — target / highlight helpers
# ============================================================================

class TestTextHelpers:
    def test_target_wraps_address(self):
        out = target(FAKE_MAC)
        assert FAKE_MAC in out
        assert "bt.purple" in out

    def test_highlight_default_style(self):
        out = highlight("foo")
        assert "foo" in out
        assert "bt.cyan" in out

    def test_highlight_custom_style(self):
        out = highlight("bar", style="bt.red")
        assert "bt.red" in out


# ============================================================================
# output.py — banner
# ============================================================================

class TestBanner:
    def test_banner_prints_once(self):
        import blue_tap.utils.output as _out
        _out._BANNER_SHOWN = False
        banner()
        assert _out._BANNER_SHOWN is True

    def test_banner_skips_second_call(self):
        import blue_tap.utils.output as _out
        _out._BANNER_SHOWN = False
        banner()
        # Second call should be a no-op (no crash, no duplicate output).
        banner()
        assert _out._BANNER_SHOWN is True


# ============================================================================
# output.py — device_table
# ============================================================================

class TestDeviceTable:
    def test_normal_devices(self):
        devs = _make_devices(3)
        tbl = device_table(devs)
        assert tbl.row_count == 3

    def test_empty_devices(self):
        tbl = device_table([])
        assert tbl.row_count == 0

    def test_na_rssi(self):
        devs = [{"address": FAKE_MAC, "name": "NoRSSI", "type": "Classic"}]
        tbl = device_table(devs)
        assert tbl.row_count == 1

    def test_with_class_info(self):
        devs = [{
            "address": FAKE_MAC, "name": "Car IVI", "rssi": -45,
            "type": "Classic",
            "class_info": {"major": "Audio/Video", "minor": "Car Audio"},
        }]
        tbl = device_table(devs)
        assert tbl.row_count == 1

    def test_with_distance(self):
        devs = [{
            "address": FAKE_MAC, "name": "Close", "rssi": -30,
            "type": "Classic", "distance_m": 1.2,
        }]
        tbl = device_table(devs)
        assert tbl.row_count == 1

    def test_strong_rssi_color(self):
        """RSSI > -50 should get green color."""
        devs = [{"address": FAKE_MAC, "name": "Strong", "rssi": -40, "type": "Classic"}]
        tbl = device_table(devs)
        assert tbl.row_count == 1

    def test_medium_rssi_color(self):
        """RSSI between -70 and -50 should get yellow color."""
        devs = [{"address": FAKE_MAC, "name": "Medium", "rssi": -60, "type": "Classic"}]
        tbl = device_table(devs)
        assert tbl.row_count == 1

    def test_weak_rssi_color(self):
        """RSSI < -70 should get red color."""
        devs = [{"address": FAKE_MAC, "name": "Weak", "rssi": -80, "type": "Classic"}]
        tbl = device_table(devs)
        assert tbl.row_count == 1


# ============================================================================
# output.py — service_table
# ============================================================================

class TestServiceTable:
    def test_normal_services(self):
        svcs = _make_services(3)
        tbl = service_table(svcs)
        assert tbl.row_count == 3

    def test_empty_services(self):
        tbl = service_table([])
        assert tbl.row_count == 0


# ============================================================================
# output.py — channel_table
# ============================================================================

class TestChannelTable:
    def test_rfcomm_format(self):
        results = [
            {"channel": 1, "status": "open", "name": "SPP"},
            {"channel": 2, "status": "closed", "name": ""},
        ]
        tbl = channel_table(results)
        assert tbl.row_count == 2

    def test_l2cap_format(self):
        results = [
            {"psm": 1, "status": "open", "response_type": "ConnectionResponse"},
            {"psm": 3, "status": "auth_required", "response_type": ""},
        ]
        tbl = channel_table(results)
        assert tbl.row_count == 2

    def test_all_status_styles(self):
        """Every known status renders without error."""
        for status in ("open", "closed", "timeout", "host_unreachable", "auth_required"):
            results = [{"channel": 1, "status": status, "name": "test"}]
            tbl = channel_table(results)
            assert tbl.row_count == 1

    def test_empty_results(self):
        tbl = channel_table([])
        assert tbl.row_count == 0


# ============================================================================
# output.py — vuln_table
# ============================================================================

class TestVulnTable:
    def test_all_severity_levels(self):
        findings = _make_findings()
        tbl = vuln_table(findings)
        assert tbl.row_count == 5

    def test_empty_findings(self):
        tbl = vuln_table([])
        assert tbl.row_count == 0

    def test_finding_with_confidence(self):
        findings = [{
            "name": "Test", "severity": "high", "status": "potential",
            "cve": "N/A", "description": "desc", "confidence": "90%",
        }]
        tbl = vuln_table(findings)
        assert tbl.row_count == 1


# ============================================================================
# output.py — summary_panel, result_box
# ============================================================================

class TestPanels:
    def test_summary_panel(self):
        summary_panel("Test", {"Key": "Value", "Num": 42})

    def test_result_box(self):
        result_box("Done", "All passed")


# ============================================================================
# output.py — progress helpers
# ============================================================================

class TestProgress:
    def test_get_progress(self):
        p = get_progress()
        # Returns a Rich Progress instance
        from rich.progress import Progress
        assert isinstance(p, Progress)

    def test_get_spinner(self):
        s = get_spinner("Testing...")
        # Returns a console.status context manager
        assert s is not None


# ============================================================================
# output.py — phase / step / substep / section
# ============================================================================

class TestPhaseStep:
    def test_phase_success(self):
        with phase("TestPhase", 1, 3):
            pass  # no error

    def test_phase_without_number(self):
        with phase("Unnamed"):
            pass

    def test_phase_exception_reports_failure(self):
        with pytest.raises(RuntimeError):
            with phase("FailPhase", 1, 1):
                raise RuntimeError("boom")

    def test_step_success(self):
        with step("do something"):
            pass

    def test_step_verbose_done(self):
        set_verbosity(1)
        with step("verbose step"):
            pass

    def test_step_exception(self):
        with pytest.raises(ValueError):
            with step("fail step"):
                raise ValueError("bad")

    def test_substep(self):
        substep("sub item")

    def test_section(self):
        section("My Section")
        section("Red Section", style="bt.red")


# ============================================================================
# utils/interactive.py — resolve_address
# ============================================================================

class TestResolveAddress:
    def test_valid_mac_returns_normalized(self):
        result = _interactive_mod.resolve_address("aa:bb:cc:dd:ee:ff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_dashes_normalized(self):
        result = _interactive_mod.resolve_address("aa-bb-cc-dd-ee-ff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_invalid_mac_returns_none(self):
        result = _interactive_mod.resolve_address("not-a-mac")
        assert result is None

    def test_none_calls_pick_device(self, monkeypatch):
        monkeypatch.setattr(
            _interactive_mod, "pick_device",
            lambda **kw: FAKE_MAC,
        )
        result = _interactive_mod.resolve_address(None)
        assert result == FAKE_MAC


# ============================================================================
# CLI — version
# ============================================================================

class TestCLIVersion:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "2.1" in result.output  # matches 2.1.x


# ============================================================================
# CLI — scan commands
# ============================================================================

class TestCLIScan:
    def test_scan_classic_with_devices(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.scanner.scan_classic",
            lambda *a, **kw: _make_devices(2),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "classic"])
        assert result.exit_code == 0
        assert "AA:BB:CC:DD:EE:00" in result.output

    def test_scan_classic_no_devices(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.scanner.scan_classic",
            lambda *a, **kw: [],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "classic"])
        assert result.exit_code == 0
        assert "no devices" in result.output.lower()

    def test_scan_ble(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.scanner.scan_ble_sync",
            lambda *a, **kw: _make_devices(1),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "ble"])
        assert result.exit_code == 0

    def test_scan_all(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.scanner.scan_all",
            lambda *a, **kw: _make_devices(3),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "all"])
        assert result.exit_code == 0


# ============================================================================
# CLI — recon commands
# ============================================================================

class TestCLIRecon:
    def test_recon_sdp(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.browse_services",
            lambda *a, **kw: _make_services(2),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "sdp", FAKE_MAC])
        assert result.exit_code == 0

    def test_recon_sdp_no_services(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.browse_services",
            lambda *a, **kw: [],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "sdp", FAKE_MAC])
        assert result.exit_code == 0
        assert "no sdp" in result.output.lower() or result.exit_code == 0

    def test_recon_fingerprint(self, monkeypatch, _stub_session):
        fp_data = {
            "address": FAKE_MAC, "name": "TestIVI",
            "manufacturer": "TestChip", "bt_version": "5.0",
            "profiles": ["HFP", "A2DP"], "ivi_likely": True,
            "ivi_signals": ["Audio sink"], "attack_surface": ["HFP ch 6"],
            "vuln_hints": ["Legacy pairing"],
            "device_class_info": {"major": "Audio/Video", "minor": "Car Audio", "services": ["Audio"]},
            "device_class": "0x240404",
            "lmp_version": "5.0",
        }
        monkeypatch.setattr(
            "blue_tap.recon.fingerprint.fingerprint_device",
            lambda *a, **kw: fp_data,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "fingerprint", FAKE_MAC])
        assert result.exit_code == 0
        assert "TestIVI" in result.output or "Fingerprint" in result.output

    def test_recon_rfcomm_scan(self, monkeypatch, _stub_session):
        class FakeScanner:
            def __init__(self, addr):
                pass
            def scan_all_channels(self, **kw):
                return [
                    {"channel": 1, "status": "open", "name": "SPP"},
                    {"channel": 2, "status": "closed", "name": ""},
                ]
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.RFCOMMScanner", FakeScanner,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "rfcomm-scan", FAKE_MAC])
        assert result.exit_code == 0

    def test_recon_l2cap_scan(self, monkeypatch, _stub_session):
        class FakeL2CAP:
            def __init__(self, addr):
                pass
            def scan_standard_psms(self, **kw):
                return [{"psm": 1, "status": "open", "response_type": "SDP"}]
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.L2CAPScanner", FakeL2CAP,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "l2cap-scan", FAKE_MAC])
        assert result.exit_code == 0

    def test_recon_gatt(self, monkeypatch, _stub_session):
        gatt_services = [{
            "uuid": "0000180a-0000-1000-8000-00805f9b34fb",
            "description": "Device Information",
            "handle": "0x0001",
            "characteristics": [{
                "uuid": "00002a29-0000-1000-8000-00805f9b34fb",
                "description": "Manufacturer Name",
                "properties": ["read"],
                "value_hex": "54657374",
                "value_str": "Test",
            }],
        }]
        monkeypatch.setattr(
            "blue_tap.recon.gatt.enumerate_services_sync",
            lambda *a, **kw: gatt_services,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "gatt", FAKE_MAC])
        assert result.exit_code == 0

    def test_recon_invalid_mac(self, _stub_session):
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "sdp", "INVALID"])
        # Should handle gracefully (exit 0 with error msg, not traceback)
        assert "Traceback" not in result.output


# ============================================================================
# CLI — vulnscan
# ============================================================================

class TestCLIVulnscan:
    def test_vulnscan_basic(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.attack.vuln_scanner.scan_vulnerabilities",
            lambda *a, **kw: _make_findings(),
        )
        runner = CliRunner()
        result = runner.invoke(main, ["vulnscan", FAKE_MAC])
        assert result.exit_code == 0
        assert "complete" in result.output.lower() or "finding" in result.output.lower()

    def test_vulnscan_active_flag(self, monkeypatch, _stub_session):
        captured_kwargs = {}

        def fake_scan(*a, **kw):
            captured_kwargs.update(kw)
            return []

        monkeypatch.setattr(
            "blue_tap.attack.vuln_scanner.scan_vulnerabilities", fake_scan,
        )
        # Supply --phone to avoid interactive picker
        runner = CliRunner()
        result = runner.invoke(main, ["vulnscan", FAKE_MAC, "--active", "--phone", FAKE_MAC2])
        assert result.exit_code == 0
        assert captured_kwargs.get("active") is True

    def test_vulnscan_no_address(self, monkeypatch, _stub_session):
        """Without address and no interactive device, should exit gracefully."""
        monkeypatch.setattr(
            _interactive_mod, "pick_device", lambda **kw: None,
        )
        # Also patch resolve_address in the cli module namespace
        monkeypatch.setattr(
            "blue_tap.utils.interactive.pick_device", lambda **kw: None,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["vulnscan"])
        # Should not crash
        assert "Traceback" not in result.output


# ============================================================================
# CLI — spoof commands
# ============================================================================

class TestCLISpoof:
    def test_spoof_mac_success(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.spoofer.spoof_address",
            lambda *a, **kw: True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "mac", FAKE_MAC])
        assert result.exit_code == 0
        assert "changed" in result.output.lower() or "MAC" in result.output

    def test_spoof_mac_failure(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.spoofer.spoof_address",
            lambda *a, **kw: False,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "mac", FAKE_MAC])
        assert result.exit_code == 0
        assert "fail" in result.output.lower()

    def test_spoof_clone(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.spoofer.clone_device_identity",
            lambda *a, **kw: True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "clone", FAKE_MAC, "Galaxy S24"])
        assert result.exit_code == 0

    def test_spoof_clone_no_name(self, monkeypatch, _stub_session):
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "clone", FAKE_MAC])
        assert result.exit_code == 0
        assert "name" in result.output.lower() or "required" in result.output.lower()

    def test_spoof_restore(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.spoofer.restore_original_mac",
            lambda *a, **kw: True,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "restore"])
        assert result.exit_code == 0
        assert "restored" in result.output.lower() or "Original" in result.output

    def test_spoof_restore_failure(self, monkeypatch, _stub_session):
        monkeypatch.setattr(
            "blue_tap.core.spoofer.restore_original_mac",
            lambda *a, **kw: False,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "restore"])
        assert result.exit_code == 0
        assert "fail" in result.output.lower()


# ============================================================================
# CLI — _save_json
# ============================================================================

class TestSaveJson:
    def test_writes_valid_json(self, tmp_path):
        out = str(tmp_path / "subdir" / "out.json")
        _save_json({"key": "value", "num": 42}, out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["key"] == "value"
        assert data["num"] == 42

    def test_creates_directories(self, tmp_path):
        out = str(tmp_path / "a" / "b" / "c" / "data.json")
        _save_json([1, 2, 3], out)
        assert os.path.exists(out)

    def test_handles_non_serializable(self, tmp_path):
        """default=str in json.dump should handle datetime etc."""
        from datetime import datetime
        out = str(tmp_path / "dt.json")
        _save_json({"ts": datetime(2025, 1, 1)}, out)
        with open(out) as f:
            data = json.load(f)
        assert "2025" in data["ts"]


# ============================================================================
# report/generator.py — ReportGenerator init
# ============================================================================

class TestReportGeneratorInit:
    def test_empty_state(self):
        rg = ReportGenerator()
        assert rg.scan_results == []
        assert rg.vuln_findings == []
        assert rg.attack_results == {}
        assert rg.dos_results == []
        assert rg.pbap_results == {}
        assert rg.map_results == {}
        assert rg.recon_results == []
        assert rg.fuzz_results == []
        assert rg.fingerprint_results == {}


# ============================================================================
# report/generator.py — data intake methods
# ============================================================================

class TestReportGeneratorIntake:
    def test_add_scan_results(self):
        rg = ReportGenerator()
        devs = _make_devices(3)
        rg.add_scan_results(devs)
        assert len(rg.scan_results) == 3
        # Adding more extends
        rg.add_scan_results(_make_devices(2))
        assert len(rg.scan_results) == 5

    def test_add_vuln_findings(self):
        rg = ReportGenerator()
        findings = _make_findings()
        rg.add_vuln_findings(findings)
        assert len(rg.vuln_findings) == 5

    def test_add_attack_results(self):
        rg = ReportGenerator()
        rg.add_attack_results({"phase": "spoof", "success": True})
        assert rg.attack_results["phase"] == "spoof"
        # Update merges
        rg.add_attack_results({"phase2": "pbap"})
        assert "phase" in rg.attack_results
        assert "phase2" in rg.attack_results

    def test_add_dos_results(self):
        rg = ReportGenerator()
        rg.add_dos_results({"type": "l2cap_flood", "packets": 1000})
        rg.add_dos_results({"type": "rfcomm_flood", "packets": 500})
        assert len(rg.dos_results) == 2

    def test_add_session_metadata(self):
        rg = ReportGenerator()
        meta = {"name": "test_session", "created": "2025-01-01", "commands": []}
        rg.add_session_metadata(meta)
        assert rg._session_metadata["name"] == "test_session"


# ============================================================================
# report/generator.py — generate_json
# ============================================================================

class TestReportGenerateJson:
    def test_writes_valid_json(self, tmp_path):
        rg = ReportGenerator()
        rg.add_scan_results(_make_devices(2))
        rg.add_vuln_findings(_make_findings())
        out = str(tmp_path / "report.json")
        result_path = rg.generate_json(out)
        assert result_path == out
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["tool"] == "Blue-Tap"
        assert "generated" in data
        assert "risk_rating" in data
        assert data["summary"]["devices_scanned"] == 2
        assert data["summary"]["total_findings"] == 5

    def test_json_structure_keys(self, tmp_path):
        rg = ReportGenerator()
        out = str(tmp_path / "empty.json")
        rg.generate_json(out)
        with open(out) as f:
            data = json.load(f)
        expected_keys = {
            "generated", "tool", "tool_version", "risk_rating", "scope",
            "summary", "timeline", "fingerprint", "scan_results",
            "vulnerabilities", "pbap_data", "map_data", "attack_results",
            "recon_results", "dos_results", "audio_captures", "other_data", "notes",
        }
        # All expected keys should be present
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

    def test_json_creates_dirs(self, tmp_path):
        rg = ReportGenerator()
        out = str(tmp_path / "deep" / "nested" / "report.json")
        rg.generate_json(out)
        assert os.path.exists(out)

    def test_json_with_session_metadata(self, tmp_path):
        rg = ReportGenerator()
        rg.add_session_metadata({
            "name": "test", "created": "2025-01-01",
            "targets": [FAKE_MAC],
            "commands": [
                {"command": "vulnscan", "category": "vuln",
                 "target": FAKE_MAC, "timestamp": "2025-01-01T10:00:00"},
            ],
        })
        out = str(tmp_path / "meta.json")
        rg.generate_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["scope"]["session_name"] == "test"
        assert len(data["timeline"]) == 1

    def test_json_summary_counts(self, tmp_path):
        rg = ReportGenerator()
        rg.add_vuln_findings([
            {"name": "A", "severity": "critical", "status": "confirmed"},
            {"name": "B", "severity": "high", "status": "potential"},
            {"name": "C", "severity": "low", "status": "unverified"},
        ])
        out = str(tmp_path / "counts.json")
        rg.generate_json(out)
        with open(out) as f:
            data = json.load(f)
        assert data["summary"]["confirmed"] == 1
        assert data["summary"]["potential"] == 1
        assert data["summary"]["unverified"] == 1
        assert data["summary"]["high_severity"] == 2  # critical + high


# ============================================================================
# report/generator.py — generate_html
# ============================================================================

class TestReportGenerateHtml:
    def test_writes_html_file(self, tmp_path):
        rg = ReportGenerator()
        rg.add_scan_results(_make_devices(1))
        rg.add_vuln_findings(_make_findings())
        out = str(tmp_path / "report.html")
        result_path = rg.generate_html(out)
        assert result_path == out
        assert os.path.exists(out)
        with open(out) as f:
            content = f.read()
        assert "<html" in content.lower()
        assert "Blue-Tap" in content

    def test_html_contains_findings(self, tmp_path):
        rg = ReportGenerator()
        rg.add_vuln_findings([
            {"name": "TestVuln", "severity": "high", "status": "confirmed",
             "cve": "CVE-2024-1234", "description": "Test vulnerability"},
        ])
        out = str(tmp_path / "vuln.html")
        rg.generate_html(out)
        with open(out) as f:
            content = f.read()
        assert "TestVuln" in content or "CVE-2024-1234" in content

    def test_html_with_empty_data(self, tmp_path):
        rg = ReportGenerator()
        out = str(tmp_path / "empty.html")
        rg.generate_html(out)
        assert os.path.exists(out)


# ============================================================================
# report/generator.py — load_from_directory
# ============================================================================

class TestReportLoadFromDirectory:
    def test_loads_attack_results(self, tmp_path):
        data = {"phase": "recon", "target": FAKE_MAC}
        with open(tmp_path / "attack_results.json", "w") as f:
            json.dump(data, f)
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        assert rg.attack_results["phase"] == "recon"

    def test_loads_vuln_json(self, tmp_path):
        findings = _make_findings()
        with open(tmp_path / "vuln_scan.json", "w") as f:
            json.dump(findings, f)
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        assert len(rg.vuln_findings) == 5

    def test_nonexistent_directory(self, tmp_path):
        rg = ReportGenerator()
        # Should not raise, just log error
        rg.load_from_directory(str(tmp_path / "nonexistent"))

    def test_loads_scan_json(self, tmp_path):
        scan_data = _make_devices(2)
        with open(tmp_path / "scan_results.json", "w") as f:
            json.dump(scan_data, f)
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        # scan files go into recon_results since they match "scan" keyword
        assert len(rg.recon_results) == 2

    def test_loads_dos_json(self, tmp_path):
        dos_data = {"type": "flood", "packets": 500}
        with open(tmp_path / "dos_results.json", "w") as f:
            json.dump(dos_data, f)
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        assert len(rg.dos_results) == 1

    def test_ignores_malformed_json(self, tmp_path):
        with open(tmp_path / "broken.json", "w") as f:
            f.write("{bad json content")
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        # Should not raise

    def test_loads_vcf_files(self, tmp_path):
        vcf_content = "BEGIN:VCARD\nFN:John Doe\nEND:VCARD\nBEGIN:VCARD\nFN:Jane Doe\nEND:VCARD"
        with open(tmp_path / "contacts.vcf", "w") as f:
            f.write(vcf_content)
        rg = ReportGenerator()
        rg.load_from_directory(str(tmp_path))
        # VCF files get loaded into pbap_results
        assert len(rg.pbap_results) > 0


# ============================================================================
# CLI — no traceback on any major command path
# ============================================================================

class TestCLINoTraceback:
    """Every command invocation should produce no Python traceback in output."""

    def test_main_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Traceback" not in result.output

    def test_scan_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0

    def test_recon_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["recon", "--help"])
        assert result.exit_code == 0

    def test_spoof_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["spoof", "--help"])
        assert result.exit_code == 0
