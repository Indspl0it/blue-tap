"""Tests for attack module standardized envelope outputs."""
from __future__ import annotations

from blue_tap.modules.exploitation.hijack import HijackSession
from blue_tap.modules.exploitation.knob import KNOBAttack
from blue_tap.modules.exploitation.bias import BIASAttack
from blue_tap.modules.exploitation.ssp_downgrade import SSPDowngradeAttack
from blue_tap.modules.exploitation.bluffs import BLUFFSAttack
from blue_tap.modules.exploitation.encryption_downgrade import EncryptionDowngradeAttack
from blue_tap.modules.exploitation.ctkd import CTKDAttack


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stub_hijack_session(monkeypatch) -> HijackSession:
    """Create a HijackSession with all external calls stubbed out."""
    session = HijackSession(
        ivi_address="AA:BB:CC:DD:EE:FF",
        phone_address="11:22:33:44:55:66",
        phone_name="TestPhone",
        hci="hci0",
    )
    # Stub adapter check
    monkeypatch.setattr(session, "_check_adapter", lambda: True)
    return session


def _assert_envelope_v2(envelope: dict, module: str = "attack"):
    """Verify an envelope satisfies v2 schema requirements."""
    assert envelope["schema_version"] == 2, f"Expected schema_version 2, got {envelope.get('schema_version')}"
    assert envelope["module"] == module
    assert "run_id" in envelope and envelope["run_id"]
    assert "started_at" in envelope
    assert "completed_at" in envelope
    assert isinstance(envelope["executions"], list)
    assert isinstance(envelope.get("artifacts", []), list)
    assert isinstance(envelope.get("module_data", {}), dict)
    assert isinstance(envelope.get("summary", {}), dict)


def _assert_execution_record(rec: dict):
    """Verify an execution record has the required fields."""
    for field in ("execution_id", "kind", "id", "title", "module",
                  "protocol", "execution_status", "module_outcome",
                  "started_at", "completed_at", "evidence"):
        assert field in rec, f"ExecutionRecord missing field: {field}"
    assert rec["execution_status"] in ("completed", "failed", "error", "skipped", "timeout")
    assert isinstance(rec["evidence"], dict)
    assert "summary" in rec["evidence"]


# ---------------------------------------------------------------------------
# Hijack tests
# ---------------------------------------------------------------------------

def test_hijack_build_envelope_produces_v2(monkeypatch):
    """HijackSession.build_envelope() returns a valid v2 RunEnvelope."""
    from blue_tap.hardware import scanner as _scanner_mod
    from blue_tap.modules.reconnaissance import fingerprint as _fp_mod, sdp as _sdp_mod

    session = _stub_hijack_session(monkeypatch)

    # Stub recon dependencies
    monkeypatch.setattr(_scanner_mod, "resolve_name", lambda addr, hci="hci0": "TestPhone")
    monkeypatch.setattr(
        _fp_mod, "fingerprint_device",
        lambda addr, hci="hci0": {"name": "TestIVI", "attack_surface": ["HFP", "PBAP"]},
    )
    monkeypatch.setattr(_sdp_mod, "browse_services", lambda addr: [])
    monkeypatch.setattr(_sdp_mod, "find_service_channel", lambda addr, name, services=None: None)

    # Run recon only (the safest phase to test in isolation)
    session.recon()

    envelope = session.build_envelope()
    _assert_envelope_v2(envelope)

    # Should have at least one execution record from recon
    assert len(envelope["executions"]) >= 1
    _assert_execution_record(envelope["executions"][0])
    assert envelope["executions"][0]["id"] == "hijack_recon"


def test_hijack_envelope_has_cli_events(monkeypatch):
    """Hijack envelope includes collected CLI events in module_data."""
    from blue_tap.hardware import scanner as _scanner_mod
    from blue_tap.modules.reconnaissance import fingerprint as _fp_mod, sdp as _sdp_mod

    session = _stub_hijack_session(monkeypatch)
    monkeypatch.setattr(_scanner_mod, "resolve_name", lambda addr, hci="hci0": "Phone")
    monkeypatch.setattr(_fp_mod, "fingerprint_device", lambda addr, hci="hci0": {"name": "IVI"})
    monkeypatch.setattr(_sdp_mod, "browse_services", lambda addr: [])
    monkeypatch.setattr(_sdp_mod, "find_service_channel", lambda addr, name, services=None: None)

    session.recon()
    envelope = session.build_envelope()

    cli_events = envelope["module_data"].get("cli_events", [])
    assert len(cli_events) >= 2  # At least phase_started + execution_result
    event_types = {e["event_type"] for e in cli_events}
    assert "phase_started" in event_types
    assert "execution_result" in event_types


def test_hijack_failed_phase_records_error(monkeypatch):
    """A failed recon produces an execution record with error status."""
    from blue_tap.hardware import scanner as _scanner_mod
    from blue_tap.modules.reconnaissance import fingerprint as _fp_mod

    session = _stub_hijack_session(monkeypatch)
    monkeypatch.setattr(_scanner_mod, "resolve_name", lambda addr, hci="hci0": "Phone")
    monkeypatch.setattr(_fp_mod, "fingerprint_device", lambda addr, hci="hci0": None)

    from blue_tap.modules.reconnaissance import sdp as _sdp_mod
    monkeypatch.setattr(_sdp_mod, "browse_services", lambda addr: [])
    monkeypatch.setattr(_sdp_mod, "find_service_channel", lambda addr, name, services=None: None)

    session.recon()
    envelope = session.build_envelope()
    _assert_envelope_v2(envelope)
    assert len(envelope["executions"]) >= 1


# ---------------------------------------------------------------------------
# KNOB tests
# ---------------------------------------------------------------------------

def test_knob_probe_produces_execution_record(monkeypatch):
    """KNOBAttack.probe() creates an execution record with correct fields."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")

    # Stub external calls
    monkeypatch.setattr(attack, "_get_bt_version", lambda: (4.2, "4.2 (0x8)"))
    monkeypatch.setattr(attack, "_get_connection_handle", lambda: None)
    monkeypatch.setattr(attack, "_check_darkfirmware", lambda: False)

    result = attack.probe()

    assert result["likely_vulnerable"] is True
    assert len(attack._executions) == 1

    rec = attack._executions[0]
    _assert_execution_record(rec)
    assert rec["id"] == "knob_probe"
    assert rec["module_outcome"] == "confirmed"
    assert "CVE-2019-9506" in rec.get("tags", [])


def test_knob_probe_not_vulnerable(monkeypatch):
    """KNOB probe on patched device produces not_applicable outcome."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    monkeypatch.setattr(attack, "_get_bt_version", lambda: (5.2, "5.2 (0xb)"))
    monkeypatch.setattr(attack, "_get_connection_handle", lambda: None)
    monkeypatch.setattr(attack, "_check_darkfirmware", lambda: False)

    result = attack.probe()

    assert result["likely_vulnerable"] is False
    rec = attack._executions[0]
    assert rec["module_outcome"] == "not_applicable"


def test_knob_build_envelope_v2(monkeypatch):
    """KNOBAttack.build_envelope() produces a valid v2 envelope."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    monkeypatch.setattr(attack, "_get_bt_version", lambda: (4.0, "4.0"))
    monkeypatch.setattr(attack, "_get_connection_handle", lambda: None)
    monkeypatch.setattr(attack, "_check_darkfirmware", lambda: False)

    attack.probe()
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["cve"] == "CVE-2019-9506"
    assert len(envelope["executions"]) == 1


def test_knob_brute_force_execution_record(monkeypatch):
    """Brute force phase produces an execution record."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")

    # Provide ACL data that will match key=0x00 with XOR
    # L2CAP header: length=0, CID=0x0001 → bytes 00 00 01 00
    acl_data = b"\x00\x00\x01\x00"
    result = attack.brute_force_key(key_size=1, acl_data=acl_data)

    assert result["key_found"] is True
    assert result["key_hex"] == "00"
    assert len(attack._executions) == 1
    rec = attack._executions[0]
    _assert_execution_record(rec)
    assert rec["id"] == "knob_brute_force"
    assert rec["module_outcome"] == "success"


def test_knob_execute_uses_requested_key_size(monkeypatch):
    """KNOBAttack.execute() passes the caller's requested key size through."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")

    monkeypatch.setattr(attack, "probe", lambda: {"likely_vulnerable": True})

    def _fake_negotiate(requested_key_size: int = 1):
        return {
            "requested_key_size": requested_key_size,
            "negotiated_key_size": None,
            "success": False,
            "method": "stub",
        }

    brute_force_calls: list[int] = []

    def _fake_brute_force(key_size: int = 1, acl_data=None):
        brute_force_calls.append(key_size)
        return {
            "key_found": False,
            "key_hex": None,
            "total_candidates": 2 ** (key_size * 8),
            "time_elapsed": 0.0,
        }

    monkeypatch.setattr(attack, "negotiate_min_key", _fake_negotiate)
    monkeypatch.setattr(attack, "brute_force_key", _fake_brute_force)

    result = attack.execute(key_size=2)

    assert result["requested_key_size"] == 2
    assert result["phases"]["negotiate"]["requested_key_size"] == 2
    assert brute_force_calls == [2]


# ---------------------------------------------------------------------------
# BIAS tests
# ---------------------------------------------------------------------------

def test_bias_build_envelope_v2():
    """BIASAttack.build_envelope() produces a valid v2 envelope."""
    attack = BIASAttack("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "TestPhone", "hci0")
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["cve"] == "CVE-2020-10135"


def test_bias_has_run_id_and_tracking():
    """BIASAttack initializes with run_id, cli_events, and executions tracking."""
    attack = BIASAttack("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "", "hci0")
    assert attack.run_id.startswith("bias-")
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_knob_has_run_id_and_tracking():
    """KNOBAttack initializes with run_id, cli_events, and executions tracking."""
    attack = KNOBAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    assert attack.run_id.startswith("knob-")
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_hijack_has_run_id_and_tracking():
    """HijackSession initializes with run_id, cli_events, and executions tracking."""
    session = HijackSession("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", hci="hci0")
    assert session.run_id.startswith("hijack-")
    assert isinstance(session._cli_events, list)
    assert isinstance(session._executions, list)


# ---------------------------------------------------------------------------
# SSP Downgrade tests
# ---------------------------------------------------------------------------

def test_ssp_downgrade_has_tracking():
    """SSPDowngradeAttack has standardized tracking fields."""
    attack = SSPDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    assert attack.run_id.startswith("ssp-downgrade-")
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_ssp_downgrade_probe_produces_execution_record(monkeypatch):
    """SSP probe creates an execution record."""
    attack = SSPDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")

    # Stub hcitool and btmgmt
    from blue_tap.modules.exploitation import ssp_downgrade as _mod
    from unittest.mock import MagicMock
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "not reachable"
    monkeypatch.setattr(_mod, "run_cmd", lambda *a, **kw: mock_result)

    result = attack.probe()

    assert len(attack._executions) == 1
    rec = attack._executions[0]
    _assert_execution_record(rec)
    assert rec["id"] == "ssp_probe"


def test_ssp_downgrade_build_envelope_v2():
    """SSPDowngradeAttack.build_envelope() produces a valid v2 envelope."""
    attack = SSPDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["operation"] == "ssp_downgrade"


# ---------------------------------------------------------------------------
# BLUFFS tests
# ---------------------------------------------------------------------------

def test_bluffs_has_tracking():
    """BLUFFSAttack has standardized tracking fields."""
    attack = BLUFFSAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    assert attack.run_id.startswith("bluffs-")
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_bluffs_build_envelope_v2():
    """BLUFFSAttack.build_envelope() produces a valid v2 envelope."""
    attack = BLUFFSAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["cve"] == "CVE-2023-24023"


def test_bluffs_execute_unimplemented_variant():
    """Unimplemented variant (a2) produces a skipped execution record."""
    attack = BLUFFSAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    result = attack.execute(variant="a2")
    assert result["success"] is False
    assert len(attack._executions) == 1
    assert attack._executions[0]["execution_status"] == "skipped"


# ---------------------------------------------------------------------------
# Encryption Downgrade tests
# ---------------------------------------------------------------------------

def test_encryption_downgrade_has_tracking():
    """EncryptionDowngradeAttack has standardized tracking fields."""
    attack = EncryptionDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    assert attack.run_id.startswith("enc-downgrade-")
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_encryption_downgrade_build_envelope_v2():
    """EncryptionDowngradeAttack.build_envelope() produces a valid v2 envelope."""
    attack = EncryptionDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["operation"] == "encryption_downgrade"


def test_encryption_downgrade_no_darkfirmware():
    """DarkFirmware unavailable produces EXECUTION_FAILED records."""
    attack = EncryptionDowngradeAttack("AA:BB:CC:DD:EE:FF", hci="hci0")
    attack._darkfirmware_available = False  # bypass lazy check

    result = attack.disable_encryption()
    assert result.get("error") == "darkfirmware_unavailable"
    assert len(attack._executions) == 1
    assert attack._executions[0]["execution_status"] == "failed"


# ---------------------------------------------------------------------------
# CTKD tests
# ---------------------------------------------------------------------------

def test_ctkd_has_tracking():
    """CTKDAttack has standardized tracking fields."""
    attack = CTKDAttack("aa:bb:cc:dd:ee:ff", hci="hci1")
    assert attack.run_id.startswith("ctkd-")
    assert attack.target == "AA:BB:CC:DD:EE:FF"
    assert isinstance(attack._cli_events, list)
    assert isinstance(attack._executions, list)


def test_ctkd_build_envelope_v2():
    """CTKDAttack.build_envelope() produces a valid v2 envelope."""
    attack = CTKDAttack("AA:BB:CC:DD:EE:FF", hci="hci1")
    envelope = attack.build_envelope()
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["cve"] == "CVE-2020-15802"


def test_ctkd_probe_no_darkfirmware(monkeypatch):
    """CTKD probe with no DarkFirmware produces EXECUTION_FAILED record."""
    from unittest.mock import MagicMock
    mock_fw = MagicMock()
    mock_fw.is_darkfirmware_loaded.return_value = False
    monkeypatch.setattr(
        "blue_tap.hardware.firmware.DarkFirmwareManager", lambda: mock_fw
    )

    attack = CTKDAttack("AA:BB:CC:DD:EE:FF", hci="hci1")
    result = attack.probe()
    assert result["error"] == "DarkFirmware not loaded"
    assert len(attack._executions) == 1
    rec = attack._executions[0]
    _assert_execution_record(rec)
    assert rec["execution_status"] == "failed"
    assert rec["module_outcome"] == "failed"
