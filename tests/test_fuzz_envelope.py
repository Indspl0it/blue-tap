"""Tests for fuzz module standardized envelope outputs."""
from __future__ import annotations

import json

from blue_tap.framework.envelopes.fuzz import (
    FUZZ_MODULE_OUTCOMES,
    build_fuzz_campaign_result,
    build_fuzz_operation_result,
    build_fuzz_protocol_execution,
    build_fuzz_result,
    make_fuzz_run_id,
)
from blue_tap.framework.contracts.result_schema import validate_run_envelope
from blue_tap.modules.fuzzing.engine import FuzzCampaign, PROTOCOL_TRANSPORT_MAP
from blue_tap.modules.fuzzing.protocols.l2cap_raw import generate_all_l2cap_sig_fuzz_cases


def _assert_envelope_v2(envelope: dict, module: str = "fuzzing"):
    assert envelope["schema_version"] == 2
    assert envelope["module"] == module
    assert envelope["schema"] == "blue_tap.fuzz.result"
    assert "run_id" in envelope and envelope["run_id"]
    assert "started_at" in envelope
    assert "completed_at" in envelope
    assert isinstance(envelope["executions"], list)
    assert len(envelope["executions"]) >= 1
    assert isinstance(envelope.get("artifacts", []), list)
    assert isinstance(envelope.get("module_data", {}), dict)
    assert isinstance(envelope.get("summary", {}), dict)


def _assert_execution_record(rec: dict):
    for field in ("execution_id", "kind", "id", "title", "module",
                  "protocol", "execution_status", "module_outcome",
                  "started_at", "completed_at", "evidence"):
        assert field in rec, f"ExecutionRecord missing field: {field}"
    assert rec["execution_status"] in ("completed", "failed", "error", "skipped", "timeout")
    assert isinstance(rec["evidence"], dict)
    assert "summary" in rec["evidence"]
    assert rec["evidence"]["summary"], "Evidence summary must be non-empty"


def _assert_evidence_has_observations(rec: dict):
    evidence = rec["evidence"]
    observations = evidence.get("observations", [])
    assert isinstance(observations, list)
    assert len(observations) > 0, "Evidence must have at least one observation"


# ---------------------------------------------------------------------------
# Run ID
# ---------------------------------------------------------------------------

def test_fuzz_run_id_format():
    rid = make_fuzz_run_id()
    assert rid.startswith("fuzz-")
    assert len(rid) > 10


def test_fuzz_run_id_is_unique():
    ids = {make_fuzz_run_id() for _ in range(10)}
    assert len(ids) == 10


# ---------------------------------------------------------------------------
# Single protocol run envelope
# ---------------------------------------------------------------------------

def test_single_protocol_envelope_v2():
    envelope = build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_sdp",
        protocol="sdp",
        result={"sent": 100, "crashes": 2, "errors": 0, "elapsed": 10.5, "total_cases": 100},
    )
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["run_type"] == "single_protocol_run"
    assert envelope["summary"]["crashes"] == 2


def test_single_protocol_execution_record():
    envelope = build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_sdp",
        protocol="sdp",
        result={"sent": 50, "crashes": 1, "errors": 0, "elapsed": 5.0},
    )
    assert len(envelope["executions"]) == 1
    rec = envelope["executions"][0]
    _assert_execution_record(rec)
    assert rec["module_outcome"] == "crash_detected"
    assert rec["protocol"] == "sdp"


def test_single_protocol_no_crashes_outcome():
    envelope = build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_att",
        protocol="ble-att",
        result={"sent": 200, "crashes": 0, "errors": 0, "elapsed": 20.0},
    )
    rec = envelope["executions"][0]
    assert rec["module_outcome"] == "completed"


def test_single_protocol_run_id_passed_through():
    rid = "fuzz-test-1234"
    envelope = build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_sdp",
        protocol="sdp",
        result={"sent": 10, "crashes": 0, "errors": 0, "elapsed": 1.0},
        run_id=rid,
    )
    assert envelope["run_id"] == rid


def test_single_protocol_validates():
    envelope = build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_sdp",
        protocol="sdp",
        result={"sent": 10, "crashes": 0, "errors": 0, "elapsed": 1.0},
    )
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Validation errors: {errors}"


# ---------------------------------------------------------------------------
# Per-protocol execution record
# ---------------------------------------------------------------------------

def test_protocol_execution_has_required_fields():
    rec = build_fuzz_protocol_execution(
        protocol="sdp",
        packets_sent=1000,
        crashes=3,
        errors=1,
        crash_types={"connection_drop": 2, "timeout": 1},
        anomalies=5,
        states_discovered=8,
    )
    _assert_execution_record(rec)
    assert rec["kind"] == "probe"
    assert rec["id"] == "fuzz_sdp"
    assert rec["module"] == "fuzzing"
    assert rec["protocol"] == "sdp"


def test_protocol_execution_crash_outcome():
    rec = build_fuzz_protocol_execution(
        protocol="ble-att", packets_sent=500, crashes=1, errors=0,
    )
    assert rec["module_outcome"] == "crash_detected"


def test_protocol_execution_completed_outcome():
    rec = build_fuzz_protocol_execution(
        protocol="rfcomm", packets_sent=500, crashes=0, errors=0,
    )
    assert rec["module_outcome"] == "completed"


def test_protocol_execution_evidence_observations():
    rec = build_fuzz_protocol_execution(
        protocol="sdp",
        packets_sent=1000,
        crashes=2,
        errors=0,
        anomalies=10,
        states_discovered=5,
        crash_types={"connection_drop": 2},
    )
    _assert_evidence_has_observations(rec)
    obs = rec["evidence"]["observations"]
    assert any("1,000" in o for o in obs), f"Expected packet count in observations: {obs}"
    assert any("crash" in o.lower() for o in obs)


def test_protocol_execution_module_outcome_in_registry():
    for crashes in (0, 3):
        rec = build_fuzz_protocol_execution(
            protocol="sdp", packets_sent=100, crashes=crashes, errors=0,
        )
        assert rec["module_outcome"] in FUZZ_MODULE_OUTCOMES


# ---------------------------------------------------------------------------
# Campaign envelope
# ---------------------------------------------------------------------------

def test_campaign_envelope_v2():
    envelope = build_fuzz_campaign_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary={
            "protocols": ["sdp", "ble-att"],
            "strategy": "coverage_guided",
            "packets_sent": 5000,
            "crashes": 3,
            "errors": 1,
            "runtime_seconds": 120.0,
            "protocol_breakdown": {"sdp": 3000, "ble-att": 2000},
        },
        crashes=[{"severity": "HIGH", "protocol": "sdp"}] * 3,
        session_fuzz_dir="/tmp/fake_fuzz_dir",
    )
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["run_type"] == "campaign"


def test_campaign_envelope_has_per_protocol_executions():
    proto_execs = [
        build_fuzz_protocol_execution(protocol="sdp", packets_sent=3000, crashes=2, errors=0),
        build_fuzz_protocol_execution(protocol="ble-att", packets_sent=2000, crashes=1, errors=0),
    ]
    envelope = build_fuzz_campaign_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary={
            "protocols": ["sdp", "ble-att"],
            "packets_sent": 5000,
            "crashes": 3,
            "runtime_seconds": 60.0,
        },
        crashes=[],
        session_fuzz_dir="/tmp/fake_fuzz_dir",
        protocol_executions=proto_execs,
    )
    # 1 campaign phase + 2 protocol probes
    assert len(envelope["executions"]) == 3
    assert envelope["executions"][0]["kind"] == "phase"
    assert envelope["executions"][1]["kind"] == "probe"
    assert envelope["executions"][2]["kind"] == "probe"


def test_campaign_envelope_validates():
    envelope = build_fuzz_campaign_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary={
            "protocols": ["sdp"],
            "packets_sent": 100,
            "crashes": 0,
            "runtime_seconds": 10.0,
        },
        crashes=[],
        session_fuzz_dir="/tmp/fake_fuzz_dir",
    )
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Validation errors: {errors}"


def test_protocol_transport_map_includes_l2cap_sig_raw_acl():
    assert PROTOCOL_TRANSPORT_MAP["l2cap-sig"]["type"] == "raw-acl"


def test_fuzz_campaign_transport_override_is_applied():
    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap-sig"],
        session_dir="/tmp/fuzz-test",
        transport_overrides={"l2cap-sig": {"hci_dev": 7}},
    )
    assert campaign.transport_overrides["l2cap-sig"]["hci_dev"] == 7


def test_l2cap_sig_generator_returns_full_l2cap_frames():
    cases = generate_all_l2cap_sig_fuzz_cases()
    assert cases
    assert any(len(case) >= 4 for case in cases)
    for case in cases:
        if len(case) >= 4:
            declared_length = int.from_bytes(case[:2], "little")
            cid = int.from_bytes(case[2:4], "little")
            assert cid in {0x0000, 0x0001, 0x0002, 0x0006, 0xFFFF}
            if declared_length != 0xFFFF:
                assert declared_length >= 0


def test_single_protocol_transport_connect_failure_is_finalized(tmp_path, monkeypatch):
    class FakeTransport:
        connected = False

        def connect(self):
            return False

        def close(self):
            return None

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap-sig"],
        session_dir=str(tmp_path),
    )

    monkeypatch.setattr(campaign, "_setup_transports", lambda: campaign._transports.update({"l2cap-sig": FakeTransport()}))
    envelope = campaign.run_single_protocol("l2cap-sig", [b"\x00\x00\x01\x00"])
    assert envelope["summary"]["errors"] == 1
    assert envelope["summary"]["sent"] == 0
    assert envelope["executions"][0]["execution_status"] in {"failed", "error"}


# ---------------------------------------------------------------------------
# Operation envelope
# ---------------------------------------------------------------------------

def test_operation_envelope_v2():
    envelope = build_fuzz_operation_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="corpus_generate",
        title="Generated corpus for 5 protocols",
        observations=["Generated 2900 seeds", "5 protocols covered"],
    )
    _assert_envelope_v2(envelope)
    assert envelope["summary"]["run_type"] == "operation"


def test_operation_envelope_validates():
    envelope = build_fuzz_operation_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="minimize",
        title="Minimized crash #1",
    )
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Validation errors: {errors}"


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

def test_all_envelopes_json_serializable():
    envelopes = [
        build_fuzz_result(
            target="AA:BB:CC:DD:EE:FF", adapter="hci0", command="fuzz_sdp",
            protocol="sdp", result={"sent": 10, "crashes": 0, "errors": 0, "elapsed": 1.0},
        ),
        build_fuzz_campaign_result(
            target="AA:BB:CC:DD:EE:FF", adapter="session",
            campaign_summary={"protocols": ["sdp"], "packets_sent": 10, "crashes": 0, "runtime_seconds": 1.0},
            crashes=[], session_fuzz_dir="/tmp/fake",
        ),
        build_fuzz_operation_result(
            target="AA:BB:CC:DD:EE:FF", adapter="session",
            operation="test", title="Test operation",
        ),
    ]
    for env in envelopes:
        serialized = json.dumps(env, default=str)
        assert len(serialized) > 0
