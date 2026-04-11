"""Tests for spoof module envelope outputs and adapter."""
from __future__ import annotations

import json

from blue_tap.core.spoof_framework import (
    SPOOF_MODULE_OUTCOMES,
    build_spoof_result,
    make_spoof_run_id,
)
from blue_tap.core.result_schema import validate_run_envelope
from blue_tap.report.adapters.spoof import SpoofReportAdapter


def _make_spoof_envelope(operation="mac", success=True):
    result = {
        "success": success,
        "method_used": "bdaddr",
        "methods_tried": ["bdaddr"],
        "original_mac": "11:22:33:44:55:66",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "verified": success,
        "hci": "hci0",
        "error": "" if success else "hardware rejected",
    }
    return build_spoof_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        operation=operation,
        result=result,
    )


def test_spoof_run_id_format():
    rid = make_spoof_run_id()
    assert rid.startswith("spoof-")


def test_spoof_envelope_v2():
    env = _make_spoof_envelope()
    assert env["schema"] == "blue_tap.spoof.result"
    assert env["schema_version"] == 2
    assert env["module"] == "spoof"
    assert len(env["executions"]) >= 1


def test_spoof_envelope_validates():
    env = _make_spoof_envelope()
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_spoof_success_outcome():
    env = _make_spoof_envelope(success=True)
    assert env["executions"][0]["module_outcome"] == "spoofed"


def test_spoof_failure_outcome():
    env = _make_spoof_envelope(success=False)
    assert env["executions"][0]["module_outcome"] == "rejected"


def test_spoof_evidence_has_mac_info():
    env = _make_spoof_envelope()
    obs = env["executions"][0]["evidence"]["observations"]
    assert any("Original MAC" in o for o in obs)
    assert any("Target MAC" in o for o in obs)


def test_spoof_restore_outcome():
    result = {
        "success": True,
        "restored_mac": "11:22:33:44:55:66",
        "hci": "hci0",
        "method": "bdaddr",
        "error": "",
    }
    env = build_spoof_result(
        target="11:22:33:44:55:66", adapter="hci0",
        operation="restore", result=result,
    )
    assert env["executions"][0]["module_outcome"] == "restored"


def test_spoof_json_serializable():
    env = _make_spoof_envelope()
    assert len(json.dumps(env, default=str)) > 0


def test_spoof_adapter_accepts():
    adapter = SpoofReportAdapter()
    env = _make_spoof_envelope()
    assert adapter.accepts(env)


def test_spoof_adapter_rejects_non_spoof():
    adapter = SpoofReportAdapter()
    assert not adapter.accepts({"module": "fuzz"})


def test_spoof_adapter_round_trip():
    adapter = SpoofReportAdapter()
    state = {}
    adapter.ingest(_make_spoof_envelope(), state)
    assert len(state["spoof_operations"]) == 1
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
    js = adapter.build_json_section(state)
    assert "operations" in js
