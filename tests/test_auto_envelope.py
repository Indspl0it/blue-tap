"""Tests for auto mode envelope outputs."""
from __future__ import annotations

import json

from blue_tap.core.auto_framework import (
    AUTO_MODULE_OUTCOMES,
    build_auto_result,
    build_auto_phase_execution,
    make_auto_run_id,
)
from blue_tap.core.result_schema import validate_run_envelope


def _make_auto_results(phases_status=None):
    if phases_status is None:
        phases_status = {
            "discovery": {"status": "success", "_elapsed_seconds": 12.0, "phone_address": "11:22:33:44:55:66"},
            "fingerprint": {"status": "success", "_elapsed_seconds": 5.0},
            "recon": {"status": "success", "_elapsed_seconds": 8.0, "sdp_services": 8},
            "vuln_assessment": {"status": "success", "_elapsed_seconds": 15.0},
            "pairing_attacks": {"status": "success", "_elapsed_seconds": 3.0},
            "exploitation": {"status": "skipped", "reason": "no phone discovered"},
            "fuzzing": {"status": "skipped", "reason": "user requested"},
            "dos_testing": {"status": "success", "_elapsed_seconds": 20.0},
            "report": {"status": "success", "_elapsed_seconds": 2.0},
        }
    return {
        "target": "AA:BB:CC:DD:EE:FF",
        "status": "complete",
        "phases": phases_status,
        "total_time_seconds": 65.0,
    }


def test_auto_run_id_format():
    rid = make_auto_run_id()
    assert rid.startswith("auto-")


def test_auto_envelope_v2():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    assert env["schema"] == "blue_tap.auto.result"
    assert env["schema_version"] == 2
    assert env["module"] == "auto"


def test_auto_envelope_has_per_phase_executions():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    assert len(env["executions"]) == 9


def test_auto_envelope_validates():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_auto_skipped_phase_has_reason():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    exploit_exec = [e for e in env["executions"] if e["id"] == "auto_exploitation"][0]
    assert exploit_exec["execution_status"] == "skipped"
    obs = exploit_exec["evidence"]["observations"]
    assert any("Skipped" in o for o in obs)


def test_auto_failed_phase_has_error():
    phases = _make_auto_results()["phases"]
    phases["recon"] = {"status": "failed", "error": "connection refused", "_elapsed_seconds": 1.0}
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results={"target": "AA:BB:CC:DD:EE:FF", "status": "partial", "phases": phases, "total_time_seconds": 30.0},
    )
    recon_exec = [e for e in env["executions"] if e["id"] == "auto_recon"][0]
    assert recon_exec["execution_status"] == "failed"
    obs = recon_exec["evidence"]["observations"]
    assert any("Error" in o for o in obs)


def test_auto_complete_outcome():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    summary = env["summary"]
    assert summary["phases_passed"] == 7
    assert summary["phases_skipped"] == 2


def test_auto_json_serializable():
    env = build_auto_result(
        target="AA:BB:CC:DD:EE:FF", adapter="hci0",
        results=_make_auto_results(),
    )
    assert len(json.dumps(env, default=str)) > 0


def test_auto_phase_execution_evidence():
    exec_rec = build_auto_phase_execution(
        phase_name="discovery",
        phase_result={"status": "success", "_elapsed_seconds": 12.0, "phone_address": "11:22:33:44:55:66"},
    )
    assert exec_rec["kind"] == "phase"
    assert exec_rec["id"] == "auto_discovery"
    assert exec_rec["evidence"]["summary"]
    assert len(exec_rec["evidence"]["observations"]) > 0
