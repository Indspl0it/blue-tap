"""Tests for firmware module envelope outputs and adapter."""
from __future__ import annotations

import json

from blue_tap.framework.envelopes.firmware import (
    FIRMWARE_MODULE_OUTCOMES,
    build_firmware_status_result,
    build_firmware_dump_result,
    build_connection_inspect_result,
    build_firmware_operation_result,
    make_firmware_run_id,
)
from blue_tap.framework.contracts.result_schema import validate_run_envelope
from blue_tap.framework.reporting.adapters.firmware import FirmwareReportAdapter


def test_firmware_run_id_format():
    rid = make_firmware_run_id()
    assert rid.startswith("firmware-")


def test_firmware_status_envelope_v2():
    env = build_firmware_status_result(
        adapter="hci1",
        status={"installed": True, "loaded": True, "hooks": {"hook1": True, "hook2": True, "hook3": True, "hook4": True}},
    )
    assert env["schema"] == "blue_tap.firmware.result"
    assert env["schema_version"] == 2
    assert env["executions"][0]["module_outcome"] == "hooks_active"


def test_firmware_status_partial_hooks():
    env = build_firmware_status_result(
        adapter="hci1",
        status={"installed": True, "loaded": True, "hooks": {"hook1": True, "hook2": False}},
    )
    assert env["executions"][0]["module_outcome"] == "hooks_partial"


def test_firmware_status_validates():
    env = build_firmware_status_result(
        adapter="hci1",
        status={"installed": True, "loaded": False, "hooks": {}},
    )
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_firmware_dump_envelope():
    env = build_firmware_dump_result(
        adapter="hci1",
        start_addr=0x80000000,
        end_addr=0x80100000,
        output_path="/tmp/rom.bin",
        success=True,
        file_size=1048576,
        invalid_regions=[(0x80010000, 0x80011000)],
    )
    assert env["schema"] == "blue_tap.firmware.result"
    assert len(env["artifacts"]) == 1
    obs = env["executions"][0]["evidence"]["observations"]
    assert any("Invalid" in o for o in obs)


def test_firmware_dump_validates():
    env = build_firmware_dump_result(
        adapter="hci1", start_addr=0, end_addr=256,
        output_path="/tmp/test.bin", success=True,
    )
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_connection_inspect_knob():
    env = build_connection_inspect_result(
        adapter="hci1",
        connections=[
            {"active": True, "address": "AA:BB:CC:DD:EE:FF", "encryption_enabled": True, "key_size": 1, "secure_connections": False},
            {"active": True, "address": "11:22:33:44:55:66", "encryption_enabled": True, "key_size": 16, "secure_connections": True},
        ],
    )
    assert "KNOB" in env["executions"][0]["evidence"]["summary"]
    assert env["executions"][0].get("severity") == "high"


def test_connection_inspect_no_knob():
    env = build_connection_inspect_result(
        adapter="hci1",
        connections=[
            {"active": True, "address": "11:22:33:44:55:66", "encryption_enabled": True, "key_size": 16, "secure_connections": True},
        ],
    )
    assert env["executions"][0].get("severity") is None


def test_connection_inspect_validates():
    env = build_connection_inspect_result(adapter="hci1", connections=[])
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_firmware_operation_install():
    env = build_firmware_operation_result(
        adapter="hci1", operation="install", title="Install DarkFirmware",
        success=True, observations=["Backup saved", "Firmware written"],
    )
    assert env["executions"][0]["module_outcome"] == "installed"


def test_firmware_operation_validates():
    env = build_firmware_operation_result(
        adapter="hci1", operation="init", title="Initialize Hooks",
        success=True,
    )
    errors = validate_run_envelope(env)
    assert errors == [], f"Validation errors: {errors}"


def test_all_firmware_envelopes_json_serializable():
    envs = [
        build_firmware_status_result(adapter="hci1", status={"installed": True, "loaded": True, "hooks": {}}),
        build_firmware_dump_result(adapter="hci1", start_addr=0, end_addr=256, output_path="/tmp/x", success=True),
        build_connection_inspect_result(adapter="hci1", connections=[]),
        build_firmware_operation_result(adapter="hci1", operation="test", title="Test", success=True),
    ]
    for env in envs:
        assert len(json.dumps(env, default=str)) > 0


def test_firmware_adapter_accepts():
    adapter = FirmwareReportAdapter()
    env = build_firmware_status_result(adapter="hci1", status={"installed": True, "loaded": True, "hooks": {}})
    assert adapter.accepts(env)


def test_firmware_adapter_rejects_non_firmware():
    adapter = FirmwareReportAdapter()
    assert not adapter.accepts({"module": "fuzz"})


def test_firmware_adapter_round_trip():
    adapter = FirmwareReportAdapter()
    state = {}
    env = build_firmware_status_result(adapter="hci1", status={"installed": True, "loaded": True, "hooks": {}})
    adapter.ingest(env, state)
    assert len(state["firmware_operations"]) == 1
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
    js = adapter.build_json_section(state)
    assert "operations" in js


def test_firmware_adapter_connection_inspection_card():
    adapter = FirmwareReportAdapter()
    state = {}
    env = build_connection_inspect_result(
        adapter="hci1",
        connections=[{"active": True, "address": "AA:BB:CC:DD:EE:FF", "encryption_enabled": True, "key_size": 1, "secure_connections": False}],
    )
    adapter.ingest(env, state)
    assert len(state.get("connection_inspections", [])) == 1
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
