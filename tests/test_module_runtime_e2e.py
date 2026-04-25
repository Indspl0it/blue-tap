"""End-to-end integration tests for the module runtime.

These tests exercise the full CLI → Invoker → Module.run() → envelope → session
path. They are the regression guard-rail for the framework boundary: any future
API mismatch between the framework helpers (make_run_id, make_execution,
build_run_envelope, make_evidence) and a module wrapper must fail at least one
of these tests.

Do NOT mock the framework helpers. Only mock hardware-touching functions.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
    make_run_id,
    validate_run_envelope,
)
from blue_tap.framework.module import Invoker, ModuleNotFound
from blue_tap.framework.module.autoload import autoload_builtin_modules
from blue_tap.framework.module.base import Module, function_module
from blue_tap.framework.module.context import RunContext
from blue_tap.framework.module.options import OptAddress, OptString
from blue_tap.framework.module.options_container import OptionsContainer
from blue_tap.framework.registry import ModuleFamily, get_registry
from blue_tap.framework.sessions.store import Session


# ── Framework helper contract tests ──────────────────────────────────────────

def test_make_run_id_no_args_returns_uuid():
    run_id = make_run_id()
    assert run_id
    assert isinstance(run_id, str)
    assert "-" in run_id  # UUID format


def test_make_run_id_with_module_prefixes():
    run_id = make_run_id("discovery.scanner")
    assert run_id.startswith("discovery.scanner-")


def test_make_execution_without_module_or_protocol():
    execution = make_execution(
        kind="collector",
        id="test",
        title="Test",
        module_id="discovery.scanner",
        execution_status="completed",
        module_outcome="observed",
        evidence=make_evidence(summary="test evidence"),
    )
    # Empty string defaults must pass validation presence checks
    assert execution["module"] == ""
    assert execution["protocol"] == ""
    assert execution["execution_status"] == "completed"


def test_build_run_envelope_without_operator_context():
    envelope = build_run_envelope(
        schema="blue_tap.test.result",
        module="discovery.scanner",
        module_id="discovery.scanner",
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        summary={"outcome": "observed"},
        executions=[],
        module_data={},
    )
    assert envelope["operator_context"] == {}
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Envelope must validate cleanly: {errors}"


def test_make_evidence_raw_alias_folds_into_module_evidence():
    evidence = make_evidence(
        summary="test",
        raw={"count": 5, "mode": "classic"},
    )
    assert evidence["module_evidence"]["count"] == 5
    assert evidence["module_evidence"]["mode"] == "classic"


def test_make_evidence_raw_and_module_evidence_merge():
    evidence = make_evidence(
        summary="test",
        module_evidence={"base": True},
        raw={"extra": "value"},
    )
    assert evidence["module_evidence"] == {"base": True, "extra": "value"}


# ── Registry tests ───────────────────────────────────────────────────────────

def test_registry_try_get_returns_none_for_unknown_module():
    registry = get_registry()
    assert registry.try_get("nonexistent.module") is None


def test_registry_get_still_raises_key_error_for_unknown_module():
    """Backward-compat: callers that depend on KeyError (e.g. dedup logic) must keep working."""
    registry = get_registry()
    with pytest.raises(KeyError):
        registry.get("nonexistent.module")


# ── Invoker tests ────────────────────────────────────────────────────────────

def test_invoker_unknown_module_raises_module_not_found():
    invoker = Invoker()
    with pytest.raises(ModuleNotFound):
        invoker.invoke("nonexistent.module", {})


def test_run_context_create_does_not_crash():
    container = OptionsContainer.from_schema(())
    container.populate({})
    ctx = RunContext.create(
        options=container,
        module_id="test.module",
        adapter="hci0",
        target="AA:BB:CC:DD:EE:FF",
    )
    assert ctx.run_id
    assert ctx.module_id == "test.module"
    assert ctx.started_at


# ── Session tests ────────────────────────────────────────────────────────────

def test_session_save_raw_accepts_content_kwarg(tmp_path):
    session = Session("test_session", base_dir=str(tmp_path))
    filepath = session.save_raw("test.txt", content="hello")
    assert filepath.endswith("test.txt")


def test_session_save_raw_accepts_data_kwarg(tmp_path):
    session = Session("test_session", base_dir=str(tmp_path))
    filepath = session.save_raw("test.bin", data=b"raw bytes")
    assert filepath.endswith("test.bin")


def test_session_save_raw_accepts_artifact_type_kwarg(tmp_path):
    session = Session("test_session", base_dir=str(tmp_path))
    filepath = session.save_raw(
        "capture.pcap",
        data=b"pcap data",
        artifact_type="pcap",
    )
    # artifact_type should route to a pcap subdirectory
    assert "pcap" in filepath


def test_session_save_raw_rejects_both_missing(tmp_path):
    session = Session("test_session", base_dir=str(tmp_path))
    with pytest.raises(TypeError):
        session.save_raw("bad.txt")


# ── function_module kwarg-bleed test ─────────────────────────────────────────

def test_function_module_ignores_unknown_options():
    """Wrapped functions with narrow signatures must not crash on extra options."""

    @function_module(
        module_id="assessment.narrow_fn_test",
        family=ModuleFamily.ASSESSMENT,
        name="Narrow Function",
        description="fn that only accepts RHOST",
        options=(OptAddress("RHOST", required=True),),
    )
    def narrow_check(RHOST: str) -> dict:
        return {"got": RHOST}

    # Invoke via the container to simulate extra options bleeding through
    container = OptionsContainer.from_schema(narrow_check.options)
    container.populate({"RHOST": "AA:BB:CC:DD:EE:FF", "CONFIRM": "yes", "HCI": "hci0"})
    ctx = RunContext.create(
        options=container,
        module_id="assessment.narrow_fn_test",
        adapter="hci0",
        target="AA:BB:CC:DD:EE:FF",
    )

    instance = narrow_check()
    result = instance.run(ctx)
    assert result["got"] == "AA:BB:CC:DD:EE:FF"


# ── End-to-end: run a real Module subclass ───────────────────────────────────

def test_invoker_runs_discovery_scanner_end_to_end():
    """CRITICAL integration test: the full CLI → Invoker → Module.run() → envelope path.

    This is the regression guard for all the Phase 1 fixes. If any future change
    breaks the framework ↔ module seam, this test fails.
    """
    autoload_builtin_modules()

    # Mock the hardware-touching scan function; keep everything else real
    # ScannerModule calls scan_all() (list-returning), not scan_all_result() (envelope-returning)
    fake_devices = [
        {"addr": "AA:BB:CC:DD:EE:01", "type": "Classic", "name": "Device1"},
        {"addr": "AA:BB:CC:DD:EE:02", "type": "BLE", "name": "Device2"},
    ]

    with patch(
        "blue_tap.hardware.scanner.scan_all",
        return_value=fake_devices,
    ):
        invoker = Invoker()
        envelope = invoker.invoke(
            "discovery.scanner",
            {"MODE": "all", "DURATION": "1", "HCI": "hci0"},
        )

    # Envelope must have every required field and validate cleanly
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Scanner envelope invalid: {errors}"

    # Functional correctness
    assert envelope["schema"] == "blue_tap.scan.result"
    assert envelope["module"] == "discovery.scanner"
    assert envelope["summary"]["device_count"] == 2
    assert envelope["summary"]["classic_count"] == 1
    assert envelope["summary"]["ble_count"] == 1
    assert envelope["summary"]["outcome"] == "observed"

    # Execution record present and valid
    assert len(envelope["executions"]) == 1
    execution = envelope["executions"][0]
    assert execution["execution_status"] == "completed"
    assert execution["module_outcome"] == "observed"
    assert execution["evidence"]["module_evidence"]["total"] == 2


def test_invoker_discovery_scanner_with_session_logs_command(tmp_path):
    """Running a module with a session must persist the envelope."""
    autoload_builtin_modules()

    # ScannerModule calls scan_all() (list-returning), not scan_all_result()
    session = Session("e2e_test", base_dir=str(tmp_path))

    with patch(
        "blue_tap.hardware.scanner.scan_all",
        return_value=[],
    ):
        invoker = Invoker()
        envelope = invoker.invoke_with_logging(
            "discovery.scanner",
            {"MODE": "all", "DURATION": "1"},
            session=session,
        )

    assert envelope["summary"]["device_count"] == 0

    # Verify the session log received the command
    assert len(session.metadata["commands"]) >= 1
    logged = session.metadata["commands"][-1]
    assert logged["command"] == "run discovery.scanner"
    assert logged["category"] == "scan"  # inferred from schema "blue_tap.scan.result"


# ── Post-exploitation API contract tests ────────────────────────────────────

def test_bluesnarfer_dispatches_to_real_at_methods():
    """``ATClient`` has real methods: read_phonebook, read_sms, send_at, get_imei,
    dump_all. The native ``BluesnarferModule._dispatch_at_command`` must route
    the COMMAND option to the matching helper. Regression guard for the bug #3
    fix applied during the Phase 5 wrapper collapse.
    """
    from blue_tap.modules.post_exploitation.data.bluesnarfer import BluesnarferModule

    instance = BluesnarferModule()

    # Mock ATClient to record method calls
    class FakeClient:
        def __init__(self):
            self.calls = []

        def read_phonebook(self):
            self.calls.append("read_phonebook")
            return [{"name": "A", "number": "1"}]

        def read_sms(self):
            self.calls.append("read_sms")
            return []

        def get_imei(self):
            self.calls.append("get_imei")
            return "IMEI-123"

        def send_at(self, cmd):
            self.calls.append(f"send_at:{cmd}")
            return "OK"

        def dump_all(self):
            self.calls.append("dump_all")
            return {"battery": 50}

    fake = FakeClient()

    assert "phonebook" in instance._dispatch_at_command(fake, "CPBR")
    assert "read_phonebook" in fake.calls

    result = instance._dispatch_at_command(fake, "CGSN")
    assert result["imei"] == "IMEI-123"

    result = instance._dispatch_at_command(fake, "DUMP")
    assert "battery" in result


def test_cli_run_command_with_unknown_module_prints_error_not_traceback():
    """`blue-tap run badmodule` must print a clean error, not a KeyError traceback."""
    from click.testing import CliRunner

    from blue_tap.interfaces.cli.runner import run_cmd

    runner = CliRunner()
    result = runner.invoke(run_cmd, ["nonexistent.module"])

    # Should exit cleanly (error printed), not crash
    assert "Module not found" in result.output or "not found" in result.output.lower()
    # Ensure no KeyError traceback leaked
    assert "KeyError" not in result.output
    assert "Traceback" not in result.output
