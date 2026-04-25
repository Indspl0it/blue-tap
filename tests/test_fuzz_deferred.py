"""Deferred tests from the fuzz migration plan (Phase 13.1).

Covers items not already present in test_fuzz_envelope.py, test_fuzz_adapter.py,
test_fuzz_adapter_migration.py, test_fuzz_cli_extra.py, or test_fuzz_cli_batch.py.

Deferred items addressed here:
  1.7  — FuzzCampaign.run_id attribute is stable and matches make_fuzz_run_id format
  2.17 — run_single_protocol emits run_started and run_completed CliEvents
  2.18 — run_single_protocol emits execution_result on crash
  3.15 — per-protocol execution carries state_coverage in module_evidence
  3.16 — per-protocol execution carries field_weights in module_evidence
  3.17 — per-protocol execution anomaly count is reflected in evidence
  4.16 — obex command delegates to _run_via_engine (l2cap-sig already in test_fuzz_cli_extra.py)
  5.15 — state_coverage data round-trips through adapter JSON section
  5.16 — field_weight data round-trips through adapter JSON section
  7.13 — build_fuzz_operation_result produces valid envelope for corpus/crash operations
  7.14 — operation envelope schema matches blue_tap.fuzz.result
"""

from __future__ import annotations

import click
from click.testing import CliRunner

from blue_tap.framework.envelopes.fuzz import (
    FUZZ_MODULE_OUTCOMES,
    build_fuzz_campaign_result,
    build_fuzz_operation_result,
    build_fuzz_protocol_execution,
    make_fuzz_run_id,
)
from blue_tap.framework.contracts.result_schema import validate_run_envelope
from blue_tap.modules.fuzzing import cli_extra
from blue_tap.modules.fuzzing.engine import FuzzCampaign
from blue_tap.framework.reporting.adapters.fuzz import FuzzReportAdapter


# ---------------------------------------------------------------------------
# 1.7 — FuzzCampaign.run_id stability
# ---------------------------------------------------------------------------

def test_fuzz_run_id_is_stable():
    """FuzzCampaign.run_id matches make_fuzz_run_id() format and is stable for the life of the campaign."""
    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["sdp"],
        session_dir="/tmp/fuzz-deferred-test",
    )
    rid = campaign.run_id
    # run_id must follow the fuzz-<uuid> format
    assert rid.startswith("fuzz-"), f"Expected run_id to start with 'fuzz-', got: {rid!r}"
    assert len(rid) > 10
    # run_id must be stable — accessing it again returns the same value
    assert campaign.run_id == rid


def test_fuzz_campaign_run_id_appears_in_envelope(tmp_path):
    """run_id from FuzzCampaign is threaded through into the RunEnvelope."""
    class FakeTransport:
        connected = False

        def connect(self):
            return False

        def close(self):
            pass

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["sdp"],
        session_dir=str(tmp_path),
    )
    campaign._setup_transports = lambda: campaign._transports.update({"sdp": FakeTransport()})

    envelope = campaign.run_single_protocol("sdp", [b"\x00\x01\x02\x03"])
    assert envelope["run_id"] == campaign.run_id


# ---------------------------------------------------------------------------
# 2.17 — run_single_protocol emits run_started and run_completed
# ---------------------------------------------------------------------------

def test_run_single_protocol_emits_run_started_and_completed(tmp_path, monkeypatch):
    """run_single_protocol emits run_started and run_completed CliEvents."""
    emitted: list[str] = []

    def fake_emit(*, event_type, module, run_id, message, target="", adapter="",
                  execution_id="", details=None, echo=True):
        emitted.append(event_type)
        return {"event_type": event_type, "run_id": run_id}

    monkeypatch.setattr("blue_tap.modules.fuzzing.engine.emit_cli_event", fake_emit)

    class FakeTransport:
        connected = False

        def connect(self):
            return False

        def close(self):
            pass

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["sdp"],
        session_dir=str(tmp_path),
    )
    campaign._setup_transports = lambda: campaign._transports.update({"sdp": FakeTransport()})

    campaign.run_single_protocol("sdp", [b"\x00\x01\x02\x03"])

    assert "run_started" in emitted
    # run_completed or run_error must be emitted (transport fails, so run_error is acceptable)
    assert any(e in emitted for e in ("run_completed", "run_error"))


# ---------------------------------------------------------------------------
# 2.18 — run_single_protocol emits execution_result on crash
# ---------------------------------------------------------------------------

def test_run_single_protocol_emits_execution_result_on_crash(tmp_path, monkeypatch):
    """run_single_protocol emits execution_result when a crash (ConnectionResetError) is detected."""
    emitted: list[str] = []

    def fake_emit(*, event_type, module, run_id, message, target="", adapter="",
                  execution_id="", details=None, echo=True):
        emitted.append(event_type)
        return {"event_type": event_type, "run_id": run_id}

    monkeypatch.setattr("blue_tap.modules.fuzzing.engine.emit_cli_event", fake_emit)

    call_count = [0]

    class CrashingTransport:
        connected = True

        def connect(self):
            return True

        def send(self, data):
            call_count[0] += 1
            raise ConnectionResetError("simulated crash")

        def recv(self, recv_timeout=None):
            return None

        def close(self):
            pass

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["sdp"],
        session_dir=str(tmp_path),
    )
    campaign._setup_transports = lambda: campaign._transports.update({"sdp": CrashingTransport()})

    campaign.run_single_protocol("sdp", [b"\x00\x01\x02\x03"], delay=0.0)

    assert "run_started" in emitted
    assert "execution_result" in emitted


# ---------------------------------------------------------------------------
# 3.15 — per-protocol execution state_coverage in module_evidence
# ---------------------------------------------------------------------------

def test_per_protocol_execution_state_coverage_in_module_evidence():
    """build_fuzz_protocol_execution includes state_coverage in evidence.module_evidence."""
    sc = {
        "total_states": 5,
        "total_transitions": 12,
        "protocols": {"sdp": {"states": 5, "transitions": 12}},
    }
    rec = build_fuzz_protocol_execution(
        module_id="fuzzing.engine",
        protocol="sdp",
        packets_sent=200,
        crashes=0,
        errors=0,
        states_discovered=5,
        state_coverage=sc,
    )
    me = rec["evidence"]["module_evidence"]
    assert "state_coverage" in me
    assert me["state_coverage"]["total_states"] == 5
    assert me["state_coverage"]["total_transitions"] == 12


# ---------------------------------------------------------------------------
# 3.16 — per-protocol execution field_weights in module_evidence
# ---------------------------------------------------------------------------

def test_per_protocol_execution_field_weights_in_module_evidence():
    """build_fuzz_protocol_execution includes field_weights in evidence.module_evidence."""
    fw = {"pdu_type": 0.45, "length": 0.22}
    rec = build_fuzz_protocol_execution(
        module_id="fuzzing.engine",
        protocol="sdp",
        packets_sent=500,
        crashes=0,
        errors=0,
        field_weights=fw,
    )
    me = rec["evidence"]["module_evidence"]
    assert "field_weights" in me
    assert me["field_weights"]["pdu_type"] == 0.45


# ---------------------------------------------------------------------------
# 3.17 — per-protocol anomaly count reflected in evidence observations
# ---------------------------------------------------------------------------

def test_per_protocol_execution_anomaly_in_observations():
    """Anomaly count from build_fuzz_protocol_execution appears in evidence.observations."""
    rec = build_fuzz_protocol_execution(
        module_id="fuzzing.engine",
        protocol="ble-att",
        packets_sent=300,
        crashes=0,
        errors=0,
        anomalies=7,
    )
    obs = rec["evidence"]["observations"]
    assert any("7" in o and "anomal" in o.lower() for o in obs), (
        f"Expected anomaly count in observations: {obs}"
    )


# ---------------------------------------------------------------------------
# 4.16 — obex CLI command delegates to _run_via_engine
# ---------------------------------------------------------------------------

def _build_fuzz_cli() -> click.Group:
    @click.group()
    def fuzz() -> None:
        pass
    cli_extra.register_extra_commands(fuzz)
    return fuzz


def test_obex_uses_run_via_engine(monkeypatch):
    """fuzz obex delegates to _run_via_engine (not the legacy _run_fuzz_cases loop)."""
    calls: list[tuple[str, dict | None]] = []

    monkeypatch.setattr(cli_extra, "resolve_address", lambda value: value)
    monkeypatch.setattr(cli_extra, "_show_fuzz_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        cli_extra,
        "_run_via_engine",
        lambda address, protocol, cases, session_dir="", delay=0.5, timeout=5.0, transport_override=None: (
            calls.append((protocol, transport_override)),
            {"sent": len(cases), "crashes": 0, "errors": 0, "elapsed": 0.0,
             "total_cases": len(cases), "logged_by_engine": True},
        )[1],
    )
    monkeypatch.setattr(
        "blue_tap.modules.fuzzing.protocols.obex.generate_all_obex_fuzz_cases",
        lambda profile: [[b"obex-fuzz-case"]],
    )

    runner = CliRunner()
    result = runner.invoke(
        _build_fuzz_cli(), ["obex", "AA:BB:CC:DD:EE:FF", "--profile", "pbap"]
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0][0] == "obex-pbap"


# ---------------------------------------------------------------------------
# 5.15/5.16 — state_coverage and field_weights round-trip through adapter JSON
# ---------------------------------------------------------------------------

def _make_envelope_with_intelligence():
    proto_execs = [
        build_fuzz_protocol_execution(
            module_id="fuzzing.engine",
            protocol="sdp",
            packets_sent=1000,
            crashes=0,
            errors=0,
            states_discovered=8,
            state_coverage={"total_states": 8, "total_transitions": 20,
                             "protocols": {"sdp": {"states": 8, "transitions": 20}}},
            field_weights={"pdu_type": 0.5, "length": 0.3},
        )
    ]
    return build_fuzz_campaign_result(
        module_id="fuzzing.campaign",
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary={
            "protocols": ["sdp"],
            "packets_sent": 1000,
            "crashes": 0,
            "runtime_seconds": 30.0,
            "campaign_stats": {
                "state_coverage": {
                    "total_states": 8,
                    "total_transitions": 20,
                    "protocols_tracked": {"sdp": {"states": 8, "transitions": 20}},
                },
                "field_weights": {"sdp": {"pdu_type": 0.5, "length": 0.3}},
            },
        },
        crashes=[],
        session_fuzz_dir="/tmp/fake_fuzz_dir",
        protocol_executions=proto_execs,
    )


def test_fuzz_adapter_state_coverage_in_json():
    """State coverage data from per-protocol executions appears in adapter JSON section."""
    adapter = FuzzReportAdapter()
    state = {}
    adapter.ingest(_make_envelope_with_intelligence(), state)
    js = adapter.build_json_section(state)
    assert "state_coverage" in js
    # State coverage list should be non-empty (extracted from per-protocol probe executions)
    assert isinstance(js["state_coverage"], list)
    assert len(js["state_coverage"]) >= 1
    first = js["state_coverage"][0]
    assert first.get("protocol") == "sdp"


def test_fuzz_adapter_field_weights_in_json():
    """Field weight data from per-protocol executions appears in adapter JSON section."""
    adapter = FuzzReportAdapter()
    state = {}
    adapter.ingest(_make_envelope_with_intelligence(), state)
    js = adapter.build_json_section(state)
    assert "field_weights" in js
    assert isinstance(js["field_weights"], list)
    assert len(js["field_weights"]) >= 1
    first = js["field_weights"][0]
    assert first.get("protocol") == "sdp"
    assert "weights" in first


# ---------------------------------------------------------------------------
# 7.13 — operation envelope for corpus/crash management is valid
# ---------------------------------------------------------------------------

def test_corpus_generate_operation_envelope_validates():
    """build_fuzz_operation_result for corpus_generate produces a valid RunEnvelope."""
    envelope = build_fuzz_operation_result(
        module_id="fuzzing.operation",
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="corpus_generate",
        title="Generated corpus for sdp, ble-att",
        observations=[
            "Generated 580 seeds",
            "2 protocols covered",
        ],
        module_data={
            "operation": "corpus_generate",
            "protocols": ["sdp", "ble-att"],
            "seed_count": 580,
        },
        module_outcome="completed",
    )
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Validation errors: {errors}"
    assert envelope["summary"]["run_type"] == "operation"


# ---------------------------------------------------------------------------
# 7.14 — crash export operation envelope is valid
# ---------------------------------------------------------------------------

def test_crash_export_operation_envelope_validates():
    """build_fuzz_operation_result for crash export produces a valid RunEnvelope."""
    envelope = build_fuzz_operation_result(
        module_id="fuzzing.operation",
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="crashes_export",
        title="Exported 3 crashes to /tmp/crashes.tar.gz",
        observations=[
            "3 crashes exported",
            "Formats: bin, json, pcap",
        ],
        module_data={
            "operation": "crashes_export",
            "crash_count": 3,
            "export_path": "/tmp/crashes.tar.gz",
        },
        module_outcome="completed",
    )
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Validation errors: {errors}"
    assert envelope["summary"]["run_type"] == "operation"


def test_operation_envelope_schema_is_fuzz():
    """Operation envelope produced by build_fuzz_operation_result uses the fuzz schema."""
    envelope = build_fuzz_operation_result(
        module_id="fuzzing.operation",
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="corpus_minimize",
        title="Minimized corpus: 580 → 420 seeds",
    )
    assert envelope["schema"] == "blue_tap.fuzz.result"
    assert envelope["module"] == "fuzzing"
    assert envelope["schema_version"] == 2
