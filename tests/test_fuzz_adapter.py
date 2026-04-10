"""Tests for fuzz report adapter ingestion and rendering."""
from __future__ import annotations

import json

from blue_tap.core.fuzz_framework import (
    build_fuzz_campaign_result,
    build_fuzz_operation_result,
    build_fuzz_protocol_execution,
    build_fuzz_result,
)
from blue_tap.report.adapters.fuzz import FuzzReportAdapter


def _make_campaign_envelope(num_protocols: int = 2, crashes: int = 0):
    protocols = ["sdp", "ble-att", "rfcomm", "bnep"][:num_protocols]
    proto_execs = [
        build_fuzz_protocol_execution(
            protocol=p,
            packets_sent=1000,
            crashes=crashes,
            errors=0,
            anomalies=5,
            states_discovered=3,
        )
        for p in protocols
    ]
    crash_list = [
        {
            "severity": "HIGH",
            "protocol": "sdp",
            "crash_type": "connection_drop",
            "payload_hex": "deadbeef" * 8,
        }
    ] * crashes
    return build_fuzz_campaign_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary={
            "protocols": protocols,
            "strategy": "coverage_guided",
            "packets_sent": 1000 * num_protocols,
            "crashes": crashes,
            "errors": 0,
            "runtime_seconds": 60.0,
            "protocol_breakdown": {p: 1000 for p in protocols},
        },
        crashes=crash_list,
        session_fuzz_dir="/tmp/fake_fuzz_dir",
        protocol_executions=proto_execs,
    )


def _make_single_run_envelope():
    return build_fuzz_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        command="fuzz_sdp",
        protocol="sdp",
        result={"sent": 100, "crashes": 1, "errors": 0, "elapsed": 10.0, "crash_db_path": "/tmp/crashes.db"},
    )


# ---------------------------------------------------------------------------
# Adapter.accepts()
# ---------------------------------------------------------------------------

def test_adapter_accepts_fuzz_envelope():
    adapter = FuzzReportAdapter()
    envelope = _make_single_run_envelope()
    assert adapter.accepts(envelope)


def test_adapter_rejects_non_fuzz_envelope():
    adapter = FuzzReportAdapter()
    assert not adapter.accepts({"module": "dos", "schema": "blue_tap.dos.result"})


# ---------------------------------------------------------------------------
# Adapter.ingest()
# ---------------------------------------------------------------------------

def test_ingest_campaign_populates_report_state():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = _make_campaign_envelope(num_protocols=2, crashes=3)
    adapter.ingest(envelope, state)
    assert "fuzz_runs" in state
    assert len(state["fuzz_runs"]) == 1
    assert "campaigns" in state
    assert "crashes" in state
    assert len(state["crashes"]) == 3


def test_ingest_campaign_extracts_per_protocol_runs():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = _make_campaign_envelope(num_protocols=3, crashes=0)
    adapter.ingest(envelope, state)
    proto_runs = state.get("fuzz_protocol_runs", [])
    assert len(proto_runs) == 3


def test_ingest_single_run_populates_results():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = _make_single_run_envelope()
    adapter.ingest(envelope, state)
    assert "fuzz_runs" in state
    assert "fuzz_results" in state
    assert len(state["fuzz_results"]) == 1


def test_ingest_operation():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = build_fuzz_operation_result(
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        operation="corpus_generate",
        title="Generated corpus",
    )
    adapter.ingest(envelope, state)
    assert "operations" in state


# ---------------------------------------------------------------------------
# Adapter.build_sections()
# ---------------------------------------------------------------------------

def test_build_sections_returns_section_models():
    adapter = FuzzReportAdapter()
    state = {}
    adapter.ingest(_make_campaign_envelope(crashes=2), state)
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
    sec = sections[0]
    assert sec.section_id == "sec-fuzz-runs"
    assert "Fuzz" in sec.title
    assert sec.summary
    assert len(sec.blocks) > 0


def test_build_sections_empty_state():
    adapter = FuzzReportAdapter()
    sections = adapter.build_sections({})
    assert sections == []


# ---------------------------------------------------------------------------
# Adapter.build_json_section()
# ---------------------------------------------------------------------------

def test_json_section_includes_all_keys():
    adapter = FuzzReportAdapter()
    state = {}
    adapter.ingest(_make_campaign_envelope(num_protocols=2, crashes=1), state)
    js = adapter.build_json_section(state)
    assert "runs" in js
    assert "campaigns" in js
    assert "crashes" in js
    assert "per_protocol_runs" in js
    assert "state_coverage" in js
    assert "field_weights" in js


def test_json_section_is_serializable():
    adapter = FuzzReportAdapter()
    state = {}
    adapter.ingest(_make_campaign_envelope(crashes=0), state)
    js = adapter.build_json_section(state)
    serialized = json.dumps(js, default=str)
    assert len(serialized) > 0


# ---------------------------------------------------------------------------
# Round-trip: envelope -> adapter -> sections
# ---------------------------------------------------------------------------

def test_campaign_round_trip():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = _make_campaign_envelope(num_protocols=2, crashes=1)
    assert adapter.accepts(envelope)
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
    js = adapter.build_json_section(state)
    assert len(js["runs"]) == 1


def test_single_run_round_trip():
    adapter = FuzzReportAdapter()
    state = {}
    envelope = _make_single_run_envelope()
    assert adapter.accepts(envelope)
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) >= 1
