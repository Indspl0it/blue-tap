"""Tests for DoS adapter migration — verifies the DosReportAdapter covers all
features previously rendered by the legacy _build_dos_html path."""

import pytest
from blue_tap.report.adapters.dos import DosReportAdapter
from blue_tap.report.renderers.sections import render_sections


def _make_envelope(executions=None, summary=None, module_data=None, extra=None):
    base = {
        "schema": "blue_tap.dos.result",
        "module": "dos",
        "summary": summary or {"success": 1, "recovered": 0, "unresponsive": 1, "failed": 0},
        "executions": executions or [],
        "module_data": module_data or {"checks": []},
    }
    if extra:
        base.update(extra)
    return base


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------

def test_empty_dos_state_produces_no_sections():
    adapter = DosReportAdapter()
    state = {}
    sections = adapter.build_sections(state)
    assert sections == []


def test_empty_runs_but_no_results_produces_no_sections():
    adapter = DosReportAdapter()
    state = {"dos_runs": [], "dos_results": []}
    sections = adapter.build_sections(state)
    assert sections == []


# ---------------------------------------------------------------------------
# Round-trip: ingest -> build_sections -> SectionModels
# ---------------------------------------------------------------------------

def test_envelope_round_trip_produces_section():
    adapter = DosReportAdapter()
    envelope = _make_envelope()
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1
    assert sections[0].section_id == "sec-dos"


def test_section_contains_status_summary_block():
    adapter = DosReportAdapter()
    state = {}
    adapter.ingest(_make_envelope(), state)
    sections = adapter.build_sections(state)
    block_types = [b.block_type for b in sections[0].blocks]
    assert "status_summary" in block_types


# ---------------------------------------------------------------------------
# Run metadata rendering
# ---------------------------------------------------------------------------

def test_run_metadata_selected_checks():
    adapter = DosReportAdapter()
    envelope = _make_envelope(extra={"selected_checks": ["l2cap_flood", "sdp_cont"]})
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "l2cap_flood" in html
    assert "sdp_cont" in html


def test_run_metadata_recovery_timeout():
    adapter = DosReportAdapter()
    envelope = _make_envelope(extra={"recovery_timeout": 30})
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "30s" in html or "30" in html


def test_run_metadata_interrupted_on():
    adapter = DosReportAdapter()
    envelope = _make_envelope(extra={"interrupted_on": "l2cap_flood"})
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "l2cap_flood" in html


def test_run_metadata_abort_reason():
    adapter = DosReportAdapter()
    envelope = _make_envelope(module_data={"checks": [], "abort_reason": "user_interrupt"})
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "user_interrupt" in html


# ---------------------------------------------------------------------------
# Per-check execution table: CVEs, protocol, pairing, status, outcome, recovery
# ---------------------------------------------------------------------------

def _make_execution(
    exec_id="e1",
    check_id="l2cap_flood",
    title="L2CAP Connection Flood",
    protocol="L2CAP",
    tags=None,
    requires_pairing=False,
    execution_status="completed",
    module_outcome="unresponsive",
    recovery=None,
    evidence_summary="Target stopped responding",
):
    return {
        "execution_id": exec_id,
        "id": check_id,
        "title": title,
        "protocol": protocol,
        "tags": tags or ["cve:2019-9506", "transport:classic"],
        "requires_pairing": requires_pairing,
        "execution_status": execution_status,
        "module_outcome": module_outcome,
        "module_data": {"recovery": recovery or {}},
        "evidence": {"summary": evidence_summary},
    }


def test_per_check_table_rendered():
    adapter = DosReportAdapter()
    execution = _make_execution()
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    block_types = [b.block_type for b in sections[0].blocks]
    assert "table" in block_types


def test_per_check_table_contains_cve():
    adapter = DosReportAdapter()
    execution = _make_execution(tags=["cve:2019-9506"])
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "2019-9506" in html


def test_per_check_table_contains_protocol():
    adapter = DosReportAdapter()
    execution = _make_execution(protocol="SDP")
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "SDP" in html


def test_per_check_table_pairing_yes():
    adapter = DosReportAdapter()
    execution = _make_execution(requires_pairing=True)
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "yes" in html


def test_per_check_table_recovery_probe_strategy():
    adapter = DosReportAdapter()
    recovery = {"recovered": True, "waited_seconds": 10, "probe_strategy": ["l2cap_ping", "hci_reset"]}
    execution = _make_execution(recovery=recovery)
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "l2cap_ping" in html
    assert "hci_reset" in html
    assert "10s" in html or "10" in html


def test_per_check_table_evidence_summary():
    adapter = DosReportAdapter()
    execution = _make_execution(evidence_summary="Target stopped responding after 50 packets")
    envelope = _make_envelope(executions=[execution])
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "Target stopped responding" in html


# ---------------------------------------------------------------------------
# Summary stats in section model
# ---------------------------------------------------------------------------

def test_section_summary_counts_unresponsive():
    adapter = DosReportAdapter()
    execution = _make_execution()
    envelope = _make_envelope(
        executions=[execution],
        summary={"success": 0, "recovered": 0, "unresponsive": 1, "failed": 0},
    )
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert "1 test(s)" in sections[0].summary
    assert "1 left target unresponsive" in sections[0].summary


# ---------------------------------------------------------------------------
# build_json_section
# ---------------------------------------------------------------------------

def test_build_json_section_structure():
    adapter = DosReportAdapter()
    envelope = _make_envelope(executions=[_make_execution()])
    state = {}
    adapter.ingest(envelope, state)
    json_section = adapter.build_json_section(state)
    assert "runs" in json_section
    assert "results" in json_section
    assert "executions" in json_section
    assert len(json_section["runs"]) == 1


# ---------------------------------------------------------------------------
# Multiple envelopes ingested
# ---------------------------------------------------------------------------

def test_multiple_envelopes_uses_latest_for_html():
    adapter = DosReportAdapter()
    state = {}
    adapter.ingest(_make_envelope(extra={"recovery_timeout": 10}), state)
    adapter.ingest(_make_envelope(
        executions=[_make_execution(check_id="sdp_des_bomb", title="SDP DES Bomb", protocol="SDP")],
        extra={"recovery_timeout": 60},
    ), state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    # Latest run has recovery_timeout=60
    assert "60s" in html or "60" in html
    assert len(state["dos_runs"]) == 2
