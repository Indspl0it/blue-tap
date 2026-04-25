"""Tests for fuzz adapter migration: ingest -> build_sections -> SectionModels."""
from __future__ import annotations

import json

import pytest

from blue_tap.framework.envelopes.fuzz import (
    build_fuzz_campaign_result,
    build_fuzz_protocol_execution,
)
from blue_tap.framework.contracts.report_contract import SectionModel
from blue_tap.framework.reporting.adapters.fuzz import FuzzReportAdapter
from blue_tap.framework.reporting.renderers import render_sections


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_campaign_envelope(
    crashes: int = 0,
    with_intelligence: bool = False,
):
    protocols = ["sdp", "ble-att"]
    proto_execs = [
        build_fuzz_protocol_execution(
            module_id="fuzzing.engine",
            protocol=p,
            packets_sent=500,
            crashes=crashes,
            errors=0,
            anomalies=3,
            states_discovered=2,
        )
        for p in protocols
    ]
    crash_list = [
        {
            "severity": "HIGH",
            "protocol": "sdp",
            "crash_type": "connection_drop",
            "payload_hex": "deadbeef" * 8,
            "payload_len": 32,
            "reproduced": True,
            "timestamp": "2025-01-01T00:00:00",
            "target_addr": "AA:BB:CC:DD:EE:FF",
            "mutation_log": "flip_byte at offset 4",
        }
    ] * crashes

    campaign_summary = {
        "protocols": protocols,
        "strategy": "coverage_guided",
        "packets_sent": 1000,
        "crashes": crashes,
        "errors": 0,
        "runtime_seconds": 120.0,
        "packets_per_second": 8.3,
        "protocol_breakdown": {"sdp": 500, "ble-att": 500},
        "result": "completed",
    }

    if with_intelligence:
        campaign_summary["state_coverage"] = {
            "total_states": 42,
            "total_transitions": 120,
            "protocols": {
                "sdp": {"states": 20, "transitions": 60},
                "ble-att": {"states": 22, "transitions": 60},
            },
        }
        campaign_summary["field_weights"] = {
            "sdp": {"pdu_type": 0.45, "length": 0.22, "uuid": 0.15},
        }
        campaign_summary["health_monitor"] = {
            "events": [
                {"timestamp": "2025-01-01T00:01:00", "status": "rebooted", "details": "device rebooted"},
                {"timestamp": "2025-01-01T00:02:00", "status": "healthy", "details": ""},
            ]
        }

    return build_fuzz_campaign_result(
        module_id="fuzzing.campaign",
        target="AA:BB:CC:DD:EE:FF",
        adapter="session",
        campaign_summary=campaign_summary,
        crashes=crash_list,
        session_fuzz_dir="/tmp/fake_fuzz_dir",
        protocol_executions=proto_execs,
    )


# ---------------------------------------------------------------------------
# Round-trip: ingest -> build_sections -> SectionModels
# ---------------------------------------------------------------------------

class TestCampaignRoundTrip:
    def test_produces_section_models(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=2), state)
        sections = adapter.build_sections(state)
        assert isinstance(sections, list)
        assert len(sections) >= 1
        for sec in sections:
            assert isinstance(sec, SectionModel)

    def test_main_section_id_is_sec_fuzzing(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1), state)
        sections = adapter.build_sections(state)
        ids = [s.section_id for s in sections]
        assert "sec-fuzzing" in ids

    def test_crash_data_produces_cards_in_section(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=2), state)
        sections = adapter.build_sections(state)
        # The main section should have crash-related blocks
        main = next(s for s in sections if s.section_id == "sec-fuzzing")
        block_types = [b.block_type for b in main.blocks]
        # Should have at least a badge_group and a table
        assert "badge_group" in block_types
        assert "table" in block_types

    def test_high_crash_produces_detail_cards(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1), state)
        sections = adapter.build_sections(state)
        main = next(s for s in sections if s.section_id == "sec-fuzzing")
        block_types = [b.block_type for b in main.blocks]
        # HIGH crash should produce an html_raw crash detail card block
        assert "html_raw" in block_types

    def test_crash_detail_contains_hexdump(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1), state)
        sections = adapter.build_sections(state)
        main = next(s for s in sections if s.section_id == "sec-fuzzing")
        raw_blocks = [b for b in main.blocks if b.block_type == "html_raw"]
        combined_html = "\n".join(b.data.get("html", "") for b in raw_blocks)
        # Should contain hexdump header and payload offset
        assert "Offset" in combined_html
        assert "0000" in combined_html

    def test_no_crashes_no_detail_cards(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0), state)
        sections = adapter.build_sections(state)
        main = next(s for s in sections if s.section_id == "sec-fuzzing")
        # No html_raw crash detail blocks when no crashes
        raw_blocks = [b for b in main.blocks if b.block_type == "html_raw"]
        # Campaign overview block is html_raw, but no crash details
        crash_detail_html = "\n".join(b.data.get("html", "") for b in raw_blocks)
        assert "Crash #" not in crash_detail_html


# ---------------------------------------------------------------------------
# Intelligence section
# ---------------------------------------------------------------------------

class TestIntelligenceSection:
    def test_intelligence_section_produced_when_data_present(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        ids = [s.section_id for s in sections]
        assert "sec-fuzz-intel" in ids

    def test_no_intelligence_section_when_no_intel_data(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0, with_intelligence=False), state)
        sections = adapter.build_sections(state)
        ids = [s.section_id for s in sections]
        assert "sec-fuzz-intel" not in ids

    def test_state_coverage_appears_in_intelligence_section(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        intel = next(s for s in sections if s.section_id == "sec-fuzz-intel")
        combined_html = "\n".join(
            b.data.get("html", "") for b in intel.blocks if b.block_type == "html_raw"
        )
        assert "State Coverage" in combined_html
        assert "42" in combined_html  # total_states from fixture

    def test_field_weights_appear_in_intelligence_section(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        intel = next(s for s in sections if s.section_id == "sec-fuzz-intel")
        combined_html = "\n".join(
            b.data.get("html", "") for b in intel.blocks if b.block_type == "html_raw"
        )
        assert "Field Mutation" in combined_html
        assert "pdu_type" in combined_html

    def test_health_events_appear_in_intelligence_section(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        intel = next(s for s in sections if s.section_id == "sec-fuzz-intel")
        combined_html = "\n".join(
            b.data.get("html", "") for b in intel.blocks if b.block_type == "html_raw"
        )
        assert "Health Events" in combined_html
        assert "REBOOTED" in combined_html


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------

class TestEmptyState:
    def test_empty_state_returns_no_sections(self):
        adapter = FuzzReportAdapter()
        sections = adapter.build_sections({})
        assert sections == []

    def test_state_without_fuzz_runs_returns_no_sections(self):
        adapter = FuzzReportAdapter()
        sections = adapter.build_sections({"crashes": [{"severity": "HIGH"}]})
        assert sections == []


# ---------------------------------------------------------------------------
# Rendering: sections -> HTML
# ---------------------------------------------------------------------------

class TestSectionRendering:
    def test_sections_render_to_html_string(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        html = render_sections(sections)
        assert isinstance(html, str)
        assert len(html) > 100

    def test_rendered_html_contains_section_id(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=0, with_intelligence=True), state)
        sections = adapter.build_sections(state)
        html = render_sections(sections)
        assert 'id="sec-fuzzing"' in html
        assert 'id="sec-fuzz-intel"' in html

    def test_html_raw_blocks_are_not_escaped(self):
        """html_raw blocks must pass through without entity-escaping the HTML."""
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=1), state)
        sections = adapter.build_sections(state)
        html = render_sections(sections)
        # Campaign overview contains proper HTML tags, not escaped
        assert "<h3>" in html
        assert "&lt;h3&gt;" not in html

    def test_json_section_serializable(self):
        adapter = FuzzReportAdapter()
        state = {}
        adapter.ingest(_make_campaign_envelope(crashes=2, with_intelligence=True), state)
        js = adapter.build_json_section(state)
        serialized = json.dumps(js, default=str)
        parsed = json.loads(serialized)
        assert "runs" in parsed
        assert "crashes" in parsed
        assert len(parsed["crashes"]) == 2
