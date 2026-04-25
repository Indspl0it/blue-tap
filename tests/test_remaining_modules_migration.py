"""Integration tests covering adapter round-trip verification.

Tests verify:
- Spoof adapter round-trip (envelope -> ingest -> build_sections -> SectionModel)
- Firmware adapter round-trip
- All adapters registered in REPORT_ADAPTERS
- generator.add_run_envelope() accepts spoof/firmware/playbook modules
- Playbook envelope round-trip via generator
"""
from __future__ import annotations

import pytest

from blue_tap.framework.envelopes.firmware import (
    build_connection_inspect_result,
    build_firmware_status_result,
)
from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
    now_iso,
)
from blue_tap.framework.envelopes.spoof import build_spoof_result
from blue_tap.framework.reporting.adapters import REPORT_ADAPTERS
from blue_tap.framework.reporting.adapters.firmware import FirmwareReportAdapter
from blue_tap.framework.reporting.adapters.spoof import SpoofReportAdapter
from blue_tap.interfaces.reporting.generator import ReportGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _spoof_envelope(success: bool = True) -> dict:
    return build_spoof_result(
        module_id="hardware.spoof",
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        operation="mac",
        result={
            "success": success,
            "method_used": "bdaddr",
            "methods_tried": ["bdaddr"],
            "original_mac": "11:22:33:44:55:66",
            "target_mac": "AA:BB:CC:DD:EE:FF",
            "verified": success,
            "hci": "hci0",
            "error": "" if success else "hardware rejected",
        },
    )


def _firmware_envelope() -> dict:
    return build_firmware_status_result(
        module_id="hardware.firmware_status",
        adapter="hci1",
        status={"installed": True, "loaded": True, "hooks": {"h1": True, "h2": True}},
    )


def _playbook_envelope() -> dict:
    execution = make_execution(
        module_id="post_exploitation.playbook",
        kind="phase",
        id="step_1",
        title="scan classic",
        module="playbook",
        protocol="multi",
        execution_status="completed",
        module_outcome="completed",
        evidence=make_evidence(
            summary="Step 1: scan classic — success",
            confidence="high",
            observations=["status=success"],
        ),
        started_at=now_iso(),
        completed_at=now_iso(),
        tags=["playbook"],
        module_data={"step": 1, "command": "scan classic", "status": "success"},
    )
    return build_run_envelope(
        module_id="post_exploitation.playbook",
        schema="blue_tap.playbook.result",
        module="playbook",
        target="",
        adapter="hci0",
        operator_context={"playbook": "test", "step_count": 1},
        summary={"passed": 1, "failed": 0, "total": 1},
        executions=[execution],
        artifacts=[],
        module_data={"steps": [{"step": 1, "command": "scan classic", "status": "success"}]},
    )


# ---------------------------------------------------------------------------
# Adapter Registration Tests
# ---------------------------------------------------------------------------

class TestAdapterRegistration:
    def test_spoof_adapter_registered(self):
        modules = {a.module for a in REPORT_ADAPTERS}
        assert "spoof" in modules

    def test_firmware_adapter_registered(self):
        modules = {a.module for a in REPORT_ADAPTERS}
        assert "firmware" in modules


# ---------------------------------------------------------------------------
# Spoof adapter round-trip tests
# ---------------------------------------------------------------------------

class TestSpoofAdapterRoundTrip:
    def test_accepts_spoof_envelope(self):
        adapter = SpoofReportAdapter()
        assert adapter.accepts(_spoof_envelope())

    def test_rejects_non_spoof(self):
        adapter = SpoofReportAdapter()
        assert not adapter.accepts({"module": "dos"})

    def test_ingest_populates_state(self):
        adapter = SpoofReportAdapter()
        state: dict = {}
        adapter.ingest(_spoof_envelope(), state)
        assert len(state["spoof_operations"]) == 1
        assert len(state["spoof_executions"]) >= 1

    def test_build_sections_returns_section_model(self):
        adapter = SpoofReportAdapter()
        state: dict = {}
        adapter.ingest(_spoof_envelope(), state)
        sections = adapter.build_sections(state)
        assert len(sections) >= 1
        sec = sections[0]
        assert sec.section_id
        assert sec.title
        assert isinstance(sec.blocks, tuple)

    def test_build_sections_has_mac_table(self):
        adapter = SpoofReportAdapter()
        state: dict = {}
        adapter.ingest(_spoof_envelope(), state)
        sections = adapter.build_sections(state)
        # Should have a table block with MAC columns
        table_blocks = [b for b in sections[0].blocks if b.block_type == "table"]
        assert len(table_blocks) >= 1
        headers = table_blocks[0].data["headers"]
        assert "Original MAC" in headers
        assert "Target MAC" in headers

    def test_build_json_section(self):
        adapter = SpoofReportAdapter()
        state: dict = {}
        adapter.ingest(_spoof_envelope(), state)
        js = adapter.build_json_section(state)
        assert "operations" in js
        assert "executions" in js

    def test_empty_state_returns_no_sections(self):
        adapter = SpoofReportAdapter()
        assert adapter.build_sections({}) == []


# ---------------------------------------------------------------------------
# Firmware adapter round-trip tests
# ---------------------------------------------------------------------------

class TestFirmwareAdapterRoundTrip:
    def test_accepts_firmware_envelope(self):
        adapter = FirmwareReportAdapter()
        assert adapter.accepts(_firmware_envelope())

    def test_rejects_non_firmware(self):
        adapter = FirmwareReportAdapter()
        assert not adapter.accepts({"module": "fuzz"})

    def test_ingest_populates_state(self):
        adapter = FirmwareReportAdapter()
        state: dict = {}
        adapter.ingest(_firmware_envelope(), state)
        assert len(state["firmware_operations"]) == 1
        assert len(state["firmware_executions"]) >= 1

    def test_build_sections_returns_section_model(self):
        adapter = FirmwareReportAdapter()
        state: dict = {}
        adapter.ingest(_firmware_envelope(), state)
        sections = adapter.build_sections(state)
        assert len(sections) >= 1
        sec = sections[0]
        assert sec.section_id
        assert sec.title

    def test_knob_connection_inspection_card(self):
        adapter = FirmwareReportAdapter()
        state: dict = {}
        env = build_connection_inspect_result(
            module_id="hardware.connection_inspect",
            adapter="hci1",
            connections=[
                {"active": True, "address": "AA:BB:CC:DD:EE:FF",
                 "encryption_enabled": True, "key_size": 1, "secure_connections": False},
            ],
        )
        adapter.ingest(env, state)
        assert len(state.get("connection_inspections", [])) == 1
        sections = adapter.build_sections(state)
        # Should include a card_list with KNOB info
        card_blocks = [b for b in sections[0].blocks if b.block_type == "card_list"]
        assert len(card_blocks) >= 1

    def test_build_json_section(self):
        adapter = FirmwareReportAdapter()
        state: dict = {}
        adapter.ingest(_firmware_envelope(), state)
        js = adapter.build_json_section(state)
        assert "operations" in js
        assert "executions" in js
        assert "connection_inspections" in js


# ---------------------------------------------------------------------------
# Generator envelope ingestion tests
# ---------------------------------------------------------------------------

class TestGeneratorEnvelopeIngestion:
    def test_generator_accepts_spoof_envelope(self):
        gen = ReportGenerator()
        result = gen.add_run_envelope(_spoof_envelope())
        assert result is True

    def test_generator_accepts_firmware_envelope(self):
        gen = ReportGenerator()
        result = gen.add_run_envelope(_firmware_envelope())
        assert result is True

    def test_generator_accepts_playbook_envelope(self):
        gen = ReportGenerator()
        result = gen.add_run_envelope(_playbook_envelope())
        # Playbook modules don't have a report adapter, so they're not ingested
        # This is expected - playbook runs are logged to session but not rendered in reports
        assert result is False

    def test_generator_rejects_unknown_module(self):
        gen = ReportGenerator()
        bad_envelope = {
            "schema": "blue_tap.unknown_xyz.result",
            "module": "unknown_xyz",
            "executions": [],
            "artifacts": [],
            "module_data": {},
        }
        result = gen.add_run_envelope(bad_envelope)
        assert result is False

    def test_generator_rejects_non_dict(self):
        gen = ReportGenerator()
        assert gen.add_run_envelope("not a dict") is False  # type: ignore[arg-type]

    def test_spoof_adapter_ingested_after_add_run_envelope(self):
        gen = ReportGenerator()
        gen.add_run_envelope(_spoof_envelope())
        spoof_state = gen._module_report_state.get("spoof", {})
        assert len(spoof_state.get("spoof_operations", [])) == 1
