"""Tests for LmpCaptureReportAdapter ingestion and rendering."""
from __future__ import annotations

import pytest

from blue_tap.report.adapters.lmp_capture import LmpCaptureReportAdapter
from blue_tap.core.report_contract import SectionModel


def _make_capture(bdaddr: str = "AA:BB:CC:DD:EE:FF", packets: list[dict] | None = None) -> dict:
    if packets is None:
        packets = [
            {
                "opcode": 8,
                "timestamp": 1700000000,
                "direction": "tx",
                "decoded": {"opcode_name": "LMP_AU_RAND", "rand": "deadbeef"},
            },
        ]
    return {"bdaddr": bdaddr, "LMPArray": packets}


def _make_envelope(captures: list[dict]) -> dict:
    return {
        "schema": "blue_tap.lmp_capture.result",
        "module": "lmp_capture",
        "module_data": {"captures": captures},
    }


# ---------------------------------------------------------------------------
# accepts()
# ---------------------------------------------------------------------------

def test_adapter_accepts_lmp_envelope():
    adapter = LmpCaptureReportAdapter()
    envelope = _make_envelope([_make_capture()])
    assert adapter.accepts(envelope)


def test_adapter_accepts_by_schema_prefix():
    adapter = LmpCaptureReportAdapter()
    assert adapter.accepts({"schema": "blue_tap.lmp_capture.result", "module": "other"})


def test_adapter_rejects_non_lmp_envelope():
    adapter = LmpCaptureReportAdapter()
    assert not adapter.accepts({"module": "dos", "schema": "blue_tap.dos.result"})


# ---------------------------------------------------------------------------
# ingest()
# ---------------------------------------------------------------------------

def test_ingest_populates_lmp_captures():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    capture = _make_capture()
    adapter.ingest(_make_envelope([capture]), state)
    assert "lmp_captures" in state
    assert len(state["lmp_captures"]) == 1
    assert state["lmp_captures"][0]["bdaddr"] == "AA:BB:CC:DD:EE:FF"


def test_ingest_accumulates_multiple_calls():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture("AA:BB:CC:DD:EE:FF")]), state)
    adapter.ingest(_make_envelope([_make_capture("11:22:33:44:55:66")]), state)
    assert len(state["lmp_captures"]) == 2


def test_ingest_handles_empty_captures():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([]), state)
    assert state.get("lmp_captures", []) == []


def test_ingest_handles_missing_captures_key():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    # module_data without 'captures' key — should not raise
    adapter.ingest({"schema": "blue_tap.lmp_capture.result", "module": "lmp_capture", "module_data": {}}, state)
    assert state.get("lmp_captures", []) == []


def test_ingest_handles_non_list_captures_gracefully():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    # malformed: captures is not a list
    adapter.ingest(_make_envelope("not_a_list"), state)  # type: ignore[arg-type]
    assert state.get("lmp_captures", []) == []


# ---------------------------------------------------------------------------
# build_sections()
# ---------------------------------------------------------------------------

def test_build_sections_returns_empty_when_no_captures():
    adapter = LmpCaptureReportAdapter()
    assert adapter.build_sections({}) == []
    assert adapter.build_sections({"lmp_captures": []}) == []


def test_build_sections_returns_single_section_model():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture()]), state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1
    assert isinstance(sections[0], SectionModel)


def test_build_sections_has_correct_section_id_and_title():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture()]), state)
    section = adapter.build_sections(state)[0]
    assert section.section_id == "sec-lmp"
    assert "LMP" in section.title


def test_build_sections_has_html_raw_block():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture()]), state)
    section = adapter.build_sections(state)[0]
    assert len(section.blocks) == 1
    assert section.blocks[0].block_type == "html_raw"


def test_build_sections_html_contains_bdaddr():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture("DE:AD:BE:EF:00:01")]), state)
    section = adapter.build_sections(state)[0]
    html = section.blocks[0].data["html"]
    assert "DE:AD:BE:EF:00:01" in html


def test_build_sections_html_contains_opcode_name():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture()]), state)
    section = adapter.build_sections(state)[0]
    html = section.blocks[0].data["html"]
    assert "LMP_AU_RAND" in html


def test_build_sections_auth_opcode_colored_red():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    # opcode 8 = auth category
    adapter.ingest(_make_envelope([_make_capture(packets=[
        {"opcode": 8, "timestamp": 0, "direction": "tx", "decoded": {"opcode_name": "LMP_AU_RAND"}},
    ])]), state)
    html = adapter.build_sections(state)[0].blocks[0].data["html"]
    assert "#dc2626" in html  # red


def test_build_sections_enc_opcode_colored_orange():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    # opcode 15 = encryption category
    adapter.ingest(_make_envelope([_make_capture(packets=[
        {"opcode": 15, "timestamp": 0, "direction": "rx", "decoded": {"opcode_name": "LMP_ENCRYPTION_MODE_REQ"}},
    ])]), state)
    html = adapter.build_sections(state)[0].blocks[0].data["html"]
    assert "#ea580c" in html  # orange


def test_build_sections_feature_bitmap_rendered():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    # opcode 39 = features, include features_hex in decoded
    adapter.ingest(_make_envelope([_make_capture(packets=[
        {"opcode": 39, "timestamp": 0, "direction": "rx", "decoded": {
            "opcode_name": "LMP_FEATURES_RES",
            "features_hex": "ff0000000000000000",
        }},
    ])]), state)
    html = adapter.build_sections(state)[0].blocks[0].data["html"]
    assert "Feature Bitmap" in html
    assert "feature-grid" in html


def test_build_sections_encryption_summary_rendered():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture(packets=[
        {"opcode": 16, "timestamp": 0, "direction": "tx", "decoded": {
            "opcode_name": "LMP_ENCRYPTION_KEY_SIZE_MASK_REQ",
            "key_size": 5,
        }},
    ])]), state)
    html = adapter.build_sections(state)[0].blocks[0].data["html"]
    assert "Encryption Negotiation Summary" in html
    assert "CVE-2019-9506" in html  # triggered because key_size < 7


def test_build_sections_knob_warning_not_shown_for_safe_key_size():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture(packets=[
        {"opcode": 16, "timestamp": 0, "direction": "tx", "decoded": {
            "opcode_name": "LMP_ENCRYPTION_KEY_SIZE_MASK_REQ",
            "key_size": 16,
        }},
    ])]), state)
    html = adapter.build_sections(state)[0].blocks[0].data["html"]
    assert "Encryption Negotiation Summary" in html
    assert "CVE-2019-9506" not in html


# ---------------------------------------------------------------------------
# build_json_section()
# ---------------------------------------------------------------------------

def test_build_json_section_returns_captures():
    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    capture = _make_capture()
    adapter.ingest(_make_envelope([capture]), state)
    result = adapter.build_json_section(state)
    assert "captures" in result
    assert len(result["captures"]) == 1


def test_build_json_section_empty_state():
    adapter = LmpCaptureReportAdapter()
    result = adapter.build_json_section({})
    assert result == {"captures": []}


# ---------------------------------------------------------------------------
# html_raw block type renders correctly via section renderer
# ---------------------------------------------------------------------------

def test_render_sections_passes_html_raw_through():
    from blue_tap.report.renderers.html import render_sections

    adapter = LmpCaptureReportAdapter()
    state: dict = {}
    adapter.ingest(_make_envelope([_make_capture()]), state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    # The rendered output must contain both the section wrapper and packet table
    assert "sec-lmp" in html
    assert "LMP_AU_RAND" in html
