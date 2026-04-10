"""Tests for standardized block renderers, adapters, and rendering pipeline."""
import json
from blue_tap.core.report_contract import SectionBlock, SectionModel
from blue_tap.report.renderers.blocks import (
    render_block,
    render_card_list,
    render_status_summary,
    render_timeline,
    render_key_value,
    render_badge_group,
)
from blue_tap.report.renderers.registry import get_default_block_renderer_registry
from blue_tap.report.renderers.sections import render_sections
from blue_tap.report.adapters import REPORT_ADAPTERS


def test_all_block_types_render():
    """Every registered block type produces non-empty HTML."""
    registry = get_default_block_renderer_registry()
    blocks = {
        "table": SectionBlock("table", {"headers": ["H1"], "rows": [["r1"]]}),
        "paragraph": SectionBlock("paragraph", {"text": "hello"}),
        "text": SectionBlock("text", {"text": "code"}),
        "card_list": SectionBlock("card_list", {"cards": [
            {"title": "T", "status": "confirmed", "details": {"K": "V"}, "body": "B"}
        ]}),
        "status_summary": SectionBlock("status_summary", {"items": [
            {"label": "Confirmed", "count": 2, "status": "confirmed"}
        ]}),
        "timeline": SectionBlock("timeline", {"events": [
            {"timestamp": "10:00", "label": "start", "message": "go", "status": "info"}
        ]}),
        "key_value": SectionBlock("key_value", {"pairs": [{"key": "A", "value": "B"}]}),
        "badge_group": SectionBlock("badge_group", {"badges": [
            {"label": "X", "value": 1, "status": "info"}
        ]}),
    }
    for name, block in blocks.items():
        html = render_block(block, registry)
        assert html, f"{name} rendered empty"
        assert "<" in html, f"{name} missing HTML tags"


def test_card_list_renders_details():
    html = render_card_list([
        {"title": "BlueFrag", "status": "confirmed", "details": {"CVE": "2020-0022"}, "body": "Overflow"}
    ])
    assert "BlueFrag" in html
    assert "confirmed" in html
    assert "2020-0022" in html
    assert "Overflow" in html


def test_status_summary_renders_counts():
    html = render_status_summary({"items": [
        {"label": "Success", "count": 5, "status": "success"},
        {"label": "Failed", "count": 1, "status": "failed"},
    ]})
    assert "5" in html
    assert "1" in html
    assert "Success" in html


def test_timeline_renders_events():
    html = render_timeline([
        {"timestamp": "2026-04-09T10:00", "label": "run_started", "message": "Scan began"},
    ])
    assert "run_started" in html
    assert "Scan began" in html


def test_badge_group_renders_badges():
    html = render_badge_group([
        {"label": "Crashes", "value": 3, "status": "critical"},
        {"label": "Runs", "value": 10, "status": "info"},
    ])
    assert "Crashes: 3" in html
    assert "Runs: 10" in html


def test_key_value_dict_input():
    html = render_key_value({"Target": "AA:BB", "Adapter": "hci0"})
    assert "Target" in html
    assert "AA:BB" in html


def test_vulnscan_adapter_uses_rich_blocks():
    """Vulnscan adapter should produce status_summary and card_list blocks."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "vulnscan")
    envelope = {
        "schema": "blue_tap.vulnscan.result",
        "module": "vulnscan",
        "summary": {"confirmed": 1, "inconclusive": 1, "pairing_required": 0, "not_applicable": 2},
        "executions": [
            {"kind": "check", "id": "CVE-2020-0022", "title": "BlueFrag",
             "module_outcome": "confirmed", "execution_status": "completed",
             "evidence": {"summary": "Buffer overflow"}, "execution_id": "e1"}
        ],
        "module_data": {
            "findings": [
                {"cve": "CVE-2020-0022", "name": "BlueFrag", "severity": "HIGH",
                 "status": "confirmed", "confidence": "high", "evidence": "Overflow"}
            ]
        },
    }
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1

    block_types = [b.block_type for b in sections[0].blocks]
    assert "status_summary" in block_types
    assert "card_list" in block_types


def test_dos_adapter_uses_rich_blocks():
    """DoS adapter should produce status_summary and card_list blocks."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "dos")
    envelope = {
        "schema": "blue_tap.dos.result",
        "module": "dos",
        "summary": {"success": 1, "recovered": 1, "unresponsive": 0, "failed": 0},
        "executions": [
            {"id": "dos-1", "title": "L2CAP Flood", "protocol": "L2CAP",
             "module_outcome": "success", "execution_status": "completed",
             "evidence": {"summary": "Target accepted flood"}, "module_data": {"recovery": {"waited_seconds": 5}}}
        ],
        "module_data": {"checks": []},
    }
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1

    block_types = [b.block_type for b in sections[0].blocks]
    assert "status_summary" in block_types
    assert "card_list" in block_types


def test_fuzz_adapter_uses_badge_group():
    """Fuzz adapter should produce badge_group and table blocks."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "fuzz")
    envelope = {
        "schema": "blue_tap.fuzz.result",
        "module": "fuzz",
        "target": "AA:BB:CC:DD:EE:FF",
        "summary": {"packets_sent": 1000, "crashes": 2, "errors": 1, "runtime_seconds": 30.0},
        "executions": [],
        "module_data": {"run_type": "single_protocol_run", "protocol": "l2cap",
                        "result": {"sent": 1000, "crashes": 2}},
        "operator_context": {"protocol": "l2cap"},
    }
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1

    block_types = [b.block_type for b in sections[0].blocks]
    assert "badge_group" in block_types
    assert "table" in block_types


def test_discovery_adapter_uses_badge_group():
    """Discovery adapter should produce badge_group and table blocks."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "scan")
    envelope = {
        "schema": "blue_tap.scan.result",
        "module": "scan",
        "summary": {"exact_dual_mode_matches": 1, "correlated_candidates": 0},
        "executions": [],
        "module_data": {
            "devices": [
                {"address": "AA:BB:CC:DD:EE:FF", "name": "TestDev", "rssi": -50,
                 "type": "Classic", "class_info": {"major": "Phone"}, "service_uuids": []},
            ]
        },
    }
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    assert len(sections) == 1

    block_types = [b.block_type for b in sections[0].blocks]
    assert "badge_group" in block_types
    assert "table" in block_types


def test_full_rendering_pipeline():
    """End-to-end: adapter -> sections -> render_sections produces HTML."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "vulnscan")
    state = {}
    adapter.ingest({
        "schema": "blue_tap.vulnscan.result", "module": "vulnscan",
        "summary": {"confirmed": 1}, "executions": [],
        "module_data": {"findings": [
            {"cve": "CVE-TEST", "name": "Test", "severity": "HIGH",
             "status": "confirmed", "confidence": "high", "evidence": "Proof"}
        ]},
    }, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    assert "Vulnerability Findings" in html
    assert "CVE-TEST" in html
    assert "badge" in html  # status_summary or card badge


def test_attack_adapter_renders_limitations_and_artifacts():
    """Attack adapter should surface capability limitations and artifact refs."""
    adapter = next(a for a in REPORT_ADAPTERS if a.module == "attack")
    envelope = {
        "schema": "blue_tap.attack.result",
        "module": "attack",
        "summary": {
            "operation": "knob",
            "capability_limitations": ["DarkFirmware unavailable on current adapter"],
        },
        "executions": [
            {
                "execution_id": "e1",
                "kind": "check",
                "id": "knob_brute_force",
                "title": "KNOB Brute Force",
                "module": "attack",
                "protocol": "BR/EDR",
                "module_outcome": "failed",
                "execution_status": "completed",
                "evidence": {
                    "summary": "Enumerated candidates",
                    "capability_limitations": ["No encrypted ACL capture available"],
                    "artifacts": [
                        {"label": "ACL sample", "kind": "capture", "path": "sessions/demo/acl.bin", "execution_id": "e1"}
                    ],
                },
                "artifacts": [],
            }
        ],
        "module_data": {"capability_limitations": ["Host-side fallback only"]},
    }
    state = {}
    adapter.ingest(envelope, state)
    sections = adapter.build_sections(state)
    html = render_sections(sections)
    json_section = adapter.build_json_section(state)

    assert "DarkFirmware unavailable on current adapter" in html
    assert "No encrypted ACL capture available" in html
    assert "sessions/demo/acl.bin" in html
    assert json_section["capability_limitations"]
    assert json_section["artifacts"]
