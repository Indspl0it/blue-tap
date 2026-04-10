from __future__ import annotations

import json

from click.testing import CliRunner

from blue_tap.cli import main
from blue_tap.report.generator import ReportGenerator


def test_empty_scan_is_persisted_to_session_log(monkeypatch):
    recorded = {}

    def fake_log_command(command, data, category="general", target=""):
        recorded["command"] = command
        recorded["data"] = data
        recorded["category"] = category
        recorded["target"] = target
        return "session-file.json"

    monkeypatch.setattr("blue_tap.utils.session.log_command", fake_log_command)
    monkeypatch.setattr(
        "blue_tap.core.scanner.scan_classic_result",
        lambda duration, hci: {
            "schema": "blue_tap.scan.result",
            "schema_version": 2,
            "module": "scan",
            "run_id": "scan-empty-1",
            "target": "range_scan",
            "adapter": hci,
            "started_at": "2026-04-10T00:00:00+00:00",
            "completed_at": "2026-04-10T00:00:01+00:00",
            "operator_context": {"scan_mode": "classic", "duration_requested": duration, "passive": False},
            "summary": {"device_count": 0, "type_counts": {}, "exact_dual_mode_matches": 0, "correlated_candidates": 0},
            "executions": [],
            "module_data": {"devices": [], "collectors": []},
        },
    )

    result = CliRunner().invoke(main, ["scan", "classic"])

    assert result.exit_code == 0
    assert recorded["command"] == "scan_classic"
    assert recorded["category"] == "scan"
    assert recorded["data"]["module_data"]["devices"] == []


def test_discovery_report_renders_zero_result_scan(tmp_path):
    report = ReportGenerator()
    report.add_run_envelope(
        {
            "schema": "blue_tap.scan.result",
            "schema_version": 2,
            "module": "scan",
            "run_id": "scan-empty-2",
            "target": "range_scan",
            "adapter": "hci0",
            "started_at": "2026-04-10T00:00:00+00:00",
            "completed_at": "2026-04-10T00:00:01+00:00",
            "operator_context": {"scan_mode": "classic", "duration_requested": 10, "passive": False},
            "summary": {
                "device_count": 0,
                "type_counts": {},
                "exact_dual_mode_matches": 0,
                "correlated_candidates": 0,
                "devices_with_services": 0,
                "devices_with_manufacturer_data": 0,
            },
            "executions": [],
            "module_data": {"devices": [], "collectors": []},
        }
    )

    html = report._build_scan_html()
    output = tmp_path / "scan-empty.json"
    report.generate_json(str(output))
    payload = json.loads(output.read_text())

    assert "no devices discovered" in html.lower()
    assert payload["modules"]["scan"]["runs"]
    assert payload["modules"]["scan"]["devices"] == []
