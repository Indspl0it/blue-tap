"""User-flow 10.2: Full assessment pipeline.

Steps: discovery.scanner → assessment.vuln_scanner → report
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import (
    validate_run_envelope,
)
from blue_tap.framework.registry.families import FAMILY_OUTCOMES, ModuleFamily

TARGET = "AA:BB:CC:DD:EE:FF"
SESSION_NAME = "flow_assessment"

_SCAN_RESULT = [
    {"address": TARGET, "name": "IVI Device", "type": "classic", "rssi": -55},
]

_VULN_RESULT = {
    "schema": "blue_tap.vulnscan.result",
    "schema_version": 2,
    "module": "vulnscan",
    "module_id": "assessment.vulnscan_meta",
    "run_id": "test-run-assessment",
    "target": TARGET,
    "adapter": "hci0",
    "started_at": "2026-04-12T00:00:00+00:00",
    "completed_at": "2026-04-12T00:00:01+00:00",
    "operator_context": {},
    "summary": {
        "outcome": "inconclusive",
        "confirmed": 0,
        "inconclusive": 1,
        "pairing_required": 0,
        "not_applicable": 0,
    },
    "executions": [
        {
            "execution_id": "check_ssp",
            "kind": "check",
            "id": "check_ssp",
            "title": "SSP Check",
            "module": "vulnscan",
            "module_id": "assessment.check_ssp",
            "protocol": "Classic",
            "execution_status": "completed",
            "module_outcome": "inconclusive",
            "evidence": {
                "summary": "SSP status uncertain",
                "observations": [],
                "packets": [],
                "responses": [],
                "state_changes": [],
                "artifacts": [],
                "capability_limitations": [],
                "module_evidence": {},
            },
            "started_at": "2026-04-12T00:00:00+00:00",
            "completed_at": "2026-04-12T00:00:01+00:00",
            "destructive": False,
            "requires_pairing": False,
            "notes": [],
            "tags": [],
            "artifacts": [],
            "module_data": {},
        },
    ],
    "artifacts": [],
    "module_data": {"findings": []},
}


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_assessment_flow(tmp_path):
    runner = _make_runner(tmp_path)

    with (
        patch("blue_tap.hardware.scanner.scan_all", return_value=_SCAN_RESULT),
        patch(
            "blue_tap.modules.assessment.vuln_scanner.run_vulnerability_scan",
            return_value=_VULN_RESULT,
        ),
    ):
        r1 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "discovery.scanner", "MODE=all"])
        assert r1.exit_code == 0, f"discovery.scanner failed:\n{r1.output}"

        r2 = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "assessment.vulnscan_meta",
             f"RHOST={TARGET}", "PHONE=11:22:33:44:55:66"],
        )
        assert r2.exit_code == 0, f"assessment.vulnscan_meta failed:\n{r2.output}"

    session_dir = tmp_path / "sessions" / SESSION_NAME
    session_meta = json.loads((session_dir / "session.json").read_text())
    commands = session_meta["commands"]
    assert len(commands) == 2, f"Expected 2 commands, got {len(commands)}"

    categories = [c["category"] for c in commands]
    assert "scan" in categories or any("scan" in c for c in categories) or "recon" in categories or "general" in categories

    # Validate envelopes
    valid_assessment_outcomes = FAMILY_OUTCOMES[ModuleFamily.ASSESSMENT]
    for cmd_entry in commands:
        cmd_file = session_dir / cmd_entry["file"]
        cmd_data = json.loads(cmd_file.read_text())
        envelope = cmd_data["data"]
        errors = validate_run_envelope(envelope)
        assert errors == [], f"Envelope invalid for {cmd_entry['command']}: {errors}"
        # For assessment module, check outcomes are valid
        if "vuln_scanner" in cmd_entry["command"] or "vulnscan" in cmd_entry.get("category", ""):
            for execution in envelope.get("executions", []):
                outcome = execution.get("module_outcome", "")
                if outcome:
                    assert outcome in valid_assessment_outcomes, \
                        f"Invalid assessment outcome: {outcome!r}"

    # Generate report
    r3 = runner.invoke(cli, ["-s", SESSION_NAME, "report"])
    assert r3.exit_code == 0, f"report failed:\n{r3.output}"

    report_file = session_dir / "report.html"
    assert report_file.exists(), "report.html was not created"

    html = report_file.read_text()
    assert len(html) > 100, "Report HTML is suspiciously short"
