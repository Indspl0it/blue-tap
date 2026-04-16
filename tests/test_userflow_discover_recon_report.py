"""User-flow 10.1: Discover → Recon → Report.

Simulates the most common operator entry path:
  1. run discovery.scanner MODE=all
  2. run reconnaissance.sdp RHOST=<addr>
  3. run reconnaissance.gatt RHOST=<addr>
  4. run reconnaissance.fingerprint RHOST=<addr>
  5. report
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import validate_run_envelope

TARGET = "AA:BB:CC:DD:EE:FF"
SESSION_NAME = "flow_discover_recon_report"

_SCAN_RESULT = {
    "status": "completed",
    "devices": [
        {"address": TARGET, "name": "Test Device", "type": "classic", "rssi": -60},
    ],
}

_SDP_RESULT = {
    "status": "completed",
    "services": [
        {"uuid": "0x1101", "name": "Serial Port", "rfcomm_channel": 1},
    ],
    "service_count": 1,
    "rfcomm_channels": [1],
    "l2cap_psms": [],
    "raw_output": "SDP service list",
}

_GATT_RESULT = {
    "status": "completed",
    "services": [
        {"uuid": "0x1800", "name": "Generic Access"},
    ],
}

_FINGERPRINT_RESULT = {
    "address": TARGET,
    "name": "Test Device",
    "version": "BT 4.2",
    "chipset": "Unknown",
    "profiles": ["HFP", "A2DP"],
    "attack_surface": [],
    "error": None,
}


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_discover_recon_report_flow(tmp_path):
    runner = _make_runner(tmp_path)

    with (
        patch("blue_tap.hardware.scanner.scan_all_result", return_value=_SCAN_RESULT),
        patch("blue_tap.modules.reconnaissance.sdp.browse_services_detailed", return_value=_SDP_RESULT),
        patch("blue_tap.modules.reconnaissance.gatt.enumerate_services_detailed_sync", return_value=_GATT_RESULT),
        patch("blue_tap.modules.reconnaissance.fingerprint.fingerprint_device", return_value=_FINGERPRINT_RESULT),
    ):
        r1 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "discovery.scanner", "MODE=all"])
        assert r1.exit_code == 0, f"discovery.scanner failed:\n{r1.output}"

        r2 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "reconnaissance.sdp", f"RHOST={TARGET}"])
        assert r2.exit_code == 0, f"reconnaissance.sdp failed:\n{r2.output}"

        r3 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "reconnaissance.gatt", f"RHOST={TARGET}"])
        assert r3.exit_code == 0, f"reconnaissance.gatt failed:\n{r3.output}"

        r4 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "reconnaissance.fingerprint", f"RHOST={TARGET}"])
        assert r4.exit_code == 0, f"reconnaissance.fingerprint failed:\n{r4.output}"

    # Verify session has 4 command entries
    session_dir = tmp_path / "sessions" / SESSION_NAME
    session_meta = json.loads((session_dir / "session.json").read_text())
    commands = session_meta["commands"]
    assert len(commands) == 4, f"Expected 4 commands, got {len(commands)}: {commands}"

    # Validate each envelope
    for cmd_entry in commands:
        cmd_file = session_dir / cmd_entry["file"]
        cmd_data = json.loads(cmd_file.read_text())
        envelope = cmd_data["data"]
        errors = validate_run_envelope(envelope)
        assert errors == [], f"Envelope invalid for {cmd_entry['command']}: {errors}"

    # Generate report
    r5 = runner.invoke(cli, ["-s", SESSION_NAME, "report"])
    assert r5.exit_code == 0, f"report failed:\n{r5.output}"

    report_file = session_dir / "report.html"
    assert report_file.exists(), "report.html was not created"

    html = report_file.read_text()
    assert "Discovery" in html or "discovery" in html or "Scanner" in html, \
        "HTML report missing Discovery section"
    assert "Reconnaissance" in html or "reconnaissance" in html or "SDP" in html, \
        "HTML report missing Reconnaissance section"
