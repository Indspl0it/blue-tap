"""User-flow 10.11: Session resume.

Two separate CliRunner invocations with the same session name.
Assertions:
  - Second invocation finds the first run's artifacts
  - session.json has 2 command entries (resume worked)
  - session.json is valid JSON after both runs (atomicity regression guard Phase 2.1)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import validate_run_envelope

SESSION_NAME = "flow_resume"
TARGET = "AA:BB:CC:DD:EE:FF"

_SCAN_RESULT = [
    {"address": TARGET, "name": "Resumable Device", "type": "classic", "rssi": -65},
]

_SDP_RESULT = {
    "status": "completed",
    "services": [{"uuid": "0x1101", "name": "Serial Port", "rfcomm_channel": 1}],
    "service_count": 1,
    "rfcomm_channels": [1],
    "l2cap_psms": [],
    "raw_output": "",
}


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_session_resume_accumulates_commands(tmp_path):
    """Two invocations with same session name must accumulate to 2 commands."""
    runner = _make_runner(tmp_path)

    # First invocation: discovery scan
    with patch("blue_tap.hardware.scanner.scan_all", return_value=_SCAN_RESULT):
        r1 = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "discovery.scanner", "MODE=all"],
        )
    assert r1.exit_code == 0, f"First invocation failed:\n{r1.output}"

    session_dir = tmp_path / "sessions" / SESSION_NAME
    assert (session_dir / "session.json").exists(), "session.json not created after first run"

    # session.json must be valid JSON after first run (atomicity guard)
    raw = (session_dir / "session.json").read_text()
    meta_after_first = json.loads(raw)  # raises if corrupt
    assert len(meta_after_first["commands"]) == 1, \
        f"Expected 1 command after first run, got {len(meta_after_first['commands'])}"

    # Second invocation: same session, recon step
    with patch(
        "blue_tap.modules.reconnaissance.sdp.browse_services_detailed",
        return_value=_SDP_RESULT,
    ):
        r2 = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "reconnaissance.sdp", f"RHOST={TARGET}"],
        )
    assert r2.exit_code == 0, f"Second invocation failed:\n{r2.output}"

    # session.json must be valid JSON after second run
    raw2 = (session_dir / "session.json").read_text()
    meta_after_second = json.loads(raw2)  # raises if corrupt

    # Must have 2 commands — resume appended to the session
    assert len(meta_after_second["commands"]) == 2, (
        f"Expected 2 commands after resume, got {len(meta_after_second['commands'])}. "
        f"Commands: {meta_after_second['commands']}"
    )

    # Validate both envelopes
    for cmd_entry in meta_after_second["commands"]:
        cmd_file = session_dir / cmd_entry["file"]
        cmd_data = json.loads(cmd_file.read_text())
        envelope = cmd_data["data"]
        errors = validate_run_envelope(envelope)
        assert errors == [], f"Envelope invalid for {cmd_entry['command']}: {errors}"
