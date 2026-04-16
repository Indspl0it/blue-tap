"""User-flow 10.10: Power-user module runner.

Replaces old console REPL test. Exercises:
  blue-tap run discovery.scanner HCI=hci0 → clean result
  blue-tap run exploitation.knob RHOST=... (without --yes) → destructive gate

Assertions:
  - Destructive gate: KNOB without --yes → warning, not a traceback
  - Session log records the discovery scanner run
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import validate_run_envelope

SESSION_NAME = "flow_runner"

_SCAN_RESULT = {
    "status": "completed",
    "devices": [
        {"address": "AA:BB:CC:DD:EE:FF", "name": "Runner Test", "type": "classic", "rssi": -60},
    ],
}


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_run_discovery_and_destructive_gate(tmp_path):
    """Run discovery via 'run' command; verify knob without --yes is blocked."""
    runner = _make_runner(tmp_path)

    # Step 1: Run discovery scanner
    with patch("blue_tap.hardware.scanner.scan_all_result", return_value=_SCAN_RESULT):
        result = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "discovery.scanner", "HCI=hci0", "MODE=classic"],
        )

    assert result.exit_code == 0, f"Discovery run crashed:\n{result.output}"
    assert "Traceback" not in result.output

    # Step 2: Run KNOB without --yes — should be blocked by destructive gate
    result2 = runner.invoke(
        cli,
        ["-s", SESSION_NAME, "run", "exploitation.knob", "RHOST=AA:BB:CC:DD:EE:FF"],
    )

    # Should NOT crash (exit_code 0 is acceptable — the module prints a warning and returns)
    assert "Traceback" not in result2.output, \
        f"Traceback in run output:\n{result2.output}"
    # The destructive warning message must appear
    output_lower = result2.output.lower()
    assert "destructive" in output_lower or "confirm" in output_lower, \
        f"Expected destructive warning for knob without --yes:\n{result2.output}"

    # Step 3: Verify session recorded the scanner run
    session_dir = tmp_path / "sessions" / SESSION_NAME
    assert (session_dir / "session.json").exists(), "session.json not created"

    session_meta = json.loads((session_dir / "session.json").read_text())
    commands = session_meta.get("commands", [])
    assert len(commands) >= 1, f"Expected at least 1 logged command, got {len(commands)}"

    cmd_file = session_dir / commands[0]["file"]
    cmd_data = json.loads(cmd_file.read_text())
    envelope = cmd_data["data"]
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Scanner envelope invalid: {errors}"
