"""User-flow 10.8: Fuzzing campaign dry run.

Steps: run fuzzing.engine PROTOCOL=sdp DURATION=1
Assertions:
  - envelope summary has valid fuzzing outcomes
  - no contradiction between execution_status and module_outcome
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import (
    validate_run_envelope,
)
from blue_tap.framework.registry.families import FAMILY_OUTCOMES, ModuleFamily

TARGET = "AA:BB:CC:DD:EE:FF"
SESSION_NAME = "flow_fuzzing"

VALID_FUZZING_OUTCOMES = FAMILY_OUTCOMES[ModuleFamily.FUZZING]


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_fuzzing_campaign_dry_run(tmp_path):
    """FuzzCampaign.run() mocked to return no crashes; envelope must be valid."""
    runner = _make_runner(tmp_path)

    mock_campaign_result = {
        "status": "completed",
        "stats": {
            "unique_crashes": 0,
            "total_iterations": 42,
            "protocols": ["sdp"],
        },
    }

    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        return_value=mock_campaign_result,
    ):
        result = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "fuzzing.engine",
             f"RHOST={TARGET}", "PROTOCOLS=sdp", "DURATION=1s", "CONFIRM=yes"],
        )

    assert result.exit_code == 0, f"CLI crashed:\n{result.output}"

    session_dir = tmp_path / "sessions" / SESSION_NAME
    session_meta = json.loads((session_dir / "session.json").read_text())
    commands = session_meta["commands"]
    assert len(commands) == 1, f"Expected 1 command, got {len(commands)}"

    cmd_file = session_dir / commands[0]["file"]
    cmd_data = json.loads(cmd_file.read_text())
    envelope = cmd_data["data"]
    errors = validate_run_envelope(envelope)
    assert errors == [], f"Envelope invalid: {errors}"

    # Summary outcome must be in fuzzing taxonomy
    summary_outcome = envelope.get("summary", {}).get("outcome", "")
    assert summary_outcome in VALID_FUZZING_OUTCOMES, \
        f"Summary outcome not in fuzzing taxonomy: {summary_outcome!r}"

    # No contradictions between execution_status and module_outcome
    for execution in envelope.get("executions", []):
        exec_status = execution.get("execution_status", "")
        module_outcome = execution.get("module_outcome", "")
        assert module_outcome in VALID_FUZZING_OUTCOMES, \
            f"Execution module_outcome not in fuzzing taxonomy: {module_outcome!r}"
        # If execution_status is "completed", module_outcome cannot be None
        if exec_status == "completed":
            assert module_outcome, \
                "completed execution must have a module_outcome"
