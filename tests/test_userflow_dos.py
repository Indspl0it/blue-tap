"""User-flow 10.5: DoS probe with explicit unknown check.

Steps:
  1. run exploitation.dos_cve_2020_0022_bluefrag RHOST=<addr> CONFIRM=yes
     → valid envelope with exploitation outcome
  2. run does_not_exist module → clean error, no traceback
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
SESSION_NAME = "flow_dos"

VALID_EXPLOITATION_OUTCOMES = FAMILY_OUTCOMES[ModuleFamily.EXPLOITATION]

# The bluefrag check is destructive. Its module_id is exploitation.dos_cve_2020_0022_bluefrag
BLUEFRAG_MODULE = "exploitation.dos_cve_2020_0022_bluefrag"


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_dos_bluefrag_valid_envelope(tmp_path):
    """BlueFrag DoS probe must produce a valid envelope when mocked."""
    runner = _make_runner(tmp_path)

    # The BlueFragModule._execute_check calls bluefrag_crash_probe — mock at that level
    mock_raw = {
        "result": "not_applicable",
        "target_status": "unknown",
        "notes": "Raw ACL socket not available (test environment)",
        "error": None,
    }

    with patch(
        "blue_tap.modules.exploitation.dos.checks_raw_acl.bluefrag_crash_probe",
        return_value=mock_raw,
    ):
        result = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", BLUEFRAG_MODULE,
             f"RHOST={TARGET}", "CONFIRM=yes"],
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


def test_dos_unknown_module_clean_error(tmp_path):
    """Running a non-existent module must produce a clean error, not a traceback."""
    runner = _make_runner(tmp_path)

    result = runner.invoke(
        cli,
        ["-s", SESSION_NAME + "_unknown", "run", "exploitation.does_not_exist",
         f"RHOST={TARGET}", "CONFIRM=yes"],
    )

    # Failed module runs now correctly exit non-zero (clean error, not crash)
    assert result.exit_code == 1, \
        f"Expected non-zero exit for unknown module, got {result.exit_code}:\n{result.output}"

    # Must say "not found" or similar — not a raw traceback
    output_lower = result.output.lower()
    assert "not found" in output_lower or "module" in output_lower, \
        f"Expected clean 'not found' error in output:\n{result.output}"

    # Must NOT contain a Python traceback
    assert "Traceback" not in result.output and "traceback" not in result.output, \
        f"Traceback appeared in output:\n{result.output}"
