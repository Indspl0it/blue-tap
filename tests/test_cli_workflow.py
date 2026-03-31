import json
from pathlib import Path

from click.testing import CliRunner

from blue_tap.cli import main


def _read_session_meta(root: Path, name: str) -> dict:
    with (root / "sessions" / name / "session.json").open() as f:
        return json.load(f)


def test_run_uses_single_session_for_all_steps() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["-s", "onesession", "run", "session list"])
        assert result.exit_code == 0

        sessions_root = Path("sessions")
        session_dirs = {p.name for p in sessions_root.iterdir() if p.is_dir()}
        assert session_dirs == {"onesession"}


def test_run_is_non_blocking_when_a_step_fails() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["-s", "wf", "run", "nonexistent", "session list"])
        assert result.exit_code == 0
        assert "Results: 1 succeeded, 1 failed out of 2" in result.output

        meta = _read_session_meta(Path("."), "wf")
        commands = [entry["command"] for entry in meta["commands"]]
        # workflow_run logs its own results; session list is read-only
        # and no longer auto-logged to avoid double-counting
        assert "workflow_run" in commands
