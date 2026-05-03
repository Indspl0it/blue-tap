"""CLI integration tests for v2.6.4 fuzz additions.

Covers the new operator-facing surface:
- ``fuzz campaign --dry-run --seed N``: byte-level reproducibility via CLI.
- ``fuzz benchmark`` subcommand: runs N trials, writes JSON + per-trial CSVs.
- ``BLUE_TAP_FUZZ_SEED`` env var: applies to both CLI commands.

These tests exercise the real Click commands end-to-end through MockTransport
(``--dry-run``) so they need no Bluetooth hardware.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli


def _runner(tmp_path: Path, **extra_env: str) -> CliRunner:
    env = {
        "BT_TAP_SESSIONS_DIR": str(tmp_path),
        "BLUE_TAP_SKIP_ROOT_CHECK": "1",
    }
    env.update(extra_env)
    return CliRunner(env=env)


# ---------------------------------------------------------------------------
# fuzz campaign --dry-run / --seed
# ---------------------------------------------------------------------------


def test_campaign_dry_run_with_seed_completes(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_dryrun_seed",
            "fuzz", "campaign",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-n", "20",
            "--cooldown", "0",
            "--seed", "42",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "Seed locked: 42" in result.output
    # Placeholder target message confirms --dry-run skipped resolve_address.
    assert "placeholder target" in result.output


def test_campaign_dry_run_seed_is_reproducible(tmp_path):
    """Two CLI campaigns with the same --seed produce the same packet count.

    With ``-n 30`` set, the campaign must run exactly 30 iterations. The
    earlier failure mode was that dry-run unconditionally clamped duration
    to 5s, so the loop exited on wall-clock instead of iteration count and
    the count drifted run-to-run (9, 10, 12, …). Pinning the assertion to
    exactly 30 guards against that regression resurfacing.
    """
    runner = _runner(tmp_path)

    def _run(label: str) -> str:
        return runner.invoke(
            cli,
            [
                "-s", f"campaign_repro_{label}",
                "fuzz", "campaign",
                "--dry-run",
                "--strategy", "random",
                "-p", "sdp",
                "-n", "30",
                "--cooldown", "0",
                "--delay", "0",
                "--seed", "777",
            ],
            catch_exceptions=False,
        ).output

    a = _run("a")
    b = _run("b")
    def _iter_count(text: str) -> str:
        for line in text.splitlines():
            if "Total Iterations" in line:
                return line.split()[-1]
        raise AssertionError(f"Total Iterations not found in:\n{text}")
    count_a, count_b = _iter_count(a), _iter_count(b)
    assert count_a == count_b == "30", (
        f"Expected exactly 30 iterations under -n 30, got {count_a!r} and {count_b!r}"
    )


def test_campaign_resume_rejects_dry_run(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_resume_conflict",
            "fuzz", "campaign",
            "--resume",
            "--dry-run",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0  # error() prints, doesn't sys.exit
    assert "--dry-run cannot be combined with --resume" in result.output


def test_campaign_resume_rejects_seed(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_resume_seed",
            "fuzz", "campaign",
            "--resume",
            "--seed", "1",
        ],
        catch_exceptions=False,
    )
    assert "--seed cannot be combined with --resume" in result.output


def test_campaign_dry_run_disables_capture(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_capture_off",
            "fuzz", "campaign",
            "--dry-run",
            "--capture",
            "--strategy", "random",
            "-p", "sdp",
            "-n", "5",
            "--cooldown", "0",
        ],
        catch_exceptions=False,
    )
    assert "--dry-run disables --capture" in result.output


def test_campaign_env_seed_locks_reproducibility(tmp_path):
    runner = _runner(tmp_path, BLUE_TAP_FUZZ_SEED="0xdeadbeef")
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_env_seed",
            "fuzz", "campaign",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-n", "10",
            "--cooldown", "0",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # 0xdeadbeef == 3735928559
    assert "Seed locked: 3735928559" in result.output


def test_campaign_env_seed_invalid_raises(tmp_path):
    runner = _runner(tmp_path, BLUE_TAP_FUZZ_SEED="garbage")
    result = runner.invoke(
        cli,
        [
            "-s", "campaign_env_bad",
            "fuzz", "campaign",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-n", "5",
            "--cooldown", "0",
        ],
    )
    # click.BadParameter exits non-zero with a usage message.
    assert result.exit_code != 0
    assert "BLUE_TAP_FUZZ_SEED" in result.output


# ---------------------------------------------------------------------------
# fuzz benchmark subcommand
# ---------------------------------------------------------------------------


def test_benchmark_dry_run_writes_json_and_csv(tmp_path):
    runner = _runner(tmp_path)
    out_json = tmp_path / "bench.json"
    csv_dir = tmp_path / "trajectories"

    result = runner.invoke(
        cli,
        [
            "-s", "bench_full",
            "fuzz", "benchmark",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-t", "3",
            "-n", "30",
            "--cooldown", "0",
            "--base-seed", "42",
            "--trajectory-interval", "0.05",
            "-o", str(out_json),
            "--csv-dir", str(csv_dir),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "Benchmark Summary" in result.output

    # JSON is round-trippable BenchmarkResult.
    payload = json.loads(out_json.read_text())
    assert payload["n_trials"] == 3
    assert payload["strategy"] == "random"
    assert len(payload["trials"]) == 3

    # Per-trial CSVs exist with header + (likely) at least one sample row.
    csvs = sorted(csv_dir.glob("trial_*.csv"))
    assert [p.name for p in csvs] == ["trial_0.csv", "trial_1.csv", "trial_2.csv"]
    for p in csvs:
        rows = p.read_text().splitlines()
        assert rows[0] == (
            "elapsed_seconds,iterations,packets_sent,crashes,errors,"
            "states,transitions"
        )


def test_benchmark_csv_dir_without_trajectory_interval_warns(tmp_path):
    runner = _runner(tmp_path)
    csv_dir = tmp_path / "trajs"

    result = runner.invoke(
        cli,
        [
            "-s", "bench_warn",
            "fuzz", "benchmark",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-t", "1",
            "-n", "10",
            "--cooldown", "0",
            "--csv-dir", str(csv_dir),
        ],
        catch_exceptions=False,
    )
    # Rich may wrap the warning across lines; check for a stable token.
    assert "trajectory-interval" in result.output and "header-only" in result.output.replace("\n", " ")


def test_benchmark_requires_duration_or_iterations(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "bench_no_budget",
            "fuzz", "benchmark",
            "--dry-run",
            "-p", "sdp",
            "-t", "1",
            "--cooldown", "0",
        ],
        catch_exceptions=False,
    )
    assert "--duration or --iterations is required" in result.output


def test_benchmark_rejects_duration_and_iterations_together(tmp_path):
    runner = _runner(tmp_path)
    result = runner.invoke(
        cli,
        [
            "-s", "bench_both_budgets",
            "fuzz", "benchmark",
            "--dry-run",
            "-p", "sdp",
            "-t", "1",
            "-d", "1s",
            "-n", "10",
            "--cooldown", "0",
        ],
        catch_exceptions=False,
    )
    assert "mutually exclusive" in result.output


def test_benchmark_env_seed_drives_reproducibility(tmp_path):
    """Two benchmark runs with the same env seed produce identical aggregate stats."""
    runner = _runner(tmp_path, BLUE_TAP_FUZZ_SEED="50")

    def _run(label: str) -> dict:
        out = tmp_path / f"bench_{label}.json"
        result = runner.invoke(
            cli,
            [
                "-s", f"bench_repro_{label}",
                "fuzz", "benchmark",
                "--dry-run",
                "--strategy", "random",
                "-p", "sdp",
                "-t", "2",
                "-n", "20",
                "--cooldown", "0",
                "-o", str(out),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        return json.loads(out.read_text())

    a = _run("a")
    b = _run("b")
    # iterations / packets_sent / crashes are deterministic; runtime is not.
    for metric in ("iterations", "packets_sent", "crashes", "crashes_per_kpkt"):
        assert a[metric] == b[metric], f"{metric} not reproducible"


def test_benchmark_label_passed_through(tmp_path):
    runner = _runner(tmp_path)
    out = tmp_path / "bench.json"
    result = runner.invoke(
        cli,
        [
            "-s", "bench_label",
            "fuzz", "benchmark",
            "--dry-run",
            "--strategy", "random",
            "-p", "sdp",
            "-t", "1",
            "-n", "5",
            "--cooldown", "0",
            "--label", "my_experiment",
            "-o", str(out),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text())
    assert payload["label"] == "my_experiment"
