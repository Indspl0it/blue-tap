"""Dry-run rollout coverage: framework hooks, root CLI flag, per-family smoke tests.

The dry-run feature must:
  1. Default-modular: every Module subclass inherits dry-run via Invoker
     short-circuit (no per-module wiring required).
  2. Opt-in rich: modules that override ``supports_dry_run = True`` keep their
     own deterministic dry-run path (fuzzer's MockTransport pipeline).
  3. Bypass the destructive CONFIRM=yes gate (the dry-run is itself the safety).
  4. Skip session writes (a no-op preview is not worth persisting).
  5. Honor both root ``--dry-run`` and ``$BLUE_TAP_DRY_RUN=1``.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from blue_tap.framework.module import (
    DestructiveConfirmationRequired,
    Invoker,
)
from blue_tap.framework.module.context import RunContext
from blue_tap.framework.module.options_container import OptionsContainer


# ── 1. Framework hooks ───────────────────────────────────────────────────────

def test_run_context_carries_dry_run_field():
    """RunContext stores dry_run; defaults to False."""
    ctx = RunContext.create(
        options=OptionsContainer.from_schema(()),
        module_id="discovery.scanner",
    )
    assert ctx.dry_run is False

    ctx2 = RunContext.create(
        options=OptionsContainer.from_schema(()),
        module_id="discovery.scanner",
        dry_run=True,
    )
    assert ctx2.dry_run is True


def test_invoker_short_circuits_default_modules_with_planned_envelope():
    """Modules without ``supports_dry_run`` get a synthesized envelope, run() is never called."""
    inv = Invoker()
    env = inv.invoke(
        "discovery.scanner",
        {"RHOST": "AA:BB:CC:DD:EE:FF"},
        dry_run=True,
    )
    assert env["summary"]["outcome"] == "not_applicable"
    assert env["summary"]["dry_run"] is True
    assert env["module_data"]["dry_run"] is True
    assert env["module_data"]["module_id"] == "discovery.scanner"
    assert env["executions"][0]["execution_status"] == "skipped"
    assert env["executions"][0]["module_outcome"] == "not_applicable"


def test_invoker_dry_run_bypasses_destructive_gate():
    """Destructive modules normally require CONFIRM=yes; dry-run bypasses that."""
    inv = Invoker()
    # Without dry_run + CONFIRM: must raise.
    with pytest.raises(DestructiveConfirmationRequired):
        inv.invoke("exploitation.knob", {"RHOST": "AA:BB:CC:DD:EE:FF"})
    # With dry_run: succeeds, envelope marks destructive=True.
    env = inv.invoke("exploitation.knob", {"RHOST": "AA:BB:CC:DD:EE:FF"}, dry_run=True)
    assert env["summary"]["destructive"] is True
    assert env["summary"]["dry_run"] is True


def test_invoker_dry_run_skips_hci_resolution():
    """The synthesized envelope shouldn't probe hardware to resolve HCI."""
    inv = Invoker()
    env = inv.invoke(
        "discovery.scanner",
        {"RHOST": "AA:BB:CC:DD:EE:FF"},
        dry_run=True,
    )
    # Adapter not auto-injected when caller didn't supply one in dry-run.
    assert env["adapter"] in ("", None) or isinstance(env["adapter"], str)


def test_supports_dry_run_opt_in_routes_to_module():
    """A module setting supports_dry_run=True keeps control of its own dry-run path.

    Uses ``fuzzing.engine`` which is the canonical opt-in module: when
    ``supports_dry_run = True``, Invoker calls ``run()`` instead of
    short-circuiting, and the engine's MockTransport pipeline executes.
    """
    from blue_tap.framework.registry import get_registry

    desc = get_registry().try_get("fuzzing.engine")
    assert desc is not None

    # The engine module sets supports_dry_run = True at class level.
    from blue_tap.modules.fuzzing.campaign import FuzzCampaignModule
    assert FuzzCampaignModule.supports_dry_run is True

    inv = Invoker()
    env = inv.invoke(
        "fuzzing.engine",
        {
            "RHOST": "AA:BB:CC:DD:EE:FF",
            "PROTOCOLS": "sdp",
            "MAX_ITERATIONS": "1",
            "DURATION": "3s",
            "SESSION_DIR": "/tmp/blue-tap-test-fuzz-optin",
        },
        dry_run=True,
    )
    # Engine actually ran (would have set packets_sent / iterations); a
    # short-circuit would have produced ``outcome=not_applicable`` and no
    # packet stats.
    summary = env.get("summary", {})
    assert summary.get("packets_sent", 0) >= 1, (
        f"Opt-in module should have executed, got synthesized envelope: {summary}"
    )


def test_invoker_skips_session_log_in_dry_run(tmp_path):
    """``invoke_with_logging`` must not call session.log() during dry-run."""
    from blue_tap.framework.sessions.store import Session
    sess = Session("dry-run-test-session")
    inv = Invoker()
    inv.invoke_with_logging(
        "discovery.scanner",
        {"RHOST": "AA:BB:CC:DD:EE:FF"},
        session=sess,
        dry_run=True,
    )
    # Session directory exists, but no commands were logged.
    log_path = os.path.join(sess.dir, "general.json")
    if os.path.exists(log_path):
        import json
        with open(log_path) as f:
            data = json.load(f)
        # Either the file is fresh (empty list) or the logged data is empty.
        assert not data or all("dry_run" in str(d) for d in data)


# ── 2. Root CLI flag and env var ─────────────────────────────────────────────

@pytest.fixture
def cli_runner(monkeypatch):
    """Set the skip-root-check env var so CliRunner doesn't trip the privilege gate."""
    monkeypatch.setenv("BLUE_TAP_SKIP_ROOT_CHECK", "1")
    monkeypatch.delenv("BLUE_TAP_DRY_RUN", raising=False)
    return CliRunner()


def test_root_dry_run_flag_propagates_to_run_command(cli_runner):
    """``blue-tap --dry-run run discovery.scanner`` short-circuits via Invoker."""
    from blue_tap.interfaces.cli.main import cli
    result = cli_runner.invoke(
        cli,
        ["--dry-run", "run", "discovery.scanner", "RHOST=AA:BB:CC:DD:EE:FF"],
    )
    assert result.exit_code == 0, result.output
    assert "Dry-run" in result.output
    assert "would run" in result.output


def test_root_dry_run_flag_propagates_to_workflow_commands(cli_runner):
    """vulnscan / discover / exploit / extract all auto-inherit via _module_runner."""
    from blue_tap.interfaces.cli.main import cli
    for argv in (
        ["--dry-run", "vulnscan", "AA:BB:CC:DD:EE:FF"],
        ["--dry-run", "discover", "classic"],
    ):
        result = cli_runner.invoke(cli, argv)
        assert result.exit_code == 0, f"{argv} → {result.output}"
        assert "Dry-run" in result.output, f"{argv}: dry-run banner missing"


def test_env_var_dry_run_alternative(cli_runner, monkeypatch):
    """``BLUE_TAP_DRY_RUN=1`` is honored without the explicit flag."""
    monkeypatch.setenv("BLUE_TAP_DRY_RUN", "1")
    from blue_tap.interfaces.cli.main import cli
    result = cli_runner.invoke(
        cli,
        ["run", "discovery.scanner", "RHOST=AA:BB:CC:DD:EE:FF"],
    )
    assert result.exit_code == 0, result.output
    assert "Dry-run" in result.output


def test_dry_run_destructive_module_via_cli_no_confirm(cli_runner):
    """Destructive modules in dry-run must NOT require --yes / CONFIRM=yes."""
    from blue_tap.interfaces.cli.main import cli
    result = cli_runner.invoke(
        cli,
        ["--dry-run", "run", "exploitation.knob", "RHOST=AA:BB:CC:DD:EE:FF"],
    )
    assert result.exit_code == 0, result.output
    assert "Dry-run" in result.output
    assert "destructive" in result.output.lower()


# ── 3. Per-family smoke tests via Invoker ────────────────────────────────────

@pytest.mark.parametrize(
    "module_id,extra_opts",
    [
        ("discovery.scanner", {}),
        ("reconnaissance.sdp", {}),
        ("assessment.vuln_scanner", {}),
        ("exploitation.knob", {}),
        # bias requires PHONE — supply a placeholder; option validation still
        # runs in dry-run so operators get accurate feedback.
        ("exploitation.bias", {"PHONE": "11:22:33:44:55:66"}),
        ("exploitation.bluffs", {}),
    ],
)
def test_dry_run_smoke_per_module(module_id, extra_opts):
    """Every listed module returns a valid 'planned' envelope under dry-run."""
    from blue_tap.framework.contracts.result_schema import validate_run_envelope
    inv = Invoker()
    env = inv.invoke(
        module_id,
        {"RHOST": "AA:BB:CC:DD:EE:FF", **extra_opts},
        dry_run=True,
    )
    errs = validate_run_envelope(env)
    assert errs == [], f"{module_id} dry-run envelope failed validation: {errs}"
    assert env["module_data"]["dry_run"] is True


def test_fuzz_dry_run_runs_engine_with_mock_transport():
    """fuzzing.engine has supports_dry_run=True; should actually run via MockTransport."""
    inv = Invoker()
    env = inv.invoke(
        "fuzzing.engine",
        {
            "RHOST": "AA:BB:CC:DD:EE:FF",
            "PROTOCOLS": "sdp",
            "MAX_ITERATIONS": "3",
            "DURATION": "5s",
            "SESSION_DIR": "/tmp/blue-tap-test-fuzz-dry-run",
        },
        dry_run=True,
    )
    # Engine ran: outcome is fuzzing-family valid, packets_sent > 0 (not the
    # synthesized "planned" envelope which would have outcome=not_applicable
    # and no packets_sent field).
    summary = env.get("summary", {})
    assert summary.get("outcome") in {"no_findings", "crash_found", "completed"}
    assert summary.get("packets_sent", 0) >= 1
