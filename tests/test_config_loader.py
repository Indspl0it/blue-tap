"""Coverage for ``blue_tap.framework.config``.

Two layers:

* The loader (path resolution, parsing, schema validation).
* The Click integration (``--config``, env var, CLI flag override).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from blue_tap.framework.config import (
    BlueTapConfig,
    ConfigError,
    build_default_map,
    load_config,
    resolve_config_path,
)
from blue_tap.interfaces.cli.main import cli


# ── Path resolution ──────────────────────────────────────────────────────


def test_resolve_path_returns_explicit_when_file_exists(tmp_path: Path):
    cfg = tmp_path / "explicit.toml"
    cfg.write_text("")
    assert resolve_config_path(str(cfg)) == str(cfg)


def test_resolve_path_returns_none_when_explicit_missing(tmp_path: Path):
    ghost = tmp_path / "ghost.toml"
    assert resolve_config_path(str(ghost)) is None


def test_resolve_path_honours_env_var(tmp_path: Path, monkeypatch):
    cfg = tmp_path / "env.toml"
    cfg.write_text("")
    monkeypatch.setenv("BLUE_TAP_CONFIG", str(cfg))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    # Pin HOME so a real ~/.config/blue-tap/config.toml on the dev box never
    # interferes with the test result.
    monkeypatch.setenv("HOME", str(tmp_path / "ghost_home"))
    assert resolve_config_path() == str(cfg)


def test_resolve_path_honours_xdg(tmp_path: Path, monkeypatch):
    xdg = tmp_path / "xdg"
    xdg_cfg = xdg / "blue-tap" / "config.toml"
    xdg_cfg.parent.mkdir(parents=True)
    xdg_cfg.write_text("")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.delenv("BLUE_TAP_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "ghost_home"))
    assert resolve_config_path() == str(xdg_cfg)


def test_resolve_path_returns_none_when_nothing_exists(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("BLUE_TAP_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty_xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "empty_home"))
    assert resolve_config_path() is None


# ── Loading and validation ───────────────────────────────────────────────


def test_load_config_returns_none_when_no_file(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("BLUE_TAP_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "x"))
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    assert load_config() is None


def test_load_config_parses_default_section(tmp_path: Path):
    f = tmp_path / "ok.toml"
    f.write_text(
        "[default]\n"
        'hci = "hci1"\n'
        'session = "engagement_42"\n'
    )
    cfg = load_config(str(f))
    assert isinstance(cfg, BlueTapConfig)
    assert cfg.default == {"hci": "hci1", "session": "engagement_42"}
    assert cfg.source_path == str(f)


def test_load_config_rejects_unknown_section(tmp_path: Path):
    f = tmp_path / "bad.toml"
    f.write_text("[invalid_section]\nfoo = 'bar'\n")
    with pytest.raises(ConfigError, match="Unknown config section"):
        load_config(str(f))


def test_load_config_rejects_unknown_key(tmp_path: Path):
    f = tmp_path / "bad.toml"
    f.write_text("[default]\nbogus_key = 'x'\n")
    with pytest.raises(ConfigError, match="Unknown key.*bogus_key"):
        load_config(str(f))


def test_load_config_rejects_non_string_value(tmp_path: Path):
    f = tmp_path / "bad.toml"
    f.write_text("[default]\nhci = 42\n")
    with pytest.raises(ConfigError, match="must be a string"):
        load_config(str(f))


def test_load_config_rejects_malformed_toml(tmp_path: Path):
    f = tmp_path / "broken.toml"
    f.write_text("[default\nhci = ")
    with pytest.raises(ConfigError, match="Cannot parse config"):
        load_config(str(f))


# ── Default-map construction ─────────────────────────────────────────────


def test_build_default_map_injects_hci_into_subcommand_options():
    """``[default].hci`` should propagate to every subcommand that takes ``--hci``."""
    cfg = BlueTapConfig(default={"hci": "hci_test"})
    dmap = build_default_map(cli, cfg)

    # ``vulnscan`` is a leaf command with --hci. Its default should be set.
    assert "vulnscan" in dmap
    assert dmap["vulnscan"].get("hci") == "hci_test"


def test_build_default_map_recurses_into_groups():
    """Nested groups (e.g. ``recon`` → ``sdp``) get their own dict entries."""
    cfg = BlueTapConfig(default={"hci": "hci0"})
    dmap = build_default_map(cli, cfg)
    # ``recon`` is a group; its --hci default lives at ``recon.hci``.
    assert "recon" in dmap
    assert dmap["recon"].get("hci") == "hci0"


def test_build_default_map_aliases_session_name():
    """Config writes ``session = ...`` but Click param dest is ``session_name``."""
    cfg = BlueTapConfig(default={"session": "engagement"})
    dmap = build_default_map(cli, cfg)
    # The root group's session_name should be in the top-level dict.
    assert dmap.get("session_name") == "engagement"


def test_build_default_map_skips_keys_not_in_config():
    cfg = BlueTapConfig(default={})
    dmap = build_default_map(cli, cfg)
    # Even with an empty config, the structure is well-formed (no errors)
    # and contains no injected values for vulnscan/recon.
    assert dmap.get("vulnscan", {}).get("hci") is None


# ── Click CLI integration ────────────────────────────────────────────────


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_cli_with_no_config_behaves_unchanged(tmp_path: Path, monkeypatch):
    """Smoke test: with no config file resolvable, the CLI runs as before."""
    monkeypatch.delenv("BLUE_TAP_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "no_home"))
    runner = _make_runner(tmp_path)
    result = runner.invoke(cli, ["doctor"], catch_exceptions=False)
    assert result.exit_code == 0


def test_cli_config_session_default_applies(tmp_path: Path, monkeypatch):
    """``[default].session`` propagates to ``-s`` when the flag is omitted."""
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[default]\nsession = "from_config"\n')

    runner = _make_runner(tmp_path)
    # Use ``info`` with no session flag — it's read-only and won't try to
    # touch hardware. We assert by checking that a session named
    # "from_config" was created on disk by the cli root callback.
    # ``info`` is in the _NO_SESSION_COMMANDS set, so we use ``run`` instead
    # which DOES create a session when one isn't passed.
    with patch(
        "blue_tap.hardware.scanner.scan_all",
        return_value=[],
    ):
        result = runner.invoke(
            cli,
            ["--config", str(cfg_file), "run", "discovery.scanner", "MODE=all"],
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    # The session named in the config should exist on disk.
    assert (tmp_path / "sessions" / "from_config" / "session.json").exists(), (
        f"Session 'from_config' from config was not created. "
        f"Sessions dir contents: {list((tmp_path / 'sessions').iterdir()) if (tmp_path / 'sessions').exists() else 'no sessions dir'}\n"
        f"Output:\n{result.output}"
    )


def test_cli_flag_overrides_config_session(tmp_path: Path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[default]\nsession = "from_config"\n')

    runner = _make_runner(tmp_path)
    with patch(
        "blue_tap.hardware.scanner.scan_all",
        return_value=[],
    ):
        result = runner.invoke(
            cli,
            [
                "--config", str(cfg_file),
                "-s", "from_flag",
                "run", "discovery.scanner", "MODE=all",
            ],
            catch_exceptions=False,
        )

    assert result.exit_code == 0, result.output
    assert (tmp_path / "sessions" / "from_flag" / "session.json").exists()
    assert not (tmp_path / "sessions" / "from_config" / "session.json").exists(), (
        "CLI flag should have overridden the config session"
    )


def test_cli_malformed_config_exits_with_clear_error(tmp_path: Path):
    cfg_file = tmp_path / "broken.toml"
    cfg_file.write_text("[default\nhci = ")
    runner = _make_runner(tmp_path)
    result = runner.invoke(
        cli,
        ["--config", str(cfg_file), "doctor"],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "Cannot parse config" in result.output


def test_cli_unknown_config_key_exits_with_clear_error(tmp_path: Path):
    cfg_file = tmp_path / "typo.toml"
    cfg_file.write_text('[default]\nhsi = "hci0"\n')  # typo: hsi vs hci
    runner = _make_runner(tmp_path)
    result = runner.invoke(
        cli,
        ["--config", str(cfg_file), "doctor"],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "Unknown key" in result.output
    assert "hsi" in result.output
