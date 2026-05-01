"""Verify every step of every bundled playbook resolves to a registered Click command.

Bundled playbooks ship as YAML with literal command strings. The legacy CLI
(pre-2026-04 redesign) used different verbs, so older releases shipped playbooks
that silently fell through to ``UsageError`` at runtime — the failure was only
visible when the operator actually invoked them. This test pins the contract:
every step parses against the current root CLI without ``UsageError``.

The check appends ``--help`` to each command, which short-circuits Click's
subcommand dispatch right after path resolution and option parsing. That gives
us a fast, hardware-free validation that:

    1. Each command path (group → subgroup → command) is registered.
    2. The flag/option spelling is accepted by Click for that leaf command.
    3. ``TargetSubcommandGroup`` parents (recon, exploit, extract) accept the
       ``<target> <subcommand>`` ordering used in the bundled YAMLs.

It does NOT validate the semantic correctness of option values (e.g., a bad
``--strategy`` choice surfaces only when invoked without ``--help``). The
end-to-end userflow test in ``test_userflow_playbook.py`` covers that path
with mocked hardware.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.interfaces.playbooks import PlaybookLoader

# Substituted in for placeholders before Click sees the args. These don't need
# to be real targets — only well-formed enough for Click to parse them as
# positional values.
_TARGET_SUB = "AA:BB:CC:DD:EE:FF"
_HCI_SUB = "hci0"
_PHONE_SUB = "11:22:33:44:55:66"


def _expand_placeholders(cmd: str) -> str:
    """Substitute ``{target}`` / ``{hci}`` / ``{phone}`` / ``TARGET`` placeholders."""
    return (
        cmd.replace("{target}", _TARGET_SUB)
        .replace("{hci}", _HCI_SUB)
        .replace("{phone}", _PHONE_SUB)
        .replace("TARGET", _TARGET_SUB)
    )


def _bundled_playbook_names() -> list[str]:
    """Return all bundled playbook names (with ``.yaml``) for parametrization."""
    return PlaybookLoader.list_bundled()


def _all_steps() -> list[tuple[str, str]]:
    """Flatten every step of every bundled playbook into ``(playbook, command)`` pairs."""
    pairs: list[tuple[str, str]] = []
    loader = PlaybookLoader()
    for pb_name in _bundled_playbook_names():
        commands = loader.load_bundled(pb_name)
        for cmd in commands:
            pairs.append((pb_name, cmd))
    return pairs


def test_bundled_playbooks_directory_is_populated():
    """Trivial sanity check: the bundle is non-empty and each YAML loads."""
    names = _bundled_playbook_names()
    assert names, "No bundled playbooks discovered — package data missing?"

    loader = PlaybookLoader()
    for name in names:
        commands = loader.load_bundled(name)
        assert commands, f"Bundled playbook {name!r} resolved to zero commands"


@pytest.mark.parametrize(
    "playbook,command",
    _all_steps(),
    ids=lambda val: val if isinstance(val, str) and " " not in val else None,
)
def test_each_bundled_step_resolves_to_real_command(playbook: str, command: str):
    """Every step resolves to a registered Click command path.

    ``--help`` is appended so Click parses through the command tree to the leaf
    and exits before any real work runs. ``BLUE_TAP_SKIP_ROOT_CHECK`` (set in
    conftest) bypasses the privilege/RTL gate for hardware-touching paths.
    """
    expanded = _expand_placeholders(command)
    args = shlex.split(expanded) + ["--help"]

    runner = CliRunner()
    result = runner.invoke(cli, args, catch_exceptions=False)

    assert result.exit_code == 0, (
        f"Playbook {playbook!r} step did not resolve to a valid command path.\n"
        f"  Step:    {command!r}\n"
        f"  Args:    {args!r}\n"
        f"  Exit:    {result.exit_code}\n"
        f"  Output:\n{result.output}"
    )

    # Click's --help output always contains "Usage:" — if we got here without it,
    # something went wrong in dispatch even though exit_code happened to be 0.
    assert "Usage:" in result.output, (
        f"Playbook {playbook!r} step exited 0 but produced no help text — "
        f"dispatch likely fell through silently.\n"
        f"  Step: {command!r}\n"
        f"  Output: {result.output[:500]!r}"
    )


def test_yaml_module_step_translation_table_targets_exist():
    """Every ``_MODULE_TO_CLI`` entry resolves to a registered Click command.

    The translation table is consulted when YAML steps use the structured
    ``module: <module_id>`` form. The table must not point at commands that
    were removed during a CLI redesign — that's a silent breakage that would
    only surface when an operator wrote a ``module:``-style playbook.

    Walks the command tree directly rather than invoking, because some
    translations resolve to commands that prompt interactively (e.g. ``recon
    auto`` opens a target picker before ``--help`` can short-circuit).
    """
    import click as _click
    from blue_tap.interfaces.playbooks import _MODULE_TO_CLI

    for module_id, cli_command in _MODULE_TO_CLI.items():
        tokens = shlex.split(cli_command)
        assert tokens, f"Empty translation for {module_id!r}"

        # Walk: start at root, consume one token per level until we hit a leaf.
        current: _click.Command = cli
        path_so_far: list[str] = []
        for token in tokens:
            assert isinstance(current, _click.Group), (
                f"Translation {module_id!r} → {cli_command!r}: token "
                f"{token!r} appears after non-group command "
                f"{'/'.join(path_so_far) or '<root>'}"
            )
            sub = current.commands.get(token)
            assert sub is not None, (
                f"Translation {module_id!r} → {cli_command!r}: "
                f"{token!r} is not a registered subcommand of "
                f"{'/'.join(path_so_far) or '<root>'}. "
                f"Available: {sorted(current.commands)}"
            )
            current = sub
            path_so_far.append(token)


def test_playbook_yaml_files_match_loader_listing():
    """Files on disk match what ``list_bundled()`` reports — guards against
    stale package-data manifests when a playbook is added/removed.
    """
    pkg_dir = Path(__file__).resolve().parents[1] / "blue_tap" / "playbooks"
    on_disk = sorted(p.name for p in pkg_dir.glob("*.yaml"))
    listed = sorted(PlaybookLoader.list_bundled())
    assert on_disk == listed, (
        f"Mismatch between disk and loader listing:\n"
        f"  on disk: {on_disk}\n"
        f"  listed:  {listed}"
    )
