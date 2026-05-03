import sys
import types
from pathlib import Path

import click
import pytest

# Stub fcntl on Windows so the framework imports cleanly.
if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.ModuleType("fcntl")

from blue_tap.framework.config import (
    BlueTapConfig,
    ConfigError,
    build_default_map,
    load_config,
)


def _toy_cli():
    """Build a small Click tree mirroring blue-tap's structure for isolated testing."""
    @click.group()
    @click.option("--hci", default="")
    @click.option("--session", "session_name", default="")
    def root():
        pass

    @root.group()
    @click.option("--seed", default="")
    def fuzz():
        pass

    @fuzz.command()
    @click.option("--verbose", is_flag=True)
    @click.option("--target", default="")
    def run(verbose, target):
        pass

    @root.command()
    @click.option("--format", "fmt", default="html")
    def report(fmt):
        pass

    return root


def test_load_config_parses_per_subcommand_sections(tmp_path):
    """All sections validated and normalised at load time when cli_root is provided."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[default]\n'
        'hci = "hci0"\n'
        '\n'
        '[fuzz]\n'
        'seed = "12345"\n'
        '\n'
        '[fuzz.run]\n'
        'target = "AA:BB:CC:DD:EE:FF"\n'
        '\n'
        '[report]\n'
        'format = "json"\n',
        encoding="utf-8",
    )

    cfg = load_config(str(cfg_path), cli_root=_toy_cli())
    assert cfg is not None
    assert cfg.default == {"hci": "hci0"}
    assert cfg.sections["fuzz"] == {"seed": "12345"}
    assert cfg.sections["fuzz.run"] == {"target": "AA:BB:CC:DD:EE:FF"}
    # ``format`` (user-friendly flag name) is normalised to dest ``fmt`` at load time.
    assert cfg.sections["report"] == {"fmt": "json"}


def test_build_default_map_uses_pre_normalised_sections(tmp_path):
    """build_default_map is now a pure builder; sections are dest-keyed already."""
    cfg = BlueTapConfig(
        source_path=str(tmp_path / "x.toml"),
        default={"hci": "hci0"},
        sections={
            "fuzz": {"seed": "12345"},
            "fuzz.run": {"target": "AA:BB:CC:DD:EE:FF"},
            "report": {"fmt": "json"},  # already normalised
        },
    )

    default_map = build_default_map(_toy_cli(), cfg)

    assert default_map.get("hci") == "hci0"
    assert default_map["fuzz"]["seed"] == "12345"
    assert default_map["fuzz"]["run"]["target"] == "AA:BB:CC:DD:EE:FF"
    assert default_map["report"]["fmt"] == "json"


def test_load_config_accepts_dest_name_directly(tmp_path):
    """Operators who know the Click dest name can use it instead of the flag name."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[report]\nfmt = "json"\n', encoding="utf-8")
    cfg = load_config(str(cfg_path), cli_root=_toy_cli())
    assert cfg is not None
    assert cfg.sections["report"] == {"fmt": "json"}


def test_load_config_rejects_unknown_section_with_cli_root(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[nonsense]\nx = "y"\n', encoding="utf-8")
    # Quoted-name format is required so rich-click does not strip ``[brackets]``
    # from the rendered error.
    with pytest.raises(ConfigError, match=r"Unknown config section 'nonsense'"):
        load_config(str(cfg_path), cli_root=_toy_cli())


def test_load_config_rejects_unknown_key_with_cli_root(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[fuzz]\nnot_an_option = "x"\n', encoding="utf-8")
    with pytest.raises(
        ConfigError,
        match=r"Unknown key 'not_an_option' in section 'fuzz'",
    ):
        load_config(str(cfg_path), cli_root=_toy_cli())


def test_load_config_rejects_non_default_section_without_cli_root(tmp_path):
    """Without a CLI tree we can't tell typos from real subcommands; reject loudly."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[fuzz]\nseed = "12345"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="requires a CLI tree"):
        load_config(str(cfg_path))


def test_load_config_rejects_top_level_scalars(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('hci = "hci0"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="Top-level keys without a section"):
        load_config(str(cfg_path), cli_root=_toy_cli())


def test_load_config_rejects_non_string_value(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[default]\nhci = 0\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="must be a string"):
        load_config(str(cfg_path), cli_root=_toy_cli())


def test_load_config_default_section_still_strict(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[default]\nbad_key = "x"\n', encoding="utf-8")
    with pytest.raises(
        ConfigError,
        match=r"Unknown key 'bad_key' in section 'default'",
    ):
        load_config(str(cfg_path), cli_root=_toy_cli())
