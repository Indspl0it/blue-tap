"""User-level config loader for ``blue-tap``.

Operators repeat the same flags constantly: ``-s mysession``, ``--hci hci0``.
This loader resolves a TOML config file (with explicit precedence) and feeds
its values into Click's ``default_map`` mechanism so every subcommand picks
them up without code changes elsewhere. CLI flags always override config
values — Click's normal flag/default precedence does the right thing once the
default_map is populated.

Resolution order (first hit wins):

  1. Explicit ``--config /path/to/file.toml`` from the CLI
  2. ``$BLUE_TAP_CONFIG`` environment variable
  3. ``$XDG_CONFIG_HOME/blue-tap/config.toml`` (or ``~/.config/blue-tap/config.toml`` if XDG_CONFIG_HOME is unset)
  4. ``~/.config/blue-tap/config.toml``  (explicit fallback when XDG_CONFIG_HOME points elsewhere)

If no file is found, ``load_config()`` returns ``None`` and the rest of the
CLI behaves exactly as before this loader was introduced.

Schema:

    [default]
    hci = "hci0"
    session = "main"

    [fuzz]
    seed = "12345"

    [fuzz.run]
    verbose = "true"

``[default]`` accepts only ``hci`` and ``session`` (root-level options Click
parses before the subcommand). Per-subcommand sections (``[fuzz]``,
``[fuzz.run]``, ``[report]``, ``[recon.sdp]``, …) accept any option name
declared on the matching Click command. Section names use TOML's nested-
table syntax: ``[fuzz.run]`` overrides options on ``blue-tap fuzz run``.

Unknown sections (no matching subcommand) and unknown keys (option not on
the matched command) raise :class:`ConfigError` so a typo never silently
disables an override. CLI flags still beat config values via Click's normal
flag/default precedence.
"""

from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# Allow-list of recognised keys per section. Anything else is a typo or a
# usage error — reject loudly rather than ignore silently.
_ALLOWED_KEYS: dict[str, set[str]] = {
    "default": {"hci", "session"},
}

# Maps Click option dest names to canonical config keys. Click uses
# ``session_name`` for ``-s/--session`` because the parameter binds via
# the keyword argument name; the config writes ``session = ...``.
_OPTION_NAME_TO_CONFIG_KEY: dict[str, str] = {
    "session_name": "session",
}


class ConfigError(Exception):
    """Raised when a config file cannot be parsed or violates the schema."""


@dataclass
class BlueTapConfig:
    """Parsed and validated TOML config.

    ``default`` holds root-level options (``[default]``). ``sections`` holds
    per-subcommand option overrides keyed by dotted Click path — e.g. the
    TOML section ``[fuzz.run]`` becomes ``sections["fuzz.run"]``.
    """

    source_path: str = ""
    default: dict[str, str] = field(default_factory=dict)
    sections: dict[str, dict[str, str]] = field(default_factory=dict)


# ── Path resolution ──────────────────────────────────────────────────────


def resolve_config_path(explicit: str | None = None) -> str | None:
    """Return the path of the config file to load, or ``None`` if no file exists.

    Respects the precedence chain documented in the module docstring. Does
    not validate or open the file — that is :func:`load_config`'s job.
    """
    if explicit:
        return explicit if os.path.isfile(explicit) else None

    env_path = os.environ.get("BLUE_TAP_CONFIG")
    if env_path:
        return env_path if os.path.isfile(env_path) else None

    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    candidates: list[str] = []
    if xdg_home:
        candidates.append(os.path.join(xdg_home, "blue-tap", "config.toml"))
    # Always add the explicit ``~/.config`` path even when XDG_CONFIG_HOME
    # points elsewhere — operators expect it to work either way.
    candidates.append(os.path.expanduser("~/.config/blue-tap/config.toml"))

    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ── Loader ───────────────────────────────────────────────────────────────


def load_config(explicit: str | None = None, *, cli_root=None) -> BlueTapConfig | None:
    """Resolve, parse, and fully validate the user's TOML config.

    Args:
        explicit: Path passed via ``--config`` (highest precedence).
        cli_root: Click root command. When provided, every per-subcommand
            section and key is cross-checked against the actual CLI tree so
            typos fail loudly here rather than silently doing nothing later.
            When omitted, only ``[default]`` is strictly validated; non-default
            sections are rejected loudly because we cannot tell whether they
            are typos without the tree. Library callers without a CLI tree
            should restrict their configs to ``[default]`` keys.

    Returns:
        ``BlueTapConfig`` on success, ``None`` when no file is found.

    Raises:
        ConfigError: parse failure or schema violation. The error message
            references the file path and the offending key/section so the
            operator can fix it without guessing.
    """
    path = resolve_config_path(explicit)
    if not path:
        return None

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError as exc:
        # Explicit --config or BLUE_TAP_CONFIG pointing at a non-file path:
        # surface clearly rather than silently ignore.
        raise ConfigError(f"Config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Cannot parse config {path!r}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read config {path!r}: {exc}") from exc

    cfg = BlueTapConfig(source_path=path)
    _validate_and_assign(raw, cfg, cli_root=cli_root)
    logger.info(
        "Loaded blue-tap config",
        extra={"path": path, "default": cfg.default, "sections": list(cfg.sections)},
    )
    return cfg


def _flatten_sections(raw: dict, prefix: str = "") -> dict[str, dict]:
    """Flatten nested TOML tables into ``{"dotted.path": {key: scalar}}``.

    A TOML file like::

        [default]
        hci = "hci0"

        [fuzz]
        seed = "12345"

        [fuzz.run]
        verbose = "true"

    becomes::

        {
            "default": {"hci": "hci0"},
            "fuzz": {"seed": "12345"},
            "fuzz.run": {"verbose": "true"},
        }

    Scalars and nested tables can co-exist in the same TOML table; scalars are
    collected at the current section path, nested tables are recursed into.
    """
    result: dict[str, dict] = {}
    scalars: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            child_path = f"{prefix}.{key}" if prefix else key
            result.update(_flatten_sections(value, prefix=child_path))
        else:
            scalars[key] = value
    if scalars:
        result[prefix] = scalars
    return result


def _build_cmd_index(cli_root) -> dict[str, tuple[Any, dict[str, str]]]:
    """Walk a Click tree once; return ``{dotted_path: (cmd, alias_map)}``.

    The alias map for each command accepts the param's dest name (e.g. ``fmt``)
    *and* the user-friendly flag-derived form (``--format`` → ``format``,
    ``--my-flag`` → ``my_flag``); both keys map to the canonical dest.
    """
    import click as _click

    def _aliases(cmd) -> dict[str, str]:
        out: dict[str, str] = {}
        for p in getattr(cmd, "params", []):
            if not isinstance(p, _click.Option):
                continue
            out[p.name] = p.name
            for flag in list(p.opts) + list(p.secondary_opts or []):
                if flag.startswith("--"):
                    out[flag[2:].replace("-", "_")] = p.name
        return out

    index: dict[str, tuple[Any, dict[str, str]]] = {}

    def _walk(cmd, path: str = "") -> None:
        index[path] = (cmd, _aliases(cmd))
        if isinstance(cmd, _click.Group):
            for sub_name, sub_cmd in cmd.commands.items():
                child = f"{path}.{sub_name}" if path else sub_name
                _walk(sub_cmd, child)

    _walk(cli_root)
    return index


def _validate_and_assign(raw: dict, cfg: BlueTapConfig, *, cli_root=None) -> None:
    """Validate ``raw`` and copy values into ``cfg``. Single source of truth.

    ``[default]`` is validated against the static ``_ALLOWED_KEYS["default"]``
    allow-list. Per-subcommand sections are validated against the Click tree
    if ``cli_root`` is provided; otherwise they are rejected (we cannot tell
    a typo from a real subcommand without the tree).
    """
    # Error messages quote section/key names rather than wrap them in
    # ``[brackets]``. rich-click renders ConfigError text through Rich's
    # markup parser, which interprets ``[fuzz]`` as a style tag and silently
    # strips it — leaving operators staring at ``Unknown key .seed`` with no
    # idea which section the loader meant.
    flattened = _flatten_sections(raw)

    if "" in flattened:
        bad_keys = ", ".join(repr(k) for k in sorted(flattened[""].keys()))
        raise ConfigError(
            f"Top-level keys without a section in {cfg.source_path!r}: "
            f"{bad_keys}. Put them under a section like 'default'."
        )

    cmd_index = _build_cmd_index(cli_root) if cli_root is not None else None

    for section_name, section_value in flattened.items():
        for key, value in section_value.items():
            if not isinstance(value, str):
                raise ConfigError(
                    f"Key {key!r} in section {section_name!r} "
                    f"(config {cfg.source_path!r}) must be a string; "
                    f"got {type(value).__name__}"
                )

        if section_name == "default":
            allowed = _ALLOWED_KEYS["default"]
            for key in section_value:
                if key not in allowed:
                    allowed_str = ", ".join(repr(k) for k in sorted(allowed))
                    raise ConfigError(
                        f"Unknown key {key!r} in section 'default' "
                        f"(config {cfg.source_path!r}). "
                        f"Allowed keys for 'default': {allowed_str}"
                    )
            cfg.default.update(section_value)
            continue

        if cmd_index is None:
            raise ConfigError(
                f"Section {section_name!r} in {cfg.source_path!r} requires a "
                "CLI tree to validate. Pass ``cli_root`` to ``load_config`` or "
                "restrict the config to ``'default'``."
            )

        if section_name not in cmd_index:
            available = ", ".join(repr(p) for p in sorted(p for p in cmd_index if p))
            raise ConfigError(
                f"Unknown config section {section_name!r} in {cfg.source_path!r}. "
                f"No matching subcommand. Known subcommands: {available}"
            )
        _, aliases = cmd_index[section_name]
        normalised: dict[str, str] = {}
        for key, value in section_value.items():
            if key not in aliases:
                user_visible = sorted({k for k, v in aliases.items() if k != v} | set(aliases.values()))
                user_visible_str = ", ".join(repr(k) for k in user_visible)
                raise ConfigError(
                    f"Unknown key {key!r} in section {section_name!r} "
                    f"(config {cfg.source_path!r}). "
                    f"Valid options for {section_name!r}: {user_visible_str}"
                )
            normalised[aliases[key]] = value  # canonical to dest at validation time
        cfg.sections[section_name] = normalised


# ── Click integration ────────────────────────────────────────────────────


def build_default_map(cli_root, cfg: BlueTapConfig) -> dict:
    """Walk a Click command tree and produce a ``ctx.default_map`` payload.

    Pure builder: ``cfg`` is assumed pre-validated by :func:`load_config`.
    Section keys in ``cfg.sections`` are already normalised to Click dest
    names there, so no alias resolution is needed at this layer.

    The resulting dict is suitable for assignment to ``ctx.default_map`` on
    the root click context.
    """
    import click as _click

    default_map: dict = {}

    def _options_for(cmd, path: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for param in getattr(cmd, "params", []):
            if not isinstance(param, _click.Option):
                continue
            canonical = _OPTION_NAME_TO_CONFIG_KEY.get(param.name, param.name)
            if canonical in cfg.default:
                out[param.name] = cfg.default[canonical]
        section_kv = cfg.sections.get(path)
        if section_kv:
            # Already normalised to dest names by _validate_and_assign.
            out.update(section_kv)
        return out

    def _walk(cmd, target: dict, path: str = "") -> None:
        target.update(_options_for(cmd, path))
        if isinstance(cmd, _click.Group):
            for sub_name, sub_cmd in cmd.commands.items():
                target.setdefault(sub_name, {})
                child = f"{path}.{sub_name}" if path else sub_name
                _walk(sub_cmd, target[sub_name], child)

    _walk(cli_root, default_map)
    return default_map
