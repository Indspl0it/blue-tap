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

Schema (v2.6.5 — minimal):

    [default]
    hci = "hci0"
    session = "main"

Only ``[default]`` keys ``hci`` and ``session`` are recognised. Any other key
is rejected with a clear validation error so typos don't silently land. The
schema will grow in v2.7.x to cover per-subcommand sections (``[fuzz]``,
``[report]``, etc.) as the rest of the CLI surface stabilises.
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
    """Parsed and validated TOML config."""

    source_path: str = ""
    default: dict[str, str] = field(default_factory=dict)


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


def load_config(explicit: str | None = None) -> BlueTapConfig | None:
    """Resolve and load the user's TOML config, or return ``None`` if absent.

    Args:
        explicit: Path passed via ``--config`` (highest precedence).

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
    _validate_and_assign(raw, cfg)
    logger.info(
        "Loaded blue-tap config",
        extra={"path": path, "default": cfg.default},
    )
    return cfg


def _validate_and_assign(raw: dict, cfg: BlueTapConfig) -> None:
    """Validate ``raw`` against the schema and copy values into ``cfg``."""
    for section_name, section_value in raw.items():
        if section_name not in _ALLOWED_KEYS:
            raise ConfigError(
                f"Unknown config section [{section_name}] in {cfg.source_path!r}. "
                f"Recognised sections: {sorted(_ALLOWED_KEYS)}"
            )
        if not isinstance(section_value, dict):
            raise ConfigError(
                f"Section [{section_name}] in {cfg.source_path!r} must be a "
                f"table; got {type(section_value).__name__}"
            )
        allowed = _ALLOWED_KEYS[section_name]
        for key, value in section_value.items():
            if key not in allowed:
                raise ConfigError(
                    f"Unknown key [{section_name}].{key} in {cfg.source_path!r}. "
                    f"Allowed keys for [{section_name}]: {sorted(allowed)}"
                )
            if not isinstance(value, str):
                raise ConfigError(
                    f"[{section_name}].{key} in {cfg.source_path!r} must be a "
                    f"string; got {type(value).__name__}"
                )
        if section_name == "default":
            cfg.default.update(section_value)


# ── Click integration ────────────────────────────────────────────────────


def build_default_map(cli_root, cfg: BlueTapConfig) -> dict:
    """Walk a Click command tree and produce a ``ctx.default_map`` payload.

    For every option whose dest matches a config key (after the
    ``_OPTION_NAME_TO_CONFIG_KEY`` aliasing pass), inject the config value at
    the appropriate path in the returned nested dict. The structure mirrors
    the Click subcommand tree so values flow naturally to nested groups.

    The resulting dict is suitable for assignment to ``ctx.default_map`` on
    the root click context.
    """
    import click as _click

    default_map: dict = {}

    def _options_for(cmd) -> dict[str, str]:
        """Return ``{config_key: value}`` for every applicable option on ``cmd``."""
        out: dict[str, str] = {}
        for param in getattr(cmd, "params", []):
            if not isinstance(param, _click.Option):
                continue
            canonical = _OPTION_NAME_TO_CONFIG_KEY.get(param.name, param.name)
            if canonical in cfg.default:
                # Click default_map keys are the param's *dest* (param.name),
                # not the canonical config key — e.g. for the root ``-s``
                # option the key is ``session_name``.
                out[param.name] = cfg.default[canonical]
        return out

    def _walk(cmd, target: dict) -> None:
        # Inject this command's option defaults at the current level.
        target.update(_options_for(cmd))
        if isinstance(cmd, _click.Group):
            for sub_name, sub_cmd in cmd.commands.items():
                target.setdefault(sub_name, {})
                _walk(sub_cmd, target[sub_name])

    _walk(cli_root, default_map)
    return default_map
