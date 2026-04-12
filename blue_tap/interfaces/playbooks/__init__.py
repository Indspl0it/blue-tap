"""Playbook loading and execution interface.

A playbook is a YAML or plain-text file that describes a sequence of blue-tap
commands.  This module owns the loading and translation logic; the CLI ``run``
command uses :class:`PlaybookLoader` to parse files and resolve ``module:``
steps into CLI command strings.

YAML format::

    name: Quick Reconnaissance
    description: Fast, non-destructive scan
    duration: ~2 minutes
    risk: none
    steps:
      - command: scan classic -d 10
        description: Discover nearby Classic devices
      - command: vulnscan {target}
      - module: reconnaissance.campaign
        args: "{target}"

Plain-text format (one command per line, ``#`` comments ignored)::

    scan classic -d 10
    vulnscan {target}

Usage::

    from blue_tap.interfaces.playbooks import PlaybookLoader

    loader = PlaybookLoader()
    commands = loader.load("quick-recon")  # bundled name OR file path
    for cmd in commands:
        print(cmd)
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# ── Module-id → CLI command translation table ──────────────────────────────────

_MODULE_TO_CLI: dict[str, str] = {
    "assessment.vuln_scanner": "vulnscan",
    "assessment.fleet": "fleet",
    "reconnaissance.campaign": "recon auto",
    "discovery.scanner": "scan all",
}

_FAMILY_PREFIXES = (
    "exploitation.",
    "assessment.",
    "reconnaissance.",
    "post_exploitation.",
    "fuzzing.",
    "discovery.",
)


def _module_step_to_command(step: dict) -> str:
    """Translate a playbook step with a ``module:`` key to a CLI command string.

    Lookup order:
      1. Exact match in :data:`_MODULE_TO_CLI`.
      2. ``exploitation.*`` → the part after the dot (e.g. ``exploitation.knob`` → ``knob``).
      3. Any other module_id → the part after the last dot.

    Args from the step dict are appended after the command name when present.
    """
    module_id: str = step.get("module", "")
    args: str = step.get("args", "")

    if module_id in _MODULE_TO_CLI:
        cmd = _MODULE_TO_CLI[module_id]
    else:
        # Use the name after the last dot as a reasonable default
        cmd = module_id.rsplit(".", 1)[-1] if "." in module_id else module_id

    return f"{cmd} {args}".strip() if args else cmd


class PlaybookLoader:
    """Load a playbook from a YAML or plain-text file and return command strings.

    Resolves bundled playbook names (no path separator, no extension needed)
    to full paths via :mod:`blue_tap.playbooks` before loading.
    """

    def load(self, path_or_name: str) -> list[str]:
        """Load a playbook and return the resolved list of CLI command strings.

        Args:
            path_or_name: File path, bundled playbook name (e.g. ``'quick-recon'``),
                or bundled name with ``.yaml`` extension.

        Returns:
            List of command strings ready to pass to ``shlex.split`` and Click.

        Raises:
            FileNotFoundError: If the file does not exist after bundled lookup.
            ValueError: If a YAML playbook has no ``steps`` list.
        """
        resolved = self._resolve_path(path_or_name)
        if not os.path.exists(resolved):
            raise FileNotFoundError(f"Playbook not found: {path_or_name!r}")

        if resolved.endswith((".yaml", ".yml")):
            return self._load_yaml(resolved)
        return self._load_text(resolved)

    def load_bundled(self, name: str) -> list[str]:
        """Load a bundled playbook by name (without path or extension)."""
        path = self.get_bundled_path(name)
        return self.load(path)

    @staticmethod
    def list_bundled() -> list[str]:
        """Return sorted list of available bundled playbook names (with ``.yaml``)."""
        from blue_tap.playbooks import list_playbooks
        return list_playbooks()

    @staticmethod
    def get_bundled_path(name: str) -> str:
        """Return the filesystem path for a bundled playbook."""
        from blue_tap.playbooks import get_playbook_path
        return get_playbook_path(name)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _resolve_path(self, path_or_name: str) -> str:
        """Resolve a name or path to a filesystem path.

        If no path separator is present and the file doesn't exist locally,
        check bundled playbooks.
        """
        if os.sep not in path_or_name and not os.path.exists(path_or_name):
            candidate = self.get_bundled_path(path_or_name)
            if os.path.exists(candidate):
                logger.debug("Resolved %r to bundled playbook: %s", path_or_name, candidate)
                return candidate
        return path_or_name

    def _load_yaml(self, path: str) -> list[str]:
        """Parse a YAML playbook and return command strings."""
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)

        steps = data.get("steps", [])
        if not steps:
            raise ValueError(f"Playbook has no steps: {path!r}")

        commands: list[str] = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            if step.get("command"):
                commands.append(step["command"])
            elif step.get("module"):
                cmd = _module_step_to_command(step)
                if cmd:
                    commands.append(cmd)
        return [c for c in commands if c]

    @staticmethod
    def _load_text(path: str) -> list[str]:
        """Parse a plain-text playbook (one command per line)."""
        with open(path) as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]


__all__ = [
    "PlaybookLoader",
    "_module_step_to_command",
]
