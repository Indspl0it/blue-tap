"""Compatibility shim — canonical location is blue_tap.interfaces.cli.main."""

# In the old CLI, the Click group was named `main`. Tests and other callers
# that do `from blue_tap.cli import main` expect the Click group object.
# The new Click group is `cli`; expose it under the old name `main`.
from blue_tap.interfaces.cli.main import cli as main  # noqa: F401
from blue_tap.interfaces.cli.main import cli  # noqa: F401
from blue_tap.interfaces.cli.main import _command_needs_darkfirmware_bootstrap  # noqa: F401

# _command_succeeded was a module-level helper in the old cli.py monolith.
# It lives in post_exploitation now; re-export for test compatibility.
from blue_tap.interfaces.cli.post_exploitation import _command_succeeded  # noqa: F401

# These names were available in the old monolith's module scope.
# Tests monkeypatch them at blue_tap.cli.*; re-export so the name exists.
from blue_tap.utils.interactive import resolve_address, pick_two_devices  # noqa: F401
from blue_tap.utils.output import info, success, error, warning, verbose, console  # noqa: F401
from blue_tap.framework.runtime.cli_events import emit_cli_event  # noqa: F401

__all__ = [
    "cli",
    "main",
    "_command_needs_darkfirmware_bootstrap",
    "_command_succeeded",
    "resolve_address",
    "pick_two_devices",
    "info",
    "success",
    "error",
    "warning",
    "verbose",
    "console",
]
