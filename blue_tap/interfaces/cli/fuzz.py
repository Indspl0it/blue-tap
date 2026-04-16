"""CLI facade for protocol-level fuzzing and crash analysis.

Creates the ``fuzz`` Click group and delegates to the existing command
implementations in ``blue_tap.modules.fuzzing.cli_commands`` and
``blue_tap.modules.fuzzing.cli_extra``.
"""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedGroup


@click.group(cls=LoggedGroup)
def fuzz():
    """Protocol-level fuzzing and crash analysis."""


# Register all fuzz sub-commands from the fuzzing module.
# NOTE: register_fuzz_commands() internally calls register_extra_commands(),
# so we must NOT call register_extra_commands() again here.
from blue_tap.modules.fuzzing.cli_commands import register_fuzz_commands  # noqa: E402

register_fuzz_commands(fuzz)
