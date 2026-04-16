"""Session interface — re-exports the framework session API for operator tooling.

The session CLI commands live in ``blue_tap.interfaces.cli.reporting`` (``session``
group).  This package re-exports the session store API so that operator scripts and
third-party tooling can work with sessions without reaching into ``framework/``.

Usage::

    from blue_tap.interfaces.sessions import Session, get_session, log_command
"""

from blue_tap.framework.sessions.store import (
    Session,
    get_session,
    set_session,
    set_adapter,
    log_command,
    save_file,
)

__all__ = [
    "Session",
    "get_session",
    "set_session",
    "set_adapter",
    "log_command",
    "save_file",
]
