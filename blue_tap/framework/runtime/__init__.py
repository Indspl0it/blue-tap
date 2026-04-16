"""CLI event taxonomy, lifecycle management, and runtime abstractions."""

from blue_tap.framework.runtime.cli_events import CANONICAL_EVENT_TYPES, emit_cli_event

__all__ = [
    "CANONICAL_EVENT_TYPES",
    "emit_cli_event",
]
