"""RunContext provides the execution context for a module run.

Wraps options, session, adapter, logging, and event emission into a single
object passed to module.run() and module.check().
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from blue_tap.framework.contracts.result_schema import ArtifactRef
    from blue_tap.framework.module.options_container import OptionsContainer
    from blue_tap.framework.sessions.store import Session

from blue_tap.framework.contracts.result_schema import make_run_id, now_iso


@dataclass(slots=True)
class RunContext:
    """Execution context for a module.

    Provides access to validated options, the active session, the HCI adapter,
    and methods for emitting CLI events and saving artifacts.

    Attributes:
        options: Validated options container.
        session: Active session for artifact storage (may be None).
        adapter: HCI adapter name (e.g., "<hciX>").
        run_id: Unique identifier for this run.
        started_at: ISO8601 timestamp when the run started.
        logger: Logger instance for this module.
        module_id: Module identifier (e.g., "exploitation.knob").
        target: Target address or identifier.
    """

    options: OptionsContainer
    session: Session | None
    adapter: str
    run_id: str
    started_at: str
    logger: logging.Logger
    module_id: str = ""
    target: str = ""
    dry_run: bool = False
    _events: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        options: OptionsContainer,
        module_id: str,
        session: Session | None = None,
        adapter: str = "",
        target: str = "",
        dry_run: bool = False,
    ) -> RunContext:
        """Create a RunContext with auto-generated run_id and timestamp."""
        return cls(
            options=options,
            session=session,
            adapter=adapter,
            run_id=make_run_id(module_id),
            started_at=now_iso(),
            logger=logging.getLogger(module_id or "blue_tap.module"),
            module_id=module_id,
            target=target,
            dry_run=dry_run,
        )

    def emit_event(
        self,
        event_type: str,
        message: str = "",
        *,
        execution_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit a CLI event with context fields pre-filled.

        Only the kwargs that ``emit_cli_event`` accepts are forwarded. Extra
        per-event data must be placed inside ``details``.
        """
        from blue_tap.framework.runtime.cli_events import emit_cli_event

        event = emit_cli_event(
            event_type=event_type,
            module=self.module_id,
            run_id=self.run_id,
            message=message or event_type,
            target=self.target,
            adapter=self.adapter,
            execution_id=execution_id,
            details=details or {},
        )
        self._events.append(event)

    def emit_run_started(self, details: dict[str, Any] | None = None) -> None:
        """Emit run_started event."""
        self.emit_event("run_started", f"Starting {self.module_id}", details=details)

    def emit_run_completed(self, details: dict[str, Any] | None = None) -> None:
        """Emit run_completed event."""
        self.emit_event("run_completed", f"Completed {self.module_id}", details=details)

    def emit_run_error(
        self,
        error: str | Exception,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit run_error event."""
        msg = str(error) if isinstance(error, Exception) else error
        self.emit_event("run_error", f"Error: {msg}", details=details)

    def emit_execution_started(
        self,
        execution_id: str,
        title: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit execution_started event for a sub-step."""
        self.emit_event(
            "execution_started",
            f"Starting: {title}",
            execution_id=execution_id,
            details=details,
        )

    def emit_execution_result(
        self,
        execution_id: str,
        status: str,
        outcome: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit execution_result event for a sub-step.

        ``status`` and ``outcome`` are packed into ``details`` so they survive
        alongside any caller-supplied details.
        """
        merged = dict(details or {})
        merged["execution_status"] = status
        if outcome is not None:
            merged["module_outcome"] = outcome
        self.emit_event(
            "execution_result",
            f"{execution_id}: {status}",
            execution_id=execution_id,
            details=merged,
        )

    def emit_execution_skipped(
        self,
        execution_id: str,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Emit execution_skipped event."""
        self.emit_event(
            "execution_skipped",
            f"Skipped: {reason}",
            execution_id=execution_id,
            details=details,
        )

    def save_artifact(
        self,
        filename: str,
        content: bytes | str,
        subdir: str = "",
        artifact_type: str = "raw",
    ) -> ArtifactRef | None:
        """Save an artifact to the session.

        Returns:
            ArtifactRef if saved successfully, None if no session.
        """
        if not self.session:
            self.logger.debug("No session, artifact not saved: %s", filename)
            return None

        data = content.encode("utf-8") if isinstance(content, str) else content

        ref = self.session.save_raw(
            filename=filename,
            data=data,
            subdir=subdir,
            artifact_type=artifact_type,
        )

        self.emit_event(
            "artifact_saved",
            f"Saved: {filename}",
            details={"artifact": str(ref), "filename": filename, "subdir": subdir},
        )
        return ref

    def get_events(self) -> list[dict[str, Any]]:
        """Return all events emitted during this run."""
        return self._events.copy()
