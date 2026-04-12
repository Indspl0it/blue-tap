"""Tests for blue_tap.core.cli_events canonical event taxonomy."""
from __future__ import annotations

import logging
import pathlib
import re

import pytest

from blue_tap.framework.runtime.cli_events import CANONICAL_EVENT_TYPES, emit_cli_event


_EXPECTED_CANONICAL = {
    "run_started",
    "phase_started",
    "execution_started",
    "execution_result",
    "execution_skipped",
    "pairing_required",
    "recovery_wait_started",
    "recovery_wait_progress",
    "recovery_wait_finished",
    "artifact_saved",
    "run_completed",
    "run_aborted",
    "run_error",
}


def test_canonical_event_types_is_frozenset():
    assert isinstance(CANONICAL_EVENT_TYPES, frozenset)


def test_canonical_event_types_has_expected_members():
    assert CANONICAL_EVENT_TYPES == _EXPECTED_CANONICAL


def test_emit_cli_event_canonical_no_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="blue_tap.framework.runtime.cli_events"):
        emit_cli_event(
            event_type="run_started",
            module="test",
            run_id="test-run-id",
            message="Run started",
            echo=False,
        )
    assert caplog.records == [], "Expected no warnings for canonical event type"


def test_emit_cli_event_non_canonical_logs_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="blue_tap.framework.runtime.cli_events"):
        result = emit_cli_event(
            event_type="execution_error",
            module="test",
            run_id="test-run-id",
            message="Something failed",
            echo=False,
        )
    assert any("execution_error" in r.message for r in caplog.records), (
        "Expected a warning mentioning the non-canonical event type"
    )
    # Execution is not blocked — the event is still returned
    assert result["event_type"] == "execution_error"


def test_emit_cli_event_non_canonical_mentions_module_in_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="blue_tap.framework.runtime.cli_events"):
        emit_cli_event(
            event_type="bad_type",
            module="mymodule",
            run_id="run-42",
            message="oops",
            echo=False,
        )
    assert any("mymodule" in r.message for r in caplog.records)


def test_emit_cli_event_returns_correct_fields():
    event = emit_cli_event(
        event_type="run_completed",
        module="vulnscan",
        run_id="abc-123",
        message="Done",
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        execution_id="exec-1",
        details={"count": 3},
        echo=False,
    )
    assert event["event_type"] == "run_completed"
    assert event["module"] == "vulnscan"
    assert event["run_id"] == "abc-123"
    assert event["target"] == "AA:BB:CC:DD:EE:FF"
    assert event["adapter"] == "hci0"
    assert event["execution_id"] == "exec-1"
    assert event["details"] == {"count": 3}
    assert event["message"] == "Done"
    assert "timestamp" in event


def test_all_emitted_events_are_canonical():
    root = pathlib.Path(__file__).resolve().parents[1] / "blue_tap"
    event_types: set[str] = set()

    patterns = (
        re.compile(r'event_type\s*=\s*"([a-z_]+)"'),
        re.compile(r'_emit\(\s*"([a-z_]+)"'),
    )

    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in patterns:
            event_types.update(pattern.findall(text))

    assert event_types, "Expected to discover at least one emitted event type"
    assert event_types <= CANONICAL_EVENT_TYPES
