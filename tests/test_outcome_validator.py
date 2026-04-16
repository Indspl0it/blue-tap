"""Unit tests for the family-aware ``module_outcome`` validator.

The validator lives in ``blue_tap.framework.contracts.result_schema`` and
is wired into ``make_execution`` behind an optional ``module_id`` kwarg so
that:

* Module authors who pass ``module_id`` get loud failures at call time when
  they use an invalid outcome (e.g. ``"failed"`` or ``"skipped"`` inside an
  exploitation Module).
* Legacy call sites that omit ``module_id`` stay unvalidated and keep
  working exactly as before.
"""

from __future__ import annotations

import pytest

from blue_tap.framework.contracts.result_schema import (
    VALID_OUTCOMES_BY_FAMILY,
    make_evidence,
    make_execution,
    validate_module_outcome,
)


def _evidence() -> dict:
    return make_evidence(summary="unit test")


@pytest.mark.parametrize(
    "family,outcome",
    [
        ("discovery", "observed"),
        ("discovery", "not_applicable"),
        ("reconnaissance", "correlated"),
        ("assessment", "confirmed"),
        ("assessment", "pairing_required"),
        ("exploitation", "success"),
        ("exploitation", "unresponsive"),
        ("exploitation", "recovered"),
        ("exploitation", "aborted"),
        ("post_exploitation", "extracted"),
        ("post_exploitation", "streamed"),
        ("post_exploitation", "transferred"),
        ("fuzzing", "crash_found"),
        ("fuzzing", "no_findings"),
    ],
)
def test_validate_module_outcome_accepts_family_taxonomy(family, outcome):
    """The direct validator accepts every value in the published taxonomy."""
    validate_module_outcome(family, outcome)  # does not raise


@pytest.mark.parametrize(
    "family,bad_outcome",
    [
        ("exploitation", "failed"),
        ("exploitation", "skipped"),
        ("exploitation", "completed"),
        ("assessment", "success"),
        ("post_exploitation", "confirmed"),
        ("fuzzing", "observed"),
        ("discovery", "extracted"),
    ],
)
def test_validate_module_outcome_rejects_foreign_outcomes(family, bad_outcome):
    """Outcomes that belong to a different family must be rejected."""
    with pytest.raises(ValueError, match="module_outcome"):
        validate_module_outcome(family, bad_outcome)


def test_validate_module_outcome_unknown_family_is_noop():
    """Unknown families silently skip validation for backward compatibility."""
    validate_module_outcome("plugin_family_not_in_taxonomy", "whatever_value")


def test_make_execution_without_module_id_skips_validation():
    """Legacy callers that omit ``module_id`` must not see new errors."""
    execution = make_execution(
        kind="attack",
        id="legacy",
        title="Legacy call site",
        execution_status="completed",
        module_outcome="failed",  # would be invalid under exploitation taxonomy
        evidence=_evidence(),
    )
    assert execution["module_outcome"] == "failed"


def test_make_execution_valid_module_id_accepts_correct_outcome():
    execution = make_execution(
        kind="attack",
        id="bias",
        title="BIAS Attack",
        execution_status="completed",
        module_outcome="success",
        evidence=_evidence(),
        module_id="exploitation.bias",
    )
    assert execution["module_outcome"] == "success"


def test_make_execution_rejects_failed_for_exploitation():
    """Regression guard for the Phase 6 bug #1 outcome cleanup."""
    with pytest.raises(ValueError, match="exploitation"):
        make_execution(
            kind="attack",
            id="bias",
            title="BIAS Attack",
            execution_status="completed",
            module_outcome="failed",
            evidence=_evidence(),
            module_id="exploitation.bias",
        )


def test_make_execution_rejects_skipped_for_exploitation():
    """Regression guard for the Phase 6 bug #2 BLUFFS A2/A4 variant cleanup."""
    with pytest.raises(ValueError, match="exploitation"):
        make_execution(
            kind="attack",
            id="bluffs_a2",
            title="BLUFFS A2",
            execution_status="skipped",
            module_outcome="skipped",
            evidence=_evidence(),
            module_id="exploitation.bluffs",
        )


def test_make_execution_rejects_post_exploitation_extracted_for_discovery():
    with pytest.raises(ValueError, match="discovery"):
        make_execution(
            kind="collector",
            id="scanner",
            title="Scanner",
            execution_status="completed",
            module_outcome="extracted",
            evidence=_evidence(),
            module_id="discovery.scanner",
        )


def test_taxonomy_constants_are_immutable_sets():
    """``VALID_OUTCOMES_BY_FAMILY`` must be frozen so modules cannot mutate it."""
    for family, outcomes in VALID_OUTCOMES_BY_FAMILY.items():
        assert isinstance(outcomes, frozenset), f"{family} outcomes should be frozen"
