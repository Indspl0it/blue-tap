"""Unit tests for the family-aware ``module_outcome`` validator.

Validation is strict: every call site must pass a ``module_id``, the family
must match a :class:`ModuleFamily` enum value, and ``module_outcome`` must
be in the canonical :data:`FAMILY_OUTCOMES` set for that family.
"""

from __future__ import annotations

import pytest

from blue_tap.framework.contracts.result_schema import (
    make_evidence,
    make_execution,
    validate_module_outcome,
)
from blue_tap.framework.registry.families import FAMILY_OUTCOMES, ModuleFamily


def _evidence() -> dict:
    return make_evidence(summary="unit test")


@pytest.mark.parametrize(
    "family,outcome",
    [
        ("discovery", "observed"),
        ("discovery", "not_applicable"),
        ("reconnaissance", "correlated"),
        ("assessment", "confirmed"),
        ("assessment", "not_detected"),
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


def test_validate_module_outcome_unknown_family_raises():
    """Unknown families now raise — strict validation, no silent no-op."""
    with pytest.raises(ValueError, match="unknown module family"):
        validate_module_outcome("plugin_family_not_in_taxonomy", "whatever_value")


def test_make_execution_requires_module_id():
    """``module_id`` is a required keyword argument; omitting it must raise."""
    with pytest.raises(TypeError):
        make_execution(  # type: ignore[call-arg]
            kind="attack",
            id="legacy",
            title="Legacy call site",
            execution_status="completed",
            module_outcome="success",
            evidence=_evidence(),
        )


def test_make_execution_rejects_malformed_module_id():
    """``module_id`` must match ``family.name`` (lowercase, dotted)."""
    with pytest.raises(ValueError, match="module_id"):
        make_execution(
            kind="attack",
            id="bias",
            title="BIAS",
            execution_status="completed",
            module_outcome="success",
            evidence=_evidence(),
            module_id="bias",  # missing family prefix
        )


def test_make_execution_rejects_unknown_family_in_module_id():
    """A module_id whose family isn't a ``ModuleFamily`` enum value must raise."""
    with pytest.raises(ValueError, match="unknown module family"):
        make_execution(
            kind="attack",
            id="bias",
            title="BIAS",
            execution_status="completed",
            module_outcome="success",
            evidence=_evidence(),
            module_id="madeup.bias",
        )


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
    """``FAMILY_OUTCOMES`` must be frozen so modules cannot mutate it."""
    for family, outcomes in FAMILY_OUTCOMES.items():
        assert isinstance(family, ModuleFamily), f"{family} should be a ModuleFamily enum value"
        assert isinstance(outcomes, frozenset), f"{family} outcomes should be frozen"
