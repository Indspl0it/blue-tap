"""Canonical output contracts — schema builders, report adapters."""

from blue_tap.framework.contracts.result_schema import (
    ArtifactRef,
    EvidenceRecord,
    make_run_id,
    now_iso,
    build_run_envelope,
    validate_run_envelope,
)
from blue_tap.framework.contracts.report_contract import (
    ReportAdapter,
    SectionModel,
    SectionBlock,
)

__all__ = [
    "ArtifactRef",
    "EvidenceRecord",
    "make_run_id",
    "now_iso",
    "build_run_envelope",
    "validate_run_envelope",
    "ReportAdapter",
    "SectionModel",
    "SectionBlock",
]
