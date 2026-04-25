"""Module family constants and outcome registries."""

from enum import Enum


class ModuleFamily(str, Enum):
    DISCOVERY = "discovery"
    RECONNAISSANCE = "reconnaissance"
    ASSESSMENT = "assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    FUZZING = "fuzzing"
    HARDWARE = "hardware"


FAMILY_OUTCOMES: dict[ModuleFamily, frozenset[str]] = {
    ModuleFamily.DISCOVERY: frozenset({
        "observed", "merged", "correlated", "partial", "not_applicable",
    }),
    ModuleFamily.RECONNAISSANCE: frozenset({
        "observed", "merged", "correlated", "partial", "not_applicable",
        "unsupported_transport", "collector_unavailable", "prerequisite_missing",
        "artifact_collected",
        "hidden_surface_detected",
        "no_relevant_traffic",
        "undetermined",
        "partial_observation",
        "auth_required",
        "not_found",
        "not_connectable",
        "timeout",
        "no_results",
    }),
    ModuleFamily.ASSESSMENT: frozenset({
        "confirmed", "inconclusive", "pairing_required", "not_applicable",
        "not_detected",
    }),
    ModuleFamily.EXPLOITATION: frozenset({
        "success", "unresponsive", "recovered", "not_applicable", "aborted",
        "confirmed",
    }),
    ModuleFamily.POST_EXPLOITATION: frozenset({
        "extracted", "connected", "streamed", "transferred", "not_applicable",
        "partial",
        "completed", "failed", "aborted",
    }),
    ModuleFamily.FUZZING: frozenset({
        "crash_found", "timeout", "corpus_grown", "no_findings",
        "completed", "crash_detected", "degraded", "aborted",
        "pairing_required", "not_applicable",
        "reproduced",
    }),
    ModuleFamily.HARDWARE: frozenset({
        "completed",
        "installed",
        "hooks_active",
        "hooks_partial",
        "not_loaded",
        "prerequisite_missing",
        "spoofed",
        "rejected",
        "restored",
        "method_unavailable",
        "not_applicable",
    }),
}
