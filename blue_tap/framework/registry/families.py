"""Module family constants and outcome registries."""

from enum import Enum


class ModuleFamily(str, Enum):
    DISCOVERY = "discovery"
    RECONNAISSANCE = "reconnaissance"
    ASSESSMENT = "assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    FUZZING = "fuzzing"


FAMILY_OUTCOMES: dict[ModuleFamily, tuple[str, ...]] = {
    ModuleFamily.DISCOVERY: ("observed", "merged", "correlated", "partial", "not_applicable"),
    ModuleFamily.RECONNAISSANCE: ("observed", "merged", "correlated", "partial", "not_applicable"),
    ModuleFamily.ASSESSMENT: ("confirmed", "inconclusive", "pairing_required", "not_applicable"),
    ModuleFamily.EXPLOITATION: ("success", "unresponsive", "recovered", "not_applicable", "aborted"),
    ModuleFamily.POST_EXPLOITATION: ("extracted", "connected", "streamed", "transferred", "not_applicable"),
    ModuleFamily.FUZZING: ("crash_found", "timeout", "corpus_grown", "no_findings"),
}
