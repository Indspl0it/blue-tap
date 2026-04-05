"""Shared protocol registry for fuzzing strategies.

Centralises the protocol -> generator mapping so that RandomWalkStrategy
and CoverageGuidedStrategy stay in sync.  Both import from here instead
of maintaining their own duplicate registries.

The registry is lazily built on first access to avoid circular imports
and to keep module load time near zero.
"""

from __future__ import annotations

import threading
from collections.abc import Callable


# ---------------------------------------------------------------------------
# Protocol registry
# ---------------------------------------------------------------------------

def _build_protocol_registry() -> dict[str, Callable[[], list]]:
    """Build the protocol -> generator mapping.

    Each value is a callable that returns ``list[bytes]`` (or
    ``list[bytes | list[bytes]]`` for OBEX).  Multi-packet sequences
    (list[bytes] items) are flattened by the strategy — each individual
    packet becomes a separate template.
    """
    from blue_tap.fuzz.protocols.sdp import generate_all_sdp_fuzz_cases
    from blue_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
    from blue_tap.fuzz.protocols.at_commands import ATCorpus
    from blue_tap.fuzz.protocols.att import generate_all_att_fuzz_cases
    from blue_tap.fuzz.protocols.smp import generate_all_smp_fuzz_cases
    from blue_tap.fuzz.protocols.bnep import generate_all_bnep_fuzz_cases
    from blue_tap.fuzz.protocols.rfcomm import generate_all_rfcomm_fuzz_cases
    from blue_tap.fuzz.protocols.l2cap import generate_all_l2cap_fuzz_cases
    from blue_tap.fuzz.protocols.lmp import generate_all_lmp_fuzz_cases

    def _lmp_bytes_only() -> list[bytes]:
        """Adapter: extract just the bytes from LMP (label, bytes) tuples."""
        return [payload for _label, payload in generate_all_lmp_fuzz_cases()]

    return {
        "sdp": generate_all_sdp_fuzz_cases,
        "obex-pbap": lambda: generate_all_obex_fuzz_cases(profile="pbap"),
        "obex-map": lambda: generate_all_obex_fuzz_cases(profile="map"),
        "obex-opp": lambda: generate_all_obex_fuzz_cases(profile="opp"),
        "at-hfp": ATCorpus.generate_hfp_slc_corpus,
        "at-phonebook": ATCorpus.generate_phonebook_corpus,
        "at-sms": ATCorpus.generate_sms_corpus,
        "at-injection": ATCorpus.generate_injection_corpus,
        "ble-att": generate_all_att_fuzz_cases,
        "ble-smp": generate_all_smp_fuzz_cases,
        "bnep": generate_all_bnep_fuzz_cases,
        "rfcomm": generate_all_rfcomm_fuzz_cases,
        "l2cap": generate_all_l2cap_fuzz_cases,
        "lmp": _lmp_bytes_only,
    }


# Thread-safe singleton.
_REGISTRY: dict[str, Callable[[], list]] | None = None
_REGISTRY_LOCK = threading.Lock()


def get_registry() -> dict[str, Callable[[], list]]:
    """Return the shared protocol registry (built once per process).

    Thread-safe: uses a lock on first build to prevent duplicate
    construction when multiple threads initialise concurrently.
    """
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    with _REGISTRY_LOCK:
        # Double-checked locking — another thread may have built it
        # while we waited for the lock.
        if _REGISTRY is None:
            _REGISTRY = _build_protocol_registry()
    return _REGISTRY


# Canonical set of all protocol names supported by the registry.
PROTOCOLS: frozenset[str] = frozenset({
    "sdp",
    "obex-pbap",
    "obex-map",
    "obex-opp",
    "at-hfp",
    "at-phonebook",
    "at-sms",
    "at-injection",
    "ble-att",
    "ble-smp",
    "bnep",
    "rfcomm",
    "l2cap",
    "lmp",
})
