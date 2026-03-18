"""Random Walk fuzzing strategy — the default mutation mode.

Alternates between template-based (protocol-aware) and corpus-based
(byte-level havoc) mutation to maximise coverage across Bluetooth
protocol attack surface.

Template mode (70%):
    Pick a valid packet from a protocol's built-in fuzz case generator,
    apply 1-3 byte-level mutations via CorpusMutator.

Corpus mode (30%):
    Pick a random seed from the Corpus, apply 1-3 byte-level mutations.

Deduplication is SHA-256 based — the same exact payload is never
returned twice from generate().
"""

from __future__ import annotations

import hashlib
import random
from typing import Callable

from bt_tap.fuzz.corpus import Corpus
from bt_tap.fuzz.mutators import CorpusMutator


# ---------------------------------------------------------------------------
# Protocol registry — maps protocol names to their fuzz case generators.
# Lazy-imported at first access to avoid circular imports and to keep
# module load time near zero.
# ---------------------------------------------------------------------------

def _get_protocol_registry() -> dict[str, Callable[[], list]]:
    """Build the protocol -> generator mapping on first call.

    Each value is a callable that returns ``list[bytes]`` (or
    ``list[bytes | list[bytes]]`` for OBEX).  Multi-packet sequences
    (list[bytes] items) are flattened — each individual packet becomes
    a separate template.
    """
    from bt_tap.fuzz.protocols.sdp import generate_all_sdp_fuzz_cases
    from bt_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
    from bt_tap.fuzz.protocols.at_commands import ATCorpus
    from bt_tap.fuzz.protocols.att import generate_all_att_fuzz_cases
    from bt_tap.fuzz.protocols.smp import generate_all_smp_fuzz_cases
    from bt_tap.fuzz.protocols.bnep import generate_all_bnep_fuzz_cases
    from bt_tap.fuzz.protocols.rfcomm import generate_all_rfcomm_fuzz_cases

    return {
        "sdp": generate_all_sdp_fuzz_cases,
        "obex-pbap": lambda: generate_all_obex_fuzz_cases(profile="pbap"),
        "obex-map": lambda: generate_all_obex_fuzz_cases(profile="map"),
        "obex-opp": lambda: generate_all_obex_fuzz_cases(profile="opp"),
        "at-hfp": ATCorpus.generate_hfp_slc_corpus,
        "at-phonebook": ATCorpus.generate_phonebook_corpus,
        "at-sms": ATCorpus.generate_sms_corpus,
        "ble-att": generate_all_att_fuzz_cases,
        "ble-smp": generate_all_smp_fuzz_cases,
        "bnep": generate_all_bnep_fuzz_cases,
        "rfcomm": generate_all_rfcomm_fuzz_cases,
    }


# Singleton — built once per process.
_REGISTRY: dict[str, Callable[[], list]] | None = None


def _registry() -> dict[str, Callable[[], list]]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _get_protocol_registry()
    return _REGISTRY


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------

# Probability of choosing template mode over corpus mode.
_TEMPLATE_WEIGHT = 0.70

# Maximum retries when generate() produces a duplicate.
_MAX_DEDUP_RETRIES = 8


class RandomWalkStrategy:
    """Random protocol-aware mutation strategy.

    Alternates between:
    - Template mode (70%): Pick valid packet template, mutate 1-3 fields
    - Corpus mode (30%): Pick seed from corpus, apply byte-level havoc

    Weights mutations toward length/type/count fields for higher bug yield.
    """

    # Expose the full protocol list so callers can iterate or validate.
    PROTOCOLS: frozenset[str] = frozenset({
        "sdp",
        "obex-pbap",
        "obex-map",
        "obex-opp",
        "at-hfp",
        "at-phonebook",
        "at-sms",
        "ble-att",
        "ble-smp",
        "bnep",
        "rfcomm",
    })

    def __init__(self, corpus: Corpus | None = None) -> None:
        self.corpus = corpus
        self.mutator = CorpusMutator()
        self._seen: set[str] = set()  # SHA-256 hex digests
        self._template_cache: dict[str, list[bytes]] = {}
        # Counters for stats().
        self._generated_total: int = 0
        self._generated_template: int = 0
        self._generated_corpus: int = 0
        self._duplicates_skipped: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, protocol: str) -> tuple[bytes, list[str]]:
        """Generate one fuzz case for the given protocol.

        Returns ``(fuzz_bytes, mutation_log_strings)``.

        Raises ``ValueError`` if *protocol* is not in :attr:`PROTOCOLS`.
        """
        if protocol not in _registry():
            raise ValueError(
                f"Unknown protocol {protocol!r}. "
                f"Valid: {', '.join(sorted(self.PROTOCOLS))}"
            )

        for _ in range(_MAX_DEDUP_RETRIES):
            use_corpus = (
                self.corpus is not None
                and self.corpus.seed_count(protocol) > 0
                and random.random() >= _TEMPLATE_WEIGHT
            )

            if use_corpus:
                data, log = self._generate_from_corpus(protocol)
            else:
                data, log = self._generate_from_template(protocol)

            if self._is_novel(data):
                self._generated_total += 1
                if use_corpus:
                    self._generated_corpus += 1
                else:
                    self._generated_template += 1
                return data, log

            self._duplicates_skipped += 1

        # After retries, accept the last one even if it is a duplicate
        # to guarantee forward progress.
        self._generated_total += 1
        self._generated_template += 1
        return data, log  # type: ignore[possibly-undefined]

    def stats(self) -> dict:
        """Return generation statistics."""
        return {
            "generated_total": self._generated_total,
            "generated_template": self._generated_template,
            "generated_corpus": self._generated_corpus,
            "duplicates_skipped": self._duplicates_skipped,
            "unique_payloads": len(self._seen),
            "cached_protocols": list(self._template_cache.keys()),
        }

    # ------------------------------------------------------------------
    # Internal — template mode
    # ------------------------------------------------------------------

    def _generate_from_template(self, protocol: str) -> tuple[bytes, list[str]]:
        """Pick a valid template, apply byte-level mutations."""
        templates = self._get_templates(protocol)
        if not templates:
            # Fallback: return a small random blob.
            return CorpusMutator.mutate(b"\x00" * 8, num_mutations=2), [
                "fallback(no_templates)"
            ]

        template = random.choice(templates)
        num_mutations = random.randint(1, 3)
        mutated = CorpusMutator.mutate(template, num_mutations=num_mutations)

        log = [
            f"template({protocol}, {len(template)}B) "
            f"-> mutate x{num_mutations} -> {len(mutated)}B"
        ]
        return mutated, log

    # ------------------------------------------------------------------
    # Internal — corpus mode
    # ------------------------------------------------------------------

    def _generate_from_corpus(self, protocol: str) -> tuple[bytes, list[str]]:
        """Pick a corpus seed, apply byte-level mutations."""
        assert self.corpus is not None
        seed = self.corpus.get_random_seed(protocol)
        if seed is None:
            return self._generate_from_template(protocol)

        num_mutations = random.randint(1, 3)
        mutated = CorpusMutator.mutate(seed, num_mutations=num_mutations)

        log = [
            f"corpus({protocol}, {len(seed)}B) "
            f"-> mutate x{num_mutations} -> {len(mutated)}B"
        ]
        return mutated, log

    # ------------------------------------------------------------------
    # Internal — template cache
    # ------------------------------------------------------------------

    def _get_templates(self, protocol: str) -> list[bytes]:
        """Get or cache the built-in fuzz cases for a protocol.

        Multi-packet sequences (returned by OBEX generators as
        ``list[bytes]`` items) are flattened so each individual packet
        is a separate template.
        """
        cached = self._template_cache.get(protocol)
        if cached is not None:
            return cached

        generator = _registry().get(protocol)
        if generator is None:
            self._template_cache[protocol] = []
            return []

        raw = generator()
        templates: list[bytes] = []
        for item in raw:
            if isinstance(item, bytes):
                if item:  # skip empty
                    templates.append(item)
            elif isinstance(item, list):
                # Multi-packet sequence — flatten.
                for sub in item:
                    if isinstance(sub, bytes) and sub:
                        templates.append(sub)

        self._template_cache[protocol] = templates
        return templates

    # ------------------------------------------------------------------
    # Internal — dedup
    # ------------------------------------------------------------------

    def _is_novel(self, data: bytes) -> bool:
        """Check if this exact payload has been generated before.

        Uses SHA-256 truncated to 16 hex chars (64 bits) for the hash
        set — collision probability is negligible at campaign scale
        (<10M cases) and saves memory vs full 64-char digests.
        """
        h = hashlib.sha256(data).hexdigest()[:16]
        if h in self._seen:
            return False
        self._seen.add(h)
        return True
