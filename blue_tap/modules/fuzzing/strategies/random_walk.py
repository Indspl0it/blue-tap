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

from blue_tap.modules.fuzzing.corpus import Corpus
from blue_tap.modules.fuzzing.mutators import CorpusMutator
from blue_tap.modules.fuzzing.strategies._registry import get_registry, PROTOCOLS as _SHARED_PROTOCOLS
from blue_tap.modules.fuzzing.strategies.base import FuzzStrategy


# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------

# Probability of choosing template mode over corpus mode.
_TEMPLATE_WEIGHT = 0.70

# Maximum retries when generate() produces a duplicate.
_MAX_DEDUP_RETRIES = 8

# Maximum size of the _seen dedup set.  When exceeded, the set is cleared
# entirely.  This prevents unbounded memory growth during long campaigns.
# Re-generating a previously seen payload is acceptable — the set only
# prevents *immediate* duplicates within a window.
_MAX_SEEN = 500_000


class RandomWalkStrategy(FuzzStrategy):
    """Random protocol-aware mutation strategy.

    Alternates between:
    - Template mode (70%): Pick valid packet template, mutate 1-3 fields
    - Corpus mode (30%): Pick seed from corpus, apply byte-level havoc

    Weights mutations toward length/type/count fields for higher bug yield.

    No feedback loop — ``feedback()`` is intentionally the inherited no-op.
    Use :class:`~.coverage_guided.CoverageGuidedStrategy` for response-guided
    mutation.
    """

    # Expose the full protocol list so callers can iterate or validate.
    PROTOCOLS: frozenset[str] = _SHARED_PROTOCOLS

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
        if protocol not in get_registry():
            raise ValueError(
                f"Unknown protocol {protocol!r}. "
                f"Valid: {', '.join(sorted(self.PROTOCOLS))}"
            )

        last_mode_corpus = False
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
            last_mode_corpus = use_corpus

            # Reject empty bytes (mutation deleted all content) alongside duplicates.
            if data and self._is_novel(data):
                self._generated_total += 1
                if use_corpus:
                    self._generated_corpus += 1
                else:
                    self._generated_template += 1
                return data, log

            self._duplicates_skipped += 1

        # After retries, accept the last one even if it is a duplicate.
        # If mutation stripped all content, fall back to a minimal random blob
        # so the engine never sends an empty payload.
        self._generated_total += 1
        if last_mode_corpus:
            self._generated_corpus += 1
        else:
            self._generated_template += 1
        if not data:  # type: ignore[possibly-undefined]
            import os as _os
            data = _os.urandom(8)
            log = ["fallback(empty_mutation_output)"]
        return data, log

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
        if not mutated:
            mutated = template  # Guard: mutation deleted all bytes

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

        generator = get_registry().get(protocol)
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

        When the dedup set exceeds ``_MAX_SEEN``, it is cleared entirely
        to bound memory usage during long campaigns.
        """
        if len(self._seen) >= _MAX_SEEN:
            self._seen.clear()

        h = hashlib.sha256(data).hexdigest()[:16]
        if h in self._seen:
            return False
        self._seen.add(h)
        return True
