"""Response-diversity guided fuzzing strategy.

Uses response fingerprinting as a proxy for code coverage — when a mutated
input produces a NOVEL response (different error code, different length,
different content pattern), it likely reached a new code path.  That input
is saved as "interesting" and prioritised for further mutation.

This is inspired by AFL/libFuzzer coverage guidance, adapted for black-box
Bluetooth fuzzing where we cannot instrument the target.

Key concepts:

  Fingerprinting
      Hash of ``(len(response), response[:fingerprint_size])``.  Different
      error codes, different response sizes, or different leading content
      bytes all map to different fingerprints.

  Energy scheduling
      New interesting inputs receive 50 "energy" points.  Each time we
      mutate them, energy decreases.  High-energy inputs get fewer
      mutations (precise exploration nearby); low-energy inputs get more
      mutations (explore further away).

  Exploration / exploitation balance
      80% of the time, mutate an "interesting" input (exploitation).
      20% of the time, mutate a random template/seed (exploration).
      Both ratios are configurable.

  Per-protocol tracking
      Interesting inputs and fingerprints are tracked per-protocol, since
      different protocols have different response patterns.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from bt_tap.fuzz.corpus import Corpus
from bt_tap.fuzz.mutators import CorpusMutator
from bt_tap.fuzz.strategies._registry import get_registry, PROTOCOLS as _SHARED_PROTOCOLS


# ---------------------------------------------------------------------------
# Default constants
# ---------------------------------------------------------------------------

# Probability of choosing an interesting input over random exploration.
_DEFAULT_INTERESTING_PRIORITY = 0.80

# Default fingerprint size — number of leading response bytes to hash.
_DEFAULT_FINGERPRINT_SIZE = 32

# Initial energy assigned to a newly discovered interesting input.
_INITIAL_ENERGY = 50

# Energy assigned to a crash-producing input (maximum priority).
_CRASH_ENERGY = 100

# Maximum dedup retries per generate() call.
_MAX_DEDUP_RETRIES = 8

# Maximum interesting inputs per protocol.  When exceeded, the lowest-energy
# inputs are evicted to bound memory usage during long campaigns.
_MAX_INTERESTING_PER_PROTOCOL = 500


# ---------------------------------------------------------------------------
# CoverageStats
# ---------------------------------------------------------------------------

@dataclass
class CoverageStats:
    """Tracks statistics for the coverage-guided strategy."""

    total_generated: int = 0
    total_feedback: int = 0
    novel_responses: int = 0
    interesting_inputs: int = 0
    fingerprints_seen: int = 0
    crashes_seen: int = 0
    exploration_rounds: int = 0   # Times we picked random instead of interesting
    exploitation_rounds: int = 0  # Times we picked an interesting input


# ---------------------------------------------------------------------------
# CoverageGuidedStrategy
# ---------------------------------------------------------------------------

class CoverageGuidedStrategy:
    """Response-diversity guided fuzzing strategy.

    Uses response fingerprinting as a proxy for code coverage:

    - Track unique response "fingerprints" (hash of response length +
      first N bytes of content).
    - When a mutation produces a NOVEL fingerprint, save the input as
      "interesting" and assign it energy for future mutations.
    - Prioritise mutating interesting inputs (80%) over random seeds (20%).
    - Over time, the corpus evolves toward inputs that reach diverse
      code paths on the target.

    The strategy works even when no interesting inputs exist yet — it
    falls back to random template selection from protocol builders.
    """

    # Expose the full protocol list so callers can iterate or validate.
    PROTOCOLS: frozenset[str] = _SHARED_PROTOCOLS

    def __init__(
        self,
        corpus: Corpus | None = None,
        fingerprint_size: int = _DEFAULT_FINGERPRINT_SIZE,
        interesting_priority: float = _DEFAULT_INTERESTING_PRIORITY,
    ) -> None:
        self.corpus = corpus
        self.fingerprint_size = fingerprint_size
        self.interesting_priority = interesting_priority

        # Response fingerprint tracking — global set across all protocols
        self._fingerprints: set[str] = set()

        # Per-protocol interesting input pools
        self._interesting_inputs: dict[str, list[bytes]] = {}

        # Energy scheduling: input_hash -> remaining energy
        self._energy: dict[str, int] = {}

        # Deduplication of generated payloads
        self._seen: set[str] = set()

        # Template cache (same pattern as RandomWalkStrategy)
        self._template_cache: dict[str, list[bytes]] = {}

        # Statistics
        self._stats = CoverageStats()

    # ------------------------------------------------------------------
    # Public API — generation
    # ------------------------------------------------------------------

    def generate(self, protocol: str) -> tuple[bytes, list[str]]:
        """Generate one fuzz case for the given protocol.

        Returns ``(fuzz_bytes, mutation_log_strings)``.

        80% chance: mutate an "interesting" input (if any exist for
        this protocol).  20% chance: mutate a random template/seed
        (exploration).

        Raises ``ValueError`` if *protocol* is not in :attr:`PROTOCOLS`.
        """
        if protocol not in get_registry():
            raise ValueError(
                f"Unknown protocol {protocol!r}. "
                f"Valid: {', '.join(sorted(self.PROTOCOLS))}"
            )

        for _ in range(_MAX_DEDUP_RETRIES):
            data, log = self._generate_one(protocol)
            if self._is_novel(data):
                self._stats.total_generated += 1
                return data, log

        # Guarantee forward progress — accept even if duplicate.
        self._stats.total_generated += 1
        return data, log  # type: ignore[possibly-undefined]

    # ------------------------------------------------------------------
    # Public API — feedback
    # ------------------------------------------------------------------

    def feedback(
        self,
        protocol: str,
        input_bytes: bytes,
        response: bytes | None,
        crash: bool = False,
    ) -> bool:
        """Process response feedback from the campaign engine.

        Called after every fuzz case with the response (or ``None`` for
        timeout).

        Returns ``True`` if the input was deemed "interesting" (novel
        response fingerprint or crash).

        Fingerprinting logic:
        - ``None`` response -> ``"timeout"`` fingerprint
        - Empty response -> ``"empty"`` fingerprint
        - Non-empty -> hash of ``(len(response), response[:fingerprint_size])``
        - Crash -> always interesting, separate ``"crash:<hash>"`` fingerprint
        """
        self._stats.total_feedback += 1

        fp = self._fingerprint(response, crash=crash)
        is_novel = fp not in self._fingerprints

        if crash:
            self._stats.crashes_seen += 1
            # Crashes are ALWAYS interesting, even if fingerprint was seen.
            is_novel = True

        if is_novel:
            self._fingerprints.add(fp)
            self._stats.fingerprints_seen = len(self._fingerprints)
            self._stats.novel_responses += 1

            # Save as interesting input for this protocol.
            pool = self._interesting_inputs.setdefault(protocol, [])
            pool.append(input_bytes)
            self._stats.interesting_inputs += 1

            # Assign energy — crashes get maximum energy.
            input_hash = self._input_hash(input_bytes)
            self._energy[input_hash] = _CRASH_ENERGY if crash else _INITIAL_ENERGY

            # Evict lowest-energy inputs when the pool exceeds the cap.
            if len(pool) > _MAX_INTERESTING_PER_PROTOCOL:
                self._evict_lowest_energy(pool)

            # Persist to corpus if available.
            if self.corpus is not None:
                reason = "crash" if crash else f"novel_fp_{fp[:8]}"
                self.corpus.save_interesting(protocol, input_bytes, reason)

        return is_novel

    # ------------------------------------------------------------------
    # Public API — introspection
    # ------------------------------------------------------------------

    def get_interesting_inputs(self, protocol: str | None = None) -> list[bytes]:
        """Return all interesting inputs, optionally filtered by protocol."""
        if protocol is not None:
            return list(self._interesting_inputs.get(protocol, []))
        result: list[bytes] = []
        for pool in self._interesting_inputs.values():
            result.extend(pool)
        return result

    def stats(self) -> dict:
        """Return strategy statistics as a JSON-serialisable dict."""
        return {
            "total_generated": self._stats.total_generated,
            "total_feedback": self._stats.total_feedback,
            "novel_responses": self._stats.novel_responses,
            "interesting_inputs": self._stats.interesting_inputs,
            "fingerprints_seen": self._stats.fingerprints_seen,
            "crashes_seen": self._stats.crashes_seen,
            "exploration_rounds": self._stats.exploration_rounds,
            "exploitation_rounds": self._stats.exploitation_rounds,
            "unique_payloads": len(self._seen),
            "interesting_by_protocol": {
                proto: len(inputs)
                for proto, inputs in self._interesting_inputs.items()
            },
            "cached_protocols": list(self._template_cache.keys()),
        }

    # ------------------------------------------------------------------
    # Internal — generation dispatcher
    # ------------------------------------------------------------------

    def _generate_one(self, protocol: str) -> tuple[bytes, list[str]]:
        """Decide between exploitation and exploration, then generate."""
        interesting_pool = self._interesting_inputs.get(protocol, [])

        use_interesting = (
            len(interesting_pool) > 0
            and random.random() < self.interesting_priority
        )

        if use_interesting:
            self._stats.exploitation_rounds += 1
            input_bytes, source = self._select_input(protocol)
            data, mutations = self._mutate_input(input_bytes)
            log = [f"coverage_exploit({source}) -> mutate -> {len(data)}B"]
            log.extend(mutations)
            return data, log
        else:
            self._stats.exploration_rounds += 1
            return self._generate_exploration(protocol)

    # ------------------------------------------------------------------
    # Internal — input selection with energy scheduling
    # ------------------------------------------------------------------

    def _select_input(self, protocol: str) -> tuple[bytes, str]:
        """Select an input to mutate from the interesting pool.

        Returns ``(input_bytes, source_description)``.

        Energy scheduling:
        - Prefer inputs with remaining energy.
        - New interesting inputs get high energy (50 mutations).
        - As energy depletes, reduce mutations per round.
        - When energy hits 0, the input remains in the pool but is
          selected with lower probability (uniform random fallback).
        """
        pool = self._interesting_inputs.get(protocol, [])
        if not pool:
            # Should not happen — caller checks — but be safe.
            return self._fallback_input(protocol)

        # Build a weighted selection: inputs with energy get priority.
        energised: list[tuple[bytes, int]] = []
        for inp in pool:
            h = self._input_hash(inp)
            energy = self._energy.get(h, 0)
            if energy > 0:
                energised.append((inp, energy))

        if energised:
            # Weighted random by energy level.
            total_energy = sum(e for _, e in energised)
            r = random.random() * total_energy
            cumulative = 0
            for inp, energy in energised:
                cumulative += energy
                if r <= cumulative:
                    # Decrement energy; remove entry when it hits 0.
                    h = self._input_hash(inp)
                    new_energy = max(0, energy - 1)
                    if new_energy == 0:
                        self._energy.pop(h, None)
                    else:
                        self._energy[h] = new_energy
                    return inp, f"interesting({protocol}, energy={new_energy})"
            # Fallthrough: pick last.
            inp, energy = energised[-1]
            h = self._input_hash(inp)
            new_energy = max(0, energy - 1)
            if new_energy == 0:
                self._energy.pop(h, None)
            else:
                self._energy[h] = new_energy
            return inp, f"interesting({protocol}, energy={new_energy})"

        # No energised inputs — uniform random from pool.
        inp = random.choice(pool)
        return inp, f"interesting({protocol}, energy=0)"

    def _fallback_input(self, protocol: str) -> tuple[bytes, str]:
        """Fallback when no interesting inputs exist for a protocol."""
        templates = self._get_templates(protocol)
        if templates:
            t = random.choice(templates)
            return t, f"template_fallback({protocol})"
        return b"\x00" * 8, "zero_fallback"

    # ------------------------------------------------------------------
    # Internal — mutation with energy-based intensity
    # ------------------------------------------------------------------

    def _mutate_input(self, data: bytes) -> tuple[bytes, list[str]]:
        """Apply mutations to selected input.

        Varies mutation intensity based on the input's energy:
        - High energy (>30): 1 mutation (precise exploration near
          the interesting input).
        - Medium energy (10-30): 1-2 mutations.
        - Low energy (<10): 2-4 mutations (explore further from
          the original).
        """
        h = self._input_hash(data)
        energy = self._energy.get(h, 0)

        if energy > 30:
            num_mutations = 1
        elif energy > 10:
            num_mutations = random.randint(1, 2)
        else:
            num_mutations = random.randint(2, 4)

        mutated = CorpusMutator.mutate(data, num_mutations=num_mutations)
        log = [
            f"mutate(energy={energy}, n={num_mutations}, "
            f"{len(data)}B -> {len(mutated)}B)"
        ]
        return mutated, log

    # ------------------------------------------------------------------
    # Internal — exploration (random template/corpus)
    # ------------------------------------------------------------------

    def _generate_exploration(self, protocol: str) -> tuple[bytes, list[str]]:
        """Generate via random template or corpus seed (exploration mode)."""
        # Try corpus first (30% when available).
        use_corpus = (
            self.corpus is not None
            and self.corpus.seed_count(protocol) > 0
            and random.random() < 0.30
        )

        if use_corpus:
            assert self.corpus is not None
            seed = self.corpus.get_random_seed(protocol)
            if seed is not None:
                num_mutations = random.randint(1, 3)
                mutated = CorpusMutator.mutate(seed, num_mutations=num_mutations)
                log = [
                    f"coverage_explore_corpus({protocol}, {len(seed)}B) "
                    f"-> mutate x{num_mutations} -> {len(mutated)}B"
                ]
                return mutated, log

        # Template mode.
        templates = self._get_templates(protocol)
        if not templates:
            return CorpusMutator.mutate(b"\x00" * 8, num_mutations=2), [
                "fallback(no_templates)"
            ]

        template = random.choice(templates)
        num_mutations = random.randint(1, 3)
        mutated = CorpusMutator.mutate(template, num_mutations=num_mutations)
        log = [
            f"coverage_explore_template({protocol}, {len(template)}B) "
            f"-> mutate x{num_mutations} -> {len(mutated)}B"
        ]
        return mutated, log

    # ------------------------------------------------------------------
    # Internal — fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint(self, response: bytes | None, crash: bool = False) -> str:
        """Compute response fingerprint.

        - ``None`` response -> ``"timeout"``
        - Empty response -> ``"empty"``
        - Non-empty -> SHA-256 of ``(len, first N bytes)``
        - Crash -> ``"crash:<content_hash>"`` (always unique per content)
        """
        if crash:
            content = response if response else b""
            h = hashlib.sha256(content).hexdigest()[:16]
            return f"crash:{h}"

        if response is None:
            return "timeout"

        if len(response) == 0:
            return "empty"

        # Hash the length + leading bytes for a compact fingerprint.
        prefix = response[: self.fingerprint_size]
        to_hash = len(response).to_bytes(4, "big") + prefix
        return hashlib.sha256(to_hash).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Internal — template cache
    # ------------------------------------------------------------------

    def _get_templates(self, protocol: str) -> list[bytes]:
        """Get or cache the built-in fuzz cases for a protocol.

        Multi-packet sequences are flattened so each individual packet
        is a separate template (same logic as RandomWalkStrategy).
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
                if item:
                    templates.append(item)
            elif isinstance(item, list):
                for sub in item:
                    if isinstance(sub, bytes) and sub:
                        templates.append(sub)

        self._template_cache[protocol] = templates
        return templates

    # ------------------------------------------------------------------
    # Internal — pool management
    # ------------------------------------------------------------------

    def _evict_lowest_energy(self, pool: list[bytes]) -> None:
        """Evict the lowest-energy inputs from *pool* to stay within cap.

        Sorts inputs by energy (ascending), removes the bottom half,
        and cleans up their energy dict entries.
        """
        # Sort by energy ascending — evict the least valuable.
        pool.sort(key=lambda inp: self._energy.get(self._input_hash(inp), 0))
        evict_count = len(pool) - _MAX_INTERESTING_PER_PROTOCOL
        evicted = pool[:evict_count]
        del pool[:evict_count]
        # Clean up energy entries for evicted inputs.
        for inp in evicted:
            self._energy.pop(self._input_hash(inp), None)

    # ------------------------------------------------------------------
    # Internal — hashing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _input_hash(data: bytes) -> str:
        """Compute a short hash for an input (used as energy dict key)."""
        return hashlib.sha256(data).hexdigest()[:16]

    def _is_novel(self, data: bytes) -> bool:
        """Check if this exact payload has been generated before.

        Uses truncated SHA-256 (64 bits) — collision probability is
        negligible at campaign scale.
        """
        h = hashlib.sha256(data).hexdigest()[:16]
        if h in self._seen:
            return False
        self._seen.add(h)
        return True
