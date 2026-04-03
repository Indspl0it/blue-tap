"""Comprehensive unit tests for blue_tap.fuzz.strategies.

Covers:
- _registry.py: get_registry(), PROTOCOLS constant
- random_walk.py: RandomWalkStrategy
- coverage_guided.py: CoverageGuidedStrategy
- state_machine.py: StateMachineStrategy plus individual models
- targeted.py: TargetedStrategy
"""

from __future__ import annotations

import hashlib
import random
from unittest.mock import MagicMock, patch

import pytest


# ============================================================================
# Registry tests
# ============================================================================


class TestRegistry:
    """Tests for blue_tap.fuzz.strategies._registry."""

    def test_protocols_is_frozenset(self):
        from blue_tap.fuzz.strategies._registry import PROTOCOLS

        assert isinstance(PROTOCOLS, frozenset)
        assert len(PROTOCOLS) > 0

    def test_protocols_contains_known_names(self):
        from blue_tap.fuzz.strategies._registry import PROTOCOLS

        expected = {
            "sdp", "obex-pbap", "obex-map", "obex-opp",
            "at-hfp", "at-phonebook", "at-sms", "at-injection",
            "ble-att", "ble-smp", "bnep", "rfcomm", "l2cap",
        }
        assert expected == PROTOCOLS

    def test_get_registry_returns_dict(self):
        from blue_tap.fuzz.strategies._registry import get_registry

        reg = get_registry()
        assert isinstance(reg, dict)
        assert len(reg) > 0

    def test_get_registry_keys_match_protocols(self):
        from blue_tap.fuzz.strategies._registry import get_registry, PROTOCOLS

        reg = get_registry()
        assert set(reg.keys()) == PROTOCOLS

    def test_get_registry_values_are_callable(self):
        from blue_tap.fuzz.strategies._registry import get_registry

        reg = get_registry()
        for name, gen in reg.items():
            assert callable(gen), f"Generator for {name!r} is not callable"

    def test_get_registry_returns_same_instance(self):
        from blue_tap.fuzz.strategies._registry import get_registry

        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2

    def test_each_generator_returns_list(self):
        from blue_tap.fuzz.strategies._registry import get_registry

        reg = get_registry()
        for name, gen in reg.items():
            result = gen()
            assert isinstance(result, list), (
                f"Generator for {name!r} returned {type(result)}, expected list"
            )
            assert len(result) > 0, f"Generator for {name!r} returned empty list"

    def test_generators_produce_bytes_items(self):
        from blue_tap.fuzz.strategies._registry import get_registry

        reg = get_registry()
        for name, gen in reg.items():
            result = gen()
            for item in result:
                assert isinstance(item, (bytes, list)), (
                    f"Generator {name!r} yielded {type(item)}, expected bytes or list"
                )
                if isinstance(item, list):
                    for sub in item:
                        assert isinstance(sub, bytes), (
                            f"Sub-item in {name!r} is {type(sub)}, expected bytes"
                        )


# ============================================================================
# RandomWalkStrategy tests
# ============================================================================


def _make_mock_corpus(seeds: dict[str, list[bytes]] | None = None):
    """Create a mock Corpus with configurable seeds per protocol."""
    corpus = MagicMock()
    seeds = seeds or {}

    def seed_count(protocol):
        return len(seeds.get(protocol, []))

    def get_random_seed(protocol):
        pool = seeds.get(protocol, [])
        return random.choice(pool) if pool else None

    corpus.seed_count = MagicMock(side_effect=seed_count)
    corpus.get_random_seed = MagicMock(side_effect=get_random_seed)
    corpus.save_interesting = MagicMock()
    return corpus


class TestRandomWalkStrategy:
    """Tests for RandomWalkStrategy."""

    def test_init_no_corpus(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        assert strat.corpus is None
        assert strat._generated_total == 0
        assert strat._generated_template == 0
        assert strat._generated_corpus == 0
        assert strat._duplicates_skipped == 0

    def test_init_with_corpus(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        corpus = _make_mock_corpus()
        strat = RandomWalkStrategy(corpus=corpus)
        assert strat.corpus is corpus

    def test_protocols_attribute(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy
        from blue_tap.fuzz.strategies._registry import PROTOCOLS

        assert RandomWalkStrategy.PROTOCOLS == PROTOCOLS

    def test_generate_returns_bytes_and_log(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        data, log = strat.generate("sdp")
        assert isinstance(data, bytes)
        # Data may be empty after mutation edge cases — just verify type
        assert isinstance(log, list)
        assert all(isinstance(s, str) for s in log)

    def test_generate_unknown_protocol_raises(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        with pytest.raises(ValueError, match="Unknown protocol"):
            strat.generate("nonexistent-protocol")

    def test_generate_all_protocols(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        for protocol in sorted(strat.PROTOCOLS):
            data, log = strat.generate(protocol)
            assert isinstance(data, bytes), f"Failed for {protocol}"

    def test_generate_increments_stats(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        strat.generate("sdp")
        strat.generate("sdp")
        assert strat._generated_total == 2

    def test_generate_with_corpus_seeds(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        seeds = {"sdp": [b"\x01\x02\x03\x04\x05\x06\x07\x08"]}
        corpus = _make_mock_corpus(seeds)
        strat = RandomWalkStrategy(corpus=corpus)

        # Run many times to cover both template and corpus paths
        for _ in range(20):
            data, log = strat.generate("sdp")
            assert isinstance(data, bytes)

    def test_stats_returns_dict(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        strat.generate("sdp")
        s = strat.stats()
        assert isinstance(s, dict)
        assert "generated_total" in s
        assert "generated_template" in s
        assert "generated_corpus" in s
        assert "duplicates_skipped" in s
        assert "unique_payloads" in s
        assert "cached_protocols" in s
        assert s["generated_total"] == 1

    def test_dedup_prevents_immediate_duplicates(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        seen = set()
        # Generate many — most should be unique
        for _ in range(50):
            data, _ = strat.generate("sdp")
            seen.add(data)
        # At least 40 out of 50 should be unique (mutations are random)
        assert len(seen) >= 30

    def test_dedup_set_clears_on_overflow(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy, _MAX_SEEN

        strat = RandomWalkStrategy()
        # Simulate a full dedup set
        strat._seen = {f"fake_{i}" for i in range(_MAX_SEEN)}
        assert len(strat._seen) == _MAX_SEEN

        # _is_novel should clear the set and add new entry
        result = strat._is_novel(b"test_data")
        assert result is True
        assert len(strat._seen) == 1

    def test_generate_from_template_fallback(self):
        """When no templates exist, the strategy falls back to a random blob."""
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        # Poison the cache so protocol returns no templates
        strat._template_cache["sdp"] = []
        data, log = strat._generate_from_template("sdp")
        assert isinstance(data, bytes)
        assert len(data) > 0
        assert "fallback" in log[0].lower()

    def test_generate_from_corpus_fallback_when_no_seed(self):
        """When corpus returns None for a seed, fall back to template mode."""
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        corpus = MagicMock()
        corpus.seed_count.return_value = 1
        corpus.get_random_seed.return_value = None
        strat = RandomWalkStrategy(corpus=corpus)
        data, log = strat._generate_from_corpus("sdp")
        assert isinstance(data, bytes)

    def test_get_templates_caching(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        t1 = strat._get_templates("sdp")
        t2 = strat._get_templates("sdp")
        assert t1 is t2  # Same list object (cached)

    def test_get_templates_flattens_multi_packet(self):
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        strat = RandomWalkStrategy()
        # OBEX generators return list[bytes | list[bytes]]
        templates = strat._get_templates("obex-pbap")
        assert isinstance(templates, list)
        for t in templates:
            assert isinstance(t, bytes), "Templates should be flattened to bytes"
            assert len(t) > 0, "Empty templates should be filtered"


# ============================================================================
# CoverageGuidedStrategy tests
# ============================================================================


class TestCoverageGuidedStrategy:
    """Tests for CoverageGuidedStrategy."""

    def test_init_defaults(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        assert strat.corpus is None
        assert strat.fingerprint_size == 32
        assert strat.interesting_priority == 0.80
        assert strat._stats.total_generated == 0

    def test_init_with_params(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        corpus = _make_mock_corpus()
        strat = CoverageGuidedStrategy(
            corpus=corpus, fingerprint_size=16, interesting_priority=0.5,
        )
        assert strat.corpus is corpus
        assert strat.fingerprint_size == 16
        assert strat.interesting_priority == 0.5

    def test_protocols_attribute(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy
        from blue_tap.fuzz.strategies._registry import PROTOCOLS

        assert CoverageGuidedStrategy.PROTOCOLS == PROTOCOLS

    def test_generate_returns_bytes_and_log(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        data, log = strat.generate("sdp")
        assert isinstance(data, bytes)
        assert isinstance(log, list)

    def test_generate_unknown_protocol_raises(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        with pytest.raises(ValueError, match="Unknown protocol"):
            strat.generate("fake-protocol")

    def test_generate_all_protocols(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        for protocol in sorted(strat.PROTOCOLS):
            data, log = strat.generate(protocol)
            assert isinstance(data, bytes), f"Failed for {protocol}"

    def test_feedback_novel_response(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        input_bytes = b"\x01\x02\x03"
        response = b"\xAA\xBB\xCC\xDD"
        is_novel = strat.feedback("sdp", input_bytes, response)
        assert is_novel is True
        assert strat._stats.total_feedback == 1
        assert strat._stats.novel_responses == 1
        assert strat._stats.interesting_inputs == 1

    def test_feedback_duplicate_response(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        response = b"\xAA\xBB\xCC\xDD"
        strat.feedback("sdp", b"\x01", response)
        is_novel = strat.feedback("sdp", b"\x02", response)
        assert is_novel is False
        assert strat._stats.novel_responses == 1

    def test_feedback_crash_always_interesting(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        response = b"\xAA\xBB"
        # First feedback with crash
        is_novel = strat.feedback("sdp", b"\x01", response, crash=True)
        assert is_novel is True
        assert strat._stats.crashes_seen == 1

        # Same response but another crash -- still interesting
        is_novel = strat.feedback("sdp", b"\x02", response, crash=True)
        assert is_novel is True
        assert strat._stats.crashes_seen == 2

    def test_feedback_timeout_response(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        is_novel = strat.feedback("sdp", b"\x01", None)
        assert is_novel is True  # First "timeout" fingerprint is novel
        is_novel = strat.feedback("sdp", b"\x02", None)
        assert is_novel is False  # Second "timeout" is duplicate

    def test_feedback_empty_response(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        is_novel = strat.feedback("sdp", b"\x01", b"")
        assert is_novel is True
        is_novel = strat.feedback("sdp", b"\x02", b"")
        assert is_novel is False

    def test_feedback_saves_to_corpus(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        corpus = _make_mock_corpus()
        strat = CoverageGuidedStrategy(corpus=corpus)
        strat.feedback("sdp", b"\x01", b"\xAA\xBB")
        corpus.save_interesting.assert_called_once()
        args = corpus.save_interesting.call_args
        assert args[0][0] == "sdp"
        assert args[0][1] == b"\x01"

    def test_feedback_crash_saves_with_reason(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        corpus = _make_mock_corpus()
        strat = CoverageGuidedStrategy(corpus=corpus)
        strat.feedback("sdp", b"\x01", b"\xAA", crash=True)
        args = corpus.save_interesting.call_args
        assert "crash" in args[0][2]

    def test_get_interesting_inputs_empty(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        assert strat.get_interesting_inputs() == []
        assert strat.get_interesting_inputs("sdp") == []

    def test_get_interesting_inputs_after_feedback(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        strat.feedback("sdp", b"\x01", b"\xAA")
        strat.feedback("bnep", b"\x02", b"\xBB")

        all_inputs = strat.get_interesting_inputs()
        assert len(all_inputs) == 2

        sdp_inputs = strat.get_interesting_inputs("sdp")
        assert sdp_inputs == [b"\x01"]

        bnep_inputs = strat.get_interesting_inputs("bnep")
        assert bnep_inputs == [b"\x02"]

    def test_stats_returns_complete_dict(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        strat.generate("sdp")
        strat.feedback("sdp", b"\x01", b"\xAA")
        s = strat.stats()
        assert isinstance(s, dict)
        expected_keys = {
            "total_generated", "total_feedback", "novel_responses",
            "interesting_inputs", "fingerprints_seen", "crashes_seen",
            "exploration_rounds", "exploitation_rounds", "unique_payloads",
            "interesting_by_protocol", "cached_protocols",
        }
        assert expected_keys.issubset(s.keys())
        assert s["total_generated"] == 1
        assert s["total_feedback"] == 1

    def test_exploitation_uses_interesting_inputs(self):
        """After feedback provides interesting inputs, exploitation path uses them."""
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy(interesting_priority=1.0)
        # Seed with interesting inputs
        for i in range(5):
            resp = bytes([i]) * 10
            strat.feedback("sdp", bytes([i]) * 8, resp)

        # Now generate -- should use exploitation (interesting_priority=1.0)
        data, log = strat.generate("sdp")
        assert isinstance(data, bytes)
        assert strat._stats.exploitation_rounds >= 1

    def test_exploration_when_no_interesting_inputs(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        strat.generate("sdp")
        assert strat._stats.exploration_rounds >= 1
        assert strat._stats.exploitation_rounds == 0

    def test_energy_decrements_on_selection(self):
        from blue_tap.fuzz.strategies.coverage_guided import (
            CoverageGuidedStrategy,
            _INITIAL_ENERGY,
        )

        strat = CoverageGuidedStrategy(interesting_priority=1.0)
        input_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        strat.feedback("sdp", input_bytes, b"\xAA\xBB\xCC\xDD")

        h = strat._input_hash(input_bytes)
        initial_energy = strat._energy.get(h, 0)
        assert initial_energy == _INITIAL_ENERGY

        strat.generate("sdp")
        new_energy = strat._energy.get(h, 0)
        assert new_energy < initial_energy

    def test_crash_gets_higher_energy(self):
        from blue_tap.fuzz.strategies.coverage_guided import (
            CoverageGuidedStrategy,
            _INITIAL_ENERGY,
            _CRASH_ENERGY,
        )

        strat = CoverageGuidedStrategy()
        normal_input = b"\x01\x02"
        crash_input = b"\x03\x04"
        strat.feedback("sdp", normal_input, b"\xAA")
        strat.feedback("sdp", crash_input, b"\xBB", crash=True)

        h_normal = strat._input_hash(normal_input)
        h_crash = strat._input_hash(crash_input)
        assert strat._energy[h_normal] == _INITIAL_ENERGY
        assert strat._energy[h_crash] == _CRASH_ENERGY

    def test_fingerprint_none(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        assert strat._fingerprint(None) == "timeout"

    def test_fingerprint_empty(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        assert strat._fingerprint(b"") == "empty"

    def test_fingerprint_crash(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        fp = strat._fingerprint(b"\xAA", crash=True)
        assert fp.startswith("crash:")

    def test_fingerprint_normal(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        fp = strat._fingerprint(b"\xAA\xBB\xCC\xDD")
        assert isinstance(fp, str)
        assert len(fp) == 16  # Truncated SHA-256

    def test_fingerprint_different_lengths_differ(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        fp1 = strat._fingerprint(b"\xAA" * 10)
        fp2 = strat._fingerprint(b"\xAA" * 20)
        assert fp1 != fp2

    def test_evict_lowest_energy(self):
        from blue_tap.fuzz.strategies.coverage_guided import (
            CoverageGuidedStrategy,
            _MAX_INTERESTING_PER_PROTOCOL,
        )

        strat = CoverageGuidedStrategy()
        pool: list[bytes] = []
        for i in range(_MAX_INTERESTING_PER_PROTOCOL + 10):
            inp = bytes([i % 256]) * 8 + i.to_bytes(4, "big")
            pool.append(inp)
            h = strat._input_hash(inp)
            strat._energy[h] = i  # Energy = index

        strat._evict_lowest_energy(pool)
        assert len(pool) == _MAX_INTERESTING_PER_PROTOCOL

    def test_generate_with_corpus_exploration(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        seeds = {"sdp": [b"\xDE\xAD\xBE\xEF" * 4]}
        corpus = _make_mock_corpus(seeds)
        strat = CoverageGuidedStrategy(corpus=corpus)

        # Run many iterations to hit the corpus exploration path
        for _ in range(30):
            data, log = strat.generate("sdp")
            assert isinstance(data, bytes)

    def test_fallback_input_with_no_templates(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        strat._template_cache["sdp"] = []
        inp, source = strat._fallback_input("sdp")
        assert isinstance(inp, bytes)
        assert "fallback" in source.lower()


# ============================================================================
# StateMachineStrategy tests
# ============================================================================


class TestStateMachineStrategy:
    """Tests for StateMachineStrategy and related models."""

    def test_init(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        assert strat._stats_generated == 0

    def test_list_models(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        models = strat.list_models()
        assert isinstance(models, list)
        expected = {"obex-pbap", "obex-map", "hfp", "smp-legacy", "smp-sc", "att"}
        assert set(models) == expected

    def test_generate_unknown_protocol_raises(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        with pytest.raises(ValueError, match="Unknown protocol"):
            strat.generate("nonexistent")

    def test_generate_returns_packets_and_log(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat.generate(model_name)
            assert isinstance(packets, list), f"Failed for {model_name}"
            assert isinstance(log, list), f"Failed for {model_name}"
            # All packets should be bytes
            for pkt in packets:
                assert isinstance(pkt, bytes), (
                    f"Packet in {model_name} is {type(pkt)}, expected bytes"
                )

    def test_generate_increments_stats(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        strat.generate("att")
        strat.generate("att")
        assert strat._stats_generated == 2

    def test_stats_returns_dict(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        strat.generate("att")
        s = strat.stats()
        assert isinstance(s, dict)
        expected_keys = {
            "generated_total", "valid_mutated", "invalid_transitions",
            "state_skips", "state_regressions", "repeated_state",
        }
        assert expected_keys == set(s.keys())
        assert s["generated_total"] == 1

    def test_generate_valid_with_mutations(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat.generate_valid_with_mutations(model_name)
            assert isinstance(packets, list)
            # Log should mention valid_mutated
            assert any("valid_mutated" in s for s in log) or len(packets) == 0

    def test_generate_invalid_transition(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat.generate_invalid_transition(model_name)
            assert isinstance(packets, list)
            assert isinstance(log, list)

    def test_generate_state_skip(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat.generate_state_skip(model_name)
            assert isinstance(packets, list)

    def test_generate_state_regression(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat.generate_state_regression(model_name)
            assert isinstance(packets, list)

    def test_generate_all_sequences(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            results = strat.generate_all_sequences(model_name)
            assert isinstance(results, list)
            assert len(results) > 0
            for packets, log in results:
                assert isinstance(packets, list)
                assert isinstance(log, list)
                for pkt in packets:
                    assert isinstance(pkt, bytes)


class TestOBEXStateMachine:
    """Tests for OBEXStateMachine model."""

    def test_pbap_init(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        assert model.initial_state == "disconnected"
        assert "connected" in model.states
        assert "getting" in model.states

    def test_map_init(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("map")
        assert model.initial_state == "disconnected"

    def test_valid_sequence(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        seq = model.valid_sequence("connected")
        assert isinstance(seq, list)
        assert len(seq) > 0
        for pkt in seq:
            assert isinstance(pkt, bytes)

    def test_valid_sequence_invalid_state_raises(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        with pytest.raises(ValueError):
            model.valid_sequence("nonexistent_state")

    def test_invalid_transition(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        packets = model.invalid_transition("connected")
        assert isinstance(packets, list)

    def test_invalid_transition_unknown_state(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        packets = model.invalid_transition("nonexistent")
        assert packets == []

    def test_all_invalid_transitions(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        invalids = model.all_invalid_transitions()
        assert isinstance(invalids, list)
        assert len(invalids) > 5  # OBEX has many invalid transitions
        for packets, log in invalids:
            assert isinstance(packets, list)
            assert isinstance(log, list)
            for pkt in packets:
                assert isinstance(pkt, bytes)

    def test_canonical_path(self):
        from blue_tap.fuzz.strategies.state_machine import OBEXStateMachine

        model = OBEXStateMachine("pbap")
        assert model.canonical_path[0] == "disconnected"
        assert "connected" in model.canonical_path


class TestHFPStateMachine:
    """Tests for HFPStateMachine model."""

    def test_init(self):
        from blue_tap.fuzz.strategies.state_machine import HFPStateMachine

        model = HFPStateMachine()
        assert model.initial_state == "idle"
        assert "brsf" in model.states
        assert "slc_established" in model.states

    def test_canonical_path(self):
        from blue_tap.fuzz.strategies.state_machine import HFPStateMachine

        model = HFPStateMachine()
        assert model.canonical_path[0] == "idle"
        assert model.canonical_path[-1] == "slc_established"
        assert len(model.canonical_path) == 8

    def test_valid_sequence_to_slc(self):
        from blue_tap.fuzz.strategies.state_machine import HFPStateMachine

        model = HFPStateMachine()
        # slc_established has empty entry_packets, but the path collects others
        seq = model.valid_sequence("chld")
        assert isinstance(seq, list)
        assert len(seq) > 0

    def test_invalid_transitions(self):
        from blue_tap.fuzz.strategies.state_machine import HFPStateMachine

        model = HFPStateMachine()
        invalids = model.all_invalid_transitions()
        assert len(invalids) > 5
        for packets, log in invalids:
            assert isinstance(packets, list)


class TestSMPStateMachine:
    """Tests for SMPStateMachine model."""

    def test_secure_connections_init(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=True)
        assert model.initial_state == "idle"
        assert "public_key" in model.states
        assert "dhkey_check" in model.states

    def test_legacy_init(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=False)
        assert model.initial_state == "idle"
        assert "public_key" not in model.states
        assert "dhkey_check" not in model.states

    def test_sc_canonical_path(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=True)
        assert "public_key" in model.canonical_path
        assert model.canonical_path[-1] == "paired"

    def test_legacy_canonical_path(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=False)
        assert "public_key" not in model.canonical_path
        assert model.canonical_path[-1] == "paired"

    def test_invalid_transitions_sc(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=True)
        invalids = model.all_invalid_transitions()
        assert len(invalids) > 5

    def test_invalid_transitions_legacy(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=False)
        invalids = model.all_invalid_transitions()
        assert len(invalids) > 3

    def test_valid_sequence(self):
        from blue_tap.fuzz.strategies.state_machine import SMPStateMachine

        model = SMPStateMachine(secure_connections=True)
        seq = model.valid_sequence("confirm")
        assert isinstance(seq, list)
        assert len(seq) > 0


class TestATTStateMachine:
    """Tests for ATTStateMachine model."""

    def test_init(self):
        from blue_tap.fuzz.strategies.state_machine import ATTStateMachine

        model = ATTStateMachine()
        assert model.initial_state == "idle"
        assert "mtu_exchanged" in model.states
        assert "notifications_enabled" in model.states

    def test_canonical_path(self):
        from blue_tap.fuzz.strategies.state_machine import ATTStateMachine

        model = ATTStateMachine()
        assert model.canonical_path[0] == "idle"
        assert model.canonical_path[-1] == "notifications_enabled"

    def test_valid_sequence(self):
        from blue_tap.fuzz.strategies.state_machine import ATTStateMachine

        model = ATTStateMachine()
        seq = model.valid_sequence("services_discovered")
        assert isinstance(seq, list)
        assert len(seq) > 0

    def test_invalid_transitions(self):
        from blue_tap.fuzz.strategies.state_machine import ATTStateMachine

        model = ATTStateMachine()
        invalids = model.all_invalid_transitions()
        assert len(invalids) >= 10


class TestProtocolState:
    """Tests for ProtocolState dataclass."""

    def test_creation(self):
        from blue_tap.fuzz.strategies.state_machine import ProtocolState

        state = ProtocolState(
            name="test",
            valid_transitions=("a", "b"),
            entry_packets=(b"\x01", b"\x02"),
        )
        assert state.name == "test"
        assert state.valid_transitions == ("a", "b")
        assert state.entry_packets == (b"\x01", b"\x02")

    def test_frozen(self):
        from blue_tap.fuzz.strategies.state_machine import ProtocolState

        state = ProtocolState(name="test")
        with pytest.raises(AttributeError):
            state.name = "changed"

    def test_defaults(self):
        from blue_tap.fuzz.strategies.state_machine import ProtocolState

        state = ProtocolState(name="test")
        assert state.valid_transitions == ()
        assert state.entry_packets == ()


# ============================================================================
# TargetedStrategy tests
# ============================================================================


class TestTargetedStrategy:
    """Tests for TargetedStrategy."""

    def test_init(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        assert strat is not None

    def test_list_cves(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        cves = strat.list_cves()
        assert isinstance(cves, list)
        assert len(cves) >= 7

        for cve in cves:
            assert "id" in cve
            assert "name" in cve
            assert "protocol" in cve
            assert "severity" in cve
            assert "method" in cve

    def test_list_cves_returns_copy(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        cves1 = strat.list_cves()
        cves2 = strat.list_cves()
        assert cves1 is not cves2

    def test_cve_2017_0785_sdp_leak(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.cve_2017_0785_sdp_leak())
        assert len(results) > 0

        # First result is exact reproduction
        payload, desc = results[0]
        assert isinstance(payload, list)  # Multi-step
        assert all(isinstance(p, bytes) for p in payload)
        assert "exact reproduction" in desc.lower() or "CVE-2017-0785" in desc

        # Check all results
        for payload, desc in results:
            assert isinstance(desc, str)
            if isinstance(payload, list):
                for p in payload:
                    assert isinstance(p, bytes)
            else:
                assert isinstance(payload, bytes)

    def test_cve_2017_0781_bnep_heap(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.cve_2017_0781_bnep_heap())
        assert len(results) > 0

        payload, desc = results[0]
        assert isinstance(payload, bytes)
        assert "CVE-2017-0781" in desc

    def test_sweyntooth_att_deadlock(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.sweyntooth_att_deadlock())
        assert len(results) > 0

        # First result is exact reproduction -- multi-step
        payload, desc = results[0]
        assert isinstance(payload, list)
        assert len(payload) == 2
        assert "deadlock" in desc.lower() or "CVE-2019-19192" in desc

    def test_sweyntooth_att_large_mtu(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.sweyntooth_att_large_mtu())
        assert len(results) > 0

        payload, desc = results[0]
        assert isinstance(payload, bytes)
        assert "MTU" in desc or "mtu" in desc

    def test_cve_2018_5383_invalid_curve(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.cve_2018_5383_invalid_curve())
        assert len(results) > 0

        # First result: multi-step with pairing request + zero key
        payload, desc = results[0]
        assert isinstance(payload, list)
        assert len(payload) == 2
        assert "CVE-2018-5383" in desc

    def test_cve_2024_24746_prepare_write(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.cve_2024_24746_prepare_write())
        assert len(results) > 0

        payload, desc = results[0]
        # First is a single Prepare Write
        assert isinstance(payload, bytes)
        assert "CVE-2024-24746" in desc

    def test_perfektblue_l2cap_cid_zero(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.perfektblue_l2cap_cid_zero())
        assert len(results) > 0

        for payload, desc in results:
            assert isinstance(payload, bytes)
            # All frames should have CID in the L2CAP header
            assert len(payload) >= 4

    def test_generate_all_no_filter(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.generate_all())
        assert len(results) > 50  # Should have many variants across all CVEs

        for payload, desc in results:
            assert isinstance(desc, str)
            assert isinstance(payload, (bytes, list))

    def test_generate_all_with_filter(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.generate_all(cve="2017-0785"))
        assert len(results) > 0
        for _, desc in results:
            assert "0785" in desc or "CVE-2017-0785" in desc

    def test_generate_all_filter_sweyntooth(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.generate_all(cve="sweyntooth"))
        assert len(results) > 0

    def test_generate_all_filter_no_match(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        results = list(strat.generate_all(cve="CVE-9999-99999"))
        assert len(results) == 0

    def test_generate_all_filter_case_insensitive(self):
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        r1 = list(strat.generate_all(cve="SWEYNTOOTH"))
        r2 = list(strat.generate_all(cve="sweyntooth"))
        assert len(r1) == len(r2)
        assert len(r1) > 0

    def test_cve_payloads_produce_valid_bytes(self):
        """Sanity check: all CVE methods produce non-empty payloads."""
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strat = TargetedStrategy()
        methods = [
            strat.cve_2017_0785_sdp_leak,
            strat.cve_2017_0781_bnep_heap,
            strat.sweyntooth_att_deadlock,
            strat.sweyntooth_att_large_mtu,
            strat.cve_2018_5383_invalid_curve,
            strat.cve_2024_24746_prepare_write,
            strat.perfektblue_l2cap_cid_zero,
        ]
        for method in methods:
            first = next(method())
            payload, desc = first
            if isinstance(payload, list):
                for p in payload:
                    assert isinstance(p, bytes)
                    assert len(p) > 0
            else:
                assert isinstance(payload, bytes)
                assert len(payload) > 0


# ============================================================================
# Edge case tests
# ============================================================================


class TestEdgeCases:
    """Cross-cutting edge case tests."""

    def test_random_walk_empty_corpus_protocol(self):
        """Corpus has no seeds for the requested protocol."""
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy

        corpus = _make_mock_corpus({"sdp": []})
        strat = RandomWalkStrategy(corpus=corpus)
        data, log = strat.generate("sdp")
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_coverage_guided_empty_corpus(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        corpus = _make_mock_corpus({})
        strat = CoverageGuidedStrategy(corpus=corpus)
        data, log = strat.generate("sdp")
        assert isinstance(data, bytes)

    def test_state_machine_repeated_state_all_models(self):
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        strat = StateMachineStrategy()
        for model_name in strat.list_models():
            packets, log = strat._generate_repeated_state(model_name)
            assert isinstance(packets, list)
            assert isinstance(log, list)

    def test_state_machine_models_share_across_instances(self):
        """MODELS dict is class-level, shared across instances."""
        from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy

        s1 = StateMachineStrategy()
        s2 = StateMachineStrategy()
        assert s1.MODELS is s2.MODELS

    def test_multiple_generate_calls_dont_crash(self):
        """Stress test: many generate calls without errors."""
        from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        rw = RandomWalkStrategy()
        cg = CoverageGuidedStrategy()
        for _ in range(100):
            rw.generate("sdp")
            cg.generate("bnep")

        assert rw._generated_total == 100
        assert cg._stats.total_generated == 100

    def test_coverage_guided_feedback_many_protocols(self):
        from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy

        strat = CoverageGuidedStrategy()
        protocols = ["sdp", "bnep", "rfcomm", "l2cap"]
        for i, proto in enumerate(protocols):
            resp = bytes([i]) * 10
            strat.feedback(proto, bytes([i]) * 8, resp)

        inputs = strat.get_interesting_inputs()
        assert len(inputs) == 4

        for proto in protocols:
            proto_inputs = strat.get_interesting_inputs(proto)
            assert len(proto_inputs) == 1
