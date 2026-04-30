"""Tests for the programmatic fuzzing research API.

These tests don't touch real Bluetooth hardware — they monkeypatch
``FuzzCampaign.run`` to return canned summary dicts and verify the
typed :class:`CampaignResult` view + delta computation.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blue_tap.modules.fuzzing import (
    BenchmarkComparison,
    BenchmarkResult,
    CampaignDelta,
    CampaignResult,
    benchmark,
    compare_benchmarks,
    compare_campaigns,
    list_protocols,
    list_strategies,
    run_campaign,
)


def _fake_summary(*, strategy: str, crashes: int, packets: int,
                  iterations: int, runtime: float, states: int = 0) -> dict:
    """Shape matches FuzzCampaign._build_summary()."""
    return {
        "result": "complete",
        "target": "AA:BB:CC:DD:EE:FF",
        "protocols": ["l2cap", "rfcomm"],
        "strategy": strategy,
        "iterations": iterations,
        "packets_sent": packets,
        "crashes": crashes,
        "errors": 0,
        "reconnects": 0,
        "runtime_seconds": runtime,
        "packets_per_second": packets / max(runtime, 0.001),
        "crash_rate_per_1000": (crashes / max(packets, 1)) * 1000.0,
        "protocol_breakdown": {"l2cap": packets // 2, "rfcomm": packets // 2},
        "state_coverage": {
            "total_states": states,
            "total_transitions": states * 2,
            "protocols_tracked": ["l2cap"],
        } if states else {},
    }


def test_run_campaign_returns_typed_result(tmp_path):
    summary = _fake_summary(strategy="random", crashes=2, packets=2000,
                            iterations=2000, runtime=10.0, states=8)
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        return_value=summary,
    ):
        result = run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap", "rfcomm"],
            strategy="random",
            max_iterations=1,
            session_dir=str(tmp_path),
        )

    assert isinstance(result, CampaignResult)
    assert result.strategy == "random"
    assert result.crashes == 2
    assert result.packets_sent == 2000
    assert result.crashes_per_kpkt == pytest.approx(1.0)
    assert result.states_discovered == 8
    assert result.transitions_discovered == 16
    assert result.aborted is False
    assert result.error is None


def test_run_campaign_records_aborted_on_keyboardinterrupt(tmp_path):
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        side_effect=KeyboardInterrupt(),
    ):
        result = run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            session_dir=str(tmp_path),
        )

    assert result.aborted is True
    assert result.error is None


def test_run_campaign_records_error_on_exception(tmp_path):
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        side_effect=RuntimeError("transport down"),
    ):
        result = run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            session_dir=str(tmp_path),
        )

    assert result.aborted is False
    assert result.error == "RuntimeError: transport down"


def test_run_campaign_rejects_empty_protocols(tmp_path):
    with pytest.raises(ValueError, match="at least one protocol"):
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=[],
                     session_dir=str(tmp_path))


def test_compare_campaigns_computes_deltas():
    a = CampaignResult.from_summary(_fake_summary(
        strategy="random", crashes=1, packets=1000, iterations=1000,
        runtime=10.0, states=4,
    ))
    b = CampaignResult.from_summary(_fake_summary(
        strategy="coverage_guided", crashes=5, packets=1000, iterations=1000,
        runtime=12.0, states=12,
    ))

    delta = compare_campaigns(a, b)

    assert isinstance(delta, CampaignDelta)
    assert delta.crashes == 4
    assert delta.runtime_seconds == pytest.approx(2.0)
    assert delta.states_discovered == 8
    assert delta.transitions_discovered == 16
    assert delta.crashes_per_kpkt == pytest.approx(4.0)


def test_campaign_result_to_dict_round_trip():
    summary = _fake_summary(strategy="mutation", crashes=3, packets=500,
                            iterations=500, runtime=5.0)
    result = CampaignResult.from_summary(summary)
    d = result.to_dict()

    assert d["strategy"] == "mutation"
    assert d["crashes"] == 3
    assert d["protocols"] == ["l2cap", "rfcomm"]
    # raw_summary is intentionally excluded from to_dict() — it's a
    # dict-of-anything escape hatch, not a stable contract.
    assert "raw_summary" not in d


def test_campaign_result_json_round_trip():
    summary = _fake_summary(strategy="coverage_guided", crashes=4, packets=2000,
                            iterations=2000, runtime=12.5, states=10)
    original = CampaignResult.from_summary(summary, aborted=False, error=None)
    payload = original.to_json()

    restored = CampaignResult.from_json(payload)

    assert restored.strategy == original.strategy
    assert restored.crashes == original.crashes
    assert restored.packets_sent == original.packets_sent
    assert restored.runtime_seconds == original.runtime_seconds
    assert restored.protocols == original.protocols
    assert restored.state_coverage == original.state_coverage
    # raw_summary is dropped on the round trip — that's the documented contract
    assert restored.raw_summary == {}


def test_campaign_result_from_json_rejects_non_object():
    import pytest
    with pytest.raises(ValueError, match="JSON object"):
        CampaignResult.from_json("[1, 2, 3]")


def test_run_campaign_seed_is_passed_to_random(tmp_path):
    """run_campaign(seed=...) must call random.seed before invoking."""
    seen_random_state: list = []

    def _capture_then_summary(*_args, **_kwargs):
        # Snapshot the RNG state inside FuzzCampaign.run() — if seed was
        # set deterministically before us, this state is reproducible.
        seen_random_state.append(random.getstate())
        return _fake_summary(strategy="random", crashes=0, packets=10,
                             iterations=10, runtime=1.0)

    import random
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        side_effect=_capture_then_summary,
    ):
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                     session_dir=str(tmp_path), seed=42)
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                     session_dir=str(tmp_path), seed=42)

    assert len(seen_random_state) == 2
    assert seen_random_state[0] == seen_random_state[1]


def test_benchmark_runs_n_trials_and_aggregates(tmp_path):
    crash_sequence = iter([1, 3, 2, 4, 0])

    def _summary_for_trial(*_a, **_kw):
        c = next(crash_sequence)
        return _fake_summary(strategy="coverage_guided", crashes=c,
                             packets=1000, iterations=1000, runtime=10.0,
                             states=4)

    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        side_effect=_summary_for_trial,
    ):
        result = benchmark(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            strategy="coverage_guided",
            trials=5,
            session_dir=str(tmp_path),
        )

    assert isinstance(result, BenchmarkResult)
    assert len(result.trials) == 5
    assert result.crashes["n"] == 5
    assert result.crashes["mean"] == pytest.approx(2.0)
    assert result.crashes["min"] == 0.0
    assert result.crashes["max"] == 4.0
    assert result.crashes["stdev"] > 0
    assert result.aborted_trials == 0
    assert result.error_trials == 0


def test_benchmark_counts_aborted_and_error_trials(tmp_path):
    side_effects = [
        _fake_summary(strategy="random", crashes=1, packets=100,
                      iterations=100, runtime=1.0),
        KeyboardInterrupt(),
        RuntimeError("transport down"),
    ]
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        side_effect=side_effects,
    ):
        result = benchmark(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            strategy="random",
            trials=3,
            session_dir=str(tmp_path),
        )

    assert len(result.trials) == 3
    assert result.aborted_trials == 1
    assert result.error_trials == 1


def test_benchmark_rejects_zero_trials(tmp_path):
    with pytest.raises(ValueError, match="trials >= 1"):
        benchmark(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                  trials=0, session_dir=str(tmp_path))


def test_compare_benchmarks_reports_cohens_d_and_mean_deltas():
    def _trials(crashes_seq: list[int], strategy: str) -> list[CampaignResult]:
        return [
            CampaignResult.from_summary(_fake_summary(
                strategy=strategy, crashes=c, packets=1000, iterations=1000,
                runtime=10.0, states=4 + c,
            ))
            for c in crashes_seq
        ]

    a = BenchmarkResult.from_trials(
        label="random",
        strategy="random",
        trials=_trials([1, 1, 2, 1, 2], "random"),
    )
    b = BenchmarkResult.from_trials(
        label="coverage_guided",
        strategy="coverage_guided",
        trials=_trials([5, 6, 7, 6, 5], "coverage_guided"),
    )

    cmp = compare_benchmarks(a, b)
    assert isinstance(cmp, BenchmarkComparison)
    # b crashes much more reliably than a → large positive d
    assert cmp.cohens_d_crashes_per_kpkt > 0.8
    assert cmp.mean_delta_crashes == pytest.approx(b.crashes["mean"] - a.crashes["mean"])
    assert cmp.mean_delta_crashes > 0


def test_compare_benchmarks_returns_zero_d_when_identical():
    trials = [
        CampaignResult.from_summary(_fake_summary(
            strategy="random", crashes=2, packets=1000, iterations=1000,
            runtime=10.0,
        ))
        for _ in range(3)
    ]
    a = BenchmarkResult.from_trials(label="a", strategy="random", trials=trials)
    b = BenchmarkResult.from_trials(label="b", strategy="random", trials=list(trials))

    cmp = compare_benchmarks(a, b)
    # Zero variance in either sample → pooled stdev is 0 → d defined as 0.0
    assert cmp.cohens_d_crashes_per_kpkt == 0.0
    assert cmp.mean_delta_crashes == 0.0


def test_run_campaign_random_source_overrides_os_urandom(tmp_path):
    """random_source kwarg must be installed on the FuzzCampaign and used
    by the fallback mutation paths instead of os.urandom."""
    from blue_tap.modules.fuzzing.engine import FuzzCampaign

    captured: list = []

    def _deterministic_bytes(n: int) -> bytes:
        captured.append(n)
        return b"\xAA" * n

    real_init = FuzzCampaign.__init__

    seen_random_source: list = []

    def _spy_init(self, *args, **kwargs):
        real_init(self, *args, **kwargs)
        seen_random_source.append(self._random_bytes)

    with patch.object(FuzzCampaign, "__init__", _spy_init), patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        return_value=_fake_summary(strategy="random", crashes=0, packets=0,
                                   iterations=0, runtime=0.1),
    ):
        run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            session_dir=str(tmp_path),
            random_source=_deterministic_bytes,
        )

    assert len(seen_random_source) == 1
    assert seen_random_source[0] is _deterministic_bytes


def test_run_campaign_seed_derives_random_source(tmp_path):
    """When seed= is given without random_source=, the engine receives a
    seeded callable so byte-level mutation choices are reproducible."""
    from blue_tap.modules.fuzzing.engine import FuzzCampaign

    seen: list = []

    def _spy_init(self, *args, **kwargs):
        FuzzCampaign.__init__.__wrapped__(self, *args, **kwargs)  # type: ignore
        # Generate a known-length sample from the seeded source.
        seen.append(self._random_bytes(16))

    real_init = FuzzCampaign.__init__
    setattr(_spy_init, "__wrapped__", real_init)

    with patch.object(FuzzCampaign, "__init__", _spy_init), patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        return_value=_fake_summary(strategy="random", crashes=0, packets=0,
                                   iterations=0, runtime=0.1),
    ):
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                     session_dir=str(tmp_path), seed=99)
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                     session_dir=str(tmp_path), seed=99)
        run_campaign(target="AA:BB:CC:DD:EE:FF", protocols=["l2cap"],
                     session_dir=str(tmp_path), seed=100)

    assert seen[0] == seen[1]
    assert seen[0] != seen[2]


def test_dry_run_uses_mock_transport(tmp_path):
    """dry_run=True must wire MockTransport for every protocol."""
    from blue_tap.modules.fuzzing.engine import FuzzCampaign
    from blue_tap.modules.fuzzing.transport import MockTransport

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap", "rfcomm"],
        session_dir=str(tmp_path),
        dry_run=True,
    )
    transports = campaign._setup_transports()

    assert set(transports.keys()) == {"l2cap", "rfcomm"}
    for proto, t in transports.items():
        assert isinstance(t, MockTransport), proto
        assert t.connect() is True
        assert t.connected is True
        assert t.send(b"\x01\x02\x03") == 3
        assert t.recv() == b""  # default response_factory


def test_mock_transport_response_factory_is_called():
    from blue_tap.modules.fuzzing.transport import MockTransport

    t = MockTransport(
        "AA:BB:CC:DD:EE:FF",
        protocol="l2cap",
        response_factory=lambda payload: b"echo:" + payload,
    )
    t.connect()
    t.send(b"hello")
    assert t.recv() == b"echo:hello"


def test_mock_transport_send_buffer_is_bounded():
    from blue_tap.modules.fuzzing.transport import MockTransport

    t = MockTransport("AA:BB:CC:DD:EE:FF", send_buffer_len=4)
    t.connect()
    for i in range(10):
        t.send(bytes([i]))

    # Only the last 4 packets are retained.
    assert len(t.sent) == 4
    assert list(t.sent) == [bytes([6]), bytes([7]), bytes([8]), bytes([9])]


def test_mock_transport_send_rejects_non_bytes():
    import pytest
    from blue_tap.modules.fuzzing.transport import MockTransport

    t = MockTransport("AA:BB:CC:DD:EE:FF")
    t.connect()
    with pytest.raises(TypeError, match="bytes"):
        t.send("not bytes")  # type: ignore[arg-type]


def test_mock_transport_response_factory_must_return_bytes():
    import pytest
    from blue_tap.modules.fuzzing.transport import MockTransport

    t = MockTransport(
        "AA:BB:CC:DD:EE:FF",
        response_factory=lambda _p: "not bytes",  # type: ignore[return-value, arg-type]
    )
    t.connect()
    t.send(b"x")
    with pytest.raises(TypeError, match="bytes"):
        t.recv()


def test_mock_transport_rejects_invalid_buffer_len():
    import pytest
    from blue_tap.modules.fuzzing.transport import MockTransport

    with pytest.raises(ValueError, match="send_buffer_len"):
        MockTransport("AA:BB:CC:DD:EE:FF", send_buffer_len=0)


def test_trajectory_interval_zero_disables_recording(tmp_path):
    """Non-positive intervals are normalised to None so the hot-path
    short-circuit fires every iteration."""
    from blue_tap.modules.fuzzing.engine import FuzzCampaign

    c = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap"],
        session_dir=str(tmp_path),
        trajectory_interval_seconds=0,
    )
    assert c.trajectory_interval_seconds is None
    c._maybe_record_trajectory()
    assert c._trajectory == []


def test_trajectory_records_after_interval(tmp_path):
    """When interval has elapsed, _maybe_record_trajectory captures stats.

    Uses a 1-second interval rather than a sub-millisecond one so the
    "no second record on rapid re-call" assertion isn't sensitive to
    pytest / GC / context-switch latency on slow hosts.
    """
    from blue_tap.modules.fuzzing.engine import FuzzCampaign

    c = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap"],
        session_dir=str(tmp_path),
        trajectory_interval_seconds=1.0,
    )
    c.stats.iterations = 50
    c.stats.packets_sent = 100
    c.stats.crashes = 1
    c.stats.errors = 2

    # First call: interval has elapsed since _last_trajectory_time=0.0 → record
    c._maybe_record_trajectory()
    # Immediately after: not enough elapsed (<<1s) → no second record
    c._maybe_record_trajectory()

    assert len(c._trajectory) == 1
    snap = c._trajectory[0]
    assert snap["iterations"] == 50
    assert snap["packets_sent"] == 100
    assert snap["crashes"] == 1
    assert snap["errors"] == 2
    assert snap["states"] == 0
    assert snap["transitions"] == 0
    assert "elapsed_seconds" in snap


def test_campaign_result_carries_trajectory_through_summary():
    summary = _fake_summary(strategy="random", crashes=0, packets=10,
                            iterations=10, runtime=1.0)
    summary["trajectory"] = [
        {"elapsed_seconds": 1.0, "iterations": 5, "packets_sent": 5,
         "crashes": 0, "errors": 0, "states": 0, "transitions": 0},
        {"elapsed_seconds": 2.0, "iterations": 10, "packets_sent": 10,
         "crashes": 0, "errors": 0, "states": 1, "transitions": 0},
    ]
    result = CampaignResult.from_summary(summary)
    assert len(result.trajectory) == 2
    assert result.trajectory[1]["states"] == 1

    # Round-trip through JSON preserves trajectory
    restored = CampaignResult.from_json(result.to_json())
    assert restored.trajectory == result.trajectory


def test_benchmark_result_json_round_trip():
    trials = [
        CampaignResult.from_summary(_fake_summary(
            strategy="random", crashes=c, packets=1000, iterations=1000,
            runtime=10.0, states=4,
        ))
        for c in [1, 2, 3]
    ]
    original = BenchmarkResult.from_trials(
        label="random@3", strategy="random", trials=trials,
    )

    payload = original.to_json()
    restored = BenchmarkResult.from_json(payload)

    assert restored.label == original.label
    assert restored.strategy == original.strategy
    assert len(restored.trials) == 3
    assert restored.crashes["mean"] == original.crashes["mean"]
    assert restored.crashes["stdev"] == original.crashes["stdev"]
    assert [t.crashes for t in restored.trials] == [t.crashes for t in original.trials]


def test_benchmark_result_from_dict_rejects_summary_only():
    """Compact form (include_trials=False) is intentionally not round-trippable."""
    import pytest

    trials = [CampaignResult.from_summary(_fake_summary(
        strategy="random", crashes=1, packets=100, iterations=100, runtime=1.0,
    ))]
    summary_only = BenchmarkResult.from_trials(
        label="x", strategy="random", trials=trials,
    ).to_dict(include_trials=False)

    assert "trials" not in summary_only
    with pytest.raises(ValueError, match="per-trial"):
        BenchmarkResult.from_dict(summary_only)


def test_benchmark_result_from_json_rejects_non_object():
    import pytest
    with pytest.raises(ValueError, match="JSON object"):
        BenchmarkResult.from_json("[]")


def test_run_campaign_dry_run_actually_completes(tmp_path):
    """End-to-end: dry_run must bypass l2ping / health-monitor probes
    and actually drive the engine through its main loop, producing a
    non-zero iteration count without ever touching real hardware."""
    result = run_campaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap"],
        strategy="random",
        max_iterations=5,
        session_dir=str(tmp_path),
        dry_run=True,
        cooldown=0,
    )

    assert result.iterations == 5
    assert result.packets_sent == 5
    assert result.aborted is False
    # error must be None — if dry_run still hit the alive check, the
    # engine would return {"result": "error", "reason": "target_unreachable"}
    # and run_campaign would surface that as result.error.
    assert result.error is None


def test_run_campaign_surfaces_engine_target_unreachable_in_error_field(tmp_path):
    """Without dry_run, an unreachable target must NOT silently produce
    an empty result — run_campaign should surface the engine's
    {"result": "error", "reason": "target_unreachable"} into
    CampaignResult.error so callers can detect the failure."""
    fake_summary = {"result": "error", "reason": "target_unreachable"}
    with patch(
        "blue_tap.modules.fuzzing.engine.FuzzCampaign.run",
        return_value=fake_summary,
    ):
        result = run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap"],
            session_dir=str(tmp_path),
        )

    assert result.error == "engine: target_unreachable"
    assert result.iterations == 0


def test_run_campaign_dry_run_seed_yields_reproducible_protocol_breakdown(tmp_path):
    """Same seed + dry_run must produce identical decisions across runs.
    Verified via protocol_breakdown — the engine's protocol-rotation
    decision is :mod:`random`-driven, so seed= must lock it down."""
    def _go() -> dict:
        return run_campaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["l2cap", "rfcomm", "sdp"],
            strategy="random",
            max_iterations=15,
            session_dir=str(tmp_path),
            dry_run=True,
            cooldown=0,
            seed=42,
        ).protocol_breakdown

    a = _go()
    b = _go()
    assert a == b
    assert sum(a.values()) == 15


def test_benchmark_dry_run_end_to_end_aggregates_real_trials(tmp_path):
    """End-to-end: benchmark + dry_run runs without hardware and yields
    a populated BenchmarkResult with real per-trial counts."""
    result = benchmark(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["l2cap"],
        strategy="random",
        trials=3,
        max_iterations=4,
        session_dir=str(tmp_path),
        dry_run=True,
        cooldown=0,
    )

    assert len(result.trials) == 3
    assert all(t.iterations == 4 for t in result.trials)
    assert all(t.error is None for t in result.trials)
    assert result.iterations["mean"] == 4.0
    assert result.aborted_trials == 0
    assert result.error_trials == 0


def test_run_campaign_dry_run_is_byte_identical_for_same_seed(tmp_path):
    """Two run_campaign calls with the same seed under dry_run must
    transmit byte-identical payloads end-to-end. This is the production
    reproducibility contract: every random source in the pipeline
    (engine fallbacks, mutators, strategies, protocol builders) reads
    from the seeded ContextVar so the seed locks down the entire run."""
    import hashlib
    from blue_tap.modules.fuzzing.transport import MockTransport

    def _capture(seed: int) -> tuple[str, int]:
        sent: list[bytes] = []
        original_send = MockTransport.send

        def _spy(self, data):
            sent.append(bytes(data))
            return original_send(self, data)

        MockTransport.send = _spy
        try:
            run_campaign(
                target="AA:BB:CC:DD:EE:FF",
                protocols=["l2cap", "sdp", "smp"],
                strategy="random",
                max_iterations=20,
                session_dir=str(tmp_path),
                dry_run=True,
                cooldown=0,
                seed=seed,
            )
        finally:
            MockTransport.send = original_send
        return hashlib.sha256(b"".join(sent)).hexdigest(), len(sent)

    a = _capture(42)
    b = _capture(42)
    c = _capture(43)

    assert a[0] == b[0], f"same seed must produce identical payloads: {a} vs {b}"
    assert a[1] == b[1] == c[1], "packet counts must be deterministic"
    assert a[0] != c[0], f"different seeds must produce different payloads: {a} vs {c}"


def test_run_campaign_dry_run_no_seed_is_non_deterministic(tmp_path):
    """Without a seed, run_campaign falls back to os.urandom and two
    runs must produce different payloads. This guards against the
    ContextVar accidentally retaining a seeded source across calls."""
    import hashlib
    from blue_tap.modules.fuzzing.transport import MockTransport

    def _capture() -> str:
        sent: list[bytes] = []
        original_send = MockTransport.send

        def _spy(self, data):
            sent.append(bytes(data))
            return original_send(self, data)

        MockTransport.send = _spy
        try:
            run_campaign(
                target="AA:BB:CC:DD:EE:FF",
                protocols=["l2cap"],
                strategy="random",
                max_iterations=10,
                session_dir=str(tmp_path),
                dry_run=True,
                cooldown=0,
            )
        finally:
            MockTransport.send = original_send
        return hashlib.sha256(b"".join(sent)).hexdigest()

    a = _capture()
    b = _capture()
    assert a != b, "without seed, two runs must produce different payloads"


def test_set_random_source_restores_previous_on_exit():
    """The ContextVar context manager must restore the previous source
    even when the with-block raises — production callers depend on this
    for nested benchmarks and exception-safe cleanup."""
    from blue_tap.modules.fuzzing._random import (
        random_bytes,
        set_random_source,
    )

    # Default source is os.urandom — produces 16 unpredictable bytes.
    before = random_bytes(16)

    # Inside the block, the source is the canned callable.
    with set_random_source(lambda n: b"\x42" * n):
        assert random_bytes(8) == b"\x42" * 8
        try:
            with set_random_source(lambda n: b"\x01" * n):
                assert random_bytes(4) == b"\x01\x01\x01\x01"
                raise RuntimeError("simulated failure mid-block")
        except RuntimeError:
            pass
        # Outer source restored, even though inner raised.
        assert random_bytes(8) == b"\x42" * 8

    # Original source restored.
    after = random_bytes(16)
    assert after != before  # both came from os.urandom (different)
    # Most importantly, the constant source is gone.
    assert after != b"\x42" * 16


def test_set_random_source_rejects_non_callable():
    import pytest
    from blue_tap.modules.fuzzing._random import set_random_source

    with pytest.raises(TypeError, match="callable"):
        with set_random_source(b"\x00" * 16):  # type: ignore[arg-type]
            pass


def test_random_bytes_rejects_negative_length():
    import pytest
    from blue_tap.modules.fuzzing._random import random_bytes

    with pytest.raises(ValueError, match="non-negative"):
        random_bytes(-1)


def test_list_strategies_and_protocols_are_tuples_of_str():
    strategies = list_strategies()
    protocols = list_protocols()

    assert isinstance(strategies, tuple)
    assert isinstance(protocols, tuple)
    assert len(strategies) > 0
    assert len(protocols) > 0
    assert all(isinstance(s, str) for s in strategies)
    assert all(isinstance(p, str) for p in protocols)
    # The default in run_campaign must be a member of the listed strategies
    assert "coverage_guided" in strategies
    assert "l2cap" in protocols


# ---------------------------------------------------------------------------
# v2.6.4 additions: env-var seed, to_csv, derive_random_source_from_seed
# ---------------------------------------------------------------------------


def test_derive_random_source_from_seed_is_deterministic():
    from blue_tap.modules.fuzzing._random import derive_random_source_from_seed

    a = derive_random_source_from_seed(7)
    b = derive_random_source_from_seed(7)
    # Two independent sources with the same seed produce identical streams.
    for _ in range(8):
        assert a(16) == b(16)


def test_derive_random_source_from_seed_rejects_non_int():
    from blue_tap.modules.fuzzing._random import derive_random_source_from_seed

    with pytest.raises(TypeError, match="int"):
        derive_random_source_from_seed("42")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="int"):
        derive_random_source_from_seed(True)  # bool is rejected explicitly


def test_derive_random_source_from_seed_rejects_negative_n():
    from blue_tap.modules.fuzzing._random import derive_random_source_from_seed

    src = derive_random_source_from_seed(0)
    with pytest.raises(ValueError, match="non-negative"):
        src(-1)


def test_run_campaign_reads_seed_from_env(tmp_path, monkeypatch):
    """Without an explicit seed kwarg, BLUE_TAP_FUZZ_SEED must drive determinism."""
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "12345")
    a = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=20,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
    )
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "12345")
    b = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=20,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
    )
    assert a.error is None and b.error is None
    assert a.protocol_breakdown == b.protocol_breakdown
    assert a.iterations == b.iterations
    assert a.packets_sent == b.packets_sent


def test_run_campaign_explicit_seed_overrides_env(tmp_path, monkeypatch):
    """An explicit seed kwarg must take precedence over BLUE_TAP_FUZZ_SEED."""
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "1")
    explicit = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=20,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
        seed=999,
    )
    # Same explicit seed, different env var → still reproducible from kwarg.
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "987654321")
    repro = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=20,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
        seed=999,
    )
    assert explicit.error is None and repro.error is None
    assert explicit.protocol_breakdown == repro.protocol_breakdown


def test_run_campaign_env_seed_invalid_raises_valueerror(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "not-an-int")
    with pytest.raises(ValueError, match="BLUE_TAP_FUZZ_SEED"):
        run_campaign(
            target="00:00:00:00:00:00",
            protocols=["sdp"],
            strategy="random",
            max_iterations=5,
            session_dir=str(tmp_path),
            cooldown=0.0,
            dry_run=True,
        )


def test_run_campaign_env_seed_accepts_hex(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "0x2a")
    result = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=10,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
    )
    # 0x2a == 42; matches an explicit seed=42 run.
    explicit = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=10,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
        seed=42,
    )
    assert result.protocol_breakdown == explicit.protocol_breakdown


def test_benchmark_uses_env_base_seed_when_omitted(tmp_path, monkeypatch):
    """benchmark() falls back to BLUE_TAP_FUZZ_SEED so trials get distinct seeds."""
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "100")
    result_env = benchmark(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        trials=2,
        max_iterations=10,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
    )
    result_explicit = benchmark(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        trials=2,
        max_iterations=10,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
        base_seed=100,
    )
    # Both produce the same trial sequence: trial[i] uses seed 100+i.
    for a, b in zip(result_env.trials, result_explicit.trials):
        assert a.protocol_breakdown == b.protocol_breakdown


def test_campaign_result_to_csv_writes_header_only_for_empty_trajectory(tmp_path):
    result = CampaignResult(
        target="aa:bb",
        protocols=["sdp"],
        strategy="random",
    )
    out = tmp_path / "empty.csv"
    written = result.to_csv(out)
    assert written == str(out)
    text = out.read_text()
    # Header only, no data rows.
    assert text.strip() == (
        "elapsed_seconds,iterations,packets_sent,crashes,errors,states,transitions"
    )


def test_campaign_result_to_csv_writes_rows_in_fixed_order(tmp_path):
    result = CampaignResult(
        target="aa:bb",
        protocols=["sdp"],
        strategy="random",
        trajectory=[
            {"elapsed_seconds": 0.1, "iterations": 5, "packets_sent": 5,
             "crashes": 0, "errors": 0, "states": 1, "transitions": 1,
             "extra_key_should_be_dropped": "ignore me"},
            {"elapsed_seconds": 0.2, "iterations": 12, "packets_sent": 12,
             "crashes": 1, "errors": 0, "states": 2, "transitions": 3},
        ],
    )
    out = tmp_path / "traj.csv"
    result.to_csv(out)
    lines = out.read_text().splitlines()
    assert lines[0] == (
        "elapsed_seconds,iterations,packets_sent,crashes,errors,states,transitions"
    )
    assert lines[1] == "0.1,5,5,0,0,1,1"
    assert lines[2] == "0.2,12,12,1,0,2,3"
    # extra_key_should_be_dropped silently ignored.
    assert "ignore me" not in out.read_text()


def test_campaign_result_to_csv_skips_non_dict_rows(tmp_path):
    result = CampaignResult(
        target="aa:bb",
        protocols=["sdp"],
        strategy="random",
        trajectory=[
            {"elapsed_seconds": 0.1, "iterations": 1, "packets_sent": 1,
             "crashes": 0, "errors": 0, "states": 0, "transitions": 0},
            "not a dict",  # type: ignore[list-item]
            None,  # type: ignore[list-item]
            {"elapsed_seconds": 0.2, "iterations": 2, "packets_sent": 2,
             "crashes": 0, "errors": 0, "states": 0, "transitions": 0},
        ],
    )
    out = tmp_path / "traj.csv"
    result.to_csv(out)
    rows = out.read_text().splitlines()
    # Header + 2 valid dict rows.
    assert len(rows) == 3


def test_campaign_result_to_csv_rejects_missing_parent_dir(tmp_path):
    result = CampaignResult(target="aa:bb", protocols=["sdp"], strategy="random")
    bogus = tmp_path / "does" / "not" / "exist" / "out.csv"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        result.to_csv(bogus)


def test_campaign_result_to_csv_atomic_no_partial_on_replace_path(tmp_path):
    """The output directory must end with exactly one CSV — no temp leftovers."""
    result = CampaignResult(
        target="aa:bb",
        protocols=["sdp"],
        strategy="random",
        trajectory=[
            {"elapsed_seconds": 0.1, "iterations": 1, "packets_sent": 1,
             "crashes": 0, "errors": 0, "states": 0, "transitions": 0},
        ],
    )
    out = tmp_path / "atomic.csv"
    result.to_csv(out)
    survivors = sorted(p.name for p in tmp_path.iterdir())
    assert survivors == ["atomic.csv"], survivors


def test_run_campaign_dry_run_with_env_seed_produces_csv_with_data(tmp_path, monkeypatch):
    """End-to-end: env seed + dry_run + trajectory_interval → non-empty CSV."""
    monkeypatch.setenv("BLUE_TAP_FUZZ_SEED", "42")
    result = run_campaign(
        target="00:00:00:00:00:00",
        protocols=["sdp"],
        strategy="random",
        max_iterations=200,
        session_dir=str(tmp_path),
        cooldown=0.0,
        dry_run=True,
        trajectory_interval_seconds=0.05,
    )
    assert result.error is None
    out = tmp_path / "traj.csv"
    result.to_csv(out)
    rows = out.read_text().splitlines()
    # Header + at least one trajectory sample.
    assert len(rows) >= 2
    assert rows[0].startswith("elapsed_seconds,")
