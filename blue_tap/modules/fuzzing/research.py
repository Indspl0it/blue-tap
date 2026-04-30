"""Programmatic research API for the BT-Tap fuzzing engine.

This module provides a small, typed surface for driving fuzzing campaigns
from notebooks, benchmarks, and ablation studies — without going through
the CLI / RunContext / RunEnvelope plumbing.

Two entry points:

- :func:`run_campaign`: construct + execute a :class:`FuzzCampaign` and
  return a typed :class:`CampaignResult`.
- :func:`compare_campaigns`: compute a per-metric delta between two
  results (e.g. ``coverage_guided`` vs ``random`` on the same target).

The summary keys come from :meth:`FuzzCampaign._build_summary`. This
module is a stable, named view over those keys so research code can
depend on field names rather than dict-string-literals.
"""

from __future__ import annotations

import csv
import json
import logging
import math
import os
import random
import statistics
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Trajectory CSV column order. Matches the keys emitted by
# :meth:`FuzzCampaign._maybe_record_trajectory` so to_csv writes a stable
# schema regardless of dict-iteration order.
_TRAJECTORY_CSV_FIELDS: tuple[str, ...] = (
    "elapsed_seconds",
    "iterations",
    "packets_sent",
    "crashes",
    "errors",
    "states",
    "transitions",
)

# Environment variable that supplies a default seed when ``run_campaign``
# is invoked without an explicit ``seed=`` keyword. Lets CI / repro
# pipelines lock down byte-level reproducibility without code changes.
_SEED_ENV_VAR = "BLUE_TAP_FUZZ_SEED"

logger = logging.getLogger(__name__)


@dataclass
class CampaignResult:
    """Typed summary of a single fuzzing campaign run.

    Constructed by :func:`run_campaign`. All fields default to safe
    zeroes so partial / aborted runs still produce a well-formed result.
    """

    target: str
    protocols: list[str]
    strategy: str
    iterations: int = 0
    packets_sent: int = 0
    crashes: int = 0
    errors: int = 0
    reconnects: int = 0
    runtime_seconds: float = 0.0
    packets_per_second: float = 0.0
    crash_rate_per_1000: float = 0.0
    protocol_breakdown: dict[str, int] = field(default_factory=dict)
    state_coverage: dict[str, Any] = field(default_factory=dict)
    field_weights: dict[str, Any] = field(default_factory=dict)
    health_monitor: dict[str, Any] = field(default_factory=dict)
    trajectory: list[dict[str, Any]] = field(default_factory=list)
    aborted: bool = False
    error: str | None = None
    raw_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def crashes_per_kpkt(self) -> float:
        """Crashes per 1000 packets — primary research-grade efficacy metric."""
        return self.crash_rate_per_1000

    @property
    def states_discovered(self) -> int:
        """Total protocol states discovered across all tracked graphs."""
        return int(self.state_coverage.get("total_states", 0) or 0)

    @property
    def transitions_discovered(self) -> int:
        """Total state-machine transitions observed."""
        return int(self.state_coverage.get("total_transitions", 0) or 0)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (no dataclass artefacts)."""
        return {
            "target": self.target,
            "protocols": list(self.protocols),
            "strategy": self.strategy,
            "iterations": self.iterations,
            "packets_sent": self.packets_sent,
            "crashes": self.crashes,
            "errors": self.errors,
            "reconnects": self.reconnects,
            "runtime_seconds": self.runtime_seconds,
            "packets_per_second": self.packets_per_second,
            "crash_rate_per_1000": self.crash_rate_per_1000,
            "protocol_breakdown": dict(self.protocol_breakdown),
            "state_coverage": dict(self.state_coverage),
            "field_weights": dict(self.field_weights),
            "health_monitor": dict(self.health_monitor),
            "trajectory": [dict(s) for s in self.trajectory],
            "aborted": self.aborted,
            "error": self.error,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialise to a JSON string. Excludes ``raw_summary``."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, payload: str | bytes) -> CampaignResult:
        """Reconstruct from a string produced by :meth:`to_json`.

        Round-trips on every field except ``raw_summary``, which is
        omitted from :meth:`to_dict` by design.
        """
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("CampaignResult.from_json requires a JSON object")
        return cls(
            target=str(data.get("target", "")),
            protocols=list(data.get("protocols", []) or []),
            strategy=str(data.get("strategy", "")),
            iterations=int(data.get("iterations", 0) or 0),
            packets_sent=int(data.get("packets_sent", 0) or 0),
            crashes=int(data.get("crashes", 0) or 0),
            errors=int(data.get("errors", 0) or 0),
            reconnects=int(data.get("reconnects", 0) or 0),
            runtime_seconds=float(data.get("runtime_seconds", 0.0) or 0.0),
            packets_per_second=float(data.get("packets_per_second", 0.0) or 0.0),
            crash_rate_per_1000=float(data.get("crash_rate_per_1000", 0.0) or 0.0),
            protocol_breakdown=dict(data.get("protocol_breakdown", {}) or {}),
            state_coverage=dict(data.get("state_coverage", {}) or {}),
            field_weights=dict(data.get("field_weights", {}) or {}),
            health_monitor=dict(data.get("health_monitor", {}) or {}),
            trajectory=[dict(s) for s in (data.get("trajectory") or [])],
            aborted=bool(data.get("aborted", False)),
            error=data.get("error"),
        )

    def to_csv(self, path: str | os.PathLike[str]) -> str:
        """Write the trajectory rows to *path* as CSV. Returns the resolved path.

        Columns (fixed order):
            ``elapsed_seconds``, ``iterations``, ``packets_sent``,
            ``crashes``, ``errors``, ``states``, ``transitions``.

        Behaviour:

        - An empty trajectory still produces a header-only file — callers
          processing batches don't need to special-case missing files.
        - The write is atomic: a sibling temp file is fully written and
          ``fsync``'d, then ``os.replace``'d onto *path* so an interrupted
          write can never leave a half-formed CSV.
        - Missing keys in a trajectory row become empty CSV cells; extra
          keys are silently dropped (``extrasaction="ignore"``).

        Raises:
            OSError: if the parent directory is not writable.
        """
        target = os.fspath(path)
        parent = os.path.dirname(os.path.abspath(target)) or "."
        if not os.path.isdir(parent):
            raise FileNotFoundError(
                f"to_csv: parent directory does not exist: {parent}"
            )
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=parent,
                delete=False,
                newline="",
                suffix=".csv.tmp",
                encoding="utf-8",
            ) as tmp:
                tmp_name = tmp.name
                writer = csv.DictWriter(
                    tmp,
                    fieldnames=list(_TRAJECTORY_CSV_FIELDS),
                    extrasaction="ignore",
                )
                writer.writeheader()
                for row in self.trajectory:
                    if not isinstance(row, dict):
                        continue
                    writer.writerow(
                        {field_name: row.get(field_name, "")
                         for field_name in _TRAJECTORY_CSV_FIELDS}
                    )
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, target)
            tmp_name = None
            return target
        finally:
            if tmp_name is not None and os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except OSError:
                    logger.warning(
                        "to_csv: failed to clean up temp file %s", tmp_name
                    )

    @classmethod
    def from_summary(cls, summary: dict[str, Any], *, aborted: bool = False,
                     error: str | None = None) -> CampaignResult:
        """Build a :class:`CampaignResult` from a ``FuzzCampaign._build_summary`` dict."""
        return cls(
            target=str(summary.get("target", "")),
            protocols=list(summary.get("protocols", []) or []),
            strategy=str(summary.get("strategy", "")),
            iterations=int(summary.get("iterations", 0) or 0),
            packets_sent=int(summary.get("packets_sent", 0) or 0),
            crashes=int(summary.get("crashes", 0) or 0),
            errors=int(summary.get("errors", 0) or 0),
            reconnects=int(summary.get("reconnects", 0) or 0),
            runtime_seconds=float(summary.get("runtime_seconds", 0.0) or 0.0),
            packets_per_second=float(summary.get("packets_per_second", 0.0) or 0.0),
            crash_rate_per_1000=float(summary.get("crash_rate_per_1000", 0.0) or 0.0),
            protocol_breakdown=dict(summary.get("protocol_breakdown", {}) or {}),
            state_coverage=dict(summary.get("state_coverage", {}) or {}),
            field_weights=dict(summary.get("field_weights", {}) or {}),
            health_monitor=dict(summary.get("health_monitor", {}) or {}),
            trajectory=[dict(s) for s in (summary.get("trajectory") or [])],
            aborted=aborted,
            error=error,
            raw_summary=dict(summary),
        )


@dataclass
class CampaignDelta:
    """Per-metric delta between two campaigns. Positive = ``b > a``."""

    a: CampaignResult
    b: CampaignResult
    iterations: int
    packets_sent: int
    crashes: int
    errors: int
    runtime_seconds: float
    crashes_per_kpkt: float
    states_discovered: int
    transitions_discovered: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "a_strategy": self.a.strategy,
            "b_strategy": self.b.strategy,
            "iterations": self.iterations,
            "packets_sent": self.packets_sent,
            "crashes": self.crashes,
            "errors": self.errors,
            "runtime_seconds": self.runtime_seconds,
            "crashes_per_kpkt": self.crashes_per_kpkt,
            "states_discovered": self.states_discovered,
            "transitions_discovered": self.transitions_discovered,
        }


def run_campaign(
    target: str,
    protocols: list[str] | tuple[str, ...],
    *,
    strategy: str = "coverage_guided",
    duration: float | None = None,
    max_iterations: int | None = None,
    session_dir: str = ".",
    cooldown: float = 0.5,
    transport_overrides: dict[str, dict[str, Any]] | None = None,
    run_id: str = "",
    seed: int | None = None,
    dry_run: bool = False,
    random_source: Callable[[int], bytes] | None = None,
    trajectory_interval_seconds: float | None = None,
) -> CampaignResult:
    """Run a single fuzzing campaign and return a typed :class:`CampaignResult`.

    All keyword arguments correspond directly to :class:`FuzzCampaign.__init__`,
    plus several research-grade hooks:

    - ``seed``: byte-level reproducibility. Calls :func:`random.seed`
      to lock down :mod:`random`-driven decisions (protocol rotation,
      mutation op choice, lengths, indices) and, when ``random_source``
      is not supplied, derives a seeded byte source via
      :func:`blue_tap.modules.fuzzing._random.derive_random_source_from_seed`.
      That source is installed via the campaign-scoped
      :class:`contextvars.ContextVar` in
      :mod:`blue_tap.modules.fuzzing._random`. Every strategy, mutator,
      and protocol builder reads bytes through that ContextVar, so two
      runs with the same seed produce byte-identical fuzz payloads.
      When ``seed`` is omitted, the ``BLUE_TAP_FUZZ_SEED`` environment
      variable is consulted (decimal, ``0x``-hex, or ``0o``-octal). A
      malformed value raises :class:`ValueError` at the boundary.
    - ``random_source``: explicit ``Callable[[int], bytes]`` installed
      via the same ContextVar mechanism. Takes precedence over
      ``seed``-derived determinism. Restored on exit (including
      exception paths).
    - ``dry_run``: route every protocol through
      :class:`~blue_tap.modules.fuzzing.transport.MockTransport`,
      bypass the pre-loop ``l2ping`` reachability check, and skip
      crash-recovery liveness probes. The campaign still runs the
      full mutation/strategy/state-tracker pipeline — only the wire
      layer and the alive-checks are replaced.
    - ``trajectory_interval_seconds``: when set (>0), the engine
      snapshots ``(iterations, packets_sent, crashes, states,
      transitions, ...)`` at most once per interval inside the main
      loop. The samples land in :attr:`CampaignResult.trajectory`.

    Catches :class:`KeyboardInterrupt` (records ``aborted=True``) and any other
    exception (records ``error=...``) so callers driving batch experiments
    never crash on a single bad run.

    Note: this is a *thin* wrapper. It does not load Module/RunContext/CLI
    state. Use the CLI ``blue-tap fuzz campaign`` for operator workflows;
    use this for benchmarking, ablation, and research notebooks.
    """
    from blue_tap.modules.fuzzing._random import derive_random_source_from_seed
    from blue_tap.modules.fuzzing.engine import FuzzCampaign

    proto_list = [str(p).strip().lower() for p in protocols if str(p).strip()]
    if not proto_list:
        raise ValueError("run_campaign requires at least one protocol")

    # Resolve seed: explicit kwarg > BLUE_TAP_FUZZ_SEED env var > None.
    # Env var lets CI pipelines and repro scripts lock down reproducibility
    # without touching code. Validated at the boundary so a malformed value
    # fails loudly with a precise message instead of a cryptic random.seed
    # TypeError later.
    if seed is None:
        env_seed_raw = os.environ.get(_SEED_ENV_VAR)
        if env_seed_raw is not None and env_seed_raw.strip():
            try:
                seed = int(env_seed_raw.strip(), 0)
            except ValueError as exc:
                raise ValueError(
                    f"{_SEED_ENV_VAR} must be an integer literal "
                    f"(decimal, 0x-hex, or 0o-octal); got {env_seed_raw!r}"
                ) from exc
            logger.info(
                "run_campaign: seed=%d loaded from %s", seed, _SEED_ENV_VAR
            )

    effective_random_source = random_source
    if seed is not None:
        # Seed the global :mod:`random` module too so any callsite that
        # *isn't* yet plumbed through random_bytes (e.g. ad-hoc list
        # shuffling) is also locked. Keeps the repro contract intact even
        # if a future patch forgets to thread random_bytes through a new
        # call site.
        random.seed(seed)
        if effective_random_source is None:
            # Derive a deterministic byte source from a private seeded
            # PRNG. Installed campaign-wide via the ContextVar in
            # blue_tap.modules.fuzzing._random so every strategy /
            # mutator / protocol builder reads bytes from it — full
            # byte-level reproducibility, not just engine fallback paths.
            effective_random_source = derive_random_source_from_seed(seed)

    campaign = FuzzCampaign(
        target=target,
        protocols=proto_list,
        strategy=strategy,
        duration=duration,
        max_iterations=max_iterations,
        session_dir=session_dir,
        cooldown=cooldown,
        run_id=run_id,
        transport_overrides=transport_overrides,
        random_source=effective_random_source,
        dry_run=dry_run,
        trajectory_interval_seconds=trajectory_interval_seconds,
    )

    aborted = False
    error_text: str | None = None
    try:
        summary = campaign.run()
    except KeyboardInterrupt:
        logger.info("run_campaign: interrupted")
        aborted = True
        summary = campaign._build_summary()
    except Exception as exc:
        logger.exception("run_campaign: campaign failed")
        error_text = f"{type(exc).__name__}: {exc}"
        summary = campaign._build_summary()

    if not isinstance(summary, dict):
        summary = {}

    # Engine reports terminal failure modes via {"result": "error",
    # "reason": "..."}. Surface that to the caller so a "successful"
    # CampaignResult with all-zero stats isn't silently misleading.
    if error_text is None and summary.get("result") == "error":
        reason = summary.get("reason") or "engine_error"
        error_text = f"engine: {reason}"

    return CampaignResult.from_summary(summary, aborted=aborted, error=error_text)


def compare_campaigns(a: CampaignResult, b: CampaignResult) -> CampaignDelta:
    """Compute a metric-by-metric delta between two campaign results.

    Useful for ablations like ``compare_campaigns(rand, coverage)`` where
    you want to know how many extra crashes/states the smarter strategy
    found per unit of runtime.
    """
    return CampaignDelta(
        a=a,
        b=b,
        iterations=b.iterations - a.iterations,
        packets_sent=b.packets_sent - a.packets_sent,
        crashes=b.crashes - a.crashes,
        errors=b.errors - a.errors,
        runtime_seconds=b.runtime_seconds - a.runtime_seconds,
        crashes_per_kpkt=b.crashes_per_kpkt - a.crashes_per_kpkt,
        states_discovered=b.states_discovered - a.states_discovered,
        transitions_discovered=b.transitions_discovered - a.transitions_discovered,
    )


# ---------------------------------------------------------------------------
# Multi-trial benchmarking
# ---------------------------------------------------------------------------


def _stats(samples: list[float]) -> dict[str, float]:
    """Mean / stddev / median / min / max for a sample list. Empty → zeroes."""
    if not samples:
        return {"mean": 0.0, "stdev": 0.0, "median": 0.0, "min": 0.0, "max": 0.0,
                "n": 0}
    return {
        "mean": float(statistics.fmean(samples)),
        "stdev": float(statistics.pstdev(samples)) if len(samples) > 1 else 0.0,
        "median": float(statistics.median(samples)),
        "min": float(min(samples)),
        "max": float(max(samples)),
        "n": len(samples),
    }


@dataclass
class BenchmarkResult:
    """Aggregated stats across N trials of the same configuration.

    Use :func:`benchmark` to construct. Each trial is a full
    :class:`CampaignResult`; the aggregate fields below summarise the
    distribution so callers can make sense of variance without
    re-implementing :mod:`statistics` calls.
    """

    label: str
    strategy: str
    trials: list[CampaignResult]
    crashes: dict[str, float] = field(default_factory=dict)
    crashes_per_kpkt: dict[str, float] = field(default_factory=dict)
    iterations: dict[str, float] = field(default_factory=dict)
    packets_sent: dict[str, float] = field(default_factory=dict)
    runtime_seconds: dict[str, float] = field(default_factory=dict)
    states_discovered: dict[str, float] = field(default_factory=dict)
    aborted_trials: int = 0
    error_trials: int = 0

    @classmethod
    def from_trials(cls, label: str, strategy: str,
                    trials: list[CampaignResult]) -> BenchmarkResult:
        return cls(
            label=label,
            strategy=strategy,
            trials=trials,
            crashes=_stats([float(t.crashes) for t in trials]),
            crashes_per_kpkt=_stats([t.crashes_per_kpkt for t in trials]),
            iterations=_stats([float(t.iterations) for t in trials]),
            packets_sent=_stats([float(t.packets_sent) for t in trials]),
            runtime_seconds=_stats([t.runtime_seconds for t in trials]),
            states_discovered=_stats([float(t.states_discovered) for t in trials]),
            aborted_trials=sum(1 for t in trials if t.aborted),
            error_trials=sum(1 for t in trials if t.error is not None),
        )

    def to_dict(self, *, include_trials: bool = True) -> dict[str, Any]:
        """Serialise to a plain dict.

        ``include_trials=True`` (default) embeds each trial via
        :meth:`CampaignResult.to_dict` so the result round-trips through
        :meth:`from_dict`. Pass ``include_trials=False`` for compact
        summary output (dashboards, log lines).
        """
        payload: dict[str, Any] = {
            "label": self.label,
            "strategy": self.strategy,
            "n_trials": len(self.trials),
            "aborted_trials": self.aborted_trials,
            "error_trials": self.error_trials,
            "crashes": dict(self.crashes),
            "crashes_per_kpkt": dict(self.crashes_per_kpkt),
            "iterations": dict(self.iterations),
            "packets_sent": dict(self.packets_sent),
            "runtime_seconds": dict(self.runtime_seconds),
            "states_discovered": dict(self.states_discovered),
        }
        if include_trials:
            payload["trials"] = [t.to_dict() for t in self.trials]
        return payload

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialise to JSON. Always includes per-trial data for round-trip."""
        return json.dumps(self.to_dict(include_trials=True),
                          indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkResult:
        """Reconstruct from a :meth:`to_dict` (with ``include_trials=True``) payload.

        Raises :class:`ValueError` on a missing ``trials`` key — the
        compact form (``include_trials=False``) is intentionally not
        round-trippable, since aggregate stats alone can't reproduce
        per-trial state.
        """
        if "trials" not in data:
            raise ValueError(
                "BenchmarkResult.from_dict requires per-trial data; "
                "the payload was produced with include_trials=False"
            )
        trials = [CampaignResult.from_json(json.dumps(t)) for t in data["trials"]]
        return cls.from_trials(
            label=str(data.get("label", "")),
            strategy=str(data.get("strategy", "")),
            trials=trials,
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> BenchmarkResult:
        """Reconstruct from a string produced by :meth:`to_json`."""
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("BenchmarkResult.from_json requires a JSON object")
        return cls.from_dict(data)


def benchmark(
    target: str,
    protocols: list[str] | tuple[str, ...],
    *,
    strategy: str = "coverage_guided",
    trials: int = 5,
    label: str | None = None,
    base_seed: int | None = None,
    duration: float | None = None,
    max_iterations: int | None = None,
    session_dir: str = ".",
    cooldown: float = 0.5,
    transport_overrides: dict[str, dict[str, Any]] | None = None,
    dry_run: bool = False,
    trajectory_interval_seconds: float | None = None,
) -> BenchmarkResult:
    """Run ``trials`` campaigns with the same config and aggregate the stats.

    If ``base_seed`` is provided each trial ``i`` uses ``base_seed + i`` so
    repeated calls to :func:`benchmark` with the same ``base_seed`` produce
    the same trial sequence (best-effort — see :func:`run_campaign`).

    Errored / aborted trials are kept in :attr:`BenchmarkResult.trials` and
    counted separately in ``aborted_trials`` / ``error_trials`` so callers
    can decide whether to discard them before reporting.
    """
    if trials < 1:
        raise ValueError("benchmark requires trials >= 1")

    # When base_seed is omitted, fall back to BLUE_TAP_FUZZ_SEED so that
    # successive trials still get distinct seeds (base, base+1, base+2,
    # ...) instead of the env var being applied identically to every
    # trial — which would collapse the variance measurement and silently
    # mislead the caller.
    if base_seed is None:
        env_seed_raw = os.environ.get(_SEED_ENV_VAR)
        if env_seed_raw is not None and env_seed_raw.strip():
            try:
                base_seed = int(env_seed_raw.strip(), 0)
            except ValueError as exc:
                raise ValueError(
                    f"{_SEED_ENV_VAR} must be an integer literal "
                    f"(decimal, 0x-hex, or 0o-octal); got {env_seed_raw!r}"
                ) from exc
            logger.info(
                "benchmark: base_seed=%d loaded from %s",
                base_seed, _SEED_ENV_VAR,
            )

    results: list[CampaignResult] = []
    for i in range(trials):
        trial_seed = (base_seed + i) if base_seed is not None else None
        logger.info("benchmark: trial %d/%d strategy=%s seed=%s",
                    i + 1, trials, strategy, trial_seed)
        results.append(run_campaign(
            target=target,
            protocols=protocols,
            strategy=strategy,
            duration=duration,
            max_iterations=max_iterations,
            session_dir=session_dir,
            cooldown=cooldown,
            transport_overrides=transport_overrides,
            seed=trial_seed,
            dry_run=dry_run,
            trajectory_interval_seconds=trajectory_interval_seconds,
        ))

    return BenchmarkResult.from_trials(
        label=label or f"{strategy}@{trials}",
        strategy=strategy,
        trials=results,
    )


@dataclass
class BenchmarkComparison:
    """Effect-size comparison between two :class:`BenchmarkResult` runs.

    ``cohens_d`` is computed on the per-trial ``crashes_per_kpkt`` series
    using the pooled-stdev convention. Conventional thresholds:
    |d| < 0.2 trivial, 0.2-0.5 small, 0.5-0.8 medium, > 0.8 large.

    ``mean_delta`` fields report ``b.mean - a.mean`` for each metric so
    sign matches the question "did B beat A?".
    """

    a: BenchmarkResult
    b: BenchmarkResult
    cohens_d_crashes_per_kpkt: float
    mean_delta_crashes: float
    mean_delta_crashes_per_kpkt: float
    mean_delta_runtime_seconds: float
    mean_delta_states_discovered: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "a_label": self.a.label,
            "b_label": self.b.label,
            "cohens_d_crashes_per_kpkt": self.cohens_d_crashes_per_kpkt,
            "mean_delta_crashes": self.mean_delta_crashes,
            "mean_delta_crashes_per_kpkt": self.mean_delta_crashes_per_kpkt,
            "mean_delta_runtime_seconds": self.mean_delta_runtime_seconds,
            "mean_delta_states_discovered": self.mean_delta_states_discovered,
        }


def _cohens_d(a_samples: list[float], b_samples: list[float]) -> float:
    """Cohen's d with pooled standard deviation. Returns 0.0 if undefined."""
    if len(a_samples) < 2 or len(b_samples) < 2:
        return 0.0
    mean_a = statistics.fmean(a_samples)
    mean_b = statistics.fmean(b_samples)
    var_a = statistics.variance(a_samples)
    var_b = statistics.variance(b_samples)
    pooled = math.sqrt((var_a + var_b) / 2.0)
    if pooled == 0.0:
        return 0.0
    return (mean_b - mean_a) / pooled


def compare_benchmarks(a: BenchmarkResult, b: BenchmarkResult) -> BenchmarkComparison:
    """Aggregate two benchmark runs into mean-delta + effect-size form.

    The headline metric is Cohen's d on ``crashes_per_kpkt`` because that's
    the protocol-throughput-normalised efficacy measure. Mean deltas on the
    other axes are reported alongside for context (a strategy can trade
    runtime for coverage; you want to see both).
    """
    a_cpk = [t.crashes_per_kpkt for t in a.trials]
    b_cpk = [t.crashes_per_kpkt for t in b.trials]
    return BenchmarkComparison(
        a=a,
        b=b,
        cohens_d_crashes_per_kpkt=_cohens_d(a_cpk, b_cpk),
        mean_delta_crashes=b.crashes["mean"] - a.crashes["mean"],
        mean_delta_crashes_per_kpkt=b.crashes_per_kpkt["mean"] - a.crashes_per_kpkt["mean"],
        mean_delta_runtime_seconds=b.runtime_seconds["mean"] - a.runtime_seconds["mean"],
        mean_delta_states_discovered=b.states_discovered["mean"] - a.states_discovered["mean"],
    )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def list_strategies() -> tuple[str, ...]:
    """Names accepted by :func:`run_campaign` ``strategy=...``."""
    from blue_tap.modules.fuzzing.campaign import STRATEGIES
    return tuple(STRATEGIES)


def list_protocols() -> tuple[str, ...]:
    """Protocol names accepted by :func:`run_campaign` ``protocols=...``."""
    from blue_tap.modules.fuzzing.campaign import PROTOCOLS
    return tuple(PROTOCOLS)


__all__ = [
    "BenchmarkComparison",
    "BenchmarkResult",
    "CampaignDelta",
    "CampaignResult",
    "benchmark",
    "compare_benchmarks",
    "compare_campaigns",
    "list_protocols",
    "list_strategies",
    "run_campaign",
]
