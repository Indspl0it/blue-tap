"""Campaign engine -- orchestrates multi-protocol, multi-hour fuzzing campaigns.

The ``FuzzCampaign`` class manages the full lifecycle of a fuzzing run:
protocol selection, transport setup, seed corpus loading, mutation,
crash detection and logging, target health monitoring, graceful shutdown,
and session persistence for resume.

Usage::

    campaign = FuzzCampaign(
        target="AA:BB:CC:DD:EE:FF",
        protocols=["sdp", "rfcomm", "bnep"],
        duration=parse_duration("2h"),
        session_dir="sessions/my_assessment",
    )
    campaign.run()
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import socket
import time
import traceback

logger = logging.getLogger(__name__)
from dataclasses import asdict, dataclass, field
from datetime import datetime
from collections.abc import Callable, Generator
from typing import Any


from blue_tap.utils.output import (
    console,
    info,
    success,
    error,
    warning,
    section,
    summary_panel,
    bare_table,
    print_table,
    CYAN,
    GREEN,
    YELLOW,
    RED,
    DIM,
    PURPLE,
)
from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.framework.sessions.store import log_command
from blue_tap.framework.envelopes.fuzz import (
    build_fuzz_campaign_result,
    build_fuzz_protocol_execution,
    campaign_started_at_from_stats,
)
from blue_tap.framework.contracts.result_schema import now_iso, validate_run_envelope
from blue_tap.framework.runtime.cli_events import emit_cli_event

# ---------------------------------------------------------------------------
# Core module imports — always available
# ---------------------------------------------------------------------------

from blue_tap.modules.fuzzing.transport import (
    L2CAPTransport,
    RFCOMMTransport,
    BLETransport,
    LMPTransport,
    RawACLTransport,
)
from blue_tap.modules.fuzzing._random import random_bytes, set_random_source
from blue_tap.modules.fuzzing.crash_db import CrashDB
from blue_tap.modules.fuzzing.corpus import Corpus
from blue_tap.modules.fuzzing.mutators import CorpusMutator

# ---------------------------------------------------------------------------
# Optional advanced features — degrade gracefully when unavailable
# ---------------------------------------------------------------------------

try:
    from blue_tap.modules.fuzzing.strategies.random_walk import RandomWalkStrategy
    from blue_tap.modules.fuzzing.strategies.coverage_guided import CoverageGuidedStrategy
    from blue_tap.modules.fuzzing.strategies.state_machine import StateMachineStrategy
    _HAS_STRATEGIES = True
except ImportError:
    _HAS_STRATEGIES = False
    logger.info("Fuzzing strategies not available — falling back to byte-level mutation")

try:
    from blue_tap.modules.fuzzing.strategies.targeted import TargetedStrategy
    _HAS_TARGETED = True
except ImportError:
    _HAS_TARGETED = False
    logger.info("TargetedStrategy not available — CVE pattern reproduction disabled")

try:
    from blue_tap.modules.fuzzing.response_analyzer import ResponseAnalyzer
    _HAS_ANALYZER = True
except ImportError:
    _HAS_ANALYZER = False
    logger.info("ResponseAnalyzer not available — anomaly detection disabled")

try:
    from blue_tap.modules.fuzzing.state_inference import StateTracker
    _HAS_STATE_TRACKER = True
except ImportError:
    _HAS_STATE_TRACKER = False
    logger.info("StateTracker not available — state inference disabled")

try:
    from blue_tap.modules.fuzzing.field_weight_tracker import FieldWeightTracker, FieldAwareMutator
    _HAS_FIELD_WEIGHTS = True
except ImportError:
    _HAS_FIELD_WEIGHTS = False
    logger.info("FieldWeightTracker not available — field-aware mutation disabled")

try:
    from blue_tap.modules.fuzzing.health_monitor import TargetHealthMonitor
    _HAS_HEALTH_MONITOR = True
except ImportError:
    _HAS_HEALTH_MONITOR = False
    logger.info("TargetHealthMonitor not available — health monitoring disabled")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Protocol name -> (transport_type, default_params)
# transport_type: "l2cap", "rfcomm", "ble"
PROTOCOL_TRANSPORT_MAP: dict[str, dict[str, Any]] = {
    "sdp":          {"type": "l2cap",  "psm": 1},
    "bnep":         {"type": "l2cap",  "psm": 15},
    "rfcomm":       {"type": "l2cap",  "psm": 3},
    "l2cap":        {"type": "l2cap",  "psm": 1},
    "l2cap-sig":    {"type": "raw-acl", "hci_dev": 1},
    "at-hfp":       {"type": "rfcomm", "channel": 10},
    "at-phonebook": {"type": "rfcomm", "channel": 1},
    "at-sms":       {"type": "rfcomm", "channel": 1},
    "at-injection": {"type": "rfcomm", "channel": 1},
    "obex-pbap":    {"type": "rfcomm", "channel": 15},
    "obex-map":     {"type": "rfcomm", "channel": 16},
    "obex-opp":     {"type": "rfcomm", "channel": 9},
    "ble-att":      {"type": "ble",    "cid": 4},
    "ble-smp":      {"type": "ble",    "cid": 6},
    "lmp":          {"type": "lmp",    "hci_dev": 1},
    "raw-acl":      {"type": "raw-acl", "hci_dev": 1},
}

#: Operator-friendly aliases → canonical transport keys.
PROTOCOL_ALIASES: dict[str, str] = {
    "pbap":      "obex-pbap",
    "map":       "obex-map",
    "opp":       "obex-opp",
    "att":       "ble-att",
    "smp":       "ble-smp",
    "hfp":       "at-hfp",
    "phonebook": "at-phonebook",
    "sms":       "at-sms",
}


def canonical_protocol(name: str) -> str:
    """Return the canonical PROTOCOL_TRANSPORT_MAP key for a user-supplied alias."""
    key = name.strip().lower()
    return PROTOCOL_ALIASES.get(key, key)

#: Severity classification for crash types.
CRASH_SEVERITY: dict[str, str] = {
    "connection_drop":     "HIGH",
    "device_disappeared":  "CRITICAL",
    "timeout":             "MEDIUM",
    "unexpected_response": "LOW",
}

#: Default cooldown seconds after a crash before resuming.
DEFAULT_COOLDOWN_SECONDS: float = 10.0

#: How long to wait for target recovery before declaring it dead.
TARGET_DEAD_TIMEOUT: float = 30.0

#: Stats print interval -- whichever comes first: seconds or iterations.
STATS_INTERVAL_SECONDS: float = 60.0
STATS_INTERVAL_ITERATIONS: int = 1000


# ---------------------------------------------------------------------------
# Duration parser
# ---------------------------------------------------------------------------

_DURATION_RE = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[smhd])\s*$",
    re.IGNORECASE,
)

_DURATION_MULTIPLIERS: dict[str, float] = {
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}

DRY_RUN_MAX_DURATION_SECONDS = float(
    os.environ.get("BT_TAP_DRY_RUN_MAX_DURATION_SECONDS", "5.0")
)
DRY_RUN_MAX_ITERATIONS = int(
    os.environ.get("BT_TAP_DRY_RUN_MAX_ITERATIONS", "100")
)


def parse_duration(s: str) -> float:
    """Parse a human-readable duration string into seconds.

    Supported formats::

        "30s"  -> 30.0
        "30m"  -> 1800.0
        "1h"   -> 3600.0
        "24h"  -> 86400.0
        "7d"   -> 604800.0

    Args:
        s: Duration string with a numeric value and unit suffix
           (``s`` seconds, ``m`` minutes, ``h`` hours, ``d`` days).

    Returns:
        Duration in seconds as a float.

    Raises:
        ValueError: If the string cannot be parsed.
    """
    match = _DURATION_RE.match(s)
    if not match:
        raise ValueError(
            f"Invalid duration format: {s!r}. "
            f"Expected a number followed by s/m/h/d (e.g. '30m', '2h', '7d')."
        )
    value = float(match.group("value"))
    unit = match.group("unit").lower()
    return value * _DURATION_MULTIPLIERS[unit]


# ---------------------------------------------------------------------------
# Campaign statistics
# ---------------------------------------------------------------------------

@dataclass
class CampaignStats:
    """Accumulates runtime statistics for a fuzzing campaign."""

    iterations: int = 0
    packets_sent: int = 0
    crashes: int = 0
    reconnects: int = 0
    start_time: float = field(default_factory=time.time)
    current_protocol: str = ""
    errors: int = 0
    protocol_breakdown: dict[str, int] = field(default_factory=dict)
    prior_elapsed: float = 0.0

    @property
    def runtime_seconds(self) -> float:
        """Elapsed wall-clock seconds including any prior resumed run."""
        return self.prior_elapsed + (time.time() - self.start_time)

    @property
    def packets_per_second(self) -> float:
        """Average packets sent per second over campaign lifetime."""
        elapsed = self.runtime_seconds
        return self.packets_sent / max(elapsed, 0.001)

    @property
    def crash_rate(self) -> float:
        """Crashes per 1000 packets sent."""
        if self.packets_sent == 0:
            return 0.0
        return (self.crashes / self.packets_sent) * 1000.0


@dataclass
class ProtocolRunStats:
    """Per-protocol statistics tracked during a campaign."""

    protocol: str = ""
    packets_sent: int = 0
    crashes: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    crash_types: dict[str, int] = field(default_factory=dict)
    anomalies: int = 0
    states_discovered: int = 0
    health_events: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_duration(seconds: float) -> str:
    """Format seconds into a human-readable ``HH:MM:SS`` string."""
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _check_target_alive(address: str) -> bool:
    """Quick reachability check via l2ping."""
    result = run_cmd(["l2ping", "-c", "1", "-t", "3", address], timeout=8)
    return result.returncode == 0


class _TargetedStrategyAdapter:
    """Adapts TargetedStrategy's generate_all() to the engine strategy interface."""

    def __init__(self) -> None:
        self._inner = TargetedStrategy()
        self._protocol_iters: dict[str, Generator] = {}

    def _get_iter(self, protocol: str) -> Generator:
        if protocol not in self._protocol_iters:
            self._protocol_iters[protocol] = self._inner.generate_all(protocol=protocol)
        return self._protocol_iters[protocol]

    def generate(self, protocol: str) -> tuple[bytes | list[bytes], list[str]]:
        it = self._get_iter(protocol)
        try:
            payload, description = next(it)
            return payload, [description]
        except StopIteration:
            self._protocol_iters[protocol] = self._inner.generate_all(protocol=protocol)
            it = self._protocol_iters[protocol]
            try:
                payload, description = next(it)
                return payload, [description]
            except StopIteration:
                raise ValueError(f"No targeted payloads for protocol {protocol!r}")

    def feedback(self, protocol: str, payload: bytes,
                 response: bytes | None, crash: bool = False) -> None:
        pass



# ---------------------------------------------------------------------------
# Campaign engine
# ---------------------------------------------------------------------------

class FuzzCampaign:
    """Orchestrates a multi-protocol fuzzing campaign against a Bluetooth target.

    The campaign engine manages:
    - Protocol rotation (round-robin across configured protocols)
    - Transport setup and reconnection
    - Seed corpus loading and mutation
    - Crash detection, classification, and logging
    - Target health monitoring with cooldown
    - Graceful shutdown on SIGINT with state persistence
    - Rich console statistics output

    Args:
        target: BD_ADDR of the target device (e.g. ``"AA:BB:CC:DD:EE:FF"``).
        protocols: List of protocol names to fuzz (see ``PROTOCOL_TRANSPORT_MAP``).
        strategy: Mutation strategy name. Currently ``"random"`` is supported;
            protocol-aware strategies will be added in Epic 2.
        duration: Maximum campaign duration in seconds, or ``None`` for unlimited.
        max_iterations: Maximum number of fuzz iterations, or ``None`` for unlimited.
        session_dir: Path to the session directory for artifact storage.
        cooldown: Seconds to wait after a crash before resuming.
    """

    def __init__(
        self,
        target: str,
        protocols: list[str],
        strategy: str = "coverage_guided",
        duration: float | None = None,
        max_iterations: int | None = None,
        session_dir: str = "",
        cooldown: float = DEFAULT_COOLDOWN_SECONDS,
        run_id: str = "",
        transport_overrides: dict[str, dict[str, Any]] | None = None,
        random_source: Callable[[int], bytes] | None = None,
        dry_run: bool = False,
        trajectory_interval_seconds: float | None = None,
    ) -> None:
        self.target = target
        protocols = [canonical_protocol(p) for p in protocols]
        self.protocols = protocols
        self.strategy = strategy
        self.duration = duration
        self.max_iterations = max_iterations
        self.session_dir = session_dir or "."
        self.cooldown = cooldown
        # Run identity
        from blue_tap.framework.envelopes.fuzz import make_fuzz_run_id
        self.run_id = run_id or make_fuzz_run_id()
        self.transport_overrides = {
            proto: dict(values)
            for proto, values in dict(transport_overrides or {}).items()
        }
        # Reproducibility hook: ``random_source(n) -> bytes`` of length n.
        # Defaults to ``os.urandom`` (CSPRNG, non-reproducible). When a
        # seeded callable is supplied, ``run()`` installs it via
        # :func:`set_random_source` for the whole campaign so every
        # ``random_bytes()`` call across the engine, mutators, strategies,
        # and protocol builders draws from it — yielding byte-identical
        # payloads across runs with the same seed. Wall-clock timing
        # (latency) is independently pinned to 0.0 under ``dry_run`` so
        # the response analyzer never branches on real durations.
        self._random_bytes: Callable[[int], bytes] = random_source or os.urandom

        self.dry_run = bool(dry_run)
        if self.dry_run:
            if self.duration is None or self.duration > DRY_RUN_MAX_DURATION_SECONDS:
                self.duration = DRY_RUN_MAX_DURATION_SECONDS
            if self.max_iterations is None or self.max_iterations > DRY_RUN_MAX_ITERATIONS:
                self.max_iterations = DRY_RUN_MAX_ITERATIONS
        # Trajectory: when interval > 0, snapshot stats at most once per
        # interval inside the main loop. ``None`` / non-positive disables
        # recording entirely (no overhead).
        if trajectory_interval_seconds is not None and trajectory_interval_seconds <= 0:
            trajectory_interval_seconds = None
        self.trajectory_interval_seconds = trajectory_interval_seconds
        self._trajectory: list[dict[str, Any]] = []
        self._last_trajectory_time: float = 0.0

        # Fuzz artifact directory
        self._fuzz_dir = os.path.join(self.session_dir, "fuzz")
        os.makedirs(self._fuzz_dir, exist_ok=True)

        # Crash database
        crash_db_path = os.path.join(self._fuzz_dir, "crashes.db")
        self.crash_db: Any = CrashDB(crash_db_path)

        # Seed corpus
        corpus_dir = os.path.join(self._fuzz_dir, "corpus")
        self.corpus: Any = Corpus(corpus_dir)

        # Mutator
        self._mutator: Any = CorpusMutator()

        # Campaign state
        self.stats = CampaignStats()
        self._running = False
        self._transports: dict[str, Any] = {}
        self._last_stats_time: float = 0.0

        # Strategy dispatch — instantiate real strategy classes when available.
        self._strategy_obj: Any = None
        if strategy == "targeted" and _HAS_TARGETED:
            self._strategy_obj = _TargetedStrategyAdapter()
            info("Strategy: targeted (known CVE pattern reproduction)")
        elif _HAS_STRATEGIES:
            if strategy == "coverage_guided":
                self._strategy_obj = CoverageGuidedStrategy(corpus=self.corpus)
                info("Strategy: coverage-guided (response-diversity feedback)")
            elif strategy == "state_machine":
                self._strategy_obj = StateMachineStrategy()
                info("Strategy: state-machine (protocol state violations)")
            elif strategy == "random":
                self._strategy_obj = RandomWalkStrategy(corpus=self.corpus)
                info("Strategy: random-walk (70% template / 30% corpus)")
        _known_strategies = ("random", "coverage_guided", "state_machine", "targeted")
        if self._strategy_obj is None and strategy not in _known_strategies:
            warning(f"Strategy '{strategy}' unavailable, falling back to byte-level mutation")
            self.strategy = "byte_level_mutation"
        elif self._strategy_obj is None and _HAS_STRATEGIES is False and strategy in _known_strategies:
            warning(f"Strategy '{strategy}' module unavailable, running byte-level mutation")
            self.strategy = "byte_level_mutation"

        # Response anomaly analyzer (learns baseline, detects deviations)
        self._analyzer: Any = ResponseAnalyzer() if _HAS_ANALYZER else None

        # State inference (Phase 1)
        self._state_tracker: Any = StateTracker() if _HAS_STATE_TRACKER else None

        # Field mutation weights (Phase 2)
        self._field_tracker: Any = FieldWeightTracker() if _HAS_FIELD_WEIGHTS else None
        self._field_mutator: Any = FieldAwareMutator() if _HAS_FIELD_WEIGHTS else None

        # Target health monitor (Phase 6)
        self._health_monitor: Any = TargetHealthMonitor(target) if _HAS_HEALTH_MONITOR else None

        # Seen response fingerprints (for corpus dedup)
        self._seen_responses: set[str] = set()

        # Per-protocol crash counts for adaptive scheduling
        self._proto_crash_counts: dict[str, int] = {p: 0 for p in protocols}

        self._protocol_stats: dict[str, ProtocolRunStats] = {}

        # Validate protocols
        unknown = [p for p in protocols if p not in PROTOCOL_TRANSPORT_MAP]
        if unknown:
            warning(
                f"Unknown protocol(s): {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(PROTOCOL_TRANSPORT_MAP))}"
            )

        # Filter to only known protocols
        valid = [p for p in protocols if p in PROTOCOL_TRANSPORT_MAP]
        if not valid:
            raise ValueError(
                f"No valid protocols after filtering. "
                f"Known: {', '.join(sorted(PROTOCOL_TRANSPORT_MAP))}"
            )
        self.protocols = valid

        for p in self.protocols:
            self._protocol_stats[p] = ProtocolRunStats(protocol=p)

    # ------------------------------------------------------------------
    # Transport setup
    # ------------------------------------------------------------------

    def _setup_transports(self) -> dict[str, Any]:
        """Create transport instances for each configured protocol.

        When ``dry_run`` is set, every protocol gets a :class:`MockTransport`
        instead of a real socket-backed transport — for benchmarks,
        regression tests, and notebook research that should not touch
        Bluetooth hardware.

        Returns:
            Mapping of protocol name to transport instance.
        """
        transports: dict[str, Any] = {}

        if self.dry_run:
            from blue_tap.modules.fuzzing.transport import MockTransport
            for protocol in self.protocols:
                if protocol not in PROTOCOL_TRANSPORT_MAP:
                    warning(f"Skipping unknown protocol: {protocol}")
                    continue
                transports[protocol] = MockTransport(
                    self.target, protocol=protocol,
                )
            self._transports = transports
            return transports

        for protocol in self.protocols:
            spec = PROTOCOL_TRANSPORT_MAP.get(protocol)
            if spec is None:
                warning(f"Skipping unknown protocol: {protocol}")
                continue
            spec = {**spec, **self.transport_overrides.get(protocol, {})}

            ttype = spec["type"]

            if ttype == "l2cap":
                transports[protocol] = L2CAPTransport(
                    self.target, psm=spec["psm"],
                )
            elif ttype == "rfcomm":
                transports[protocol] = RFCOMMTransport(
                    self.target, channel=spec["channel"],
                )
            elif ttype == "ble":
                transports[protocol] = BLETransport(
                    self.target, cid=spec["cid"],
                    address_type=BLETransport._detect_address_type(self.target),
                )
            elif ttype == "lmp":
                transports[protocol] = LMPTransport(
                    self.target,
                    hci_dev=spec.get("hci_dev", 1),
                    timeout=spec.get("timeout", 5.0),
                )
            elif ttype == "raw-acl":
                transports[protocol] = RawACLTransport(
                    self.target,
                    hci_dev=spec.get("hci_dev", 1),
                )
            else:
                warning(f"Unknown transport type '{ttype}' for protocol '{protocol}' — skipping")

        self._transports = transports
        return transports

    # ------------------------------------------------------------------
    # Fuzz case generation
    # ------------------------------------------------------------------

    def _generate_fuzz_case(self, protocol: str) -> tuple[bytes | list[bytes], list[str]]:
        """Generate a mutated fuzz case for the given protocol.

        Delegates to the active strategy object when available, otherwise
        falls back to byte-level corpus mutation.

        Returns:
            Tuple of (fuzz_bytes_or_sequence, mutation_log).
            For state-machine strategy, fuzz_bytes may be a list[bytes]
            (multi-packet sequence to send in order).
        """
        # Delegate to strategy object if available
        if self._strategy_obj is not None:
            try:
                result = self._strategy_obj.generate(protocol)
                return result
            except (ValueError, KeyError):
                # Protocol not supported by this strategy — fall through
                pass

        # Use field-aware mutation whenever tracker has learned weights
        if self._field_mutator is not None and self._field_tracker is not None:
            if self._field_tracker.get_weights(protocol):
                try:
                    seed = self.corpus.get_random_seed(protocol)
                    if seed is not None:
                        mutated, log = self._field_mutator.mutate(protocol, seed, self._field_tracker)
                        return mutated, log
                except Exception:
                    logger.debug("Field-aware mutation failed for %s, falling through to byte-level", protocol, exc_info=True)

        # Fallback: byte-level corpus mutation
        seed = self.corpus.get_random_seed(protocol)
        if seed is None:
            import random as _rng
            seed = random_bytes(_rng.randint(8, 256))

        mutated = self._mutator.mutate(seed)
        if not mutated:
            import random as _rng
            mutated = random_bytes(_rng.randint(4, 64))
        mutation_log = getattr(self._mutator, "last_mutations", ["mutated"])
        return mutated, mutation_log

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyze_response(
        self,
        protocol: str,
        payload: bytes,
        response: bytes | None,
        mutation_log: list[str],
        latency_ms: float = 0.0,
    ) -> None:
        """Analyze the target's response to a fuzz case.

        Three layers of analysis:
        1. Coverage-guided strategy feedback (response diversity tracking)
        2. Response fingerprinting (novel response -> save to corpus)
        3. Behavioral anomaly detection (structural, statistical, leak indicators)
        """
        # Feed back to strategy for coverage-guided learning.
        # FuzzStrategy ABC guarantees feedback() exists on all strategy objects
        # (no-op default on stateless strategies like RandomWalk).
        if self._strategy_obj is not None:
            try:
                self._strategy_obj.feedback(protocol, payload, response, crash=False)
            except Exception as exc:
                logger.debug("Strategy feedback error for %s: %s", protocol, exc)

        # Run anomaly analyzer (structural + baseline deviation + leak detection)
        if self._analyzer is not None:
            anomalies = self._analyzer.analyze(protocol, payload, response, latency_ms)
            # Guard: add the payload to the corpus at most once per analysis call.
            # Multiple anomalies can score >= 7.0 for the same payload in one
            # response, and 9.0+ anomalies also trigger _handle_crash() which calls
            # add_seed() internally.  Without this flag, corpus.seeds accumulates
            # multiple copies of the same bytes.
            _seed_added_this_call = False
            for anomaly in anomalies:
                if anomaly.score >= 7.0:
                    info(
                        f"[bt.yellow]ANOMALY[/bt.yellow] "
                        f"[{anomaly.severity}] {anomaly.description}"
                    )
                    # Only add to corpus for sub-crash-threshold anomalies.
                    # 9.0+ anomalies delegate entirely to _handle_crash() which
                    # calls add_seed() once.
                    if anomaly.score < 9.0 and not _seed_added_this_call:
                        try:
                            self.corpus.add_seed(
                                protocol, payload,
                                name=f"anomaly_{anomaly.anomaly_type.value}_{self.stats.iterations}",
                            )
                            _seed_added_this_call = True
                        except (OSError, AttributeError):
                            pass
                if anomaly.score >= 9.0:
                    # Very high score — log as potential crash/leak for investigation
                    self._handle_crash(
                        "unexpected_response", protocol, [payload], mutation_log,
                    )
                    return  # Don't double-count (crash handler bumps anomaly weight)
                elif anomaly.score >= 5.0:
                    # Medium-high anomaly — boost seed weight without triggering crash path
                    try:
                        self.corpus.record_anomaly(protocol, payload)
                    except (OSError, AttributeError):
                        pass

            if anomalies and protocol in self._protocol_stats:
                self._protocol_stats[protocol].anomalies += len([a for a in anomalies if a.score >= 5.0])

            # Feed anomaly info to field weight tracker
            if self._field_tracker is not None and anomalies:
                for log_entry in mutation_log:
                    if ":" in log_entry:
                        field_name = log_entry.split(":")[0].strip()
                        if not field_name:
                            continue
                        for anomaly in anomalies:
                            if anomaly.score >= 5.0:
                                try:
                                    self._field_tracker.record_anomaly(protocol, field_name)
                                except Exception as exc:
                                    warning(f"Field weight tracker error: {exc}")

        if response is None:
            return

        if len(response) > 0:
            # Response fingerprinting for corpus evolution
            len_bucket = len(response) // 16
            opcode = response[0] if response else 0
            err_byte = response[1] if len(response) > 1 else 0
            fp_data = f"{len_bucket}:{opcode}:{err_byte}:{response[:16].hex()}"
            fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:16]

            if fingerprint not in self._seen_responses:
                self._seen_responses.add(fingerprint)
                try:
                    self.corpus.add_seed(
                        protocol,
                        payload,
                        name=f"interesting_{self.stats.iterations}",
                    )
                except (OSError, AttributeError) as exc:
                    logger.warning("Failed to add interesting seed to corpus: %s", exc)

    # ------------------------------------------------------------------
    # Crash handling
    # ------------------------------------------------------------------

    def _handle_crash(
        self,
        crash_type: str,
        protocol: str,
        packets: list[bytes] | bytes,
        mutation_log: list[str],
    ) -> None:
        """Handle a detected crash: log, cooldown, verify target health.

        Args:
            crash_type: Type of crash (``connection_drop``, ``timeout``,
                ``device_disappeared``, ``unexpected_response``).
            protocol: Protocol that was being fuzzed when crash occurred.
            packets: The full multi-packet sequence that triggered the crash
                (or a single ``bytes`` payload for backward compatibility).
                The last packet is treated as the primary fuzz payload;
                all packets are stored for state-machine crash reproduction.
            mutation_log: Mutations applied to produce the payload.
        """
        # Normalize to list so all paths see the same type.
        if isinstance(packets, (bytes, bytearray)):
            pkt_list = [bytes(packets)]
        else:
            pkt_list = list(packets)
        primary_payload = pkt_list[-1] if pkt_list else b""

        severity = CRASH_SEVERITY.get(crash_type, "MEDIUM")
        self.stats.crashes += 1

        if protocol in self._protocol_stats:
            ps = self._protocol_stats[protocol]
            ps.crashes += 1
            ps.crash_types[crash_type] = ps.crash_types.get(crash_type, 0) + 1

        # Track per-protocol crash count for adaptive scheduling
        self._proto_crash_counts[protocol] = (
            self._proto_crash_counts.get(protocol, 0) + 1
        )

        # Log to crash database
        try:
            self.crash_db.log_crash(
                self.target,
                protocol,
                primary_payload,
                crash_type,
                severity=severity,
                mutation_log=mutation_log,
                packet_sequence=pkt_list if len(pkt_list) > 1 else None,
            )
        except Exception as exc:
            error(f"Failed to log crash: {exc}")

        # Feed crash payload back into corpus as a high-value seed.
        # Crash-producing inputs are the best starting points for
        # finding related bugs via further mutation.
        try:
            self.corpus.add_seed(
                protocol,
                primary_payload,
                name=f"crash_{self.stats.crashes}",
            )
        except (OSError, AttributeError) as exc:
            logger.warning("Failed to add crash seed to corpus: %s", exc)

        # Bump anomaly weight so this seed is sampled more often going forward.
        try:
            self.corpus.record_anomaly(protocol, primary_payload)
        except (OSError, AttributeError) as exc:
            logger.warning("Failed to record anomaly weight: %s", exc)

        # Feed crash info to field weight tracker
        if self._field_tracker is not None:
            for log_entry in mutation_log:
                if ":" in log_entry:
                    field_name = log_entry.split(":")[0].strip()
                    try:
                        self._field_tracker.record_crash(protocol, field_name)
                    except Exception as exc:
                        logger.debug("Field weight crash tracking error: %s", exc)

        # Notify strategy of the crash (for coverage-guided energy boost).
        # FuzzStrategy ABC guarantees feedback() exists — no hasattr needed.
        if self._strategy_obj is not None:
            try:
                self._strategy_obj.feedback(protocol, primary_payload, None, crash=True)
            except Exception as exc:
                logger.debug("Strategy crash feedback error: %s", exc)

        crash_num = self.stats.crashes
        emit_cli_event(
            event_type="execution_result",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Crash detected: {crash_type} ({severity}) on {protocol}",
            details={
                "crash_type": crash_type,
                "severity": severity,
                "protocol": protocol,
                "payload_size": len(primary_payload),
            },
            echo=False,
        )
        info(
            f"[bt.red]CRASH #{crash_num}[/bt.red] "
            f"type=[bt.yellow]{crash_type}[/bt.yellow] "
            f"severity=[bt.yellow]{severity}[/bt.yellow] "
            f"protocol=[bt.cyan]{protocol}[/bt.cyan] "
            f"payload_size={len(primary_payload)} "
            f"packets={len(pkt_list)}"
        )

        emit_cli_event(
            event_type="recovery_wait_started",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Recovery wait: {self.cooldown:.0f}s cooldown after {crash_type}",
            details={"timeout_seconds": self.cooldown, "crash_type": crash_type},
            echo=False,
        )
        # Cooldown: wait for target recovery
        info(f"Cooling down {self.cooldown:.0f}s for target recovery...")
        self._interruptible_sleep(self.cooldown)
        if not self._running:
            return

        # Verify target is still alive. Skipped under dry_run — there is
        # no real target and MockTransport never reports a real crash, so
        # this branch is reached only via injected response_factory; in
        # that case we keep the campaign running for the caller to drive.
        if not self.dry_run:
            if not _check_target_alive(self.target):
                warning("Target not responding after cooldown. Extending wait...")
                self._interruptible_sleep(TARGET_DEAD_TIMEOUT)
                if not self._running:
                    return
                if not _check_target_alive(self.target):
                    error("Target appears permanently down. Stopping campaign.")
                    self._running = False
                    return

        emit_cli_event(
            event_type="recovery_wait_finished",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Target recovered after {crash_type} crash",
            details={"recovered": True},
            echo=False,
        )
        # Reconnect the transport for this protocol
        transport = self._transports.get(protocol)
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
            self.stats.reconnects += 1

    def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep in 0.5s increments, checking ``_running`` between each."""
        end = time.time() + seconds
        while time.time() < end and self._running:
            time.sleep(min(0.5, end - time.time()))

    def _maybe_record_trajectory(self) -> None:
        """Append a trajectory snapshot if the configured interval has elapsed.

        No-op when ``trajectory_interval_seconds`` is None. Cheap to call
        every iteration — the elapsed-time check short-circuits before
        any allocation.
        """
        if self.trajectory_interval_seconds is None:
            return
        now = time.time()
        if now - self._last_trajectory_time < self.trajectory_interval_seconds:
            return
        self._last_trajectory_time = now

        states = 0
        transitions = 0
        if self._state_tracker is not None:
            try:
                graphs = self._state_tracker.to_dict().get("graphs", {}) or {}
                for g in graphs.values():
                    states += len(g.get("nodes", []) or [])
                    transitions += len(g.get("edges", []) or [])
            except Exception:
                logger.debug("trajectory: state tracker snapshot failed",
                             exc_info=True)

        self._trajectory.append({
            "elapsed_seconds": round(self.stats.runtime_seconds, 3),
            "iterations": self.stats.iterations,
            "packets_sent": self.stats.packets_sent,
            "crashes": self.stats.crashes,
            "errors": self.stats.errors,
            "states": states,
            "transitions": transitions,
        })

    # ------------------------------------------------------------------
    # Loop control
    # ------------------------------------------------------------------

    def _should_continue(self) -> bool:
        """Check whether the campaign should continue running.

        Returns ``False`` if any stop condition is met: interrupt received,
        duration exceeded, or iteration limit reached.
        """
        if not self._running:
            return False
        if self.duration is not None and self.stats.runtime_seconds >= self.duration:
            info("Duration limit reached.")
            return False
        if self.max_iterations is not None and self.stats.iterations >= self.max_iterations:
            info("Iteration limit reached.")
            return False
        return True

    def _next_protocol(self) -> str:
        """Select the next protocol with crash-rate-weighted scheduling.

        Protocols that have produced more crashes get proportionally more
        iterations.  Baseline weight ensures all protocols still get tested.
        Falls back to round-robin when no crashes have been observed yet.
        """
        import random as _rng

        total_crashes = sum(self._proto_crash_counts.values())
        if total_crashes == 0:
            # No crashes yet — use round-robin to explore evenly
            idx = self.stats.iterations % len(self.protocols)
            return self.protocols[idx]

        # Weight = baseline(1) + crash_count for each protocol.
        # This ensures every protocol gets at least ~1/N of iterations,
        # while high-crash protocols get proportionally more.
        weights = []
        for p in self.protocols:
            weights.append(1.0 + self._proto_crash_counts.get(p, 0))
        return _rng.choices(self.protocols, weights=weights, k=1)[0]

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Execute the fuzzing campaign.

        Activates the campaign's :attr:`_random_bytes` source for every
        ``random_bytes()`` call made by the strategies, mutators, and
        protocol builders during this run, restoring the previous
        process-wide source on exit (including exception paths).

        Installs a SIGINT handler for graceful shutdown, sets up transports,
        and enters the main fuzz loop. On completion (or interrupt), saves
        campaign state and prints a final summary.

        Returns:
            Summary dict with campaign statistics.
        """
        with set_random_source(self._random_bytes):
            return self._run_impl()

    def _run_impl(self) -> dict:
        """Inner body of :meth:`run` — runs under an active random-source context."""
        self._running = True
        self.stats = CampaignStats()
        self._last_stats_time = time.time()

        # Graceful shutdown on Ctrl+C
        # signal.signal() fails from non-main threads with ValueError
        prev_handler = signal.getsignal(signal.SIGINT)
        try:
            signal.signal(signal.SIGINT, self._handle_interrupt)
        except ValueError:
            warning("Cannot install SIGINT handler from non-main thread")

        section("Fuzz Campaign", style="bt.red")
        info(f"Target: [bt.purple]{self.target}[/bt.purple]")
        info(f"Protocols: [bt.cyan]{', '.join(self.protocols)}[/bt.cyan]")
        info(f"Strategy: [bt.yellow]{self.strategy}[/bt.yellow]")
        if self.duration is not None:
            info(f"Duration limit: [bt.yellow]{_format_duration(self.duration)}[/bt.yellow]")
        if self.max_iterations is not None:
            info(f"Iteration limit: [bt.yellow]{self.max_iterations:,}[/bt.yellow]")

        # Verify target is reachable. Skipped under dry_run because there
        # is no real target — l2ping would fail and abort the campaign
        # before MockTransport ever gets used.
        if self.dry_run:
            info("Skipping target reachability check (dry_run).")
        else:
            info("Checking target reachability...")
            if not _check_target_alive(self.target):
                error(
                    f"Target {self.target} is not reachable. "
                    "Ensure it is powered on and in range."
                )
                try:
                    signal.signal(signal.SIGINT, prev_handler)
                except ValueError:
                    pass
                return {"result": "error", "reason": "target_unreachable"}

            success("Target is alive.")
        emit_cli_event(
            event_type="run_started",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Fuzz campaign started: {len(self.protocols)} protocol(s), strategy={self.strategy}",
            details={
                "protocols": self.protocols,
                "strategy": self.strategy,
                "duration": self.duration,
                "max_iterations": self.max_iterations,
            },
        )

        # Setup transports
        info("Setting up transports...")
        self._setup_transports()
        if not self._transports:
            error("No valid transports configured. Check protocol names.")
            try:
                signal.signal(signal.SIGINT, prev_handler)
            except ValueError:
                pass
            return {"result": "error", "reason": "no_transports"}

        for proto, transport in self._transports.items():
            try:
                connected = transport.connect()
                if connected:
                    success(f"Connected: [bt.cyan]{proto}[/bt.cyan]")
                else:
                    warning(f"Could not connect: [bt.cyan]{proto}[/bt.cyan] (will retry)")
            except OSError as exc:
                warning(f"Transport setup failed for {proto}: {exc}")

        # Generate initial seeds if corpus is empty
        for proto in self.protocols:
            if self.corpus.seed_count(proto) == 0:
                info(f"Generating initial seeds for [bt.cyan]{proto}[/bt.cyan]...")
                self._generate_initial_seeds(proto)

        info(f"Corpus loaded: {sum(self.corpus.seed_count(p) for p in self.protocols)} seeds")

        # Baseline learning: send a few valid seeds per protocol and record
        # normal response behavior (size, latency, opcodes) before fuzzing.
        if self._analyzer is not None:
            emit_cli_event(
                event_type="phase_started",
                module="fuzzing",
                run_id=self.run_id,
                target=self.target,
                message="Learning baseline response behavior",
                details={"phase": "baseline_learning"},
                echo=False,
            )
            info("Learning baseline response behavior...")
            for proto in self.protocols:
                transport = self._transports.get(proto)
                if transport is None:
                    continue
                seeds = self.corpus.get_all_seeds(proto) if hasattr(self.corpus, 'get_all_seeds') else []
                for seed in seeds[:5]:  # up to 5 baseline samples per protocol
                    try:
                        if not transport.connected:
                            transport.connect()
                        t0 = time.time()
                        transport.send(seed)
                        response = transport.recv(recv_timeout=5.0)
                        # See main loop: pin baseline latency to 0 under
                        # dry_run for full reproducibility.
                        latency_ms = 0.0 if self.dry_run else (time.time() - t0) * 1000
                        self._analyzer.record_baseline(proto, response, latency_ms)
                    except Exception:
                        logger.debug("Baseline sample failed for %s", proto, exc_info=True)
            self._analyzer.finalize_baselines()
            bl_summary = self._analyzer.baseline_summary()
            for proto, stats in bl_summary.items():
                info(f"  {proto}: {stats['samples']} samples, "
                     f"avg {stats['mean_len']:.0f}B, {stats['mean_latency_ms']:.0f}ms")

        console.print()

        # Main fuzzing loop
        emit_cli_event(
            event_type="phase_started",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message="Main fuzzing loop started",
            details={"phase": "fuzzing"},
            echo=False,
        )
        _last_event_protocol = ""
        try:
            while self._should_continue():
                self._maybe_record_trajectory()
                protocol = self._next_protocol()
                if protocol != _last_event_protocol:
                    emit_cli_event(
                        event_type="execution_started",
                        module="fuzzing",
                        run_id=self.run_id,
                        target=self.target,
                        message=f"Fuzzing protocol: {protocol}",
                        details={"protocol": protocol, "iteration": self.stats.iterations},
                        echo=False,
                    )
                    _last_event_protocol = protocol
                self.stats.current_protocol = protocol
                transport = self._transports.get(protocol)

                if transport is None:
                    self.stats.iterations += 1
                    continue

                # Generate fuzz case (may be single bytes or multi-packet list)
                fuzz_result, mutation_log = self._generate_fuzz_case(protocol)

                # Normalize to list for uniform handling.  State-machine
                # strategy returns list[bytes]; others return bytes.
                if isinstance(fuzz_result, list):
                    packets = fuzz_result
                else:
                    packets = [fuzz_result]

                # For crash attribution, keep the last packet as the
                # "fuzz_case" — it's typically the mutated/attack packet.
                fuzz_case = packets[-1] if packets else b""

                # Send and observe
                try:
                    if not transport.connected:
                        if not transport.connect():
                            self.stats.errors += 1
                            self.stats.iterations += 1
                            continue

                    response = None
                    t0 = time.time()
                    for i, pkt in enumerate(packets):
                        if i == len(packets) - 1:
                            t0 = time.time()
                        transport.send(pkt)
                        self.stats.packets_sent += 1
                        self.stats.protocol_breakdown[protocol] = (
                            self.stats.protocol_breakdown.get(protocol, 0) + 1
                        )
                        if protocol in self._protocol_stats:
                            self._protocol_stats[protocol].packets_sent += 1
                        response = transport.recv()
                    # Wall-clock latency is non-deterministic across runs.
                    # Under dry_run we want byte-identical reproducibility
                    # (same seed → same payloads, end-to-end), so the
                    # response analyzer must not branch on real latency.
                    # Pin to 0.0 — clustering becomes a no-op, but every
                    # other determinism property is preserved.
                    if self.dry_run:
                        latency_ms = 0.0
                    else:
                        latency_ms = (time.time() - t0) * 1000

                    self._analyze_response(
                        protocol, fuzz_case, response, mutation_log, latency_ms,
                    )

                    # State tracking
                    if self._state_tracker is not None and response is not None:
                        try:
                            novel_state = self._state_tracker.record(protocol, response, seed=fuzz_case)
                            if novel_state:
                                try:
                                    self.corpus.add_seed(protocol, fuzz_case, name=f"state_novel_{self.stats.iterations}")
                                except (OSError, AttributeError):
                                    pass
                                if protocol in self._protocol_stats:
                                    self._protocol_stats[protocol].states_discovered += 1
                        except Exception as exc:
                            logger.debug("State tracker error for %s: %s", protocol, exc)

                    # Health monitoring. Under dry_run, every probe would
                    # call l2ping against a fake target, flooding warnings
                    # and burning CPU on syscalls; the entire monitor is
                    # meaningless without a real device.
                    if self._health_monitor is not None and not self.dry_run:
                        self._health_monitor.record_fuzz_case(fuzz_case)
                        if self._health_monitor.should_check(self.stats.iterations):
                            try:
                                health = self._health_monitor.update(self.stats.iterations, latency_ms, response, protocol=protocol)
                                if health.value in ("rebooted", "zombie", "degraded", "unreachable"):
                                    emit_cli_event(
                                        event_type="recovery_wait_started",
                                        module="fuzzing",
                                        run_id=self.run_id,
                                        target=self.target,
                                        message=f"Target health: {health.value}",
                                        details={"health_status": health.value, "protocol": protocol},
                                        echo=False,
                                    )
                                    if protocol in self._protocol_stats:
                                        self._protocol_stats[protocol].health_events += 1
                                if health.value in ("rebooted", "zombie"):
                                    for payload, confidence in self._health_monitor.get_crash_candidates():
                                        self._handle_crash(
                                            "device_disappeared", protocol, [payload],
                                            [f"reboot_candidate(conf={confidence:.1f})"],
                                        )
                            except Exception as exc:
                                logger.debug("Health monitor error: %s", exc)

                except ConnectionResetError:
                    self._handle_crash("connection_drop", protocol, packets, mutation_log)
                except BrokenPipeError:
                    self._handle_crash("connection_drop", protocol, packets, mutation_log)
                except TimeoutError:
                    self._handle_crash("timeout", protocol, packets, mutation_log)
                except OSError as exc:
                    if "Host is down" in str(exc) or "No route" in str(exc):
                        self._handle_crash("device_disappeared", protocol, packets, mutation_log)
                    else:
                        self.stats.errors += 1

                self.stats.iterations += 1

                # Periodic stats output
                now = time.time()
                if (
                    self.stats.iterations % STATS_INTERVAL_ITERATIONS == 0
                    or (now - self._last_stats_time) >= STATS_INTERVAL_SECONDS
                ):
                    self._print_stats()
                    self._last_stats_time = now

        except Exception as exc:
            error(f"Campaign terminated with unexpected error: {exc}\n{traceback.format_exc()}")
            emit_cli_event(
                event_type="run_error",
                module="fuzzing",
                run_id=self.run_id,
                target=self.target,
                message=f"Campaign error: {exc}",
                details={"error": str(exc)},
                echo=False,
            )
        finally:
            # Restore original signal handler
            try:
                signal.signal(signal.SIGINT, prev_handler)
            except ValueError:
                pass

        # Finalize
        self._finalize()
        return self._build_summary()

    # ------------------------------------------------------------------
    # Single-protocol run (per-protocol CLI commands)
    # ------------------------------------------------------------------

    def run_single_protocol(
        self,
        protocol: str,
        cases: list[bytes],
        delay: float = 0.5,
        recv_timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Run a fixed set of fuzz cases for a single protocol.

        Returns a RunEnvelope dict.
        """
        from blue_tap.framework.envelopes.fuzz import build_fuzz_result
        from blue_tap.framework.contracts.result_schema import now_iso

        started_at = now_iso()
        sent = 0
        crashes = 0
        errors = 0

        def _finalize_single_run(*, message: str, error_text: str | None = None) -> dict[str, Any]:
            completed_at = now_iso()
            result = {
                "sent": sent,
                "crashes": crashes,
                "errors": errors,
                "elapsed": max(time.time() - start_epoch, 0.0),
                "total_cases": len(cases),
                "crash_db_path": os.path.join(self._fuzz_dir, "crashes.db"),
                "started_at": started_at,
                "completed_at": completed_at,
            }
            envelope = build_fuzz_result(
                module_id=f"fuzzing.{protocol.replace('-', '_')}",
                target=self.target,
                adapter="session",
                command=f"fuzz_{protocol}",
                protocol=protocol,
                result=result,
                run_id=self.run_id,
            )
            validation_errors = validate_run_envelope(envelope)
            if validation_errors:
                logger.warning("Single-protocol envelope validation errors: %s", validation_errors)
            log_command(f"fuzz_{protocol}", envelope, category="fuzz", target=self.target)
            if error_text is not None:
                emit_cli_event(
                    event_type="run_error",
                    module="fuzzing",
                    run_id=self.run_id,
                    target=self.target,
                    message=message,
                    details={"error": error_text, "protocol": protocol, "total_cases": len(cases)},
                    echo=False,
                )
            emit_cli_event(
                event_type="run_completed",
                module="fuzzing",
                run_id=self.run_id,
                target=self.target,
                message=message,
                details={"sent": sent, "crashes": crashes, "errors": errors, "protocol": protocol},
                echo=False,
            )
            return envelope

        start_epoch = time.time()

        emit_cli_event(
            event_type="run_started",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Single-protocol fuzz: {protocol}, {len(cases)} cases",
            details={"protocol": protocol, "total_cases": len(cases)},
        )

        # Ensure we have a transport for this protocol
        if protocol not in self._transports:
            self._setup_transports()
        transport = self._transports.get(protocol)
        if transport is None:
            errors += 1
            return _finalize_single_run(
                message=f"Fuzz {protocol} failed: no transport available",
                error_text=f"No transport available for {protocol}",
            )

        try:
            if not transport.connected and not transport.connect():
                errors += 1
                return _finalize_single_run(
                    message=f"Fuzz {protocol} failed: transport setup failed",
                    error_text=f"Failed to connect transport for {protocol}",
                )
        except OSError as exc:
            error(f"Connection failed: {exc}")
            errors += 1
            return _finalize_single_run(
                message=f"Fuzz {protocol} failed: connection error",
                error_text=str(exc),
            )

        for i, payload in enumerate(cases):
            try:
                if not transport.connected:
                    if not transport.connect():
                        errors += 1
                        continue

                t_iter = time.time()
                transport.send(payload)
                sent += 1

                if protocol in self._protocol_stats:
                    self._protocol_stats[protocol].packets_sent += 1

                response = transport.recv(recv_timeout=recv_timeout) if hasattr(transport, 'recv') else None
                latency_ms = (time.time() - t_iter) * 1000

                # Route through the full response-analysis pipeline so anomalies
                # and novel responses feed crash handling, corpus updates, and
                # field-weight tracking — not just the analyzer in isolation.
                try:
                    self._analyze_response(protocol, payload, response, [f"case_{i+1}"], latency_ms)
                except Exception:
                    logger.debug("Response analysis failed for %s", protocol, exc_info=True)

            except (ConnectionResetError, BrokenPipeError):
                crashes += 1
                self._handle_crash("connection_drop", protocol, [payload], [f"case_{i+1}"])
                transport.close()
                time.sleep(2.0)
                try:
                    transport = self._transports.get(protocol)
                    if transport and not transport.connect():
                        errors += 1
                        break
                except Exception:
                    errors += 1
                    break
            except TimeoutError:
                crashes += 1
                self._handle_crash("timeout", protocol, [payload], [f"case_{i+1}"])
            except OSError as exc:
                if "Host is down" in str(exc) or "No route" in str(exc):
                    crashes += 1
                    self._handle_crash("device_disappeared", protocol, [payload], [f"case_{i+1}"])
                else:
                    errors += 1

            if delay > 0:
                time.sleep(delay)

        transport.close()
        return _finalize_single_run(
            message=f"Fuzz {protocol} complete: {sent}/{len(cases)} sent, {crashes} crashes",
        )

    # ------------------------------------------------------------------
    # Seed generation
    # ------------------------------------------------------------------

    def _generate_initial_seeds(self, protocol: str) -> None:
        """Generate basic seed corpus entries for a protocol.

        Creates a small set of minimal valid-ish packets that serve as
        starting points for mutation.  Protocol-specific builders (Epic 2)
        will replace these with structurally valid packets.
        """
        seeds: list[tuple[bytes, str]] = []

        if protocol == "sdp":
            # Minimal SDP ServiceSearchRequest
            seeds.append((
                bytes([
                    0x02, 0x00, 0x01, 0x00, 0x08,
                    0x35, 0x03, 0x19, 0x01, 0x00,
                    0x00, 0x10, 0x00,
                ]),
                "sdp_service_search",
            ))
            # SDP ServiceSearchAttributeRequest
            seeds.append((
                bytes([
                    0x06, 0x00, 0x01, 0x00, 0x11,
                    0x35, 0x03, 0x19, 0x01, 0x00,
                    0x00, 0x40,
                    0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff,
                    0x00,
                ]),
                "sdp_search_attr",
            ))
        elif protocol in ("at-hfp", "at-phonebook"):
            for cmd in [b"AT\r\n", b"AT+BRSF=0\r\n", b"AT+CIND=?\r\n",
                        b"AT+CPBS=\"ME\"\r\n", b"AT+CPBR=1,100\r\n"]:
                seeds.append((cmd, f"at_{cmd[2:6].decode(errors='replace').strip()}"))
        elif protocol == "at-sms":
            for cmd in [b"AT\r\n", b"AT+CMGF=1\r\n", b"AT+CMGL=\"ALL\"\r\n", b"AT+CNMI=2,1,0,0,0\r\n"]:
                seeds.append((cmd, f"at_{cmd[2:6].decode(errors='replace').strip()}"))
        elif protocol == "at-injection":
            for cmd in [
                b"AT+BRSF=%n%n\r",
                b"AT+CPBR=\x001,100\r",
                b"AT+CMGL=\"ALL\"\r\nAT+CHUP\r\n",
                b"AT" + (b"A" * 128) + b"\r",
            ]:
                seeds.append((cmd, "at_injection"))
        elif protocol == "bnep":
            # BNEP setup connection request
            seeds.append((
                bytes([0x01, 0x01, 0x00, 0x08, 0x00]),
                "bnep_setup_conn",
            ))
        elif protocol == "rfcomm":
            # Minimal RFCOMM SABM frame
            seeds.append((
                bytes([0x03, 0x3f, 0x01, 0x1c]),
                "rfcomm_sabm",
            ))
        elif protocol == "ble-att":
            # ATT Exchange MTU Request
            seeds.append((bytes([0x02, 0x00, 0x02]), "att_mtu_req"))
            # ATT Read By Group Type Request (discover services)
            seeds.append((
                bytes([0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28]),
                "att_read_by_group",
            ))
        elif protocol == "ble-smp":
            # SMP Pairing Request
            seeds.append((
                bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07]),
                "smp_pairing_req",
            ))
        elif protocol in ("obex-pbap", "obex-map"):
            # OBEX Connect
            seeds.append((
                bytes([0x80, 0x00, 0x07, 0x10, 0x00, 0x20, 0x00]),
                "obex_connect",
            ))

        # Always add some random seeds as well
        import random as _rng
        for i in range(3):
            seeds.append((random_bytes(_rng.randint(8, 128)), f"random_{i}"))

        for data, label in seeds:
            self.corpus.add_seed(protocol, data, name=label)

    # ------------------------------------------------------------------
    # Statistics display
    # ------------------------------------------------------------------

    def _print_stats(self) -> None:
        """Print a Rich table with current campaign statistics."""
        table = bare_table()
        table.title = "[bold]Fuzz Campaign Status[/bold]"
        table.add_column("Metric", style="bt.dim", min_width=18)
        table.add_column("Value", min_width=16)

        table.add_row("Runtime", f"[{CYAN}]{_format_duration(self.stats.runtime_seconds)}[/{CYAN}]")
        table.add_row("Iterations", f"[{CYAN}]{self.stats.iterations:,}[/{CYAN}]")
        table.add_row("Packets Sent", f"[{CYAN}]{self.stats.packets_sent:,}[/{CYAN}]")
        table.add_row("Packets/sec", f"[{YELLOW}]{self.stats.packets_per_second:.1f}[/{YELLOW}]")
        table.add_row(
            "Crashes",
            f"[{RED}]{self.stats.crashes}[/{RED}]"
            if self.stats.crashes > 0
            else f"[{GREEN}]0[/{GREEN}]",
        )
        table.add_row(
            "Crash Rate",
            f"[{YELLOW}]{self.stats.crash_rate:.2f}/1000 pkts[/{YELLOW}]",
        )
        table.add_row("Reconnects", f"[{YELLOW}]{self.stats.reconnects}[/{YELLOW}]")
        table.add_row("Errors", f"[{DIM}]{self.stats.errors}[/{DIM}]")
        table.add_row(
            "Current Protocol",
            f"[{PURPLE}]{self.stats.current_protocol}[/{PURPLE}]",
        )
        table.add_row(
            "Unique Crashes (DB)",
            f"[{RED}]{self.crash_db.crash_count()}[/{RED}]",
        )

        print_table(table)

    def _print_final_summary(self) -> None:
        """Print a detailed final summary with per-protocol breakdown and crash list."""
        section("Campaign Complete", style="bt.green")

        # Overall stats panel
        summary_panel("Campaign Summary", {
            "Target": self.target,
            "Runtime": _format_duration(self.stats.runtime_seconds),
            "Total Iterations": f"{self.stats.iterations:,}",
            "Packets Sent": f"{self.stats.packets_sent:,}",
            "Avg Packets/sec": f"{self.stats.packets_per_second:.1f}",
            "Total Crashes": str(self.stats.crashes),
            "Crash Rate": f"{self.stats.crash_rate:.2f}/1000 pkts",
            "Reconnects": str(self.stats.reconnects),
            "Errors": str(self.stats.errors),
        }, style="red" if self.stats.crashes > 0 else "green")

        # Per-protocol breakdown
        if self.stats.protocol_breakdown:
            proto_table = bare_table()
            proto_table.title = "[bold]Per-Protocol Breakdown[/bold]"
            proto_table.add_column("Protocol", style="bt.purple", min_width=16)
            proto_table.add_column("Packets", justify="right", min_width=10)
            proto_table.add_column("% of Total", justify="right", min_width=10)

            total = max(self.stats.packets_sent, 1)
            for proto, count in sorted(
                self.stats.protocol_breakdown.items(),
                key=lambda x: x[1],
                reverse=True,
            ):
                pct = (count / total) * 100
                proto_table.add_row(proto, f"{count:,}", f"{pct:.1f}%")
            print_table(proto_table)

        # Crash listing
        crash_count = self.crash_db.crash_count()
        if crash_count > 0:
            console.print()
            info(f"[bt.red]{crash_count} crash(es)[/bt.red] logged to: {self._fuzz_dir}")
            try:
                crashes = self.crash_db.get_crashes()
                crash_table = bare_table()
                crash_table.title = "[bold]Crashes[/bold]"
                crash_table.add_column("#", style="bt.dim", width=4, justify="right")
                crash_table.add_column("Type", style="bt.yellow", min_width=18)
                crash_table.add_column("Severity", min_width=10)
                crash_table.add_column("Protocol", style="bt.purple", min_width=12)
                crash_table.add_column("Payload Size", justify="right", min_width=10)
                crash_table.add_column("Timestamp", style="bt.dim", min_width=20)

                sev_styles = {
                    "CRITICAL": f"bold {RED}",
                    "HIGH": RED,
                    "MEDIUM": YELLOW,
                    "LOW": GREEN,
                }

                for i, crash in enumerate(crashes[:20], 1):  # Show max 20
                    sev = crash.get("severity", "MEDIUM")
                    sev_style = sev_styles.get(sev, DIM)
                    crash_table.add_row(
                        str(i),
                        crash.get("crash_type", "unknown"),
                        f"[{sev_style}]{sev}[/{sev_style}]",
                        crash.get("protocol", ""),
                        str(crash.get("payload_len", "?")),
                        crash.get("timestamp", ""),
                    )

                print_table(crash_table)
                if crash_count > 20:
                    info(f"... and {crash_count - 20} more. See {self._fuzz_dir}")
            except Exception:
                logger.debug("Crash summary display failed", exc_info=True)
        else:
            success("No crashes detected during this campaign.")

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def _finalize(self) -> None:
        """Clean up transports, save state, print summary, log to session."""
        emit_cli_event(
            event_type="run_completed",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message=f"Fuzz campaign completed: {self.stats.iterations:,} iterations, {self.stats.crashes} crashes",
            details={
                "iterations": self.stats.iterations,
                "packets_sent": self.stats.packets_sent,
                "crashes": self.stats.crashes,
                "runtime_seconds": round(self.stats.runtime_seconds, 1),
            },
            echo=False,
        )
        # Close all transports
        for proto, transport in self._transports.items():
            try:
                transport.close()
            except Exception:
                pass

        # Save final state
        self.save_state()

        # Save stats as JSON
        stats_path = os.path.join(self._fuzz_dir, "campaign_stats.json")
        try:
            with open(stats_path, "w") as f:
                json.dump(self._build_summary(), f, indent=2, default=str)
            emit_cli_event(
                event_type="artifact_saved",
                module="fuzzing",
                run_id=self.run_id,
                target=self.target,
                message=f"Campaign stats saved: {stats_path}",
                details={"artifact_type": "json", "path": stats_path},
                echo=False,
            )
        except OSError as exc:
            warning(f"Could not save campaign stats: {exc}")

        # Print summary
        self._print_final_summary()

        # Log to session using the standardized fuzz result envelope.
        campaign_summary = self._build_summary()
        try:
            crashes = self.crash_db.get_crashes()
        except Exception:
            logger.debug("Failed to retrieve crashes from crash DB", exc_info=True)
            crashes = []
        protocol_executions = []
        for proto, ps in self._protocol_stats.items():
            state_coverage = None
            if self._state_tracker is not None:
                try:
                    tracker_data = self._state_tracker.to_dict()
                    proto_graph = tracker_data.get("graphs", {}).get(proto, {})
                    if proto_graph:
                        state_coverage = {
                            "states": len(proto_graph.get("nodes", [])),
                            "transitions": len(proto_graph.get("edges", [])),
                        }
                except Exception:
                    logger.debug("State coverage extraction failed for %s", proto, exc_info=True)
            field_weights = None
            if self._field_tracker is not None:
                try:
                    w = self._field_tracker.get_weights(proto)
                    if w:
                        field_weights = w
                except Exception:
                    logger.debug("Field weight extraction failed for %s", proto, exc_info=True)
            protocol_executions.append(
                build_fuzz_protocol_execution(
                    module_id=f"fuzzing.{proto.replace('-', '_')}",
                    protocol=proto,
                    packets_sent=ps.packets_sent,
                    crashes=ps.crashes,
                    errors=ps.errors,
                    crash_types=ps.crash_types,
                    anomalies=ps.anomalies,
                    states_discovered=ps.states_discovered,
                    health_events=ps.health_events,
                    started_at=campaign_started_at_from_stats(ps.start_time),
                    completed_at=now_iso() if ps.end_time == 0.0 else campaign_started_at_from_stats(ps.end_time),
                    state_coverage=state_coverage,
                    field_weights=field_weights,
                )
            )
        envelope = build_fuzz_campaign_result(
            module_id="fuzzing.engine",
            target=self.target,
            adapter="session",
            campaign_summary=campaign_summary,
            crashes=crashes,
            session_fuzz_dir=self._fuzz_dir,
            started_at=campaign_started_at_from_stats(self.stats.start_time),
            run_id=self.run_id,
            protocol_executions=protocol_executions,
        )
        validation_errors = validate_run_envelope(envelope)
        if validation_errors:
            logger.warning("Campaign envelope validation errors: %s", validation_errors)
        log_command("fuzz_campaign", envelope, category="fuzz", target=self.target)

        try:
            self.crash_db.close()
        except Exception:
            logger.debug("Failed to close crash DB", exc_info=True)

    def _build_summary(self) -> dict:
        """Build a summary dict of the campaign for serialization."""
        result = {
            "result": "complete" if not self._running or self.stats.iterations > 0 else "stopped",
            "target": self.target,
            "protocols": self.protocols,
            "strategy": self.strategy,
            "runtime_seconds": self.stats.runtime_seconds,
            "runtime_formatted": _format_duration(self.stats.runtime_seconds),
            "iterations": self.stats.iterations,
            "packets_sent": self.stats.packets_sent,
            "packets_per_second": round(self.stats.packets_per_second, 2),
            "crashes": self.stats.crashes,
            "crash_rate_per_1000": round(self.stats.crash_rate, 4),
            "reconnects": self.stats.reconnects,
            "errors": self.stats.errors,
            "protocol_breakdown": dict(self.stats.protocol_breakdown),
            "crash_db_path": os.path.join(self._fuzz_dir, "crashes.db"),
            "corpus_dir": os.path.join(self._fuzz_dir, "corpus"),
        }

        if self._trajectory:
            result["trajectory"] = list(self._trajectory)

        # State coverage stats (Phase 1)
        if self._state_tracker is not None:
            try:
                tracker_data = self._state_tracker.to_dict()
                total_states = sum(
                    len(g.get("nodes", []))
                    for g in tracker_data.get("graphs", {}).values()
                )
                total_transitions = sum(
                    len(g.get("edges", []))
                    for g in tracker_data.get("graphs", {}).values()
                )
                result["state_coverage"] = {
                    "total_states": total_states,
                    "total_transitions": total_transitions,
                    "protocols_tracked": list(tracker_data.get("graphs", {}).keys()),
                }
            except Exception:
                logger.debug("State coverage summary extraction failed", exc_info=True)

        # Field weight stats (Phase 2)
        if self._field_tracker is not None:
            try:
                weights_summary = {}
                for proto in self.protocols:
                    w = self._field_tracker.get_weights(proto)
                    if w:
                        weights_summary[proto] = w
                if weights_summary:
                    result["field_weights"] = weights_summary
            except Exception:
                logger.debug("Field weight summary extraction failed", exc_info=True)

        # Health monitor stats (Phase 6)
        if self._health_monitor is not None:
            try:
                result["health_monitor"] = self._health_monitor.get_stats()
            except Exception:
                logger.debug("Health monitor stats extraction failed", exc_info=True)

        return result

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def save_state(self) -> str:
        """Save campaign state to JSON for later resumption.

        Returns:
            Path to the saved state file.
        """
        # Snapshot total elapsed time so resume carries it forward.
        stats_dict = asdict(self.stats)
        stats_dict["prior_elapsed"] = self.stats.runtime_seconds
        state = {
            "target": self.target,
            "protocols": self.protocols,
            "strategy": self.strategy,
            "duration": self.duration,
            "max_iterations": self.max_iterations,
            "cooldown": self.cooldown,
            "session_dir": self.session_dir,
            "run_id": self.run_id,
            "stats": stats_dict,
            "timestamp": datetime.now().isoformat(),
        }

        # Persist Phase 1/2/6 module states
        if self._state_tracker is not None:
            try:
                state["state_tracker"] = self._state_tracker.to_dict()
            except Exception as exc:
                logger.debug("State tracker serialization failed: %s", exc)
        if self._field_tracker is not None:
            try:
                state["field_tracker"] = self._field_tracker.to_dict()
            except Exception as exc:
                logger.debug("Field tracker serialization failed: %s", exc)
        if self._health_monitor is not None:
            try:
                state["health_monitor"] = self._health_monitor.to_dict()
            except Exception as exc:
                logger.debug("Health monitor serialization failed: %s", exc)
        # Persist strategy fingerprint / energy state so resume picks up where we left off
        if self._strategy_obj is not None and hasattr(self._strategy_obj, "to_dict"):
            try:
                state["strategy_state"] = self._strategy_obj.to_dict()
                info("Strategy state serialised into campaign snapshot")
            except Exception as exc:
                info(f"[bt.yellow]Strategy state serialisation skipped: {exc}[/bt.yellow]")
        state_path = os.path.join(self._fuzz_dir, "campaign_state.json")
        with open(state_path, "w") as f:
            json.dump(state, f, indent=2, default=str)
        info(f"Campaign state saved to {state_path}")
        return state_path

    @classmethod
    def resume(cls, session_dir: str) -> FuzzCampaign:
        """Resume a campaign from a previously saved state file.

        Args:
            session_dir: Path to the session directory containing ``fuzz/campaign_state.json``.

        Returns:
            A new ``FuzzCampaign`` instance initialized from the saved state.

        Raises:
            FileNotFoundError: If no saved state exists.
            json.JSONDecodeError: If the state file is corrupt.
        """
        state_path = os.path.join(session_dir, "fuzz", "campaign_state.json")
        with open(state_path) as f:
            state = json.load(f)

        campaign = cls(
            target=state["target"],
            protocols=state["protocols"],
            strategy=state.get("strategy", "random"),
            duration=state.get("duration"),
            max_iterations=state.get("max_iterations"),
            session_dir=session_dir,
            cooldown=state.get("cooldown", DEFAULT_COOLDOWN_SECONDS),
        )
        campaign.run_id = state.get("run_id", campaign.run_id)

        # Restore stats
        saved_stats = state.get("stats", {})
        campaign.stats = CampaignStats(
            iterations=saved_stats.get("iterations", 0),
            packets_sent=saved_stats.get("packets_sent", 0),
            crashes=saved_stats.get("crashes", 0),
            reconnects=saved_stats.get("reconnects", 0),
            start_time=time.time(),
            current_protocol=saved_stats.get("current_protocol", ""),
            errors=saved_stats.get("errors", 0),
            protocol_breakdown=saved_stats.get("protocol_breakdown", {}),
            prior_elapsed=saved_stats.get("prior_elapsed", 0.0),
        )

        # Restore Phase 1/2/6 module states
        if _HAS_STATE_TRACKER and "state_tracker" in state:
            try:
                campaign._state_tracker = StateTracker.from_dict(state["state_tracker"])
            except Exception as exc:
                logger.warning("State tracker restore failed: %s", exc)
        if _HAS_FIELD_WEIGHTS and "field_tracker" in state:
            try:
                campaign._field_tracker = FieldWeightTracker.from_dict(state["field_tracker"])
            except Exception as exc:
                logger.warning("Field tracker restore failed: %s", exc)
        if _HAS_HEALTH_MONITOR and "health_monitor" in state:
            try:
                campaign._health_monitor = TargetHealthMonitor.from_dict(state["health_monitor"])
            except Exception as exc:
                logger.warning("Health monitor restore failed: %s", exc)
        # Restore CoverageGuidedStrategy from serialised snapshot, then reload interesting inputs
        if _HAS_STRATEGIES and "strategy_state" in state:
            try:
                if isinstance(campaign._strategy_obj, CoverageGuidedStrategy):
                    corpus_arg = campaign.corpus
                    campaign._strategy_obj = CoverageGuidedStrategy.from_dict(
                        state["strategy_state"],
                        corpus=corpus_arg,
                    )
                    info("CoverageGuidedStrategy state restored from snapshot")
            except Exception as exc:
                info(f"[bt.yellow]Strategy state restore skipped: {exc}[/bt.yellow]")
        # Reload interesting inputs from disk regardless of snapshot presence
        # (handles the case where interesting/ files exist but snapshot was lost)
        if _HAS_STRATEGIES and isinstance(campaign._strategy_obj, CoverageGuidedStrategy):
            if isinstance(campaign.corpus, Corpus):
                try:
                    # Load seeds from disk first so list_protocols() is populated.
                    # Without this the corpus is empty in memory and load_from_corpus
                    # has no protocol list to iterate over.
                    corpus_dir = os.path.join(session_dir, "fuzz", "corpus")
                    if os.path.isdir(corpus_dir):
                        campaign.corpus.load_from_directory(corpus_dir)
                    loaded = campaign._strategy_obj.load_from_corpus(campaign.corpus)
                    if loaded > 0:
                        info(
                            f"Reloaded {loaded} interesting input(s) from previous session "
                            f"into coverage strategy"
                        )
                except Exception as exc:
                    info(f"[bt.yellow]Interesting inputs reload skipped: {exc}[/bt.yellow]")

        info(
            f"Resumed campaign from {state_path} "
            f"(prev: {saved_stats.get('iterations', 0):,} iterations, "
            f"{saved_stats.get('crashes', 0)} crashes)"
        )
        return campaign

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_interrupt(self, _signum: int, _frame: Any) -> None:
        """Handle SIGINT (Ctrl+C) for graceful campaign shutdown.

        Sets the running flag to False so the main loop exits cleanly.
        State is saved by the finalization step in ``run()``.
        """
        info("[bt.yellow]Interrupt received. Stopping campaign gracefully...[/bt.yellow]")
        self._running = False
        emit_cli_event(
            event_type="run_aborted",
            module="fuzzing",
            run_id=self.run_id,
            target=self.target,
            message="Fuzz campaign aborted by operator (SIGINT)",
            echo=False,
        )
