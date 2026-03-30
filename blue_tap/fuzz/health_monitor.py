"""Target health monitoring — watchdog reboot detection, degradation, and zombie states.

Detects when a Bluetooth target reboots (watchdog restart), enters a degraded
state (rising latency / resource exhaustion), or becomes a zombie (L2CAP alive
but protocol-level unresponsive).
"""

from __future__ import annotations

import collections
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from blue_tap.utils.output import info, warning, error


# ---------------------------------------------------------------------------
# Enums & data classes
# ---------------------------------------------------------------------------

class HealthStatus(Enum):
    """Observable states of a fuzz target."""

    ALIVE = "alive"
    UNREACHABLE = "unreachable"
    REBOOTING = "rebooting"
    REBOOTED = "rebooted"
    DEGRADED = "degraded"
    ZOMBIE = "zombie"


@dataclass
class HealthEvent:
    """Snapshot of a notable health transition."""

    timestamp: float
    status: HealthStatus
    details: str
    iteration: int
    last_fuzz_cases: list[bytes] = field(default_factory=list)

    # -- serialisation helpers ------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "status": self.status.value,
            "details": self.details,
            "iteration": self.iteration,
            "last_fuzz_cases": [c.hex() for c in self.last_fuzz_cases],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HealthEvent:
        return cls(
            timestamp=d["timestamp"],
            status=HealthStatus(d["status"]),
            details=d["details"],
            iteration=d["iteration"],
            last_fuzz_cases=[bytes.fromhex(h) for h in d.get("last_fuzz_cases", [])],
        )


# ---------------------------------------------------------------------------
# Main monitor
# ---------------------------------------------------------------------------

class TargetHealthMonitor:
    """Tracks target liveness, reboots, degradation and zombie states."""

    def __init__(self, target: str, check_interval: int = 50) -> None:
        self.target = target
        self.check_interval = check_interval

        # Internal state
        self._last_status: HealthStatus = HealthStatus.ALIVE
        self._last_alive_time: float = time.time()
        self._reboot_count: int = 0
        self._consecutive_failures: int = 0
        self._recent_fuzz_cases: collections.deque[bytes] = collections.deque(maxlen=10)
        self._events: list[HealthEvent] = []
        self._latency_trend: collections.deque[float] = collections.deque(maxlen=100)

    # ------------------------------------------------------------------
    # Liveness probe
    # ------------------------------------------------------------------

    def check_alive(self, target: str) -> HealthStatus:
        """Ping *target* via ``l2ping``; fall back to a raw L2CAP socket."""
        try:
            result = subprocess.run(
                ["l2ping", "-c", "1", "-t", "2", target],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                return HealthStatus.ALIVE
            return HealthStatus.UNREACHABLE
        except FileNotFoundError:
            # l2ping not installed — try raw L2CAP socket
            return self._l2cap_probe(target)
        except subprocess.TimeoutExpired:
            return HealthStatus.UNREACHABLE

    def _l2cap_probe(self, target: str) -> HealthStatus:
        """Attempt a raw L2CAP connection on PSM 1 (SDP) as a liveness check."""
        sock = None
        try:
            sock = socket.socket(
                socket.AF_BLUETOOTH,  # type: ignore[attr-defined]
                socket.SOCK_SEQPACKET,
                socket.BTPROTO_L2CAP,  # type: ignore[attr-defined]
            )
            sock.settimeout(2)
            sock.connect((target, 1))  # PSM 1 = SDP
            return HealthStatus.ALIVE
        except (OSError, socket.timeout):
            return HealthStatus.UNREACHABLE
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Iteration gating
    # ------------------------------------------------------------------

    def should_check(self, iteration: int) -> bool:
        """Return *True* when a health check is due."""
        if self._last_status != HealthStatus.ALIVE:
            return True
        return iteration % self.check_interval == 0

    # ------------------------------------------------------------------
    # Core update logic
    # ------------------------------------------------------------------

    def update(self, iteration: int, latency_ms: float | None, response: Any) -> HealthStatus:
        """Process one iteration's health data and return the new status."""
        # Track latency
        if latency_ms is not None:
            self._latency_trend.append(latency_ms)

        probe_status = self.check_alive(self.target)

        if probe_status == HealthStatus.UNREACHABLE:
            self._consecutive_failures += 1

            if self._last_status == HealthStatus.ALIVE:
                warning(f"Target {self.target} became unreachable at iteration {iteration}")

            # Try to detect a reboot cycle
            if self._detect_reboot():
                self._reboot_count += 1
                self._consecutive_failures = 0
                status = HealthStatus.REBOOTED
                cases_snapshot = list(self._recent_fuzz_cases)
                self._events.append(HealthEvent(
                    timestamp=time.time(),
                    status=status,
                    details=f"Watchdog reboot #{self._reboot_count} detected after iteration {iteration}",
                    iteration=iteration,
                    last_fuzz_cases=cases_snapshot,
                ))
                info(f"Reboot #{self._reboot_count} detected — {len(cases_snapshot)} candidate payloads saved")
                self._last_status = status
                self._last_alive_time = time.time()
                return status

            self._last_status = HealthStatus.UNREACHABLE
            return HealthStatus.UNREACHABLE

        # Target is reachable
        self._consecutive_failures = 0
        self._last_alive_time = time.time()

        # Transition from unreachable -> alive means rebooted
        if self._last_status == HealthStatus.UNREACHABLE:
            self._reboot_count += 1
            cases_snapshot = list(self._recent_fuzz_cases)
            self._events.append(HealthEvent(
                timestamp=time.time(),
                status=HealthStatus.REBOOTED,
                details=f"Target reappeared (reboot #{self._reboot_count}) at iteration {iteration}",
                iteration=iteration,
                last_fuzz_cases=cases_snapshot,
            ))
            info(f"Target back online — reboot #{self._reboot_count}")
            self._last_status = HealthStatus.REBOOTED
            return HealthStatus.REBOOTED

        # Check degradation
        if self._check_degradation():
            if self._last_status != HealthStatus.DEGRADED:
                self._events.append(HealthEvent(
                    timestamp=time.time(),
                    status=HealthStatus.DEGRADED,
                    details=f"Latency degradation detected at iteration {iteration}",
                    iteration=iteration,
                ))
                warning(f"Target {self.target} showing latency degradation")
            self._last_status = HealthStatus.DEGRADED
            return HealthStatus.DEGRADED

        self._last_status = HealthStatus.ALIVE
        return HealthStatus.ALIVE

    # ------------------------------------------------------------------
    # Fuzz-case ring buffer
    # ------------------------------------------------------------------

    def record_fuzz_case(self, payload: bytes) -> None:
        """Append *payload* to the recent fuzz-case ring buffer."""
        self._recent_fuzz_cases.append(payload)

    # ------------------------------------------------------------------
    # Reboot detection (exponential back-off reconnect)
    # ------------------------------------------------------------------

    def _detect_reboot(self) -> bool:
        """After target becomes unreachable, probe at 1 s, 2 s, 4 s intervals."""
        for delay in (1, 2, 4):
            time.sleep(delay)
            if self.check_alive(self.target) == HealthStatus.ALIVE:
                return True
        return False

    # ------------------------------------------------------------------
    # Degradation (latency linear regression)
    # ------------------------------------------------------------------

    def _check_degradation(self) -> bool:
        """Return *True* when latency slope exceeds 0.5 ms/iteration."""
        n = len(self._latency_trend)
        if n < 10:
            return False

        ys = list(self._latency_trend)
        xs = list(range(n))

        x_mean = sum(xs) / n
        y_mean = sum(ys) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
        denominator = sum((x - x_mean) ** 2 for x in xs)

        if denominator == 0:
            return False

        slope = numerator / denominator
        return slope > 0.5

    # ------------------------------------------------------------------
    # Zombie detection
    # ------------------------------------------------------------------

    def _check_zombie(self, protocol_responses: dict[str, bool]) -> bool:
        """L2CAP alive but every protocol request fails -> zombie."""
        if not protocol_responses:
            return False
        if self.check_alive(self.target) != HealthStatus.ALIVE:
            return False
        return not any(protocol_responses.values())

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_events(self) -> list[HealthEvent]:
        """Return all recorded health events."""
        return list(self._events)

    def get_stats(self) -> dict[str, Any]:
        """Summary statistics for the current target."""
        return {
            "reboot_count": self._reboot_count,
            "current_status": self._last_status.value,
            "consecutive_failures": self._consecutive_failures,
            "latency_trend_slope": self._latency_slope(),
        }

    def get_crash_candidates(self) -> list[tuple[bytes, float]]:
        """After a reboot, return recent fuzz cases with descending confidence.

        The most recent case is the most likely trigger (confidence 0.9),
        with each prior case receiving progressively lower confidence.
        """
        cases = list(self._recent_fuzz_cases)
        if not cases:
            return []

        confidences = [0.9, 0.7, 0.5]
        # Extend with 0.3 for any remaining cases beyond the first three
        while len(confidences) < len(cases):
            confidences.append(0.3)

        # Most recent first
        cases_reversed = list(reversed(cases))
        return [(c, confidences[i]) for i, c in enumerate(cases_reversed)]

    def get_cooldown(self) -> float:
        """Adaptive cooldown based on reboot count.

        0 reboots -> 10 s, 1 -> 15 s, 2 -> 20 s, 3+ -> 30 s.
        """
        if self._reboot_count == 0:
            return 10.0
        elif self._reboot_count == 1:
            return 15.0
        elif self._reboot_count == 2:
            return 20.0
        return 30.0

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise monitor state to a plain dict."""
        return {
            "target": self.target,
            "check_interval": self.check_interval,
            "last_status": self._last_status.value,
            "last_alive_time": self._last_alive_time,
            "reboot_count": self._reboot_count,
            "consecutive_failures": self._consecutive_failures,
            "recent_fuzz_cases": [c.hex() for c in self._recent_fuzz_cases],
            "events": [e.to_dict() for e in self._events],
            "latency_trend": list(self._latency_trend),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TargetHealthMonitor:
        """Restore a monitor from a previously serialised dict."""
        mon = cls(target=d["target"], check_interval=d.get("check_interval", 50))
        mon._last_status = HealthStatus(d["last_status"])
        mon._last_alive_time = d.get("last_alive_time", time.time())
        mon._reboot_count = d.get("reboot_count", 0)
        mon._consecutive_failures = d.get("consecutive_failures", 0)
        for h in d.get("recent_fuzz_cases", []):
            mon._recent_fuzz_cases.append(bytes.fromhex(h))
        mon._events = [HealthEvent.from_dict(e) for e in d.get("events", [])]
        for v in d.get("latency_trend", []):
            mon._latency_trend.append(v)
        return mon

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _latency_slope(self) -> float:
        """Compute the linear-regression slope of the latency trend."""
        n = len(self._latency_trend)
        if n < 2:
            return 0.0

        ys = list(self._latency_trend)
        xs = list(range(n))
        x_mean = sum(xs) / n
        y_mean = sum(ys) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
        denominator = sum((x - x_mean) ** 2 for x in xs)

        if denominator == 0:
            return 0.0
        return numerator / denominator
