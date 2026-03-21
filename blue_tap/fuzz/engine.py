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
import os
import re
import signal
import socket
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from rich.table import Table
from rich.style import Style

from blue_tap.utils.output import (
    console,
    info,
    success,
    error,
    warning,
    section,
    summary_panel,
    CYAN,
    GREEN,
    YELLOW,
    RED,
    DIM,
    PURPLE,
)
from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.utils.session import log_command

# ---------------------------------------------------------------------------
# Conditional imports for modules being built in parallel by other agents.
# These will be available once their respective tasks are complete.
# ---------------------------------------------------------------------------

try:
    from blue_tap.fuzz.transport import (
        L2CAPTransport,
        RFCOMMTransport,
        BLETransport,
    )
    _HAS_TRANSPORT = True
except ImportError:
    _HAS_TRANSPORT = False

try:
    from blue_tap.fuzz.crash_db import CrashDB
    _HAS_CRASH_DB = True
except ImportError:
    _HAS_CRASH_DB = False

try:
    from blue_tap.fuzz.corpus import Corpus
    _HAS_CORPUS = True
except ImportError:
    _HAS_CORPUS = False

try:
    from blue_tap.fuzz.mutators import CorpusMutator
    _HAS_MUTATORS = True
except ImportError:
    _HAS_MUTATORS = False


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
    "at-hfp":       {"type": "rfcomm", "channel": 10},
    "at-phonebook": {"type": "rfcomm", "channel": 1},
    "at-sms":       {"type": "rfcomm", "channel": 1},
    "at-injection": {"type": "rfcomm", "channel": 1},
    "obex-pbap":    {"type": "rfcomm", "channel": 15},
    "obex-map":     {"type": "rfcomm", "channel": 16},
    "obex-opp":     {"type": "rfcomm", "channel": 9},
    "ble-att":      {"type": "ble",    "cid": 4},
    "ble-smp":      {"type": "ble",    "cid": 6},
}

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

    @property
    def runtime_seconds(self) -> float:
        """Elapsed wall-clock seconds since campaign start."""
        return time.time() - self.start_time

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


# ---------------------------------------------------------------------------
# Stub implementations for missing modules
# ---------------------------------------------------------------------------

class _StubCrashDB:
    """Minimal crash DB that writes JSON files when the real CrashDB is unavailable."""

    def __init__(self, db_path: str) -> None:
        self._dir = os.path.dirname(db_path) or "."
        os.makedirs(self._dir, exist_ok=True)
        self._count = 0

    def log_crash(
        self,
        target: str,
        protocol: str,
        payload: bytes,
        crash_type: str,
        *,
        severity: str = "MEDIUM",
        mutation_log: str = "",
    ) -> None:
        self._count += 1
        crash_file = os.path.join(self._dir, f"crash_{self._count:04d}.json")
        data = {
            "target": target,
            "protocol": protocol,
            "payload_hex": payload.hex(),
            "payload_len": len(payload),
            "crash_type": crash_type,
            "severity": severity,
            "mutation_log": mutation_log,
            "timestamp": datetime.now().isoformat(),
        }
        with open(crash_file, "w") as f:
            json.dump(data, f, indent=2)

    def crash_count(self) -> int:
        return self._count

    def get_crashes(self) -> list[dict]:
        crashes: list[dict] = []
        for fname in sorted(os.listdir(self._dir)):
            if fname.startswith("crash_") and fname.endswith(".json"):
                fpath = os.path.join(self._dir, fname)
                try:
                    with open(fpath) as f:
                        crashes.append(json.load(f))
                except (json.JSONDecodeError, OSError):
                    pass
        return crashes


class _StubCorpus:
    """Minimal corpus that generates random seeds when the real Corpus is unavailable."""

    def __init__(self, corpus_dir: str) -> None:
        self._dir = corpus_dir
        os.makedirs(self._dir, exist_ok=True)

    def get_random_seed(self, protocol: str = "") -> bytes:
        """Return a random seed from the corpus or a fresh random payload."""
        protocol_dir = os.path.join(self._dir, protocol) if protocol else self._dir
        if os.path.isdir(protocol_dir):
            seeds = [
                f for f in os.listdir(protocol_dir)
                if os.path.isfile(os.path.join(protocol_dir, f))
            ]
            if seeds:
                import random
                chosen = random.choice(seeds)
                with open(os.path.join(protocol_dir, chosen), "rb") as f:
                    return f.read()
        # Fallback: generate random bytes
        import random
        return os.urandom(random.randint(8, 256))

    def add_seed(self, protocol: str, data: bytes, name: str = "") -> str:
        """Save a seed to the corpus directory."""
        protocol_dir = os.path.join(self._dir, protocol) if protocol else self._dir
        os.makedirs(protocol_dir, exist_ok=True)
        name = name or hashlib.sha256(data).hexdigest()[:16]
        path = os.path.join(protocol_dir, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
        return path

    def seed_count(self, protocol: str = "") -> int:
        protocol_dir = os.path.join(self._dir, protocol) if protocol else self._dir
        if not os.path.isdir(protocol_dir):
            return 0
        return sum(
            1 for f in os.listdir(protocol_dir)
            if os.path.isfile(os.path.join(protocol_dir, f))
        )


class _StubMutator:
    """Minimal byte-level mutator when the real CorpusMutator is unavailable."""

    def mutate(self, data: bytes) -> tuple[bytes, list[str]]:
        """Apply a random byte-level mutation and return (mutated, log)."""
        import random

        if not data:
            data = os.urandom(random.randint(8, 64))

        mutated = bytearray(data)
        mutations: list[str] = []

        strategy = random.choice(["bitflip", "byte_replace", "insert", "delete", "truncate"])

        if strategy == "bitflip" and mutated:
            pos = random.randint(0, len(mutated) - 1)
            bit = 1 << random.randint(0, 7)
            mutated[pos] ^= bit
            mutations.append(f"bitflip@{pos} bit={bit:#04x}")

        elif strategy == "byte_replace" and mutated:
            pos = random.randint(0, len(mutated) - 1)
            old_val = mutated[pos]
            mutated[pos] = random.randint(0, 255)
            mutations.append(f"byte_replace@{pos} {old_val:#04x}->{mutated[pos]:#04x}")

        elif strategy == "insert":
            pos = random.randint(0, len(mutated))
            count = random.randint(1, 16)
            insert_bytes = os.urandom(count)
            mutated[pos:pos] = insert_bytes
            mutations.append(f"insert@{pos} count={count}")

        elif strategy == "delete" and len(mutated) > 1:
            pos = random.randint(0, len(mutated) - 1)
            count = min(random.randint(1, 8), len(mutated) - pos)
            del mutated[pos:pos + count]
            mutations.append(f"delete@{pos} count={count}")

        elif strategy == "truncate" and len(mutated) > 1:
            new_len = random.randint(1, len(mutated) - 1)
            mutated = mutated[:new_len]
            mutations.append(f"truncate len={new_len}")

        return bytes(mutated), mutations


# ---------------------------------------------------------------------------
# Stub transport (used when transport module not yet available)
# ---------------------------------------------------------------------------

_AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
_BTPROTO_L2CAP = 0
_BTPROTO_RFCOMM = 3


class _StubTransport:
    """Minimal transport that uses raw sockets when the transport module is unavailable."""

    def __init__(
        self,
        address: str,
        transport_type: str = "l2cap",
        psm: int = 1,
        channel: int = 1,
        cid: int = 4,
        timeout: float = 5.0,
    ) -> None:
        self.address = address
        self.transport_type = transport_type
        self.psm = psm
        self.channel = channel
        self.cid = cid
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._connected = False

    def connect(self) -> bool:
        """Open a Bluetooth socket to the target."""
        try:
            if self.transport_type == "l2cap":
                self._sock = socket.socket(_AF_BLUETOOTH, socket.SOCK_SEQPACKET, _BTPROTO_L2CAP)
                self._sock.settimeout(self.timeout)
                self._sock.connect((self.address, self.psm))
            elif self.transport_type == "rfcomm":
                self._sock = socket.socket(_AF_BLUETOOTH, socket.SOCK_STREAM, _BTPROTO_RFCOMM)
                self._sock.settimeout(self.timeout)
                self._sock.connect((self.address, self.channel))
            elif self.transport_type == "ble":
                # BLE L2CAP fixed-channel -- requires kernel support
                self._sock = socket.socket(_AF_BLUETOOTH, socket.SOCK_SEQPACKET, _BTPROTO_L2CAP)
                self._sock.settimeout(self.timeout)
                self._sock.connect((self.address, self.cid))
            else:
                error(f"Unknown transport type: {self.transport_type}")
                return False
            self._connected = True
            return True
        except OSError as exc:
            error(f"Transport connect failed ({self.transport_type}): {exc}")
            self._connected = False
            return False

    def send(self, data: bytes) -> int:
        """Send data over the transport. Raises on failure."""
        if self._sock is None:
            raise BrokenPipeError("Not connected")
        return self._sock.send(data)

    def recv(self, bufsize: int = 4096) -> bytes | None:
        """Receive data with timeout. Returns None on timeout."""
        if self._sock is None:
            return None
        try:
            data = self._sock.recv(bufsize)
            return data if data else None
        except socket.timeout:
            return None

    def close(self) -> None:
        """Close the socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    def reconnect(self) -> bool:
        """Close and reconnect with backoff."""
        self.close()
        for attempt in range(3):
            delay = min(2 ** attempt, 30)
            time.sleep(delay)
            try:
                if self.connect():
                    return True
            except OSError:
                continue
        return False


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
        strategy: str = "random",
        duration: float | None = None,
        max_iterations: int | None = None,
        session_dir: str = "",
        cooldown: float = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        self.target = target
        self.protocols = protocols
        self.strategy = strategy
        self.duration = duration
        self.max_iterations = max_iterations
        self.session_dir = session_dir or "."
        self.cooldown = cooldown

        # Fuzz artifact directory
        self._fuzz_dir = os.path.join(self.session_dir, "fuzz")
        os.makedirs(self._fuzz_dir, exist_ok=True)

        # Crash database
        crash_db_path = os.path.join(self._fuzz_dir, "crashes.db")
        if _HAS_CRASH_DB:
            self.crash_db: Any = CrashDB(crash_db_path)
        else:
            self.crash_db = _StubCrashDB(crash_db_path)

        # Seed corpus
        corpus_dir = os.path.join(self._fuzz_dir, "corpus")
        if _HAS_CORPUS:
            self.corpus: Any = Corpus(corpus_dir)
        else:
            self.corpus = _StubCorpus(corpus_dir)

        # Mutator
        if _HAS_MUTATORS:
            self._mutator: Any = CorpusMutator()
        else:
            self._mutator = _StubMutator()

        # Campaign state
        self.stats = CampaignStats()
        self._running = False
        self._transports: dict[str, Any] = {}
        self._last_stats_time: float = 0.0

        # Seen response fingerprints (for corpus dedup, fix #8)
        self._seen_responses: set[str] = set()

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

    # ------------------------------------------------------------------
    # Transport setup
    # ------------------------------------------------------------------

    def _setup_transports(self) -> dict[str, Any]:
        """Create transport instances for each configured protocol.

        Returns:
            Mapping of protocol name to transport instance.
        """
        transports: dict[str, Any] = {}

        for protocol in self.protocols:
            spec = PROTOCOL_TRANSPORT_MAP.get(protocol)
            if spec is None:
                warning(f"Skipping unknown protocol: {protocol}")
                continue

            ttype = spec["type"]

            if _HAS_TRANSPORT:
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
                    )
            else:
                transports[protocol] = _StubTransport(
                    self.target,
                    transport_type=ttype,
                    psm=spec.get("psm", 1),
                    channel=spec.get("channel", 1),
                    cid=spec.get("cid", 4),
                )

        self._transports = transports
        return transports

    # ------------------------------------------------------------------
    # Fuzz case generation
    # ------------------------------------------------------------------

    def _generate_fuzz_case(self, protocol: str) -> tuple[bytes, list[str]]:
        """Generate a mutated fuzz case for the given protocol.

        Retrieves a random seed from the corpus, applies mutations,
        and returns the mutated payload along with a mutation log.

        Args:
            protocol: Protocol name to generate a case for.

        Returns:
            Tuple of (fuzz_bytes, mutation_log).
        """
        seed = self.corpus.get_random_seed(protocol)

        # Handle None seed from corpus (generate random bytes as fallback)
        if seed is None:
            import random as _rng
            seed = os.urandom(_rng.randint(8, 256))

        # CorpusMutator.mutate() returns bytes, not a tuple.
        # Wrap the call to always return (bytes, list[str]).
        result = self._mutator.mutate(seed)
        if isinstance(result, tuple):
            mutated, mutation_log = result
        else:
            mutated = result
            mutation_log = ["mutated"]
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
    ) -> None:
        """Analyze the target's response to a fuzz case.

        Checks for anomalies such as timeouts (potential hangs),
        unexpected error codes, or response patterns that suggest
        interesting behavior worth adding to the corpus.

        Args:
            protocol: Protocol that was fuzzed.
            payload: The fuzz payload that was sent.
            response: Response bytes, or ``None`` if the target timed out.
            mutation_log: List of mutation operations applied.
        """
        if response is None:
            # Timeout -- potential hang. Don't classify as crash yet;
            # the main loop handles connection-level errors.
            return

        # Check for interesting response patterns that suggest new code paths.
        # If the response is significantly different from typical responses,
        # save it as an interesting input for the corpus.
        if len(response) > 0:
            # Only add if the response fingerprint hasn't been seen before
            # to prevent explosive corpus growth.
            fingerprint = hashlib.sha256(response[:32]).hexdigest()
            if fingerprint not in self._seen_responses:
                self._seen_responses.add(fingerprint)
                try:
                    self.corpus.add_seed(
                        protocol,
                        payload,
                        name=f"interesting_{self.stats.iterations}",
                    )
                except (OSError, AttributeError):
                    pass

    # ------------------------------------------------------------------
    # Crash handling
    # ------------------------------------------------------------------

    def _handle_crash(
        self,
        crash_type: str,
        protocol: str,
        payload: bytes,
        mutation_log: list[str],
    ) -> None:
        """Handle a detected crash: log, cooldown, verify target health.

        Args:
            crash_type: Type of crash (``connection_drop``, ``timeout``,
                ``device_disappeared``, ``unexpected_response``).
            protocol: Protocol that was being fuzzed when crash occurred.
            payload: The fuzz payload that triggered the crash.
            mutation_log: Mutations applied to produce the payload.
        """
        severity = CRASH_SEVERITY.get(crash_type, "MEDIUM")
        self.stats.crashes += 1

        # Log to crash database
        try:
            self.crash_db.log_crash(
                self.target,
                protocol,
                payload,
                crash_type,
                severity=severity,
                mutation_log="\n".join(mutation_log),
            )
        except Exception as exc:
            error(f"Failed to log crash: {exc}")

        crash_num = self.stats.crashes
        info(
            f"[bt.red]CRASH #{crash_num}[/bt.red] "
            f"type=[bt.yellow]{crash_type}[/bt.yellow] "
            f"severity=[bt.yellow]{severity}[/bt.yellow] "
            f"protocol=[bt.cyan]{protocol}[/bt.cyan] "
            f"payload_size={len(payload)}"
        )

        # Cooldown: wait for target recovery
        info(f"Cooling down {self.cooldown:.0f}s for target recovery...")
        time.sleep(self.cooldown)

        # Verify target is still alive
        if not _check_target_alive(self.target):
            warning("Target not responding after cooldown. Extending wait...")
            time.sleep(TARGET_DEAD_TIMEOUT)
            if not _check_target_alive(self.target):
                error("Target appears permanently down. Stopping campaign.")
                self._running = False
                return

        # Reconnect the transport for this protocol
        transport = self._transports.get(protocol)
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
            self.stats.reconnects += 1

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
        """Select the next protocol using round-robin rotation."""
        idx = self.stats.iterations % len(self.protocols)
        return self.protocols[idx]

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Execute the fuzzing campaign.

        Installs a SIGINT handler for graceful shutdown, sets up transports,
        and enters the main fuzz loop. On completion (or interrupt), saves
        campaign state and prints a final summary.

        Returns:
            Summary dict with campaign statistics.
        """
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

        # Verify target is reachable
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
        console.print()

        # Main fuzzing loop
        try:
            while self._should_continue():
                protocol = self._next_protocol()
                self.stats.current_protocol = protocol
                transport = self._transports.get(protocol)

                if transport is None:
                    self.stats.iterations += 1
                    continue

                # Generate fuzz case
                fuzz_case, mutation_log = self._generate_fuzz_case(protocol)

                # Send and observe
                try:
                    # BluetoothTransport uses a .connected property,
                    # _StubTransport uses .is_connected() method.
                    _is_conn = (
                        transport.connected
                        if hasattr(transport, "connected") and isinstance(
                            type(transport).__dict__.get("connected"), property
                        )
                        else transport.is_connected()
                        if hasattr(transport, "is_connected")
                        else False
                    )
                    if not _is_conn:
                        if not transport.connect():
                            self.stats.errors += 1
                            self.stats.iterations += 1
                            continue

                    transport.send(fuzz_case)
                    self.stats.packets_sent += 1
                    self.stats.protocol_breakdown[protocol] = (
                        self.stats.protocol_breakdown.get(protocol, 0) + 1
                    )

                    response = transport.recv()
                    self._analyze_response(protocol, fuzz_case, response, mutation_log)

                except ConnectionResetError:
                    self._handle_crash("connection_drop", protocol, fuzz_case, mutation_log)
                except BrokenPipeError:
                    self._handle_crash("connection_drop", protocol, fuzz_case, mutation_log)
                except socket.timeout:
                    self._handle_crash("timeout", protocol, fuzz_case, mutation_log)
                except OSError as exc:
                    if "Host is down" in str(exc) or "No route" in str(exc):
                        self._handle_crash("device_disappeared", protocol, fuzz_case, mutation_log)
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
            seeds.append((os.urandom(_rng.randint(8, 128)), f"random_{i}"))

        for data, label in seeds:
            self.corpus.add_seed(protocol, data, name=label)

    # ------------------------------------------------------------------
    # Statistics display
    # ------------------------------------------------------------------

    def _print_stats(self) -> None:
        """Print a Rich table with current campaign statistics."""
        table = Table(
            title=f"[bold {RED}]Fuzz Campaign Status[/bold {RED}]",
            show_lines=False,
            border_style=DIM,
            header_style=Style(bold=True, color=CYAN),
            title_style=Style(bold=True, color=RED),
        )
        table.add_column("Metric", style="bold white", min_width=18)
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

        console.print()
        console.print(table)
        console.print()

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
            proto_table = Table(
                title=f"[bold {CYAN}]Per-Protocol Breakdown[/bold {CYAN}]",
                show_lines=False,
                border_style=DIM,
                header_style=Style(bold=True, color=CYAN),
            )
            proto_table.add_column("Protocol", style=f"bold {PURPLE}", min_width=16)
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
            console.print(proto_table)

        # Crash listing
        crash_count = self.crash_db.crash_count()
        if crash_count > 0:
            console.print()
            info(f"[bt.red]{crash_count} crash(es)[/bt.red] logged to: {self._fuzz_dir}")
            try:
                crashes = self.crash_db.get_crashes()
                crash_table = Table(
                    title=f"[bold {RED}]Crashes[/bold {RED}]",
                    show_lines=True,
                    border_style=DIM,
                    header_style=Style(bold=True, color=RED),
                )
                crash_table.add_column("#", style=DIM, width=4, justify="right")
                crash_table.add_column("Type", style=f"bold {YELLOW}", min_width=18)
                crash_table.add_column("Severity", min_width=10)
                crash_table.add_column("Protocol", style=PURPLE, min_width=12)
                crash_table.add_column("Payload Size", justify="right", min_width=10)
                crash_table.add_column("Timestamp", style=DIM, min_width=20)

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

                console.print(crash_table)
                if crash_count > 20:
                    info(f"... and {crash_count - 20} more. See {self._fuzz_dir}")
            except Exception:
                pass
        else:
            success("No crashes detected during this campaign.")

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def _finalize(self) -> None:
        """Clean up transports, save state, print summary, log to session."""
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
        except OSError as exc:
            warning(f"Could not save campaign stats: {exc}")

        # Print summary
        self._print_final_summary()

        # Log to session system
        log_command(
            "fuzz_campaign",
            self._build_summary(),
            category="fuzz",
            target=self.target,
        )

    def _build_summary(self) -> dict:
        """Build a summary dict of the campaign for serialization."""
        return {
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

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def save_state(self) -> str:
        """Save campaign state to JSON for later resumption.

        Returns:
            Path to the saved state file.
        """
        state = {
            "target": self.target,
            "protocols": self.protocols,
            "strategy": self.strategy,
            "duration": self.duration,
            "max_iterations": self.max_iterations,
            "cooldown": self.cooldown,
            "session_dir": self.session_dir,
            "stats": asdict(self.stats),
            "timestamp": datetime.now().isoformat(),
        }
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

        # Restore stats
        saved_stats = state.get("stats", {})
        campaign.stats = CampaignStats(
            iterations=saved_stats.get("iterations", 0),
            packets_sent=saved_stats.get("packets_sent", 0),
            crashes=saved_stats.get("crashes", 0),
            reconnects=saved_stats.get("reconnects", 0),
            start_time=time.time(),  # Reset start time for the resumed run
            current_protocol=saved_stats.get("current_protocol", ""),
            errors=saved_stats.get("errors", 0),
            protocol_breakdown=saved_stats.get("protocol_breakdown", {}),
        )

        info(
            f"Resumed campaign from {state_path} "
            f"(prev: {saved_stats.get('iterations', 0):,} iterations, "
            f"{saved_stats.get('crashes', 0)} crashes)"
        )
        return campaign

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _handle_interrupt(self, signum: int, frame: Any) -> None:
        """Handle SIGINT (Ctrl+C) for graceful campaign shutdown.

        Sets the running flag to False so the main loop exits cleanly.
        State is saved by the finalization step in ``run()``.
        """
        info("[bt.yellow]Interrupt received. Stopping campaign gracefully...[/bt.yellow]")
        self._running = False
