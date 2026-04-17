"""Response-based state inference for protocol-aware fuzzing.

Extracts protocol state IDs from Bluetooth response bytes, tracks state
sequences, builds a directed state graph, and provides AFLNet-style
state-aware seed selection.

Research basis:
  - AFLNet (ICST 2020) -- state inference from response codes
  - BLEEM (USENIX Sec 2023) -- packet sequence as state indicator

This module intentionally redefines protocol constants locally to avoid
circular imports with blue_tap.modules.fuzzing.protocols.*.
"""

from __future__ import annotations

import hashlib
import math
import random
import re
import struct
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# StateID -- hashable identifier for a single protocol state
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StateID:
    """Unique identifier for a protocol state derived from a response.

    Attributes:
        protocol:   Protocol name (e.g. "sdp", "att", "l2cap").
        opcode:     Response PDU type / command code.
        error_code: Protocol-specific error code, 0 if not an error.
        extra:      Sub-type info (e.g. continuation state, request opcode).
    """

    protocol: str
    opcode: int
    error_code: int = 0
    extra: int = 0

    def __str__(self) -> str:
        parts = [f"{self.protocol}:op=0x{self.opcode:02X}"]
        if self.error_code:
            parts.append(f"err=0x{self.error_code:02X}")
        if self.extra:
            parts.append(f"extra=0x{self.extra:02X}")
        return f"State({', '.join(parts)})"


# ===========================================================================
# Protocol constants (local copies -- avoid circular imports)
# ===========================================================================

# SDP PDU IDs
_SDP_ERROR_RSP = 0x01
_SDP_SERVICE_SEARCH_RSP = 0x03
_SDP_SERVICE_ATTR_RSP = 0x05
_SDP_SERVICE_SEARCH_ATTR_RSP = 0x07

# ATT Opcodes
_ATT_ERROR_RSP = 0x01
_ATT_EXCHANGE_MTU_RSP = 0x03
_ATT_FIND_INFO_RSP = 0x05
_ATT_FIND_BY_TYPE_VALUE_RSP = 0x07
_ATT_READ_BY_TYPE_RSP = 0x09
_ATT_READ_RSP = 0x0B
_ATT_READ_BLOB_RSP = 0x0D
_ATT_READ_MULTIPLE_RSP = 0x0F
_ATT_READ_BY_GROUP_TYPE_RSP = 0x11
_ATT_WRITE_RSP = 0x13
_ATT_PREPARE_WRITE_RSP = 0x17
_ATT_EXECUTE_WRITE_RSP = 0x19
_ATT_HANDLE_VALUE_NTF = 0x1B
_ATT_HANDLE_VALUE_IND = 0x1D
_ATT_HANDLE_VALUE_CFM = 0x1E
_ATT_WRITE_CMD = 0x52
_ATT_SIGNED_WRITE_CMD = 0xD2

# L2CAP Signaling Command Codes
_L2CAP_CMD_REJECT = 0x01
_L2CAP_CONN_RSP = 0x03
_L2CAP_CONF_RSP = 0x05
_L2CAP_DISCONN_RSP = 0x07
_L2CAP_ECHO_RSP = 0x09
_L2CAP_INFO_RSP = 0x0B

# RFCOMM Frame Types (with P/F bit set)
_RFCOMM_SABM = 0x3F
_RFCOMM_UA = 0x73
_RFCOMM_DM = 0x1F
_RFCOMM_DISC = 0x53
_RFCOMM_UIH = 0xFF
# Without P/F bit
_RFCOMM_SABM_NP = 0x2F
_RFCOMM_UA_NP = 0x63
_RFCOMM_DM_NP = 0x0F
_RFCOMM_DISC_NP = 0x43
_RFCOMM_UIH_NP = 0xEF

# SMP Command Codes
_SMP_PAIRING_REQUEST = 0x01
_SMP_PAIRING_RESPONSE = 0x02
_SMP_PAIRING_CONFIRM = 0x03
_SMP_PAIRING_RANDOM = 0x04
_SMP_PAIRING_FAILED = 0x05
_SMP_SECURITY_REQUEST = 0x0B
_SMP_PAIRING_PUBLIC_KEY = 0x0C

# OBEX Response Codes
_OBEX_CONTINUE = 0x90
_OBEX_SUCCESS = 0xA0
_OBEX_BAD_REQUEST = 0xC0
_OBEX_UNAUTHORIZED = 0xC1
_OBEX_FORBIDDEN = 0xC3
_OBEX_NOT_FOUND = 0xC4
_OBEX_INTERNAL_ERROR = 0xD0

# BNEP Packet Types
_BNEP_GENERAL_ETHERNET = 0x00
_BNEP_CONTROL = 0x01
_BNEP_COMPRESSED = 0x02

# BNEP Control Types
_BNEP_SETUP_CONNECTION_REQ = 0x01
_BNEP_SETUP_CONNECTION_RSP = 0x02
_BNEP_FILTER_NET_TYPE_SET = 0x03
_BNEP_FILTER_NET_TYPE_RSP = 0x04


# ===========================================================================
# State extractors -- one per protocol
# ===========================================================================

def extract_state_sdp(response: bytes) -> StateID:
    """Extract state from an SDP response.

    SDP PDU header: PDU_ID (byte 0), Transaction ID (bytes 1-2 BE),
    Parameter Length (bytes 3-4 BE).

    For Error (0x01): ErrorCode from bytes 5-6 (big-endian uint16).
    For non-error: continuation state presence from last byte.
    """
    if len(response) < 5:
        # Truncated -- use whatever we have
        pdu_id = response[0] if response else 0
        return StateID("sdp", pdu_id, 0, 0)

    pdu_id = response[0]
    error_code = 0
    extra = 0

    if pdu_id == _SDP_ERROR_RSP:
        if len(response) >= 7:
            error_code = struct.unpack(">H", response[5:7])[0]
    else:
        # Continuation state: last byte != 0x00 means more data
        extra = 1 if response[-1] != 0x00 else 0

    return StateID("sdp", pdu_id, error_code, extra)


def extract_state_att(response: bytes) -> StateID:
    """Extract state from a BLE ATT response.

    ATT opcode is byte 0.
    For Error (0x01): request_opcode (byte 1), handle (bytes 2-3 LE),
    error_code (byte 4).
    """
    if not response:
        return StateID("att", 0, 0, 0)

    opcode = response[0]
    error_code = 0
    extra = 0

    if opcode == _ATT_ERROR_RSP:
        if len(response) >= 5:
            extra = response[1]       # request opcode that caused the error
            error_code = response[4]  # ATT error code
        elif len(response) >= 2:
            extra = response[1]
    # Command opcodes -- no response expected, but if we see them as
    # "responses" (e.g. server sending write CMD), just record the opcode.

    return StateID("att", opcode, error_code, extra)


def extract_state_l2cap(response: bytes) -> StateID:
    """Extract state from an L2CAP signaling response.

    Signaling header: Code (byte 0), Identifier (byte 1),
    Length (bytes 2-3 LE).

    For ConnRsp (0x03): Result field at bytes 8-9 (LE).
    For ConfRsp (0x05): Result field at bytes 8-9 (LE).
    """
    if not response:
        return StateID("l2cap", 0, 0, 0)

    code = response[0]
    error_code = 0
    extra = 0

    if code == _L2CAP_CONN_RSP:
        # ConnRsp payload: DCID(2) + SCID(2) + Result(2) + Status(2)
        # Result is at offset 8 from start of signaling command
        # (code=1 + id=1 + len=2 + dcid=2 + scid=2 = offset 8)
        if len(response) >= 10:
            error_code = struct.unpack("<H", response[8:10])[0]
    elif code == _L2CAP_CONF_RSP:
        # ConfRsp payload: SCID(2) + Flags(2) + Result(2) + Config(var)
        # Result is at offset 8 (code=1 + id=1 + len=2 + scid=2 + flags=2)
        if len(response) >= 10:
            error_code = struct.unpack("<H", response[8:10])[0]
    elif code == _L2CAP_CMD_REJECT:
        # Reject: Reason(2)
        if len(response) >= 6:
            error_code = struct.unpack("<H", response[4:6])[0]

    return StateID("l2cap", code, error_code, extra)


def extract_state_rfcomm(response: bytes) -> StateID:
    """Extract state from an RFCOMM frame.

    Address byte (byte 0): DLCI in bits 2-7.
    Control byte (byte 1): frame type.
    For UIH frames: check for multiplexer commands.
    """
    if len(response) < 2:
        opcode = response[0] if response else 0
        return StateID("rfcomm", opcode, 0, 0)

    address = response[0]
    control = response[1]
    dlci = (address >> 2) & 0x3F
    extra = dlci

    # Normalize control byte: mask off P/F bit (bit 4) for frame type
    frame_type = control & ~0x10

    error_code = 0
    # For UIH frames on DLCI 0, extract multiplexer command type
    if frame_type in (_RFCOMM_UIH & ~0x10, _RFCOMM_UIH_NP) and dlci == 0:
        # UIH on DLCI 0 = multiplexer command
        # Mux header starts after length field(s)
        # Minimum: addr(1) + ctrl(1) + len(1) + mux_type(1) = 4 bytes
        if len(response) >= 4:
            # Length field: bit 0 of byte 2 is EA bit
            # If EA=1, length is single byte; if EA=0, two bytes
            if response[2] & 0x01:
                mux_offset = 3
            else:
                mux_offset = 4
            if len(response) > mux_offset:
                error_code = response[mux_offset]  # mux command type byte

    return StateID("rfcomm", frame_type, error_code, extra)


def extract_state_smp(response: bytes) -> StateID:
    """Extract state from an SMP command.

    SMP Code is byte 0 (after L2CAP header, CID 0x0006).
    For Pairing Failed (0x05): reason byte at byte 1.
    """
    if not response:
        return StateID("smp", 0, 0, 0)

    code = response[0]
    error_code = 0
    extra = 0

    if code == _SMP_PAIRING_FAILED:
        if len(response) >= 2:
            error_code = response[1]  # reason code (0x01-0x0E)

    return StateID("smp", code, error_code, extra)


def extract_state_obex(response: bytes) -> StateID:
    """Extract state from an OBEX response.

    Response code is byte 0. Bit 7 is the Final bit.
    """
    if not response:
        return StateID("obex", 0, 0, 0)

    raw_code = response[0]
    # Final bit is bit 7
    final_bit = (raw_code >> 7) & 0x01
    # Response code with final bit (as defined in spec)
    opcode = raw_code

    return StateID("obex", opcode, 0, final_bit)


def extract_state_bnep(response: bytes) -> StateID:
    """Extract state from a BNEP frame.

    Type from first byte (bits 0-6). Bit 7 is extension flag.
    For Control (0x01): extract control type from second byte.
    """
    if not response:
        return StateID("bnep", 0, 0, 0)

    pkt_type = response[0] & 0x7F  # bits 0-6
    error_code = 0
    extra = 0

    if pkt_type == _BNEP_CONTROL:
        if len(response) >= 2:
            error_code = response[1]  # control type byte

    return StateID("bnep", pkt_type, error_code, extra)


def extract_state_at(response: bytes) -> StateID:
    """Extract state from an AT command response (text-based).

    Responses: "OK\\r\\n", "ERROR\\r\\n", "+CME ERROR: N\\r\\n".
    Informational: "+BRSF:...", "+CIND:...", etc.
    """
    if not response:
        return StateID("at", 0, 0, 0)

    try:
        text = response.decode("ascii", errors="replace").strip()
    except Exception:
        text = ""

    if not text:
        return StateID("at", 0, 0, 0)

    # +CME ERROR: <code>
    cme_match = re.match(r"\+CME\s*ERROR:\s*(\d+)", text, re.IGNORECASE)
    if cme_match:
        code = int(cme_match.group(1))
        return StateID("at", 2, code, 0)  # opcode 2 = extended error

    if text.upper().startswith("ERROR"):
        return StateID("at", 1, 0, 0)  # opcode 1 = generic error

    if text.upper().startswith("OK"):
        return StateID("at", 0, 0, 0)  # opcode 0 = success

    # Informational response: +<INDICATOR>: ...
    info_match = re.match(r"\+([A-Z]+)", text, re.IGNORECASE)
    if info_match:
        indicator = info_match.group(1).upper()
        extra = int.from_bytes(hashlib.md5(indicator.encode("ascii")).digest()[:2], "big")
        return StateID("at", 3, 0, extra)  # opcode 3 = informational

    # Unknown text response
    return StateID("at", 0xFF, 0, len(response))


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_EXTRACTORS: dict[str, Any] = {
    "sdp": extract_state_sdp,
    "att": extract_state_att,
    "l2cap": extract_state_l2cap,
    "rfcomm": extract_state_rfcomm,
    "smp": extract_state_smp,
    "obex": extract_state_obex,
    "bnep": extract_state_bnep,
    "at": extract_state_at,
}


def extract_state(protocol: str, response: bytes) -> StateID:
    """Dispatch to the correct protocol-specific state extractor.

    Falls back to a generic extractor for unknown protocols:
    StateID(protocol, response[0], 0, len(response)).
    """
    extractor = _EXTRACTORS.get(protocol.lower())
    if extractor is not None:
        return extractor(response)

    # Generic fallback
    opcode = response[0] if response else 0
    return StateID(protocol.lower(), opcode, 0, len(response))


# ===========================================================================
# StateSequence -- ordered list of StateIDs from one seed execution
# ===========================================================================

class StateSequence:
    """Ordered list of StateIDs observed during one seed execution.

    Attributes:
        states:    Raw ordered list of all observed StateIDs.
        seed:      The seed bytes that produced this sequence (optional).
        iteration: The campaign iteration when this was observed.
    """

    __slots__ = ("states", "seed", "iteration")

    def __init__(
        self,
        seed: bytes | None = None,
        iteration: int = 0,
    ) -> None:
        self.states: list[StateID] = []
        self.seed = seed
        self.iteration = iteration

    def append(self, state: StateID) -> None:
        """Add a state observation."""
        self.states.append(state)

    def trimmed(self) -> list[StateID]:
        """Return sequence with consecutive duplicates removed (AFLNet pattern).

        Example: [220, 220, 250, 250] -> [220, 250]
        """
        if not self.states:
            return []
        result = [self.states[0]]
        for s in self.states[1:]:
            if s != result[-1]:
                result.append(s)
        return result

    def hash(self) -> str:
        """SHA-256 of the trimmed sequence for fast comparison."""
        trimmed = self.trimmed()
        h = hashlib.sha256()
        for s in trimmed:
            # Encode each StateID deterministically
            h.update(s.protocol.encode("utf-8"))
            h.update(struct.pack(">III", s.opcode, s.error_code, s.extra))
        return h.hexdigest()

    def __len__(self) -> int:
        return len(self.states)

    def __repr__(self) -> str:
        return f"StateSequence(len={len(self.states)}, hash={self.hash()[:12]})"


# ===========================================================================
# StateGraph -- directed graph of state transitions (IPSM equivalent)
# ===========================================================================

class StateGraph:
    """Directed graph of state transitions.

    Nodes are StateIDs, edges are observed transitions.
    """

    def __init__(self) -> None:
        self._nodes: set[StateID] = set()
        self._edges: set[tuple[StateID, StateID]] = set()

    def add_transition(self, from_state: StateID, to_state: StateID) -> bool:
        """Add a transition edge. Returns True if the transition is new."""
        self._nodes.add(from_state)
        self._nodes.add(to_state)
        edge = (from_state, to_state)
        if edge in self._edges:
            return False
        self._edges.add(edge)
        return True

    def is_new_transition(self, from_state: StateID, to_state: StateID) -> bool:
        """Check if a transition would be new without modifying the graph."""
        return (from_state, to_state) not in self._edges

    def transition_count(self) -> int:
        """Total unique transitions discovered."""
        return len(self._edges)

    def node_count(self) -> int:
        """Total unique states reached."""
        return len(self._nodes)

    def coverage_score(self) -> float:
        """Ratio of discovered transitions to theoretical maximum (N^2)."""
        n = len(self._nodes)
        if n == 0:
            return 0.0
        max_edges = n * n
        return len(self._edges) / max_edges

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "nodes": [
                {
                    "protocol": s.protocol,
                    "opcode": s.opcode,
                    "error_code": s.error_code,
                    "extra": s.extra,
                }
                for s in sorted(self._nodes, key=lambda s: (s.protocol, s.opcode))
            ],
            "edges": [
                {
                    "from": {
                        "protocol": e[0].protocol,
                        "opcode": e[0].opcode,
                        "error_code": e[0].error_code,
                        "extra": e[0].extra,
                    },
                    "to": {
                        "protocol": e[1].protocol,
                        "opcode": e[1].opcode,
                        "error_code": e[1].error_code,
                        "extra": e[1].extra,
                    },
                }
                for e in sorted(
                    self._edges,
                    key=lambda e: (e[0].protocol, e[0].opcode, e[1].protocol, e[1].opcode),
                )
            ],
            "node_count": self.node_count(),
            "transition_count": self.transition_count(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StateGraph:
        """Deserialize from JSON-compatible dict."""
        graph = cls()
        for node_data in data.get("nodes", []):
            graph._nodes.add(StateID(**node_data))
        for edge_data in data.get("edges", []):
            from_state = StateID(**edge_data["from"])
            to_state = StateID(**edge_data["to"])
            graph._edges.add((from_state, to_state))
        return graph


# ===========================================================================
# StateInfo -- per-state metadata for AFLNet-style seed selection
# ===========================================================================

@dataclass
class StateInfo:
    """Per-state metadata tracking seeds, paths, and fuzzing activity.

    Used by the AFLNet scoring formula to prioritize under-explored states.
    """

    state_id: StateID
    seeds: list[bytes] = field(default_factory=list)
    paths: int = 0
    paths_discovered: int = 0
    selected_times: int = 0
    fuzz_count: int = 0
    score: float = 0.0

    def compute_score(self) -> float:
        """Compute AFLNet selection score.

        Formula: 1000 * 2^(-log10(log10(fuzz_count+1) * selected_times + 1))
                      * 2^(log(paths_discovered+1))

        Frequently fuzzed states get lower scores; productive states (many
        new paths discovered) get higher scores.
        """
        fc = self.fuzz_count + 1
        st = self.selected_times
        pd = self.paths_discovered + 1

        # Inner term: log10(fuzz_count + 1) * selected_times
        inner = math.log10(fc) * st
        # Penalty exponent: -log10(inner + 1)
        penalty = -math.log10(inner + 1) if inner + 1 > 0 else 0.0
        # Reward exponent: log(paths_discovered + 1) (natural log)
        reward = math.log(pd)

        self.score = 1000.0 * (2.0 ** penalty) * (2.0 ** reward)
        return self.score

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict (seeds stored as hex)."""
        return {
            "state_id": {
                "protocol": self.state_id.protocol,
                "opcode": self.state_id.opcode,
                "error_code": self.state_id.error_code,
                "extra": self.state_id.extra,
            },
            "seeds_hex": [s.hex() for s in self.seeds],
            "paths": self.paths,
            "paths_discovered": self.paths_discovered,
            "selected_times": self.selected_times,
            "fuzz_count": self.fuzz_count,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StateInfo:
        """Deserialize from JSON-compatible dict."""
        state_id = StateID(**data["state_id"])
        seeds = [bytes.fromhex(h) for h in data.get("seeds_hex", [])]
        info = cls(
            state_id=state_id,
            seeds=seeds,
            paths=data.get("paths", 0),
            paths_discovered=data.get("paths_discovered", 0),
            selected_times=data.get("selected_times", 0),
            fuzz_count=data.get("fuzz_count", 0),
            score=data.get("score", 0.0),
        )
        return info


# ===========================================================================
# StateTracker -- main class integrating all state inference components
# ===========================================================================

class StateTracker:
    """Main state tracking engine integrating extractors, sequences, graphs,
    and AFLNet-style seed selection.

    Usage in the fuzzing loop::

        tracker = StateTracker()
        tracker.reset_sequence("sdp")

        # After each response:
        is_novel = tracker.record("sdp", response_bytes)
        if is_novel:
            corpus.save(seed, reason=f"novel_state_{tracker.last_state}")

        # When selecting next target:
        target = tracker.select_target_state("sdp")
        seed = tracker.select_seed_for_state(target)
    """

    def __init__(self) -> None:
        # Per-protocol state graphs
        self._graphs: dict[str, StateGraph] = {}
        # Per-protocol current sequences (reset each seed execution)
        self._current_sequences: dict[str, StateSequence] = {}
        # Set of seen sequence hashes for novelty detection
        self._seen_hashes: set[str] = set()
        # Mapping: sequence_hash -> seed bytes for reproduction
        self._hash_to_seed: dict[str, bytes] = {}
        # Per-state metadata: (protocol, state_id) -> StateInfo
        self._state_info: dict[StateID, StateInfo] = {}
        # Last extracted state (for external inspection)
        self.last_state: StateID | None = None

    # -- Core recording API ------------------------------------------------

    def record(self, protocol: str, response: bytes,
               seed: bytes | None = None) -> bool:
        """Extract state from response, update graph, return True if novel.

        If *seed* is provided, it is automatically registered for the
        discovered state (so state-aware seed selection works).

        A state is "novel" if:
          1. The transition from the previous state is new, OR
          2. This is the first observation of this state.
        """
        protocol = protocol.lower()
        state = extract_state(protocol, response)
        self.last_state = state

        # Ensure graph exists
        if protocol not in self._graphs:
            self._graphs[protocol] = StateGraph()
        graph = self._graphs[protocol]

        # Ensure current sequence exists
        if protocol not in self._current_sequences:
            self._current_sequences[protocol] = StateSequence()
        seq = self._current_sequences[protocol]

        novel = False

        # Check transition novelty
        if seq.states:
            prev = seq.states[-1]
            if graph.add_transition(prev, state):
                novel = True
        else:
            # First state in sequence -- check if node is new
            if state not in graph._nodes:
                novel = True
            graph._nodes.add(state)

        seq.append(state)

        # Update StateInfo
        if state not in self._state_info:
            self._state_info[state] = StateInfo(state_id=state)
            novel = True
        self._state_info[state].paths += 1

        # Auto-register seed for this state if provided
        if seed is not None:
            self.register_seed_for_state(state, seed)

        return novel

    def finalize_sequence(self, protocol: str, seed: bytes | None = None) -> bool:
        """Finalize current sequence after seed execution completes.

        Hashes the trimmed sequence and checks for novelty.
        Returns True if this sequence hash has not been seen before.
        """
        protocol = protocol.lower()
        seq = self._current_sequences.get(protocol)
        if seq is None or not seq.states:
            return False

        seq.seed = seed
        seq_hash = seq.hash()

        is_new = seq_hash not in self._seen_hashes
        if is_new:
            self._seen_hashes.add(seq_hash)
            if seed is not None:
                self._hash_to_seed[seq_hash] = seed
            # Credit all states in this sequence with a new path
            for state in set(seq.trimmed()):
                info = self._state_info.get(state)
                if info is not None:
                    info.paths_discovered += 1

        return is_new

    def reset_sequence(self, protocol: str) -> None:
        """Reset the current sequence for a new seed execution."""
        self._current_sequences[protocol.lower()] = StateSequence()

    def current_sequence(self, protocol: str) -> StateSequence:
        """Get the current sequence being built for a protocol."""
        protocol = protocol.lower()
        if protocol not in self._current_sequences:
            self._current_sequences[protocol] = StateSequence()
        return self._current_sequences[protocol]

    # -- State-aware seed selection (AFLNet) --------------------------------

    def select_target_state(self, protocol: str) -> StateID | None:
        """Select a target state for fuzzing using AFLNet weighted scoring.

        Computes scores for all known states of the given protocol, then
        performs weighted random selection. Returns None if no states known.
        """
        protocol = protocol.lower()
        candidates: list[StateInfo] = [
            info for info in self._state_info.values()
            if info.state_id.protocol == protocol
        ]
        if not candidates:
            return None

        # Recompute scores
        for info in candidates:
            info.compute_score()

        total = sum(info.score for info in candidates)
        if total <= 0:
            # All scores zero -- uniform random
            chosen = random.choice(candidates)
        else:
            # Weighted random selection
            r = random.uniform(0, total)
            cumulative = 0.0
            chosen = candidates[-1]  # fallback
            for info in candidates:
                cumulative += info.score
                if cumulative >= r:
                    chosen = info
                    break

        chosen.selected_times += 1
        return chosen.state_id

    def select_seed_for_state(self, state: StateID) -> bytes | None:
        """Select a seed that reaches the given state.

        Prefers seeds that have been fuzzed fewer times in this state context.
        Falls back to random choice from the seed pool.
        Returns None if no seeds are registered for the state.
        """
        info = self._state_info.get(state)
        if info is None or not info.seeds:
            return None

        # Simple strategy: random choice (can be refined with per-seed tracking)
        return random.choice(info.seeds)

    def register_seed_for_state(self, state: StateID, seed: bytes) -> None:
        """Register that a seed reaches the given state."""
        if state not in self._state_info:
            self._state_info[state] = StateInfo(state_id=state)
        info = self._state_info[state]
        # Avoid duplicates (idempotent)
        if seed not in info.seeds:
            info.seeds.append(seed)

    def increment_fuzz_count(self, state: StateID) -> None:
        """Increment the fuzz count for a state after generating an input."""
        info = self._state_info.get(state)
        if info is not None:
            info.fuzz_count += 1

    # -- Coverage reporting ------------------------------------------------

    def get_state_coverage(self, protocol: str | None = None) -> dict[str, Any]:
        """Get state coverage statistics.

        If protocol is given, return stats for that protocol only.
        Otherwise, return aggregate stats across all protocols.
        """
        if protocol is not None:
            protocol = protocol.lower()
            graph = self._graphs.get(protocol, StateGraph())
            states = [
                info for info in self._state_info.values()
                if info.state_id.protocol == protocol
            ]
            return {
                "protocol": protocol,
                "states_discovered": graph.node_count(),
                "transitions_discovered": graph.transition_count(),
                "coverage_score": graph.coverage_score(),
                "novel_sequences": len(self._seen_hashes),
                "state_details": {
                    str(info.state_id): {
                        "seeds": len(info.seeds),
                        "paths": info.paths,
                        "paths_discovered": info.paths_discovered,
                        "fuzz_count": info.fuzz_count,
                        "score": info.score,
                    }
                    for info in states
                },
            }

        # Aggregate across all protocols
        total_states = 0
        total_transitions = 0
        per_protocol: dict[str, Any] = {}
        for proto, graph in self._graphs.items():
            total_states += graph.node_count()
            total_transitions += graph.transition_count()
            per_protocol[proto] = {
                "states": graph.node_count(),
                "transitions": graph.transition_count(),
            }

        return {
            "total_states": total_states,
            "total_transitions": total_transitions,
            "novel_sequences": len(self._seen_hashes),
            "protocols": per_protocol,
        }

    # -- Persistence --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize full tracker state to JSON-compatible dict."""
        return {
            "graphs": {
                proto: graph.to_dict()
                for proto, graph in self._graphs.items()
            },
            "seen_hashes": sorted(self._seen_hashes),
            "hash_to_seed": {
                h: seed.hex() for h, seed in self._hash_to_seed.items()
            },
            "state_info": {
                str(state): info.to_dict()
                for state, info in self._state_info.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StateTracker:
        """Deserialize from JSON-compatible dict."""
        tracker = cls()

        # Restore graphs
        for proto, graph_data in data.get("graphs", {}).items():
            tracker._graphs[proto] = StateGraph.from_dict(graph_data)

        # Restore seen hashes
        tracker._seen_hashes = set(data.get("seen_hashes", []))

        # Restore hash-to-seed mapping
        tracker._hash_to_seed = {
            h: bytes.fromhex(seed_hex)
            for h, seed_hex in data.get("hash_to_seed", {}).items()
        }

        # Restore state info
        for _key, info_data in data.get("state_info", {}).items():
            info = StateInfo.from_dict(info_data)
            tracker._state_info[info.state_id] = info

        return tracker
