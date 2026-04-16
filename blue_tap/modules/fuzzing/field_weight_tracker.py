"""Anomaly-guided mutation weight tracking for protocol-aware fuzzing.

Implements Phase 2 of the advanced fuzzing engine: track which protocol
fields produce anomalies when mutated, increase mutation probability for
productive fields.  Based on BrakTooth (USENIX Sec 2022) PSO-guided
mutation probabilities and L2Fuzz (DSN 2022) core field mutation.

Key components:
- ProtocolFieldMap: static field layout definitions per protocol
- identify_fields(): parse raw packets into PacketField objects
- FieldWeightTracker: per-protocol, per-field mutation weight tracking
- FieldAwareMutator: weighted field selection + typed mutation
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from blue_tap.modules.fuzzing.mutators import (
    FieldMutator,
    IntegerMutator,
    LengthMutator,
    PacketField,
    ProtocolMutator,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANOMALY_BOOST: float = 5.0
CRASH_BOOST: float = 20.0
DEFAULT_UPDATE_INTERVAL: int = 100  # recalculate weights every N mutations

# ---------------------------------------------------------------------------
# Field descriptor type alias
# ---------------------------------------------------------------------------

# (field_name, byte_offset, byte_length, field_type)
#   byte_offset: 0-based start position; -1 means relative to end
#   byte_length: number of bytes; -1 means "rest of packet"
#   field_type: "uint" | "length" | "raw" | "flags" | "enum"
FieldDescriptor = tuple[str, int, int, str]

# ---------------------------------------------------------------------------
# ProtocolFieldMap — static field layouts per protocol
# ---------------------------------------------------------------------------

# Generic (default) field maps keyed by protocol name.
# Opcode-specific maps are stored separately.

PROTOCOL_FIELD_MAP: dict[str, list[FieldDescriptor]] = {
    # SDP (Service Discovery Protocol)
    "sdp": [
        ("pdu_id", 0, 1, "uint"),
        ("transaction_id", 1, 2, "uint"),
        ("param_length", 3, 2, "length"),
        ("payload", 5, -1, "raw"),
    ],
    # BLE ATT (Attribute Protocol) — generic layout
    "ble-att": [
        ("opcode", 0, 1, "uint"),
        ("handle", 1, 2, "uint"),
        ("value", 3, -1, "raw"),
    ],
    # L2CAP Signaling
    "l2cap": [
        ("code", 0, 1, "uint"),
        ("identifier", 1, 1, "uint"),
        ("length", 2, 2, "length"),
        ("data", 4, -1, "raw"),
    ],
    # RFCOMM
    "rfcomm": [
        ("address", 0, 1, "flags"),
        ("control", 1, 1, "uint"),
        ("length", 2, 1, "length"),
        ("info", 3, -1, "raw"),
        # FCS is the last byte; handled specially in identify_fields
    ],
    # BLE SMP (Security Manager Protocol)
    "ble-smp": [
        ("code", 0, 1, "uint"),
        ("data", 1, -1, "raw"),
    ],
    "l2cap-sig": [
        ("length", 0, 2, "length"),
        ("cid", 2, 2, "uint"),
        ("code", 4, 1, "uint"),
        ("identifier", 5, 1, "uint"),
        ("sig_length", 6, 2, "length"),
        ("payload", 8, -1, "raw"),
    ],
    # OBEX (generic — covers PBAP, MAP, OPP)
    "obex-pbap": [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    "obex-map": [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    "obex-opp": [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # BNEP (Bluetooth Network Encapsulation Protocol)
    "bnep": [
        ("type", 0, 1, "uint"),
        ("data", 1, -1, "raw"),
    ],
    # AT commands (HFP)
    "at-hfp": [
        ("command", 0, -1, "raw"),
    ],
    # AT commands (Phonebook)
    "at-phonebook": [
        ("command", 0, -1, "raw"),
    ],
    # AT commands (SMS)
    "at-sms": [
        ("command", 0, -1, "raw"),
    ],
    # AT commands (Injection)
    "at-injection": [
        ("command", 0, -1, "raw"),
    ],
    # LMP (Link Manager Protocol) — below-HCI fuzzing via DarkFirmware on UB500
    #
    # PDU structure: byte 0 = [TID:3bits | opcode:5bits], bytes 1+ = params.
    # Many fields overlap intentionally — the tracker selects probabilistically,
    # so overlapping fields let the same bytes be targeted by different mutation
    # types (e.g. "key_size" as uint vs "payload_raw" as raw blob).
    "lmp": [
        ("tid_opcode",    0,  1, "uint"),  # byte 0: [TID:3 | opcode:5]
        ("param_byte_0",  1,  1, "uint"),  # first param: key_size, enc_mode, features[0]
        ("param_byte_1",  2,  1, "uint"),  # second param
        ("param_byte_2",  3,  1, "uint"),  # third param
        ("rand_field",    1,  8, "raw"),   # AU_RAND / IN_RAND / TEMP_RAND (8 bytes)
        ("sres_field",    1,  4, "raw"),   # SRES response (4 bytes)
        ("key_size",      1,  1, "uint"),  # LMP_encryption_key_size_req param (KNOB target)
        ("features_mask", 1,  8, "raw"),   # LMP_features_res bitmask (8 bytes)
        ("payload_raw",   1, -1, "raw"),   # full payload — generic mutation fallback
    ],
}

# Opcode-specific field maps: protocol -> opcode -> field list
OPCODE_FIELD_MAP: dict[str, dict[int, list[FieldDescriptor]]] = {
    "sdp": {
        # ServiceSearchRequest
        0x02: [
            ("pdu_id", 0, 1, "uint"),
            ("transaction_id", 1, 2, "uint"),
            ("param_length", 3, 2, "length"),
            ("service_search_pattern", 5, -1, "raw"),
            # max_count and continuation are inside the variable payload
        ],
        # ServiceSearchResponse
        0x03: [
            ("pdu_id", 0, 1, "uint"),
            ("transaction_id", 1, 2, "uint"),
            ("param_length", 3, 2, "length"),
            ("total_count", 5, 2, "uint"),
            ("current_count", 7, 2, "uint"),
            ("record_handles", 9, -1, "raw"),
        ],
        # ServiceAttributeRequest
        0x04: [
            ("pdu_id", 0, 1, "uint"),
            ("transaction_id", 1, 2, "uint"),
            ("param_length", 3, 2, "length"),
            ("service_record_handle", 5, 4, "uint"),
            ("max_byte_count", 9, 2, "uint"),
            ("attribute_id_list", 11, -1, "raw"),
        ],
        # ServiceAttributeResponse
        0x05: [
            ("pdu_id", 0, 1, "uint"),
            ("transaction_id", 1, 2, "uint"),
            ("param_length", 3, 2, "length"),
            ("attribute_list_byte_count", 5, 2, "length"),
            ("attribute_list", 7, -1, "raw"),
        ],
        # ServiceSearchAttributeRequest
        0x06: [
            ("pdu_id", 0, 1, "uint"),
            ("transaction_id", 1, 2, "uint"),
            ("param_length", 3, 2, "length"),
            ("service_search_pattern", 5, -1, "raw"),
        ],
    },
    "ble-att": {
        # Read By Type Request
        0x08: [
            ("opcode", 0, 1, "uint"),
            ("start_handle", 1, 2, "uint"),
            ("end_handle", 3, 2, "uint"),
            ("uuid", 5, -1, "raw"),  # 2 or 16 bytes
        ],
        # Read By Type Response
        0x09: [
            ("opcode", 0, 1, "uint"),
            ("length", 1, 1, "length"),
            ("attribute_data", 2, -1, "raw"),
        ],
        # Read Request
        0x0A: [
            ("opcode", 0, 1, "uint"),
            ("handle", 1, 2, "uint"),
        ],
        # Read Response
        0x0B: [
            ("opcode", 0, 1, "uint"),
            ("value", 1, -1, "raw"),
        ],
        # Write Request
        0x12: [
            ("opcode", 0, 1, "uint"),
            ("handle", 1, 2, "uint"),
            ("value", 3, -1, "raw"),
        ],
        # Write Response
        0x13: [
            ("opcode", 0, 1, "uint"),
        ],
        # Error Response
        0x01: [
            ("opcode", 0, 1, "uint"),
            ("request_opcode", 1, 1, "uint"),
            ("handle", 2, 2, "uint"),
            ("error_code", 4, 1, "enum"),
        ],
        # Find Information Request
        0x04: [
            ("opcode", 0, 1, "uint"),
            ("start_handle", 1, 2, "uint"),
            ("end_handle", 3, 2, "uint"),
        ],
        # Find Information Response
        0x05: [
            ("opcode", 0, 1, "uint"),
            ("format", 1, 1, "enum"),
            ("information_data", 2, -1, "raw"),
        ],
        # Exchange MTU Request
        0x02: [
            ("opcode", 0, 1, "uint"),
            ("client_mtu", 1, 2, "uint"),
        ],
        # Exchange MTU Response
        0x03: [
            ("opcode", 0, 1, "uint"),
            ("server_mtu", 1, 2, "uint"),
        ],
        # Write Command (no response)
        0x52: [
            ("opcode", 0, 1, "uint"),
            ("handle", 1, 2, "uint"),
            ("value", 3, -1, "raw"),
        ],
    },
    "l2cap": {
        # Connection Request
        0x02: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("psm", 4, 2, "uint"),
            ("scid", 6, 2, "uint"),
        ],
        # Connection Response
        0x03: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("dcid", 4, 2, "uint"),
            ("scid", 6, 2, "uint"),
            ("result", 8, 2, "enum"),
            ("status", 10, 2, "enum"),
        ],
        # Configuration Request
        0x04: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("dcid", 4, 2, "uint"),
            ("flags", 6, 2, "flags"),
            ("options", 8, -1, "raw"),
        ],
        # Configuration Response
        0x05: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("scid", 4, 2, "uint"),
            ("flags", 6, 2, "flags"),
            ("result", 8, 2, "enum"),
            ("options", 10, -1, "raw"),
        ],
        # Disconnection Request
        0x06: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("dcid", 4, 2, "uint"),
            ("scid", 6, 2, "uint"),
        ],
        # Information Request
        0x0A: [
            ("code", 0, 1, "uint"),
            ("identifier", 1, 1, "uint"),
            ("length", 2, 2, "length"),
            ("info_type", 4, 2, "enum"),
        ],
    },
    "rfcomm": {
        # SABM (Set Asynchronous Balanced Mode)
        0x2F: [
            ("address", 0, 1, "flags"),
            ("control", 1, 1, "uint"),
            ("length", 2, 1, "length"),
            ("fcs", -1, 1, "uint"),
        ],
        # UA (Unnumbered Acknowledgement)
        0x63: [
            ("address", 0, 1, "flags"),
            ("control", 1, 1, "uint"),
            ("length", 2, 1, "length"),
            ("fcs", -1, 1, "uint"),
        ],
        # DM (Disconnected Mode)
        0x0F: [
            ("address", 0, 1, "flags"),
            ("control", 1, 1, "uint"),
            ("length", 2, 1, "length"),
            ("fcs", -1, 1, "uint"),
        ],
        # UIH (Unnumbered Information with Header check)
        0xEF: [
            ("address", 0, 1, "flags"),
            ("control", 1, 1, "uint"),
            ("length", 2, 1, "length"),
            ("info", 3, -1, "raw"),
            # FCS handled specially
        ],
    },
    "ble-smp": {
        # Pairing Request
        0x01: [
            ("code", 0, 1, "uint"),
            ("io_capability", 1, 1, "enum"),
            ("oob_flag", 2, 1, "uint"),
            ("auth_req", 3, 1, "flags"),
            ("max_key_size", 4, 1, "uint"),
            ("initiator_key_dist", 5, 1, "flags"),
            ("responder_key_dist", 6, 1, "flags"),
        ],
        # Pairing Response
        0x02: [
            ("code", 0, 1, "uint"),
            ("io_capability", 1, 1, "enum"),
            ("oob_flag", 2, 1, "uint"),
            ("auth_req", 3, 1, "flags"),
            ("max_key_size", 4, 1, "uint"),
            ("initiator_key_dist", 5, 1, "flags"),
            ("responder_key_dist", 6, 1, "flags"),
        ],
        # Pairing Confirm
        0x03: [
            ("code", 0, 1, "uint"),
            ("confirm_value", 1, 16, "raw"),
        ],
        # Pairing Random
        0x04: [
            ("code", 0, 1, "uint"),
            ("random_value", 1, 16, "raw"),
        ],
        # Pairing Failed
        0x05: [
            ("code", 0, 1, "uint"),
            ("reason", 1, 1, "enum"),
        ],
        # Security Request
        0x0B: [
            ("code", 0, 1, "uint"),
            ("auth_req", 1, 1, "flags"),
        ],
        # Pairing Public Key
        0x0C: [
            ("code", 0, 1, "uint"),
            ("public_key_x", 1, 32, "raw"),
            ("public_key_y", 33, 32, "raw"),
        ],
    },
    "bnep": {
        # General Ethernet
        0x00: [
            ("type", 0, 1, "uint"),
            ("dest_addr", 1, 6, "raw"),
            ("src_addr", 7, 6, "raw"),
            ("network_type", 13, 2, "uint"),
            ("payload", 15, -1, "raw"),
        ],
        # Control
        0x01: [
            ("type", 0, 1, "uint"),
            ("control_type", 1, 1, "enum"),
            ("control_data", 2, -1, "raw"),
        ],
        # Compressed Ethernet
        0x02: [
            ("type", 0, 1, "uint"),
            ("network_type", 1, 2, "uint"),
            ("payload", 3, -1, "raw"),
        ],
    },
}

# Alias OBEX protocols to share the same opcode map
_OBEX_OPCODE_MAP: dict[int, list[FieldDescriptor]] = {
    # Connect
    0x80: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("version", 3, 1, "uint"),
        ("flags", 4, 1, "flags"),
        ("max_packet_length", 5, 2, "uint"),
        ("headers", 7, -1, "raw"),
    ],
    # Disconnect
    0x81: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # Put
    0x02: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # Put Final
    0x82: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # Get
    0x03: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # Get Final
    0x83: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
    # SetPath
    0x85: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("flags", 3, 1, "flags"),
        ("constants", 4, 1, "uint"),
        ("headers", 5, -1, "raw"),
    ],
    # Abort
    0xFF: [
        ("opcode", 0, 1, "uint"),
        ("length", 1, 2, "length"),
        ("headers", 3, -1, "raw"),
    ],
}

for _obex_proto in ("obex-pbap", "obex-map", "obex-opp"):
    OPCODE_FIELD_MAP[_obex_proto] = _OBEX_OPCODE_MAP


# ---------------------------------------------------------------------------
# identify_fields — parse raw packet into PacketField objects
# ---------------------------------------------------------------------------

def _resolve_protocol(protocol: str) -> str:
    """Normalize protocol name to a key in PROTOCOL_FIELD_MAP."""
    p = protocol.lower().strip()
    # Direct match
    if p in PROTOCOL_FIELD_MAP:
        return p
    # Common aliases
    aliases: dict[str, str] = {
        "att": "ble-att",
        "ble_att": "ble-att",
        "smp": "ble-smp",
        "ble_smp": "ble-smp",
        "obex": "obex-pbap",
        "pbap": "obex-pbap",
        "map": "obex-map",
        "opp": "obex-opp",
        "hfp": "at-hfp",
        "at": "at-hfp",
        "phonebook": "at-phonebook",
        "sms": "at-sms",
        "injection": "at-injection",
    }
    return aliases.get(p, p)


def _extract_opcode(protocol: str, packet: bytes) -> int | None:
    """Extract the opcode byte from a packet for opcode-specific field maps."""
    if not packet:
        return None
    if protocol in ("rfcomm",):
        # RFCOMM control byte is at offset 1
        if len(packet) >= 2:
            return packet[1]
        return None
    # Most protocols: opcode/code/type is the first byte
    return packet[0]


def _apply_field_map(
    descriptors: list[FieldDescriptor],
    packet: bytes,
    protocol: str,
) -> list[PacketField]:
    """Parse a packet according to a list of field descriptors."""
    fields: list[PacketField] = []
    pkt_len = len(packet)

    for name, offset, length, ftype in descriptors:
        # Handle negative offset (relative to end)
        if offset < 0:
            actual_offset = pkt_len + offset
        else:
            actual_offset = offset

        if actual_offset < 0 or actual_offset >= pkt_len:
            # Field beyond packet boundary — skip gracefully
            continue

        # Determine actual byte length
        if length == -1:
            # "rest of packet" — but check if there's a trailing FCS for RFCOMM
            if protocol == "rfcomm" and name != "fcs":
                # Reserve last byte for FCS
                actual_length = max(0, pkt_len - actual_offset - 1)
            else:
                actual_length = pkt_len - actual_offset
        else:
            actual_length = min(length, pkt_len - actual_offset)

        if actual_length <= 0 and ftype != "raw":
            continue

        raw_bytes = packet[actual_offset : actual_offset + actual_length]

        if ftype in ("uint", "enum", "flags", "length"):
            bit_width = actual_length * 8
            value = int.from_bytes(raw_bytes, byteorder="big") if raw_bytes else 0
            fields.append(PacketField(
                name=name,
                value=value,
                bit_width=bit_width,
                field_type=ftype,
            ))
        else:
            # raw
            fields.append(PacketField(
                name=name,
                value=raw_bytes,
                bit_width=actual_length * 8,
                field_type="raw",
            ))

    return fields


def _generic_chunked_fields(packet: bytes) -> list[PacketField]:
    """Fall back to 4-byte aligned chunking for unknown opcodes."""
    fields: list[PacketField] = []
    chunk_size = 4
    for i in range(0, len(packet), chunk_size):
        chunk = packet[i : i + chunk_size]
        fields.append(PacketField(
            name=f"chunk_{i}",
            value=chunk,
            bit_width=len(chunk) * 8,
            field_type="raw",
        ))
    return fields


def identify_fields(protocol: str, packet: bytes) -> list[PacketField]:
    """Parse a raw packet into PacketField objects using protocol field maps.

    Uses opcode-specific maps when available, falls back to the generic
    protocol map, and ultimately to 4-byte aligned chunking for completely
    unknown protocols or opcodes.

    Parameters
    ----------
    protocol:
        Protocol name (e.g. ``"sdp"``, ``"ble-att"``, ``"l2cap"``).
    packet:
        Raw packet bytes.

    Returns
    -------
    list[PacketField]
        Parsed fields with names, values, and type annotations.
    """
    if not packet:
        return []

    resolved = _resolve_protocol(protocol)

    # Try opcode-specific map first
    opcode_maps = OPCODE_FIELD_MAP.get(resolved)
    if opcode_maps:
        opcode = _extract_opcode(resolved, packet)
        if opcode is not None and opcode in opcode_maps:
            return _apply_field_map(opcode_maps[opcode], packet, resolved)

    # Fall back to generic protocol map
    generic_map = PROTOCOL_FIELD_MAP.get(resolved)
    if generic_map:
        return _apply_field_map(generic_map, packet, resolved)

    # Completely unknown protocol — chunked fallback
    return _generic_chunked_fields(packet)


# ---------------------------------------------------------------------------
# FieldStats — per-field mutation statistics
# ---------------------------------------------------------------------------

@dataclass
class FieldStats:
    """Tracks mutation outcomes for a single protocol field."""

    mutations: int = 0
    anomalies: int = 0
    crashes: int = 0
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mutations": self.mutations,
            "anomalies": self.anomalies,
            "crashes": self.crashes,
            "weight": self.weight,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FieldStats:
        return cls(
            mutations=d.get("mutations", 0),
            anomalies=d.get("anomalies", 0),
            crashes=d.get("crashes", 0),
            weight=d.get("weight", 1.0),
        )


# ---------------------------------------------------------------------------
# FieldWeightTracker — anomaly-guided mutation weight tracking
# ---------------------------------------------------------------------------

class FieldWeightTracker:
    """Track which protocol fields produce anomalies and adjust mutation
    weights accordingly.

    Maintains per-protocol, per-field statistics and recalculates weights
    periodically so the fuzzer converges on productive fields.

    Parameters
    ----------
    update_interval:
        Recalculate weights every *update_interval* total mutations.
    """

    def __init__(self, update_interval: int = DEFAULT_UPDATE_INTERVAL) -> None:
        # protocol -> field_name -> FieldStats
        self._stats: dict[str, dict[str, FieldStats]] = {}
        self._update_interval = update_interval
        self._mutation_count_since_update = 0

    def _ensure_field(self, protocol: str, field_name: str) -> FieldStats:
        """Get or create FieldStats for a protocol/field pair."""
        proto_stats = self._stats.setdefault(protocol, {})
        if field_name not in proto_stats:
            proto_stats[field_name] = FieldStats()
        return proto_stats[field_name]

    def record_mutation(self, protocol: str, field_name: str) -> None:
        """Record that a field was mutated."""
        stats = self._ensure_field(protocol, field_name)
        stats.mutations += 1
        self._mutation_count_since_update += 1
        if self._mutation_count_since_update >= self._update_interval:
            self.update_weights()
            self._mutation_count_since_update = 0

    def record_anomaly(self, protocol: str, field_name: str) -> None:
        """Record that mutating a field produced an anomalous response."""
        stats = self._ensure_field(protocol, field_name)
        stats.anomalies += 1

    def record_crash(self, protocol: str, field_name: str) -> None:
        """Record that mutating a field produced a crash."""
        stats = self._ensure_field(protocol, field_name)
        stats.crashes += 1

    def update_weights(self) -> None:
        """Recalculate weights for all protocols.

        Formula per field::

            weight = 1.0 + (anomaly_ratio * ANOMALY_BOOST) + (crash_ratio * CRASH_BOOST)

        Weights are then normalized to sum to 1.0 within each protocol.
        """
        for proto_stats in self._stats.values():
            if not proto_stats:
                continue

            # Calculate raw weights
            for stats in proto_stats.values():
                mutations = max(stats.mutations, 1)
                anomaly_ratio = stats.anomalies / mutations
                crash_ratio = stats.crashes / mutations
                stats.weight = (
                    1.0
                    + (anomaly_ratio * ANOMALY_BOOST)
                    + (crash_ratio * CRASH_BOOST)
                )

            # Normalize to sum=1.0
            total = sum(s.weight for s in proto_stats.values())
            if total > 0:
                for stats in proto_stats.values():
                    stats.weight /= total

    def select_field(self, protocol: str) -> str:
        """Select a field to mutate using weighted random selection.

        If no stats exist for the protocol, initializes uniform weights
        from the protocol's field map and returns a random field.

        Returns
        -------
        str
            The name of the selected field.
        """
        resolved = _resolve_protocol(protocol)
        proto_stats = self._stats.get(resolved)

        if not proto_stats:
            # Bootstrap from the generic field map
            generic_map = PROTOCOL_FIELD_MAP.get(resolved)
            if generic_map:
                field_names = [desc[0] for desc in generic_map]
            else:
                # Unknown protocol — return a placeholder
                return "chunk_0"
            # Initialize uniform stats
            for name in field_names:
                self._ensure_field(resolved, name)
            proto_stats = self._stats[resolved]
            # Set uniform weights
            n = len(proto_stats)
            for stats in proto_stats.values():
                stats.weight = 1.0 / n

        names = list(proto_stats.keys())
        weights = [proto_stats[n].weight for n in names]
        chosen = random.choices(names, weights=weights, k=1)[0]
        return chosen

    def get_weights(self, protocol: str) -> dict[str, float]:
        """Return current weights for a protocol, for reporting.

        Returns
        -------
        dict[str, float]
            Mapping of field name to weight. Empty dict if no data.
        """
        resolved = _resolve_protocol(protocol)
        proto_stats = self._stats.get(resolved, {})
        return {name: s.weight for name, s in proto_stats.items()}

    def to_dict(self) -> dict[str, Any]:
        """Serialize tracker state for campaign persistence."""
        return {
            protocol: {
                field_name: stats.to_dict()
                for field_name, stats in fields.items()
            }
            for protocol, fields in self._stats.items()
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        update_interval: int = DEFAULT_UPDATE_INTERVAL,
    ) -> FieldWeightTracker:
        """Restore tracker state from a serialized dict."""
        tracker = cls(update_interval=update_interval)
        for protocol, fields in data.items():
            tracker._stats[protocol] = {
                field_name: FieldStats.from_dict(stats_dict)
                for field_name, stats_dict in fields.items()
            }
        return tracker


# ---------------------------------------------------------------------------
# FieldAwareMutator — weighted field selection + typed mutation
# ---------------------------------------------------------------------------

class FieldAwareMutator:
    """Mutate packets using anomaly-guided field weights.

    Combines :func:`identify_fields` for parsing, :class:`FieldWeightTracker`
    for weighted field selection, and the appropriate typed mutator
    (:class:`IntegerMutator`, :class:`LengthMutator`, :class:`FieldMutator`)
    for applying mutations.
    """

    def __init__(self) -> None:
        self._protocol_mutator = ProtocolMutator()

    def mutate(
        self,
        protocol: str,
        packet: bytes,
        tracker: FieldWeightTracker,
    ) -> tuple[bytes, list[str]]:
        """Mutate a packet with anomaly-guided field selection.

        Parameters
        ----------
        protocol:
            Protocol name (e.g. ``"sdp"``, ``"ble-att"``).
        packet:
            Raw packet bytes to mutate.
        tracker:
            The field weight tracker that guides field selection.

        Returns
        -------
        tuple[bytes, list[str]]
            ``(mutated_bytes, mutation_log_entries)``
        """
        if not packet:
            return packet, []

        # Step 1: Parse packet into fields
        fields = identify_fields(protocol, packet)
        if not fields:
            return packet, []

        # Step 2: Select field to mutate via tracker
        target_field_name = tracker.select_field(protocol)

        # Find the target field in parsed fields
        target_idx: int | None = None
        for i, f in enumerate(fields):
            if f.name == target_field_name:
                target_idx = i
                break

        # If selected field not in this packet, pick a random one
        if target_idx is None:
            target_idx = random.randint(0, len(fields) - 1)
            target_field_name = fields[target_idx].name

        target = fields[target_idx]
        original_value = target.value
        log_entries: list[str] = []

        # Step 3: Apply typed mutation
        if target.field_type in ("uint", "enum", "flags"):
            bw = target.bit_width if target.bit_width > 0 else 8
            if isinstance(target.value, int):
                target.value = IntegerMutator.mutate(target.value, bw)
            strategy = "IntegerMutator"
        elif target.field_type == "length":
            bw = target.bit_width if target.bit_width > 0 else 16
            if isinstance(target.value, int):
                target.value = LengthMutator.mutate(target.value, bw)
            strategy = "LengthMutator"
        elif target.field_type == "raw":
            if isinstance(target.value, bytes) and target.value:
                op = random.choice([
                    FieldMutator.bitflip,
                    FieldMutator.byte_insert,
                    FieldMutator.byte_delete,
                    FieldMutator.byte_replace,
                ])
                target.value = op(target.value)
                strategy = f"FieldMutator.{op.__name__}"
            else:
                strategy = "noop(empty_raw)"
        else:
            strategy = "unknown_field_type"

        fields[target_idx] = target
        log_entries.append(
            f"{target_field_name}: {original_value!r} -> {target.value!r} ({strategy})"
        )

        # Record mutation in tracker
        resolved = _resolve_protocol(protocol)
        tracker.record_mutation(resolved, target_field_name)

        # Step 4: Serialize fields back to bytes
        # BLE protocols (ATT, SMP) and L2CAP use little-endian per BT Core Spec.
        # BR/EDR protocols (SDP, RFCOMM, OBEX, BNEP) use big-endian.
        _LE_PROTOCOLS = {"l2cap", "ble-att", "ble-smp"}
        endian = "little" if resolved in _LE_PROTOCOLS else "big"
        mutated_bytes = ProtocolMutator.serialize_fields(fields, endian=endian)

        return mutated_bytes, log_entries
