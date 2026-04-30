"""Mutation engine for protocol-aware Bluetooth fuzzing.

Provides multiple mutation strategies from raw byte-level (bitflip, insert,
delete) to structured protocol-aware mutations that understand field types
(integers, lengths, enums, flags).  Includes AFL-style havoc mode for
aggressive exploration.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from blue_tap.modules.fuzzing._random import random_bytes


# ---------------------------------------------------------------------------
# FieldMutator — raw byte-level mutations
# ---------------------------------------------------------------------------

class FieldMutator:
    """Static methods for raw byte-level mutations.

    Every method accepts ``bytes`` and returns ``bytes``.  All position /
    value parameters default to random choices when ``None``.
    """

    @staticmethod
    def bitflip(data: bytes, num_bits: int = 1) -> bytes:
        """Flip *num_bits* random bits in *data*.

        Returns the original data unchanged if *data* is empty.
        """
        if not data:
            return data
        arr = bytearray(data)
        for _ in range(num_bits):
            byte_idx = random.randint(0, len(arr) - 1)
            bit_idx = random.randint(0, 7)
            arr[byte_idx] ^= (1 << bit_idx)
        return bytes(arr)

    @staticmethod
    def byte_insert(data: bytes, pos: int | None = None, value: int | None = None) -> bytes:
        """Insert a single byte at *pos*.

        *pos* defaults to a random position (including after the last byte).
        *value* defaults to a random byte.
        """
        if pos is None:
            pos = random.randint(0, len(data))
        if value is None:
            value = random.randint(0, 255)
        return data[:pos] + bytes([value & 0xFF]) + data[pos:]

    @staticmethod
    def byte_delete(data: bytes, pos: int | None = None) -> bytes:
        """Delete one byte at *pos*.  Returns *data* unchanged if empty."""
        if not data:
            return data
        if pos is None:
            pos = random.randint(0, len(data) - 1)
        return data[:pos] + data[pos + 1:]

    @staticmethod
    def byte_replace(data: bytes, pos: int | None = None, value: int | None = None) -> bytes:
        """Replace one byte at *pos* with *value*.

        Returns *data* unchanged if empty.
        """
        if not data:
            return data
        if pos is None:
            pos = random.randint(0, len(data) - 1)
        if value is None:
            value = random.randint(0, 255)
        return data[:pos] + bytes([value & 0xFF]) + data[pos + 1:]

    @staticmethod
    def chunk_duplicate(data: bytes, start: int | None = None, length: int | None = None) -> bytes:
        """Duplicate a chunk of bytes in-place.

        Copies ``data[start:start+length]`` and inserts the copy right after
        the original chunk.  Returns *data* unchanged if empty.
        """
        if not data:
            return data
        if start is None:
            start = random.randint(0, max(0, len(data) - 1))
        remaining = len(data) - start
        if remaining <= 0:
            return data
        if length is None:
            length = random.randint(1, min(32, remaining))
        length = max(1, min(length, remaining))
        chunk = data[start:start + length]
        return data[:start + length] + chunk + data[start + length:]

    @staticmethod
    def chunk_shuffle(data: bytes, chunk_size: int = 4) -> bytes:
        """Split *data* into fixed-size chunks and shuffle them.

        The final chunk may be smaller than *chunk_size* and is included
        as-is.  Returns *data* unchanged if empty or shorter than two chunks.
        """
        if not data or chunk_size <= 0:
            return data
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        if len(chunks) < 2:
            return data
        random.shuffle(chunks)
        return b"".join(chunks)

    @staticmethod
    def truncate(data: bytes, new_len: int | None = None) -> bytes:
        """Truncate *data* to *new_len* bytes.

        *new_len* defaults to a random length between 0 and ``len(data)``.
        """
        if not data:
            return data
        if new_len is None:
            new_len = random.randint(0, len(data))
        return data[:max(0, new_len)]

    @staticmethod
    def extend(data: bytes, extra: int | None = None) -> bytes:
        """Append *extra* random bytes to *data*.

        *extra* defaults to a random count between 1 and 64.
        """
        if extra is None:
            extra = random.randint(1, 64)
        return data + random_bytes(max(0, extra))


# ---------------------------------------------------------------------------
# IntegerMutator — integer field mutations
# ---------------------------------------------------------------------------

class IntegerMutator:
    """Mutations targeted at integer protocol fields.

    Generates boundary values, interesting constants, and random
    perturbations that are known to trigger off-by-one errors, signedness
    bugs, and overflow conditions in Bluetooth stack implementations.
    """

    @staticmethod
    def boundary_values(bit_width: int) -> list[int]:
        """Return classic boundary/edge-case values for a *bit_width*-bit field.

        Includes 0, 1, max-1, max, max+1, half, half+1, and all-bits-set.
        """
        if bit_width <= 0:
            return [0]
        max_val = (1 << bit_width) - 1
        half = max_val // 2
        return [
            0,
            1,
            max_val - 1,
            max_val,
            max_val + 1,
            half,
            half + 1,
            max_val,  # all-bits-set (same as max for unsigned)
        ]

    @staticmethod
    def mutate(value: int, bit_width: int) -> int:
        """Mutate an integer value using a random strategy.

        Strategies: boundary, random, bitflip, increment, negate.
        The result is masked to *bit_width* bits.
        """
        if bit_width <= 0:
            return 0
        max_val = (1 << bit_width) - 1
        strategy = random.choice(["boundary", "random", "bitflip", "increment", "negate"])

        if strategy == "boundary":
            result = random.choice(IntegerMutator.boundary_values(bit_width))
        elif strategy == "random":
            result = random.randint(0, max_val)
        elif strategy == "bitflip":
            bit = random.randint(0, bit_width - 1)
            result = value ^ (1 << bit)
        elif strategy == "increment":
            delta = random.choice([-1, 1, -2, 2])
            result = value + delta
        elif strategy == "negate":
            # Two's complement negate, masked to bit_width
            result = (~value + 1)
        else:
            result = value

        return result & max_val

    @staticmethod
    def interesting_values_8() -> list[int]:
        """Classic 8-bit boundary/interesting values."""
        return [0, 1, 0x7F, 0x80, 0xFF]

    @staticmethod
    def interesting_values_16() -> list[int]:
        """Classic 16-bit boundary/interesting values."""
        return [0, 1, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]

    @staticmethod
    def interesting_values_32() -> list[int]:
        """Classic 32-bit boundary/interesting values."""
        return [0, 1, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


# ---------------------------------------------------------------------------
# LengthMutator — length field specific
# ---------------------------------------------------------------------------

class LengthMutator:
    """Mutations specifically targeting protocol length fields.

    Length fields are extremely high-value targets: off-by-one errors in
    length validation frequently lead to heap overflows, info leaks, and
    denial-of-service in Bluetooth stacks.
    """

    @staticmethod
    def mutate(actual_length: int, bit_width: int = 16) -> int:
        """Mutate a length field using a high-value strategy.

        Strategies: zero, minimal, off-by-one (both directions), double,
        maximum, random.
        """
        max_val = (1 << bit_width) - 1 if bit_width > 0 else 0
        strategies = [
            0,                                  # Zero length
            1,                                  # Minimal
            max(0, actual_length - 1),          # One short
            actual_length + 1,                  # One over
            actual_length * 2,                  # Double
            max_val,                            # Maximum
            random.randint(0, max_val),         # Random
        ]
        return random.choice(strategies) & max_val

    @staticmethod
    def strategies() -> list[str]:
        """List available length mutation strategies."""
        return [
            "zero",
            "minimal",
            "off_by_one_under",
            "off_by_one_over",
            "double",
            "maximum",
            "random",
        ]


# ---------------------------------------------------------------------------
# PacketField — structured field descriptor
# ---------------------------------------------------------------------------

@dataclass
class PacketField:
    """Describes a single field in a protocol packet.

    Attributes:
        name:       Human-readable field name (e.g. ``"pdu_id"``).
        value:      Current value — ``int`` for numeric fields, ``bytes``
                    for raw payloads.
        bit_width:  Width in bits for integer/length/enum/flags fields.
                    Ignored when *field_type* is ``"raw"``.
        field_type: One of ``"uint"``, ``"length"``, ``"raw"``,
                    ``"enum"``, ``"flags"``.
    """

    name: str
    value: int | bytes
    bit_width: int = 0
    field_type: str = "raw"  # "uint" | "length" | "raw" | "enum" | "flags"


# ---------------------------------------------------------------------------
# MutationLog — records mutations for crash reproduction
# ---------------------------------------------------------------------------

@dataclass
class MutationLog:
    """Records every mutation applied to a packet so crashes can be
    reproduced deterministically.

    Each entry is a tuple of ``(field_name, original_value, mutated_value,
    strategy)``.
    """

    entries: list[tuple[str, Any, Any, str]] = field(default_factory=list)

    def add(self, field_name: str, original: Any, mutated: Any, strategy: str) -> None:
        """Record a single mutation."""
        self.entries.append((field_name, original, mutated, strategy))

    def to_string(self) -> str:
        """Return a human-readable multi-line log."""
        if not self.entries:
            return "(no mutations)"
        lines: list[str] = []
        for i, (fname, orig, mut, strat) in enumerate(self.entries, 1):
            lines.append(f"  [{i}] {fname}: {orig!r} -> {mut!r} ({strat})")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        return {
            "mutation_count": len(self.entries),
            "mutations": [
                {
                    "field": fname,
                    "original": _serialise_value(orig),
                    "mutated": _serialise_value(mut),
                    "strategy": strat,
                }
                for fname, orig, mut, strat in self.entries
            ],
        }


def _serialise_value(val: Any) -> str | int:
    """Convert a field value to a JSON-safe representation."""
    if isinstance(val, bytes):
        return val.hex()
    if isinstance(val, int):
        return val
    return repr(val)


# ---------------------------------------------------------------------------
# ProtocolMutator — structured packet mutation
# ---------------------------------------------------------------------------

class ProtocolMutator:
    """Mutate structured protocol packets by field type.

    Uses the appropriate mutator class for each field type:

    * ``"uint"`` / ``"enum"`` / ``"flags"`` -> :class:`IntegerMutator`
    * ``"length"`` -> :class:`LengthMutator`
    * ``"raw"`` -> :class:`FieldMutator`
    """

    def mutate_packet(
        self,
        fields: list[PacketField],
        num_mutations: int = 1,
    ) -> tuple[list[PacketField], list[str]]:
        """Mutate *num_mutations* random fields in a packet.

        Returns ``(mutated_fields, mutation_log_strings)`` where
        *mutated_fields* is a deep copy with mutations applied, and
        *mutation_log_strings* is a human-readable list.
        """
        if not fields:
            return [], []

        # Deep copy fields so the originals are untouched
        mutated = [
            PacketField(f.name, f.value, f.bit_width, f.field_type)
            for f in fields
        ]
        log_strings: list[str] = []

        for _ in range(min(num_mutations, len(mutated))):
            idx = random.randint(0, len(mutated) - 1)
            f = mutated[idx]
            original = f.value

            if f.field_type in ("uint", "enum", "flags"):
                bw = f.bit_width if f.bit_width > 0 else 8
                if isinstance(f.value, int):
                    f.value = IntegerMutator.mutate(f.value, bw)
                strategy = "IntegerMutator"
            elif f.field_type == "length":
                bw = f.bit_width if f.bit_width > 0 else 16
                if isinstance(f.value, int):
                    f.value = LengthMutator.mutate(f.value, bw)
                strategy = "LengthMutator"
            elif f.field_type == "raw":
                if isinstance(f.value, bytes) and f.value:
                    op = random.choice([
                        FieldMutator.bitflip,
                        FieldMutator.byte_insert,
                        FieldMutator.byte_delete,
                        FieldMutator.byte_replace,
                    ])
                    f.value = op(f.value)
                    strategy = f"FieldMutator.{op.__name__}"
                else:
                    strategy = "noop(empty_raw)"
            else:
                strategy = "unknown_field_type"

            log_strings.append(f"{f.name}: {original!r} -> {f.value!r} ({strategy})")

        return mutated, log_strings

    @staticmethod
    def serialize_fields(fields: list[PacketField], endian: str = "big") -> bytes:
        """Serialise a list of :class:`PacketField` back to wire bytes.

        Integer fields are serialised to ``ceil(bit_width / 8)`` bytes in
        the specified *endian* order.  Raw fields are emitted as-is.
        """
        parts: list[bytes] = []
        byteorder = "big" if endian == "big" else "little"

        for f in fields:
            if isinstance(f.value, bytes):
                parts.append(f.value)
            elif isinstance(f.value, int):
                byte_len = max(1, (f.bit_width + 7) // 8) if f.bit_width > 0 else 1
                # Mask to the actual bit width to avoid overflow
                mask = (1 << (byte_len * 8)) - 1
                parts.append((f.value & mask).to_bytes(byte_len, byteorder=byteorder))
            else:
                # Fallback: treat as raw bytes
                parts.append(bytes(f.value) if f.value else b"")

        return b"".join(parts)


# ---------------------------------------------------------------------------
# CorpusMutator — traditional byte-level (AFL-style)
# ---------------------------------------------------------------------------

class CorpusMutator:
    """Traditional byte-level mutator for raw seed data.

    Applies random combinations of :class:`FieldMutator` operations,
    including an AFL-style havoc mode for aggressive exploration.
    """

    # Mutation operations available for random selection
    _OPS = [
        FieldMutator.bitflip,
        FieldMutator.byte_insert,
        FieldMutator.byte_delete,
        FieldMutator.byte_replace,
        FieldMutator.chunk_duplicate,
        FieldMutator.chunk_shuffle,
        FieldMutator.truncate,
        FieldMutator.extend,
    ]

    @staticmethod
    def mutate(data: bytes, num_mutations: int = 1) -> bytes:
        """Apply *num_mutations* random mutations to *data*."""
        result = data
        for _ in range(num_mutations):
            op = random.choice(CorpusMutator._OPS)
            result = op(result)
        return result

    @staticmethod
    def mutate_batch(data: bytes, count: int = 10) -> list[bytes]:
        """Generate *count* mutated variants of *data*.

        Each variant receives between 1 and 3 random mutations.
        """
        variants: list[bytes] = []
        for _ in range(count):
            n = random.randint(1, 3)
            variants.append(CorpusMutator.mutate(data, num_mutations=n))
        return variants

    @staticmethod
    def havoc(data: bytes) -> bytes:
        """AFL-style havoc: apply 5-20 random operations aggressively.

        This mode is designed for maximum exploration — it stacks many
        mutations on a single input to produce highly divergent outputs.
        """
        result = data if data else random_bytes(random.randint(1, 32))
        num_ops = random.randint(5, 20)
        for _ in range(num_ops):
            op = random.choice(CorpusMutator._OPS)
            result = op(result)
            # Re-seed if we accidentally truncated to nothing
            if not result:
                result = random_bytes(random.randint(1, 16))
        return result
