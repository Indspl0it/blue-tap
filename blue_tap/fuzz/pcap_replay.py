"""pcap/btsnoop capture replay for Bluetooth protocol fuzzing.

Parses btsnoop v1 capture files (as produced by ``btmon -w``), extracts
L2CAP frames from HCI ACL data packets, classifies protocols, and supports
selective replay against live targets.  Captured payloads can also be
imported into the fuzzer corpus as seeds.

All parsing is done with the stdlib ``struct`` module -- no external
dependencies required.
"""

from __future__ import annotations

import hashlib
import logging
import struct
import time
from dataclasses import dataclass
from typing import Callable

from blue_tap.fuzz.corpus import Corpus
from blue_tap.fuzz.mutators import FieldMutator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# btsnoop epoch offset: microseconds between 0000-01-01 and 1970-01-01
# ---------------------------------------------------------------------------
_BTSNOOP_EPOCH_OFFSET = 0x00DCDDB30F2F8000


# ---------------------------------------------------------------------------
# BtsnoopRecord — a single record from a btsnoop capture
# ---------------------------------------------------------------------------

@dataclass
class BtsnoopRecord:
    """A single record from a btsnoop capture file."""

    original_length: int
    included_length: int
    flags: int
    drops: int
    timestamp: int  # Microseconds since btsnoop epoch (0000-01-01)
    data: bytes

    @property
    def is_sent(self) -> bool:
        """True if this packet was sent FROM the host (to controller)."""
        return (self.flags & 0x01) == 0

    @property
    def is_received(self) -> bool:
        """True if this packet was received BY the host (from controller)."""
        return (self.flags & 0x01) == 1

    @property
    def is_data(self) -> bool:
        """True if this is an ACL data packet (not HCI command/event)."""
        return (self.flags & 0x02) == 0

    @property
    def timestamp_seconds(self) -> float:
        """Timestamp as Unix epoch seconds."""
        return (self.timestamp - _BTSNOOP_EPOCH_OFFSET) / 1_000_000


# ---------------------------------------------------------------------------
# BtsnoopParser — parse btsnoop v1 capture files
# ---------------------------------------------------------------------------

class BtsnoopParser:
    """Parse btsnoop v1 capture files (as produced by ``btmon -w``).

    btsnoop format:

    - **File header** (16 bytes):
      - Identification: 8 bytes ``"btsnoop\\0"``
      - Version: 4 bytes big-endian (must be 1)
      - Datalink Type: 4 bytes big-endian (1002 = HCI UART, 2001 = Monitor)

    - **Records** (repeated until EOF):
      - Original Length: 4 bytes BE
      - Included Length: 4 bytes BE
      - Flags: 4 bytes BE
      - Cumulative Drops: 4 bytes BE
      - Timestamp: 8 bytes BE (microseconds since btsnoop epoch)
      - Data: ``Included Length`` bytes
    """

    MAGIC = b"btsnoop\x00"
    VERSION = 1
    HEADER_SIZE = 16
    RECORD_HEADER_SIZE = 24  # 4+4+4+4+8

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.datalink_type: int = 0
        self.records: list[BtsnoopRecord] = []

    def parse(self) -> list[BtsnoopRecord]:
        """Parse the entire btsnoop file.  Returns list of records.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file header is invalid.
        """
        self.records = []
        with open(self.filepath, "rb") as f:
            self.parse_header(f)
            while True:
                record = self.parse_record(f)
                if record is None:
                    break
                self.records.append(record)
        return self.records

    def parse_header(self, f) -> bool:
        """Parse and validate the 16-byte file header.

        Returns True on success.  Raises ``ValueError`` on invalid header.
        """
        header = f.read(self.HEADER_SIZE)
        if len(header) < self.HEADER_SIZE:
            raise ValueError(
                f"btsnoop header too short: expected {self.HEADER_SIZE} bytes, "
                f"got {len(header)}"
            )

        magic = header[:8]
        if magic != self.MAGIC:
            raise ValueError(
                f"Not a btsnoop file: expected magic {self.MAGIC!r}, got {magic!r}"
            )

        version, datalink = struct.unpack(">II", header[8:16])
        if version != self.VERSION:
            raise ValueError(
                f"Unsupported btsnoop version {version} (only v1 supported)"
            )

        self.datalink_type = datalink
        return True

    def parse_record(self, f) -> BtsnoopRecord | None:
        """Parse a single record.  Returns ``None`` at EOF.

        Truncated records (e.g. due to interrupted capture) are silently
        skipped with a log warning rather than raising.
        """
        rec_header = f.read(self.RECORD_HEADER_SIZE)
        if len(rec_header) == 0:
            return None  # clean EOF
        if len(rec_header) < self.RECORD_HEADER_SIZE:
            logger.warning(
                "Truncated record header at offset %d (got %d of %d bytes)",
                f.tell() - len(rec_header),
                len(rec_header),
                self.RECORD_HEADER_SIZE,
            )
            return None

        original_length, included_length, flags, drops, timestamp = struct.unpack(
            ">IIIIQ", rec_header
        )

        # Sanity-check included_length to avoid allocating huge buffers on
        # corrupt files.  Real HCI packets are <=65539 bytes (HCI max).
        if included_length > 1_000_000:
            logger.warning(
                "Suspiciously large record (%d bytes) at offset %d — skipping rest of file",
                included_length,
                f.tell() - self.RECORD_HEADER_SIZE,
            )
            return None

        data = f.read(included_length)
        if len(data) < included_length:
            logger.warning(
                "Truncated record data: expected %d bytes, got %d",
                included_length,
                len(data),
            )
            # Still return the partial record — caller can decide
            return BtsnoopRecord(
                original_length=original_length,
                included_length=included_length,
                flags=flags,
                drops=drops,
                timestamp=timestamp,
                data=data,
            )

        return BtsnoopRecord(
            original_length=original_length,
            included_length=included_length,
            flags=flags,
            drops=drops,
            timestamp=timestamp,
            data=data,
        )

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)


# ---------------------------------------------------------------------------
# L2CAPFrame — extracted L2CAP frame from HCI ACL data
# ---------------------------------------------------------------------------

@dataclass
class L2CAPFrame:
    """Extracted L2CAP frame from an HCI ACL packet."""

    handle: int       # HCI connection handle (12-bit)
    length: int       # L2CAP payload length
    cid: int          # L2CAP channel ID
    payload: bytes    # L2CAP payload (protocol data)
    direction: str    # "sent" or "received"
    timestamp: float  # Unix epoch seconds


# ---------------------------------------------------------------------------
# HCI ACL data extraction with fragmentation reassembly
# ---------------------------------------------------------------------------

# HCI ACL Packet Boundary (PB) flag values (bits 13-12 of handle field)
_PB_FIRST_NON_AUTO = 0b00     # First non-automatically-flushable (start)
_PB_CONTINUING     = 0b01     # Continuing fragment
_PB_FIRST_AUTO     = 0b10     # First automatically-flushable (start)

# btsnoop Monitor datalink type uses an opcode prefix before HCI data.
# For HCI UART (1002) there is no prefix — data starts at byte 0.
# For Monitor (2001) the first 2 bytes are an opcode we skip.
_MONITOR_DATALINK = 2001
_HCI_UART_DATALINK = 1002

# HCI packet type indicators (for Monitor format)
_HCI_ACL_DATA_PKT = 0x02


def extract_l2cap_frames(
    records: list[BtsnoopRecord],
    datalink_type: int = 0,
) -> list[L2CAPFrame]:
    """Extract L2CAP frames from btsnoop records.

    Parses HCI ACL data packets and reassembles fragmented L2CAP PDUs:

    - **HCI ACL header**: Handle (2 LE) + Data Total Length (2 LE).
      The handle field encodes the connection handle (bits 0-11),
      PB flag (bits 13-12), and BC flag (bits 15-14).
    - **L2CAP header** (first fragment only): Length (2 LE) + CID (2 LE).
    - **L2CAP payload**: remaining data across all fragments.

    Args:
        records: Parsed btsnoop records.
        datalink_type: The btsnoop datalink type from the file header.
            Used to determine whether records have a Monitor opcode prefix.

    Returns:
        List of reassembled L2CAP frames.
    """
    frames: list[L2CAPFrame] = []

    # Reassembly buffer: (connection_handle, direction) -> (l2cap_length, cid, accumulated_data, direction, timestamp)
    # Keyed by (handle, direction) to avoid merging fragments from opposite directions on the same handle.
    pending: dict[tuple[int, str], tuple[int, int, bytearray, str, float]] = {}

    for record in records:
        # Filter to ACL data packets only
        if not record.is_data:
            continue

        data = record.data
        if not data:
            continue

        # For Monitor datalink, the first bytes are an opcode.
        # We need to detect the HCI packet type from the monitor header.
        offset = 0
        if datalink_type == _MONITOR_DATALINK:
            # Monitor format: 2-byte opcode.  ACL TX = 0x0000, ACL RX = 0x0001
            # Actually the opcodes vary; the btsnoop flags already tell us
            # direction and type, so we just skip the 2-byte opcode prefix.
            if len(data) < 2:
                continue
            offset = 2

        # Ensure we have at least the HCI ACL header (4 bytes)
        if len(data) < offset + 4:
            continue

        # Parse HCI ACL header (little-endian)
        handle_raw, acl_data_len = struct.unpack_from("<HH", data, offset)
        offset += 4

        connection_handle = handle_raw & 0x0FFF
        pb_flag = (handle_raw >> 12) & 0x03

        direction = "sent" if record.is_sent else "received"
        timestamp = record.timestamp_seconds

        acl_payload = data[offset:offset + acl_data_len]
        if len(acl_payload) < acl_data_len:
            logger.warning(
                "Truncated ACL payload: expected %d, got %d",
                acl_data_len, len(acl_payload),
            )
        if len(acl_payload) == 0:
            continue

        if pb_flag in (_PB_FIRST_AUTO, _PB_FIRST_NON_AUTO):
            # Start of a new L2CAP PDU — parse L2CAP header
            if len(acl_payload) < 4:
                # Not enough data for L2CAP header; skip
                continue

            l2cap_length, l2cap_cid = struct.unpack_from("<HH", acl_payload, 0)
            l2cap_data = acl_payload[4:]

            if len(l2cap_data) >= l2cap_length:
                # Complete frame in a single ACL packet
                frames.append(L2CAPFrame(
                    handle=connection_handle,
                    length=l2cap_length,
                    cid=l2cap_cid,
                    payload=bytes(l2cap_data[:l2cap_length]),
                    direction=direction,
                    timestamp=timestamp,
                ))
                # Clear any stale pending for this handle+direction
                pending.pop((connection_handle, direction), None)
            else:
                # First fragment — start reassembly
                pending[(connection_handle, direction)] = (
                    l2cap_length,
                    l2cap_cid,
                    bytearray(l2cap_data),
                    direction,
                    timestamp,
                )

        elif pb_flag == _PB_CONTINUING:
            # Continuation fragment
            pending_key = (connection_handle, direction)
            if pending_key not in pending:
                # No start fragment seen — drop
                logger.debug(
                    "Continuation fragment for handle 0x%03x (%s) with no pending start",
                    connection_handle, direction,
                )
                continue

            l2cap_length, l2cap_cid, buf, orig_dir, orig_ts = pending[pending_key]
            buf.extend(acl_payload)

            if len(buf) >= l2cap_length:
                # Reassembly complete
                frames.append(L2CAPFrame(
                    handle=connection_handle,
                    length=l2cap_length,
                    cid=l2cap_cid,
                    payload=bytes(buf[:l2cap_length]),
                    direction=orig_dir,
                    timestamp=orig_ts,
                ))
                del pending[pending_key]
        # else: unknown PB flag — ignore

    return frames


# ---------------------------------------------------------------------------
# Protocol classifier
# ---------------------------------------------------------------------------

# Well-known fixed L2CAP CIDs
_FIXED_CID_MAP: dict[int, str] = {
    0x0001: "l2cap-signaling",
    0x0002: "connectionless",
    0x0003: "amp-manager",
    0x0004: "ble-att",
    0x0005: "ble-le-signaling",
    0x0006: "ble-smp",
    0x0007: "br-edr-smp",
}

# SDP PDU IDs (first byte)
_SDP_PDU_IDS = set(range(0x01, 0x08))  # 0x01..0x07

# OBEX opcodes (first byte)
_OBEX_OPCODES = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0xFF, 0x02, 0x03,
                 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

# BNEP frame types (first byte, upper 7 bits)
_BNEP_FRAME_TYPES = {0x00, 0x01, 0x02, 0x03, 0x04}


def classify_protocol(frame: L2CAPFrame) -> str:
    """Classify the protocol of an L2CAP frame by CID/PSM.

    Fixed CIDs are mapped directly.  For dynamic CIDs the first bytes
    of the payload are inspected for protocol signatures.

    Returns:
        A protocol name string (e.g. ``"sdp"``, ``"ble-att"``, ``"rfcomm"``).
        Returns ``"unknown"`` if no protocol can be determined.
    """
    # Fixed CIDs
    if frame.cid in _FIXED_CID_MAP:
        return _FIXED_CID_MAP[frame.cid]

    # Dynamic CIDs — inspect payload
    payload = frame.payload
    if not payload:
        return "unknown"

    first_byte = payload[0]

    # AT commands (HFP/HSP over RFCOMM): starts with "AT" or "\r\n"
    if len(payload) >= 2:
        prefix = payload[:2]
        if prefix in (b"AT", b"at", b"At", b"\r\n"):
            return "at-hfp"

    # SDP: PDU IDs 0x01-0x07
    if first_byte in _SDP_PDU_IDS:
        # Extra validation: SDP has a 5-byte header (pdu_id, tid, param_len)
        if len(payload) >= 5:
            param_len = struct.unpack(">H", payload[3:5])[0]
            # +2 slack accounts for continuation state bytes that may
            # follow the PDU body (e.g. ContinuationState in SDP responses).
            if param_len <= len(payload) - 5 + 2:
                return "sdp"

    # RFCOMM: check for RFCOMM address byte pattern.
    # RFCOMM frames start with address(1) + control(1) + length(1+).
    # Address byte: EA(1) | CR(1) | DLCI(6).  EA is always 1 for RFCOMM.
    if len(payload) >= 3:
        addr_byte = first_byte
        if addr_byte & 0x01:  # EA bit set
            ctrl = payload[1]
            # RFCOMM frame types (control field values):
            #   0x2F = SABM (Set Asynchronous Balanced Mode)
            #   0x3F = SABM with P/F bit set
            #   0x63 = UA (Unnumbered Acknowledgement)
            #   0x73 = UA with P/F bit set
            #   0x0F = DM (Disconnected Mode)
            #   0x43 = DISC (Disconnect)
            #   0x53 = DISC with P/F bit set
            #   0xEF = UIH (Unnumbered Information with Header check)
            #   0xE3 = UIH variant
            #   0x03 = UI (Unnumbered Information)
            # Check both exact matches and masked (ctrl & 0xEF) matches
            # in a single consolidated set.
            if ctrl in (0x3F, 0xEF, 0x53, 0x73, 0x2F, 0xE3, 0x63) or \
               (ctrl & 0xEF) in (0x2F, 0x63, 0x0F, 0x43, 0xEF, 0x03):
                return "rfcomm"

    # OBEX: opcodes
    if first_byte in _OBEX_OPCODES:
        if len(payload) >= 3:
            # OBEX has 2-byte big-endian length at offset 1
            obex_len = struct.unpack(">H", payload[1:3])[0]
            if 3 <= obex_len <= len(payload) + 2:  # allow slack
                return "obex"

    # BNEP: frame types in upper 7 bits of first byte
    bnep_type = first_byte & 0x7F
    if bnep_type in _BNEP_FRAME_TYPES:
        # BNEP general ethernet frames are at least 15 bytes
        if bnep_type == 0x00 and len(payload) >= 15:
            return "bnep"
        elif bnep_type in (0x01, 0x02, 0x03):
            return "bnep"
        elif bnep_type == 0x04 and len(payload) >= 2:
            return "bnep"

    return "unknown"


# ---------------------------------------------------------------------------
# Corpus import
# ---------------------------------------------------------------------------

def import_btsnoop_to_corpus(filepath: str, corpus: Corpus) -> dict[str, int]:
    """Import a btsnoop capture as corpus seeds.

    Parses the capture, extracts L2CAP frames, classifies protocols,
    and adds unique payloads to the corpus.  Deduplication is by
    SHA-256 of the payload bytes.

    Args:
        filepath: Path to the btsnoop capture file.
        corpus: Target corpus to add seeds to.

    Returns:
        Dict mapping protocol name to number of seeds imported.
    """
    parser = BtsnoopParser(filepath)
    records = parser.parse()
    frames = extract_l2cap_frames(records, datalink_type=parser.datalink_type)

    counts: dict[str, int] = {}
    seen: set[str] = set()

    for frame in frames:
        if not frame.payload:
            continue

        protocol = classify_protocol(frame)
        if protocol == "unknown":
            continue

        content_hash = hashlib.sha256(frame.payload).hexdigest()
        if content_hash in seen:
            continue
        seen.add(content_hash)

        corpus.add_seed(protocol, frame.payload)
        counts[protocol] = counts.get(protocol, 0) + 1

    return counts


# ---------------------------------------------------------------------------
# CaptureReplayer — selective replay engine
# ---------------------------------------------------------------------------

class CaptureReplayer:
    """Replay frames from a btsnoop capture against a target.

    Supports:

    - Replay all sent frames (optionally filtered by protocol).
    - Replay specific frame indices.
    - Replay with original inter-frame timing preserved.
    - Replay with mutations applied to each frame.

    Args:
        filepath: Path to the btsnoop capture file.
        target: Target device BD_ADDR (e.g. ``"AA:BB:CC:DD:EE:FF"``).
    """

    def __init__(self, filepath: str, target: str) -> None:
        self.filepath = filepath
        self.target = target
        self.parser = BtsnoopParser(filepath)
        self.frames: list[L2CAPFrame] = []

    def load(self) -> int:
        """Parse the capture and extract L2CAP frames.

        Returns:
            The number of frames extracted.
        """
        records = self.parser.parse()
        self.frames = extract_l2cap_frames(
            records, datalink_type=self.parser.datalink_type
        )
        return len(self.frames)

    # ------------------------------------------------------------------
    # Replay methods
    # ------------------------------------------------------------------

    def replay_all(
        self,
        protocol: str | None = None,
        transport_factory: Callable[[str], object] | None = None,
        delay: float = 0.5,
        preserve_timing: bool = False,
    ) -> dict:
        """Replay all sent frames, optionally filtered by protocol.

        Args:
            protocol: If given, only replay frames matching this protocol.
            transport_factory: Callable ``(target) -> transport`` that
                returns a connected transport with ``send()`` / ``close()``
                methods.  If ``None``, frames are "dry-run" replayed
                (logged but not sent).
            delay: Fixed inter-frame delay in seconds (ignored when
                *preserve_timing* is True).
            preserve_timing: If True, use the original inter-frame delays
                from the capture timestamps.

        Returns:
            Dict with ``sent``, ``skipped``, ``errors``, and ``protocol``
            counts.
        """
        result = {"sent": 0, "skipped": 0, "errors": 0, "protocols": {}}
        selected = self._select_frames(protocol=protocol, direction="sent")

        if not selected:
            return result

        transport = None
        if transport_factory is not None:
            transport = transport_factory(self.target)
            if hasattr(transport, "connect"):
                try:
                    connected = transport.connect()
                    if not connected:
                        result["errors"] += 1
                        return result
                except Exception as exc:
                    logger.error("Transport connect failed: %s", exc)
                    result["errors"] += 1
                    return result

        try:
            prev_ts: float | None = None
            for frame in selected:
                proto = classify_protocol(frame)
                result["protocols"][proto] = result["protocols"].get(proto, 0) + 1

                # Apply timing
                if preserve_timing and prev_ts is not None:
                    inter_delay = max(0.0, frame.timestamp - prev_ts)
                    # Cap to 10 seconds to avoid excessively long waits
                    time.sleep(min(inter_delay, 10.0))
                elif delay > 0 and result["sent"] > 0:
                    time.sleep(delay)
                prev_ts = frame.timestamp

                # Send or dry-run
                if transport is not None:
                    try:
                        transport.send(frame.payload)
                        result["sent"] += 1
                    except Exception as exc:
                        logger.warning("Send failed for frame: %s", exc)
                        result["errors"] += 1
                else:
                    # Dry-run
                    result["sent"] += 1
        finally:
            if transport is not None and hasattr(transport, "close"):
                try:
                    transport.close()
                except Exception:
                    pass

        return result

    def replay_frame(self, index: int, transport) -> dict:
        """Replay a single frame by index.

        Args:
            index: Frame index (0-based) into ``self.frames``.
            transport: A connected transport object with a ``send()`` method.

        Returns:
            Dict with ``success``, ``index``, ``protocol``, ``size``,
            and optionally ``error``.
        """
        if not self.frames:
            return {
                "success": False,
                "index": index,
                "error": "No frames loaded. Call load() first.",
            }

        if index < 0 or index >= len(self.frames):
            return {
                "success": False,
                "index": index,
                "error": f"Index {index} out of range (0-{len(self.frames) - 1})",
            }

        frame = self.frames[index]
        proto = classify_protocol(frame)

        try:
            transport.send(frame.payload)
            return {
                "success": True,
                "index": index,
                "protocol": proto,
                "size": len(frame.payload),
            }
        except Exception as exc:
            return {
                "success": False,
                "index": index,
                "protocol": proto,
                "size": len(frame.payload),
                "error": str(exc),
            }

    def replay_with_mutations(
        self,
        protocol: str | None = None,
        num_mutations: int = 1,
        transport_factory: Callable[[str], object] | None = None,
        delay: float = 0.5,
    ) -> dict:
        """Replay frames with mutations applied.

        For each selected frame, applies *num_mutations* random byte-level
        mutations (bitflip, replace, insert, delete) before sending.  This
        finds variants of captured traffic that may trigger different
        code paths in the target.

        Args:
            protocol: If given, only replay frames matching this protocol.
            num_mutations: Number of mutation rounds per frame.
            transport_factory: Callable ``(target) -> transport``.
                If ``None``, performs a dry run.
            delay: Inter-frame delay in seconds.

        Returns:
            Dict with ``sent``, ``errors``, ``mutations_applied``, and
            ``protocols`` counts.
        """
        import random as _random

        result = {"sent": 0, "errors": 0, "mutations_applied": 0, "protocols": {}}
        selected = self._select_frames(protocol=protocol, direction="sent")

        if not selected:
            return result

        mutators = [
            FieldMutator.bitflip,
            FieldMutator.byte_replace,
            FieldMutator.byte_insert,
            FieldMutator.byte_delete,
        ]

        transport = None
        if transport_factory is not None:
            transport = transport_factory(self.target)
            if hasattr(transport, "connect"):
                try:
                    if not transport.connect():
                        result["errors"] += 1
                        return result
                except Exception as exc:
                    logger.error("Transport connect failed: %s", exc)
                    result["errors"] += 1
                    return result

        try:
            for frame in selected:
                proto = classify_protocol(frame)
                result["protocols"][proto] = result["protocols"].get(proto, 0) + 1

                # Apply mutations
                mutated = frame.payload
                for _ in range(num_mutations):
                    mutator = _random.choice(mutators)
                    mutated = mutator(mutated)
                    result["mutations_applied"] += 1

                # Skip sending empty payloads (mutations can reduce to empty bytes)
                if not mutated:
                    continue

                if delay > 0 and result["sent"] > 0:
                    time.sleep(delay)

                if transport is not None:
                    try:
                        transport.send(mutated)
                        result["sent"] += 1
                    except Exception as exc:
                        logger.warning("Send failed for mutated frame: %s", exc)
                        result["errors"] += 1
                else:
                    result["sent"] += 1
        finally:
            if transport is not None and hasattr(transport, "close"):
                try:
                    transport.close()
                except Exception:
                    pass

        return result

    # ------------------------------------------------------------------
    # Inspection / display
    # ------------------------------------------------------------------

    def list_frames(self, protocol: str | None = None) -> list[dict]:
        """List all frames with metadata (for CLI display).

        Args:
            protocol: If given, only include frames matching this protocol.

        Returns:
            List of dicts with ``index``, ``direction``, ``protocol``,
            ``cid``, ``handle``, ``size``, ``timestamp``.
        """
        result = []
        for i, frame in enumerate(self.frames):
            proto = classify_protocol(frame)
            if protocol is not None and proto != protocol:
                continue
            result.append({
                "index": i,
                "direction": frame.direction,
                "protocol": proto,
                "cid": f"0x{frame.cid:04x}",
                "handle": f"0x{frame.handle:03x}",
                "size": len(frame.payload),
                "timestamp": frame.timestamp,
            })
        return result

    def summary(self) -> dict:
        """Capture summary: frame counts by protocol, direction, duration.

        Returns:
            Dict with ``total_frames``, ``sent_frames``, ``received_frames``,
            ``protocols`` (count by name), ``duration_seconds``, and
            ``datalink_type``.
        """
        protocols: dict[str, int] = {}
        sent = 0
        received = 0
        min_ts = float("inf")
        max_ts = float("-inf")

        for frame in self.frames:
            proto = classify_protocol(frame)
            protocols[proto] = protocols.get(proto, 0) + 1
            if frame.direction == "sent":
                sent += 1
            else:
                received += 1
            if frame.timestamp < min_ts:
                min_ts = frame.timestamp
            if frame.timestamp > max_ts:
                max_ts = frame.timestamp

        duration = max_ts - min_ts if self.frames else 0.0

        return {
            "total_frames": len(self.frames),
            "sent_frames": sent,
            "received_frames": received,
            "protocols": protocols,
            "duration_seconds": round(duration, 3),
            "datalink_type": self.parser.datalink_type,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_frames(
        self,
        protocol: str | None = None,
        direction: str | None = None,
    ) -> list[L2CAPFrame]:
        """Filter frames by protocol and/or direction.

        Args:
            protocol: Protocol name to match, or ``None`` for all.
            direction: ``"sent"`` or ``"received"``, or ``None`` for both.

        Returns:
            Filtered list of frames.
        """
        result = []
        for frame in self.frames:
            if direction is not None and frame.direction != direction:
                continue
            if protocol is not None and classify_protocol(frame) != protocol:
                continue
            result.append(frame)
        return result
