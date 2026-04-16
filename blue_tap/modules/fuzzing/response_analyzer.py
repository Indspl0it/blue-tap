"""Black-box response anomaly detection for Bluetooth fuzzing.

Detects 0-day indicators WITHOUT access to the target's internals by
learning baseline behavior and flagging deviations.  Works against any
Bluetooth stack (Bluedroid, BlueZ, Broadcom, Qualcomm) because it never
assumes a specific implementation — only structural self-consistency and
statistical deviation from the target's own observed behavior.

Three detection layers:

1. **Structural self-consistency** — does the response's internal
   structure agree with itself?  (e.g. declared length vs actual bytes)
   This is implementation-agnostic: ALL stacks must produce
   self-consistent PDUs.

2. **Baseline deviation** — does this response differ statistically
   from what this specific target normally returns?  Learned at
   campaign start from valid requests.

3. **Leak indicators** — heuristics for information disclosure:
   unexpected response growth, high-entropy payloads where structured
   data is expected, ASCII/heap patterns in binary fields.
"""

from __future__ import annotations

import collections
import math
import struct
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Anomaly representation
# ---------------------------------------------------------------------------

class AnomalyType(Enum):
    """Categories of detected anomalies."""
    STRUCTURAL = "structural"       # Response is internally inconsistent
    LENGTH_MISMATCH = "length"      # Declared vs actual length disagree
    TIMING = "timing"               # Latency deviates from baseline
    SIZE_DEVIATION = "size"         # Response size deviates from baseline
    UNEXPECTED_OPCODE = "opcode"    # Response opcode is unexpected
    LEAK_INDICATOR = "leak"         # Response suggests info disclosure
    BEHAVIORAL = "behavioral"       # Target behavior changed (errors, silence)


@dataclass
class Anomaly:
    """A single detected anomaly in a response."""
    anomaly_type: AnomalyType
    severity: str           # "critical", "high", "medium", "low"
    protocol: str
    description: str
    evidence: str = ""      # Hex dump or measurement
    score: float = 0.0      # Numeric anomaly score (higher = more interesting)


# ---------------------------------------------------------------------------
# Baseline sample
# ---------------------------------------------------------------------------

@dataclass
class ResponseSample:
    """One baseline observation from a valid request."""
    response_len: int
    latency_ms: float
    first_byte: int         # opcode / PDU type
    error_code: int = 0     # protocol-level error code if applicable
    raw: bytes = b""


@dataclass
class ProtocolBaseline:
    """Learned baseline for one protocol on one target."""
    samples: list[ResponseSample] = field(default_factory=list)

    # Computed stats (updated after learning phase)
    mean_len: float = 0.0
    std_len: float = 0.0
    max_len: int = 0
    mean_latency_ms: float = 0.0
    std_latency_ms: float = 0.0
    seen_opcodes: set[int] = field(default_factory=set)
    seen_error_codes: set[int] = field(default_factory=set)

    # Phase 4: Timing-based coverage proxy fields
    latency_histogram: dict[int, int] = field(default_factory=dict)
    opcode_latency: dict[int, list[float]] = field(default_factory=dict)

    @property
    def latency_p50(self) -> float:
        """50th percentile latency from baseline samples."""
        return self._latency_percentile(0.50)

    @property
    def latency_p90(self) -> float:
        """90th percentile latency from baseline samples."""
        return self._latency_percentile(0.90)

    @property
    def latency_p99(self) -> float:
        """99th percentile latency from baseline samples."""
        return self._latency_percentile(0.99)

    def _latency_percentile(self, p: float) -> float:
        """Compute the p-th percentile of baseline latencies."""
        if not self.samples:
            return 0.0
        latencies = sorted(s.latency_ms for s in self.samples)
        idx = int(p * (len(latencies) - 1))
        return latencies[idx]

    def compute_stats(self) -> None:
        """Recompute statistics from samples."""
        if not self.samples:
            return
        lengths = [s.response_len for s in self.samples]
        latencies = [s.latency_ms for s in self.samples]

        self.mean_len = sum(lengths) / len(lengths)
        self.std_len = _std(lengths)
        self.max_len = max(lengths)
        self.mean_latency_ms = sum(latencies) / len(latencies)
        self.std_latency_ms = _std(latencies)
        self.seen_opcodes = {s.first_byte for s in self.samples}
        self.seen_error_codes = {s.error_code for s in self.samples if s.error_code}

        # Phase 4: Build latency histogram (1ms buckets)
        self.latency_histogram = {}
        for lat in latencies:
            bucket = int(lat)
            self.latency_histogram[bucket] = self.latency_histogram.get(bucket, 0) + 1

        # Phase 4: Build per-opcode latency tracking
        self.opcode_latency = {}
        for s in self.samples:
            self.opcode_latency.setdefault(s.first_byte, []).append(s.latency_ms)


def _std(values: list[float | int]) -> float:
    """Population standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _zscore(value: float, mean: float, std: float) -> float:
    """Z-score (number of standard deviations from mean)."""
    if std < 0.001:
        return 0.0 if abs(value - mean) < 0.001 else 10.0
    return abs(value - mean) / std


# ---------------------------------------------------------------------------
# Structural validators (implementation-agnostic)
# ---------------------------------------------------------------------------

def _validate_sdp_structure(response: bytes) -> list[Anomaly]:
    """Check SDP PDU internal consistency.

    SDP header: PDU_ID(1) + TransactionID(2) + ParameterLength(2)
    The ParameterLength field MUST equal len(response) - 5.
    Any stack that violates this has a bug.
    """
    anomalies = []
    if len(response) < 5:
        if len(response) > 0:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "sdp",
                f"SDP response too short for valid PDU ({len(response)} bytes, need 5)",
                evidence=response.hex(),
                score=7.0,
            ))
        return anomalies

    pdu_id = response[0]
    param_len = struct.unpack(">H", response[3:5])[0]
    actual_param_len = len(response) - 5

    if param_len != actual_param_len:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "high", "sdp",
            f"SDP ParameterLength declares {param_len} but actual payload is {actual_param_len} bytes",
            evidence=f"header={response[:5].hex()} full_len={len(response)}",
            score=8.0,
        ))

    # Check for known vs unknown PDU IDs
    valid_pdu_ids = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
    if pdu_id not in valid_pdu_ids:
        anomalies.append(Anomaly(
            AnomalyType.UNEXPECTED_OPCODE, "medium", "sdp",
            f"SDP response has non-standard PDU ID 0x{pdu_id:02x}",
            evidence=response[:8].hex(),
            score=5.0,
        ))

    # Error response (0x01): check error code is in valid range
    if pdu_id == 0x01 and len(response) >= 7:
        err_code = struct.unpack(">H", response[5:7])[0]
        if err_code > 0x0006:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "sdp",
                f"SDP error code 0x{err_code:04x} is outside defined range (0x0001-0x0006)",
                evidence=response[:8].hex(),
                score=5.0,
            ))

    # --- Enhanced checks (Task 3.2.1) ---
    payload = response[5:]

    if pdu_id == 0x03 and len(payload) >= 5:
        # ServiceSearchResponse: TotalCount(2) + CurrentCount(2) + handles + ContState
        total_count = struct.unpack(">H", payload[0:2])[0]
        current_count = struct.unpack(">H", payload[2:4])[0]
        if total_count < current_count:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "sdp",
                f"SDP SearchRsp TotalCount ({total_count}) < CurrentCount ({current_count})",
                evidence=response[:12].hex(),
                score=7.0,
            ))
        # Continuation state after handles (4 bytes each)
        handles_end = 4 + current_count * 4
        if len(payload) > handles_end:
            cont_state_len = payload[handles_end]
            if cont_state_len > 16:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "sdp",
                    f"SDP continuation state length {cont_state_len} exceeds max 16",
                    evidence=response[:16].hex(),
                    score=6.0,
                ))

    elif pdu_id in (0x05, 0x07) and len(payload) >= 3:
        # AttributeResponse / SearchAttributeResponse: ByteCount(2) + data + ContState
        byte_count = struct.unpack(">H", payload[0:2])[0]
        data_end = 2 + byte_count
        if len(payload) > data_end:
            cont_state_len = payload[data_end]
            if cont_state_len > 16:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "sdp",
                    f"SDP continuation state length {cont_state_len} exceeds max 16",
                    evidence=response[:16].hex(),
                    score=6.0,
                ))
        # Data Element nesting validation
        attr_data = payload[2:2 + byte_count]
        if len(attr_data) >= 2:
            anomalies.extend(_validate_sdp_data_element(attr_data, 0))

    return anomalies


def _validate_sdp_data_element(data: bytes, depth: int) -> list[Anomaly]:
    """Validate SDP Data Element Sequence nesting.

    Checks that DES/DEA containers do not declare lengths exceeding
    their parent container boundary.  Limits recursion to avoid stack
    overflow on malformed data.
    """
    anomalies: list[Anomaly] = []
    if depth > 8 or len(data) < 1:
        return anomalies

    offset = 0
    while offset < len(data):
        descriptor = data[offset]
        elem_type = (descriptor >> 3) & 0x1F
        size_index = descriptor & 0x07
        offset += 1

        # Determine element size
        if size_index <= 4:
            elem_size = [1, 2, 4, 8, 16][size_index]
            if elem_type == 0 and size_index == 0:
                elem_size = 0
        elif size_index == 5:
            if offset >= len(data):
                break
            elem_size = data[offset]
            offset += 1
        elif size_index == 6:
            if offset + 2 > len(data):
                break
            elem_size = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
        elif size_index == 7:
            if offset + 4 > len(data):
                break
            elem_size = struct.unpack(">I", data[offset:offset + 4])[0]
            offset += 4
        else:
            break

        if elem_size > len(data) - offset:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "sdp",
                f"SDP Data Element at depth {depth} declares size {elem_size} "
                f"but only {len(data) - offset} bytes remain",
                evidence=data[max(0, offset - 2):offset + min(8, elem_size)].hex(),
                score=7.0,
            ))
            break

        # Recurse into DES (type 6) and DEA (type 7)
        if elem_type in (6, 7) and elem_size > 0:
            anomalies.extend(
                _validate_sdp_data_element(data[offset:offset + elem_size], depth + 1)
            )

        offset += elem_size

    return anomalies


def _validate_att_structure(response: bytes) -> list[Anomaly]:
    """Check ATT PDU internal consistency.

    ATT responses have opcode as first byte. Request opcodes are even,
    response opcodes are odd (or 0x01 for error). If we get back a
    request opcode, the stack is confused.
    """
    anomalies = []
    if not response:
        return anomalies

    opcode = response[0]

    # Error Response (0x01): must be at least 5 bytes
    # (opcode + req_opcode + handle + error_code)
    if opcode == 0x01:
        if len(response) < 5:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "ble-att",
                f"ATT Error Response too short ({len(response)} bytes, need 5)",
                evidence=response.hex(),
                score=7.0,
            ))
        elif len(response) >= 5:
            error_code = response[4]
            # Valid error codes: 0x01-0x14 + 0x80-0xFF (application)
            if error_code == 0x00 or (0x15 <= error_code <= 0x7F):
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "ble-att",
                    f"ATT Error Response has undefined error code 0x{error_code:02x}",
                    evidence=response[:6].hex(),
                    score=5.0,
                ))
        return anomalies

    # MTU Exchange Response (0x03): exactly 3 bytes (opcode + mtu_u16)
    if opcode == 0x03 and len(response) != 3:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "medium", "ble-att",
            f"ATT MTU Response should be 3 bytes, got {len(response)}",
            evidence=response.hex()[:32],
            score=6.0,
        ))

    # If we receive a REQUEST opcode (even, except 0x52/0xD2 which are
    # write commands), the stack is mirroring our request back
    if opcode not in (0x52, 0xD2) and opcode % 2 == 0 and opcode <= 0x22:
        anomalies.append(Anomaly(
            AnomalyType.UNEXPECTED_OPCODE, "high", "ble-att",
            f"Received request opcode 0x{opcode:02x} as response — stack may be confused",
            evidence=response[:8].hex(),
            score=8.0,
        ))

    # --- Enhanced checks (Task 3.2.2) ---

    # Read By Type Response (0x09): each attribute data pair must be same length
    if opcode == 0x09 and len(response) >= 2:
        pair_len = response[1]  # Length of each handle-value pair
        data_section = response[2:]
        if pair_len > 0 and len(data_section) > 0 and len(data_section) % pair_len != 0:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "ble-att",
                f"ATT Read By Type Rsp pair length {pair_len} does not evenly divide "
                f"data ({len(data_section)} bytes)",
                evidence=response[:12].hex(),
                score=7.0,
            ))

    # Find Information Response (0x05): format byte must be 0x01 or 0x02
    if opcode == 0x05 and len(response) >= 2:
        fmt = response[1]
        if fmt not in (0x01, 0x02):
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "ble-att",
                f"ATT Find Info Rsp has invalid format byte 0x{fmt:02x} (must be 0x01 or 0x02)",
                evidence=response[:8].hex(),
                score=6.0,
            ))
        else:
            # 0x01 = 2+2 (handle + 16-bit UUID), 0x02 = 2+16 (handle + 128-bit UUID)
            entry_size = 4 if fmt == 0x01 else 18
            data_section = response[2:]
            if len(data_section) > 0 and len(data_section) % entry_size != 0:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "ble-att",
                    f"ATT Find Info Rsp data length {len(data_section)} is not a multiple "
                    f"of entry size {entry_size} (format=0x{fmt:02x})",
                    evidence=response[:12].hex(),
                    score=5.0,
                ))

    # Write Response (0x13): must be exactly 1 byte (opcode only)
    if opcode == 0x13 and len(response) != 1:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "medium", "ble-att",
            f"ATT Write Response should be exactly 1 byte, got {len(response)}",
            evidence=response.hex()[:32],
            score=6.0,
        ))

    return anomalies


def _validate_l2cap_structure(response: bytes) -> list[Anomaly]:
    """Check L2CAP signaling internal consistency.

    L2CAP signaling header: Code(1) + Identifier(1) + Length(2 LE)
    The Length field MUST equal len(response) - 4.
    """
    anomalies = []
    if len(response) < 4:
        if len(response) > 0:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "l2cap",
                f"L2CAP signaling response too short ({len(response)} bytes)",
                evidence=response.hex(),
                score=5.0,
            ))
        return anomalies

    code = response[0]
    declared_len = struct.unpack("<H", response[2:4])[0]
    actual_len = len(response) - 4

    if declared_len != actual_len:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "high", "l2cap",
            f"L2CAP signaling length declares {declared_len} but actual is {actual_len}",
            evidence=f"header={response[:4].hex()} full_len={len(response)}",
            score=8.0,
        ))

    # Command Reject (0x01): minimum 2 bytes reason code
    if code == 0x01 and actual_len < 2:
        anomalies.append(Anomaly(
            AnomalyType.STRUCTURAL, "medium", "l2cap",
            "L2CAP Command Reject missing reason code",
            evidence=response.hex(),
            score=5.0,
        ))

    # --- Enhanced checks (Task 3.2.3) ---
    data = response[4:]

    # Connection Response (0x03): Result + Status valid ranges
    if code == 0x03 and len(data) >= 8:
        # ConnRsp: DCID(2) + SCID(2) + Result(2) + Status(2)
        result = struct.unpack("<H", data[4:6])[0]
        status = struct.unpack("<H", data[6:8])[0]
        # Result: 0x0000-0x0004 defined
        if result > 0x0004:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "l2cap",
                f"L2CAP ConnRsp Result 0x{result:04x} outside valid range (0x0000-0x0004)",
                evidence=response[:12].hex(),
                score=6.0,
            ))
        # Status only meaningful when Result=0x0001 (pending); 0x0000-0x0002 defined
        if result == 0x0001 and status > 0x0002:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "l2cap",
                f"L2CAP ConnRsp Status 0x{status:04x} outside valid range for pending result",
                evidence=response[:12].hex(),
                score=5.0,
            ))

    # Configuration Response (0x05): validate option type/length pairs
    if code == 0x05 and len(data) >= 6:
        # ConfRsp: SCID(2) + Flags(2) + Result(2) + Options...
        conf_result = struct.unpack("<H", data[4:6])[0]
        if conf_result > 0x0004:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "l2cap",
                f"L2CAP ConfRsp Result 0x{conf_result:04x} outside valid range (0x0000-0x0004)",
                evidence=response[:12].hex(),
                score=6.0,
            ))
        # Parse option TLVs after the 6-byte fixed portion
        opt_offset = 6
        while opt_offset + 2 <= len(data):
            opt_type = data[opt_offset]
            opt_len = data[opt_offset + 1]
            opt_offset += 2
            if opt_len > len(data) - opt_offset:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "high", "l2cap",
                    f"L2CAP ConfRsp option type 0x{opt_type:02x} declares length {opt_len} "
                    f"but only {len(data) - opt_offset} bytes remain",
                    evidence=response[:16].hex(),
                    score=7.0,
                ))
                break
            opt_offset += opt_len

    return anomalies


def _validate_rfcomm_structure(response: bytes) -> list[Anomaly]:
    """Check RFCOMM frame consistency.

    RFCOMM frame: Address(1) + Control(1) + Length(1-2) + [data] + FCS(1)
    The length field indicates the information payload size.
    """
    anomalies = []
    if len(response) < 3:
        return anomalies

    # Length field: bit 0 of the length byte determines format
    # If bit 0 == 1: 7-bit length (single byte), shift right by 1
    # If bit 0 == 0: 15-bit length (two bytes)
    length_byte = response[2]
    if length_byte & 0x01:
        info_len = length_byte >> 1
        header_size = 3
    else:
        if len(response) < 4:
            return anomalies
        info_len = (response[3] << 7) | (length_byte >> 1)
        header_size = 4

    # Expected total: header + info + FCS(1)
    expected_total = header_size + info_len + 1
    if len(response) != expected_total and abs(len(response) - expected_total) > 1:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "medium", "rfcomm",
            f"RFCOMM frame length mismatch: declares {info_len} info bytes, "
            f"expected {expected_total} total, got {len(response)}",
            evidence=response[:8].hex(),
            score=6.0,
        ))

    # --- Enhanced checks (Task 3.2.4) ---

    # FCS validation
    if len(response) >= expected_total and expected_total >= (header_size + 1):
        actual_fcs = response[-1]
        # FCS is computed over Address + Control (+ Length for UIH frames)
        control = response[1]
        # For SABM/DISC/UA/DM, FCS covers Address + Control + Length
        # For UIH (0xEF/0xFF), FCS covers only Address + Control
        if (control & 0xEF) == 0xEF:
            fcs_bytes = response[0:2]  # Address + Control only for UIH
        else:
            fcs_bytes = response[0:header_size]
        expected_fcs = _rfcomm_fcs(fcs_bytes)
        if actual_fcs != expected_fcs:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "high", "rfcomm",
                f"RFCOMM FCS mismatch: got 0x{actual_fcs:02x}, expected 0x{expected_fcs:02x} "
                f"(possible corruption)",
                evidence=response[:8].hex() + f"...fcs={response[-1]:02x}",
                score=7.0,
            ))

    # DLCI 0 = control channel: must only carry multiplexer commands
    address = response[0]
    dlci = (address >> 2) & 0x3F
    control = response[1]
    if dlci == 0 and (control & 0xEF) == 0xEF and info_len > 0:
        # UIH on DLCI 0 = multiplexer command. First byte of info is
        # the MCC type. Valid types: 0x20(PN), 0x24(PSC), 0x38(CLD),
        # 0x08(Test), 0x28(FCoff), 0x18(FCon), 0x38(MSC), 0x14(NSC),
        # 0x24(RPN), 0x04(RLS), 0x10(SNC)
        info_start = header_size
        if info_start < len(response) - 1:
            mcc_type = response[info_start] & 0xFC  # Strip EA+CR bits
            valid_mcc = {0x20, 0x24, 0x38, 0x08, 0x28, 0x18, 0x14, 0x04, 0x10, 0x00}
            if mcc_type not in valid_mcc:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "rfcomm",
                    f"RFCOMM DLCI 0 (control channel) has unknown MCC type 0x{mcc_type:02x}",
                    evidence=response[:min(12, len(response))].hex(),
                    score=5.0,
                ))

    return anomalies


# RFCOMM FCS lookup table (ITU-T V.42 / GSM 07.10)
_RFCOMM_FCS_TABLE = [
    0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75,
    0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
    0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,
    0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
    0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D,
    0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
    0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51,
    0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,
    0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
    0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
    0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19,
    0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
    0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D,
    0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
    0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,
    0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,
    0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95,
    0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
    0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89,
    0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
    0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,
    0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
    0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1,
    0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
    0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5,
    0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
    0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,
    0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
    0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD,
    0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
    0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,
    0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF,
]


def _rfcomm_fcs(data: bytes) -> int:
    """Compute RFCOMM Frame Check Sequence (reversed CRC-8)."""
    fcs = 0xFF
    for b in data:
        fcs = _RFCOMM_FCS_TABLE[fcs ^ b]
    return 0xFF - fcs


def _validate_smp_structure(response: bytes) -> list[Anomaly]:
    """Check SMP (Security Manager Protocol) PDU consistency.

    SMP Code (byte 0) identifies the PDU type.  Each type has a fixed
    expected length per the BT Core Spec.
    """
    anomalies: list[Anomaly] = []
    if not response:
        return anomalies

    code = response[0]

    # Valid SMP codes: 0x01-0x0E
    if code == 0x00 or code > 0x0E:
        anomalies.append(Anomaly(
            AnomalyType.UNEXPECTED_OPCODE, "medium", "ble-smp",
            f"SMP code 0x{code:02x} is outside defined range (0x01-0x0E)",
            evidence=response[:8].hex(),
            score=6.0,
        ))
        return anomalies

    # Expected lengths per SMP code (total PDU including code byte)
    _SMP_EXPECTED_LENGTHS: dict[int, int] = {
        0x01: 7,   # Pairing Request
        0x02: 7,   # Pairing Response
        0x03: 17,  # Pairing Confirm
        0x04: 17,  # Pairing Random
        0x05: 2,   # Pairing Failed
        0x0C: 65,  # Pairing Public Key
        0x0D: 17,  # Pairing DHKey Check
    }

    expected_len = _SMP_EXPECTED_LENGTHS.get(code)
    if expected_len is not None and len(response) != expected_len:
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "high", "ble-smp",
            f"SMP code 0x{code:02x} should be {expected_len} bytes, got {len(response)}",
            evidence=response[:min(16, len(response))].hex(),
            score=7.0,
        ))

    # Pairing Failed (0x05): reason code must be in 0x01-0x0E
    if code == 0x05 and len(response) >= 2:
        reason = response[1]
        if reason == 0x00 or reason > 0x0E:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "ble-smp",
                f"SMP Pairing Failed reason 0x{reason:02x} outside defined range (0x01-0x0E)",
                evidence=response[:4].hex(),
                score=5.0,
            ))

    return anomalies


def _validate_obex_structure(response: bytes) -> list[Anomaly]:
    """Check OBEX response PDU consistency.

    OBEX response: ResponseCode(1) + PacketLength(2 BE) + [headers...]
    The PacketLength must match the actual response length.
    """
    anomalies: list[Anomaly] = []
    if len(response) < 3:
        if len(response) > 0:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "obex",
                f"OBEX response too short ({len(response)} bytes, need at least 3)",
                evidence=response.hex(),
                score=5.0,
            ))
        return anomalies

    resp_code = response[0]
    packet_len = struct.unpack(">H", response[1:3])[0]

    # Valid OBEX response codes (high bit set = final response)
    _VALID_OBEX_CODES = {
        0x10,  # Continue (non-final)
        0x90,  # Continue (final)
        0x20, 0xA0,  # Success
        0x21, 0xA1,  # Created
        0x22, 0xA2,  # Accepted
        0x40, 0xC0,  # Bad Request
        0x41, 0xC1,  # Unauthorized
        0x43, 0xC3,  # Forbidden
        0x44, 0xC4,  # Not Found
        0x45, 0xC5,  # Method Not Allowed
        0x46, 0xC6,  # Not Acceptable
        0x4D, 0xCD,  # Request Entity Too Large
        0x50, 0xD0,  # Internal Server Error
        0x51, 0xD1,  # Not Implemented
        0x60, 0xE0,  # Database Full
        0x61, 0xE1,  # Database Locked
    }
    if resp_code not in _VALID_OBEX_CODES:
        anomalies.append(Anomaly(
            AnomalyType.UNEXPECTED_OPCODE, "medium", "obex",
            f"OBEX response code 0x{resp_code:02x} is not a recognized response code",
            evidence=response[:8].hex(),
            score=5.0,
        ))

    # Packet length must match actual
    if packet_len != len(response):
        anomalies.append(Anomaly(
            AnomalyType.LENGTH_MISMATCH, "high", "obex",
            f"OBEX PacketLength declares {packet_len} but actual is {len(response)} bytes",
            evidence=f"header={response[:3].hex()} full_len={len(response)}",
            score=8.0,
        ))

    # Parse OBEX headers (start at offset 3)
    offset = 3
    while offset < len(response):
        if offset >= len(response):
            break
        hdr_id = response[offset]
        hdr_type = (hdr_id >> 6) & 0x03
        offset += 1

        if hdr_type in (0x00, 0x01):
            # Unicode string or byte sequence: 2-byte length follows (includes hdr_id + length)
            if offset + 2 > len(response):
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "high", "obex",
                    f"OBEX header 0x{hdr_id:02x} truncated (no length field)",
                    evidence=response[max(0, offset - 2):offset + 4].hex(),
                    score=7.0,
                ))
                break
            hdr_len = struct.unpack(">H", response[offset:offset + 2])[0]
            offset += 2
            # hdr_len includes the header ID byte and the 2-byte length field
            body_len = hdr_len - 3
            if body_len < 0 or body_len > len(response) - offset:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "high", "obex",
                    f"OBEX header 0x{hdr_id:02x} declares body length {body_len} "
                    f"but only {len(response) - offset} bytes remain",
                    evidence=response[max(0, offset - 3):offset + min(8, max(body_len, 0))].hex(),
                    score=7.0,
                ))
                break
            offset += body_len
        elif hdr_type == 0x02:
            # 1-byte value
            if offset >= len(response):
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "obex",
                    f"OBEX 1-byte header 0x{hdr_id:02x} truncated",
                    evidence=response[max(0, offset - 2):].hex(),
                    score=5.0,
                ))
                break
            offset += 1
        elif hdr_type == 0x03:
            # 4-byte value
            if offset + 4 > len(response):
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "obex",
                    f"OBEX 4-byte header 0x{hdr_id:02x} truncated",
                    evidence=response[max(0, offset - 2):].hex(),
                    score=5.0,
                ))
                break
            offset += 4

    return anomalies


def _validate_bnep_structure(response: bytes) -> list[Anomaly]:
    """Check BNEP (Bluetooth Network Encapsulation Protocol) PDU consistency.

    BNEP header: Type(1) where bits 0-6 = packet type, bit 7 = extension flag.
    """
    anomalies: list[Anomaly] = []
    if not response:
        return anomalies

    type_byte = response[0]
    pkt_type = type_byte & 0x7F
    _has_extension = bool(type_byte & 0x80)  # parsed but not validated yet

    # Valid BNEP types: 0x00 (General Ethernet), 0x01 (Control),
    # 0x02 (Compressed Ethernet), 0x03 (Compressed Src Only),
    # 0x04 (Compressed Dst Only)
    if pkt_type > 0x04:
        anomalies.append(Anomaly(
            AnomalyType.UNEXPECTED_OPCODE, "medium", "bnep",
            f"BNEP type 0x{pkt_type:02x} outside valid range (0x00-0x04)",
            evidence=response[:8].hex(),
            score=5.0,
        ))

    # Control type validation (type=0x01)
    if pkt_type == 0x01 and len(response) >= 2:
        control_type = response[1]
        # Valid control types: 0x00 (Command Not Understood),
        # 0x01 (Setup Connection Req), 0x02 (Setup Connection Rsp),
        # 0x03 (Filter Net Type Set), 0x04 (Filter Net Type Rsp),
        # Others are reserved
        if control_type > 0x04:
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "medium", "bnep",
                f"BNEP control type 0x{control_type:02x} outside valid range (0x00-0x04)",
                evidence=response[:8].hex(),
                score=5.0,
            ))

        # Setup Connection Response (control_type=0x02): must be 4 bytes total
        # Type(1) + ControlType(1) + ResponseMessage(2)
        if control_type == 0x02:
            if len(response) < 4:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "bnep",
                    f"BNEP Setup Connection Rsp too short ({len(response)} bytes, need 4)",
                    evidence=response.hex(),
                    score=5.0,
                ))
            elif len(response) >= 4:
                rsp_msg = struct.unpack(">H", response[2:4])[0]
                # Response codes: 0x0000 (success), 0x0001 (not allowed),
                # 0x0002 (invalid service), 0x0003 (insufficient security)
                if rsp_msg > 0x0003:
                    anomalies.append(Anomaly(
                        AnomalyType.STRUCTURAL, "medium", "bnep",
                        f"BNEP Setup Connection Rsp code 0x{rsp_msg:04x} outside "
                        f"valid range (0x0000-0x0003)",
                        evidence=response[:6].hex(),
                        score=5.0,
                    ))

    return anomalies


def _validate_at_structure(response: bytes) -> list[Anomaly]:
    """Check AT command response consistency.

    AT responses are text-based.  They must end with \\r\\n, and must
    contain at least one complete line.  Binary data in text fields is
    anomalous and may indicate a memory leak.
    """
    anomalies: list[Anomaly] = []
    if not response:
        return anomalies

    # Try decoding as ASCII/UTF-8
    try:
        text = response.decode("utf-8", errors="replace")
    except Exception:
        text = response.decode("latin-1", errors="replace")

    # Check for binary content in what should be text
    non_printable = sum(
        1 for b in response
        if b < 0x20 and b not in (0x0A, 0x0D, 0x09)  # Allow LF, CR, TAB
    )
    if non_printable > 0 and len(response) > 2:
        ratio = non_printable / len(response)
        if ratio > 0.1:
            anomalies.append(Anomaly(
                AnomalyType.LEAK_INDICATOR, "high", "at",
                f"AT response contains {non_printable} non-printable bytes "
                f"({ratio:.0%}) — possible binary data leak in text protocol",
                evidence=response[:32].hex(),
                score=7.0,
            ))

    # Must end with \r\n
    if not text.rstrip("\x00").endswith("\r\n"):
        anomalies.append(Anomaly(
            AnomalyType.STRUCTURAL, "medium", "at",
            "AT response does not end with \\r\\n",
            evidence=repr(text[-20:]) if len(text) > 20 else repr(text),
            score=4.0,
        ))

    # Must contain at least one complete line
    lines = text.strip().split("\r\n")
    if not lines or all(not line.strip() for line in lines):
        anomalies.append(Anomaly(
            AnomalyType.STRUCTURAL, "medium", "at",
            "AT response contains no complete lines",
            evidence=repr(text[:40]),
            score=4.0,
        ))
        return anomalies

    # Check for +CME ERROR: N — N must be numeric
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith("+CME ERROR:"):
            error_part = line_stripped[len("+CME ERROR:"):].strip()
            if error_part and not error_part.isdigit():
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "medium", "at",
                    f"+CME ERROR code is not numeric: {error_part!r}",
                    evidence=repr(line_stripped),
                    score=5.0,
                ))

    # Check terminal response presence (OK, ERROR, +CME ERROR, +CMS ERROR)
    terminal_patterns = ("OK", "ERROR", "+CME ERROR:", "+CMS ERROR:")
    _has_terminal = any(
        line.strip().startswith(p) or line.strip() == p.rstrip(":")
        for line in lines
        for p in terminal_patterns
    )
    # Informational lines ("+XXX:") should have a colon separator
    for line in lines:
        ls = line.strip()
        if ls.startswith("+") and ":" not in ls and ls not in ("", "+"):
            # This could be a malformed informational line
            anomalies.append(Anomaly(
                AnomalyType.STRUCTURAL, "low", "at",
                f"AT informational line missing ':' separator: {ls!r}",
                evidence=repr(ls),
                score=2.0,
            ))

    return anomalies


def _validate_lmp_structure(response: bytes) -> list[Anomaly]:
    """Parse LMP response opcode and extract structured anomaly signals.

    LMP PDU wire format: byte 0 = (opcode << 1) | tid (over-the-air encoding).
    DarkFirmware strips the TID-shift so bytes arriving here are raw:
      byte 0 = opcode (lower 7 bits)

    Well-known response opcodes and their significance:
      LMP_ACCEPTED      (3)  — normal acknowledgement, low signal
      LMP_NOT_ACCEPTED  (4)  — rejection: byte 1 = rejected opcode, byte 2 = reason
      LMP_DETACH        (7)  — link termination: byte 1 = error code; HIGH SIGNAL
      LMP_FEATURES_RES  (40) — feature bitmask in bytes 1-8
    """
    if len(response) == 0:
        return []

    anomalies: list[Anomaly] = []
    opcode = response[0] & 0x7F  # mask TID bit just in case

    if opcode == 7:  # LMP_DETACH
        reason = response[1] if len(response) > 1 else 0x00
        anomalies.append(Anomaly(
            AnomalyType.BEHAVIORAL, "critical", "lmp",
            f"LMP_DETACH received — remote disconnected (reason=0x{reason:02x}); "
            f"possible crash, state corruption, or security rejection",
            evidence=response.hex(),
            score=9.0,
        ))

    elif opcode == 4:  # LMP_NOT_ACCEPTED
        rejected_opcode = response[1] if len(response) > 1 else 0x00
        reason = response[2] if len(response) > 2 else 0x00
        # NOT_ACCEPTED is medium signal — novel (rejected_opcode, reason) pairs
        # indicate new code paths being exercised on the target.
        anomalies.append(Anomaly(
            AnomalyType.BEHAVIORAL, "medium", "lmp",
            f"LMP_NOT_ACCEPTED for opcode 0x{rejected_opcode:02x} "
            f"(reason=0x{reason:02x})",
            evidence=response.hex(),
            # Score varies by reason code: 0x06 = "Command Disallowed" in wrong state
            score=5.0 if reason in (0x06, 0x12) else 3.5,
        ))

    elif opcode == 3:  # LMP_ACCEPTED
        accepted_opcode = response[1] if len(response) > 1 else 0x00
        # Accepted is low signal unless the accepted opcode is security-critical
        # (encryption, auth, key exchange).
        _security_opcodes = {0x10, 0x11, 0x12, 0x13, 0x17, 0x18, 0x19, 0x1A}
        if accepted_opcode in _security_opcodes:
            anomalies.append(Anomaly(
                AnomalyType.BEHAVIORAL, "low", "lmp",
                f"LMP_ACCEPTED for security-critical opcode 0x{accepted_opcode:02x} "
                f"— target entered security negotiation path",
                evidence=response.hex(),
                score=4.0,
            ))

    return anomalies


# Map protocol names to validators
_STRUCTURAL_VALIDATORS: dict[str, type[list]] = {
    "sdp": _validate_sdp_structure,
    "ble-att": _validate_att_structure,
    "l2cap": _validate_l2cap_structure,
    "l2cap-sig": _validate_l2cap_structure,
    "rfcomm": _validate_rfcomm_structure,
    "ble-smp": _validate_smp_structure,
    "obex-pbap": _validate_obex_structure,
    "obex-map": _validate_obex_structure,
    "obex-opp": _validate_obex_structure,
    "bnep": _validate_bnep_structure,
    "at-hfp": _validate_at_structure,
    "at-phonebook": _validate_at_structure,
    "at-sms": _validate_at_structure,
    "at-injection": _validate_at_structure,
    "lmp": _validate_lmp_structure,
}


# ---------------------------------------------------------------------------
# Leak / info disclosure heuristics
# ---------------------------------------------------------------------------

def _check_leak_indicators(
    protocol: str,
    request: bytes,
    response: bytes,
    baseline: ProtocolBaseline | None,
) -> list[Anomaly]:
    """Detect potential information leaks via weighted composite scoring.

    Phase 5 enhanced version: combines seven signals into a weighted
    composite score, with per-protocol entropy baselines and confidence
    levels.

    Signal weights (sum = 1.0):
    - Entropy deviation from protocol-specific baseline:  0.25
    - Sliding window max entropy spike:                   0.20
    - Response size deviation:                            0.15
    - Null byte ratio:                                    0.10
    - Request echo detection:                             0.10
    - Heap pattern detection:                             0.10
    - Renyi entropy deviation:                            0.10

    Confidence levels based on composite score:
    - 0-3:   "normal"
    - 3-5:   "suspicious"
    - 5-7:   "likely_leak"
    - 7+:    "high_confidence_leak"
    """
    anomalies: list[Anomaly] = []
    if not response or len(response) < 4:
        return anomalies

    header_len = min(5, len(response))
    body = response[header_len:]

    # -- Collect individual signal scores (each 0-10 range) --
    signal_entropy_dev = 0.0
    signal_window_spike = 0.0
    signal_size_dev = 0.0
    signal_null_ratio = 0.0
    signal_echo = 0.0
    signal_heap = 0.0
    signal_renyi = 0.0

    evidence_parts: list[str] = []

    # --- 1. Entropy deviation from protocol-specific baseline (weight 0.25) ---
    if len(body) >= 16:
        entropy = _byte_entropy(body)
        expected = _EXPECTED_ENTROPY.get(protocol, (2.0, 6.0))
        if entropy > expected[1]:
            deviation = entropy - expected[1]
            signal_entropy_dev = min(deviation * 3.0, 10.0)
            evidence_parts.append(
                f"shannon={entropy:.2f} (expected {expected[0]:.1f}-{expected[1]:.1f})"
            )
        elif entropy < expected[0] * 0.5:
            # Extremely low entropy can also be suspicious (all zeros, etc.)
            signal_entropy_dev = min((expected[0] - entropy) * 2.0, 5.0)

    # --- 2. Sliding window max entropy spike (weight 0.20) ---
    if len(body) >= 16:
        max_e, mean_e, var_e = _sliding_window_entropy(body)
        # A localized spike is more suspicious than uniformly high entropy
        if max_e > 6.5 and var_e > 1.0:
            signal_window_spike = min((max_e - 5.0) * 2.0, 10.0)
            evidence_parts.append(
                f"window_max={max_e:.2f} mean={mean_e:.2f} var={var_e:.2f}"
            )
        elif max_e > 7.0:
            signal_window_spike = min((max_e - 5.0) * 1.5, 10.0)
            evidence_parts.append(f"window_max={max_e:.2f}")

    # --- 3. Response size deviation (weight 0.15) ---
    if baseline and baseline.max_len > 0:
        overshoot = len(response) / max(baseline.max_len, 1)
        if overshoot > 1.5:
            signal_size_dev = min((overshoot - 1.0) * 4.0, 10.0)
            evidence_parts.append(
                f"size={len(response)}B ({overshoot:.1f}x baseline max {baseline.max_len})"
            )

    # --- 4. Null byte ratio (weight 0.10) ---
    if len(body) >= 16:
        null_ratio = body.count(0x00) / len(body)
        if null_ratio > 0.7 and len(body) > 32:
            signal_null_ratio = min(null_ratio * 10.0, 10.0)
            evidence_parts.append(f"null_ratio={null_ratio:.0%}")

    # --- 5. Request echo detection (weight 0.10) ---
    if len(request) >= 4 and len(response) >= 8:
        req_fragment = request[2:min(8, len(request))]
        if len(req_fragment) >= 4:
            pos = response[4:].find(req_fragment)
            if pos >= 0:
                signal_echo = 6.0
                evidence_parts.append(
                    f"echo={len(req_fragment)}B@offset{pos + 4}"
                )

    # --- 6. Heap pattern detection (weight 0.10) ---
    if len(body) >= 4:
        heap_hits = _detect_heap_patterns(body)
        if heap_hits:
            # More hits = higher confidence; cap at 10
            signal_heap = min(len(heap_hits) * 3.0, 10.0)
            first_hits = heap_hits[:3]
            evidence_parts.append(
                f"heap_patterns={len(heap_hits)} [{', '.join(h[1] for h in first_hits)}]"
            )

    # --- 7. Renyi entropy deviation (weight 0.10) ---
    if len(body) >= 16:
        renyi = _renyi_entropy(body, order=2.0)
        expected = _EXPECTED_ENTROPY.get(protocol, (2.0, 6.0))
        if renyi > expected[1]:
            deviation = renyi - expected[1]
            signal_renyi = min(deviation * 3.0, 10.0)
            evidence_parts.append(f"renyi2={renyi:.2f}")

    # -- Weighted composite score --
    composite = (
        signal_entropy_dev * 0.25
        + signal_window_spike * 0.20
        + signal_size_dev * 0.15
        + signal_null_ratio * 0.10
        + signal_echo * 0.10
        + signal_heap * 0.10
        + signal_renyi * 0.10
    )

    # -- Confidence level --
    if composite >= 7.0:
        confidence = "high_confidence_leak"
        severity = "critical"
    elif composite >= 5.0:
        confidence = "likely_leak"
        severity = "high"
    elif composite >= 3.0:
        confidence = "suspicious"
        severity = "medium"
    else:
        confidence = "normal"
        severity = "low"

    # -- Emit anomalies --

    # Always emit the composite result if above "normal"
    if composite >= 3.0:
        anomalies.append(Anomaly(
            AnomalyType.LEAK_INDICATOR, severity, protocol,
            f"Leak composite score {composite:.2f} ({confidence}): "
            + "; ".join(evidence_parts[:5]),
            evidence=f"first_32={response[:32].hex()}",
            score=composite,
        ))

    # Additionally emit specific high-signal anomalies for backward compat
    # and detailed triage:

    if signal_size_dev > 0 and baseline and baseline.max_len > 0:
        overshoot = len(response) / max(baseline.max_len, 1)
        anomalies.append(Anomaly(
            AnomalyType.LEAK_INDICATOR, "high" if overshoot > 2.0 else "medium", protocol,
            f"Response is {overshoot:.1f}x larger than any baseline response "
            f"({len(response)} vs max {baseline.max_len})",
            evidence=f"first_32={response[:32].hex()}",
            score=signal_size_dev,
        ))

    if signal_echo > 0 and len(request) >= 4 and len(response) >= 8:
        req_fragment = request[2:min(8, len(request))]
        pos = response[4:].find(req_fragment)
        if pos >= 0:
            anomalies.append(Anomaly(
                AnomalyType.LEAK_INDICATOR, "medium", protocol,
                f"Response echoes {len(req_fragment)} request bytes at offset {pos + 4} "
                f"(possible buffer reuse)",
                evidence=(
                    f"req={request[:12].hex()} "
                    f"rsp_at_pos={response[pos+4:pos+4+len(req_fragment)].hex()}"
                ),
                score=signal_echo,
            ))

    if signal_entropy_dev >= 5.0 and len(body) >= 16:
        entropy = _byte_entropy(body)
        anomalies.append(Anomaly(
            AnomalyType.LEAK_INDICATOR, "high", protocol,
            f"Response body has high entropy ({entropy:.2f} bits/byte) — "
            f"possible heap data disclosure",
            evidence=f"body_hex={body[:32].hex()} entropy={entropy:.2f}",
            score=signal_entropy_dev,
        ))

    if signal_null_ratio >= 5.0 and len(body) >= 16:
        null_ratio = body.count(0x00) / len(body)
        anomalies.append(Anomaly(
            AnomalyType.LEAK_INDICATOR, "medium", protocol,
            f"Response body is {null_ratio:.0%} null bytes ({len(body)}B) — "
            f"possible uninitialized memory",
            evidence=f"body_hex={body[:32].hex()}",
            score=signal_null_ratio,
        ))

    if signal_heap >= 5.0 and len(body) >= 4:
        heap_hits = _detect_heap_patterns(body)
        anomalies.append(Anomaly(
            AnomalyType.LEAK_INDICATOR, "high", protocol,
            f"Heap/allocator patterns detected ({len(heap_hits)} hits): "
            + ", ".join(h[1] for h in heap_hits[:3]),
            evidence=f"body_hex={body[:32].hex()}",
            score=signal_heap,
        ))

    return anomalies


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Phase 5: Enhanced entropy and leak detection
# ---------------------------------------------------------------------------

# Per-protocol expected entropy ranges (bits/byte): (low, high)
_EXPECTED_ENTROPY: dict[str, tuple[float, float]] = {
    "sdp": (2.0, 4.5),
    "ble-att": (3.0, 5.5),
    "l2cap": (2.0, 4.5),
    "l2cap-sig": (2.0, 4.5),
    "rfcomm": (3.0, 6.5),
    "ble-smp": (3.0, 5.0),
    "obex-pbap": (3.0, 6.0),
    "obex-map": (3.0, 6.0),
    "bnep": (3.5, 7.0),
    "at-hfp": (2.0, 4.0),
}


def _sliding_window_entropy(
    data: bytes, window_size: int = 16,
) -> tuple[float, float, float]:
    """Compute Shannon entropy in sliding windows over *data*.

    Returns ``(max_entropy, mean_entropy, variance)`` across all windows.
    A single high-entropy window surrounded by low-entropy data is more
    suspicious than uniformly high entropy (which could just be compressed
    or encrypted content).
    """
    if len(data) < window_size:
        e = _byte_entropy(data)
        return (e, e, 0.0)

    entropies: list[float] = []
    for start in range(0, len(data) - window_size + 1, max(window_size // 2, 1)):
        window = data[start : start + window_size]
        entropies.append(_byte_entropy(window))

    if not entropies:
        return (0.0, 0.0, 0.0)

    max_e = max(entropies)
    mean_e = sum(entropies) / len(entropies)
    variance = (
        sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
        if len(entropies) > 1
        else 0.0
    )
    return (max_e, mean_e, variance)


def _renyi_entropy(data: bytes, order: float = 2.0) -> float:
    """Renyi entropy of the given *order* (default 2, a.k.a. collision entropy).

    H_alpha = (1 / (1 - alpha)) * log2(sum(p_i^alpha))

    Renyi entropy of order 2 is more sensitive to dominant byte values
    than Shannon entropy, making it useful for detecting partial leaks
    where most bytes are structured but some are leaked heap data.
    """
    if not data or order == 1.0:
        # order == 1.0 reduces to Shannon entropy
        return _byte_entropy(data)

    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    if n == 0:
        return 0.0

    sum_p_alpha = sum((count / n) ** order for count in freq if count > 0)
    if sum_p_alpha <= 0.0:
        return 0.0

    return (1.0 / (1.0 - order)) * math.log2(sum_p_alpha)


# Well-known heap/allocator sentinel patterns
_HEAP_SENTINELS: list[tuple[bytes, str]] = [
    (b"\xDE\xAD\xBE\xEF", "DEADBEEF (freed memory marker)"),
    (b"\xBA\xAD\xF0\x0D", "BAADF00D (uninitialized heap — Windows)"),
    (b"\xFE\xED\xFA\xCE", "FEEDFACE (Mach-O magic / debug sentinel)"),
    (b"\xAB\xAB\xAB\xAB", "ABABABAB (HeapAlloc guard — Windows)"),
    (b"\xFD\xFD\xFD\xFD", "FDFDFDFD (heap guard bytes — Windows debug)"),
    (b"\xCD\xCD\xCD\xCD", "CDCDCDCD (uninitialized heap — MSVC debug)"),
    (b"\x41\x41\x41\x41", "41414141 (classic spray pattern 'AAAA')"),
]


def _detect_heap_patterns(data: bytes) -> list[tuple[int, str]]:
    """Scan *data* for heap/allocator artefacts.

    Returns a list of ``(offset, description)`` for each match.

    Checks:
    1. Known sentinel values (DEADBEEF, BAADF00D, etc.)
    2. Repeated 4-byte patterns (common in freed-chunk metadata)
    3. Pointer-like values in the 0x08000000 - 0x7FFFFFFF range
       (typical userspace heap addresses on 32-bit / lower-half 64-bit)
    """
    hits: list[tuple[int, str]] = []
    if len(data) < 4:
        return hits

    # 1. Known sentinels
    for sentinel, desc in _HEAP_SENTINELS:
        offset = 0
        while True:
            pos = data.find(sentinel, offset)
            if pos < 0:
                break
            hits.append((pos, desc))
            offset = pos + 1

    # 2. Repeated 4-byte patterns (at least 3 consecutive repeats = 12 bytes)
    seen_patterns: set[bytes] = set()
    for i in range(0, len(data) - 11):
        pat = data[i : i + 4]
        if pat in seen_patterns:
            continue
        # Check for 3 consecutive repetitions
        if data[i + 4 : i + 8] == pat and data[i + 8 : i + 12] == pat:
            # Exclude all-zero (null padding) and common single-byte fills
            # already covered by sentinels
            if pat != b"\x00\x00\x00\x00":
                seen_patterns.add(pat)
                hits.append((i, f"repeated 4-byte pattern {pat.hex()} (x3+)"))

    # 3. Pointer-like values (0x08000000 - 0x7FFFFFFF, little-endian)
    for i in range(0, len(data) - 3):
        val = struct.unpack_from("<I", data, i)[0]
        if 0x08000000 <= val <= 0x7FFFFFFF:
            # Only flag if not already covered by a sentinel or repeat hit
            # and the surrounding context doesn't look like a normal counter
            if i % 4 == 0:  # aligned reads are more likely real pointers
                hits.append((i, f"pointer-like value 0x{val:08x}"))
                # Skip ahead to avoid flooding on consecutive pointer-like values
                # (we'll record at most one per 8-byte stride)
                # Break if we already have plenty of evidence
                if len(hits) > 32:
                    break

    return hits


@dataclass
class CausalMap:
    """Maps input byte indices to the set of response byte indices they affect.

    Built by systematically deleting individual input bytes and observing
    which response bytes change.  This reveals which parts of the input the
    parser actually reads, enabling mutation focus on high-impact bytes.
    """
    map: dict[int, set[int]] = field(default_factory=dict)

    def record(self, input_byte: int, affected_response_bytes: set[int]) -> None:
        """Record that mutating *input_byte* caused *affected_response_bytes* to change."""
        self.map.setdefault(input_byte, set()).update(affected_response_bytes)

    def high_impact_bytes(self) -> list[int]:
        """Return input byte indices sorted by decreasing impact (most affected response bytes)."""
        return sorted(self.map.keys(), key=lambda k: len(self.map[k]), reverse=True)

    def dead_bytes(self) -> list[int]:
        """Return input byte indices with zero causal effect on the response."""
        if not self.map:
            return []
        all_indices = set(range(max(self.map.keys()) + 1))
        live = {k for k, v in self.map.items() if len(v) > 0}
        return sorted(all_indices - live)

    def to_dict(self) -> dict[str, list[int]]:
        """Serialize to JSON-safe dict (keys as strings, sets as sorted lists)."""
        return {str(k): sorted(v) for k, v in self.map.items()}

    @classmethod
    def from_dict(cls, data: dict[str, list[int]]) -> CausalMap:
        """Deserialize from the format produced by ``to_dict()``."""
        cm = cls()
        for k, v in data.items():
            cm.map[int(k)] = set(v)
        return cm


def differential_compare(
    baseline_response: bytes, fuzzed_response: bytes,
) -> dict:
    """Byte-level comparison between *baseline_response* and *fuzzed_response*.

    Returns a dict with:
    - ``changed_bytes``: list of ``(index, old, new)`` for bytes present in both
    - ``added_bytes``: count of bytes in fuzzed but beyond baseline length
    - ``removed_bytes``: count of bytes in baseline but beyond fuzzed length
    - ``change_ratio``: fraction of overlapping bytes that differ
    """
    min_len = min(len(baseline_response), len(fuzzed_response))
    changed: list[tuple[int, int, int]] = []

    for i in range(min_len):
        if baseline_response[i] != fuzzed_response[i]:
            changed.append((i, baseline_response[i], fuzzed_response[i]))

    added = max(0, len(fuzzed_response) - len(baseline_response))
    removed = max(0, len(baseline_response) - len(fuzzed_response))
    change_ratio = len(changed) / min_len if min_len > 0 else 0.0

    return {
        "changed_bytes": changed,
        "added_bytes": added,
        "removed_bytes": removed,
        "change_ratio": change_ratio,
    }


# ---------------------------------------------------------------------------
# Timing cluster detection (Phase 4)
# ---------------------------------------------------------------------------

@dataclass
class TimingCluster:
    """A cluster of latency observations around a center point.

    Each cluster represents a likely different code path in the target.
    """
    center_ms: float
    count: int
    min_ms: float
    max_ms: float

    def update(self, latency_ms: float) -> None:
        """Add a new observation to this cluster (running mean)."""
        self.center_ms = (self.center_ms * self.count + latency_ms) / (self.count + 1)
        self.count += 1
        self.min_ms = min(self.min_ms, latency_ms)
        self.max_ms = max(self.max_ms, latency_ms)

    def contains(self, latency_ms: float, radius_ms: float = 5.0) -> bool:
        """Check whether *latency_ms* falls within *radius_ms* of the center."""
        return abs(latency_ms - self.center_ms) <= radius_ms


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class ResponseAnalyzer:
    """Black-box response anomaly detector.

    Usage in campaign engine::

        analyzer = ResponseAnalyzer()

        # Learning phase (before fuzzing starts)
        for valid_request, valid_response, latency in baseline_pairs:
            analyzer.record_baseline(protocol, valid_response, latency)
        analyzer.finalize_baselines()

        # Fuzzing phase
        anomalies = analyzer.analyze(protocol, request, response, latency_ms)
        for a in anomalies:
            if a.score >= 5.0:
                corpus.save_interesting(protocol, request, f"anomaly_{a.anomaly_type.value}")
    """

    def __init__(self) -> None:
        self._baselines: dict[str, ProtocolBaseline] = {}
        self._consecutive_timeouts: dict[str, int] = {}
        self._consecutive_errors: dict[str, int] = {}
        # Phase 4: Timing cluster tracking
        self._timing_clusters: dict[str, list[TimingCluster]] = {}
        self._consecutive_spikes: dict[str, int] = {}
        # Phase 3 (Task 3.3): Cross-protocol heuristic state
        self._recent_response_codes: dict[str, collections.deque] = {}
        self._recent_response_sizes: dict[str, collections.deque] = {}

    # -- Timing cluster management -----------------------------------------

    def _update_timing_clusters(
        self, protocol: str, latency_ms: float,
    ) -> bool:
        """Update timing clusters for *protocol* with a new observation.

        Returns ``True`` when a **new** cluster is created, which signals
        that the target likely took a previously-unseen code path.
        """
        clusters = self._timing_clusters.setdefault(protocol, [])

        # Try to find an existing cluster within 5ms of this observation
        for cluster in clusters:
            if cluster.contains(latency_ms, radius_ms=5.0):
                cluster.update(latency_ms)
                return False

        # No existing cluster matches — create a new one
        clusters.append(TimingCluster(
            center_ms=latency_ms,
            count=1,
            min_ms=latency_ms,
            max_ms=latency_ms,
        ))
        return True

    @staticmethod
    def _opcode_p99(baseline: ProtocolBaseline, opcode: int) -> float:
        """Return p99 latency for *opcode*, falling back to global p99."""
        latencies = baseline.opcode_latency.get(opcode)
        if latencies and len(latencies) >= 3:
            s = sorted(latencies)
            return s[int(0.99 * (len(s) - 1))]
        return baseline.latency_p99

    @staticmethod
    def _opcode_p50(baseline: ProtocolBaseline, opcode: int) -> float:
        """Return p50 latency for *opcode*, falling back to global p50."""
        latencies = baseline.opcode_latency.get(opcode)
        if latencies and len(latencies) >= 3:
            s = sorted(latencies)
            return s[int(0.50 * (len(s) - 1))]
        return baseline.latency_p50

    # -- Baseline learning --------------------------------------------------

    def record_baseline(
        self,
        protocol: str,
        response: bytes | None,
        latency_ms: float,
    ) -> None:
        """Record one baseline sample from a known-valid request."""
        if response is None or len(response) == 0:
            return

        baseline = self._baselines.setdefault(protocol, ProtocolBaseline())
        sample = ResponseSample(
            response_len=len(response),
            latency_ms=latency_ms,
            first_byte=response[0],
            error_code=_extract_error_code(protocol, response),
            raw=response[:64],  # keep first 64 bytes for comparison
        )
        baseline.samples.append(sample)
        # Phase 4: Track per-opcode latency during baseline learning
        baseline.opcode_latency.setdefault(sample.first_byte, []).append(latency_ms)

    def finalize_baselines(self) -> None:
        """Compute statistics from collected baseline samples."""
        for baseline in self._baselines.values():
            baseline.compute_stats()

    def has_baseline(self, protocol: str) -> bool:
        """Whether a baseline exists for this protocol."""
        bl = self._baselines.get(protocol)
        return bl is not None and len(bl.samples) >= 3

    def baseline_summary(self) -> dict[str, dict]:
        """Return baseline stats for reporting."""
        result = {}
        for proto, bl in self._baselines.items():
            clusters = self._timing_clusters.get(proto, [])
            result[proto] = {
                "samples": len(bl.samples),
                "mean_len": round(bl.mean_len, 1),
                "std_len": round(bl.std_len, 1),
                "max_len": bl.max_len,
                "mean_latency_ms": round(bl.mean_latency_ms, 1),
                "latency_p50": round(bl.latency_p50, 2),
                "latency_p90": round(bl.latency_p90, 2),
                "latency_p99": round(bl.latency_p99, 2),
                "timing_clusters": len(clusters),
                "seen_opcodes": sorted(bl.seen_opcodes),
            }
        return result

    # -- Analysis -----------------------------------------------------------

    def analyze(
        self,
        protocol: str,
        request: bytes,
        response: bytes | None,
        latency_ms: float,
    ) -> list[Anomaly]:
        """Analyze a fuzz response for anomalies.

        Returns a list of anomalies (may be empty).  Higher ``score``
        values indicate more interesting findings.
        """
        anomalies: list[Anomaly] = []
        baseline = self._baselines.get(protocol)

        # -- Handle timeouts / no response --
        if response is None:
            self._consecutive_timeouts[protocol] = (
                self._consecutive_timeouts.get(protocol, 0) + 1
            )
            ct = self._consecutive_timeouts[protocol]
            if ct >= 3:
                anomalies.append(Anomaly(
                    AnomalyType.BEHAVIORAL, "high", protocol,
                    f"{ct} consecutive timeouts — target may be hung or crashed",
                    score=6.0 + min(ct, 10),
                ))
            return anomalies
        else:
            self._consecutive_timeouts[protocol] = 0

        if len(response) == 0:
            return anomalies

        # -- 1. Structural self-consistency --
        validator = _STRUCTURAL_VALIDATORS.get(protocol)
        if validator:
            anomalies.extend(validator(response))

        # -- 2. Baseline deviation --
        if baseline and len(baseline.samples) >= 3:
            # Size deviation
            z_len = _zscore(len(response), baseline.mean_len, baseline.std_len)
            if z_len > 3.0:
                anomalies.append(Anomaly(
                    AnomalyType.SIZE_DEVIATION, "medium", protocol,
                    f"Response size {len(response)}B deviates {z_len:.1f} sigma from "
                    f"baseline (mean={baseline.mean_len:.0f}, std={baseline.std_len:.0f})",
                    score=min(z_len, 10.0),
                ))

            # Phase 4: Per-opcode latency spike / drop detection
            opcode = response[0]
            opcode_p99 = self._opcode_p99(baseline, opcode)
            opcode_p50 = self._opcode_p50(baseline, opcode)

            is_spike = False
            if opcode_p99 > 0 and latency_ms > opcode_p99:
                ratio = latency_ms / opcode_p99
                if ratio >= 10.0:
                    severity, score = "critical", 9.0
                elif ratio >= 5.0:
                    severity, score = "high", 7.0
                elif ratio >= 2.0:
                    severity, score = "medium", 5.0
                else:
                    severity, score = "low", 3.0

                if score >= 5.0:
                    is_spike = True
                    anomalies.append(Anomaly(
                        AnomalyType.TIMING, severity, protocol,
                        f"Latency spike: {latency_ms:.0f}ms is {ratio:.1f}x the p99 "
                        f"({opcode_p99:.0f}ms) for opcode 0x{opcode:02x}",
                        evidence=f"opcode=0x{opcode:02x} p99={opcode_p99:.1f}ms",
                        score=score,
                    ))

            # Consecutive spike escalation
            if is_spike:
                self._consecutive_spikes[protocol] = (
                    self._consecutive_spikes.get(protocol, 0) + 1
                )
                cs = self._consecutive_spikes[protocol]
                if cs >= 3:
                    anomalies.append(Anomaly(
                        AnomalyType.TIMING, "high", protocol,
                        f"{cs} consecutive latency spikes — sustained slow path "
                        f"or resource exhaustion",
                        score=7.0 + min(cs - 3, 3),
                    ))
            else:
                self._consecutive_spikes[protocol] = 0

            # Latency drop detection (shallow rejection heuristic)
            if opcode_p50 > 0 and latency_ms < opcode_p50 * 0.3:
                anomalies.append(Anomaly(
                    AnomalyType.TIMING, "low", protocol,
                    f"Latency drop: {latency_ms:.1f}ms is <30% of p50 "
                    f"({opcode_p50:.1f}ms) for opcode 0x{opcode:02x} — "
                    f"shallow_rejection (parser likely rejected early)",
                    evidence=f"opcode=0x{opcode:02x} p50={opcode_p50:.1f}ms",
                    score=2.0,
                ))

            # Legacy z-score latency deviation (kept for global baseline compat)
            z_lat = _zscore(latency_ms, baseline.mean_latency_ms, baseline.std_latency_ms)
            if z_lat > 3.0 and latency_ms > 50:
                anomalies.append(Anomaly(
                    AnomalyType.TIMING, "medium", protocol,
                    f"Response latency {latency_ms:.0f}ms deviates {z_lat:.1f} sigma from "
                    f"baseline (mean={baseline.mean_latency_ms:.0f}ms)",
                    score=min(z_lat, 8.0),
                ))

            # Unexpected opcode (opcode already extracted above for timing)
            if opcode not in baseline.seen_opcodes:
                anomalies.append(Anomaly(
                    AnomalyType.UNEXPECTED_OPCODE, "medium", protocol,
                    f"Response opcode 0x{opcode:02x} was never seen in baseline "
                    f"(known: {[f'0x{o:02x}' for o in sorted(baseline.seen_opcodes)]})",
                    evidence=response[:8].hex(),
                    score=6.0,
                ))

        # -- 3. Leak indicators --
        anomalies.extend(_check_leak_indicators(protocol, request, response, baseline))

        # -- 4. Timing cluster novelty (Phase 4) --
        new_cluster = self._update_timing_clusters(protocol, latency_ms)
        if new_cluster:
            n_clusters = len(self._timing_clusters.get(protocol, []))
            anomalies.append(Anomaly(
                AnomalyType.TIMING, "medium", protocol,
                f"New timing cluster created at {latency_ms:.1f}ms — "
                f"likely new code path (total clusters: {n_clusters})",
                evidence=f"latency={latency_ms:.1f}ms clusters={n_clusters}",
                score=6.0,
            ))

        # -- Track consecutive errors --
        error_code = _extract_error_code(protocol, response)
        if error_code:
            self._consecutive_errors[protocol] = (
                self._consecutive_errors.get(protocol, 0) + 1
            )
        else:
            self._consecutive_errors[protocol] = 0

        # -- 5. Cross-protocol heuristics (Task 3.3) --
        anomalies.extend(self._check_wrong_protocol(protocol, response))
        anomalies.extend(self._check_response_code_regression(protocol, response))
        anomalies.extend(self._check_size_oscillation(protocol, response))

        return anomalies

    # -- Cross-protocol heuristics (Task 3.3) -------------------------------

    def _check_wrong_protocol(
        self, protocol: str, response: bytes,
    ) -> list[Anomaly]:
        """Detect responses that look like they belong to a different protocol.

        Checks the first byte against expected opcode ranges for the declared
        protocol.  If the first byte falls into another protocol's range
        instead, flag as critical.
        """
        anomalies: list[Anomaly] = []
        if len(response) < 2:
            return anomalies

        first = response[0]

        # Expected first-byte ranges per protocol family
        _OPCODE_RANGES: dict[str, tuple[set[int] | range, str]] = {
            "sdp": ({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "SDP PDU IDs"),
            "ble-att": (range(0x01, 0x25), "ATT opcodes"),
            "ble-smp": (range(0x01, 0x0F), "SMP codes"),
            "l2cap": (range(0x01, 0x12), "L2CAP signaling codes"),
            "l2cap-sig": (range(0x01, 0x12), "L2CAP signaling codes"),
        }

        # Text-based protocols: first byte should be printable ASCII
        text_protocols = {"at-hfp", "at-phonebook", "at-sms", "at-injection"}
        if protocol in text_protocols:
            if first < 0x20 or first > 0x7E:
                # Could be binary protocol response instead of AT text
                if first in range(0x01, 0x08):
                    anomalies.append(Anomaly(
                        AnomalyType.STRUCTURAL, "critical", protocol,
                        f"Expected AT text response but got binary first byte 0x{first:02x} "
                        f"(looks like SDP/L2CAP opcode)",
                        evidence=response[:12].hex(),
                        score=9.0,
                    ))
            return anomalies

        expected = _OPCODE_RANGES.get(protocol)
        if expected is None:
            return anomalies

        valid_range, range_name = expected
        if first not in valid_range:
            # Check if it looks like it belongs to another protocol
            wrong_match = ""
            for other_proto, (other_range, other_name) in _OPCODE_RANGES.items():
                if other_proto != protocol and first in other_range:
                    wrong_match = f" (matches {other_name} from {other_proto})"
                    break
            if wrong_match:
                anomalies.append(Anomaly(
                    AnomalyType.STRUCTURAL, "critical", protocol,
                    f"Response first byte 0x{first:02x} is outside expected "
                    f"{range_name}{wrong_match} — possible cross-protocol confusion",
                    evidence=response[:12].hex(),
                    score=9.0,
                ))

        return anomalies

    def _check_response_code_regression(
        self, protocol: str, response: bytes,
    ) -> list[Anomaly]:
        """Detect shifts from success responses to error responses.

        Tracks the last N response codes per protocol.  If the recent
        window shifts from predominantly success to predominantly errors,
        flag as a behavioral anomaly.
        """
        anomalies: list[Anomaly] = []
        if not response:
            return anomalies

        error_code = _extract_error_code(protocol, response)
        # Use 0 for success, the error code for errors
        code_deque = self._recent_response_codes.setdefault(
            protocol, collections.deque(maxlen=20)
        )
        code_deque.append(error_code)

        # Need at least 10 observations to detect a shift
        if len(code_deque) < 10:
            return anomalies

        codes = list(code_deque)
        first_half = codes[:len(codes) // 2]
        second_half = codes[len(codes) // 2:]

        first_error_rate = sum(1 for c in first_half if c != 0) / len(first_half)
        second_error_rate = sum(1 for c in second_half if c != 0) / len(second_half)

        # Detect regression: first half mostly success, second half mostly errors
        if first_error_rate < 0.3 and second_error_rate > 0.7:
            anomalies.append(Anomaly(
                AnomalyType.BEHAVIORAL, "high", protocol,
                f"Response code regression: error rate shifted from "
                f"{first_error_rate:.0%} to {second_error_rate:.0%} over last "
                f"{len(codes)} responses",
                evidence=f"recent_codes={codes[-6:]}",
                score=7.0,
            ))

        return anomalies

    def _check_size_oscillation(
        self, protocol: str, response: bytes,
    ) -> list[Anomaly]:
        """Detect periodic response size patterns.

        If the response size alternates between two values (e.g., 10, 50,
        10, 50), the target may be in a confused state.
        """
        anomalies: list[Anomaly] = []
        if not response:
            return anomalies

        size_deque = self._recent_response_sizes.setdefault(
            protocol, collections.deque(maxlen=20)
        )
        size_deque.append(len(response))

        # Need at least 6 observations to detect oscillation
        if len(size_deque) < 6:
            return anomalies

        sizes = list(size_deque)
        last_6 = sizes[-6:]

        # Check for alternating pattern (A, B, A, B, A, B)
        even_vals = {last_6[i] for i in range(0, 6, 2)}
        odd_vals = {last_6[i] for i in range(1, 6, 2)}

        if (len(even_vals) == 1 and len(odd_vals) == 1
                and even_vals != odd_vals):
            val_a = even_vals.pop()
            val_b = odd_vals.pop()
            # Only flag if the difference is significant
            if abs(val_a - val_b) > max(val_a, val_b) * 0.2:
                anomalies.append(Anomaly(
                    AnomalyType.BEHAVIORAL, "medium", protocol,
                    f"Response size oscillation detected: alternating between "
                    f"{val_a}B and {val_b}B over last 6 responses",
                    evidence=f"sizes={last_6}",
                    score=5.0,
                ))

        return anomalies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_error_code(protocol: str, response: bytes) -> int:
    """Extract protocol-level error code from response, or 0 if not an error."""
    if not response:
        return 0

    if protocol == "sdp" and len(response) >= 7:
        if response[0] == 0x01:  # SDP Error Response
            return struct.unpack(">H", response[5:7])[0]

    elif protocol == "ble-att" and len(response) >= 5:
        if response[0] == 0x01:  # ATT Error Response
            return response[4]

    elif protocol == "l2cap" and len(response) >= 6:
        if response[0] == 0x01:  # Command Reject
            return struct.unpack("<H", response[4:6])[0]

    return 0
