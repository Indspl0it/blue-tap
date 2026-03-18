"""BLE ATT (Attribute Protocol) PDU builder and fuzz case generator.

Constructs well-formed and malformed ATT PDUs for protocol-aware fuzzing.
All multi-byte fields are little-endian per Bluetooth Core Spec Vol 3, Part F.

ATT runs on L2CAP CID 0x0004 (LE) or 0x0005 (BR/EDR). PDU format:
  Opcode (1) + Parameters (variable, up to ATT_MTU - 1)

Opcode byte structure:
  Bit 7:    Authentication Signature Flag (1 = 12-byte signature appended)
  Bit 6:    Command Flag (1 = command, no response expected)
  Bits 5-0: Method (6-bit identifier)

This module provides:
  - ATT opcode, error code, and GATT UUID constants
  - PDU builders for all client-to-server ATT operations
  - Fuzz case generators targeting handle boundaries, MTU edge cases,
    write overflows, unknown opcodes, UUID size violations, and protocol
    sequence attacks (SweynTooth patterns, CVE-2024-24746)

Reference: Bluetooth Core Spec v5.4, Vol 3, Part F (ATT)
CVE targets: CVE-2024-24746 (Zephyr), SweynTooth family, CVE-2020-10069
"""

from __future__ import annotations

import os
import struct


# ---------------------------------------------------------------------------
# ATT Opcodes (Bluetooth Core Spec Vol 3, Part F, Section 3.4)
# ---------------------------------------------------------------------------

ATT_ERROR_RSP = 0x01
ATT_EXCHANGE_MTU_REQ = 0x02
ATT_EXCHANGE_MTU_RSP = 0x03
ATT_FIND_INFO_REQ = 0x04
ATT_FIND_INFO_RSP = 0x05
ATT_FIND_BY_TYPE_VALUE_REQ = 0x06
ATT_FIND_BY_TYPE_VALUE_RSP = 0x07
ATT_READ_BY_TYPE_REQ = 0x08
ATT_READ_BY_TYPE_RSP = 0x09
ATT_READ_REQ = 0x0A
ATT_READ_RSP = 0x0B
ATT_READ_BLOB_REQ = 0x0C
ATT_READ_BLOB_RSP = 0x0D
ATT_READ_MULTIPLE_REQ = 0x0E
ATT_READ_MULTIPLE_RSP = 0x0F
ATT_READ_BY_GROUP_TYPE_REQ = 0x10
ATT_READ_BY_GROUP_TYPE_RSP = 0x11
ATT_WRITE_REQ = 0x12
ATT_WRITE_RSP = 0x13
ATT_PREPARE_WRITE_REQ = 0x16
ATT_PREPARE_WRITE_RSP = 0x17
ATT_EXECUTE_WRITE_REQ = 0x18
ATT_EXECUTE_WRITE_RSP = 0x19
ATT_HANDLE_VALUE_NTF = 0x1B
ATT_HANDLE_VALUE_IND = 0x1D
ATT_HANDLE_VALUE_CFM = 0x1E
ATT_WRITE_CMD = 0x52
ATT_SIGNED_WRITE_CMD = 0xD2

# Human-readable names for logging/reporting
OPCODE_NAMES: dict[int, str] = {
    ATT_ERROR_RSP: "Error Response",
    ATT_EXCHANGE_MTU_REQ: "Exchange MTU Request",
    ATT_EXCHANGE_MTU_RSP: "Exchange MTU Response",
    ATT_FIND_INFO_REQ: "Find Information Request",
    ATT_FIND_INFO_RSP: "Find Information Response",
    ATT_FIND_BY_TYPE_VALUE_REQ: "Find By Type Value Request",
    ATT_FIND_BY_TYPE_VALUE_RSP: "Find By Type Value Response",
    ATT_READ_BY_TYPE_REQ: "Read By Type Request",
    ATT_READ_BY_TYPE_RSP: "Read By Type Response",
    ATT_READ_REQ: "Read Request",
    ATT_READ_RSP: "Read Response",
    ATT_READ_BLOB_REQ: "Read Blob Request",
    ATT_READ_BLOB_RSP: "Read Blob Response",
    ATT_READ_MULTIPLE_REQ: "Read Multiple Request",
    ATT_READ_MULTIPLE_RSP: "Read Multiple Response",
    ATT_READ_BY_GROUP_TYPE_REQ: "Read By Group Type Request",
    ATT_READ_BY_GROUP_TYPE_RSP: "Read By Group Type Response",
    ATT_WRITE_REQ: "Write Request",
    ATT_WRITE_RSP: "Write Response",
    ATT_PREPARE_WRITE_REQ: "Prepare Write Request",
    ATT_PREPARE_WRITE_RSP: "Prepare Write Response",
    ATT_EXECUTE_WRITE_REQ: "Execute Write Request",
    ATT_EXECUTE_WRITE_RSP: "Execute Write Response",
    ATT_HANDLE_VALUE_NTF: "Handle Value Notification",
    ATT_HANDLE_VALUE_IND: "Handle Value Indication",
    ATT_HANDLE_VALUE_CFM: "Handle Value Confirmation",
    ATT_WRITE_CMD: "Write Command",
    ATT_SIGNED_WRITE_CMD: "Signed Write Command",
}

# Set of all defined opcodes for fuzz_unknown_opcodes
DEFINED_OPCODES: frozenset[int] = frozenset(OPCODE_NAMES.keys())


# ---------------------------------------------------------------------------
# ATT Error Codes (Bluetooth Core Spec Vol 3, Part F, Section 3.4.1.1)
# ---------------------------------------------------------------------------

ATT_ERR_INVALID_HANDLE = 0x01
ATT_ERR_READ_NOT_PERMITTED = 0x02
ATT_ERR_WRITE_NOT_PERMITTED = 0x03
ATT_ERR_INVALID_PDU = 0x04
ATT_ERR_INSUFF_AUTH = 0x05
ATT_ERR_REQ_NOT_SUPPORTED = 0x06
ATT_ERR_INVALID_OFFSET = 0x07
ATT_ERR_INSUFF_AUTHOR = 0x08
ATT_ERR_PREP_QUEUE_FULL = 0x09
ATT_ERR_ATTR_NOT_FOUND = 0x0A
ATT_ERR_ATTR_NOT_LONG = 0x0B
ATT_ERR_INSUFF_ENC_KEY = 0x0C
ATT_ERR_INVALID_VALUE_LEN = 0x0D
ATT_ERR_UNLIKELY = 0x0E
ATT_ERR_INSUFF_ENC = 0x0F
ATT_ERR_UNSUPPORTED_GROUP = 0x10
ATT_ERR_INSUFF_RESOURCES = 0x11

# BT 5.1+ error codes
ATT_ERR_DATABASE_OUT_OF_SYNC = 0x12
ATT_ERR_VALUE_NOT_ALLOWED = 0x13

# Application error range: 0x80-0x9F (defined by higher-layer spec)
ATT_ERR_APP_MIN = 0x80
ATT_ERR_APP_MAX = 0x9F

# Common profile/service error codes: 0xE0-0xFF
ATT_ERR_WRITE_REQUEST_REJECTED = 0xFC
ATT_ERR_CCC_IMPROPER_CONFIG = 0xFD
ATT_ERR_PROCEDURE_IN_PROGRESS = 0xFE
ATT_ERR_OUT_OF_RANGE = 0xFF

ERROR_NAMES: dict[int, str] = {
    ATT_ERR_INVALID_HANDLE: "Invalid Handle",
    ATT_ERR_READ_NOT_PERMITTED: "Read Not Permitted",
    ATT_ERR_WRITE_NOT_PERMITTED: "Write Not Permitted",
    ATT_ERR_INVALID_PDU: "Invalid PDU",
    ATT_ERR_INSUFF_AUTH: "Insufficient Authentication",
    ATT_ERR_REQ_NOT_SUPPORTED: "Request Not Supported",
    ATT_ERR_INVALID_OFFSET: "Invalid Offset",
    ATT_ERR_INSUFF_AUTHOR: "Insufficient Authorization",
    ATT_ERR_PREP_QUEUE_FULL: "Prepare Queue Full",
    ATT_ERR_ATTR_NOT_FOUND: "Attribute Not Found",
    ATT_ERR_ATTR_NOT_LONG: "Attribute Not Long",
    ATT_ERR_INSUFF_ENC_KEY: "Insufficient Encryption Key Size",
    ATT_ERR_INVALID_VALUE_LEN: "Invalid Attribute Value Length",
    ATT_ERR_UNLIKELY: "Unlikely Error",
    ATT_ERR_INSUFF_ENC: "Insufficient Encryption",
    ATT_ERR_UNSUPPORTED_GROUP: "Unsupported Group Type",
    ATT_ERR_INSUFF_RESOURCES: "Insufficient Resources",
    ATT_ERR_DATABASE_OUT_OF_SYNC: "Database Out of Sync",
    ATT_ERR_VALUE_NOT_ALLOWED: "Value Not Allowed",
    ATT_ERR_WRITE_REQUEST_REJECTED: "Write Request Rejected",
    ATT_ERR_CCC_IMPROPER_CONFIG: "CCC Improperly Configured",
    ATT_ERR_PROCEDURE_IN_PROGRESS: "Procedure Already in Progress",
    ATT_ERR_OUT_OF_RANGE: "Out of Range",
}


# ---------------------------------------------------------------------------
# GATT UUIDs (Bluetooth Core Spec Vol 3, Part G)
# ---------------------------------------------------------------------------

UUID_PRIMARY_SERVICE = 0x2800
UUID_SECONDARY_SERVICE = 0x2801
UUID_INCLUDE = 0x2802
UUID_CHARACTERISTIC = 0x2803
UUID_CHAR_EXTENDED_PROPERTIES = 0x2900
UUID_CHAR_USER_DESCRIPTION = 0x2901
UUID_CCCD = 0x2902
UUID_SCCD = 0x2903
UUID_CHAR_PRESENTATION_FORMAT = 0x2904
UUID_CHAR_AGGREGATE_FORMAT = 0x2905

# Common GATT service UUIDs for discovery fuzzing
UUID_GENERIC_ACCESS = 0x1800
UUID_GENERIC_ATTRIBUTE = 0x1801
UUID_DEVICE_INFORMATION = 0x180A
UUID_HEART_RATE = 0x180D
UUID_BATTERY_SERVICE = 0x180F
UUID_BLOOD_PRESSURE = 0x1810
UUID_HID_SERVICE = 0x1812

# Default ATT_MTU values
ATT_MTU_DEFAULT = 23
ATT_MTU_MAX = 517


# ===========================================================================
# PDU Builders — All multi-byte fields are LITTLE-ENDIAN
# ===========================================================================

def build_exchange_mtu_req(mtu: int) -> bytes:
    """Build an Exchange MTU Request PDU (opcode 0x02).

    Requests the server to use the specified MTU for this ATT bearer.
    Valid range per spec: 23-517, but any uint16 value can be sent for fuzzing.

    Args:
        mtu: Client receive MTU value (uint16).

    Returns:
        3-byte PDU: opcode(1) + ClientRxMTU(2 LE).
    """
    return struct.pack("<BH", ATT_EXCHANGE_MTU_REQ, mtu & 0xFFFF)


def build_find_info_req(start: int, end: int) -> bytes:
    """Build a Find Information Request PDU (opcode 0x04).

    Discovers attribute handles and their types in the given range.
    Spec requires StartHandle <= EndHandle and StartHandle >= 0x0001.

    Args:
        start: Starting handle (uint16).
        end: Ending handle (uint16).

    Returns:
        5-byte PDU: opcode(1) + StartHandle(2 LE) + EndHandle(2 LE).
    """
    return struct.pack("<BHH", ATT_FIND_INFO_REQ, start & 0xFFFF, end & 0xFFFF)


def build_find_by_type_value_req(
    start: int,
    end: int,
    attr_type: int,
    attr_value: bytes,
) -> bytes:
    """Build a Find By Type Value Request PDU (opcode 0x06).

    Finds attributes with a given 16-bit type UUID and matching value.

    Args:
        start: Starting handle (uint16).
        end: Ending handle (uint16).
        attr_type: 16-bit attribute type UUID.
        attr_value: Attribute value to match (variable length).

    Returns:
        PDU: opcode(1) + StartHandle(2 LE) + EndHandle(2 LE) + AttrType(2 LE) + AttrValue.
    """
    return (
        struct.pack("<BHHH", ATT_FIND_BY_TYPE_VALUE_REQ, start & 0xFFFF,
                     end & 0xFFFF, attr_type & 0xFFFF)
        + attr_value
    )


def build_read_by_type_req(start: int, end: int, uuid: int | bytes) -> bytes:
    """Build a Read By Type Request PDU (opcode 0x08).

    Reads attributes of a given type within a handle range.
    UUID can be 2 bytes (UUID16) or 16 bytes (UUID128).

    Args:
        start: Starting handle (uint16).
        end: Ending handle (uint16).
        uuid: Attribute type — int for UUID16, bytes for UUID128 or fuzz sizes.

    Returns:
        PDU: opcode(1) + StartHandle(2 LE) + EndHandle(2 LE) + UUID(2 or 16 LE).
    """
    pdu = struct.pack("<BHH", ATT_READ_BY_TYPE_REQ, start & 0xFFFF, end & 0xFFFF)
    if isinstance(uuid, int):
        pdu += struct.pack("<H", uuid & 0xFFFF)
    else:
        pdu += uuid  # Raw bytes (UUID128 or deliberately malformed)
    return pdu


def build_read_req(handle: int) -> bytes:
    """Build a Read Request PDU (opcode 0x0A).

    Reads the entire value of an attribute by handle.

    Args:
        handle: Attribute handle (uint16).

    Returns:
        3-byte PDU: opcode(1) + AttrHandle(2 LE).
    """
    return struct.pack("<BH", ATT_READ_REQ, handle & 0xFFFF)


def build_read_blob_req(handle: int, offset: int) -> bytes:
    """Build a Read Blob Request PDU (opcode 0x0C).

    Reads a portion of a long attribute value starting at the given offset.

    Args:
        handle: Attribute handle (uint16).
        offset: Value offset to start reading from (uint16).

    Returns:
        5-byte PDU: opcode(1) + AttrHandle(2 LE) + ValueOffset(2 LE).
    """
    return struct.pack("<BHH", ATT_READ_BLOB_REQ, handle & 0xFFFF, offset & 0xFFFF)


def build_read_multiple_req(handles: list[int]) -> bytes:
    """Build a Read Multiple Request PDU (opcode 0x0E).

    Reads multiple attribute values in a single request.
    Spec requires at least 2 handles (SetOfHandles is 4+ bytes).

    Args:
        handles: List of attribute handles (uint16 each). Minimum 2 per spec.

    Returns:
        PDU: opcode(1) + handles(2 LE each).
    """
    pdu = bytes([ATT_READ_MULTIPLE_REQ])
    for h in handles:
        pdu += struct.pack("<H", h & 0xFFFF)
    return pdu


def build_read_by_group_type_req(start: int, end: int, uuid: int | bytes) -> bytes:
    """Build a Read By Group Type Request PDU (opcode 0x10).

    Discovers services by reading attribute groupings. UUID must be 0x2800
    (Primary Service) or 0x2801 (Secondary Service) for valid requests.

    Args:
        start: Starting handle (uint16).
        end: Ending handle (uint16).
        uuid: Group type — int for UUID16, bytes for UUID128 or fuzz sizes.

    Returns:
        PDU: opcode(1) + StartHandle(2 LE) + EndHandle(2 LE) + UUID(2 or 16 LE).
    """
    pdu = struct.pack("<BHH", ATT_READ_BY_GROUP_TYPE_REQ, start & 0xFFFF, end & 0xFFFF)
    if isinstance(uuid, int):
        pdu += struct.pack("<H", uuid & 0xFFFF)
    else:
        pdu += uuid
    return pdu


def build_write_req(handle: int, value: bytes) -> bytes:
    """Build a Write Request PDU (opcode 0x12).

    Writes an attribute value and expects a Write Response. Max value
    length is ATT_MTU - 3 for a conformant implementation.

    Args:
        handle: Attribute handle (uint16).
        value: Attribute value to write (variable length).

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + AttrValue(variable).
    """
    return struct.pack("<BH", ATT_WRITE_REQ, handle & 0xFFFF) + value


def build_write_cmd(handle: int, value: bytes) -> bytes:
    """Build a Write Command PDU (opcode 0x52).

    Writes an attribute value with no response expected (fire-and-forget).
    Opcode bit 6 (Command Flag) is set: 0x52 = 0b01010010.

    Args:
        handle: Attribute handle (uint16).
        value: Attribute value to write (variable length).

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + AttrValue(variable).
    """
    return struct.pack("<BH", ATT_WRITE_CMD, handle & 0xFFFF) + value


def build_prepare_write_req(handle: int, offset: int, value: bytes) -> bytes:
    """Build a Prepare Write Request PDU (opcode 0x16).

    Queues a partial write for later execution. Used for long attribute
    writes that exceed ATT_MTU - 3 bytes. The server echoes back the
    request in a Prepare Write Response.

    Args:
        handle: Attribute handle (uint16).
        offset: Value offset where this fragment starts (uint16).
        value: Partial attribute value to queue.

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + ValueOffset(2 LE) + PartAttrValue.
    """
    return struct.pack("<BHH", ATT_PREPARE_WRITE_REQ, handle & 0xFFFF,
                       offset & 0xFFFF) + value


def build_execute_write_req(flags: int = 0x01) -> bytes:
    """Build an Execute Write Request PDU (opcode 0x18).

    Commits or cancels all queued Prepare Write operations.

    Args:
        flags: 0x00 = cancel all prepared writes, 0x01 = commit all.
               Other values are undefined per spec (fuzz targets).

    Returns:
        2-byte PDU: opcode(1) + Flags(1).
    """
    return struct.pack("<BB", ATT_EXECUTE_WRITE_REQ, flags & 0xFF)


def build_handle_value_ntf(handle: int, value: bytes) -> bytes:
    """Build a Handle Value Notification PDU (opcode 0x1B).

    Notifications are normally server-to-client only. Sending from client
    is invalid and tests how the server handles unexpected direction.

    Args:
        handle: Attribute handle (uint16).
        value: Attribute value (variable length).

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + AttrValue(variable).
    """
    return struct.pack("<BH", ATT_HANDLE_VALUE_NTF, handle & 0xFFFF) + value


def build_handle_value_ind(handle: int, value: bytes) -> bytes:
    """Build a Handle Value Indication PDU (opcode 0x1D).

    Indications are normally server-to-client only. Sending from client
    is invalid and tests how the server handles unexpected direction.

    Args:
        handle: Attribute handle (uint16).
        value: Attribute value (variable length).

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + AttrValue(variable).
    """
    return struct.pack("<BH", ATT_HANDLE_VALUE_IND, handle & 0xFFFF) + value


def build_handle_value_cfm() -> bytes:
    """Build a Handle Value Confirmation PDU (opcode 0x1E).

    Sent by the client to acknowledge a Handle Value Indication.
    Sending without a prior indication tests state machine handling.

    Returns:
        1-byte PDU: opcode only.
    """
    return bytes([ATT_HANDLE_VALUE_CFM])


def build_signed_write_cmd(handle: int, value: bytes, signature: bytes) -> bytes:
    """Build a Signed Write Command PDU (opcode 0xD2).

    Opcode bit 7 (Auth Signature Flag) is set: 0xD2 = 0b11010010.
    A 12-byte authentication signature is appended after the value.

    Args:
        handle: Attribute handle (uint16).
        value: Attribute value (variable length).
        signature: 12-byte CMAC authentication signature.

    Returns:
        PDU: opcode(1) + AttrHandle(2 LE) + AttrValue(variable) + AuthSignature(12).

    Raises:
        ValueError: If signature is not exactly 12 bytes.
    """
    if len(signature) != 12:
        raise ValueError(f"Authentication signature must be 12 bytes, got {len(signature)}")
    return struct.pack("<BH", ATT_SIGNED_WRITE_CMD, handle & 0xFFFF) + value + signature


# ===========================================================================
# Fuzz Case Generators
# ===========================================================================

def fuzz_handles() -> list[bytes]:
    """Fuzz handle boundary values across all handle-based opcodes.

    Tests handle 0x0000 (invalid per spec), 0x0001 (minimum valid),
    0xFFFE (near maximum), and 0xFFFF (maximum) against Read, Write,
    Read Blob, and Prepare Write operations.

    Returns:
        List of PDU bytes exercising handle boundaries.
    """
    cases: list[bytes] = []
    for handle in [0x0000, 0x0001, 0xFFFE, 0xFFFF]:
        cases.append(build_read_req(handle))
        cases.append(build_write_req(handle, b"\x00"))
        cases.append(build_read_blob_req(handle, 0))
        cases.append(build_prepare_write_req(handle, 0, b"\x00"))
    return cases


def fuzz_range_reversed() -> list[bytes]:
    """Generate requests where StartHandle > EndHandle.

    Per spec, the server must return ATT_ERR_INVALID_HANDLE (0x01) when
    StartHandle > EndHandle or StartHandle == 0x0000.

    Returns:
        List of PDU bytes with reversed or invalid handle ranges.
    """
    return [
        build_find_info_req(0x0005, 0x0001),
        build_read_by_type_req(0xFFFF, 0x0001, UUID_CHARACTERISTIC),
        build_read_by_group_type_req(0x0010, 0x0001, UUID_PRIMARY_SERVICE),
        build_find_info_req(0x0000, 0x0000),  # StartHandle = 0 is invalid
        build_find_info_req(0x0000, 0xFFFF),  # StartHandle = 0
        build_read_by_type_req(0x0000, 0x0001, UUID_CHARACTERISTIC),  # StartHandle = 0
    ]


def fuzz_mtu_values() -> list[bytes]:
    """Generate Exchange MTU Requests with interesting boundary values.

    Tests: 0 (zero), 1 (below minimum), 22 (below default), 23 (default
    minimum), 24 (just above), 255/256 (byte boundary), 512 (common max),
    517 (spec max), 0xFFFF (uint16 max — SweynTooth allocation crash target).

    Returns:
        List of Exchange MTU Request PDU bytes.
    """
    return [
        build_exchange_mtu_req(m)
        for m in [0, 1, 22, 23, 24, 255, 256, 512, 517, 0xFFFF]
    ]


def fuzz_write_sizes() -> list[bytes]:
    """Generate Write Request and Write Command PDUs with various payload sizes.

    Tests zero-length writes, single-byte, MTU boundary values (20=ATT_MTU-3,
    22=ATT_MTU-1, 23=ATT_MTU), oversized payloads, and extreme sizes.
    Capped at 512 bytes per payload to avoid excessive memory use.

    Returns:
        List of Write Request and Write Command PDU bytes.
    """
    cases: list[bytes] = []
    for size in [0, 1, 20, 22, 23, 100, 255, 512]:
        payload = os.urandom(size) if size > 0 else b""
        cases.append(build_write_req(0x0003, payload))
        cases.append(build_write_cmd(0x0003, payload))
    return cases


def fuzz_prepare_write_overflow() -> list[bytes]:
    """Generate Prepare Write Requests with large offsets and values.

    Tests the CVE-2024-24746 pattern: offset + value length exceeding the
    attribute's maximum value size can cause heap buffer overflow in
    vulnerable implementations (Zephyr, NimBLE).

    Also tests Execute Write without prior Prepare, Execute with cancel,
    and Execute with invalid flags.

    Returns:
        List of Prepare Write and Execute Write PDU bytes.
    """
    cases: list[bytes] = []
    for offset in [0, 1, 0x7FFF, 0xFFFE, 0xFFFF]:
        for size in [1, 100, 512]:
            cases.append(build_prepare_write_req(0x0003, offset, os.urandom(size)))
    # Execute Write without prior Prepare (tests empty queue handling)
    cases.append(build_execute_write_req(0x01))
    # Execute Write with cancel (tests cancel of empty queue)
    cases.append(build_execute_write_req(0x00))
    # Execute Write with invalid flags
    cases.append(build_execute_write_req(0x02))
    cases.append(build_execute_write_req(0xFF))
    return cases


def fuzz_unknown_opcodes() -> list[bytes]:
    """Generate PDUs with every undefined ATT opcode byte (0x00-0xFF).

    Per spec, the server should return ATT_ERR_REQ_NOT_SUPPORTED (0x06)
    for undefined opcodes. Includes 2 bytes of dummy data after the opcode
    to avoid triggering truncation-only errors.

    Returns:
        List of raw PDU bytes, one per undefined opcode.
    """
    return [
        bytes([op]) + b"\x01\x00"
        for op in range(256)
        if op not in DEFINED_OPCODES
    ]


def fuzz_invalid_uuid_sizes() -> list[bytes]:
    """Generate Read By Type Requests with non-standard UUID sizes.

    ATT only accepts UUID16 (2 bytes) or UUID128 (16 bytes). Other sizes
    should trigger ATT_ERR_INVALID_PDU (0x04). Tests 1, 3, 4, 5, 8, 15,
    17, and 32 byte UUIDs.

    Returns:
        List of malformed Read By Type Request PDU bytes.
    """
    cases: list[bytes] = []
    for size in [1, 3, 4, 5, 8, 15, 17, 32]:
        pdu = struct.pack("<BHH", ATT_READ_BY_TYPE_REQ, 0x0001, 0xFFFF) + os.urandom(size)
        cases.append(pdu)
    return cases


def fuzz_rapid_sequential_requests(count: int = 50) -> list[bytes]:
    """Generate rapid sequential Read Requests (SweynTooth deadlock pattern).

    SweynTooth CVEs exploit BLE stacks that deadlock when receiving multiple
    ATT requests before responding to the first. The ATT protocol requires
    sequential request-response, so flooding tests state machine robustness.

    Args:
        count: Number of rapid requests to generate. Default 50.

    Returns:
        List of identical Read Request PDU bytes.
    """
    return [build_read_req(0x0001) for _ in range(count)]


def fuzz_cccd_writes() -> list[bytes]:
    """Generate writes to CCCD (Client Characteristic Configuration Descriptor).

    CCCD (UUID 0x2902) is a 2-byte little-endian bitfield:
      Bit 0 (0x0001): Notifications enabled
      Bit 1 (0x0002): Indications enabled
      Bits 2-15: Reserved (must be 0)

    Tests valid values, both bits set, and reserved/invalid bit patterns.
    Uses handle 0x0004 (common CCCD handle in typical GATT databases).

    Returns:
        List of Write Request PDU bytes targeting CCCD.
    """
    cases: list[bytes] = []
    cccd_handle = 0x0004  # Common CCCD handle
    for value in [0x0000, 0x0001, 0x0002, 0x0003, 0xFFFF]:
        cases.append(build_write_req(cccd_handle, struct.pack("<H", value)))
    return cases


def fuzz_service_discovery() -> list[bytes]:
    """Generate malformed service discovery sequences.

    Tests GATT service discovery edge cases:
      - Read By Group Type with non-service UUIDs (should return error 0x10)
      - Find By Type Value with empty and oversized values
      - Read By Type targeting descriptor UUIDs across full handle range
      - Read Multiple with only 1 handle (spec requires minimum 2)

    Returns:
        List of malformed discovery PDU bytes.
    """
    cases: list[bytes] = []

    # Read By Group Type with non-service UUID (should return Unsupported Group Type)
    cases.append(build_read_by_group_type_req(0x0001, 0xFFFF, UUID_CHARACTERISTIC))
    cases.append(build_read_by_group_type_req(0x0001, 0xFFFF, UUID_CCCD))
    cases.append(build_read_by_group_type_req(0x0001, 0xFFFF, 0x0000))  # Zero UUID

    # Find By Type Value with Primary Service UUID but empty value
    cases.append(build_find_by_type_value_req(
        0x0001, 0xFFFF, UUID_PRIMARY_SERVICE, b""
    ))
    # Find By Type Value with oversized value
    cases.append(build_find_by_type_value_req(
        0x0001, 0xFFFF, UUID_PRIMARY_SERVICE, os.urandom(256)
    ))

    # Read By Type targeting CCCD across full range
    cases.append(build_read_by_type_req(0x0001, 0xFFFF, UUID_CCCD))

    # Read Multiple with only 1 handle (spec requires minimum 2)
    cases.append(build_read_multiple_req([0x0001]))

    # Read Multiple with 0 handles (just opcode, no handles)
    cases.append(bytes([ATT_READ_MULTIPLE_REQ]))

    # Read Multiple with many handles
    cases.append(build_read_multiple_req(list(range(0x0001, 0x0021))))

    return cases


def fuzz_execute_without_prepare() -> list[bytes]:
    """Generate Execute Write Requests without any prior Prepare Write.

    Tests how the server handles Execute Write when the prepare queue is
    empty. Both commit and cancel flags are tested, plus invalid flag values.

    Returns:
        List of Execute Write Request PDU bytes.
    """
    return [
        build_execute_write_req(0x01),  # Commit empty queue
        build_execute_write_req(0x00),  # Cancel empty queue
        build_execute_write_req(0x02),  # Invalid flag
        build_execute_write_req(0x80),  # Invalid flag, high bit
        build_execute_write_req(0xFF),  # All bits set
    ]


def fuzz_notification_from_client() -> list[bytes]:
    """Generate Notification and Indication PDUs from the client side.

    Notifications (0x1B) and Indications (0x1D) are server-to-client only.
    Sending them from client tests whether the server properly rejects or
    ignores invalid-direction PDUs. Also tests unsolicited Confirmation
    (0x1E) without a prior Indication.

    Returns:
        List of invalid-direction PDU bytes.
    """
    cases: list[bytes] = []

    # Client sends Notification (invalid direction)
    cases.append(build_handle_value_ntf(0x0001, b"\x00"))
    cases.append(build_handle_value_ntf(0x0001, os.urandom(20)))

    # Client sends Indication (invalid direction)
    cases.append(build_handle_value_ind(0x0001, b"\x00"))
    cases.append(build_handle_value_ind(0x0001, os.urandom(20)))

    # Unsolicited Confirmation
    cases.append(build_handle_value_cfm())

    return cases


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_att_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all ATT fuzz payloads.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a raw ATT PDU suitable for sending over L2CAP CID 0x0004.

    Returns:
        List of fuzz case bytes. Typical count: ~500-700 cases.
    """
    cases: list[bytes] = []

    # Handle boundary tests
    cases.extend(fuzz_handles())

    # Range validation tests
    cases.extend(fuzz_range_reversed())

    # MTU negotiation tests
    cases.extend(fuzz_mtu_values())

    # Write size boundary tests
    cases.extend(fuzz_write_sizes())

    # Prepare Write overflow tests (CVE-2024-24746 pattern)
    cases.extend(fuzz_prepare_write_overflow())

    # Unknown opcode tests
    cases.extend(fuzz_unknown_opcodes())

    # Invalid UUID size tests
    cases.extend(fuzz_invalid_uuid_sizes())

    # SweynTooth deadlock pattern
    cases.extend(fuzz_rapid_sequential_requests())

    # CCCD write tests
    cases.extend(fuzz_cccd_writes())

    # Malformed service discovery
    cases.extend(fuzz_service_discovery())

    # Execute without Prepare
    cases.extend(fuzz_execute_without_prepare())

    # Invalid-direction PDUs (client sends server-only opcodes)
    cases.extend(fuzz_notification_from_client())

    return cases
