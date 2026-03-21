"""OBEX (Object Exchange) protocol builder for Bluetooth fuzzing.

Complete OBEX packet construction library supporting PBAP, MAP, OPP, and FTP
profiles.  Provides well-formed packet builders, profile-specific helpers,
and targeted fuzz-case generators for exercising stack parsers.

Reference: IrDA OBEX 1.5, Bluetooth PBAP 1.2, Bluetooth MAP 1.4.
All multi-byte fields are big-endian.
"""

from __future__ import annotations

import struct
from typing import Optional

# ---------------------------------------------------------------------------
# Opcodes (request)
# ---------------------------------------------------------------------------

OBEX_CONNECT: int = 0x80
OBEX_DISCONNECT: int = 0x81
OBEX_PUT: int = 0x02
OBEX_PUT_FINAL: int = 0x82
OBEX_GET: int = 0x03
OBEX_GET_FINAL: int = 0x83
OBEX_SETPATH: int = 0x85
OBEX_ABORT: int = 0xFF
OBEX_SESSION: int = 0x87

# ---------------------------------------------------------------------------
# Response codes (all have Final bit 0x80 set)
# ---------------------------------------------------------------------------

# Informational
OBEX_CONTINUE: int = 0x90

# Success
OBEX_SUCCESS: int = 0xA0
OBEX_CREATED: int = 0xA1
OBEX_ACCEPTED: int = 0xA2
OBEX_NON_AUTHORITATIVE: int = 0xA3
OBEX_NO_CONTENT: int = 0xA4
OBEX_RESET_CONTENT: int = 0xA5
OBEX_PARTIAL_CONTENT: int = 0xA6

# Redirection
OBEX_MULTIPLE_CHOICES: int = 0xB0
OBEX_MOVED_PERMANENTLY: int = 0xB1
OBEX_MOVED_TEMPORARILY: int = 0xB2
OBEX_SEE_OTHER: int = 0xB3
OBEX_NOT_MODIFIED: int = 0xB4
OBEX_USE_PROXY: int = 0xB5

# Client error
OBEX_BAD_REQUEST: int = 0xC0
OBEX_UNAUTHORIZED: int = 0xC1
OBEX_PAYMENT_REQUIRED: int = 0xC2
OBEX_FORBIDDEN: int = 0xC3
OBEX_NOT_FOUND: int = 0xC4
OBEX_METHOD_NOT_ALLOWED: int = 0xC5
OBEX_NOT_ACCEPTABLE: int = 0xC6
OBEX_PROXY_AUTH_REQUIRED: int = 0xC7
OBEX_REQUEST_TIMEOUT: int = 0xC8
OBEX_CONFLICT: int = 0xC9
OBEX_GONE: int = 0xCA
OBEX_LENGTH_REQUIRED: int = 0xCB
OBEX_PRECON_FAILED: int = 0xCC
OBEX_ENTITY_TOO_LARGE: int = 0xCD
OBEX_REQUEST_URL_TOO_LARGE: int = 0xCE
OBEX_UNSUPPORTED_MEDIA_TYPE: int = 0xCF

# Server error
OBEX_INTERNAL_ERROR: int = 0xD0
OBEX_NOT_IMPLEMENTED: int = 0xD1
OBEX_BAD_GATEWAY: int = 0xD2
OBEX_UNAVAILABLE: int = 0xD3
OBEX_GATEWAY_TIMEOUT: int = 0xD4
OBEX_HTTP_VERSION_NOT_SUPPORTED: int = 0xD5

# OBEX-specific
OBEX_DATABASE_FULL: int = 0xE0
OBEX_DATABASE_LOCKED: int = 0xE1

# ---------------------------------------------------------------------------
# Header IDs
# ---------------------------------------------------------------------------

HI_COUNT: int = 0xC0          # 4-byte
HI_NAME: int = 0x01           # Unicode
HI_TYPE: int = 0x42           # Byte seq
HI_LENGTH: int = 0xC3         # 4-byte
HI_TIME: int = 0x44           # Byte seq
HI_DESCRIPTION: int = 0x05    # Unicode
HI_TARGET: int = 0x46         # Byte seq
HI_HTTP: int = 0x47           # Byte seq
HI_BODY: int = 0x48           # Byte seq
HI_END_OF_BODY: int = 0x49    # Byte seq
HI_WHO: int = 0x4A            # Byte seq
HI_CONNECTION_ID: int = 0xCB  # 4-byte
HI_APP_PARAMS: int = 0x4C     # Byte seq
HI_AUTH_CHALLENGE: int = 0x4D # Byte seq
HI_AUTH_RESPONSE: int = 0x4E  # Byte seq
HI_OBJECT_CLASS: int = 0x51   # Byte seq

# ---------------------------------------------------------------------------
# Header type masks
# ---------------------------------------------------------------------------

HI_MASK: int = 0xC0
HI_UNICODE: int = 0x00    # top 2 bits = 00
HI_BYTESEQ: int = 0x40    # top 2 bits = 01
HI_BYTE1: int = 0x80      # top 2 bits = 10
HI_BYTE4: int = 0xC0      # top 2 bits = 11

# ---------------------------------------------------------------------------
# Profile Target UUIDs (16 bytes each)
# ---------------------------------------------------------------------------

PBAP_TARGET_UUID: bytes = bytes([
    0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8,
    0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
])

MAP_MAS_TARGET_UUID: bytes = bytes([
    0xBB, 0x58, 0x2B, 0x40, 0x42, 0x0C, 0x11, 0xDB,
    0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
])

MAP_MNS_TARGET_UUID: bytes = bytes([
    0xBB, 0x58, 0x2B, 0x41, 0x42, 0x0C, 0x11, 0xDB,
    0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
])

FTP_TARGET_UUID: bytes = bytes([
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2,
    0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09,
])

# ---------------------------------------------------------------------------
# PBAP Application Parameter Tags  (Tag -> expected length)
# ---------------------------------------------------------------------------

PBAP_TAG_ORDER: int = 0x01               # 1 byte
PBAP_TAG_SEARCH_VALUE: int = 0x02        # variable
PBAP_TAG_SEARCH_ATTRIBUTE: int = 0x03    # 1 byte
PBAP_TAG_MAX_LIST_COUNT: int = 0x04      # 2 bytes
PBAP_TAG_LIST_START_OFFSET: int = 0x05   # 2 bytes
PBAP_TAG_FILTER: int = 0x06             # 8 bytes
PBAP_TAG_FORMAT: int = 0x07             # 1 byte
PBAP_TAG_PHONEBOOK_SIZE: int = 0x08      # 2 bytes
PBAP_TAG_NEW_MISSED_CALLS: int = 0x09    # 1 byte
PBAP_TAG_PRIMARY_VERSION: int = 0x0A     # 16 bytes
PBAP_TAG_SECONDARY_VERSION: int = 0x0B   # 16 bytes
PBAP_TAG_VCARD_SELECTOR: int = 0x0C      # 8 bytes
PBAP_TAG_DATABASE_ID: int = 0x0D         # 16 bytes
PBAP_TAG_VCARD_SEL_OP: int = 0x0E        # 1 byte
PBAP_TAG_RESET_MISSED: int = 0x0F        # 1 byte
PBAP_TAG_SUPPORTED_FEATURES: int = 0x10  # 4 bytes

PBAP_TAG_LENGTHS: dict[int, int | None] = {
    PBAP_TAG_ORDER: 1,
    PBAP_TAG_SEARCH_VALUE: None,  # variable
    PBAP_TAG_SEARCH_ATTRIBUTE: 1,
    PBAP_TAG_MAX_LIST_COUNT: 2,
    PBAP_TAG_LIST_START_OFFSET: 2,
    PBAP_TAG_FILTER: 8,
    PBAP_TAG_FORMAT: 1,
    PBAP_TAG_PHONEBOOK_SIZE: 2,
    PBAP_TAG_NEW_MISSED_CALLS: 1,
    PBAP_TAG_PRIMARY_VERSION: 16,
    PBAP_TAG_SECONDARY_VERSION: 16,
    PBAP_TAG_VCARD_SELECTOR: 8,
    PBAP_TAG_DATABASE_ID: 16,
    PBAP_TAG_VCARD_SEL_OP: 1,
    PBAP_TAG_RESET_MISSED: 1,
    PBAP_TAG_SUPPORTED_FEATURES: 4,
}

# ---------------------------------------------------------------------------
# MAP Application Parameter Tags  (Tag -> expected length)
# ---------------------------------------------------------------------------

MAP_TAG_MAX_LIST_COUNT: int = 0x01       # 2 bytes
MAP_TAG_START_OFFSET: int = 0x02         # 2 bytes
MAP_TAG_FILTER_MSG_TYPE: int = 0x03      # 1 byte
MAP_TAG_FILTER_PERIOD_BEGIN: int = 0x04  # variable
MAP_TAG_FILTER_PERIOD_END: int = 0x05    # variable
MAP_TAG_FILTER_READ_STATUS: int = 0x06   # 1 byte
MAP_TAG_FILTER_RECIPIENT: int = 0x07     # variable
MAP_TAG_FILTER_ORIGINATOR: int = 0x08    # variable
MAP_TAG_FILTER_PRIORITY: int = 0x09      # 1 byte
MAP_TAG_ATTACHMENT: int = 0x0A           # 1 byte
MAP_TAG_TRANSPARENT: int = 0x0B          # 1 byte
MAP_TAG_RETRY: int = 0x0C               # 1 byte
MAP_TAG_NEW_MESSAGE: int = 0x0D          # 1 byte
MAP_TAG_NOTIFICATION_STATUS: int = 0x0E  # 1 byte
MAP_TAG_MAS_INSTANCE_ID: int = 0x0F      # 1 byte
MAP_TAG_PARAMETER_MASK: int = 0x10       # 4 bytes
MAP_TAG_FOLDER_LISTING_SIZE: int = 0x11  # 2 bytes
MAP_TAG_MSG_LISTING_SIZE: int = 0x12     # 2 bytes
MAP_TAG_SUBJECT_LENGTH: int = 0x13       # 1 byte
MAP_TAG_CHARSET: int = 0x14             # 1 byte
MAP_TAG_FRACTION_REQUEST: int = 0x15     # 1 byte
MAP_TAG_FRACTION_DELIVER: int = 0x16     # 1 byte
MAP_TAG_STATUS_INDICATOR: int = 0x17     # 1 byte
MAP_TAG_STATUS_VALUE: int = 0x18         # 1 byte
MAP_TAG_MSE_TIME: int = 0x19            # variable

MAP_TAG_LENGTHS: dict[int, int | None] = {
    MAP_TAG_MAX_LIST_COUNT: 2,
    MAP_TAG_START_OFFSET: 2,
    MAP_TAG_FILTER_MSG_TYPE: 1,
    MAP_TAG_FILTER_PERIOD_BEGIN: None,
    MAP_TAG_FILTER_PERIOD_END: None,
    MAP_TAG_FILTER_READ_STATUS: 1,
    MAP_TAG_FILTER_RECIPIENT: None,
    MAP_TAG_FILTER_ORIGINATOR: None,
    MAP_TAG_FILTER_PRIORITY: 1,
    MAP_TAG_ATTACHMENT: 1,
    MAP_TAG_TRANSPARENT: 1,
    MAP_TAG_RETRY: 1,
    MAP_TAG_NEW_MESSAGE: 1,
    MAP_TAG_NOTIFICATION_STATUS: 1,
    MAP_TAG_MAS_INSTANCE_ID: 1,
    MAP_TAG_PARAMETER_MASK: 4,
    MAP_TAG_FOLDER_LISTING_SIZE: 2,
    MAP_TAG_MSG_LISTING_SIZE: 2,
    MAP_TAG_SUBJECT_LENGTH: 1,
    MAP_TAG_CHARSET: 1,
    MAP_TAG_FRACTION_REQUEST: 1,
    MAP_TAG_FRACTION_DELIVER: 1,
    MAP_TAG_STATUS_INDICATOR: 1,
    MAP_TAG_STATUS_VALUE: 1,
    MAP_TAG_MSE_TIME: None,
}

# ---------------------------------------------------------------------------
# Type strings (ASCII, used in Type header with null terminator)
# ---------------------------------------------------------------------------

PBAP_TYPE_PHONEBOOK: bytes = b"x-bt/phonebook"
PBAP_TYPE_VCARD_LIST: bytes = b"x-bt/vcard-listing"
PBAP_TYPE_VCARD: bytes = b"x-bt/vcard"

MAP_TYPE_FOLDER_LIST: bytes = b"x-obex/folder-listing"
MAP_TYPE_MSG_LISTING: bytes = b"x-bt/MAP-msg-listing"
MAP_TYPE_MESSAGE: bytes = b"x-bt/message"
MAP_TYPE_NOTIF_REG: bytes = b"x-bt/MAP-NotificationRegistration"
MAP_TYPE_MSG_STATUS: bytes = b"x-bt/messageStatus"


# ===================================================================
# Header Builders
# ===================================================================

def build_unicode_header(hi: int, text: str) -> bytes:
    """Build a Unicode (type 0x00) header.

    Format: HI(1) + Length(2 BE, inclusive) + UTF-16BE encoded text + null
    terminator (0x0000).

    Args:
        hi: Header ID byte (upper 2 bits must be 0b00).
        text: Text to encode as UTF-16BE.

    Returns:
        Complete header bytes.
    """
    encoded = text.encode("utf-16-be") + b"\x00\x00"
    length = 1 + 2 + len(encoded)  # HI + length field + payload
    return bytes([hi]) + struct.pack(">H", length) + encoded


def build_byteseq_header(hi: int, data: bytes) -> bytes:
    """Build a byte-sequence (type 0x40) header.

    Format: HI(1) + Length(2 BE, inclusive) + raw bytes.

    Args:
        hi: Header ID byte (upper 2 bits must be 0b01).
        data: Raw byte payload.

    Returns:
        Complete header bytes.
    """
    length = 1 + 2 + len(data)
    return bytes([hi]) + struct.pack(">H", length) + data


def build_byte1_header(hi: int, value: int) -> bytes:
    """Build a 1-byte value (type 0x80) header.

    Format: HI(1) + Value(1).  Total 2 bytes, no length field.

    Args:
        hi: Header ID byte (upper 2 bits must be 0b10).
        value: Single byte value (0-255).

    Returns:
        Complete header bytes (always 2 bytes).
    """
    return bytes([hi, value & 0xFF])


def build_byte4_header(hi: int, value: int) -> bytes:
    """Build a 4-byte value (type 0xC0) header.

    Format: HI(1) + Value(4 BE).  Total 5 bytes, no length field.

    Args:
        hi: Header ID byte (upper 2 bits must be 0b11).
        value: 32-bit unsigned integer.

    Returns:
        Complete header bytes (always 5 bytes).
    """
    return bytes([hi]) + struct.pack(">I", value)


# ===================================================================
# Packet Builders
# ===================================================================

def build_obex_packet(opcode: int, body: bytes = b"") -> bytes:
    """Build a generic OBEX packet.

    Format: Opcode(1) + Length(2 BE, inclusive) + body.

    Args:
        opcode: OBEX opcode byte.
        body: Concatenated headers and/or extra fields.

    Returns:
        Complete OBEX packet.
    """
    length = 1 + 2 + len(body)
    return bytes([opcode]) + struct.pack(">H", length) + body


def build_connect(
    target_uuid: Optional[bytes] = None,
    version: int = 0x10,
    flags: int = 0x00,
    max_pkt_len: int = 0xFFFF,
) -> bytes:
    """Build an OBEX Connect request.

    Connect has a special format: Opcode(1) + Length(2) + Version(1) +
    Flags(1) + MaxPacketLength(2 BE) + Headers.

    Args:
        target_uuid: 16-byte profile UUID for directed connection (Target
            header).  ``None`` for undirected (OPP).
        version: OBEX version byte (default 0x10 = OBEX 1.0).
        flags: Reserved flags byte (default 0x00).
        max_pkt_len: Maximum packet length the client can receive.

    Returns:
        Complete Connect packet (minimum 7 bytes).
    """
    body = struct.pack(">BBH", version, flags, max_pkt_len)
    if target_uuid is not None:
        body += build_byteseq_header(HI_TARGET, target_uuid)
    length = 1 + 2 + len(body)
    return bytes([OBEX_CONNECT]) + struct.pack(">H", length) + body


def build_disconnect(connection_id: Optional[int] = None) -> bytes:
    """Build an OBEX Disconnect request.

    Args:
        connection_id: Optional Connection-ID to include.

    Returns:
        Complete Disconnect packet.
    """
    headers = b""
    if connection_id is not None:
        headers += build_byte4_header(HI_CONNECTION_ID, connection_id)
    return build_obex_packet(OBEX_DISCONNECT, headers)


def build_setpath(
    name: Optional[str] = None,
    backup: bool = False,
    no_create: bool = True,
) -> bytes:
    """Build an OBEX SetPath request.

    SetPath has extra fields: Flags(1) + Constants(1) before headers.

    Flags:
        Bit 0: Backup a level before applying name (cd ..).
        Bit 1: Don't create folder if it doesn't exist.

    Args:
        name: Folder name to navigate to.  ``None`` omits the Name header
            (backup-only).  Empty string resets to root.
        backup: Set the backup flag (cd .. first).
        no_create: Set the don't-create flag.

    Returns:
        Complete SetPath packet.
    """
    flags = (0x01 if backup else 0x00) | (0x02 if no_create else 0x00)
    body = bytes([flags, 0x00])  # flags + constants (reserved, must be 0)
    if name is not None:
        body += build_unicode_header(HI_NAME, name)
    length = 1 + 2 + len(body)
    return bytes([OBEX_SETPATH]) + struct.pack(">H", length) + body


def build_get(
    connection_id: int,
    name: str,
    type_str: bytes,
    app_params: bytes = b"",
    final: bool = True,
) -> bytes:
    """Build an OBEX Get request.

    Args:
        connection_id: Connection-ID from Connect response.
        name: Object name (UTF-16BE in Name header).
        type_str: MIME type bytes (null terminator appended automatically).
        app_params: Pre-built application parameters (raw TLV bytes).
        final: If True, use Get Final (0x83); otherwise Get (0x03).

    Returns:
        Complete Get / Get Final packet.
    """
    opcode = OBEX_GET_FINAL if final else OBEX_GET
    headers = build_byte4_header(HI_CONNECTION_ID, connection_id)
    headers += build_unicode_header(HI_NAME, name)
    headers += build_byteseq_header(HI_TYPE, type_str + b"\x00")
    if app_params:
        headers += build_byteseq_header(HI_APP_PARAMS, app_params)
    return build_obex_packet(opcode, headers)


def build_put(
    name: str,
    type_str: bytes,
    body_data: bytes = b"",
    final: bool = True,
    connection_id: Optional[int] = None,
) -> bytes:
    """Build an OBEX Put request.

    Uses End-of-Body for final packets and Body for intermediate packets.

    Args:
        name: Object name (UTF-16BE in Name header).
        type_str: MIME type bytes (null terminator appended automatically).
        body_data: Object body payload.
        final: If True, use Put Final with End-of-Body; otherwise Put
            with Body.
        connection_id: Connection-ID from Connect response.  ``None`` omits
            the header (appropriate for OPP which has no Target UUID).

    Returns:
        Complete Put / Put Final packet.
    """
    opcode = OBEX_PUT_FINAL if final else OBEX_PUT
    headers = b""
    if connection_id is not None:
        headers += build_byte4_header(HI_CONNECTION_ID, connection_id)
    headers += build_unicode_header(HI_NAME, name)
    headers += build_byteseq_header(HI_TYPE, type_str + b"\x00")
    if body_data:
        body_hi = HI_END_OF_BODY if final else HI_BODY
        headers += build_byteseq_header(body_hi, body_data)
    return build_obex_packet(opcode, headers)


def build_abort(connection_id: Optional[int] = None) -> bytes:
    """Build an OBEX Abort request.

    Args:
        connection_id: Optional Connection-ID header.

    Returns:
        Complete Abort packet.
    """
    headers = b""
    if connection_id is not None:
        headers += build_byte4_header(HI_CONNECTION_ID, connection_id)
    return build_obex_packet(OBEX_ABORT, headers)


# ===================================================================
# Application Parameters (TLV)
# ===================================================================

def build_app_params(tags: list[tuple[int, bytes]]) -> bytes:
    """Build TLV-encoded application parameters.

    Each entry is Tag(1) + Length(1) + Value(N).

    Args:
        tags: List of (tag_id, value_bytes) tuples.

    Returns:
        Concatenated TLV bytes suitable for an App-Parameters header.
    """
    result = b""
    for tag, value in tags:
        result += bytes([tag, len(value)]) + value
    return result


def build_pbap_app_params(
    max_count: Optional[int] = None,
    offset: Optional[int] = None,
    fmt: Optional[int] = None,
    filter_mask: Optional[int] = None,
    search_value: Optional[str] = None,
    search_attr: Optional[int] = None,
    order: Optional[int] = None,
) -> bytes:
    """Build PBAP-specific application parameters.

    All arguments are optional; only non-None values are included.

    Args:
        max_count: MaxListCount (uint16 BE).
        offset: ListStartOffset (uint16 BE).
        fmt: vCard format (0x00=2.1, 0x01=3.0).
        filter_mask: 64-bit vCard property filter bitmask.
        search_value: UTF-8 search string.
        search_attr: Search attribute (0=Name, 1=Number, 2=Sound).
        order: Sort order (0=Indexed, 1=Alpha, 2=Phonetic).

    Returns:
        TLV-encoded PBAP application parameters.
    """
    tags: list[tuple[int, bytes]] = []
    if order is not None:
        tags.append((PBAP_TAG_ORDER, bytes([order])))
    if search_value is not None:
        tags.append((PBAP_TAG_SEARCH_VALUE, search_value.encode("utf-8")))
    if search_attr is not None:
        tags.append((PBAP_TAG_SEARCH_ATTRIBUTE, bytes([search_attr])))
    if max_count is not None:
        tags.append((PBAP_TAG_MAX_LIST_COUNT, struct.pack(">H", max_count)))
    if offset is not None:
        tags.append((PBAP_TAG_LIST_START_OFFSET, struct.pack(">H", offset)))
    if filter_mask is not None:
        tags.append((PBAP_TAG_FILTER, struct.pack(">Q", filter_mask)))
    if fmt is not None:
        tags.append((PBAP_TAG_FORMAT, bytes([fmt])))
    return build_app_params(tags)


def build_map_app_params(
    max_count: Optional[int] = None,
    offset: Optional[int] = None,
    subject_length: Optional[int] = None,
    charset: Optional[int] = None,
    filter_msg_type: Optional[int] = None,
    parameter_mask: Optional[int] = None,
) -> bytes:
    """Build MAP-specific application parameters.

    All arguments are optional; only non-None values are included.

    Args:
        max_count: MaxListCount (uint16 BE).
        offset: StartOffset (uint16 BE).
        subject_length: Maximum subject characters (uint8, 1-255).
        charset: Character set (0x00=native, 0x01=UTF-8).
        filter_msg_type: Message type bitmask filter.
        parameter_mask: 32-bit attribute filter bitmask.

    Returns:
        TLV-encoded MAP application parameters.
    """
    tags: list[tuple[int, bytes]] = []
    if max_count is not None:
        tags.append((MAP_TAG_MAX_LIST_COUNT, struct.pack(">H", max_count)))
    if offset is not None:
        tags.append((MAP_TAG_START_OFFSET, struct.pack(">H", offset)))
    if filter_msg_type is not None:
        tags.append((MAP_TAG_FILTER_MSG_TYPE, bytes([filter_msg_type])))
    if subject_length is not None:
        tags.append((MAP_TAG_SUBJECT_LENGTH, bytes([subject_length])))
    if charset is not None:
        tags.append((MAP_TAG_CHARSET, bytes([charset])))
    if parameter_mask is not None:
        tags.append((MAP_TAG_PARAMETER_MASK, struct.pack(">I", parameter_mask)))
    return build_app_params(tags)


# ===================================================================
# Profile-Specific Builders — PBAP
# ===================================================================

def build_pbap_connect() -> bytes:
    """Build a PBAP Connect request (includes PBAP Target UUID)."""
    return build_connect(target_uuid=PBAP_TARGET_UUID)


def build_pbap_pull_phonebook(
    path: str = "telecom/pb.vcf",
    max_count: int = 0xFFFF,
    offset: int = 0,
    fmt: int = 0,
) -> bytes:
    """Build a PBAP PullPhoneBook request (Get Final).

    Args:
        path: Phonebook path (e.g. "telecom/pb.vcf").
        max_count: Maximum entries to return.
        offset: Starting offset.
        fmt: vCard format (0=2.1, 1=3.0).

    Returns:
        Complete Get Final packet for PullPhoneBook.

    Note:
        Uses connection_id=1 as placeholder; callers should substitute the
        actual Connection-ID from the Connect response.
    """
    app_params = build_pbap_app_params(
        max_count=max_count, offset=offset, fmt=fmt,
    )
    return build_get(1, path, PBAP_TYPE_PHONEBOOK, app_params)


def build_pbap_pull_vcard_listing(
    folder: str = "telecom/pb",
    max_count: int = 0xFFFF,
    offset: int = 0,
) -> bytes:
    """Build a PBAP PullvCardListing request (Get Final).

    Args:
        folder: Folder path to list (e.g. "telecom/pb").
        max_count: Maximum entries.
        offset: Starting offset.

    Returns:
        Complete Get Final packet for PullvCardListing.
    """
    app_params = build_pbap_app_params(max_count=max_count, offset=offset)
    return build_get(1, folder, PBAP_TYPE_VCARD_LIST, app_params)


# ===================================================================
# Profile-Specific Builders — MAP
# ===================================================================

def build_map_connect() -> bytes:
    """Build a MAP MAS Connect request (includes MAP MAS Target UUID)."""
    return build_connect(target_uuid=MAP_MAS_TARGET_UUID)


def build_map_get_folder_listing(connection_id: int = 1) -> bytes:
    """Build a MAP GetFolderListing request.

    Args:
        connection_id: Connection-ID from Connect response.

    Returns:
        Complete Get Final packet for folder listing.
    """
    return build_get(connection_id, "", MAP_TYPE_FOLDER_LIST)


def build_map_get_msg_listing(
    connection_id: int = 1,
    folder: str = "inbox",
    max_count: int = 10,
    subject_length: int = 30,
) -> bytes:
    """Build a MAP GetMessagesListing request.

    Args:
        connection_id: Connection-ID.
        folder: Message folder name (e.g. "inbox").
        max_count: Maximum messages to return.
        subject_length: Maximum subject characters in listing.

    Returns:
        Complete Get Final packet for message listing.
    """
    app_params = build_map_app_params(
        max_count=max_count, subject_length=subject_length,
    )
    return build_get(connection_id, folder, MAP_TYPE_MSG_LISTING, app_params)


def build_map_get_message(
    connection_id: int = 1,
    handle: str = "00000001",
) -> bytes:
    """Build a MAP GetMessage request.

    Args:
        connection_id: Connection-ID.
        handle: Message handle string.

    Returns:
        Complete Get Final packet for a single message.
    """
    app_params = build_map_app_params(charset=0x01)  # UTF-8
    return build_get(connection_id, handle, MAP_TYPE_MESSAGE, app_params)


# ===================================================================
# Profile-Specific Builders — OPP
# ===================================================================

def build_opp_connect() -> bytes:
    """Build an OPP Connect request (no Target header — undirected)."""
    return build_connect(target_uuid=None)


def build_opp_push(
    name: str,
    type_str: bytes,
    body_data: bytes,
) -> bytes:
    """Build an OPP object push (Put Final).

    Args:
        name: Object name (e.g. "contact.vcf").
        type_str: MIME type (e.g. b"text/x-vcard").
        body_data: Full file contents.

    Returns:
        Complete Put Final packet with object data.
    """
    return build_put(
        name=name,
        type_str=type_str,
        body_data=body_data,
        final=True,
        connection_id=None,  # OPP has no Target UUID, so no Connection-ID
    )


# ===================================================================
# Fuzzing Helpers
# ===================================================================

def fuzz_packet_length(packet: bytes) -> list[bytes]:
    """Generate variants with corrupted 2-byte packet length field.

    Replaces bytes [1:3] (the big-endian length) with various invalid values.

    Args:
        packet: Well-formed OBEX packet (minimum 3 bytes).

    Returns:
        List of mutated packets with bad length values.
    """
    if len(packet) < 3:
        return [packet]
    results: list[bytes] = []
    actual = len(packet)
    for new_len in [0, 1, 2, actual - 1, actual + 1, 0xFFFF]:
        mutated = packet[0:1] + struct.pack(">H", new_len) + packet[3:]
        results.append(mutated)
    return results


def fuzz_header_length(header: bytes) -> list[bytes]:
    """Generate variants with corrupted variable-header length field.

    Only meaningful for Unicode (0x00) and byte-sequence (0x40) headers
    that have a 2-byte length at positions [1:3].

    Args:
        header: Well-formed variable-length OBEX header.

    Returns:
        List of mutated headers with bad length values.
    """
    if len(header) < 3:
        return [header]
    results: list[bytes] = []
    for new_len in [0, 1, 2, 0xFFFF]:
        mutated = header[0:1] + struct.pack(">H", new_len) + header[3:]
        results.append(mutated)
    return results


def build_path_traversal_name(depth: int = 5) -> bytes:
    """Build a Name header with path traversal payload.

    Generates ``../`` repeated *depth* times followed by ``etc/passwd``,
    encoded as UTF-16BE in a Unicode Name header.

    Args:
        depth: Number of ``../`` levels to traverse.

    Returns:
        Complete Name header with traversal payload.
    """
    path = "../" * depth + "etc/passwd"
    return build_unicode_header(HI_NAME, path)


def fuzz_unicode_odd_bytes() -> bytes:
    """Build a Unicode header with an odd number of value bytes.

    UTF-16BE requires an even number of bytes.  This header has 3 value bytes,
    which is invalid and may trigger parser errors.

    Returns:
        Malformed Unicode Name header.
    """
    # HI=0x01 (Name), Length=6 (1+2+3), 3 raw bytes (odd = invalid UTF-16)
    return bytes([HI_NAME]) + struct.pack(">H", 6) + b"\x00\x41\x42"


def fuzz_unicode_no_null() -> bytes:
    """Build a Unicode header without the required null terminator.

    OBEX Unicode headers must end with 0x0000.  Omitting it may cause
    parsers to read past the header boundary.

    Returns:
        Malformed Unicode Name header (no null terminator).
    """
    text_bytes = "test".encode("utf-16-be")  # 8 bytes, no null
    length = 1 + 2 + len(text_bytes)
    return bytes([HI_NAME]) + struct.pack(">H", length) + text_bytes


def fuzz_app_param_tlv_overflow() -> bytes:
    """Build an App-Parameters header with TLV Length exceeding remaining data.

    The TLV says Length=0xFF but only 1 byte of value follows, causing a
    read past the header boundary.

    Returns:
        Malformed App-Parameters header.
    """
    # Tag=0x04 (MaxListCount), Length=0xFF (claims 255 bytes), Value=0x00 (only 1 byte)
    return build_byteseq_header(HI_APP_PARAMS, bytes([0x04, 0xFF, 0x00]))


def fuzz_duplicate_headers() -> bytes:
    """Build a packet body containing multiple Connection-ID headers.

    OBEX requires at most one Connection-ID per packet.  Duplicate headers
    may confuse stateful parsers or cause use of stale/conflicting IDs.

    Returns:
        OBEX Get Final packet with two Connection-ID headers.
    """
    headers = (
        build_byte4_header(HI_CONNECTION_ID, 1)
        + build_byte4_header(HI_CONNECTION_ID, 2)
        + build_unicode_header(HI_NAME, "test.vcf")
        + build_byteseq_header(HI_TYPE, PBAP_TYPE_PHONEBOOK + b"\x00")
    )
    return build_obex_packet(OBEX_GET_FINAL, headers)


def fuzz_connect_attacks() -> list[bytes]:
    """Generate malformed Connect packets targeting parser edge cases.

    Returns:
        List of malformed Connect packets:
        - MaxPktLen=0 (zero-size negotiation)
        - MaxPktLen=1 (impossibly small)
        - Version=0xFF (unknown version)
        - Flags=0xFF (all reserved bits set)
        - Truncated (missing MaxPktLen field)
    """
    results: list[bytes] = []
    # MaxPktLen=0
    results.append(build_connect(version=0x10, flags=0x00, max_pkt_len=0))
    # MaxPktLen=1
    results.append(build_connect(version=0x10, flags=0x00, max_pkt_len=1))
    # Bad version
    results.append(build_connect(version=0xFF, flags=0x00, max_pkt_len=0xFFFF))
    # All flags set
    results.append(build_connect(version=0x10, flags=0xFF, max_pkt_len=0xFFFF))
    # Truncated: opcode + length + version only (missing flags + maxpktlen)
    results.append(bytes([OBEX_CONNECT]) + struct.pack(">H", 4) + bytes([0x10]))
    return results


def fuzz_setpath_attacks() -> list[bytes]:
    """Generate malformed SetPath packets targeting parser edge cases.

    Returns:
        List of malformed SetPath packets:
        - Undefined flag bits set (bits 2-7)
        - Non-zero constants byte
        - Deep nesting sequence (1000 levels)
        - Path traversal name
    """
    results: list[bytes] = []

    # Undefined flag bits (bits 2-7 all set)
    body = bytes([0xFC, 0x00])  # flags=0xFC (reserved bits), constants=0x00
    body += build_unicode_header(HI_NAME, "test")
    results.append(
        bytes([OBEX_SETPATH]) + struct.pack(">H", 1 + 2 + len(body)) + body
    )

    # Non-zero constants byte
    body = bytes([0x02, 0xFF])  # flags=no_create, constants=0xFF (should be 0)
    body += build_unicode_header(HI_NAME, "test")
    results.append(
        bytes([OBEX_SETPATH]) + struct.pack(">H", 1 + 2 + len(body)) + body
    )

    # Deep nesting: 1000 SetPath descents
    deep_sequence: list[bytes] = []
    for i in range(1000):
        deep_sequence.append(build_setpath(name=f"dir{i}", no_create=True))
    results.extend(deep_sequence)

    # Path traversal via SetPath
    results.append(build_setpath(name="../../../etc/passwd", backup=True))

    return results


def fuzz_session_attacks() -> list[list[bytes]]:
    """Generate out-of-order session-level attack sequences.

    Each inner list is a sequence of OBEX packets to send in order.

    Returns:
        List of attack sequences:
        - Get before Connect
        - Double Connect
        - Abort without pending operation
        - Disconnect then Get
        - Interleaved Put and Get
        - Rapid connect/disconnect (resource exhaustion)
    """
    return [
        # Get before Connect (no session established)
        [build_get(1, "pb.vcf", PBAP_TYPE_PHONEBOOK)],
        # Double Connect
        [build_pbap_connect(), build_pbap_connect()],
        # Abort without pending operation
        [build_pbap_connect(), build_abort(connection_id=1)],
        # Disconnect then Get
        [
            build_pbap_connect(),
            build_disconnect(connection_id=1),
            build_pbap_pull_phonebook(),
        ],
        # Interleaved Put and Get
        [
            build_pbap_connect(),
            build_put("test.vcf", b"text/x-vcard", b"BEGIN:VCARD", final=False, connection_id=1),
            build_get(1, "pb.vcf", PBAP_TYPE_PHONEBOOK),
        ],
        # Rapid connect/disconnect (resource exhaustion)
        [
            item
            for _ in range(50)
            for item in (build_pbap_connect(), build_disconnect(connection_id=1))
        ],
        # Stale Connection-ID (use ID from hypothetical prior session)
        [build_pbap_connect(), build_get(0xDEADBEEF, "pb.vcf", PBAP_TYPE_PHONEBOOK)],
    ]


# ===================================================================
# Master Generator
# ===================================================================

def generate_all_obex_fuzz_cases(
    profile: str = "pbap",
) -> list[bytes | list[bytes]]:
    """Generate a comprehensive list of OBEX fuzz cases for a profile.

    Combines well-formed packets with all fuzzing helpers for thorough
    coverage of packet-level, header-level, TLV-level, and session-level
    attack surface.

    Args:
        profile: One of "pbap", "map", or "opp".

    Returns:
        Mixed list of single packets (``bytes``) and multi-packet sequences
        (``list[bytes]``) for session-level attacks.
    """
    cases: list[bytes | list[bytes]] = []

    # --- Profile-specific well-formed seeds ---
    if profile == "pbap":
        connect = build_pbap_connect()
        cases.append(connect)
        cases.append(build_pbap_pull_phonebook())
        cases.append(build_pbap_pull_phonebook("telecom/ich.vcf"))
        cases.append(build_pbap_pull_phonebook("telecom/mch.vcf"))
        cases.append(build_pbap_pull_phonebook("SIM1/telecom/pb.vcf"))
        cases.append(build_pbap_pull_vcard_listing())
        cases.append(build_pbap_pull_vcard_listing("telecom/ich"))
    elif profile == "map":
        connect = build_map_connect()
        cases.append(connect)
        cases.append(build_map_get_folder_listing())
        cases.append(build_map_get_msg_listing())
        cases.append(build_map_get_msg_listing(folder="sent"))
        cases.append(build_map_get_message())
    elif profile == "opp":
        connect = build_opp_connect()
        cases.append(connect)
        cases.append(build_opp_push("test.vcf", b"text/x-vcard", b"BEGIN:VCARD\r\nEND:VCARD"))
        cases.append(build_opp_push("photo.jpg", b"image/jpeg", b"\xFF\xD8\xFF" + b"\x00" * 100))
    else:
        connect = build_pbap_connect()
        cases.append(connect)

    # --- Packet length corruption on each seed ---
    for seed in list(cases):
        if isinstance(seed, bytes):
            cases.extend(fuzz_packet_length(seed))

    # --- Header-level fuzzing (wrapped in OBEX packets) ---
    # Path traversal names wrapped in SetPath packets
    cases.append(build_setpath(name="../" * 5 + "etc/passwd", backup=True))
    cases.append(build_setpath(name="../" * 20 + "etc/passwd", backup=True))
    # Malformed Unicode headers wrapped in Get Final packets
    cases.append(build_obex_packet(OBEX_GET_FINAL, fuzz_unicode_odd_bytes()))
    cases.append(build_obex_packet(OBEX_GET_FINAL, fuzz_unicode_no_null()))
    cases.append(fuzz_duplicate_headers())

    # Corrupt individual header lengths
    for hi, data in [
        (HI_NAME, "test".encode("utf-16-be") + b"\x00\x00"),
        (HI_TYPE, PBAP_TYPE_PHONEBOOK + b"\x00"),
        (HI_TARGET, PBAP_TARGET_UUID),
    ]:
        well_formed = build_byteseq_header(hi, data) if (hi & HI_MASK) == HI_BYTESEQ else build_unicode_header(hi, "test")
        cases.extend(fuzz_header_length(well_formed))

    # --- App-Parameters TLV fuzzing ---
    cases.append(fuzz_app_param_tlv_overflow())

    # TLV with Length=0
    cases.append(build_byteseq_header(HI_APP_PARAMS, bytes([0x04, 0x00])))
    # Unknown tag
    cases.append(build_byteseq_header(HI_APP_PARAMS, bytes([0xFF, 0x01, 0xAA])))
    # Duplicate tags
    cases.append(
        build_byteseq_header(
            HI_APP_PARAMS,
            bytes([0x04, 0x02, 0x00, 0x01, 0x04, 0x02, 0x00, 0x02]),
        )
    )
    # MaxListCount = 0xFFFF
    cases.append(
        build_byteseq_header(
            HI_APP_PARAMS,
            build_app_params([(0x04, struct.pack(">H", 0xFFFF))]),
        )
    )
    # Filter = all bits set
    cases.append(
        build_byteseq_header(
            HI_APP_PARAMS,
            build_app_params([(0x06, b"\xFF" * 8)]),
        )
    )
    # Format = invalid value
    cases.append(
        build_byteseq_header(
            HI_APP_PARAMS,
            build_app_params([(0x07, bytes([0xFF]))]),
        )
    )
    # Wrong length for fixed-size tag (MaxListCount with 1 byte instead of 2)
    cases.append(
        build_byteseq_header(HI_APP_PARAMS, bytes([0x04, 0x01, 0xFF]))
    )

    # --- Connect attacks ---
    cases.extend(fuzz_connect_attacks())

    # --- SetPath attacks ---
    cases.extend(fuzz_setpath_attacks())

    # --- Session-level attacks (multi-packet sequences) ---
    cases.extend(fuzz_session_attacks())

    # --- Unknown/reserved opcodes ---
    for opcode in [0x00, 0x04, 0x05, 0x06, 0x7F]:
        cases.append(build_obex_packet(opcode, b""))

    # --- Disconnect ---
    cases.append(build_disconnect(connection_id=1))
    cases.append(build_disconnect())  # no connection ID

    return cases
