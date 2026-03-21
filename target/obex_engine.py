"""OBEX binary protocol engine for the Vulnerable IVI Simulator.

Implements parsing, building, chunking, and session state management for
OBEX over RFCOMM. Used by PBAP, MAP, and OPP server implementations.

OBEX packet format:
    Byte 0:    Opcode (0x80=Connect, 0x81=Disconnect, 0x83=Get, etc.)
    Bytes 1-2: Total packet length (big-endian, includes opcode+length)
    Bytes 3+:  Opcode-specific body + headers

OBEX header encoding (determined by high 2 bits of Header ID):
    0x00-0x3F: Unicode string — HI(1B) + Length(2B) + UTF-16-BE data
    0x40-0x7F: Byte sequence  — HI(1B) + Length(2B) + raw data
    0x80-0xBF: 1-byte value   — HI(1B) + value(1B)
    0xC0-0xFF: 4-byte value   — HI(1B) + value(4B)
    Length fields are big-endian and INCLUDE the HI byte and length bytes.
"""

import struct
from ivi_config import (
    OBEX_CONNECT, OBEX_DISCONNECT, OBEX_PUT, OBEX_PUT_FINAL,
    OBEX_GET, OBEX_GET_FINAL, OBEX_SETPATH,
    OBEX_SUCCESS, OBEX_CONTINUE, OBEX_BAD_REQUEST,
    OBEX_UNAUTHORIZED, OBEX_NOT_FOUND, OBEX_INTERNAL_ERROR,
    HDR_NAME, HDR_TYPE, HDR_TARGET, HDR_BODY, HDR_END_OF_BODY,
    HDR_WHO, HDR_APP_PARAMS, HDR_CONNECTION_ID, HDR_LENGTH,
)
from ivi_log import log


# ============================================================================
# PARSING
# ============================================================================

def parse_packet(data: bytes) -> dict:
    """Parse an OBEX packet into its components.

    Returns dict with keys: opcode, length, headers (raw list),
    plus opcode-specific fields (version, flags, max_packet for CONNECT;
    setpath_flags for SETPATH).
    """
    if len(data) < 3:
        return {"opcode": 0, "length": 0, "error": "packet too short"}

    opcode = data[0]
    length = struct.unpack(">H", data[1:3])[0]

    result = {
        "opcode": opcode,
        "length": length,
    }

    # Limit parsing to declared length (ignore trailing garbage)
    packet_data = data[:length]

    # Connect requests AND responses share the same body format:
    # version(1) + flags(1) + max_packet(2) + headers (starting at offset 7)
    _connect_opcodes = {OBEX_CONNECT, OBEX_SUCCESS, OBEX_CONTINUE}
    # Heuristic: if packet has version byte 0x10 at offset 3, treat as Connect format.
    # This avoids misinterpreting a plain SUCCESS response as Connect format.
    _is_connect_format = (
        opcode in _connect_opcodes
        and len(data) >= 7
        and data[3] == 0x10  # OBEX version 1.0
    )

    if _is_connect_format:
        # Connect format: opcode(1) + len(2) + version(1) + flags(1) + max_packet(2) + headers
        if len(packet_data) < 7:
            result["error"] = "CONNECT packet truncated"
            result["headers"] = {}
            return result
        result["version"] = packet_data[3]
        result["flags"] = packet_data[4]
        result["max_packet"] = struct.unpack(">H", packet_data[5:7])[0]
        raw_headers = parse_headers(packet_data, 7)
        result["headers"] = extract_headers(raw_headers)

    elif opcode == OBEX_SETPATH:
        # SetPath: opcode(1) + len(2) + flags(1) + constants(1) + headers
        if len(packet_data) < 5:
            result["error"] = "SETPATH packet truncated"
            result["headers"] = {}
            return result
        result["setpath_flags"] = packet_data[3]
        result["setpath_constants"] = packet_data[4]
        raw_headers = parse_headers(packet_data, 5)
        result["headers"] = extract_headers(raw_headers)

    elif opcode in (OBEX_GET, OBEX_GET_FINAL, OBEX_PUT, OBEX_PUT_FINAL,
                    OBEX_DISCONNECT):
        # Standard: opcode(1) + len(2) + headers
        raw_headers = parse_headers(packet_data, 3)
        result["headers"] = extract_headers(raw_headers)

    else:
        # Unknown opcode — try to parse headers anyway
        raw_headers = parse_headers(packet_data, 3)
        result["headers"] = extract_headers(raw_headers)

    return result


def parse_headers(data: bytes, offset: int) -> list[tuple[int, bytes]]:
    """Parse OBEX headers from a byte stream starting at offset.

    Returns list of (header_id, raw_value) tuples.
    Value encoding depends on header type (caller uses extract_headers to decode).
    """
    headers = []
    pos = offset

    while pos < len(data):
        if pos >= len(data):
            break

        hi = data[pos]
        hi_type = hi & 0xC0  # high 2 bits determine encoding

        try:
            if hi_type == 0x00 or hi_type == 0x40:
                # Unicode string (0x00) or byte sequence (0x40)
                # Format: HI(1B) + Length(2B, includes HI+len) + data
                if pos + 3 > len(data):
                    break
                hdr_len = struct.unpack(">H", data[pos + 1:pos + 3])[0]
                if hdr_len < 3:
                    break  # invalid length
                value = data[pos + 3:pos + hdr_len]
                headers.append((hi, value))
                pos += hdr_len

            elif hi_type == 0x80:
                # 1-byte value
                if pos + 2 > len(data):
                    break
                value = data[pos + 1:pos + 2]
                headers.append((hi, value))
                pos += 2

            elif hi_type == 0xC0:
                # 4-byte value
                if pos + 5 > len(data):
                    break
                value = data[pos + 1:pos + 5]
                headers.append((hi, value))
                pos += 5

            else:
                break  # shouldn't happen, but safety

        except (struct.error, IndexError):
            break  # malformed data, stop parsing

    return headers


def extract_headers(raw_headers: list[tuple[int, bytes]]) -> dict:
    """Decode raw OBEX headers into a usable dict.

    Keys: name, type, target, body, end_of_body, connection_id,
    app_params, length, who, other.
    """
    result = {
        "name": None,
        "type": None,
        "target": None,
        "body": None,
        "end_of_body": None,
        "connection_id": None,
        "app_params": None,
        "length": None,
        "who": None,
        "other": [],
    }

    for hi, value in raw_headers:
        if hi == HDR_NAME:
            # UTF-16-BE string, strip null terminator
            try:
                text = value.decode("utf-16-be")
                result["name"] = text.rstrip("\x00")
            except UnicodeDecodeError:
                result["name"] = value.hex()

        elif hi == HDR_TYPE:
            # ASCII string, strip null terminator
            try:
                result["type"] = value.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                result["type"] = value.decode("latin-1").rstrip("\x00")

        elif hi == HDR_TARGET:
            result["target"] = value

        elif hi == HDR_BODY:
            result["body"] = value

        elif hi == HDR_END_OF_BODY:
            result["end_of_body"] = value

        elif hi == HDR_CONNECTION_ID:
            if len(value) == 4:
                result["connection_id"] = struct.unpack(">I", value)[0]
            else:
                result["connection_id"] = int.from_bytes(value, "big")

        elif hi == HDR_APP_PARAMS:
            result["app_params"] = value

        elif hi == HDR_LENGTH:
            if len(value) == 4:
                result["length"] = struct.unpack(">I", value)[0]
            else:
                result["length"] = int.from_bytes(value, "big")

        elif hi == HDR_WHO:
            result["who"] = value

        else:
            result["other"].append((hi, value))

    return result


def parse_app_params(data: bytes) -> dict:
    """Parse OBEX Application Parameters (TLV format).

    Returns dict mapping tag names to values.
    """
    params = {}
    pos = 0

    while pos + 2 <= len(data):
        tag = data[pos]
        tag_len = data[pos + 1]
        pos += 2

        if pos + tag_len > len(data):
            break

        value = data[pos:pos + tag_len]
        pos += tag_len

        # Decode known tags
        if tag == 0x04 and tag_len == 2:     # MaxListCount (PBAP)
            params["max_list_count"] = struct.unpack(">H", value)[0]
        elif tag == 0x05 and tag_len == 2:   # ListStartOffset (PBAP)
            params["list_start_offset"] = struct.unpack(">H", value)[0]
        elif tag == 0x06 and tag_len == 8:   # Filter (PBAP)
            params["filter"] = value
        elif tag == 0x07 and tag_len == 1:   # Format (PBAP)
            params["format"] = value[0]      # 0=vCard2.1, 1=vCard3.0
        elif tag == 0x08 and tag_len == 2:   # PhonebookSize (PBAP response)
            params["phonebook_size"] = struct.unpack(">H", value)[0]
        elif tag == 0x02 and tag_len == 1:   # SearchAttribute (PBAP)
            params["search_attribute"] = value[0]
        elif tag == 0x03:                    # SearchValue (PBAP, variable)
            try:
                params["search_value"] = value.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                params["search_value"] = value.hex()
        elif tag == 0x01 and tag_len == 2:   # MaxListCount (MAP)
            params["max_list_count"] = struct.unpack(">H", value)[0]
        elif tag == 0x14 and tag_len == 1:   # Charset (MAP)
            params["charset"] = value[0]     # 1=UTF-8
        elif tag == 0x0E and tag_len == 1:   # NotificationStatus (MAP)
            params["notification_status"] = value[0]
        elif tag == 0x17 and tag_len == 1:   # StatusIndicator (MAP)
            params["status_indicator"] = value[0]
        elif tag == 0x18 and tag_len == 1:   # StatusValue (MAP)
            params["status_value"] = value[0]
        else:
            params[f"unknown_0x{tag:02x}"] = value

    return params


# ============================================================================
# BUILDING
# ============================================================================

def build_header_unicode(hi: int, text: str) -> bytes:
    """Build a Unicode string header (type 0x00-0x3F).

    Encodes text as UTF-16-BE with null terminator.
    Length field includes HI byte + 2 length bytes + data.
    """
    encoded = text.encode("utf-16-be") + b"\x00\x00"
    length = 3 + len(encoded)  # HI + 2-byte len + data
    return struct.pack(">BH", hi, length) + encoded


def build_header_bytes(hi: int, data: bytes) -> bytes:
    """Build a byte sequence header (type 0x40-0x7F).

    Length field includes HI byte + 2 length bytes + data.
    """
    length = 3 + len(data)
    return struct.pack(">BH", hi, length) + data


def build_header_u8(hi: int, value: int) -> bytes:
    """Build a 1-byte value header (type 0x80-0xBF)."""
    return struct.pack(">BB", hi, value & 0xFF)


def build_header_u32(hi: int, value: int) -> bytes:
    """Build a 4-byte value header (type 0xC0-0xFF)."""
    return struct.pack(">BI", hi, value)


def build_connection_id(conn_id: int) -> bytes:
    """Shortcut: build ConnectionID header (0xCB)."""
    return build_header_u32(HDR_CONNECTION_ID, conn_id)


def build_body(data: bytes, final: bool = False) -> bytes:
    """Build Body (0x48) or End-of-Body (0x49) header."""
    hi = HDR_END_OF_BODY if final else HDR_BODY
    return build_header_bytes(hi, data)


def build_who(uuid: bytes) -> bytes:
    """Build Who header (0x4A) — identifies service in Connect response."""
    return build_header_bytes(HDR_WHO, uuid)


def build_app_params_header(params: dict) -> bytes:
    """Build Application Parameters header (0x4C) from a dict.

    Supported keys: phonebook_size (tag 0x08, 2B),
                    new_message (tag 0x0D, 1B).
    """
    tlv = b""

    if "phonebook_size" in params:
        tlv += struct.pack(">BBH", 0x08, 2, params["phonebook_size"])
    if "new_message" in params:
        tlv += struct.pack(">BBB", 0x0D, 1, params["new_message"])

    if not tlv:
        return b""

    return build_header_bytes(HDR_APP_PARAMS, tlv)


def build_response(opcode: int, *header_parts: bytes) -> bytes:
    """Build a standard OBEX response packet (non-Connect).

    Format: opcode(1B) + length(2B) + concatenated headers.
    """
    headers = b"".join(header_parts)
    length = 3 + len(headers)  # opcode + 2-byte len + headers
    return struct.pack(">BH", opcode, length) + headers


def build_connect_response(opcode: int, *header_parts: bytes) -> bytes:
    """Build an OBEX Connect response packet.

    Format: opcode(1B) + length(2B) + version(1B) + flags(1B)
            + max_packet(2B) + headers.
    """
    headers = b"".join(header_parts)
    length = 7 + len(headers)  # opcode(1) + len(2) + ver(1) + flags(1) + maxpkt(2) + headers
    return struct.pack(">BHBBH", opcode, length, 0x10, 0x00, 0xFFFF) + headers


# ============================================================================
# CHUNKING
# ============================================================================

def chunked_response(data: bytes, conn_id: int,
                     max_packet: int = 4096) -> list[bytes]:
    """Split a large response body into OBEX CONTINUE + SUCCESS packets.

    Returns a list of complete OBEX response packets:
    - First N-1 packets: CONTINUE (0x90) + ConnectionID + Body (0x48) + chunk
    - Last packet:       SUCCESS (0xA0) + ConnectionID + End-of-Body (0x49) + chunk

    Each packet respects max_packet size limit.
    """
    # Overhead per packet:
    #   opcode(1) + length(2) + ConnectionID header(5) + Body/EOB header(3+len)
    #   Body header: HI(1) + len(2) + data = 3 + data_len
    #   Total overhead: 3 + 5 + 3 = 11 bytes
    overhead = 11
    chunk_size = max_packet - overhead
    if chunk_size < 1:
        chunk_size = 1  # absolute minimum

    # Edge case: empty data
    if not data:
        packet = build_response(
            OBEX_SUCCESS,
            build_connection_id(conn_id),
            build_body(b"", final=True),
        )
        return [packet]

    # Edge case: fits in single packet
    if len(data) <= chunk_size:
        packet = build_response(
            OBEX_SUCCESS,
            build_connection_id(conn_id),
            build_body(data, final=True),
        )
        return [packet]

    # Multi-packet response
    packets = []
    offset = 0

    while offset < len(data):
        chunk = data[offset:offset + chunk_size]
        remaining = len(data) - offset - len(chunk)

        if remaining <= 0:
            # Final chunk
            packet = build_response(
                OBEX_SUCCESS,
                build_connection_id(conn_id),
                build_body(chunk, final=True),
            )
        else:
            # Intermediate chunk
            packet = build_response(
                OBEX_CONTINUE,
                build_connection_id(conn_id),
                build_body(chunk, final=False),
            )

        packets.append(packet)
        offset += len(chunk)

    return packets


# ============================================================================
# SESSION STATE MACHINE
# ============================================================================

class OBEXSession:
    """Base OBEX session handler — tracks connection state and dispatches opcodes.

    Subclass and override on_get(), on_put() for profile-specific behavior
    (PBAP, MAP, OPP).
    """

    def __init__(self, profile_name: str = "OBEX"):
        self.profile = profile_name
        self.connected = False
        self.connection_id = 0
        self.target_uuid = b""
        self.current_path: list[str] = []
        self.max_packet = 0xFFFF
        self.pending_chunks: list[bytes] = []
        self._put_buffer = b""
        self._put_name = ""

    def handle_packet(self, data: bytes) -> bytes | None:
        """Main dispatch: parse packet and route to handler.

        Returns response bytes to send back, or None if no response needed.
        """
        pkt = parse_packet(data)
        opcode = pkt.get("opcode", 0)

        log.obex("recv", opcode, pkt.get("length", 0))
        log.obex_hex("raw", data)

        if opcode == OBEX_CONNECT:
            return self._dispatch_connect(pkt)

        elif opcode in (OBEX_GET, OBEX_GET_FINAL):
            return self._dispatch_get(pkt)

        elif opcode == OBEX_SETPATH:
            return self._dispatch_setpath(pkt)

        elif opcode in (OBEX_PUT, OBEX_PUT_FINAL):
            return self._dispatch_put(pkt, final=(opcode == OBEX_PUT_FINAL))

        elif opcode == OBEX_DISCONNECT:
            return self._dispatch_disconnect(pkt)

        else:
            log.warn(self.profile, f"Unknown opcode 0x{opcode:02X}")
            return build_response(OBEX_INTERNAL_ERROR)

    # ── Connect ────────────────────────────────────────────────────────

    def _dispatch_connect(self, pkt: dict) -> bytes:
        headers = pkt.get("headers", {})
        target = headers.get("target")
        client_max = pkt.get("max_packet", 0xFFFF)

        # Negotiate max packet size (use smaller of client's and ours)
        self.max_packet = min(client_max, 0xFFFF)

        if target:
            self.target_uuid = target

        # Generate a connection ID
        import random
        self.connection_id = random.randint(1, 0xFFFFFFFF)
        self.connected = True
        self.current_path = []

        log.connection(self.profile, "", f"OBEX Connect (maxpkt={self.max_packet})")

        # Let subclass customize the response
        return self.on_connect(pkt)

    def on_connect(self, pkt: dict) -> bytes:
        """Override in subclass. Default: accept with ConnectionID + Who."""
        response_headers = build_connection_id(self.connection_id)
        if self.target_uuid:
            response_headers += build_who(self.target_uuid)
        resp = build_connect_response(OBEX_SUCCESS, response_headers)
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    # ── Get ─────────────────────────────────────────────────────────────

    def _dispatch_get(self, pkt: dict) -> bytes:
        headers = pkt.get("headers", {})

        # If we have pending chunks from a previous multi-packet GET,
        # a continuation GET (with no new Name/Type headers) means
        # "send the next chunk"
        if self.pending_chunks and headers.get("name") is None and headers.get("type") is None:
            chunk = self.pending_chunks.pop(0)
            log.obex("send", chunk[0], len(chunk))
            return chunk

        # Fresh GET — let subclass handle it
        response_data = self.on_get(pkt)

        if response_data is None:
            resp = build_response(OBEX_NOT_FOUND,
                                  build_connection_id(self.connection_id))
            log.obex("send", OBEX_NOT_FOUND, len(resp))
            return resp

        # If on_get returned a pre-built OBEX response packet (starts with
        # a valid response opcode), send it directly without chunking.
        # This is used for header-only responses like PBAP PhonebookSize.
        if len(response_data) >= 3 and response_data[0] in (
            OBEX_SUCCESS, OBEX_CONTINUE, OBEX_BAD_REQUEST,
            OBEX_UNAUTHORIZED, OBEX_NOT_FOUND, OBEX_INTERNAL_ERROR,
        ):
            declared_len = struct.unpack(">H", response_data[1:3])[0]
            if declared_len == len(response_data):
                # Looks like a complete OBEX packet — send directly
                log.obex("send", response_data[0], len(response_data))
                return response_data

        # Chunk the response
        chunks = chunked_response(response_data, self.connection_id,
                                  self.max_packet)

        if len(chunks) == 1:
            # Single packet — send directly
            log.obex("send", chunks[0][0], len(chunks[0]))
            return chunks[0]
        else:
            # Multi-packet — send first, queue rest
            self.pending_chunks = chunks[1:]
            log.info(self.profile,
                     f"Chunked response: {len(chunks)} packets "
                     f"({len(response_data)} bytes)")
            log.obex("send", chunks[0][0], len(chunks[0]))
            return chunks[0]

    def on_get(self, pkt: dict) -> bytes | None:
        """Override in subclass. Return body data bytes, or None for NOT_FOUND."""
        return None

    # ── SetPath ────────────────────────────────────────────────────────

    def _dispatch_setpath(self, pkt: dict) -> bytes:
        headers = pkt.get("headers", {})
        flags = pkt.get("setpath_flags", 0)

        if flags & 0x02:
            # Go to root
            self.current_path = []
            log.info(self.profile, "SetPath → / (root)")
        elif flags & 0x01:
            # Go up one level
            if self.current_path:
                removed = self.current_path.pop()
                log.info(self.profile, f"SetPath ← (up from {removed})")
            else:
                log.info(self.profile, "SetPath ← (already at root)")
        else:
            # Navigate into folder
            folder = headers.get("name", "")
            if folder:
                self.current_path.append(folder)
                log.info(self.profile,
                         f"SetPath → {'/'.join(self.current_path)}")
            else:
                # Empty name with no flags = go to root (PBAP convention)
                self.current_path = []
                log.info(self.profile, "SetPath → / (empty name)")

        self.on_setpath(pkt)

        resp = build_response(OBEX_SUCCESS,
                              build_connection_id(self.connection_id))
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    def on_setpath(self, pkt: dict):
        """Override in subclass for custom SetPath handling."""
        pass

    # ── Put ─────────────────────────────────────────────────────────────

    def _dispatch_put(self, pkt: dict, final: bool) -> bytes:
        headers = pkt.get("headers", {})

        # Track filename from first PUT packet
        if headers.get("name") and not self._put_name:
            self._put_name = headers["name"]

        # Accumulate body data
        if headers.get("body"):
            self._put_buffer += headers["body"]
        if headers.get("end_of_body"):
            self._put_buffer += headers["end_of_body"]

        if final:
            # PUT complete — hand off to subclass
            result = self.on_put(self._put_name, self._put_buffer, pkt)
            self._put_buffer = b""
            self._put_name = ""

            if result:
                resp = build_response(OBEX_SUCCESS,
                                      build_connection_id(self.connection_id))
            else:
                resp = build_response(OBEX_INTERNAL_ERROR,
                                      build_connection_id(self.connection_id))
            log.obex("send", resp[0], len(resp))
            return resp
        else:
            # Intermediate chunk — send CONTINUE
            resp = build_response(OBEX_CONTINUE,
                                  build_connection_id(self.connection_id))
            log.obex("send", OBEX_CONTINUE, len(resp))
            return resp

    def on_put(self, name: str, data: bytes, pkt: dict) -> bool:
        """Override in subclass. Return True to accept, False to reject."""
        return True

    # ── Disconnect ─────────────────────────────────────────────────────

    def _dispatch_disconnect(self, pkt: dict) -> bytes:
        self.connected = False
        self.pending_chunks = []
        self.current_path = []
        self._put_buffer = b""
        self._put_name = ""

        log.connection(self.profile, "", "OBEX Disconnect")

        resp = build_response(OBEX_SUCCESS,
                              build_connection_id(self.connection_id))
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    # ── Utility ────────────────────────────────────────────────────────

    @property
    def path_str(self) -> str:
        """Current path as a string."""
        return "/".join(self.current_path)
