"""MAP (Message Access Profile) client for SMS/MMS extraction from IVI.

MAP uses OBEX over RFCOMM/L2CAP to access messages on the remote device.
The IVI typically mirrors messages from the paired phone.

Target UUID: 0x1132 (MAP MAS - Message Access Server)
OBEX Target: bb582b40-420c-11db-b0de-0800200c9a66 (MAP MAS)
"""

import os
import socket
import struct

from bt_tap.utils.output import info, success, error, warning


# MAP MAS OBEX Target UUID
MAP_MAS_TARGET_UUID = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")

OBEX_CONNECT = 0x80
OBEX_DISCONNECT = 0x81
OBEX_GET = 0x83
OBEX_SETPATH = 0x85
OBEX_RESPONSE_SUCCESS = 0xA0
OBEX_RESPONSE_CONTINUE = 0x90

OBEX_HEADER_NAME = 0x01
OBEX_HEADER_TYPE = 0x42
OBEX_HEADER_BODY = 0x48
OBEX_HEADER_END_OF_BODY = 0x49
OBEX_HEADER_TARGET = 0x46
OBEX_HEADER_CONNECTION_ID = 0xCB
OBEX_HEADER_APP_PARAMS = 0x4C

# MAP message types
MAP_MSG_TYPES = {
    0x00: "EMAIL",
    0x01: "SMS_GSM",
    0x02: "SMS_CDMA",
    0x03: "MMS",
    0x04: "IM",
}

# MAP folders
MAP_FOLDERS = [
    "telecom/msg/inbox",
    "telecom/msg/outbox",
    "telecom/msg/sent",
    "telecom/msg/deleted",
    "telecom/msg/draft",
]


class MAPClient:
    """MAP client for downloading SMS/MMS messages from IVI/phone.

    Usage:
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connect()
        messages = client.get_messages_listing("telecom/msg/inbox")
        for msg_handle in messages:
            content = client.get_message(msg_handle)
        client.disconnect()
    """

    def __init__(self, address: str, channel: int | None = None):
        self.address = address
        self.channel = channel
        self.sock = None
        self.connection_id = None

    def connect(self) -> bool:
        """Establish OBEX connection to MAP MAS server."""
        try:
            self.sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
            )
            info(f"Connecting MAP to {self.address} channel {self.channel}...")
            self.sock.connect((self.address, self.channel))
            success("RFCOMM connected for MAP")

            # OBEX Connect with MAP target
            target_header = struct.pack(">BH", OBEX_HEADER_TARGET,
                                        len(MAP_MAS_TARGET_UUID) + 3) + MAP_MAS_TARGET_UUID
            body = struct.pack(">BBH", 0x10, 0x00, 0xFFFF) + target_header
            packet = struct.pack(">BH", OBEX_CONNECT, 3 + len(body)) + body
            self.sock.send(packet)

            response = self._recv_response()
            if response and response[0] == OBEX_RESPONSE_SUCCESS:
                self._parse_connection_id(response)
                success(f"MAP session established (conn_id={self.connection_id})")
                return True
            else:
                error("MAP OBEX Connect rejected")
                return False

        except OSError as e:
            error(f"MAP connect failed: {e}")
            return False

    def disconnect(self):
        """Disconnect MAP session."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            info("MAP disconnected")

    def set_folder(self, path: str) -> bool:
        """Navigate to a MAP folder using OBEX SetPath."""
        # Navigate to root first
        self._setpath_root()

        # Then navigate down each component
        for component in path.split("/"):
            if not self._setpath_down(component):
                error(f"Failed to navigate to folder component: {component}")
                return False

        info(f"Current MAP folder: {path}")
        return True

    def get_messages_listing(self, folder: str = "telecom/msg/inbox",
                              max_count: int = 100) -> str:
        """Get listing of messages in a folder.

        Returns XML listing with message handles, subjects, senders, timestamps.
        """
        info(f"Listing messages in {folder}")

        if not self.set_folder(folder):
            return ""

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        # Type header for message listing
        type_str = b"x-bt/MAP-msg-listing\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        # App params: MaxListCount
        app_params = struct.pack(">BBH", 0x01, 0x02, max_count)
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", OBEX_GET, 3 + len(headers)) + headers
        self.sock.send(packet)

        body = self._recv_body()
        result = body.decode("utf-8", errors="replace")
        if result:
            success(f"Retrieved message listing ({len(result)} bytes)")
        return result

    def get_message(self, handle: str) -> str:
        """Get a specific message by handle.

        Returns the message in bMessage format (contains sender, recipient,
        timestamp, and message body).
        """
        info(f"Fetching message: {handle}")

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        # Name header (message handle)
        name_bytes = handle.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        # Type header
        type_str = b"x-bt/message\x00"
        headers += struct.pack(">BH", OBEX_HEADER_TYPE, len(type_str) + 3) + type_str

        # App params: charset=UTF-8
        app_params = struct.pack(">BBB", 0x14, 0x01, 0x01)  # Charset UTF-8
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", OBEX_GET, 3 + len(headers)) + headers
        self.sock.send(packet)

        body = self._recv_body()
        return body.decode("utf-8", errors="replace")

    def dump_all_messages(self, output_dir: str = "map_dump") -> dict:
        """Dump all messages from all folders."""
        os.makedirs(output_dir, exist_ok=True)
        results = {}

        for folder in MAP_FOLDERS:
            folder_name = folder.split("/")[-1]
            listing = self.get_messages_listing(folder)
            if listing:
                listing_file = os.path.join(output_dir, f"{folder_name}_listing.xml")
                with open(listing_file, "w") as f:
                    f.write(listing)
                results[folder] = {"listing_file": listing_file}
                success(f"Saved listing: {listing_file}")

                # TODO: Parse XML listing for handles and fetch each message
                # This requires XML parsing of the MAP listing format

        return results

    def _setpath_root(self):
        """Navigate to root folder."""
        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)
        # SetPath with flags=0x02 (go to root)
        body = struct.pack(">BB", 0x02, 0x00) + headers
        packet = struct.pack(">BH", OBEX_SETPATH, 3 + len(body)) + body
        self.sock.send(packet)
        self._recv_response()

    def _setpath_down(self, folder: str) -> bool:
        """Navigate down one folder level."""
        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)
        name_bytes = folder.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        body = struct.pack(">BB", 0x00, 0x00) + headers
        packet = struct.pack(">BH", OBEX_SETPATH, 3 + len(body)) + body
        self.sock.send(packet)

        response = self._recv_response()
        return response is not None and response[0] == OBEX_RESPONSE_SUCCESS

    def _recv_response(self) -> bytes | None:
        try:
            self.sock.settimeout(10.0)
            header = self.sock.recv(3)
            if len(header) < 3:
                return None
            length = struct.unpack(">H", header[1:3])[0]
            remaining = length - 3
            data = b""
            while remaining > 0:
                chunk = self.sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            return bytes([header[0]]) + header[1:3] + data
        except (socket.timeout, OSError):
            return None

    def _recv_body(self) -> bytes:
        """Receive multi-part OBEX body."""
        body = b""
        while True:
            response = self._recv_response()
            if response is None:
                break
            opcode = response[0]
            body += self._extract_body_data(response)
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
        return body

    def _extract_body_data(self, response: bytes) -> bytes:
        data = b""
        offset = 3
        while offset < len(response):
            hid = response[offset]
            if hid in (OBEX_HEADER_BODY, OBEX_HEADER_END_OF_BODY):
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                data += response[offset + 3:offset + length]
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
        return data

    def _parse_connection_id(self, response: bytes):
        offset = 7
        while offset < len(response):
            hid = response[offset]
            if hid == OBEX_HEADER_CONNECTION_ID:
                self.connection_id = struct.unpack(">I", response[offset + 1:offset + 5])[0]
                return
            elif hid & 0xC0 in (0x00, 0x40):
                length = struct.unpack(">H", response[offset + 1:offset + 3])[0]
                offset += length
            elif hid & 0xC0 == 0x80:
                offset += 2
            elif hid & 0xC0 == 0xC0:
                offset += 5
            else:
                break
