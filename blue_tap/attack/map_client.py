"""MAP (Message Access Profile) client for SMS/MMS extraction from IVI.

MAP uses OBEX over RFCOMM/L2CAP to access messages on the remote device.
The IVI typically mirrors messages from the paired phone.

Target UUID: 0x1132 (MAP MAS - Message Access Server)
OBEX Target: bb582b40-420c-11db-b0de-0800200c9a66 (MAP MAS)
"""

import os
import socket
import struct

from blue_tap.utils.output import info, success, error, warning


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
        """Disconnect MAP session cleanly with OBEX Disconnect."""
        if self.sock:
            try:
                # Send OBEX Disconnect
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
        import re as _re

        os.makedirs(output_dir, exist_ok=True)
        results = {}

        for folder in MAP_FOLDERS:
            folder_name = folder.split("/")[-1]
            listing = self.get_messages_listing(folder)
            if listing:
                listing_file = os.path.join(output_dir, f"{folder_name}_listing.xml")
                with open(listing_file, "w") as f:
                    f.write(listing)
                results[folder] = {"listing_file": listing_file, "messages": []}
                success(f"Saved listing: {listing_file}")

                # Parse message handles from XML listing
                # MAP listing XML uses <msg handle="XXXX" .../>
                handles = _re.findall(r'handle\s*=\s*"([^"]+)"', listing)
                if handles:
                    info(f"Found {len(handles)} message handle(s) in {folder_name}")
                    msg_dir = os.path.join(output_dir, folder_name)
                    os.makedirs(msg_dir, exist_ok=True)

                    for handle in handles:
                        try:
                            content = self.get_message(handle)
                            if content:
                                msg_file = os.path.join(msg_dir, f"{handle}.bmsg")
                                with open(msg_file, "w") as f:
                                    f.write(content)
                                results[folder]["messages"].append({
                                    "handle": handle,
                                    "file": msg_file,
                                })
                        except OSError as e:
                            warning(f"Failed to fetch message {handle}: {e}")

                    fetched = len(results[folder]["messages"])
                    if fetched:
                        success(f"Fetched {fetched}/{len(handles)} messages from {folder_name}")

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
        except (TimeoutError, OSError):
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

    def push_message(self, folder: str, recipient: str, body: str,
                      msg_type: str = "SMS_GSM") -> bool:
        """Send an SMS/MMS through the IVI via MAP PushMessage.

        This sends a message FROM the paired phone via the IVI's connection.
        Requires MAP write access (not all IVIs support this).

        Args:
            folder: Target folder (e.g., "telecom/msg/outbox")
            recipient: Phone number to send to
            body: Message text
            msg_type: Message type (SMS_GSM, SMS_CDMA, MMS, EMAIL)
        """
        info(f"Pushing {msg_type} to {recipient} via MAP...")

        if not self.set_folder(folder):
            error(f"Cannot navigate to {folder}")
            return False

        # Build bMessage format
        bmsg = (
            f"BEGIN:BMSG\r\n"
            f"VERSION:1.0\r\n"
            f"STATUS:UNREAD\r\n"
            f"TYPE:{msg_type}\r\n"
            f"FOLDER:{folder}\r\n"
            f"BEGIN:VCARD\r\n"
            f"VERSION:2.1\r\n"
            f"TEL:{recipient}\r\n"
            f"END:VCARD\r\n"
            f"BEGIN:BENV\r\n"
            f"BEGIN:BBODY\r\n"
            f"CHARSET:UTF-8\r\n"
            f"LENGTH:{len(body)}\r\n"
            f"BEGIN:MSG\r\n"
            f"{body}\r\n"
            f"END:MSG\r\n"
            f"END:BBODY\r\n"
            f"END:BENV\r\n"
            f"END:BMSG\r\n"
        )

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        # Type header
        type_str = b"x-bt/message\x00"
        headers += struct.pack(">BH", 0x42, len(type_str) + 3) + type_str

        # App params: Charset=UTF-8
        app_params = struct.pack(">BBB", 0x14, 0x01, 0x01)
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        # Body
        body_bytes = bmsg.encode("utf-8")
        headers += struct.pack(">BH", OBEX_HEADER_END_OF_BODY,
                               len(body_bytes) + 3) + body_bytes

        # OBEX PUT (0x82 = PUT-Final)
        packet = struct.pack(">BH", 0x82, 3 + len(headers)) + headers
        self.sock.send(packet)

        response = self._recv_response()
        if response and response[0] == OBEX_RESPONSE_SUCCESS:
            success(f"Message pushed to {recipient}")
            return True
        else:
            error("PushMessage failed — IVI may not support MAP write access")
            return False

    def set_message_status(self, handle: str, indicator: str,
                            value: bool) -> bool:
        """Set message status (read/deleted) on the IVI.

        Args:
            handle: Message handle from listing
            indicator: "read" or "deleted"
            value: True to set, False to clear

        This can be used to:
          - Mark messages as read (hide new message notifications)
          - Delete messages remotely
        """
        indicator_id = {"read": 0x00, "deleted": 0x01}.get(indicator)
        if indicator_id is None:
            error(f"Invalid indicator: {indicator} (use 'read' or 'deleted')")
            return False

        info(f"Setting message {handle} {indicator}={value}")

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        name_bytes = handle.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        type_str = b"x-bt/messageStatus\x00"
        headers += struct.pack(">BH", 0x42, len(type_str) + 3) + type_str

        # App params: StatusIndicator + StatusValue
        app_params = struct.pack(">BBB", 0x17, 0x01, indicator_id)
        app_params += struct.pack(">BBB", 0x18, 0x01, 0x01 if value else 0x00)
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", 0x82, 3 + len(headers)) + headers
        self.sock.send(packet)

        response = self._recv_response()
        if response and response[0] == OBEX_RESPONSE_SUCCESS:
            success(f"Message {handle} {indicator} set to {value}")
            return True
        error(f"SetMessageStatus failed for {handle}")
        return False

    def enable_notifications(self) -> bool:
        """Register for MAP event notifications (new message, delivery, etc).

        When enabled, the IVI will push events to us via MNS (Message
        Notification Server). Events include:
          - NewMessage: New SMS/MMS received
          - DeliverySuccess: Message delivered
          - SendingSuccess: Message sent
          - MessageDeleted: Message deleted
          - MessageShift: Message moved between folders

        Note: Requires running an MNS server (OBEX server) to receive events.
        This method only sends the registration request.
        """
        info("Registering for MAP event notifications...")

        headers = b""
        if self.connection_id is not None:
            headers += struct.pack(">BI", OBEX_HEADER_CONNECTION_ID, self.connection_id)

        type_str = b"x-bt/MAP-NotificationRegistration\x00"
        headers += struct.pack(">BH", 0x42, len(type_str) + 3) + type_str

        # App params: NotificationStatus = ON
        app_params = struct.pack(">BBB", 0x0E, 0x01, 0x01)
        headers += struct.pack(">BH", OBEX_HEADER_APP_PARAMS,
                               len(app_params) + 3) + app_params

        packet = struct.pack(">BH", 0x82, 3 + len(headers)) + headers
        self.sock.send(packet)

        response = self._recv_response()
        if response and response[0] == OBEX_RESPONSE_SUCCESS:
            success("MAP notifications enabled — listening for events")
            return True
        warning("Notification registration failed — IVI may not support MNS")
        return False

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


def parse_bmessage(bmsg_text: str) -> dict:
    """Parse a bMessage (MAP message format) into structured data.

    bMessage format contains: status, type, folder, sender vCard,
    recipient vCard, and message body.

    Returns:
        {"type": "SMS_GSM", "status": "READ", "folder": "...",
         "sender": "+1234567890", "sender_name": "John",
         "recipient": "+0987654321", "body": "Hello",
         "timestamp": "20240101T120000"}
    """
    result = {
        "type": "", "status": "", "folder": "",
        "sender": "", "sender_name": "",
        "recipient": "", "recipient_name": "",
        "body": "", "charset": "",
    }

    import re

    for line in bmsg_text.splitlines():
        line = line.strip()
        if line.startswith("TYPE:"):
            result["type"] = line.split(":", 1)[1].strip()
        elif line.startswith("STATUS:"):
            result["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("FOLDER:"):
            result["folder"] = line.split(":", 1)[1].strip()
        elif line.startswith("CHARSET:"):
            result["charset"] = line.split(":", 1)[1].strip()

    # Extract sender from first VCARD
    vcard_blocks = re.findall(r"BEGIN:VCARD\r?\n(.+?)END:VCARD", bmsg_text, re.DOTALL)
    if vcard_blocks:
        sender_vc = vcard_blocks[0]
        tel_m = re.search(r"TEL[^:]*:(.+)", sender_vc)
        if tel_m:
            result["sender"] = tel_m.group(1).strip()
        fn_m = re.search(r"FN:(.+)", sender_vc)
        if fn_m:
            result["sender_name"] = fn_m.group(1).strip()
        n_m = re.search(r"N:(.+)", sender_vc)
        if n_m and not result["sender_name"]:
            result["sender_name"] = n_m.group(1).strip()

    if len(vcard_blocks) > 1:
        recip_vc = vcard_blocks[1]
        tel_m = re.search(r"TEL[^:]*:(.+)", recip_vc)
        if tel_m:
            result["recipient"] = tel_m.group(1).strip()
        fn_m = re.search(r"FN:(.+)", recip_vc)
        if fn_m:
            result["recipient_name"] = fn_m.group(1).strip()

    # Extract message body
    msg_m = re.search(r"BEGIN:MSG\r?\n(.+?)END:MSG", bmsg_text, re.DOTALL)
    if msg_m:
        result["body"] = msg_m.group(1).strip()

    return result
