"""OPP (Object Push Profile) for pushing files to IVI.

OPP allows pushing vCard, vCalendar, and other objects to the IVI.
Can be used to inject contacts, calendar entries, or test file handling.
"""

import os
import socket
import struct

from blue_tap.utils.output import info, success, error


OBEX_CONNECT = 0x80
OBEX_PUT = 0x82
OBEX_RESPONSE_SUCCESS = 0xA0
OBEX_RESPONSE_CONTINUE = 0x90
OBEX_HEADER_NAME = 0x01
OBEX_HEADER_LENGTH = 0xC3
OBEX_HEADER_BODY = 0x48
OBEX_HEADER_END_OF_BODY = 0x49


class OPPClient:
    """Object Push Profile client for pushing files to IVI.

    Usage:
        opp = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        opp.connect()
        opp.push_file("contact.vcf")
        opp.disconnect()
    """

    def __init__(self, address: str, channel: int):
        self.address = address
        self.channel = channel
        self.sock = None

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
            )
            self.sock.settimeout(15.0)
            self.sock.connect((self.address, self.channel))

            # OBEX Connect (no target UUID for OPP)
            packet = struct.pack(">BHBBH", OBEX_CONNECT, 7, 0x10, 0x00, 0xFFFF)
            self.sock.send(packet)
            response = self._recv()
            if response and response[0] == OBEX_RESPONSE_SUCCESS:
                success("OPP connected")
                return True
            error("OPP connect rejected")
            return False
        except OSError as e:
            error(f"OPP connect failed: {e}")
            return False

    def disconnect(self):
        if self.sock:
            try:
                # Send OBEX Disconnect
                pkt = struct.pack(">BH", 0x81, 3)
                self.sock.send(pkt)
                self._recv()
            except OSError:
                pass
            finally:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
            info("OPP disconnected")

    def push_file(self, filepath: str) -> bool:
        """Push a file to the remote device via OPP."""
        if not os.path.exists(filepath):
            error(f"File not found: {filepath}")
            return False

        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            data = f.read()

        info(f"Pushing {filename} ({len(data)} bytes)...")

        # Build PUT request
        headers = b""

        # Name header
        name_bytes = filename.encode("utf-16-be") + b"\x00\x00"
        headers += struct.pack(">BH", OBEX_HEADER_NAME, len(name_bytes) + 3) + name_bytes

        # Length header
        headers += struct.pack(">BI", OBEX_HEADER_LENGTH, len(data))

        # Body (or End-of-Body if small enough)
        max_body = 0xFFF0 - len(headers) - 6
        if len(data) <= max_body:
            headers += struct.pack(">BH", OBEX_HEADER_END_OF_BODY,
                                   len(data) + 3) + data
            packet = struct.pack(">BH", OBEX_PUT | 0x80, 3 + len(headers)) + headers
            self.sock.send(packet)
        else:
            # Multi-part PUT
            chunk = data[:max_body]
            rest = data[max_body:]
            headers += struct.pack(">BH", OBEX_HEADER_BODY, len(chunk) + 3) + chunk
            packet = struct.pack(">BH", OBEX_PUT, 3 + len(headers)) + headers
            self.sock.send(packet)

            response = self._recv()
            if not response or response[0] != OBEX_RESPONSE_CONTINUE:
                error("PUT rejected during transfer")
                return False

            # Send remaining chunks
            while rest:
                chunk = rest[:0xFFF0]
                rest = rest[len(chunk):]
                is_final = len(rest) == 0
                hid = OBEX_HEADER_END_OF_BODY if is_final else OBEX_HEADER_BODY
                body_hdr = struct.pack(">BH", hid, len(chunk) + 3) + chunk
                opcode = (OBEX_PUT | 0x80) if is_final else OBEX_PUT
                pkt = struct.pack(">BH", opcode, 3 + len(body_hdr)) + body_hdr
                self.sock.send(pkt)

                response = self._recv()
                expected = OBEX_RESPONSE_SUCCESS if is_final else OBEX_RESPONSE_CONTINUE
                if not response or response[0] != expected:
                    error("PUT failed mid-transfer")
                    return False

            success(f"Pushed: {filename}")
            return True

        response = self._recv()
        if response and response[0] == OBEX_RESPONSE_SUCCESS:
            success(f"Pushed: {filename}")
            return True
        error("PUT final response not OK")
        return False

    def push_vcard(self, name: str, phone: str, email: str = "") -> bool:
        """Push a crafted vCard contact to the IVI."""
        vcard = f"""BEGIN:VCARD
VERSION:3.0
FN:{name}
TEL;TYPE=CELL:{phone}
"""
        if email:
            vcard += f"EMAIL:{email}\n"
        vcard += "END:VCARD\n"

        tmpfile = "/tmp/blue_tap_push.vcf"
        with open(tmpfile, "w") as f:
            f.write(vcard)

        try:
            return self.push_file(tmpfile)
        finally:
            try:
                os.unlink(tmpfile)
            except OSError:
                pass

    def _recv(self) -> bytes | None:
        try:
            self.sock.settimeout(10.0)
            header = self.sock.recv(3)
            if len(header) < 3:
                return None
            length = struct.unpack(">H", header[1:3])[0]
            data = b""
            remaining = length - 3
            while remaining > 0:
                chunk = self.sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            return bytes([header[0]]) + header[1:3] + data
        except (socket.timeout, OSError):
            return None
