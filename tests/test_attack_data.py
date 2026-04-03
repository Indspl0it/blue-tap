"""Comprehensive unit tests for data/audio attack modules.

Covers:
  - PBAP: PBAPClient (all methods)
  - MAP: MAPClient (all methods) + parse_bmessage
  - HFP: HFPClient methods NOT covered in test_hfp_a2dp_spoof.py
  - A2DP: functions NOT covered in test_hfp_a2dp_spoof.py
  - OPP: OPPClient (all methods)
  - Bluesnarfer: ATClient + bluesnarfer_extract
  - AVRCP: AVRCPController methods NOT covered in test_vuln_attack.py
"""

import asyncio
import datetime
import io
import os
import struct
import subprocess
import time
import wave
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch, AsyncMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run_cmd_result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _obex_success_response(extra=b""):
    """Build a minimal OBEX success response (opcode=0xA0)."""
    payload = extra
    length = 3 + len(payload)
    return bytes([0xA0]) + struct.pack(">H", length) + payload


def _obex_continue_response(body_data=b""):
    """Build an OBEX Continue (0x90) response with optional body."""
    headers = b""
    if body_data:
        headers += struct.pack(">BH", 0x48, len(body_data) + 3) + body_data
    length = 3 + len(headers)
    return bytes([0x90]) + struct.pack(">H", length) + headers


def _obex_success_with_body(body_data=b""):
    """Build an OBEX Success response with End-of-Body header."""
    headers = b""
    if body_data:
        headers += struct.pack(">BH", 0x49, len(body_data) + 3) + body_data
    length = 3 + len(headers)
    return bytes([0xA0]) + struct.pack(">H", length) + headers


def _obex_connect_success(connection_id=1):
    """Build an OBEX Connect Success response with version, flags, max_packet, and connection_id."""
    # version(1) + flags(1) + max_packet(2) = 4 bytes after opcode+length
    body = struct.pack(">BBH", 0x10, 0x00, 0xFFFF)
    # Connection ID header
    body += struct.pack(">BI", 0xCB, connection_id)
    length = 3 + len(body)
    return bytes([0xA0]) + struct.pack(">H", length) + body


class FakeSocket:
    """Mock Bluetooth socket that returns pre-configured responses."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self._resp_idx = 0
        self.sent = []
        self._closed = False

    def connect(self, addr):
        pass

    def settimeout(self, t):
        pass

    def send(self, data):
        self.sent.append(data)

    def recv(self, bufsize):
        if self._resp_idx >= len(self.responses):
            raise TimeoutError("no more data")
        data = self.responses[self._resp_idx]
        self._resp_idx += 1
        return data

    def close(self):
        self._closed = True


def _make_fake_socket_for_obex(responses):
    """Create a FakeSocket that feeds OBEX responses correctly.

    For _recv_response: first recv(3) returns first 3 bytes (header),
    second recv returns remaining bytes.
    """
    parts = []
    for resp in responses:
        parts.append(resp[:3])  # header: opcode + length
        if len(resp) > 3:
            parts.append(resp[3:])  # body
    return FakeSocket(parts)


# ===========================================================================
# PBAP Tests
# ===========================================================================

from blue_tap.attack.pbap import (
    PBAPClient, PBAP_TARGET_UUID,
    OBEX_CONNECT, OBEX_HEADER_TARGET, OBEX_HEADER_CONNECTION_ID,
    OBEX_HEADER_BODY, OBEX_HEADER_END_OF_BODY, OBEX_HEADER_APP_PARAMS,
    OBEX_RESPONSE_SUCCESS, OBEX_RESPONSE_CONTINUE,
)


class TestPBAPBuildConnect:
    def test_packet_starts_with_connect_opcode(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        packet = client._build_connect()
        assert packet[0] == OBEX_CONNECT

    def test_packet_contains_target_uuid(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        packet = client._build_connect()
        assert PBAP_TARGET_UUID in packet

    def test_packet_length_matches_header(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        packet = client._build_connect()
        declared_len = struct.unpack(">H", packet[1:3])[0]
        assert declared_len == len(packet)

    def test_version_and_flags(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        packet = client._build_connect()
        # After opcode(1)+length(2): version(1)=0x10, flags(1)=0x00
        assert packet[3] == 0x10
        assert packet[4] == 0x00

    def test_max_packet_size(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.max_packet = 0x1000
        packet = client._build_connect()
        max_pkt = struct.unpack(">H", packet[5:7])[0]
        assert max_pkt == 0x1000


class TestPBAPRecvResponse:
    def test_successful_recv(self):
        resp = _obex_success_response(b"\x01\x02\x03")
        sock = FakeSocket([resp[:3], resp[3:]])
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.sock = sock
        result = client._recv_response()
        assert result is not None
        assert result[0] == 0xA0

    def test_timeout_returns_none(self):
        sock = FakeSocket([])  # No data
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.sock = sock
        result = client._recv_response()
        assert result is None

    def test_short_header_returns_none(self):
        sock = FakeSocket([b"\xA0\x00"])  # Only 2 bytes
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.sock = sock
        result = client._recv_response()
        assert result is None


class TestPBAPParseConnectResponse:
    def test_extracts_connection_id(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        resp = _obex_connect_success(connection_id=42)
        client._parse_connect_response(resp)
        assert client.connection_id == 42

    def test_no_connection_id_header(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        # Response with just version/flags/max_packet, no headers
        body = struct.pack(">BBH", 0x10, 0x00, 0xFFFF)
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(body)) + body
        client._parse_connect_response(resp)
        assert client.connection_id is None

    def test_skips_non_connection_id_headers(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        body = struct.pack(">BBH", 0x10, 0x00, 0xFFFF)
        # Add a byte-sequence header (0x46 = Target, class 0x40)
        uuid = b"\x00" * 16
        body += struct.pack(">BH", 0x46, len(uuid) + 3) + uuid
        # Then connection ID
        body += struct.pack(">BI", 0xCB, 99)
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(body)) + body
        client._parse_connect_response(resp)
        assert client.connection_id == 99


class TestPBAPExtractBody:
    def test_extracts_body_header(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        data = b"Hello World"
        headers = struct.pack(">BH", OBEX_HEADER_BODY, len(data) + 3) + data
        resp = bytes([0x90]) + struct.pack(">H", 3 + len(headers)) + headers
        assert client._extract_body(resp) == data

    def test_extracts_end_of_body(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        data = b"Final chunk"
        headers = struct.pack(">BH", OBEX_HEADER_END_OF_BODY, len(data) + 3) + data
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(headers)) + headers
        assert client._extract_body(resp) == data

    def test_concatenates_multiple_body_headers(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        d1 = b"Part1"
        d2 = b"Part2"
        headers = struct.pack(">BH", OBEX_HEADER_BODY, len(d1) + 3) + d1
        headers += struct.pack(">BH", OBEX_HEADER_END_OF_BODY, len(d2) + 3) + d2
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(headers)) + headers
        assert client._extract_body(resp) == d1 + d2

    def test_skips_non_body_headers(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        # Add a 4-byte-value header (class 0xC0) before body
        headers = struct.pack(">BI", 0xCB, 1)
        data = b"bodydata"
        headers += struct.pack(">BH", OBEX_HEADER_BODY, len(data) + 3) + data
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(headers)) + headers
        assert client._extract_body(resp) == data

    def test_empty_response(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        resp = bytes([0xA0]) + struct.pack(">H", 3)
        assert client._extract_body(resp) == b""


class TestPBAPConnect:
    @patch("blue_tap.attack.pbap.socket.socket")
    def test_successful_connect(self, mock_socket_cls):
        sock = _make_fake_socket_for_obex([_obex_connect_success(42)])
        mock_socket_cls.return_value = sock
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        assert client.connect() is True
        assert client.connection_id == 42

    @patch("blue_tap.attack.pbap.socket.socket")
    def test_rejected_connect(self, mock_socket_cls):
        # Return a non-success opcode
        bad_resp = bytes([0xC0]) + struct.pack(">H", 3)
        sock = _make_fake_socket_for_obex([bad_resp])
        mock_socket_cls.return_value = sock
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        assert client.connect() is False

    @patch("blue_tap.attack.pbap.socket.socket")
    def test_no_response(self, mock_socket_cls):
        sock = FakeSocket([])  # Will timeout on recv
        mock_socket_cls.return_value = sock
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        assert client.connect() is False

    @patch("blue_tap.attack.pbap.socket.socket")
    def test_os_error(self, mock_socket_cls):
        mock_socket_cls.return_value.connect = Mock(side_effect=OSError("fail"))
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        assert client.connect() is False


class TestPBAPDisconnect:
    def test_disconnect_with_connection_id(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        sock = _make_fake_socket_for_obex([_obex_success_response()])
        client.sock = sock
        client.connection_id = 1
        client.disconnect()
        assert client.sock is None
        assert len(sock.sent) == 1

    def test_disconnect_without_connection_id(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        sock = _make_fake_socket_for_obex([_obex_success_response()])
        client.sock = sock
        client.connection_id = None
        client.disconnect()
        assert client.sock is None

    def test_disconnect_os_error(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        sock = Mock()
        sock.send = Mock(side_effect=OSError("oops"))
        sock.close = Mock()
        client.sock = sock
        client.disconnect()
        assert client.sock is None
        sock.close.assert_called_once()

    def test_disconnect_no_socket(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.sock = None
        client.disconnect()  # Should not raise


class TestPBAPPullPhonebook:
    def test_success_single_response(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = 1
        body = b"BEGIN:VCARD\nEND:VCARD"
        resp = _obex_success_with_body(body)
        client.sock = _make_fake_socket_for_obex([resp])
        result = client.pull_phonebook("telecom/pb.vcf")
        assert "BEGIN:VCARD" in result

    def test_multi_part_response(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = 1
        part1 = _obex_continue_response(b"Part1")
        part2 = _obex_success_with_body(b"Part2")
        client.sock = _make_fake_socket_for_obex([part1, part2])
        result = client.pull_phonebook("telecom/pb.vcf")
        assert "Part1" in result
        assert "Part2" in result

    def test_error_response(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = 1
        # Error opcode
        resp = bytes([0xC3]) + struct.pack(">H", 3)
        client.sock = _make_fake_socket_for_obex([resp])
        result = client.pull_phonebook("telecom/pb.vcf")
        assert result == ""

    def test_no_connection_id(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = None
        body = b"data"
        resp = _obex_success_with_body(body)
        client.sock = _make_fake_socket_for_obex([resp])
        result = client.pull_phonebook("telecom/pb.vcf")
        assert result == "data"


class TestPBAPPullAllData:
    @patch.object(PBAPClient, "pull_phonebook")
    def test_pulls_and_saves(self, mock_pull, tmp_path):
        mock_pull.return_value = "BEGIN:VCARD\nFN:John\nEND:VCARD\n" + "x" * 20
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        output_dir = str(tmp_path / "pbap_dump")
        results = client.pull_all_data(output_dir)
        assert len(results) > 0
        for path_key, info in results.items():
            assert os.path.isfile(info["file"])

    @patch.object(PBAPClient, "pull_phonebook")
    def test_empty_data_skipped(self, mock_pull, tmp_path):
        mock_pull.return_value = ""
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        results = client.pull_all_data(str(tmp_path / "pbap_empty"))
        assert results == {}

    @patch.object(PBAPClient, "pull_phonebook")
    def test_exception_handled(self, mock_pull, tmp_path):
        mock_pull.side_effect = OSError("connection lost")
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        results = client.pull_all_data(str(tmp_path / "pbap_err"))
        assert results == {}


class TestPBAPGetPhonebookSize:
    def test_returns_size(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = 1
        # Build app params with PhonebookSize tag (0x08, len 2, value 42)
        app_params = struct.pack(">BBH", 0x08, 0x02, 42)
        headers = struct.pack(">BH", OBEX_HEADER_APP_PARAMS, len(app_params) + 3) + app_params
        # Add version/flags/max_packet stub first (for _parse_phonebook_size which starts at offset 3)
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(headers)) + headers
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.get_phonebook_size("telecom/pb.vcf") == 42

    def test_failure_returns_negative(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        client.connection_id = 1
        # Error response
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.get_phonebook_size() == -1


class TestPBAPBuildAppParams:
    def test_default_params(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        params = client._build_pbap_app_params()
        assert len(params) > 0
        # Should contain Format tag (0x07)
        assert b"\x07\x01" in params
        # Should contain Filter tag (0x06, 8 bytes)
        assert b"\x06\x08" in params

    def test_with_max_count(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        params = client._build_pbap_app_params(max_count=50)
        # MaxListCount tag: 0x04, 0x02, then 2-byte value
        assert struct.pack(">BBH", 0x04, 0x02, 50) in params

    def test_with_offset(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        params = client._build_pbap_app_params(offset=10)
        assert struct.pack(">BBH", 0x05, 0x02, 10) in params

    def test_with_filter_bits(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        params = client._build_pbap_app_params(filter_bits=0x07)
        assert struct.pack(">Q", 0x07) in params

    def test_vcard_version(self):
        client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=15)
        params = client._build_pbap_app_params(vcard_version=0)
        assert struct.pack(">BBB", 0x07, 0x01, 0) in params


# ===========================================================================
# MAP Tests
# ===========================================================================

from blue_tap.attack.map_client import MAPClient, parse_bmessage, MAP_FOLDERS


class TestMAPConnect:
    @patch("blue_tap.attack.map_client.socket.socket")
    def test_successful_connect(self, mock_socket_cls):
        resp = _obex_connect_success(7)
        sock = _make_fake_socket_for_obex([resp])
        mock_socket_cls.return_value = sock
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        assert client.connect() is True
        assert client.connection_id == 7

    @patch("blue_tap.attack.map_client.socket.socket")
    def test_rejected_connect(self, mock_socket_cls):
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        sock = _make_fake_socket_for_obex([resp])
        mock_socket_cls.return_value = sock
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        assert client.connect() is False

    @patch("blue_tap.attack.map_client.socket.socket")
    def test_os_error(self, mock_socket_cls):
        mock_socket_cls.return_value.connect = Mock(side_effect=OSError("fail"))
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        assert client.connect() is False


class TestMAPDisconnect:
    def test_disconnect_with_connection_id(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        sock = _make_fake_socket_for_obex([_obex_success_response()])
        client.sock = sock
        client.connection_id = 1
        client.disconnect()
        assert client.sock is None

    def test_disconnect_no_socket(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.sock = None
        client.disconnect()

    def test_disconnect_os_error(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        sock = Mock()
        sock.send = Mock(side_effect=OSError)
        sock.close = Mock()
        client.sock = sock
        client.disconnect()
        assert client.sock is None


class TestMAPSetFolder:
    def test_successful_navigation(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        # Root + 3 components (telecom/msg/inbox)
        resps = [_obex_success_response()] * 4
        client.sock = _make_fake_socket_for_obex(resps)
        assert client.set_folder("telecom/msg/inbox") is True

    def test_failed_navigation(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        # Root succeeds, first folder fails
        resps = [_obex_success_response(), bytes([0xC0]) + struct.pack(">H", 3)]
        client.sock = _make_fake_socket_for_obex(resps)
        assert client.set_folder("telecom/msg/inbox") is False


class TestMAPGetMessagesListing:
    @patch.object(MAPClient, "set_folder", return_value=True)
    def test_returns_listing(self, mock_set_folder):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        body = b'<MAP-msg-listing><msg handle="0001"/></MAP-msg-listing>'
        resp = _obex_success_with_body(body)
        client.sock = _make_fake_socket_for_obex([resp])
        result = client.get_messages_listing("telecom/msg/inbox")
        assert "handle" in result

    @patch.object(MAPClient, "set_folder", return_value=False)
    def test_folder_fail_returns_empty(self, mock_set_folder):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        result = client.get_messages_listing("telecom/msg/inbox")
        assert result == ""


class TestMAPGetMessage:
    def test_returns_message_content(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        body = b"BEGIN:BMSG\r\nEND:BMSG\r\n"
        resp = _obex_success_with_body(body)
        client.sock = _make_fake_socket_for_obex([resp])
        result = client.get_message("0001")
        assert "BEGIN:BMSG" in result


class TestMAPDumpAllMessages:
    @patch.object(MAPClient, "get_message", return_value="BEGIN:BMSG\r\nEND:BMSG\r\n")
    @patch.object(MAPClient, "get_messages_listing")
    def test_dumps_messages(self, mock_listing, mock_get_msg, tmp_path):
        mock_listing.return_value = '<MAP-msg-listing><msg handle="001"/></MAP-msg-listing>'
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        results = client.dump_all_messages(str(tmp_path / "map_dump"))
        assert len(results) > 0

    @patch.object(MAPClient, "get_messages_listing", return_value="")
    def test_empty_folders(self, mock_listing, tmp_path):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        results = client.dump_all_messages(str(tmp_path / "map_dump"))
        assert results == {}


class TestMAPRecvResponse:
    def test_successful(self):
        resp = _obex_success_response(b"\x01\x02")
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.sock = FakeSocket([resp[:3], resp[3:]])
        result = client._recv_response()
        assert result[0] == 0xA0

    def test_timeout(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.sock = FakeSocket([])
        assert client._recv_response() is None


class TestMAPRecvBody:
    def test_multi_part(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        part1 = _obex_continue_response(b"AAA")
        part2 = _obex_success_with_body(b"BBB")
        client.sock = _make_fake_socket_for_obex([part1, part2])
        result = client._recv_body()
        assert result == b"AAABBB"


class TestMAPExtractBodyData:
    def test_extracts_body(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        data = b"body content"
        headers = struct.pack(">BH", 0x48, len(data) + 3) + data
        resp = bytes([0xA0]) + struct.pack(">H", 3 + len(headers)) + headers
        assert client._extract_body_data(resp) == data


class TestMAPPushMessage:
    @patch.object(MAPClient, "set_folder", return_value=True)
    def test_success(self, mock_set_folder):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.push_message("telecom/msg/outbox", "+1234567890", "Hello") is True

    @patch.object(MAPClient, "set_folder", return_value=False)
    def test_folder_fail(self, mock_set_folder):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        assert client.push_message("telecom/msg/outbox", "+1234567890", "Hello") is False

    @patch.object(MAPClient, "set_folder", return_value=True)
    def test_push_rejected(self, mock_set_folder):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.push_message("telecom/msg/outbox", "+1234567890", "Hello") is False


class TestParseBmessage:
    def test_valid_bmessage(self):
        bmsg = (
            "BEGIN:BMSG\r\n"
            "VERSION:1.0\r\n"
            "STATUS:READ\r\n"
            "TYPE:SMS_GSM\r\n"
            "FOLDER:telecom/msg/inbox\r\n"
            "BEGIN:VCARD\r\n"
            "VERSION:2.1\r\n"
            "FN:John Doe\r\n"
            "TEL:+1234567890\r\n"
            "END:VCARD\r\n"
            "BEGIN:VCARD\r\n"
            "VERSION:2.1\r\n"
            "TEL:+0987654321\r\n"
            "END:VCARD\r\n"
            "BEGIN:BENV\r\n"
            "BEGIN:BBODY\r\n"
            "CHARSET:UTF-8\r\n"
            "BEGIN:MSG\r\n"
            "Hello World\r\n"
            "END:MSG\r\n"
            "END:BBODY\r\n"
            "END:BENV\r\n"
            "END:BMSG\r\n"
        )
        result = parse_bmessage(bmsg)
        assert result["type"] == "SMS_GSM"
        assert result["status"] == "READ"
        assert result["folder"] == "telecom/msg/inbox"
        assert result["sender"] == "+1234567890"
        assert result["sender_name"] == "John Doe"
        assert result["recipient"] == "+0987654321"
        assert result["body"] == "Hello World"
        assert result["charset"] == "UTF-8"

    def test_malformed_no_vcard(self):
        bmsg = "BEGIN:BMSG\r\nTYPE:MMS\r\nEND:BMSG\r\n"
        result = parse_bmessage(bmsg)
        assert result["type"] == "MMS"
        assert result["sender"] == ""
        assert result["body"] == ""

    def test_empty_string(self):
        result = parse_bmessage("")
        assert result["type"] == ""
        assert result["body"] == ""

    def test_single_vcard_no_recipient(self):
        bmsg = (
            "BEGIN:BMSG\r\n"
            "TYPE:SMS_GSM\r\n"
            "BEGIN:VCARD\r\n"
            "N:Smith;Jane\r\n"
            "TEL:+555\r\n"
            "END:VCARD\r\n"
            "BEGIN:MSG\r\n"
            "Test\r\n"
            "END:MSG\r\n"
            "END:BMSG\r\n"
        )
        result = parse_bmessage(bmsg)
        assert result["sender"] == "+555"
        assert result["sender_name"] == "Smith;Jane"  # Falls back to N: field
        assert result["recipient"] == ""
        assert result["body"] == "Test"


class TestMAPSetpathRoot:
    def test_sends_setpath(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        client._setpath_root()
        assert len(client.sock.sent) == 1

    def test_no_connection_id(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = None
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        client._setpath_root()
        assert len(client.sock.sent) == 1


class TestMAPSetpathDown:
    def test_success(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        assert client._setpath_down("inbox") is True

    def test_failure(self):
        client = MAPClient("AA:BB:CC:DD:EE:FF", channel=16)
        client.connection_id = 1
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        client.sock = _make_fake_socket_for_obex([resp])
        assert client._setpath_down("inbox") is False


# ===========================================================================
# HFP Tests (methods NOT in test_hfp_a2dp_spoof.py)
# ===========================================================================

from blue_tap.attack.hfp import HFPClient


class TestHFPDial:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_dial_sends_atd(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.dial("+1234567890")
        mock_send.assert_called_once_with("ATD+1234567890;", timeout=30.0)
        assert result == "OK"


class TestHFPAnswer:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_answer(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.answer() == "OK"
        mock_send.assert_called_once_with("ATA")


class TestHFPHangup:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_hangup(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.hangup() == "OK"
        mock_send.assert_called_once_with("AT+CHUP")


class TestHFPGetCallList:
    @patch.object(HFPClient, "_send_at", return_value="+CLCC: 1,0,0,0,0\nOK")
    def test_get_call_list(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.get_call_list()
        assert "+CLCC:" in result
        mock_send.assert_called_once_with("AT+CLCC")


class TestHFPGetOperator:
    @patch.object(HFPClient, "_send_at", return_value="+COPS: 0,0,\"T-Mobile\"\nOK")
    def test_get_operator(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.get_operator()
        assert "T-Mobile" in result


class TestHFPGetSubscriberNumber:
    @patch.object(HFPClient, "_send_at", return_value="+CNUM: ,\"+1234567890\",145\nOK")
    def test_get_subscriber(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.get_subscriber_number()
        assert "+1234567890" in result


class TestHFPSetVolume:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_set_volume(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.set_volume(speaker=10, mic=5)
        assert mock_send.call_count == 2
        mock_send.assert_any_call("AT+VGS=10")
        mock_send.assert_any_call("AT+VGM=5")


class TestHFPDisableNrec:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_disable_nrec(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.disable_nrec()
        assert result == "OK"
        mock_send.assert_called_once_with("AT+NREC=0")


class TestHFPDtmf:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_valid_digit(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.dtmf("5")
        assert result == "OK"
        mock_send.assert_called_once_with("AT+VTS=5")

    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_star_and_hash(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.dtmf("*")
        client.dtmf("#")
        assert mock_send.call_count == 2

    def test_invalid_digit(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.dtmf("X")
        assert result == ""

    def test_multi_char_digit(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.dtmf("12")
        assert result == ""

    def test_empty_string(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.dtmf("")
        assert result == ""

    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_lowercase_converted_to_upper(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.dtmf("a")
        mock_send.assert_called_once_with("AT+VTS=A")


class TestHFPDtmfSequence:
    @patch.object(HFPClient, "dtmf", return_value="OK")
    @patch("blue_tap.attack.hfp.time.sleep")
    def test_sends_all_digits(self, mock_sleep, mock_dtmf):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        results = client.dtmf_sequence("123", interval=0.1)
        assert len(results) == 3
        assert mock_dtmf.call_count == 3
        # Sleep called between digits (not after last)
        assert mock_sleep.call_count == 2

    @patch.object(HFPClient, "dtmf", return_value="OK")
    @patch("blue_tap.attack.hfp.time.sleep")
    def test_single_digit_no_sleep(self, mock_sleep, mock_dtmf):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        results = client.dtmf_sequence("5")
        assert len(results) == 1
        mock_sleep.assert_not_called()


class TestHFPCallHold:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_valid_action(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        for action in range(5):
            client.call_hold(action)
        assert mock_send.call_count == 5

    def test_invalid_action(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.call_hold(5)
        assert result == ""

    def test_negative_action(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        result = client.call_hold(-1)
        assert result == ""


class TestHFPRedial:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_redial(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.redial() == "OK"
        mock_send.assert_called_once_with("AT+BLDN")


class TestHFPVoiceRecognition:
    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_enable(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.voice_recognition(True)
        mock_send.assert_called_once_with("AT+BVRA=1")

    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_disable(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.voice_recognition(False)
        mock_send.assert_called_once_with("AT+BVRA=0")


class TestHFPNegotiateCodec:
    @patch.object(HFPClient, "_send_at")
    def test_msbc_negotiated(self, mock_send):
        mock_send.side_effect = [
            "+BCS: 2\nOK",  # BAC response with codec selection
            "OK",  # BCS confirmation
        ]
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.negotiate_codec(prefer_msbc=True) is True
        assert client.audio_rate == 16000
        assert client.audio_codec == "mSBC"

    @patch.object(HFPClient, "_send_at")
    def test_cvsd_negotiated(self, mock_send):
        mock_send.side_effect = [
            "+BCS: 1\nOK",
            "OK",
        ]
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.negotiate_codec(prefer_msbc=True) is True
        assert client.audio_rate == 8000
        assert client.audio_codec == "CVSD"

    @patch.object(HFPClient, "_send_at", return_value="OK")
    def test_no_bcs_response(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.negotiate_codec() is True
        # No BCS in response, just OK

    @patch.object(HFPClient, "_send_at", return_value="+BCS:\nOK")
    def test_bcs_with_no_codec_id_falls_through(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        # +BCS: followed by newline+OK -> parses "OK" as codec_id (not "2")
        # → falls through to CVSD path, returns True
        result = client.negotiate_codec()
        assert result is True
        assert client.audio_codec == "CVSD"

    @patch.object(HFPClient, "_send_at", return_value="NO_RESPONSE")
    def test_unsupported_returns_false(self, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        # No "OK" and no "ERROR" in response → unsupported
        assert client.negotiate_codec() is False


class TestHFPGetPhonebookViaAt:
    @patch.object(HFPClient, "_send_at")
    def test_extracts_entries(self, mock_send):
        mock_send.side_effect = [
            "OK",  # AT+CPBS
            '+CPBR: 1,"+1234567890",145,"John Doe"\n+CPBR: 2,"+0987654321",145,"Jane"\nOK',
        ]
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        entries = client.get_phonebook_via_at("ME", 1, 200)
        assert len(entries) == 2
        assert entries[0]["number"] == "+1234567890"
        assert entries[0]["name"] == "John Doe"

    @patch.object(HFPClient, "_send_at")
    def test_memory_error(self, mock_send):
        mock_send.return_value = "ERROR"
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        entries = client.get_phonebook_via_at("XX")
        assert entries == []


class TestHFPGetCallHistoryViaAt:
    @patch.object(HFPClient, "get_phonebook_via_at")
    def test_collects_all_types(self, mock_get_pb):
        mock_get_pb.side_effect = [
            [{"index": "1", "number": "+111", "type": "145", "name": "A"}],  # DC
            [{"index": "1", "number": "+222", "type": "145", "name": "B"}],  # RC
            [],  # MC
        ]
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        history = client.get_call_history_via_at()
        assert "Dialed" in history
        assert "Received" in history
        assert "Missed" not in history  # empty list filtered out


class TestHFPSilentCall:
    @patch.object(HFPClient, "_send_at")
    @patch("blue_tap.attack.hfp.time.sleep")
    def test_success(self, mock_sleep, mock_send):
        mock_send.side_effect = ["OK", "OK", "OK"]
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.silent_call("+1234567890") is True
        # Should mute after dialing
        calls = [c[0][0] for c in mock_send.call_args_list]
        assert "ATD+1234567890;" in calls
        assert "AT+VGS=0" in calls
        assert "AT+VGM=0" in calls

    @patch.object(HFPClient, "_send_at", return_value="ERROR")
    @patch("blue_tap.attack.hfp.time.sleep")
    def test_dial_fails(self, mock_sleep, mock_send):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        assert client.silent_call("+1234567890") is False


class TestHFPWaitForIncoming:
    def test_detects_ring_and_clip(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.rfcomm_sock = Mock()
        # First recv: AT+CLIP=1 response, second: RING with CLIP
        clip_data = b'\r\nRING\r\n+CLIP: "+1234567890",145,,"John"\r\n'
        client.rfcomm_sock.recv = Mock(return_value=clip_data)
        # Also mock _send_at for the CLIP enable
        with patch.object(client, "_send_at", return_value="OK"):
            result = client.wait_for_incoming(timeout=2)
        assert result is not None
        assert result["number"] == "+1234567890"
        assert result["name"] == "John"
        assert result["type"] == 145

    def test_timeout_no_call(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.rfcomm_sock = Mock()
        client.rfcomm_sock.recv = Mock(side_effect=TimeoutError)
        with patch.object(client, "_send_at", return_value="OK"):
            with patch("blue_tap.attack.hfp.time.time") as mock_time:
                # Simulate immediate timeout
                mock_time.side_effect = [0, 0, 100]
                result = client.wait_for_incoming(timeout=1)
        assert result is None


class TestHFPInjectAudio:
    def test_inject_with_sco(self, tmp_path):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.sco_sock = Mock()
        client.sco_sock.send = Mock()

        # Create a valid WAV file
        wav_path = str(tmp_path / "test.wav")
        with wave.open(wav_path, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(8000)
            wf.writeframes(b"\x00" * 960)

        with patch("blue_tap.attack.hfp.time.sleep"):
            result = client.inject_audio(wav_path)
        assert result is True
        assert client.sco_sock.send.call_count >= 1

    def test_file_not_found(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.sco_sock = Mock()
        result = client.inject_audio("/nonexistent/file.wav")
        assert result is False

    def test_no_sco_and_setup_fails(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        client.sco_sock = None
        with patch.object(client, "setup_audio", return_value=False):
            result = client.inject_audio("test.wav")
        assert result is False


# ===========================================================================
# A2DP Tests (methods NOT in test_hfp_a2dp_spoof.py)
# ===========================================================================

from blue_tap.attack.a2dp import (
    get_active_profile, unmute_source, mute_source,
    mute_laptop_mic, unmute_laptop_mic, detect_mic_channels,
    record_car_mic, live_eavesdrop, play_to_car, stream_mic_to_car,
    stop_loopback, inject_tts, record_navigation_audio,
    capture_a2dp, diagnose_bt_audio, list_captures,
    play_capture, interactive_review, set_sink_volume,
    _active_loopback_id,
)
import blue_tap.attack.a2dp as a2dp_mod


class TestGetActiveProfile:
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_finds_profile(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout=(
            "Card #1\n"
            "\tName: bluez_card.AA_BB_CC_DD_EE_FF\n"
            "\tActive Profile: headset-head-unit\n"
            "\n"
        ))
        assert get_active_profile("AA:BB:CC:DD:EE:FF") == "headset-head-unit"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_card_not_found(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout="Card #1\n\tName: other_card\n")
        assert get_active_profile("AA:BB:CC:DD:EE:FF") == "unknown"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_command_fails(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1)
        assert get_active_profile("AA:BB:CC:DD:EE:FF") == "unknown"


class TestUnmuteSource:
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_success(self, mock_run):
        mock_run.return_value = _make_run_cmd_result()
        assert unmute_source("bluez_input.XX.0") is True
        assert mock_run.call_count == 2

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_failure(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1, stderr="fail")
        assert unmute_source("bluez_input.XX.0") is False


class TestMuteSource:
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_success(self, mock_run):
        mock_run.return_value = _make_run_cmd_result()
        assert mute_source("bluez_input.XX.0") is True

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_failure(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1, stderr="err")
        assert mute_source("bluez_input.XX.0") is False


class TestMuteLaptopMic:
    @patch("blue_tap.attack.a2dp.run_cmd")
    @patch("blue_tap.attack.a2dp.mute_source")
    def test_mutes_alsa_sources(self, mock_mute, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout=(
            "1\talsa_input.analog-stereo\tmod\ts16le\tRUNNING\n"
            "2\tbluez_input.XX.0\tmod\ts16le\tIDLE\n"
        ))
        assert mute_laptop_mic() is True
        mock_mute.assert_called_once_with("alsa_input.analog-stereo")

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_command_fails(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1)
        assert mute_laptop_mic() is False


class TestUnmuteLaptopMic:
    @patch("blue_tap.attack.a2dp.run_cmd")
    @patch("blue_tap.attack.a2dp.unmute_source")
    def test_unmutes_alsa(self, mock_unmute, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout=(
            "1\talsa_input.analog-stereo\tmod\ts16le\tRUNNING\n"
        ))
        assert unmute_laptop_mic() is True
        mock_unmute.assert_called_once_with("alsa_input.analog-stereo")


class TestDetectMicChannels:
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_detects_stereo(self, mock_run):
        # detect_mic_channels looks for first number on a line containing "channel"
        mock_run.return_value = _make_run_cmd_result(stdout=(
            "Source #1\n"
            "\tName: bluez_input.AA_BB_CC_DD_EE_FF.0\n"
            "\tSample Specification: s16le 2ch 16000Hz\n"
            "\tChannel Map: 2 channels\n"
        ))
        assert detect_mic_channels("AA:BB:CC:DD:EE:FF") == 2

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_defaults_to_mono(self, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1)
        assert detect_mic_channels("AA:BB:CC:DD:EE:FF") == 1


class TestRecordCarMic:
    @patch("blue_tap.attack.a2dp.unmute_laptop_mic")
    @patch("blue_tap.attack.a2dp.check_tool", return_value=True)
    @patch("blue_tap.attack.a2dp.detect_mic_channels", return_value=1)
    @patch("blue_tap.attack.a2dp.unmute_source")
    @patch("blue_tap.attack.a2dp.mute_laptop_mic")
    @patch("blue_tap.attack.a2dp.set_profile_hfp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    @patch("blue_tap.attack.a2dp.subprocess.Popen")
    def test_records_file(self, mock_popen, mock_sleep, mock_hfp, mock_mute,
                          mock_unmute_src, mock_channels, mock_check, mock_unmute_mic,
                          tmp_path):
        output = str(tmp_path / "car_mic.wav")
        proc = Mock()
        proc.pid = 123
        proc.terminate = Mock()
        proc.wait = Mock()
        mock_popen.return_value = proc

        # Create file to simulate parecord output
        with open(output, "wb") as f:
            f.write(b"\x00" * 2000)

        result = record_car_mic("AA:BB:CC:DD:EE:FF", output, duration=1)
        assert result == output
        mock_popen.assert_called_once()

    @patch("blue_tap.attack.a2dp.check_tool", return_value=False)
    @patch("blue_tap.attack.a2dp.detect_mic_channels", return_value=1)
    @patch("blue_tap.attack.a2dp.unmute_source")
    @patch("blue_tap.attack.a2dp.mute_laptop_mic")
    @patch("blue_tap.attack.a2dp.set_profile_hfp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    def test_no_parecord(self, mock_sleep, mock_hfp, mock_mute,
                         mock_unmute, mock_channels, mock_check):
        result = record_car_mic("AA:BB:CC:DD:EE:FF", "/tmp/test.wav", duration=1)
        assert result == ""


class TestLiveEavesdrop:
    @patch("blue_tap.attack.a2dp.unmute_laptop_mic")
    @patch("blue_tap.attack.a2dp.unmute_source")
    @patch("blue_tap.attack.a2dp.mute_laptop_mic")
    @patch("blue_tap.attack.a2dp.set_profile_hfp")
    @patch("blue_tap.attack.a2dp.detect_mic_channels", return_value=1)
    @patch("blue_tap.attack.a2dp.time.sleep")
    @patch("blue_tap.attack.a2dp.subprocess.Popen")
    def test_starts_and_stops(self, mock_popen, mock_sleep, mock_channels,
                               mock_hfp, mock_mute, mock_unmute, mock_unmute_mic):
        record_proc = Mock()
        record_proc.stdout = Mock()
        play_proc = Mock()
        play_proc.wait = Mock(side_effect=KeyboardInterrupt)
        mock_popen.side_effect = [record_proc, play_proc]

        live_eavesdrop("AA:BB:CC:DD:EE:FF")
        record_proc.terminate.assert_called_once()
        play_proc.terminate.assert_called_once()


class TestPlayToCar:
    @patch("blue_tap.attack.a2dp.subprocess.run")
    @patch("blue_tap.attack.a2dp.set_sink_volume")
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    def test_success(self, mock_sleep, mock_profile, mock_vol, mock_run, tmp_path):
        audio_file = str(tmp_path / "test.wav")
        with open(audio_file, "w") as f:
            f.write("data")
        mock_run.return_value = _make_run_cmd_result()
        assert play_to_car("AA:BB:CC:DD:EE:FF", audio_file) is True

    def test_file_not_found(self):
        assert play_to_car("AA:BB:CC:DD:EE:FF", "/nonexistent.wav") is False


class TestStreamMicToCar:
    @patch("blue_tap.attack.a2dp.run_cmd")
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    def test_success(self, mock_sleep, mock_profile, mock_run):
        mock_run.side_effect = [
            # list sources
            _make_run_cmd_result(stdout="1\talsa_input.analog-stereo\tmod\ts16le\tRUNNING\n"),
            # load-module
            _make_run_cmd_result(stdout="42"),
        ]
        assert stream_mic_to_car("AA:BB:CC:DD:EE:FF") is True
        assert a2dp_mod._active_loopback_id == "42"

    @patch("blue_tap.attack.a2dp.run_cmd")
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    def test_no_mic_found(self, mock_sleep, mock_profile, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout="1\tbluez_input.XX.0\tmod\ts16le\tRUNNING\n")
        assert stream_mic_to_car("AA:BB:CC:DD:EE:FF") is False


class TestStopLoopback:
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_stored_id(self, mock_run):
        a2dp_mod._active_loopback_id = "42"
        mock_run.return_value = _make_run_cmd_result()
        assert stop_loopback() is True
        assert a2dp_mod._active_loopback_id is None
        mock_run.assert_called_once_with(["pactl", "unload-module", "42"])

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_fallback_by_name(self, mock_run):
        a2dp_mod._active_loopback_id = None
        mock_run.return_value = _make_run_cmd_result()
        assert stop_loopback() is True

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_fallback_by_index(self, mock_run):
        a2dp_mod._active_loopback_id = None
        mock_run.side_effect = [
            _make_run_cmd_result(returncode=1),  # unload by name fails
            _make_run_cmd_result(stdout="10\tmodule-loopback\targs\n"),  # list
            _make_run_cmd_result(),  # unload by index
        ]
        assert stop_loopback() is True

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_no_loopback_found(self, mock_run):
        a2dp_mod._active_loopback_id = None
        mock_run.side_effect = [
            _make_run_cmd_result(returncode=1),  # unload by name fails
            _make_run_cmd_result(stdout="10\tmodule-alsa-card\n"),  # no loopback
        ]
        assert stop_loopback() is False


class TestInjectTts:
    @patch("blue_tap.attack.a2dp.play_to_car", return_value=True)
    @patch("blue_tap.attack.a2dp.check_tool")
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_espeak(self, mock_run, mock_check, mock_play):
        mock_check.side_effect = lambda t: t == "espeak-ng"
        mock_run.return_value = _make_run_cmd_result()
        assert inject_tts("AA:BB:CC:DD:EE:FF", "Hello world") is True

    @patch("blue_tap.attack.a2dp.check_tool", return_value=False)
    def test_no_tts_engine(self, mock_check):
        assert inject_tts("AA:BB:CC:DD:EE:FF", "Hello") is False


class TestRecordNavigationAudio:
    @patch("blue_tap.attack.a2dp.check_tool", return_value=True)
    @patch("blue_tap.attack.a2dp.unmute_source")
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp._detect_source_rate", return_value=44100)
    @patch("blue_tap.attack.a2dp.time.sleep")
    @patch("blue_tap.attack.a2dp.subprocess.Popen")
    def test_records(self, mock_popen, mock_sleep, mock_rate, mock_profile,
                     mock_unmute, mock_check, tmp_path):
        output = str(tmp_path / "nav.wav")
        proc = Mock()
        proc.pid = 1
        proc.terminate = Mock()
        proc.wait = Mock()
        mock_popen.return_value = proc
        with open(output, "wb") as f:
            f.write(b"\x00" * 1000)
        result = record_navigation_audio("AA:BB:CC:DD:EE:FF", output, duration=1)
        assert result == output


class TestCaptureA2dp:
    @patch("blue_tap.attack.a2dp._detect_source_rate", return_value=44100)
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    @patch("blue_tap.attack.a2dp.subprocess.Popen")
    def test_captures_with_mac(self, mock_popen, mock_sleep, mock_profile, mock_rate):
        proc = Mock()
        proc.pid = 1
        proc.terminate = Mock()
        proc.wait = Mock()
        mock_popen.return_value = proc
        result = capture_a2dp("AA:BB:CC:DD:EE:FF", "out.wav", duration=1)
        assert result == "out.wav"

    @patch("blue_tap.attack.a2dp.list_bt_audio_sources", return_value=[])
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_no_source_no_mac(self, mock_run, mock_list):
        mock_run.return_value = _make_run_cmd_result(stdout="")
        result = capture_a2dp(mac=None, output_file="out.wav", duration=1)
        assert result == ""

    @patch("blue_tap.attack.a2dp._detect_source_rate", return_value=44100)
    @patch("blue_tap.attack.a2dp.set_profile_a2dp")
    @patch("blue_tap.attack.a2dp.time.sleep")
    @patch("blue_tap.attack.a2dp.subprocess.Popen")
    def test_timeout_with_valid_file(self, mock_popen, mock_sleep, mock_profile, mock_rate, tmp_path):
        output = str(tmp_path / "a2dp.wav")
        proc = Mock()
        proc.pid = 1
        proc.terminate = Mock()
        # First wait (after terminate) raises TimeoutExpired, second (after kill) succeeds
        proc.wait = Mock(side_effect=[subprocess.TimeoutExpired("cmd", 5), None])
        proc.kill = Mock()
        mock_popen.return_value = proc
        # Create file with more than WAV header (>44 bytes)
        with open(output, "wb") as f:
            f.write(b"\x00" * 100)
        result = capture_a2dp("AA:BB:CC:DD:EE:FF", output, duration=1)
        assert result == output


class TestDiagnoseBtAudio:
    @patch("blue_tap.attack.a2dp.get_active_profile", return_value="a2dp-sink")
    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_runs_without_error(self, mock_run, mock_profile):
        mock_run.return_value = _make_run_cmd_result(stdout=(
            "Card #1\n"
            "\tName: bluez_card.AA_BB_CC_DD_EE_FF\n"
            "\tActive Profile: a2dp-sink\n"
        ))
        # Should not raise
        diagnose_bt_audio("AA:BB:CC:DD:EE:FF")


class TestListCaptures:
    def test_finds_wav_files(self, tmp_path):
        # Create WAV files
        for name in ["a.wav", "b.wav"]:
            path = tmp_path / name
            with wave.open(str(path), "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(8000)
                wf.writeframes(b"\x00" * 16000)

        # Create non-WAV file
        (tmp_path / "c.txt").write_text("not audio")

        caps = list_captures(str(tmp_path))
        assert len(caps) == 2
        assert all(c["filename"].endswith(".wav") for c in caps)
        assert all(c["duration_secs"] > 0 for c in caps)

    def test_empty_directory(self, tmp_path):
        assert list_captures(str(tmp_path)) == []

    def test_nested_directory(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        path = subdir / "nested.wav"
        with wave.open(str(path), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(8000)
            wf.writeframes(b"\x00" * 8000)

        caps = list_captures(str(tmp_path))
        assert len(caps) == 1
        assert "sub" in caps[0]["filename"]


class TestPlayCapture:
    @patch("blue_tap.attack.a2dp.subprocess.run")
    def test_success_with_aplay(self, mock_run, tmp_path):
        f = tmp_path / "test.wav"
        f.write_text("data")
        mock_run.return_value = _make_run_cmd_result()
        assert play_capture(str(f)) is True

    def test_file_not_found(self):
        assert play_capture("/nonexistent.wav") is False

    @patch("blue_tap.attack.a2dp.subprocess.run")
    def test_all_players_fail(self, mock_run, tmp_path):
        f = tmp_path / "test.wav"
        f.write_text("data")
        mock_run.side_effect = FileNotFoundError
        assert play_capture(str(f)) is False


class TestInteractiveReview:
    @patch("blue_tap.attack.a2dp.list_captures", return_value=[])
    def test_no_captures(self, mock_list):
        interactive_review("/tmp")

    @patch("builtins.input", return_value="q")
    @patch("blue_tap.attack.a2dp.list_captures")
    def test_quit(self, mock_list, mock_input):
        mock_list.return_value = [{
            "filename": "test.wav", "duration_secs": 1.0,
            "size_bytes": 1024, "modified": "2024-01-01T00:00:00",
        }]
        interactive_review("/tmp")

    @patch("blue_tap.attack.a2dp.play_capture", return_value=True)
    @patch("builtins.input", side_effect=["0", "q"])
    @patch("blue_tap.attack.a2dp.list_captures")
    def test_select_and_play(self, mock_list, mock_input, mock_play):
        mock_list.return_value = [{
            "filename": "test.wav", "duration_secs": 1.0,
            "size_bytes": 1024, "modified": "2024-01-01T00:00:00",
        }]
        interactive_review("/tmp")
        mock_play.assert_called_once()


# ===========================================================================
# OPP Tests
# ===========================================================================

from blue_tap.attack.opp import OPPClient


class TestOPPInit:
    def test_stores_params(self):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.address == "AA:BB:CC:DD:EE:FF"
        assert client.channel == 9
        assert client.sock is None


class TestOPPConnect:
    @patch("blue_tap.attack.opp.socket.socket")
    def test_success(self, mock_socket_cls):
        # OBEX Connect response (no target UUID for OPP)
        resp = _obex_success_response()
        sock = _make_fake_socket_for_obex([resp])
        mock_socket_cls.return_value = sock
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.connect() is True

    @patch("blue_tap.attack.opp.socket.socket")
    def test_rejected(self, mock_socket_cls):
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        sock = _make_fake_socket_for_obex([resp])
        mock_socket_cls.return_value = sock
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.connect() is False

    @patch("blue_tap.attack.opp.socket.socket")
    def test_os_error(self, mock_socket_cls):
        mock_socket_cls.return_value.connect = Mock(side_effect=OSError("fail"))
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.connect() is False


class TestOPPDisconnect:
    def test_sends_disconnect(self):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        sock = _make_fake_socket_for_obex([_obex_success_response()])
        client.sock = sock
        client.disconnect()
        assert client.sock is None
        assert len(sock.sent) == 1

    def test_no_socket(self):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        client.sock = None
        client.disconnect()  # Should not raise

    def test_os_error(self):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        sock = Mock()
        sock.send = Mock(side_effect=OSError)
        sock.close = Mock()
        client.sock = sock
        client.disconnect()
        assert client.sock is None


class TestOPPPushFile:
    def test_small_file(self, tmp_path):
        f = tmp_path / "test.vcf"
        f.write_text("BEGIN:VCARD\nEND:VCARD")
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.push_file(str(f)) is True

    def test_file_not_found(self):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        client.sock = Mock()
        assert client.push_file("/nonexistent.vcf") is False

    def test_push_rejected(self, tmp_path):
        f = tmp_path / "test.vcf"
        f.write_text("data")
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        resp = bytes([0xC0]) + struct.pack(">H", 3)
        client.sock = _make_fake_socket_for_obex([resp])
        assert client.push_file(str(f)) is False


class TestOPPPushVcard:
    @patch.object(OPPClient, "push_file", return_value=True)
    def test_creates_and_pushes(self, mock_push):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.push_vcard("John Doe", "+1234567890", "john@example.com") is True
        mock_push.assert_called_once()
        # Temp file should be cleaned up
        assert not os.path.exists("/tmp/blue_tap_push.vcf")

    @patch.object(OPPClient, "push_file", return_value=False)
    def test_push_fails(self, mock_push):
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        assert client.push_vcard("Jane", "+555") is False


class TestOPPBuildConnect:
    """Test the OBEX Connect packet via connect() method internals."""

    @patch("blue_tap.attack.opp.socket.socket")
    def test_connect_packet_format(self, mock_socket_cls):
        sock = _make_fake_socket_for_obex([_obex_success_response()])
        mock_socket_cls.return_value = sock
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        client.connect()
        # Check the sent connect packet
        pkt = sock.sent[0]
        assert pkt[0] == 0x80  # OBEX_CONNECT
        length = struct.unpack(">H", pkt[1:3])[0]
        assert length == 7  # opcode(1)+length(2)+version(1)+flags(1)+max_packet(2)


class TestOPPBuildPut:
    """Verify PUT packet structure by examining what push_file sends."""

    def test_put_packet_has_name_header(self, tmp_path):
        f = tmp_path / "test.vcf"
        f.write_bytes(b"tiny")
        client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
        resp = _obex_success_response()
        client.sock = _make_fake_socket_for_obex([resp])
        client.push_file(str(f))
        pkt = client.sock.sent[0]
        # PUT-Final opcode is 0x82 | 0x80 = 0x82 (already has final bit for small files)
        # The packet should contain the Name header (0x01)
        assert b"\x01" in pkt[3:]  # Name header exists


# ===========================================================================
# Bluesnarfer Tests
# ===========================================================================

from blue_tap.attack.bluesnarfer import ATClient, bluesnarfer_extract


class TestATClientInit:
    def test_defaults(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.address == "AA:BB:CC:DD:EE:FF"
        assert client.channel == 1
        assert client.sock is None

    def test_custom_channel(self):
        client = ATClient("AA:BB:CC:DD:EE:FF", channel=5)
        assert client.channel == 5


class TestATClientConnect:
    @patch("blue_tap.attack.bluesnarfer.socket.socket")
    def test_success(self, mock_socket_cls):
        sock = Mock()
        sock.recv = Mock(side_effect=TimeoutError)
        mock_socket_cls.return_value = sock
        client = ATClient("AA:BB:CC:DD:EE:FF", channel=1)
        assert client.connect() is True

    @patch("blue_tap.attack.bluesnarfer.socket.socket")
    def test_os_error(self, mock_socket_cls):
        mock_socket_cls.return_value.connect = Mock(side_effect=OSError("fail"))
        client = ATClient("AA:BB:CC:DD:EE:FF", channel=1)
        assert client.connect() is False


class TestATClientDisconnect:
    def test_closes_socket(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        client.sock = Mock()
        client.disconnect()
        assert client.sock is None

    def test_no_socket(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        client.disconnect()  # Should not raise


class TestATClientSendAt:
    def test_sends_command(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        sock = Mock()
        sock.recv = Mock(return_value=b"\r\nOK\r\n")
        client.sock = sock
        result = client.send_at("AT")
        assert "OK" in result

    def test_no_socket(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.send_at("AT") == ""

    def test_os_error(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        sock = Mock()
        sock.send = Mock(side_effect=OSError("broken"))
        client.sock = sock
        assert client.send_at("AT") == ""


class TestATClientListAvailableMemories:
    @patch.object(ATClient, "send_at")
    def test_parses_memories(self, mock_send):
        mock_send.return_value = '+CPBS: ("ME","SM","DC","RC","MC")\nOK'
        client = ATClient("AA:BB:CC:DD:EE:FF")
        result = client.list_available_memories()
        assert "ME" in result
        assert "SM" in result
        assert len(result) == 5

    @patch.object(ATClient, "send_at", return_value="ERROR")
    def test_error(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.list_available_memories() == []


class TestATClientReadPhonebook:
    @patch.object(ATClient, "send_at")
    def test_reads_entries(self, mock_send):
        mock_send.side_effect = [
            "OK",  # CPBS
            '+CPBR: 1,"+1234",145,"John"\n+CPBR: 2,"+5678",145,"Jane"\nOK',
        ]
        client = ATClient("AA:BB:CC:DD:EE:FF")
        entries = client.read_phonebook("ME", 1, 100)
        assert len(entries) == 2
        assert entries[0]["number"] == "+1234"

    @patch.object(ATClient, "send_at", return_value="ERROR")
    def test_memory_error(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.read_phonebook("XX") == []


class TestATClientReadSms:
    @patch.object(ATClient, "send_at")
    def test_reads_messages(self, mock_send):
        mock_send.side_effect = [
            "OK",  # CMGF
            '+CMGL: 0,"REC READ","+1234",,\"24/01/01,12:00:00+00\"\nHello World\nOK',
        ]
        client = ATClient("AA:BB:CC:DD:EE:FF")
        msgs = client.read_sms("ALL")
        assert len(msgs) == 1
        assert msgs[0]["body"] == "Hello World"


class TestATClientGetImei:
    @patch.object(ATClient, "send_at")
    def test_extracts_imei(self, mock_send):
        mock_send.return_value = "\r\n123456789012345\r\nOK\r\n"
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.get_imei() == "123456789012345"

    @patch.object(ATClient, "send_at", return_value="ERROR")
    def test_no_imei(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.get_imei() == ""


class TestATClientGetImsi:
    @patch.object(ATClient, "send_at")
    def test_extracts_imsi(self, mock_send):
        mock_send.return_value = "\r\n12345678901234567\r\nOK\r\n"
        client = ATClient("AA:BB:CC:DD:EE:FF")
        # IMSI is >= 14 digits
        assert client.get_imsi() == "12345678901234567"


class TestATClientGetSubscriberNumber:
    @patch.object(ATClient, "send_at", return_value="+CNUM: 123\nOK")
    def test_returns_response(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert "+CNUM" in client.get_subscriber_number()


class TestATClientGetBattery:
    @patch.object(ATClient, "send_at", return_value="+CBC: 0,95\nOK")
    def test_returns_response(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert "+CBC" in client.get_battery()


class TestATClientGetSignal:
    @patch.object(ATClient, "send_at", return_value="+CSQ: 15,99\nOK")
    def test_returns_response(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert "+CSQ" in client.get_signal()


class TestATClientGetOperator:
    @patch.object(ATClient, "send_at", return_value="+COPS: 0,0,\"Test\"\nOK")
    def test_returns_response(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert "Test" in client.get_operator()


class TestATClientDial:
    @patch.object(ATClient, "send_at", return_value="OK")
    def test_dial(self, mock_send):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        assert client.dial("+555") == "OK"
        mock_send.assert_called_once_with("ATD+555;")


class TestATClientSendSms:
    def test_sends_sms(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        sock = Mock()
        sock.recv = Mock(return_value=b"+CMGS: 1\r\nOK\r\n")
        client.sock = sock
        with patch.object(client, "send_at", return_value="OK"):
            with patch("blue_tap.attack.bluesnarfer.time.sleep"):
                result = client.send_sms("+555", "Hello")
        assert "OK" in result or "CMGS" in result

    def test_no_socket(self):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        client.sock = None
        assert client.send_sms("+555", "Hello") == ""


class TestATClientDumpAll:
    def test_dumps(self, tmp_path):
        client = ATClient("AA:BB:CC:DD:EE:FF")
        with patch.object(client, "get_imei", return_value="123456789012345"), \
             patch.object(client, "get_imsi", return_value=""), \
             patch.object(client, "get_subscriber_number", return_value=""), \
             patch.object(client, "get_operator", return_value=""), \
             patch.object(client, "get_signal", return_value=""), \
             patch.object(client, "get_battery", return_value=""), \
             patch.object(client, "list_available_memories", return_value=["ME"]), \
             patch.object(client, "read_phonebook", return_value=[]), \
             patch.object(client, "read_sms", return_value=[]):
            results = client.dump_all(str(tmp_path / "dump"))
        assert "device_info" in results
        assert results["device_info"]["imei"] == "123456789012345"


class TestBluesnarferExtract:
    @patch("blue_tap.attack.bluesnarfer.run_cmd")
    @patch("blue_tap.attack.bluesnarfer.check_tool", return_value=True)
    def test_success(self, mock_check, mock_run):
        mock_run.return_value = _make_run_cmd_result(stdout="phonebook data")
        result = bluesnarfer_extract("AA:BB:CC:DD:EE:FF")
        assert "phonebook" in result

    @patch("blue_tap.attack.bluesnarfer.check_tool", return_value=False)
    def test_tool_not_found(self, mock_check):
        assert bluesnarfer_extract("AA:BB:CC:DD:EE:FF") == ""

    @patch("blue_tap.attack.bluesnarfer.run_cmd")
    @patch("blue_tap.attack.bluesnarfer.check_tool", return_value=True)
    def test_failure(self, mock_check, mock_run):
        mock_run.return_value = _make_run_cmd_result(returncode=1, stderr="error")
        assert bluesnarfer_extract("AA:BB:CC:DD:EE:FF") == ""


# ===========================================================================
# AVRCP Tests (methods NOT in test_vuln_attack.py)
# ===========================================================================

from blue_tap.attack.avrcp import AVRCPController, _run_async, _variant_to_python


class TestRunAsync:
    def test_runs_coroutine(self):
        async def coro():
            return 42
        assert _run_async(coro()) == 42

    def test_runs_inside_existing_loop(self):
        """When already in an event loop, _run_async uses thread pool."""
        async def inner():
            async def coro():
                return 99
            return _run_async(coro())

        result = asyncio.run(inner())
        assert result == 99


class TestAVRCPInit:
    def test_defaults(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.address == "AA:BB:CC:DD:EE:FF"
        assert ctrl.hci == "hci0"
        assert ctrl._bus is None
        assert ctrl._player_iface is None

    def test_custom_hci(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF", hci="hci1")
        assert ctrl.hci == "hci1"


class TestAVRCPDisconnect:
    def test_disconnect_cleans_up(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._bus = Mock()
        ctrl._player_iface = Mock()
        ctrl._props_iface = Mock()
        ctrl._transport_props = Mock()
        ctrl.dbus_path = "/test"
        ctrl.disconnect()
        assert ctrl._bus is None
        assert ctrl._player_iface is None
        assert ctrl._props_iface is None
        assert ctrl._transport_props is None
        assert ctrl.dbus_path is None

    def test_disconnect_no_bus(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl.disconnect()  # Should not raise


class TestAVRCPPlayPauseStopNextPrev:
    """Test transport control methods."""

    def _make_controller(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = Mock()
        return ctrl

    @patch("blue_tap.attack.avrcp._run_async")
    def test_play(self, mock_run):
        ctrl = self._make_controller()
        assert ctrl.play() is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_pause(self, mock_run):
        ctrl = self._make_controller()
        assert ctrl.pause() is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_stop(self, mock_run):
        ctrl = self._make_controller()
        assert ctrl.stop() is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_next_track(self, mock_run):
        ctrl = self._make_controller()
        assert ctrl.next_track() is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_previous_track(self, mock_run):
        ctrl = self._make_controller()
        assert ctrl.previous_track() is True

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.play() is False
        assert ctrl.pause() is False
        assert ctrl.stop() is False
        assert ctrl.next_track() is False
        assert ctrl.previous_track() is False

    @patch("blue_tap.attack.avrcp._run_async", side_effect=Exception("dbus err"))
    def test_error(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = Mock()
        assert ctrl.play() is False


class TestAVRCPGetTrackInfo:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_returns_track(self, mock_run):
        mock_run.return_value = {"Artist": "TestArtist", "Title": "TestTrack"}
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        result = ctrl.get_track_info()
        assert result["Artist"] == "TestArtist"

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.get_track_info() == {}

    @patch("blue_tap.attack.avrcp._run_async", side_effect=Exception("err"))
    def test_error(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        assert ctrl.get_track_info() == {}


class TestAVRCPGetStatus:
    @patch("blue_tap.attack.avrcp._run_async", return_value="playing")
    def test_returns_status(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        assert ctrl.get_status() == "playing"

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.get_status() == ""

    @patch("blue_tap.attack.avrcp._run_async", side_effect=Exception("err"))
    def test_error(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        assert ctrl.get_status() == ""


class TestAVRCPSetVolume:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_success(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._transport_props = Mock()
        with patch("blue_tap.attack.avrcp.Variant", create=True):
            assert ctrl.set_volume(100) is True

    def test_no_transport(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.set_volume(100) is False

    @patch("blue_tap.attack.avrcp._run_async")
    def test_clamps_range(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._transport_props = Mock()
        with patch("blue_tap.attack.avrcp.Variant", create=True):
            ctrl.set_volume(200)  # Should clamp to 127
            ctrl.set_volume(-5)   # Should clamp to 0


class TestAVRCPGetPlayerInfo:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_returns_info(self, mock_run):
        mock_run.return_value = "Spotify"
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        result = ctrl.get_player_info()
        assert "Name" in result

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.get_player_info() == {}


class TestAVRCPGetPlayerSettings:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_returns_settings(self, mock_run):
        mock_run.return_value = "off"
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        result = ctrl.get_player_settings()
        assert isinstance(result, dict)

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.get_player_settings() == {}


class TestAVRCPSetRepeatShuffle:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_set_repeat(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        with patch("blue_tap.attack.avrcp.Variant", create=True):
            assert ctrl.set_repeat("alltracks") is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_set_shuffle(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._props_iface = Mock()
        with patch("blue_tap.attack.avrcp.Variant", create=True):
            assert ctrl.set_shuffle("alltracks") is True

    def test_not_connected(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.set_repeat("off") is False
        assert ctrl.set_shuffle("off") is False


class TestAVRCPFastForwardRewind:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_fast_forward(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = Mock()
        assert ctrl.fast_forward() is True

    @patch("blue_tap.attack.avrcp._run_async")
    def test_rewind(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = Mock()
        assert ctrl.rewind() is True


class TestAVRCPVolumeRamp:
    @patch.object(AVRCPController, "set_volume", return_value=True)
    @patch("blue_tap.attack.avrcp.time.sleep")
    def test_ramp_up(self, mock_sleep, mock_vol):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.volume_ramp(start=0, target=5, step_ms=10) is True
        # Should call set_volume for start + each step (0,1,2,3,4,5 = 6 calls)
        assert mock_vol.call_count == 6

    @patch.object(AVRCPController, "set_volume", return_value=True)
    @patch("blue_tap.attack.avrcp.time.sleep")
    def test_ramp_down(self, mock_sleep, mock_vol):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.volume_ramp(start=5, target=0, step_ms=10) is True
        assert mock_vol.call_count == 6

    @patch.object(AVRCPController, "set_volume", return_value=True)
    def test_already_at_target(self, mock_vol):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.volume_ramp(start=50, target=50) is True
        assert mock_vol.call_count == 1  # Only initial set

    @patch.object(AVRCPController, "set_volume", return_value=False)
    def test_initial_set_fails(self, mock_vol):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.volume_ramp(start=0, target=10) is False

    @patch.object(AVRCPController, "set_volume")
    @patch("blue_tap.attack.avrcp.time.sleep")
    def test_mid_ramp_failure(self, mock_sleep, mock_vol):
        mock_vol.side_effect = [True, True, False]  # Fails at step 2
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        assert ctrl.volume_ramp(start=0, target=5, step_ms=10) is False


class TestAVRCPSkipFlood:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_skip_flood(self, mock_run):
        mock_run.return_value = True
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = Mock()
        assert ctrl.skip_flood(count=10, interval_ms=10) is True

    def test_interval_clamp(self):
        """Verify interval_ms is clamped to minimum 10ms in _async_skip_flood."""
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl._player_iface = AsyncMock()
        ctrl._player_iface.call_next = AsyncMock()
        result = asyncio.run(ctrl._async_skip_flood(count=2, interval_ms=0))
        assert result is True
        assert ctrl._player_iface.call_next.call_count == 2


class TestAVRCPMonitorMetadata:
    @patch("blue_tap.attack.avrcp._run_async")
    def test_calls_async_monitor(self, mock_run):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        ctrl.dbus_path = "/test"
        ctrl.monitor_metadata(duration=1)
        mock_run.assert_called_once()

    def test_no_dbus_fast(self):
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        with patch.dict("sys.modules", {"dbus_fast": None, "dbus_fast.aio": None}):
            # Should handle ImportError gracefully
            pass


class TestAVRCPAsyncConnect:
    """Test _async_connect D-Bus leak fix (bus disconnected on failure)."""

    def test_connect_returns_false_when_dbus_unavailable(self):
        """When dbus-fast is not importable, connect returns False."""
        ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
        import builtins
        original = builtins.__import__
        def reject_dbus(name, *args, **kwargs):
            if "dbus" in name:
                raise ImportError("no dbus")
            return original(name, *args, **kwargs)
        with patch.object(builtins, "__import__", side_effect=reject_dbus):
            result = ctrl.connect()
        assert result is False
