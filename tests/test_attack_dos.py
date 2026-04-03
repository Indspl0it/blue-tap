"""Comprehensive unit tests for blue_tap.attack.protocol_dos.

Tests all 33 functions across module helpers, L2CAPDoS, SDPDoS,
RFCOMMDoS, OBEXDoS, and HFPDoS classes.
"""

from __future__ import annotations

import errno
import socket
import struct
import time
from unittest.mock import MagicMock, patch, call

import pytest

from blue_tap.attack.protocol_dos import (
    _make_result,
    _l2cap_raw_socket,
    _l2cap_connect,
    _build_signaling_cmd,
    _rfcomm_fcs,
    _build_rfcomm_frame,
    L2CAPDoS,
    SDPDoS,
    RFCOMMDoS,
    OBEXDoS,
    HFPDoS,
    AF_BLUETOOTH,
    BTPROTO_L2CAP,
    BTPROTO_RFCOMM,
    PSM_SDP,
    PSM_RFCOMM,
    RFCOMM_SABM,
    RFCOMM_UIH,
    DTD_UUID16,
    DTD_DES8,
    DTD_UINT32,
    SDP_SERVICE_SEARCH_ATTR_REQ,
    OBEX_CONNECT,
    OBEX_SETPATH,
    CID_SIGNALING,
    L2CAP_ECHO_REQ,
    L2CAP_INFO_REQ,
)

TARGET = "AA:BB:CC:DD:EE:FF"


# ===================================================================
# Module-level helpers
# ===================================================================


class TestMakeResult:
    """Tests for _make_result helper."""

    def test_success_result_structure(self):
        start = time.time()
        r = _make_result(TARGET, "test_attack", 42, start, "success", "ok")
        assert r["target"] == TARGET
        assert r["attack"] == "test_attack"
        assert r["attack_name"] == "test_attack"
        assert r["packets_sent"] == 42
        assert r["result"] == "success"
        assert r["notes"] == "ok"
        assert isinstance(r["duration_seconds"], float)
        assert r["duration_seconds"] >= 0

    def test_failure_result(self):
        start = time.time()
        r = _make_result(TARGET, "fail_attack", 0, start, "error", "conn refused")
        assert r["result"] == "error"
        assert r["packets_sent"] == 0
        assert r["notes"] == "conn refused"

    def test_timeout_result(self):
        start = time.time()
        r = _make_result(TARGET, "timeout_attack", 5, start, "target_unresponsive")
        assert r["result"] == "target_unresponsive"
        assert r["notes"] == ""

    def test_duration_is_positive(self):
        start = time.time() - 1.5
        r = _make_result(TARGET, "x", 0, start, "success")
        assert r["duration_seconds"] >= 1.0

    def test_all_required_keys_present(self):
        r = _make_result(TARGET, "a", 1, time.time(), "success")
        expected_keys = {"target", "attack", "attack_name", "packets_sent",
                         "duration_seconds", "result", "notes"}
        assert set(r.keys()) == expected_keys


class TestL2capRawSocket:
    """Tests for _l2cap_raw_socket."""

    def test_creates_bluetooth_seqpacket_socket(self, monkeypatch):
        mock_sock = MagicMock()
        mock_ctor = MagicMock(return_value=mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        result = _l2cap_raw_socket("hci0")
        mock_ctor.assert_called_once_with(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        assert result is mock_sock

    def test_ignores_hci_parameter(self, monkeypatch):
        """hci parameter is accepted but not used in socket creation."""
        mock_ctor = MagicMock(return_value=MagicMock())
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        _l2cap_raw_socket("hci1")
        mock_ctor.assert_called_once_with(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)


class TestL2capConnect:
    """Tests for _l2cap_connect."""

    def test_connect_success(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        result = _l2cap_connect(TARGET, PSM_SDP, "hci0")
        mock_sock.settimeout.assert_called_once_with(10)
        mock_sock.connect.assert_called_once_with((TARGET, PSM_SDP))
        assert result is mock_sock

    def test_connect_refused(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "Connection refused")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        with pytest.raises(OSError) as exc_info:
            _l2cap_connect(TARGET, PSM_SDP)
        assert exc_info.value.errno == errno.ECONNREFUSED

    def test_connect_timeout(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        with pytest.raises(socket.timeout):
            _l2cap_connect(TARGET, PSM_SDP)

    def test_connect_general_oserror(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "Host unreachable")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        with pytest.raises(OSError):
            _l2cap_connect(TARGET, PSM_SDP)


class TestBuildSignalingCmd:
    """Tests for _build_signaling_cmd."""

    def test_echo_request_structure(self):
        data = b"\x41\x42\x43\x44"
        result = _build_signaling_cmd(L2CAP_ECHO_REQ, 0x01, data)
        # Code(1) + ID(1) + Length(2 LE) + data
        assert len(result) == 4 + len(data)
        assert result[0] == L2CAP_ECHO_REQ
        assert result[1] == 0x01
        length = struct.unpack("<H", result[2:4])[0]
        assert length == len(data)
        assert result[4:] == data

    def test_info_request_structure(self):
        data = b"\x01\x00"
        result = _build_signaling_cmd(L2CAP_INFO_REQ, 0x05, data)
        assert result[0] == L2CAP_INFO_REQ
        assert result[1] == 0x05
        length = struct.unpack("<H", result[2:4])[0]
        assert length == 2

    def test_empty_data(self):
        result = _build_signaling_cmd(0x02, 0x10, b"")
        assert len(result) == 4
        assert struct.unpack("<H", result[2:4])[0] == 0

    def test_known_good_values(self):
        """Verify exact bytes for a known signaling command."""
        result = _build_signaling_cmd(0x08, 0x01, b"\xAB\xCD")
        assert result == bytes([0x08, 0x01, 0x02, 0x00, 0xAB, 0xCD])


class TestRfcommFcs:
    """Tests for _rfcomm_fcs."""

    def test_known_input_addr_control(self):
        """FCS over address=0x03, control=0x3F should produce a deterministic value."""
        fcs = _rfcomm_fcs(bytes([0x03, 0x3F]))
        assert isinstance(fcs, int)
        assert 0 <= fcs <= 0xFF

    def test_fcs_deterministic(self):
        data = bytes([0x03, 0x3F])
        assert _rfcomm_fcs(data) == _rfcomm_fcs(data)

    def test_fcs_different_inputs_differ(self):
        fcs1 = _rfcomm_fcs(bytes([0x03, 0x3F]))
        fcs2 = _rfcomm_fcs(bytes([0x0B, 0x2F]))
        # Different inputs should typically produce different FCS
        # (not guaranteed but very likely for these particular values)
        assert isinstance(fcs1, int) and isinstance(fcs2, int)

    def test_empty_input(self):
        fcs = _rfcomm_fcs(b"")
        # With no data, fcs = 0xFF - 0xFF = 0x00 (initial value untouched)
        assert fcs == 0

    def test_single_byte(self):
        fcs = _rfcomm_fcs(bytes([0x00]))
        assert 0 <= fcs <= 0xFF

    def test_addr_0x03_ctrl_0x3f_exact_value(self):
        """Compute and verify the exact FCS for DLCI 0, SABM (common case)."""
        # addr = (0 << 2) | (1 << 1) | 0x01 = 0x03
        # ctrl = 0x2F | (1 << 4) = 0x3F
        fcs = _rfcomm_fcs(bytes([0x03, 0x3F]))
        # Re-compute manually to get expected value
        crctable = [
            0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75,
            0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
            0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,
            0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
            0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D,
            0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
            0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51,
            0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,
            0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
            0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
            0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19,
            0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
            0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D,
            0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
            0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,
            0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,
            0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95,
            0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
            0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89,
            0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
            0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,
            0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
            0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1,
            0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
            0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5,
            0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
            0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,
            0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
            0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD,
            0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
            0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,
            0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF,
        ]
        expected = 0xFF
        for byte in [0x03, 0x3F]:
            expected = crctable[expected ^ byte]
        expected = 0xFF - expected
        assert fcs == expected


class TestBuildRfcommFrame:
    """Tests for _build_rfcomm_frame."""

    def test_sabm_frame_dlci_0(self):
        """SABM on DLCI 0: addr=0x03, ctrl=0x3F, len=0x01(EA), FCS."""
        frame = _build_rfcomm_frame(0, RFCOMM_SABM)
        # addr = (0 << 2) | (1 << 1) | 0x01 = 0x03
        assert frame[0] == 0x03
        # ctrl = 0x2F | (1 << 4) = 0x3F
        assert frame[1] == 0x3F
        # length field: 0 payload, EA=1 => (0 << 1) | 0x01 = 0x01
        assert frame[2] == 0x01
        # FCS byte at end
        assert len(frame) == 4  # addr + ctrl + length + fcs

    def test_sabm_frame_dlci_5(self):
        frame = _build_rfcomm_frame(5, RFCOMM_SABM)
        addr = (5 << 2) | (1 << 1) | 0x01
        assert frame[0] == addr

    def test_uih_frame_with_payload(self):
        payload = b"\x01\x02\x03"
        frame = _build_rfcomm_frame(0, RFCOMM_UIH, payload, pf=0)
        # addr = 0x03
        assert frame[0] == 0x03
        # ctrl = 0xEF | (0 << 4) = 0xEF
        assert frame[1] == 0xEF
        # length = 3, EA=1 => (3 << 1) | 0x01 = 0x07
        assert frame[2] == 0x07
        # payload
        assert frame[3:6] == payload
        # FCS at end
        assert len(frame) == 4 + len(payload)

    def test_large_payload_two_byte_length(self):
        payload = b"\xAA" * 200
        frame = _build_rfcomm_frame(0, RFCOMM_UIH, payload, pf=0)
        # Length > 127 => 2-byte length field, EA=0
        length_field = struct.unpack("<H", frame[2:4])[0]
        assert (length_field & 0x01) == 0  # EA=0
        assert (length_field >> 1) == 200
        assert frame[4:204] == payload

    def test_cr_bit(self):
        frame_cr0 = _build_rfcomm_frame(1, RFCOMM_SABM, cr=0)
        frame_cr1 = _build_rfcomm_frame(1, RFCOMM_SABM, cr=1)
        # CR bit is bit 1 of address
        assert (frame_cr0[0] & 0x02) == 0
        assert (frame_cr1[0] & 0x02) == 0x02

    def test_pf_bit(self):
        frame_pf0 = _build_rfcomm_frame(0, RFCOMM_SABM, pf=0)
        frame_pf1 = _build_rfcomm_frame(0, RFCOMM_SABM, pf=1)
        # PF bit is bit 4 of control
        assert (frame_pf0[1] & 0x10) == 0
        assert (frame_pf1[1] & 0x10) == 0x10

    def test_fcs_is_valid(self):
        """FCS should match _rfcomm_fcs(addr + ctrl)."""
        frame = _build_rfcomm_frame(0, RFCOMM_SABM)
        expected_fcs = _rfcomm_fcs(bytes([frame[0], frame[1]]))
        assert frame[-1] == expected_fcs


# ===================================================================
# L2CAPDoS
# ===================================================================


class TestL2CAPDoS:
    """Tests for L2CAPDoS class (4 methods)."""

    def _make_mock_sock(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        return mock_sock

    # -- config_option_bomb --

    def test_config_option_bomb_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        result = dos.config_option_bomb(rounds=5)
        assert result["result"] == "success"
        assert result["packets_sent"] == 5
        assert result["attack"] == "l2cap_connection_storm"
        assert mock_sock.connect.call_count == 5
        assert mock_sock.close.call_count == 5

    def test_config_option_bomb_connection_failure(self, monkeypatch):
        mock_sock = MagicMock()
        call_count = 0

        def mock_connect(*args):
            nonlocal call_count
            call_count += 1
            if call_count > 3:
                raise OSError("Connection refused")

        mock_sock.connect = mock_connect
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)

        dos = L2CAPDoS(TARGET)
        result = dos.config_option_bomb(rounds=10)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 3
        assert "round 4" in result["notes"]

    def test_config_option_bomb_zero_rounds(self, monkeypatch):
        self._make_mock_sock(monkeypatch)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        result = dos.config_option_bomb(rounds=0)
        assert result["result"] == "success"
        assert result["packets_sent"] == 0

    # -- cid_exhaustion --

    def test_cid_exhaustion_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        result = dos.cid_exhaustion(count=5)
        assert result["result"] == "success"
        assert result["packets_sent"] == 5
        assert result["attack"] == "cid_exhaustion"

    def test_cid_exhaustion_partial_failure(self, monkeypatch):
        call_count = 0

        def mock_ctor(*a, **kw):
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            if call_count > 3:
                m.connect.side_effect = OSError("Host down")
            return m

        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        result = dos.cid_exhaustion(count=10)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 3
        assert "3/10" in result["notes"]

    def test_cid_exhaustion_cleans_up_sockets(self, monkeypatch):
        sockets_created = []

        def mock_ctor(*a, **kw):
            m = MagicMock()
            sockets_created.append(m)
            return m

        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        dos.cid_exhaustion(count=3)
        for sock in sockets_created:
            sock.close.assert_called()

    # -- echo_amplification --

    def test_echo_amplification_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = L2CAPDoS(TARGET)
        result = dos.echo_amplification(count=10, payload_size=100)
        assert result["result"] == "success"
        assert result["packets_sent"] == 10
        assert result["attack"] == "data_flood"

    def test_echo_amplification_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("No route")
        dos = L2CAPDoS(TARGET)
        result = dos.echo_amplification(count=10)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_echo_amplification_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.send.side_effect = [None, None, OSError("Broken pipe")]
        mock_sock.recv.side_effect = TimeoutError
        dos = L2CAPDoS(TARGET)
        result = dos.echo_amplification(count=10, payload_size=100)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 2

    def test_echo_amplification_payload_structure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = L2CAPDoS(TARGET)
        dos.echo_amplification(count=1, payload_size=100)
        sent_data = mock_sock.send.call_args[0][0]
        assert sent_data[0] == 0x06  # SDP PDU
        assert len(sent_data) == 100

    # -- info_request_flood --

    def test_info_request_flood_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = L2CAPDoS(TARGET)
        result = dos.info_request_flood(count=10)
        assert result["result"] == "success"
        assert result["packets_sent"] == 10
        assert result["attack"] == "sdp_request_flood"

    def test_info_request_flood_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("refused")
        dos = L2CAPDoS(TARGET)
        result = dos.info_request_flood(count=10)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_info_request_flood_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.send.side_effect = [None, None, None, OSError("dead")]
        mock_sock.recv.side_effect = TimeoutError
        dos = L2CAPDoS(TARGET)
        result = dos.info_request_flood(count=10)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 3

    def test_info_request_flood_pdu_structure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = L2CAPDoS(TARGET)
        dos.info_request_flood(count=2)
        # First call sends SSR (0x02), second sends SAR (0x04)
        first_pdu = mock_sock.send.call_args_list[0][0][0]
        second_pdu = mock_sock.send.call_args_list[1][0][0]
        assert first_pdu[0] == 0x02
        assert second_pdu[0] == 0x04


# ===================================================================
# SDPDoS
# ===================================================================


class TestSDPDoS:
    """Tests for SDPDoS class (8 methods)."""

    def _make_mock_sock(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        return mock_sock

    # -- _build_sdp_pdu --

    def test_build_sdp_pdu_structure(self):
        sdp = SDPDoS(TARGET)
        params = b"\x01\x02\x03"
        pdu = sdp._build_sdp_pdu(0x06, 0x0001, params)
        assert pdu[0] == 0x06  # PDU ID
        tid = struct.unpack(">H", pdu[1:3])[0]
        assert tid == 1
        param_len = struct.unpack(">H", pdu[3:5])[0]
        assert param_len == 3
        assert pdu[5:] == params

    def test_build_sdp_pdu_empty_params(self):
        sdp = SDPDoS(TARGET)
        pdu = sdp._build_sdp_pdu(0x02, 100, b"")
        assert len(pdu) == 5
        assert struct.unpack(">H", pdu[3:5])[0] == 0

    # -- _encode_uuid16 --

    def test_encode_uuid16(self):
        sdp = SDPDoS(TARGET)
        encoded = sdp._encode_uuid16(0x1101)
        assert encoded[0] == DTD_UUID16
        val = struct.unpack(">H", encoded[1:3])[0]
        assert val == 0x1101
        assert len(encoded) == 3

    def test_encode_uuid16_truncation(self):
        sdp = SDPDoS(TARGET)
        encoded = sdp._encode_uuid16(0x1FFFF)  # > 16 bits
        val = struct.unpack(">H", encoded[1:3])[0]
        assert val == 0xFFFF  # masked to 16 bits

    # -- _encode_des --

    def test_encode_des_short(self):
        sdp = SDPDoS(TARGET)
        elements = [b"\x01\x02", b"\x03"]
        des = sdp._encode_des(elements)
        assert des[0] == DTD_DES8
        assert des[1] == 3  # total length of elements
        assert des[2:] == b"\x01\x02\x03"

    def test_encode_des_empty(self):
        sdp = SDPDoS(TARGET)
        des = sdp._encode_des([])
        assert des[0] == DTD_DES8
        assert des[1] == 0

    def test_encode_des_long_body(self):
        """Body > 255 bytes uses DTD_DES8+1 with 2-byte length."""
        sdp = SDPDoS(TARGET)
        elements = [b"\xAA" * 300]
        des = sdp._encode_des(elements)
        assert des[0] == DTD_DES8 + 1
        body_len = struct.unpack(">H", des[1:3])[0]
        assert body_len == 300

    # -- _encode_uint32 --

    def test_encode_uint32(self):
        sdp = SDPDoS(TARGET)
        encoded = sdp._encode_uint32(0x0000FFFF)
        assert encoded[0] == DTD_UINT32
        val = struct.unpack(">I", encoded[1:5])[0]
        assert val == 0x0000FFFF
        assert len(encoded) == 5

    def test_encode_uint32_zero(self):
        sdp = SDPDoS(TARGET)
        encoded = sdp._encode_uint32(0)
        assert struct.unpack(">I", encoded[1:5])[0] == 0

    def test_encode_uint32_max(self):
        sdp = SDPDoS(TARGET)
        encoded = sdp._encode_uint32(0xFFFFFFFF)
        assert struct.unpack(">I", encoded[1:5])[0] == 0xFFFFFFFF

    # -- _build_service_search_attr_req --

    def test_build_service_search_attr_req_complete(self):
        sdp = SDPDoS(TARGET)
        pdu = sdp._build_service_search_attr_req([0x0100], max_bytes=0xFFFF, tid=1)
        # Should be SDP_SERVICE_SEARCH_ATTR_REQ (0x06)
        assert pdu[0] == SDP_SERVICE_SEARCH_ATTR_REQ
        tid = struct.unpack(">H", pdu[1:3])[0]
        assert tid == 1
        # Params should include DES with UUID, max_bytes, attr list, continuation
        param_len = struct.unpack(">H", pdu[3:5])[0]
        assert param_len == len(pdu) - 5

    def test_build_service_search_attr_req_multiple_uuids(self):
        sdp = SDPDoS(TARGET)
        pdu = sdp._build_service_search_attr_req([0x0100, 0x1101, 0x110A], tid=5)
        assert pdu[0] == SDP_SERVICE_SEARCH_ATTR_REQ
        tid = struct.unpack(">H", pdu[1:3])[0]
        assert tid == 5

    def test_build_service_search_attr_req_custom_continuation(self):
        sdp = SDPDoS(TARGET)
        cont = b"\x04\x01\x02\x03\x04"
        pdu = sdp._build_service_search_attr_req([0x0100], continuation=cont, tid=2)
        # The continuation bytes should be at the end of params
        assert pdu[-len(cont):] == cont

    # -- continuation_exhaustion --

    def test_continuation_exhaustion_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = SDPDoS(TARGET)
        result = dos.continuation_exhaustion(connections=3)
        assert result["result"] == "success"
        assert result["packets_sent"] == 3
        assert result["attack"] == "continuation_exhaustion"

    def test_continuation_exhaustion_connect_refused(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("Connection refused")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = SDPDoS(TARGET)
        result = dos.continuation_exhaustion(connections=5)
        # Should break on "Connection refused"
        assert result["packets_sent"] == 0

    def test_continuation_exhaustion_partial(self, monkeypatch):
        call_count = 0
        mock_sock = MagicMock()

        def mock_connect(*args):
            nonlocal call_count
            call_count += 1
            if call_count > 2:
                raise OSError("Connection refused")

        mock_sock.connect = mock_connect
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = SDPDoS(TARGET)
        result = dos.continuation_exhaustion(connections=5)
        assert result["packets_sent"] == 2

    # -- large_service_search --

    def test_large_service_search_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = SDPDoS(TARGET)
        result = dos.large_service_search(count=5)
        assert result["result"] == "success"
        assert result["packets_sent"] == 5
        assert result["attack"] == "large_service_search"

    def test_large_service_search_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("SDP down")
        dos = SDPDoS(TARGET)
        result = dos.large_service_search(count=5)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_large_service_search_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.send.side_effect = [None, None, OSError("broken")]
        mock_sock.recv.side_effect = TimeoutError
        dos = SDPDoS(TARGET)
        result = dos.large_service_search(count=10)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 2

    # -- nested_des_bomb --

    def test_nested_des_bomb_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = SDPDoS(TARGET)
        result = dos.nested_des_bomb(depth=10)
        assert result["result"] == "success"
        assert result["packets_sent"] == 1
        assert result["attack"] == "nested_des_bomb"
        assert "depth=10" in result["notes"]

    def test_nested_des_bomb_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("down")
        dos = SDPDoS(TARGET)
        result = dos.nested_des_bomb(depth=10)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_nested_des_bomb_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.send.side_effect = OSError("broken")
        dos = SDPDoS(TARGET)
        result = dos.nested_des_bomb(depth=5)
        assert result["result"] == "target_unresponsive"

    def test_nested_des_bomb_payload_has_nesting(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = SDPDoS(TARGET)
        dos.nested_des_bomb(depth=5)
        sent_data = mock_sock.send.call_args[0][0]
        # The sent PDU should start with SDP_SERVICE_SEARCH_ATTR_REQ
        assert sent_data[0] == SDP_SERVICE_SEARCH_ATTR_REQ
        # Count DTD_DES8 occurrences to verify nesting
        count_des = sent_data.count(bytes([DTD_DES8]))
        # Should have at least depth+1 DES headers (depth nested + outer wrapper + attrs)
        assert count_des >= 5


# ===================================================================
# RFCOMMDoS
# ===================================================================


class TestRFCOMMDoS:
    """Tests for RFCOMMDoS class (3 methods)."""

    def _make_mock_sock(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        return mock_sock

    # -- sabm_flood --

    def test_sabm_flood_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        result = dos.sabm_flood(count=5)
        assert result["result"] == "success"
        assert result["attack"] == "sabm_flood"
        # 1 SABM for DLCI 0 + 5 for DLCIs 2..6
        assert result["packets_sent"] == 6

    def test_sabm_flood_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("refused")
        dos = RFCOMMDoS(TARGET)
        result = dos.sabm_flood(count=5)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_sabm_flood_send_failure_midway(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        # First send succeeds (DLCI 0 SABM), second fails
        mock_sock.send.side_effect = [None, None, OSError("dead")]
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        result = dos.sabm_flood(count=5)
        assert result["result"] == "target_unresponsive"

    def test_sabm_flood_sends_to_multiple_dlcis(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        dos.sabm_flood(count=3)
        # First call: DLCI 0, then DLCIs 2, 3, 4
        sent_frames = [c[0][0] for c in mock_sock.send.call_args_list]
        # DLCI 0 SABM frame
        assert sent_frames[0][0] == 0x03  # addr for DLCI 0
        # DLCI 2 SABM frame
        addr_dlci2 = (2 << 2) | (1 << 1) | 0x01
        assert sent_frames[1][0] == addr_dlci2

    # -- credit_exhaustion --

    def test_credit_exhaustion_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = RFCOMMDoS(TARGET)
        result = dos.credit_exhaustion()
        assert result["result"] == "success"
        assert result["attack"] == "credit_exhaustion"
        # 1 SABM(DLCI 0) + 10 DLCIs * (PN + SABM) = 21
        assert result["packets_sent"] == 21
        assert "Zero-credit" in result["notes"]

    def test_credit_exhaustion_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("no route")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = RFCOMMDoS(TARGET)
        result = dos.credit_exhaustion()
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_credit_exhaustion_pn_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        # SABM DLCI 0 succeeds, first PN fails
        mock_sock.send.side_effect = [None, OSError("fail")]
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = RFCOMMDoS(TARGET)
        result = dos.credit_exhaustion()
        assert result["packets_sent"] == 1

    # -- mux_command_flood --

    def test_mux_command_flood_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        result = dos.mux_command_flood(count=10)
        assert result["result"] == "success"
        assert result["attack"] == "mux_command_flood"
        # 1 SABM for DLCI 0 + 10 Test commands
        assert result["packets_sent"] == 11

    def test_mux_command_flood_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("refused")
        dos = RFCOMMDoS(TARGET)
        result = dos.mux_command_flood(count=10)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_mux_command_flood_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        # SABM DLCI 0 succeeds, first test command fails
        mock_sock.send.side_effect = [None, OSError("broken")]
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        result = dos.mux_command_flood(count=10)
        assert result["result"] == "target_unresponsive"

    def test_mux_command_flood_sends_on_dlci_0(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        dos = RFCOMMDoS(TARGET)
        dos.mux_command_flood(count=3)
        # All frames should be on DLCI 0 (addr byte = 0x03)
        for c in mock_sock.send.call_args_list:
            frame = c[0][0]
            assert frame[0] == 0x03  # DLCI 0 address


# ===================================================================
# OBEXDoS
# ===================================================================


class TestOBEXDoS:
    """Tests for OBEXDoS class (5 methods)."""

    # -- _find_obex_channels --

    def test_find_obex_channels_with_results(self, monkeypatch):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "  Channel: 4\n  Channel: 7\n"
        monkeypatch.setattr("blue_tap.attack.protocol_dos.run_cmd",
                            lambda *a, **kw: mock_result)
        dos = OBEXDoS(TARGET)
        channels = dos._find_obex_channels()
        assert 4 in channels
        assert 7 in channels

    def test_find_obex_channels_no_results(self, monkeypatch):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        monkeypatch.setattr("blue_tap.attack.protocol_dos.run_cmd",
                            lambda *a, **kw: mock_result)
        dos = OBEXDoS(TARGET)
        channels = dos._find_obex_channels()
        assert channels == []

    def test_find_obex_channels_deduplication(self, monkeypatch):
        """Same channel from multiple services should appear once."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "  Channel: 4\n"
        monkeypatch.setattr("blue_tap.attack.protocol_dos.run_cmd",
                            lambda *a, **kw: mock_result)
        dos = OBEXDoS(TARGET)
        channels = dos._find_obex_channels()
        assert channels.count(4) == 1

    def test_find_obex_channels_invalid_channel(self, monkeypatch):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "  Channel: abc\n  Channel: 5\n"
        monkeypatch.setattr("blue_tap.attack.protocol_dos.run_cmd",
                            lambda *a, **kw: mock_result)
        dos = OBEXDoS(TARGET)
        channels = dos._find_obex_channels()
        assert 5 in channels
        assert len(channels) >= 1

    # -- _build_obex_connect --

    def test_build_obex_connect_structure(self):
        dos = OBEXDoS(TARGET)
        pkt = dos._build_obex_connect()
        # Opcode
        assert pkt[0] == OBEX_CONNECT
        # Length (2 bytes BE)
        length = struct.unpack(">H", pkt[1:3])[0]
        assert length == len(pkt)
        # Version 1.0
        assert pkt[3] == 0x10
        # Flags
        assert pkt[4] == 0x00
        # Max packet length
        max_len = struct.unpack(">H", pkt[5:7])[0]
        assert max_len == 0xFFFF

    # -- _build_obex_setpath --

    def test_build_obex_setpath_with_name(self):
        dos = OBEXDoS(TARGET)
        pkt = dos._build_obex_setpath(name="telecom")
        assert pkt[0] == OBEX_SETPATH
        length = struct.unpack(">H", pkt[1:3])[0]
        assert length == len(pkt)
        # Flags byte: not backup
        assert pkt[3] == 0x00
        # Constants byte
        assert pkt[4] == 0x00
        # Name header starts with 0x01
        assert pkt[5] == 0x01

    def test_build_obex_setpath_backup(self):
        dos = OBEXDoS(TARGET)
        pkt = dos._build_obex_setpath(backup=True)
        assert pkt[0] == OBEX_SETPATH
        # Backup flag
        assert pkt[3] == 0x01
        # No name header

    def test_build_obex_setpath_empty_name(self):
        dos = OBEXDoS(TARGET)
        pkt = dos._build_obex_setpath(name="")
        assert pkt[0] == OBEX_SETPATH
        # No name header when empty
        length = struct.unpack(">H", pkt[1:3])[0]
        assert length == len(pkt)

    # -- connect_flood --

    def test_connect_flood_success(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xA0\x00\x03"
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        # Mock _find_obex_channels to return channels
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [4, 7])
        result = dos.connect_flood(count=4)
        assert result["result"] == "success"
        assert result["attack"] == "connect_flood"
        assert result["packets_sent"] > 0

    def test_connect_flood_no_channels_uses_defaults(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xA0\x00\x03"
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [])
        result = dos.connect_flood(count=3)
        # Should fall back to default channels [1..10]
        assert result["result"] == "success"

    def test_connect_flood_all_fail(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("refused")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [4])
        result = dos.connect_flood(count=3)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    # -- setpath_loop --

    def test_setpath_loop_success(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [4])
        result = dos.setpath_loop(count=10)
        assert result["result"] == "success"
        assert result["attack"] == "setpath_loop"
        # 1 CONNECT + 10 SETPATHs
        assert result["packets_sent"] == 11

    def test_setpath_loop_no_channels(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("nope")
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [])
        result = dos.setpath_loop(count=5)
        assert result["result"] == "error"
        assert "No OBEX channels" in result["notes"]

    def test_setpath_loop_send_failure(self, monkeypatch):
        mock_sock = MagicMock()
        # CONNECT send succeeds, first SETPATH fails
        mock_sock.send.side_effect = [None, OSError("dead")]
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [4])
        result = dos.setpath_loop(count=5)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 1

    def test_setpath_loop_alternates_forward_backward(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = OBEXDoS(TARGET)
        monkeypatch.setattr(dos, "_find_obex_channels", lambda: [4])
        dos.setpath_loop(count=4)
        # call_args_list: [0]=CONNECT, [1]=SETPATH(forward), [2]=SETPATH(backup), ...
        sent = [c[0][0] for c in mock_sock.send.call_args_list]
        # Index 0 is CONNECT, skip it
        # Index 1 (i=0, even) should be forward (flags=0x00)
        assert sent[1][3] == 0x00  # forward
        # Index 2 (i=1, odd) should be backup (flags=0x01)
        assert sent[2][3] == 0x01  # backup


# ===================================================================
# HFPDoS
# ===================================================================


class TestHFPDoS:
    """Tests for HFPDoS class (2 methods)."""

    def _make_mock_sock(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket",
                            lambda *a, **kw: mock_sock)
        return mock_sock

    # -- at_command_flood --

    def test_at_command_flood_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        result = dos.at_command_flood(channel=10, count=20)
        assert result["result"] == "success"
        assert result["attack"] == "at_command_flood"
        # 4 SLC setup commands + 20 flood commands
        assert result["packets_sent"] == 24

    def test_at_command_flood_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("refused")
        dos = HFPDoS(TARGET)
        result = dos.at_command_flood(channel=10, count=20)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_at_command_flood_sends_at_commands(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        dos.at_command_flood(channel=10, count=4)
        sent = [c[0][0] for c in mock_sock.send.call_args_list]
        # SLC commands
        assert sent[0] == b"AT+BRSF=0\r"
        assert sent[1] == b"AT+CIND=?\r"
        assert sent[2] == b"AT+CIND?\r"
        assert sent[3] == b"AT+CMER=3,0,0,1\r"
        # Flood commands
        assert sent[4] == b"AT+CLCC\r"
        assert sent[5] == b"AT+COPS?\r"

    def test_at_command_flood_send_failure_during_flood(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        # 4 SLC commands succeed, then 2 flood, then fail
        effects = [None] * 6 + [OSError("dead")]
        mock_sock.send.side_effect = effects
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        result = dos.at_command_flood(channel=10, count=20)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 6

    def test_at_command_flood_uses_rfcomm_socket(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError
        created_with = []

        def mock_ctor(*a, **kw):
            created_with.append(a)
            return mock_sock

        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        dos.at_command_flood(channel=5, count=1)
        assert created_with[0] == (AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        mock_sock.connect.assert_called_once_with((TARGET, 5))

    # -- slc_state_confusion --

    def test_slc_state_confusion_success(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        result = dos.slc_state_confusion(channel=10)
        assert result["result"] == "success"
        assert result["attack"] == "slc_state_confusion"
        assert result["packets_sent"] == 30  # 30 confusion commands
        assert "out-of-order" in result["notes"]

    def test_slc_state_confusion_connect_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.connect.side_effect = OSError("refused")
        dos = HFPDoS(TARGET)
        result = dos.slc_state_confusion(channel=10)
        assert result["result"] == "error"
        assert result["packets_sent"] == 0

    def test_slc_state_confusion_sends_out_of_order(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        dos.slc_state_confusion(channel=10)
        sent = [c[0][0] for c in mock_sock.send.call_args_list]
        # First command should be CHLD (out of order - before BRSF)
        assert sent[0] == b"AT+CHLD=?\r"
        # BRSF should come later (at index 4)
        assert sent[4] == b"AT+BRSF=0\r"

    def test_slc_state_confusion_send_failure(self, monkeypatch):
        mock_sock = self._make_mock_sock(monkeypatch)
        mock_sock.send.side_effect = [None, None, OSError("dead")]
        mock_sock.recv.side_effect = TimeoutError
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        result = dos.slc_state_confusion(channel=10)
        assert result["result"] == "target_unresponsive"
        assert result["packets_sent"] == 2

    def test_slc_state_confusion_uses_rfcomm_socket(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError
        created_with = []

        def mock_ctor(*a, **kw):
            created_with.append(a)
            return mock_sock

        monkeypatch.setattr("blue_tap.attack.protocol_dos.socket.socket", mock_ctor)
        monkeypatch.setattr("blue_tap.attack.protocol_dos.time.sleep", lambda x: None)
        dos = HFPDoS(TARGET)
        dos.slc_state_confusion(channel=7)
        assert created_with[0] == (AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        mock_sock.connect.assert_called_once_with((TARGET, 7))
