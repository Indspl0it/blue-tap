"""Comprehensive unit tests for all 8 fuzz protocol builder modules.

Tests every public function in:
  - blue_tap.fuzz.protocols.sdp
  - blue_tap.fuzz.protocols.att
  - blue_tap.fuzz.protocols.l2cap
  - blue_tap.fuzz.protocols.rfcomm
  - blue_tap.fuzz.protocols.obex
  - blue_tap.fuzz.protocols.smp
  - blue_tap.fuzz.protocols.bnep
  - blue_tap.fuzz.protocols.at_commands
"""

from __future__ import annotations

import struct

import pytest


# ======================================================================
# SDP Protocol Tests
# ======================================================================

class TestSDPEncoders:
    """Test all SDP data element encoders."""

    def test_encode_nil(self):
        from blue_tap.fuzz.protocols.sdp import encode_nil, DTD_NIL
        result = encode_nil()
        assert result == bytes([DTD_NIL])
        assert len(result) == 1

    def test_encode_uint8(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint8, DTD_UINT8
        result = encode_uint8(0x42)
        assert result == bytes([DTD_UINT8, 0x42])
        assert len(result) == 2

    def test_encode_uint8_max(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint8
        result = encode_uint8(0xFF)
        assert result[1] == 0xFF

    def test_encode_uint8_overflow_masked(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint8
        result = encode_uint8(0x1FF)
        assert result[1] == 0xFF  # masked to 0xFF

    def test_encode_uint16(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint16, DTD_UINT16
        result = encode_uint16(0x1234)
        assert result[0] == DTD_UINT16
        assert struct.unpack(">H", result[1:])[0] == 0x1234
        assert len(result) == 3

    def test_encode_uint32(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint32, DTD_UINT32
        result = encode_uint32(0xDEADBEEF)
        assert result[0] == DTD_UINT32
        assert struct.unpack(">I", result[1:])[0] == 0xDEADBEEF
        assert len(result) == 5

    def test_encode_uint64(self):
        from blue_tap.fuzz.protocols.sdp import encode_uint64, DTD_UINT64
        result = encode_uint64(0x123456789ABCDEF0)
        assert result[0] == DTD_UINT64
        assert struct.unpack(">Q", result[1:])[0] == 0x123456789ABCDEF0
        assert len(result) == 9

    def test_encode_sint8(self):
        from blue_tap.fuzz.protocols.sdp import encode_sint8, DTD_SINT8
        result = encode_sint8(-1)
        assert result[0] == DTD_SINT8
        assert struct.unpack(">b", result[1:])[0] == -1

    def test_encode_sint16(self):
        from blue_tap.fuzz.protocols.sdp import encode_sint16, DTD_SINT16
        result = encode_sint16(-1000)
        assert result[0] == DTD_SINT16
        assert struct.unpack(">h", result[1:])[0] == -1000

    def test_encode_sint32(self):
        from blue_tap.fuzz.protocols.sdp import encode_sint32, DTD_SINT32
        result = encode_sint32(-100000)
        assert result[0] == DTD_SINT32
        assert struct.unpack(">i", result[1:])[0] == -100000

    def test_encode_uuid16(self):
        from blue_tap.fuzz.protocols.sdp import encode_uuid16, DTD_UUID16
        result = encode_uuid16(0x1101)
        assert result[0] == DTD_UUID16
        assert struct.unpack(">H", result[1:])[0] == 0x1101
        assert len(result) == 3

    def test_encode_uuid32(self):
        from blue_tap.fuzz.protocols.sdp import encode_uuid32, DTD_UUID32
        result = encode_uuid32(0x00001101)
        assert result[0] == DTD_UUID32
        assert len(result) == 5

    def test_encode_uuid128(self):
        from blue_tap.fuzz.protocols.sdp import encode_uuid128, DTD_UUID128
        val = b"\x01" * 16
        result = encode_uuid128(val)
        assert result[0] == DTD_UUID128
        assert result[1:] == val
        assert len(result) == 17

    def test_encode_uuid128_wrong_length(self):
        from blue_tap.fuzz.protocols.sdp import encode_uuid128
        with pytest.raises(ValueError, match="16 bytes"):
            encode_uuid128(b"\x01" * 15)

    def test_encode_string_short(self):
        from blue_tap.fuzz.protocols.sdp import encode_string, DTD_STR8
        result = encode_string("Hello")
        assert result[0] == DTD_STR8
        assert result[1] == 5  # length
        assert result[2:] == b"Hello"

    def test_encode_string_empty(self):
        from blue_tap.fuzz.protocols.sdp import encode_string, DTD_STR8
        result = encode_string("")
        assert result[0] == DTD_STR8
        assert result[1] == 0

    def test_encode_bool_true(self):
        from blue_tap.fuzz.protocols.sdp import encode_bool, DTD_BOOL
        result = encode_bool(True)
        assert result == bytes([DTD_BOOL, 0x01])

    def test_encode_bool_false(self):
        from blue_tap.fuzz.protocols.sdp import encode_bool, DTD_BOOL
        result = encode_bool(False)
        assert result == bytes([DTD_BOOL, 0x00])

    def test_encode_des_empty(self):
        from blue_tap.fuzz.protocols.sdp import encode_des, DTD_DES8
        result = encode_des([])
        assert result == bytes([DTD_DES8, 0x00])

    def test_encode_des_with_elements(self):
        from blue_tap.fuzz.protocols.sdp import encode_des, encode_uint8, DTD_DES8
        elem = encode_uint8(0x42)
        result = encode_des([elem])
        assert result[0] == DTD_DES8
        assert result[1] == len(elem)
        assert result[2:] == elem

    def test_encode_dea_empty(self):
        from blue_tap.fuzz.protocols.sdp import encode_dea, DTD_DEA8
        result = encode_dea([])
        assert result == bytes([DTD_DEA8, 0x00])

    def test_encode_dea_with_elements(self):
        from blue_tap.fuzz.protocols.sdp import encode_dea, encode_uint16, DTD_DEA8
        elem = encode_uint16(0x1234)
        result = encode_dea([elem])
        assert result[0] == DTD_DEA8
        assert result[1] == len(elem)

    def test_encode_url(self):
        from blue_tap.fuzz.protocols.sdp import encode_url, DTD_URL8
        result = encode_url("http://test.com")
        assert result[0] == DTD_URL8
        assert result[1] == len("http://test.com")


class TestSDPPDUBuilder:
    """Test SDP PDU header construction."""

    def test_build_sdp_pdu(self):
        from blue_tap.fuzz.protocols.sdp import build_sdp_pdu
        result = build_sdp_pdu(0x02, 0x0001, b"\xAA\xBB")
        assert len(result) == 5 + 2
        assert result[0] == 0x02  # PDU ID
        assert struct.unpack(">H", result[1:3])[0] == 0x0001  # TID
        assert struct.unpack(">H", result[3:5])[0] == 2  # param length
        assert result[5:] == b"\xAA\xBB"

    def test_build_sdp_pdu_empty_params(self):
        from blue_tap.fuzz.protocols.sdp import build_sdp_pdu
        result = build_sdp_pdu(0x01, 0, b"")
        assert len(result) == 5
        assert struct.unpack(">H", result[3:5])[0] == 0


class TestSDPRequestBuilders:
    """Test SDP request builders."""

    def test_build_service_search_req(self):
        from blue_tap.fuzz.protocols.sdp import (
            build_service_search_req, SDP_SERVICE_SEARCH_REQ,
        )
        result = build_service_search_req([0x0100], max_count=10, tid=5)
        assert isinstance(result, bytes)
        assert len(result) > 5
        assert result[0] == SDP_SERVICE_SEARCH_REQ
        assert struct.unpack(">H", result[1:3])[0] == 5  # TID

    def test_build_service_search_req_defaults(self):
        from blue_tap.fuzz.protocols.sdp import build_service_search_req
        result = build_service_search_req([0x0001])
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_build_service_attr_req(self):
        from blue_tap.fuzz.protocols.sdp import (
            build_service_attr_req, SDP_SERVICE_ATTR_REQ,
        )
        result = build_service_attr_req(handle=0x00010000, max_bytes=100, tid=2)
        assert isinstance(result, bytes)
        assert result[0] == SDP_SERVICE_ATTR_REQ

    def test_build_service_attr_req_custom_ranges(self):
        from blue_tap.fuzz.protocols.sdp import build_service_attr_req
        result = build_service_attr_req(
            handle=1, attr_ranges=[(0x0000, 0x0100), (0x0200, 0x0300)],
        )
        assert isinstance(result, bytes)
        assert len(result) > 5

    def test_build_service_search_attr_req(self):
        from blue_tap.fuzz.protocols.sdp import (
            build_service_search_attr_req, SDP_SERVICE_SEARCH_ATTR_REQ,
        )
        result = build_service_search_attr_req([0x0100, 0x0003], tid=3)
        assert isinstance(result, bytes)
        assert result[0] == SDP_SERVICE_SEARCH_ATTR_REQ


class TestSDPContinuation:
    """Test SDP continuation state builders."""

    def test_build_continuation_empty(self):
        from blue_tap.fuzz.protocols.sdp import build_continuation
        result = build_continuation()
        assert result == b"\x00"

    def test_build_continuation_with_data(self):
        from blue_tap.fuzz.protocols.sdp import build_continuation
        result = build_continuation(b"\x01\x02")
        assert result == b"\x02\x01\x02"

    def test_build_continuation_oversized(self):
        from blue_tap.fuzz.protocols.sdp import build_continuation_oversized
        result = build_continuation_oversized(17)
        assert result[0] == 17
        assert len(result) == 18
        assert result[1:] == b"\xFF" * 17

    def test_build_continuation_oversized_255(self):
        from blue_tap.fuzz.protocols.sdp import build_continuation_oversized
        result = build_continuation_oversized(255)
        assert result[0] == 255
        assert len(result) == 256


class TestSDPFuzzGenerators:
    """Test all SDP fuzz case generators return valid non-empty lists of bytes."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0

    def test_fuzz_invalid_dtd_bytes(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_invalid_dtd_bytes
        self._assert_fuzz_list(fuzz_invalid_dtd_bytes())

    def test_fuzz_nested_des(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_nested_des
        result = fuzz_nested_des(depth=5)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_fuzz_nested_des_default_depth(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_nested_des
        result = fuzz_nested_des()
        assert isinstance(result, bytes)
        assert len(result) > 10

    def test_fuzz_des_size_overflow(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_des_size_overflow
        result = fuzz_des_size_overflow()
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_fuzz_string_size_overflow(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_string_size_overflow
        result = fuzz_string_size_overflow()
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_fuzz_all_type_size_combos(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_all_type_size_combos
        self._assert_fuzz_list(fuzz_all_type_size_combos())

    def test_fuzz_parameter_length_mismatch(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_parameter_length_mismatch
        self._assert_fuzz_list(fuzz_parameter_length_mismatch())

    def test_fuzz_max_count_boundary(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_max_count_boundary
        self._assert_fuzz_list(fuzz_max_count_boundary())

    def test_fuzz_max_bytes_boundary(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_max_bytes_boundary
        self._assert_fuzz_list(fuzz_max_bytes_boundary())

    def test_fuzz_handle_boundary(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_handle_boundary
        self._assert_fuzz_list(fuzz_handle_boundary())

    def test_fuzz_empty_patterns(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_empty_patterns
        self._assert_fuzz_list(fuzz_empty_patterns())

    def test_fuzz_too_many_uuids(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_too_many_uuids
        self._assert_fuzz_list(fuzz_too_many_uuids())

    def test_fuzz_reserved_pdu_ids(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_reserved_pdu_ids
        self._assert_fuzz_list(fuzz_reserved_pdu_ids())

    def test_fuzz_response_as_request(self):
        from blue_tap.fuzz.protocols.sdp import fuzz_response_as_request
        self._assert_fuzz_list(fuzz_response_as_request())

    def test_generate_continuation_attacks(self):
        from blue_tap.fuzz.protocols.sdp import generate_continuation_attacks
        attacks = generate_continuation_attacks(b"\x00\x20")
        self._assert_fuzz_list(attacks)

    def test_generate_continuation_attacks_single_byte(self):
        from blue_tap.fuzz.protocols.sdp import generate_continuation_attacks
        attacks = generate_continuation_attacks(b"\x10")
        self._assert_fuzz_list(attacks)

    def test_generate_cross_service_attack(self):
        from blue_tap.fuzz.protocols.sdp import generate_cross_service_attack
        result = generate_cross_service_attack()
        assert isinstance(result, list)
        assert len(result) > 0
        for initial_req, followup_factory in result:
            assert isinstance(initial_req, bytes)
            assert callable(followup_factory)
            followup = followup_factory(b"\x00\x20")
            assert isinstance(followup, bytes)

    def test_generate_all_sdp_fuzz_cases(self):
        from blue_tap.fuzz.protocols.sdp import generate_all_sdp_fuzz_cases
        cases = generate_all_sdp_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 100
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0


# ======================================================================
# ATT Protocol Tests
# ======================================================================

class TestATTPDUBuilders:
    """Test all ATT PDU builder functions."""

    def test_build_exchange_mtu_req(self):
        from blue_tap.fuzz.protocols.att import build_exchange_mtu_req, ATT_EXCHANGE_MTU_REQ
        result = build_exchange_mtu_req(23)
        assert len(result) == 3
        assert result[0] == ATT_EXCHANGE_MTU_REQ
        assert struct.unpack("<H", result[1:])[0] == 23

    def test_build_exchange_mtu_req_max(self):
        from blue_tap.fuzz.protocols.att import build_exchange_mtu_req
        result = build_exchange_mtu_req(0xFFFF)
        assert struct.unpack("<H", result[1:])[0] == 0xFFFF

    def test_build_find_info_req(self):
        from blue_tap.fuzz.protocols.att import build_find_info_req, ATT_FIND_INFO_REQ
        result = build_find_info_req(0x0001, 0xFFFF)
        assert len(result) == 5
        assert result[0] == ATT_FIND_INFO_REQ
        start, end = struct.unpack("<HH", result[1:])
        assert start == 0x0001
        assert end == 0xFFFF

    def test_build_find_by_type_value_req(self):
        from blue_tap.fuzz.protocols.att import build_find_by_type_value_req, ATT_FIND_BY_TYPE_VALUE_REQ
        result = build_find_by_type_value_req(1, 0xFFFF, 0x2800, b"\x01\x02")
        assert result[0] == ATT_FIND_BY_TYPE_VALUE_REQ
        assert len(result) == 7 + 2  # opcode + start(2) + end(2) + type(2) + value(2)

    def test_build_find_by_type_value_req_empty_value(self):
        from blue_tap.fuzz.protocols.att import build_find_by_type_value_req
        result = build_find_by_type_value_req(1, 0xFFFF, 0x2800, b"")
        assert len(result) == 7

    def test_build_read_by_type_req_uuid16(self):
        from blue_tap.fuzz.protocols.att import build_read_by_type_req, ATT_READ_BY_TYPE_REQ
        result = build_read_by_type_req(1, 0xFFFF, 0x2803)
        assert result[0] == ATT_READ_BY_TYPE_REQ
        assert len(result) == 7  # opcode + start(2) + end(2) + uuid16(2)

    def test_build_read_by_type_req_uuid128(self):
        from blue_tap.fuzz.protocols.att import build_read_by_type_req
        uuid128 = b"\x01" * 16
        result = build_read_by_type_req(1, 0xFFFF, uuid128)
        assert len(result) == 5 + 16

    def test_build_read_req(self):
        from blue_tap.fuzz.protocols.att import build_read_req, ATT_READ_REQ
        result = build_read_req(0x0003)
        assert len(result) == 3
        assert result[0] == ATT_READ_REQ
        assert struct.unpack("<H", result[1:])[0] == 0x0003

    def test_build_read_blob_req(self):
        from blue_tap.fuzz.protocols.att import build_read_blob_req, ATT_READ_BLOB_REQ
        result = build_read_blob_req(0x0003, 100)
        assert len(result) == 5
        assert result[0] == ATT_READ_BLOB_REQ
        handle, offset = struct.unpack("<HH", result[1:])
        assert handle == 0x0003
        assert offset == 100

    def test_build_read_multiple_req(self):
        from blue_tap.fuzz.protocols.att import build_read_multiple_req, ATT_READ_MULTIPLE_REQ
        result = build_read_multiple_req([0x0001, 0x0002, 0x0003])
        assert result[0] == ATT_READ_MULTIPLE_REQ
        assert len(result) == 1 + 3 * 2

    def test_build_read_multiple_req_empty(self):
        from blue_tap.fuzz.protocols.att import build_read_multiple_req
        result = build_read_multiple_req([])
        assert len(result) == 1

    def test_build_read_multiple_variable_req(self):
        from blue_tap.fuzz.protocols.att import build_read_multiple_variable_req, ATT_READ_MULTIPLE_VAR_REQ
        result = build_read_multiple_variable_req([0x0001, 0x0002])
        assert result[0] == ATT_READ_MULTIPLE_VAR_REQ
        assert len(result) == 5

    def test_build_read_by_group_type_req_uuid16(self):
        from blue_tap.fuzz.protocols.att import build_read_by_group_type_req, ATT_READ_BY_GROUP_TYPE_REQ
        result = build_read_by_group_type_req(1, 0xFFFF, 0x2800)
        assert result[0] == ATT_READ_BY_GROUP_TYPE_REQ
        assert len(result) == 7

    def test_build_write_req(self):
        from blue_tap.fuzz.protocols.att import build_write_req, ATT_WRITE_REQ
        result = build_write_req(0x0003, b"\x01\x02")
        assert result[0] == ATT_WRITE_REQ
        assert struct.unpack("<H", result[1:3])[0] == 0x0003
        assert result[3:] == b"\x01\x02"

    def test_build_write_req_empty(self):
        from blue_tap.fuzz.protocols.att import build_write_req
        result = build_write_req(1, b"")
        assert len(result) == 3

    def test_build_write_cmd(self):
        from blue_tap.fuzz.protocols.att import build_write_cmd, ATT_WRITE_CMD
        result = build_write_cmd(0x0003, b"\xAA")
        assert result[0] == ATT_WRITE_CMD
        assert len(result) == 4

    def test_build_prepare_write_req(self):
        from blue_tap.fuzz.protocols.att import build_prepare_write_req, ATT_PREPARE_WRITE_REQ
        result = build_prepare_write_req(0x0003, 10, b"\x01\x02\x03")
        assert result[0] == ATT_PREPARE_WRITE_REQ
        handle, offset = struct.unpack("<HH", result[1:5])
        assert handle == 0x0003
        assert offset == 10
        assert result[5:] == b"\x01\x02\x03"

    def test_build_execute_write_req_commit(self):
        from blue_tap.fuzz.protocols.att import build_execute_write_req, ATT_EXECUTE_WRITE_REQ
        result = build_execute_write_req(0x01)
        assert result == bytes([ATT_EXECUTE_WRITE_REQ, 0x01])

    def test_build_execute_write_req_cancel(self):
        from blue_tap.fuzz.protocols.att import build_execute_write_req
        result = build_execute_write_req(0x00)
        assert result[1] == 0x00

    def test_build_handle_value_ntf(self):
        from blue_tap.fuzz.protocols.att import build_handle_value_ntf, ATT_HANDLE_VALUE_NTF
        result = build_handle_value_ntf(0x0005, b"\xDE\xAD")
        assert result[0] == ATT_HANDLE_VALUE_NTF
        assert struct.unpack("<H", result[1:3])[0] == 0x0005
        assert result[3:] == b"\xDE\xAD"

    def test_build_handle_value_ind(self):
        from blue_tap.fuzz.protocols.att import build_handle_value_ind, ATT_HANDLE_VALUE_IND
        result = build_handle_value_ind(0x0005, b"\xBE\xEF")
        assert result[0] == ATT_HANDLE_VALUE_IND

    def test_build_handle_value_cfm(self):
        from blue_tap.fuzz.protocols.att import build_handle_value_cfm, ATT_HANDLE_VALUE_CFM
        result = build_handle_value_cfm()
        assert result == bytes([ATT_HANDLE_VALUE_CFM])
        assert len(result) == 1

    def test_build_signed_write_cmd(self):
        from blue_tap.fuzz.protocols.att import build_signed_write_cmd, ATT_SIGNED_WRITE_CMD
        sig = b"\x00" * 12
        result = build_signed_write_cmd(0x0003, b"\x01", sig)
        assert result[0] == ATT_SIGNED_WRITE_CMD
        assert len(result) == 3 + 1 + 12

    def test_build_signed_write_cmd_wrong_sig_length(self):
        from blue_tap.fuzz.protocols.att import build_signed_write_cmd
        with pytest.raises(ValueError, match="12 bytes"):
            build_signed_write_cmd(0x0001, b"\x01", b"\x00" * 11)


class TestATTFuzzGenerators:
    """Test all ATT fuzz case generators."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)

    def test_fuzz_handles(self):
        from blue_tap.fuzz.protocols.att import fuzz_handles
        self._assert_fuzz_list(fuzz_handles())

    def test_fuzz_range_reversed(self):
        from blue_tap.fuzz.protocols.att import fuzz_range_reversed
        self._assert_fuzz_list(fuzz_range_reversed())

    def test_fuzz_mtu_values(self):
        from blue_tap.fuzz.protocols.att import fuzz_mtu_values
        self._assert_fuzz_list(fuzz_mtu_values())

    def test_fuzz_write_sizes(self):
        from blue_tap.fuzz.protocols.att import fuzz_write_sizes
        self._assert_fuzz_list(fuzz_write_sizes())

    def test_fuzz_prepare_write_overflow(self):
        from blue_tap.fuzz.protocols.att import fuzz_prepare_write_overflow
        self._assert_fuzz_list(fuzz_prepare_write_overflow())

    def test_fuzz_unknown_opcodes(self):
        from blue_tap.fuzz.protocols.att import fuzz_unknown_opcodes, DEFINED_OPCODES
        cases = fuzz_unknown_opcodes()
        self._assert_fuzz_list(cases)
        # Each case opcode should NOT be in defined opcodes
        for case in cases:
            assert case[0] not in DEFINED_OPCODES

    def test_fuzz_invalid_uuid_sizes(self):
        from blue_tap.fuzz.protocols.att import fuzz_invalid_uuid_sizes
        self._assert_fuzz_list(fuzz_invalid_uuid_sizes())

    def test_fuzz_rapid_sequential_requests(self):
        from blue_tap.fuzz.protocols.att import fuzz_rapid_sequential_requests
        cases = fuzz_rapid_sequential_requests(count=10)
        assert len(cases) == 10
        self._assert_fuzz_list(cases)

    def test_fuzz_rapid_sequential_requests_default(self):
        from blue_tap.fuzz.protocols.att import fuzz_rapid_sequential_requests
        cases = fuzz_rapid_sequential_requests()
        assert len(cases) == 50

    def test_fuzz_cccd_writes(self):
        from blue_tap.fuzz.protocols.att import fuzz_cccd_writes
        self._assert_fuzz_list(fuzz_cccd_writes())

    def test_fuzz_service_discovery(self):
        from blue_tap.fuzz.protocols.att import fuzz_service_discovery
        self._assert_fuzz_list(fuzz_service_discovery())

    def test_fuzz_execute_without_prepare(self):
        from blue_tap.fuzz.protocols.att import fuzz_execute_without_prepare
        self._assert_fuzz_list(fuzz_execute_without_prepare())

    def test_fuzz_notification_from_client(self):
        from blue_tap.fuzz.protocols.att import fuzz_notification_from_client
        self._assert_fuzz_list(fuzz_notification_from_client())

    def test_fuzz_read_multiple_variable(self):
        from blue_tap.fuzz.protocols.att import fuzz_read_multiple_variable
        self._assert_fuzz_list(fuzz_read_multiple_variable())

    def test_fuzz_truncated_pdus(self):
        from blue_tap.fuzz.protocols.att import fuzz_truncated_pdus
        cases = fuzz_truncated_pdus()
        assert isinstance(cases, list)
        assert len(cases) > 0
        # Some truncated PDUs may be empty bytes (b"")
        for case in cases:
            assert isinstance(case, bytes)

    def test_generate_all_att_fuzz_cases(self):
        from blue_tap.fuzz.protocols.att import generate_all_att_fuzz_cases
        cases = generate_all_att_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 100
        for case in cases:
            assert isinstance(case, bytes)


# ======================================================================
# L2CAP Protocol Tests
# ======================================================================

class TestL2CAPBuilders:
    """Test all L2CAP builder functions."""

    def test_build_signaling_cmd(self):
        from blue_tap.fuzz.protocols.l2cap import build_signaling_cmd
        result = build_signaling_cmd(0x02, 1, b"\x01\x00\x40\x00")
        assert len(result) == 4 + 4
        assert result[0] == 0x02
        assert result[1] == 1
        assert struct.unpack("<H", result[2:4])[0] == 4

    def test_build_l2cap_frame(self):
        from blue_tap.fuzz.protocols.l2cap import build_l2cap_frame
        payload = b"\xAA\xBB"
        result = build_l2cap_frame(0x0001, payload)
        length, cid = struct.unpack("<HH", result[:4])
        assert length == 2
        assert cid == 0x0001
        assert result[4:] == payload

    def test_build_signaling_frame(self):
        from blue_tap.fuzz.protocols.l2cap import build_signaling_frame, CID_SIGNALING
        result = build_signaling_frame(0x08, 1, b"PING")
        # Should be L2CAP header (4 bytes) + signaling command
        _, cid = struct.unpack("<HH", result[:4])
        assert cid == CID_SIGNALING

    def test_build_conn_req(self):
        from blue_tap.fuzz.protocols.l2cap import build_conn_req, L2CAP_CONN_REQ
        result = build_conn_req(0x0001, 0x0040)
        assert result[0] == L2CAP_CONN_REQ
        assert result[1] == 1  # default identifier

    def test_build_conn_rsp(self):
        from blue_tap.fuzz.protocols.l2cap import build_conn_rsp, L2CAP_CONN_RSP
        result = build_conn_rsp(0x0040, 0x0041, result=0, status=0)
        assert result[0] == L2CAP_CONN_RSP

    def test_build_conf_req(self):
        from blue_tap.fuzz.protocols.l2cap import build_conf_req, L2CAP_CONF_REQ
        result = build_conf_req(0x0040, options=b"\x01\x02\x00\x48")
        assert result[0] == L2CAP_CONF_REQ

    def test_build_conf_req_empty_options(self):
        from blue_tap.fuzz.protocols.l2cap import build_conf_req
        result = build_conf_req(0x0040)
        # Header (4) only, data = dcid(2) + flags(2)
        assert len(result) == 4 + 4

    def test_build_disconn_req(self):
        from blue_tap.fuzz.protocols.l2cap import build_disconn_req, L2CAP_DISCONN_REQ
        result = build_disconn_req(0x0040, 0x0041)
        assert result[0] == L2CAP_DISCONN_REQ

    def test_build_echo_req(self):
        from blue_tap.fuzz.protocols.l2cap import build_echo_req, L2CAP_ECHO_REQ
        result = build_echo_req(b"PING")
        assert result[0] == L2CAP_ECHO_REQ
        assert b"PING" in result

    def test_build_echo_req_empty(self):
        from blue_tap.fuzz.protocols.l2cap import build_echo_req
        result = build_echo_req()
        assert len(result) == 4  # header only

    def test_build_info_req(self):
        from blue_tap.fuzz.protocols.l2cap import build_info_req, L2CAP_INFO_REQ
        result = build_info_req(2)
        assert result[0] == L2CAP_INFO_REQ
        assert len(result) == 4 + 2

    def test_encode_opt_mtu(self):
        from blue_tap.fuzz.protocols.l2cap import encode_opt_mtu, L2CAP_OPT_MTU
        result = encode_opt_mtu(672)
        assert result[0] == L2CAP_OPT_MTU
        assert result[1] == 2
        assert struct.unpack("<H", result[2:])[0] == 672

    def test_encode_opt_flush_timeout(self):
        from blue_tap.fuzz.protocols.l2cap import encode_opt_flush_timeout, L2CAP_OPT_FLUSH_TIMEOUT
        result = encode_opt_flush_timeout(100)
        assert result[0] == L2CAP_OPT_FLUSH_TIMEOUT
        assert result[1] == 2

    def test_encode_opt_fcs(self):
        from blue_tap.fuzz.protocols.l2cap import encode_opt_fcs, L2CAP_OPT_FCS
        result = encode_opt_fcs(1)
        assert result[0] == L2CAP_OPT_FCS
        assert result[1] == 1
        assert result[2] == 1

    def test_encode_opt_unknown(self):
        from blue_tap.fuzz.protocols.l2cap import encode_opt_unknown
        result = encode_opt_unknown(0x80, b"\x01\x02\x03")
        assert result[0] == 0x80
        assert result[1] == 3
        assert result[2:] == b"\x01\x02\x03"

    def test_encode_opt_unknown_oversized(self):
        from blue_tap.fuzz.protocols.l2cap import encode_opt_unknown
        data = b"\xFF" * 300
        result = encode_opt_unknown(0x80, data)
        assert result[1] == 255  # clamped to 255
        assert result[2:] == data  # but full data follows


class TestL2CAPFuzzGenerators:
    """Test all L2CAP fuzz generators."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0

    def test_fuzz_config_options(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_config_options
        self._assert_fuzz_list(fuzz_config_options())

    def test_fuzz_cid_manipulation(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_cid_manipulation
        self._assert_fuzz_list(fuzz_cid_manipulation())

    def test_fuzz_echo_requests(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_echo_requests
        self._assert_fuzz_list(fuzz_echo_requests())

    def test_fuzz_info_requests(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_info_requests
        self._assert_fuzz_list(fuzz_info_requests())

    def test_fuzz_command_reject(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_command_reject
        self._assert_fuzz_list(fuzz_command_reject())

    def test_fuzz_signaling_length_mismatch(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_signaling_length_mismatch
        self._assert_fuzz_list(fuzz_signaling_length_mismatch())

    def test_fuzz_reserved_codes(self):
        from blue_tap.fuzz.protocols.l2cap import fuzz_reserved_codes
        self._assert_fuzz_list(fuzz_reserved_codes())

    def test_generate_all_l2cap_fuzz_cases(self):
        from blue_tap.fuzz.protocols.l2cap import generate_all_l2cap_fuzz_cases
        cases = generate_all_l2cap_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 50
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0


# ======================================================================
# RFCOMM Protocol Tests
# ======================================================================

class TestRFCOMMFCS:
    """Test RFCOMM FCS calculation."""

    def test_calculate_fcs_known_values(self):
        from blue_tap.fuzz.protocols.rfcomm import calculate_fcs
        # FCS of empty data
        result = calculate_fcs(b"")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFF

    def test_calculate_fcs_deterministic(self):
        from blue_tap.fuzz.protocols.rfcomm import calculate_fcs
        data = b"\x03\x3F"
        fcs1 = calculate_fcs(data)
        fcs2 = calculate_fcs(data)
        assert fcs1 == fcs2

    def test_calculate_fcs_different_data(self):
        from blue_tap.fuzz.protocols.rfcomm import calculate_fcs
        fcs1 = calculate_fcs(b"\x03\x3F")
        fcs2 = calculate_fcs(b"\x0B\x3F")
        assert fcs1 != fcs2  # Different address bytes yield different FCS


class TestRFCOMMFrameBuilders:
    """Test RFCOMM frame component and complete frame builders."""

    def test_build_address(self):
        from blue_tap.fuzz.protocols.rfcomm import build_address
        addr = build_address(dlci=2, cr=1, ea=1)
        assert isinstance(addr, int)
        assert (addr >> 2) & 0x3F == 2
        assert (addr >> 1) & 0x01 == 1
        assert addr & 0x01 == 1

    def test_build_address_dlci_0(self):
        from blue_tap.fuzz.protocols.rfcomm import build_address
        addr = build_address(dlci=0)
        assert (addr >> 2) & 0x3F == 0

    def test_build_address_max_dlci(self):
        from blue_tap.fuzz.protocols.rfcomm import build_address
        addr = build_address(dlci=63)
        assert (addr >> 2) & 0x3F == 63

    def test_build_length_short(self):
        from blue_tap.fuzz.protocols.rfcomm import build_length
        result = build_length(10)
        assert len(result) == 1
        assert result[0] & 0x01 == 1  # EA bit set for 1-byte length
        assert (result[0] >> 1) == 10

    def test_build_length_long(self):
        from blue_tap.fuzz.protocols.rfcomm import build_length
        result = build_length(200)
        assert len(result) == 2
        assert result[0] & 0x01 == 0  # EA bit not set for 2-byte length

    def test_build_length_max_single_byte(self):
        from blue_tap.fuzz.protocols.rfcomm import build_length
        result = build_length(127)
        assert len(result) == 1

    def test_build_length_min_two_byte(self):
        from blue_tap.fuzz.protocols.rfcomm import build_length
        result = build_length(128)
        assert len(result) == 2

    def test_build_rfcomm_frame(self):
        from blue_tap.fuzz.protocols.rfcomm import build_rfcomm_frame, RFCOMM_UIH
        result = build_rfcomm_frame(2, RFCOMM_UIH, b"hello")
        assert isinstance(result, bytes)
        assert len(result) > 3  # addr + ctrl + length + data + fcs
        assert result[-1] != 0  # FCS should be non-zero in general

    def test_build_rfcomm_frame_custom_fcs(self):
        from blue_tap.fuzz.protocols.rfcomm import build_rfcomm_frame, RFCOMM_SABM
        result = build_rfcomm_frame(2, RFCOMM_SABM, fcs=0xAA)
        assert result[-1] == 0xAA

    def test_build_sabm(self):
        from blue_tap.fuzz.protocols.rfcomm import build_sabm, RFCOMM_SABM
        result = build_sabm(2)
        assert isinstance(result, bytes)
        assert result[1] == RFCOMM_SABM

    def test_build_ua(self):
        from blue_tap.fuzz.protocols.rfcomm import build_ua, RFCOMM_UA
        result = build_ua(2)
        assert result[1] == RFCOMM_UA

    def test_build_disc(self):
        from blue_tap.fuzz.protocols.rfcomm import build_disc, RFCOMM_DISC
        result = build_disc(2)
        assert result[1] == RFCOMM_DISC

    def test_build_dm(self):
        from blue_tap.fuzz.protocols.rfcomm import build_dm, RFCOMM_DM
        result = build_dm(2)
        assert result[1] == RFCOMM_DM

    def test_build_uih(self):
        from blue_tap.fuzz.protocols.rfcomm import build_uih, RFCOMM_UIH
        result = build_uih(2, b"data")
        assert result[1] == RFCOMM_UIH
        assert len(result) > 4

    def test_build_uih_empty(self):
        from blue_tap.fuzz.protocols.rfcomm import build_uih
        result = build_uih(2)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_build_uih_with_credits(self):
        from blue_tap.fuzz.protocols.rfcomm import build_uih_with_credits, RFCOMM_UIH
        result = build_uih_with_credits(2, b"test", credits=10)
        assert isinstance(result, bytes)
        assert result[1] == RFCOMM_UIH
        assert len(result) > 5


class TestRFCOMMMuxBuilders:
    """Test RFCOMM multiplexer command builders."""

    def test_build_mux_command(self):
        from blue_tap.fuzz.protocols.rfcomm import build_mux_command, MUX_PN
        result = build_mux_command(MUX_PN, 8, b"\x00" * 8)
        assert result[0] == MUX_PN
        assert len(result) > 2

    def test_build_pn(self):
        from blue_tap.fuzz.protocols.rfcomm import build_pn
        result = build_pn(2, frame_size=127, credits=7)
        assert isinstance(result, bytes)
        assert len(result) > 5

    def test_build_msc(self):
        from blue_tap.fuzz.protocols.rfcomm import build_msc
        result = build_msc(2, fc=True, rtc=True, rtr=True, ic=False, dv=True)
        assert isinstance(result, bytes)
        assert len(result) > 5

    def test_build_rpn(self):
        from blue_tap.fuzz.protocols.rfcomm import build_rpn
        result = build_rpn(2, baud_rate=7, data_bits=3)
        assert isinstance(result, bytes)
        assert len(result) > 5

    def test_build_rls(self):
        from blue_tap.fuzz.protocols.rfcomm import build_rls
        result = build_rls(2, line_status=0x02)
        assert isinstance(result, bytes)
        assert len(result) > 5

    def test_build_test(self):
        from blue_tap.fuzz.protocols.rfcomm import build_test
        result = build_test(b"ECHO")
        assert isinstance(result, bytes)
        assert len(result) > 3

    def test_build_test_empty(self):
        from blue_tap.fuzz.protocols.rfcomm import build_test
        result = build_test()
        assert isinstance(result, bytes)


class TestRFCOMMFuzzGenerators:
    """Test all RFCOMM fuzz generators."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0

    def test_fuzz_fcs(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_fcs
        self._assert_fuzz_list(fuzz_fcs())

    def test_fuzz_length_mismatch(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_length_mismatch
        self._assert_fuzz_list(fuzz_length_mismatch())

    def test_fuzz_invalid_control_bytes(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_invalid_control_bytes
        self._assert_fuzz_list(fuzz_invalid_control_bytes())

    def test_fuzz_dlci_range(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_dlci_range
        self._assert_fuzz_list(fuzz_dlci_range())

    def test_fuzz_pn_params(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_pn_params
        self._assert_fuzz_list(fuzz_pn_params())

    def test_fuzz_msc_signals(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_msc_signals
        cases = fuzz_msc_signals()
        self._assert_fuzz_list(cases)
        assert len(cases) >= 32  # 32 signal combinations + extras

    def test_fuzz_rapid_sabm(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_rapid_sabm
        self._assert_fuzz_list(fuzz_rapid_sabm())

    def test_fuzz_data_without_sabm(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_data_without_sabm
        self._assert_fuzz_list(fuzz_data_without_sabm())

    def test_fuzz_double_disc(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_double_disc
        self._assert_fuzz_list(fuzz_double_disc())

    def test_fuzz_credit_flow(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_credit_flow
        self._assert_fuzz_list(fuzz_credit_flow())

    def test_fuzz_mux_length_mismatch(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_mux_length_mismatch
        self._assert_fuzz_list(fuzz_mux_length_mismatch())

    def test_fuzz_rpn_params(self):
        from blue_tap.fuzz.protocols.rfcomm import fuzz_rpn_params
        self._assert_fuzz_list(fuzz_rpn_params())

    def test_generate_all_rfcomm_fuzz_cases(self):
        from blue_tap.fuzz.protocols.rfcomm import generate_all_rfcomm_fuzz_cases
        cases = generate_all_rfcomm_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 100
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0


# ======================================================================
# OBEX Protocol Tests
# ======================================================================

class TestOBEXHeaderBuilders:
    """Test OBEX header builder functions."""

    def test_build_unicode_header(self):
        from blue_tap.fuzz.protocols.obex import build_unicode_header, HI_NAME
        result = build_unicode_header(HI_NAME, "test")
        assert result[0] == HI_NAME
        length = struct.unpack(">H", result[1:3])[0]
        assert length == len(result)
        # Should contain UTF-16BE "test" + null terminator
        assert b"\x00\x00" in result[3:]

    def test_build_unicode_header_empty(self):
        from blue_tap.fuzz.protocols.obex import build_unicode_header, HI_NAME
        result = build_unicode_header(HI_NAME, "")
        assert result[0] == HI_NAME
        # Empty string still has null terminator (2 bytes)
        assert len(result) == 1 + 2 + 2

    def test_build_byteseq_header(self):
        from blue_tap.fuzz.protocols.obex import build_byteseq_header, HI_TARGET
        data = b"\x01\x02\x03"
        result = build_byteseq_header(HI_TARGET, data)
        assert result[0] == HI_TARGET
        length = struct.unpack(">H", result[1:3])[0]
        assert length == 1 + 2 + 3
        assert result[3:] == data

    def test_build_byte1_header(self):
        from blue_tap.fuzz.protocols.obex import build_byte1_header
        result = build_byte1_header(0x93, 0x42)
        assert len(result) == 2
        assert result[0] == 0x93
        assert result[1] == 0x42

    def test_build_byte4_header(self):
        from blue_tap.fuzz.protocols.obex import build_byte4_header, HI_CONNECTION_ID
        result = build_byte4_header(HI_CONNECTION_ID, 0x00000001)
        assert len(result) == 5
        assert result[0] == HI_CONNECTION_ID
        assert struct.unpack(">I", result[1:])[0] == 1


class TestOBEXPacketBuilders:
    """Test OBEX packet builder functions."""

    def test_build_obex_packet(self):
        from blue_tap.fuzz.protocols.obex import build_obex_packet
        result = build_obex_packet(0x80, b"\x01\x02")
        assert result[0] == 0x80
        length = struct.unpack(">H", result[1:3])[0]
        assert length == 5  # opcode(1) + length(2) + body(2)

    def test_build_obex_packet_empty(self):
        from blue_tap.fuzz.protocols.obex import build_obex_packet
        result = build_obex_packet(0xFF)
        assert len(result) == 3
        assert struct.unpack(">H", result[1:3])[0] == 3

    def test_build_connect_default(self):
        from blue_tap.fuzz.protocols.obex import build_connect, OBEX_CONNECT
        result = build_connect()
        assert result[0] == OBEX_CONNECT
        assert len(result) >= 7  # minimum connect packet

    def test_build_connect_with_target(self):
        from blue_tap.fuzz.protocols.obex import build_connect, PBAP_TARGET_UUID
        result = build_connect(target_uuid=PBAP_TARGET_UUID)
        assert len(result) > 7

    def test_build_connect_custom_params(self):
        from blue_tap.fuzz.protocols.obex import build_connect
        result = build_connect(version=0xFF, flags=0xFF, max_pkt_len=0)
        assert isinstance(result, bytes)

    def test_build_disconnect(self):
        from blue_tap.fuzz.protocols.obex import build_disconnect, OBEX_DISCONNECT
        result = build_disconnect()
        assert result[0] == OBEX_DISCONNECT

    def test_build_disconnect_with_connection_id(self):
        from blue_tap.fuzz.protocols.obex import build_disconnect
        result = build_disconnect(connection_id=1)
        assert len(result) > 3

    def test_build_setpath_default(self):
        from blue_tap.fuzz.protocols.obex import build_setpath, OBEX_SETPATH
        result = build_setpath(name="test")
        assert result[0] == OBEX_SETPATH

    def test_build_setpath_backup(self):
        from blue_tap.fuzz.protocols.obex import build_setpath
        result = build_setpath(backup=True)
        # Flags byte at position 3 should have bit 0 set
        assert result[3] & 0x01 == 0x01

    def test_build_setpath_no_name(self):
        from blue_tap.fuzz.protocols.obex import build_setpath
        result = build_setpath(name=None, backup=True)
        assert isinstance(result, bytes)

    def test_build_get(self):
        from blue_tap.fuzz.protocols.obex import build_get, OBEX_GET_FINAL
        result = build_get(1, "test.vcf", b"text/x-vcard")
        assert result[0] == OBEX_GET_FINAL

    def test_build_get_non_final(self):
        from blue_tap.fuzz.protocols.obex import build_get, OBEX_GET
        result = build_get(1, "test", b"text/plain", final=False)
        assert result[0] == OBEX_GET

    def test_build_put(self):
        from blue_tap.fuzz.protocols.obex import build_put, OBEX_PUT_FINAL
        result = build_put("test.vcf", b"text/x-vcard", b"data", final=True)
        assert result[0] == OBEX_PUT_FINAL

    def test_build_put_non_final(self):
        from blue_tap.fuzz.protocols.obex import build_put, OBEX_PUT
        result = build_put("test.vcf", b"text/x-vcard", b"data", final=False)
        assert result[0] == OBEX_PUT

    def test_build_put_empty_body(self):
        from blue_tap.fuzz.protocols.obex import build_put
        result = build_put("test.vcf", b"text/plain", b"")
        assert isinstance(result, bytes)

    def test_build_abort(self):
        from blue_tap.fuzz.protocols.obex import build_abort, OBEX_ABORT
        result = build_abort()
        assert result[0] == OBEX_ABORT

    def test_build_abort_with_connection_id(self):
        from blue_tap.fuzz.protocols.obex import build_abort
        result = build_abort(connection_id=1)
        assert len(result) > 3


class TestOBEXAppParams:
    """Test OBEX application parameter builders."""

    def test_build_app_params(self):
        from blue_tap.fuzz.protocols.obex import build_app_params
        result = build_app_params([(0x04, struct.pack(">H", 100))])
        assert result == bytes([0x04, 0x02, 0x00, 0x64])

    def test_build_app_params_multiple(self):
        from blue_tap.fuzz.protocols.obex import build_app_params
        result = build_app_params([
            (0x01, bytes([0x00])),
            (0x04, struct.pack(">H", 50)),
        ])
        assert len(result) == 3 + 4  # tag+len+val for each

    def test_build_pbap_app_params(self):
        from blue_tap.fuzz.protocols.obex import build_pbap_app_params
        result = build_pbap_app_params(max_count=100, offset=0, fmt=0)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_build_pbap_app_params_empty(self):
        from blue_tap.fuzz.protocols.obex import build_pbap_app_params
        result = build_pbap_app_params()
        assert result == b""

    def test_build_map_app_params(self):
        from blue_tap.fuzz.protocols.obex import build_map_app_params
        result = build_map_app_params(max_count=10, charset=1)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestOBEXProfileBuilders:
    """Test OBEX profile-specific builders."""

    def test_build_pbap_connect(self):
        from blue_tap.fuzz.protocols.obex import build_pbap_connect, OBEX_CONNECT
        result = build_pbap_connect()
        assert result[0] == OBEX_CONNECT

    def test_build_pbap_pull_phonebook(self):
        from blue_tap.fuzz.protocols.obex import build_pbap_pull_phonebook
        result = build_pbap_pull_phonebook()
        assert isinstance(result, bytes)
        assert len(result) > 10

    def test_build_pbap_pull_vcard_listing(self):
        from blue_tap.fuzz.protocols.obex import build_pbap_pull_vcard_listing
        result = build_pbap_pull_vcard_listing()
        assert isinstance(result, bytes)

    def test_build_map_connect(self):
        from blue_tap.fuzz.protocols.obex import build_map_connect, OBEX_CONNECT
        result = build_map_connect()
        assert result[0] == OBEX_CONNECT

    def test_build_map_get_folder_listing(self):
        from blue_tap.fuzz.protocols.obex import build_map_get_folder_listing
        result = build_map_get_folder_listing()
        assert isinstance(result, bytes)

    def test_build_map_get_msg_listing(self):
        from blue_tap.fuzz.protocols.obex import build_map_get_msg_listing
        result = build_map_get_msg_listing()
        assert isinstance(result, bytes)

    def test_build_map_get_message(self):
        from blue_tap.fuzz.protocols.obex import build_map_get_message
        result = build_map_get_message()
        assert isinstance(result, bytes)

    def test_build_opp_connect(self):
        from blue_tap.fuzz.protocols.obex import build_opp_connect, OBEX_CONNECT
        result = build_opp_connect()
        assert result[0] == OBEX_CONNECT

    def test_build_opp_push(self):
        from blue_tap.fuzz.protocols.obex import build_opp_push
        result = build_opp_push("test.vcf", b"text/x-vcard", b"BEGIN:VCARD\r\nEND:VCARD")
        assert isinstance(result, bytes)
        assert len(result) > 10


class TestOBEXFuzzHelpers:
    """Test OBEX fuzzing helper functions."""

    def test_fuzz_packet_length(self):
        from blue_tap.fuzz.protocols.obex import fuzz_packet_length, build_connect
        packet = build_connect()
        cases = fuzz_packet_length(packet)
        assert isinstance(cases, list)
        assert len(cases) == 6
        for case in cases:
            assert isinstance(case, bytes)
            assert case[0] == packet[0]  # opcode preserved

    def test_fuzz_packet_length_short(self):
        from blue_tap.fuzz.protocols.obex import fuzz_packet_length
        result = fuzz_packet_length(b"\x80\x00")
        assert result == [b"\x80\x00"]  # too short, returned as-is

    def test_fuzz_header_length(self):
        from blue_tap.fuzz.protocols.obex import fuzz_header_length, build_unicode_header, HI_NAME
        header = build_unicode_header(HI_NAME, "test")
        cases = fuzz_header_length(header)
        assert isinstance(cases, list)
        assert len(cases) == 4

    def test_build_path_traversal_name(self):
        from blue_tap.fuzz.protocols.obex import build_path_traversal_name
        result = build_path_traversal_name(depth=3)
        assert isinstance(result, bytes)
        assert len(result) > 3

    def test_fuzz_unicode_odd_bytes(self):
        from blue_tap.fuzz.protocols.obex import fuzz_unicode_odd_bytes
        result = fuzz_unicode_odd_bytes()
        assert isinstance(result, bytes)
        # Length field claims 6 but content is 3 value bytes

    def test_fuzz_unicode_no_null(self):
        from blue_tap.fuzz.protocols.obex import fuzz_unicode_no_null
        result = fuzz_unicode_no_null()
        assert isinstance(result, bytes)
        # Should NOT end with \x00\x00
        assert not result.endswith(b"\x00\x00")

    def test_fuzz_app_param_tlv_overflow(self):
        from blue_tap.fuzz.protocols.obex import fuzz_app_param_tlv_overflow
        result = fuzz_app_param_tlv_overflow()
        assert isinstance(result, bytes)

    def test_fuzz_duplicate_headers(self):
        from blue_tap.fuzz.protocols.obex import fuzz_duplicate_headers
        result = fuzz_duplicate_headers()
        assert isinstance(result, bytes)

    def test_fuzz_connect_attacks(self):
        from blue_tap.fuzz.protocols.obex import fuzz_connect_attacks
        cases = fuzz_connect_attacks()
        assert isinstance(cases, list)
        assert len(cases) == 5
        for case in cases:
            assert isinstance(case, bytes)

    def test_fuzz_setpath_attacks(self):
        from blue_tap.fuzz.protocols.obex import fuzz_setpath_attacks
        cases = fuzz_setpath_attacks()
        assert isinstance(cases, list)
        assert len(cases) > 3
        for case in cases:
            assert isinstance(case, bytes)

    def test_fuzz_session_attacks(self):
        from blue_tap.fuzz.protocols.obex import fuzz_session_attacks
        cases = fuzz_session_attacks()
        assert isinstance(cases, list)
        assert len(cases) > 0
        for seq in cases:
            assert isinstance(seq, list)
            for pkt in seq:
                assert isinstance(pkt, bytes)

    def test_generate_all_obex_fuzz_cases_pbap(self):
        from blue_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
        cases = generate_all_obex_fuzz_cases(profile="pbap")
        assert isinstance(cases, list)
        assert len(cases) > 50

    def test_generate_all_obex_fuzz_cases_map(self):
        from blue_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
        cases = generate_all_obex_fuzz_cases(profile="map")
        assert isinstance(cases, list)
        assert len(cases) > 50

    def test_generate_all_obex_fuzz_cases_opp(self):
        from blue_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
        cases = generate_all_obex_fuzz_cases(profile="opp")
        assert isinstance(cases, list)
        assert len(cases) > 50


# ======================================================================
# SMP Protocol Tests
# ======================================================================

class TestSMPCommandBuilders:
    """Test all SMP command builder functions."""

    def test_build_pairing_request_defaults(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_request, SMP_PAIRING_REQUEST
        result = build_pairing_request()
        assert len(result) == 7
        assert result[0] == SMP_PAIRING_REQUEST

    def test_build_pairing_request_custom(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_request, IO_KEYBOARD_DISPLAY
        result = build_pairing_request(
            io_cap=IO_KEYBOARD_DISPLAY,
            oob=0x01,
            auth_req=0x0D,
            max_key_size=16,
            init_key_dist=0x07,
            resp_key_dist=0x07,
        )
        assert len(result) == 7
        assert result[1] == IO_KEYBOARD_DISPLAY

    def test_build_pairing_response(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_response, SMP_PAIRING_RESPONSE
        result = build_pairing_response()
        assert len(result) == 7
        assert result[0] == SMP_PAIRING_RESPONSE

    def test_build_pairing_confirm(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_confirm, SMP_PAIRING_CONFIRM
        result = build_pairing_confirm(b"\x01" * 16)
        assert len(result) == 17
        assert result[0] == SMP_PAIRING_CONFIRM

    def test_build_pairing_confirm_padding(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_confirm
        result = build_pairing_confirm(b"\x01" * 5)
        assert len(result) == 17
        # Should be padded to 16 bytes
        assert result[6:] == b"\x00" * 11

    def test_build_pairing_random(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_random, SMP_PAIRING_RANDOM
        result = build_pairing_random(b"\x02" * 16)
        assert len(result) == 17
        assert result[0] == SMP_PAIRING_RANDOM

    def test_build_pairing_failed(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_failed, SMP_PAIRING_FAILED
        result = build_pairing_failed(0x08)
        assert result == bytes([SMP_PAIRING_FAILED, 0x08])

    def test_build_encryption_info(self):
        from blue_tap.fuzz.protocols.smp import build_encryption_info, SMP_ENCRYPTION_INFO
        result = build_encryption_info(b"\xAA" * 16)
        assert len(result) == 17
        assert result[0] == SMP_ENCRYPTION_INFO

    def test_build_central_identification(self):
        from blue_tap.fuzz.protocols.smp import build_central_identification, SMP_CENTRAL_ID
        result = build_central_identification(0x1234, b"\xBB" * 8)
        assert len(result) == 11
        assert result[0] == SMP_CENTRAL_ID
        ediv = struct.unpack("<H", result[1:3])[0]
        assert ediv == 0x1234

    def test_build_identity_info(self):
        from blue_tap.fuzz.protocols.smp import build_identity_info, SMP_IDENTITY_INFO
        result = build_identity_info(b"\xCC" * 16)
        assert len(result) == 17
        assert result[0] == SMP_IDENTITY_INFO

    def test_build_identity_addr_info(self):
        from blue_tap.fuzz.protocols.smp import build_identity_addr_info, SMP_IDENTITY_ADDR_INFO
        result = build_identity_addr_info(0x00, b"\x11\x22\x33\x44\x55\x66")
        assert len(result) == 8
        assert result[0] == SMP_IDENTITY_ADDR_INFO
        assert result[1] == 0x00

    def test_build_signing_info(self):
        from blue_tap.fuzz.protocols.smp import build_signing_info, SMP_SIGNING_INFO
        result = build_signing_info(b"\xDD" * 16)
        assert len(result) == 17
        assert result[0] == SMP_SIGNING_INFO

    def test_build_security_request(self):
        from blue_tap.fuzz.protocols.smp import build_security_request, SMP_SECURITY_REQUEST
        result = build_security_request(0x0D)
        assert result == bytes([SMP_SECURITY_REQUEST, 0x0D])

    def test_build_pairing_public_key(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_public_key, SMP_PAIRING_PUBLIC_KEY
        result = build_pairing_public_key(b"\x01" * 32, b"\x02" * 32)
        assert len(result) == 65
        assert result[0] == SMP_PAIRING_PUBLIC_KEY

    def test_build_pairing_dhkey_check(self):
        from blue_tap.fuzz.protocols.smp import build_pairing_dhkey_check, SMP_PAIRING_DHKEY_CHECK
        result = build_pairing_dhkey_check(b"\xEE" * 16)
        assert len(result) == 17
        assert result[0] == SMP_PAIRING_DHKEY_CHECK

    def test_build_keypress_notification(self):
        from blue_tap.fuzz.protocols.smp import build_keypress_notification, SMP_KEYPRESS_NTF
        result = build_keypress_notification(0x02)
        assert result == bytes([SMP_KEYPRESS_NTF, 0x02])


class TestSMPFuzzGenerators:
    """Test all SMP fuzz generators."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0

    def test_fuzz_io_capabilities(self):
        from blue_tap.fuzz.protocols.smp import fuzz_io_capabilities
        cases = fuzz_io_capabilities()
        assert len(cases) == 256

    def test_fuzz_max_key_size(self):
        from blue_tap.fuzz.protocols.smp import fuzz_max_key_size
        cases = fuzz_max_key_size()
        assert len(cases) == 8
        self._assert_fuzz_list(cases)

    def test_fuzz_auth_req(self):
        from blue_tap.fuzz.protocols.smp import fuzz_auth_req
        self._assert_fuzz_list(fuzz_auth_req())

    def test_fuzz_oob_flag(self):
        from blue_tap.fuzz.protocols.smp import fuzz_oob_flag
        self._assert_fuzz_list(fuzz_oob_flag())

    def test_fuzz_key_dist(self):
        from blue_tap.fuzz.protocols.smp import fuzz_key_dist
        cases = fuzz_key_dist()
        self._assert_fuzz_list(cases)
        # 10 values * 2 (init + resp) = 20
        assert len(cases) == 20

    def test_fuzz_public_key_invalid_curve(self):
        from blue_tap.fuzz.protocols.smp import fuzz_public_key_invalid_curve
        cases = fuzz_public_key_invalid_curve()
        self._assert_fuzz_list(cases)
        for case in cases:
            assert len(case) == 65

    def test_fuzz_out_of_sequence(self):
        from blue_tap.fuzz.protocols.smp import fuzz_out_of_sequence
        sequences = fuzz_out_of_sequence()
        assert isinstance(sequences, list)
        assert len(sequences) > 0
        for seq in sequences:
            assert isinstance(seq, list)
            for cmd in seq:
                assert isinstance(cmd, bytes)

    def test_fuzz_repeated_pairing(self):
        from blue_tap.fuzz.protocols.smp import fuzz_repeated_pairing
        cases = fuzz_repeated_pairing(count=10)
        assert len(cases) == 10
        self._assert_fuzz_list(cases)

    def test_fuzz_repeated_pairing_default(self):
        from blue_tap.fuzz.protocols.smp import fuzz_repeated_pairing
        cases = fuzz_repeated_pairing()
        assert len(cases) == 50

    def test_fuzz_oversized_pdus(self):
        from blue_tap.fuzz.protocols.smp import fuzz_oversized_pdus
        self._assert_fuzz_list(fuzz_oversized_pdus())

    def test_fuzz_truncated_pdus(self):
        from blue_tap.fuzz.protocols.smp import fuzz_truncated_pdus
        self._assert_fuzz_list(fuzz_truncated_pdus())

    def test_fuzz_unknown_commands(self):
        from blue_tap.fuzz.protocols.smp import fuzz_unknown_commands
        cases = fuzz_unknown_commands()
        self._assert_fuzz_list(cases)
        # Codes 0x0F-0xFF = 241 codes
        assert len(cases) == 241

    def test_generate_all_smp_fuzz_cases(self):
        from blue_tap.fuzz.protocols.smp import generate_all_smp_fuzz_cases
        cases = generate_all_smp_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 200
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0


# ======================================================================
# BNEP Protocol Tests
# ======================================================================

class TestBNEPFrameBuilders:
    """Test all BNEP frame builder functions."""

    def test_build_general_ethernet(self):
        from blue_tap.fuzz.protocols.bnep import build_general_ethernet, BNEP_GENERAL_ETHERNET
        dst = b"\xFF" * 6
        src = b"\x11\x22\x33\x44\x55\x66"
        result = build_general_ethernet(dst, src, 0x0800, b"\x01\x02")
        assert result[0] == BNEP_GENERAL_ETHERNET
        assert result[1:7] == dst
        assert result[7:13] == src
        assert struct.unpack(">H", result[13:15])[0] == 0x0800
        assert result[15:] == b"\x01\x02"

    def test_build_general_ethernet_empty_payload(self):
        from blue_tap.fuzz.protocols.bnep import build_general_ethernet
        result = build_general_ethernet(b"\x00" * 6, b"\x00" * 6, 0x0800)
        assert len(result) == 1 + 6 + 6 + 2

    def test_build_control_frame(self):
        from blue_tap.fuzz.protocols.bnep import build_control_frame, BNEP_CONTROL
        result = build_control_frame(0x01, b"\x02\x11\x16\x11\x15")
        assert result[0] == BNEP_CONTROL
        assert result[1] == 0x01

    def test_build_setup_connection_req_default(self):
        from blue_tap.fuzz.protocols.bnep import build_setup_connection_req
        result = build_setup_connection_req()
        assert isinstance(result, bytes)
        assert result[0] == 0x01  # BNEP_CONTROL
        assert result[1] == 0x01  # SETUP_REQ
        assert result[2] == 2    # uuid_size=2

    def test_build_setup_connection_req_uuid16(self):
        from blue_tap.fuzz.protocols.bnep import build_setup_connection_req
        result = build_setup_connection_req(uuid_size=2)
        assert result[2] == 2
        # Should have 4 bytes of UUID data (2 * 2)
        assert len(result) == 3 + 4

    def test_build_setup_connection_req_uuid128(self):
        from blue_tap.fuzz.protocols.bnep import build_setup_connection_req
        result = build_setup_connection_req(uuid_size=16)
        assert result[2] == 16
        assert len(result) == 3 + 32  # 2 * 16

    def test_build_setup_connection_req_custom_uuids(self):
        from blue_tap.fuzz.protocols.bnep import build_setup_connection_req
        dst = b"\x11\x16"
        src = b"\x11\x15"
        result = build_setup_connection_req(uuid_size=2, dst_uuid=dst, src_uuid=src)
        assert result[3:5] == dst
        assert result[5:7] == src

    def test_build_setup_connection_rsp(self):
        from blue_tap.fuzz.protocols.bnep import build_setup_connection_rsp
        result = build_setup_connection_rsp(0x0000)
        assert len(result) == 4
        assert struct.unpack(">H", result[2:])[0] == 0x0000

    def test_build_filter_net_type_set(self):
        from blue_tap.fuzz.protocols.bnep import build_filter_net_type_set
        result = build_filter_net_type_set([(0x0800, 0x0800)])
        assert isinstance(result, bytes)
        # Header (2) + list_length (2) + 1 range (4)
        assert len(result) == 2 + 2 + 4

    def test_build_filter_net_type_set_empty(self):
        from blue_tap.fuzz.protocols.bnep import build_filter_net_type_set
        result = build_filter_net_type_set([])
        assert len(result) == 4  # header + length(0)

    def test_build_filter_multicast_set(self):
        from blue_tap.fuzz.protocols.bnep import build_filter_multicast_set
        start = b"\x01\x00\x5E\x00\x00\x01"
        end = b"\x01\x00\x5E\x00\x00\x02"
        result = build_filter_multicast_set([(start, end)])
        assert isinstance(result, bytes)
        assert len(result) == 2 + 2 + 12

    def test_build_compressed(self):
        from blue_tap.fuzz.protocols.bnep import build_compressed, BNEP_COMPRESSED
        result = build_compressed(0x0800, b"\x01\x02")
        assert result[0] == BNEP_COMPRESSED
        assert struct.unpack(">H", result[1:3])[0] == 0x0800
        assert result[3:] == b"\x01\x02"

    def test_build_compressed_empty(self):
        from blue_tap.fuzz.protocols.bnep import build_compressed
        result = build_compressed(0x0800)
        assert len(result) == 3

    def test_build_compressed_src_only(self):
        from blue_tap.fuzz.protocols.bnep import build_compressed_src_only, BNEP_COMPRESSED_SRC_ONLY
        src = b"\x11\x22\x33\x44\x55\x66"
        result = build_compressed_src_only(src, 0x0800, b"\xAA")
        assert result[0] == BNEP_COMPRESSED_SRC_ONLY
        assert result[1:7] == src

    def test_build_compressed_dst_only(self):
        from blue_tap.fuzz.protocols.bnep import build_compressed_dst_only, BNEP_COMPRESSED_DST_ONLY
        dst = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        result = build_compressed_dst_only(dst, 0x0806, b"\xBB")
        assert result[0] == BNEP_COMPRESSED_DST_ONLY
        assert result[1:7] == dst


class TestBNEPFuzzGenerators:
    """Test all BNEP fuzz generators."""

    def _assert_fuzz_list(self, cases):
        assert isinstance(cases, list)
        assert len(cases) > 0
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0

    def test_fuzz_setup_uuid_sizes(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_setup_uuid_sizes
        self._assert_fuzz_list(fuzz_setup_uuid_sizes())

    def test_fuzz_setup_oversized_uuid(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_setup_oversized_uuid
        self._assert_fuzz_list(fuzz_setup_oversized_uuid())

    def test_fuzz_oversized_ethernet(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_oversized_ethernet
        self._assert_fuzz_list(fuzz_oversized_ethernet())

    def test_fuzz_invalid_control_types(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_invalid_control_types
        cases = fuzz_invalid_control_types()
        self._assert_fuzz_list(cases)
        # 0x07-0xFF = 249 cases
        assert len(cases) == 249

    def test_fuzz_filter_overflow(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_filter_overflow
        self._assert_fuzz_list(fuzz_filter_overflow())

    def test_fuzz_zero_length_frames(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_zero_length_frames
        self._assert_fuzz_list(fuzz_zero_length_frames())

    def test_fuzz_extension_bit(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_extension_bit
        self._assert_fuzz_list(fuzz_extension_bit())

    def test_fuzz_invalid_packet_types(self):
        from blue_tap.fuzz.protocols.bnep import fuzz_invalid_packet_types
        self._assert_fuzz_list(fuzz_invalid_packet_types())

    def test_generate_all_bnep_fuzz_cases(self):
        from blue_tap.fuzz.protocols.bnep import generate_all_bnep_fuzz_cases
        cases = generate_all_bnep_fuzz_cases()
        assert isinstance(cases, list)
        assert len(cases) > 200
        for case in cases:
            assert isinstance(case, bytes)
            assert len(case) > 0


# ======================================================================
# AT Commands Protocol Tests
# ======================================================================

class TestATCmdHelper:
    """Test the at_cmd encoding helper."""

    def test_at_cmd_basic(self):
        from blue_tap.fuzz.protocols.at_commands import at_cmd
        result = at_cmd("AT+BRSF=127")
        assert result == b"AT+BRSF=127\r"

    def test_at_cmd_empty(self):
        from blue_tap.fuzz.protocols.at_commands import at_cmd
        result = at_cmd("")
        assert result == b"\r"

    def test_at_cmd_unicode(self):
        from blue_tap.fuzz.protocols.at_commands import at_cmd
        result = at_cmd("AT+TEST=\u00c4")
        assert isinstance(result, bytes)
        assert result.endswith(b"\r")


class TestATCorpusGenerators:
    """Test each ATCorpus generator method."""

    def _assert_corpus(self, corpus):
        assert isinstance(corpus, list)
        assert len(corpus) > 0
        for payload in corpus:
            assert isinstance(payload, bytes)

    def test_generate_hfp_slc_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_hfp_slc_corpus()
        self._assert_corpus(corpus)
        # Should include BRSF, BAC, CIND, CMER, CHLD, BIND, BCS, BVRA, BIEV
        text = b"".join(corpus)
        assert b"AT+BRSF=" in text
        assert b"AT+BAC=" in text
        assert b"AT+CIND" in text

    def test_generate_hfp_call_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_hfp_call_corpus()
        self._assert_corpus(corpus)
        text = b"".join(corpus)
        assert b"AT+CHLD=" in text
        assert b"ATD" in text
        assert b"ATA" in text

    def test_generate_hfp_query_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_hfp_query_corpus()
        self._assert_corpus(corpus)
        text = b"".join(corpus)
        assert b"AT+VGS=" in text
        assert b"AT+VGM=" in text

    def test_generate_phonebook_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_phonebook_corpus()
        self._assert_corpus(corpus)
        text = b"".join(corpus)
        assert b"AT+CPBS=" in text
        assert b"AT+CPBR=" in text
        assert b"AT+CPBF=" in text
        assert b"AT+CPBW=" in text

    def test_generate_sms_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_sms_corpus()
        self._assert_corpus(corpus)
        text = b"".join(corpus)
        assert b"AT+CMGF=" in text
        assert b"AT+CMGL=" in text

    def test_generate_injection_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_injection_corpus()
        self._assert_corpus(corpus)
        # Should include buffer overflow, null byte, format string, CRLF injection
        assert len(corpus) > 30

    def test_generate_device_info_corpus(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        corpus = ATCorpus.generate_device_info_corpus()
        self._assert_corpus(corpus)
        text = b"".join(corpus)
        assert b"ATI" in text
        assert b"AT+GMI" in text

    def test_generate_all(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        all_payloads = ATCorpus.generate_all()
        assert isinstance(all_payloads, list)
        assert len(all_payloads) > 300
        # Should be de-duplicated
        assert len(all_payloads) == len(set(all_payloads))
        for payload in all_payloads:
            assert isinstance(payload, bytes)

    def test_corpus_stats(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        stats = ATCorpus.corpus_stats()
        assert isinstance(stats, dict)
        assert "total" in stats
        assert "hfp_slc" in stats
        assert "injection" in stats
        assert stats["total"] > 300
        # Each category should have at least some payloads
        for key, count in stats.items():
            assert count > 0


# ======================================================================
# Cross-Module Integration Tests
# ======================================================================

class TestMasterGenerators:
    """Test that all master generator functions work and return substantial output."""

    def test_sdp_master_generator_count(self):
        from blue_tap.fuzz.protocols.sdp import generate_all_sdp_fuzz_cases
        cases = generate_all_sdp_fuzz_cases()
        assert len(cases) >= 200

    def test_att_master_generator_count(self):
        from blue_tap.fuzz.protocols.att import generate_all_att_fuzz_cases
        cases = generate_all_att_fuzz_cases()
        assert len(cases) >= 200

    def test_l2cap_master_generator_count(self):
        from blue_tap.fuzz.protocols.l2cap import generate_all_l2cap_fuzz_cases
        cases = generate_all_l2cap_fuzz_cases()
        assert len(cases) >= 50

    def test_rfcomm_master_generator_count(self):
        from blue_tap.fuzz.protocols.rfcomm import generate_all_rfcomm_fuzz_cases
        cases = generate_all_rfcomm_fuzz_cases()
        assert len(cases) >= 100

    def test_smp_master_generator_count(self):
        from blue_tap.fuzz.protocols.smp import generate_all_smp_fuzz_cases
        cases = generate_all_smp_fuzz_cases()
        assert len(cases) >= 200

    def test_bnep_master_generator_count(self):
        from blue_tap.fuzz.protocols.bnep import generate_all_bnep_fuzz_cases
        cases = generate_all_bnep_fuzz_cases()
        assert len(cases) >= 200

    def test_at_master_generator_count(self):
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        cases = ATCorpus.generate_all()
        assert len(cases) >= 300

    def test_all_generators_produce_bytes(self):
        """Verify all master generators produce only bytes items."""
        from blue_tap.fuzz.protocols.sdp import generate_all_sdp_fuzz_cases
        from blue_tap.fuzz.protocols.att import generate_all_att_fuzz_cases
        from blue_tap.fuzz.protocols.l2cap import generate_all_l2cap_fuzz_cases
        from blue_tap.fuzz.protocols.rfcomm import generate_all_rfcomm_fuzz_cases
        from blue_tap.fuzz.protocols.smp import generate_all_smp_fuzz_cases
        from blue_tap.fuzz.protocols.bnep import generate_all_bnep_fuzz_cases
        from blue_tap.fuzz.protocols.at_commands import ATCorpus

        generators = [
            generate_all_sdp_fuzz_cases,
            generate_all_att_fuzz_cases,
            generate_all_l2cap_fuzz_cases,
            generate_all_rfcomm_fuzz_cases,
            generate_all_smp_fuzz_cases,
            generate_all_bnep_fuzz_cases,
            ATCorpus.generate_all,
        ]
        for gen in generators:
            cases = gen()
            for case in cases:
                assert isinstance(case, bytes), (
                    f"{gen.__qualname__} produced non-bytes: {type(case)}"
                )
