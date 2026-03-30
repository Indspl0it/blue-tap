"""Tests for Phase 1: Response-Based State Inference."""

import struct
import pytest

from blue_tap.fuzz.state_inference import (
    StateID,
    StateGraph,
    StateInfo,
    StateSequence,
    StateTracker,
    extract_state,
    extract_state_sdp,
    extract_state_att,
    extract_state_l2cap,
    extract_state_rfcomm,
    extract_state_smp,
    extract_state_obex,
    extract_state_bnep,
    extract_state_at,
)


# ===================================================================
# StateID
# ===================================================================

class TestStateID:
    def test_hashable(self):
        s1 = StateID("sdp", 0x01, 0x03, 0)
        s2 = StateID("sdp", 0x01, 0x03, 0)
        assert s1 == s2
        assert hash(s1) == hash(s2)
        assert len({s1, s2}) == 1

    def test_different_states_not_equal(self):
        s1 = StateID("sdp", 0x01, 0x03, 0)
        s2 = StateID("sdp", 0x01, 0x05, 0)
        assert s1 != s2

    def test_repr_readable(self):
        s = StateID("sdp", 0x01, 0x03, 0)
        r = repr(s)
        assert "sdp" in r
        assert "0x01" in r or "1" in r


# ===================================================================
# State Extractors
# ===================================================================

class TestExtractStateSDP:
    def test_error_response(self):
        # SDP Error: PDU=0x01, TID=0x0001, ParamLen=2, ErrorCode=0x0003
        data = bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3)
        s = extract_state_sdp(data)
        assert s.opcode == 0x01
        assert s.error_code == 0x0003

    def test_search_response(self):
        # SDP ServiceSearchRsp: PDU=0x03
        data = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        s = extract_state_sdp(data)
        assert s.opcode == 0x03

    def test_truncated(self):
        s = extract_state_sdp(b"\x01")
        assert s.protocol == "sdp"

    def test_empty(self):
        s = extract_state_sdp(b"")
        assert s.protocol == "sdp"
        assert s.opcode == 0


class TestExtractStateATT:
    def test_error_response(self):
        # ATT Error: opcode=0x01, req_opcode=0x08, handle=0x0001, error=0x06
        data = bytes([0x01, 0x08, 0x01, 0x00, 0x06])
        s = extract_state_att(data)
        assert s.opcode == 0x01
        assert s.error_code == 0x06

    def test_mtu_response(self):
        data = bytes([0x03, 0x17, 0x00])  # MTU Exchange RSP, MTU=23
        s = extract_state_att(data)
        assert s.opcode == 0x03

    def test_empty(self):
        s = extract_state_att(b"")
        assert s.opcode == 0


class TestExtractStateL2CAP:
    def test_command_reject(self):
        # L2CAP Reject: Code=0x01, ID=0x01, Len=2, Reason=0x0000
        data = bytes([0x01, 0x01]) + struct.pack("<H", 2) + struct.pack("<H", 0)
        s = extract_state_l2cap(data)
        assert s.opcode == 0x01

    def test_connection_response(self):
        # ConnRsp: Code=0x03, ID=1, Len=8, DCID=0x0040, SCID=0x0041, Result=0, Status=0
        data = bytes([0x03, 0x01]) + struct.pack("<H", 8)
        data += struct.pack("<HH", 0x0040, 0x0041)
        data += struct.pack("<HH", 0x0000, 0x0000)
        s = extract_state_l2cap(data)
        assert s.opcode == 0x03

    def test_empty(self):
        s = extract_state_l2cap(b"")
        assert s.opcode == 0


class TestExtractStateRFCOMM:
    def test_ua_frame(self):
        # RFCOMM UA: Address=0x03, Control=0x63
        data = bytes([0x03, 0x63, 0x01, 0xD7])
        s = extract_state_rfcomm(data)
        assert s.protocol == "rfcomm"

    def test_empty(self):
        s = extract_state_rfcomm(b"")
        assert s.opcode == 0


class TestExtractStateSMP:
    def test_pairing_response(self):
        data = bytes([0x02, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07])
        s = extract_state_smp(data)
        assert s.opcode == 0x02

    def test_pairing_failed(self):
        data = bytes([0x05, 0x04])  # Failed, reason=AuthFail
        s = extract_state_smp(data)
        assert s.opcode == 0x05
        assert s.error_code == 0x04


class TestExtractStateOBEX:
    def test_success(self):
        data = bytes([0xA0]) + struct.pack(">H", 3)
        s = extract_state_obex(data)
        assert s.opcode == 0xA0

    def test_bad_request(self):
        data = bytes([0xC0]) + struct.pack(">H", 3)
        s = extract_state_obex(data)
        assert s.opcode == 0xC0


class TestExtractStateBNEP:
    def test_control(self):
        data = bytes([0x01, 0x02, 0x00, 0x00])
        s = extract_state_bnep(data)
        assert s.protocol == "bnep"

    def test_empty(self):
        s = extract_state_bnep(b"")
        assert s.opcode == 0


class TestExtractStateAT:
    def test_ok(self):
        s = extract_state_at(b"OK\r\n")
        assert s.protocol == "at"

    def test_error(self):
        s = extract_state_at(b"ERROR\r\n")
        assert s.error_code != 0 or s.opcode != 0

    def test_cme_error(self):
        s = extract_state_at(b"+CME ERROR: 10\r\n")
        assert s.protocol == "at"

    def test_informational(self):
        s = extract_state_at(b"+BRSF: 127\r\n")
        assert s.protocol == "at"

    def test_empty(self):
        s = extract_state_at(b"")
        assert s.opcode == 0


class TestExtractStateDispatcher:
    def test_sdp(self):
        data = bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3)
        s = extract_state("sdp", data)
        assert s.protocol == "sdp"

    def test_unknown_protocol_fallback(self):
        s = extract_state("unknown_proto", bytes([0x42, 0x00]))
        assert s.protocol == "unknown_proto"
        assert s.opcode == 0x42

    def test_empty_unknown(self):
        s = extract_state("foo", b"")
        assert s.opcode == 0


# ===================================================================
# StateSequence
# ===================================================================

class TestStateSequence:
    def test_append_and_trimmed(self):
        seq = StateSequence()
        s1 = StateID("sdp", 1, 0, 0)
        s2 = StateID("sdp", 3, 0, 0)
        seq.append(s1)
        seq.append(s1)  # duplicate
        seq.append(s2)
        seq.append(s2)  # duplicate
        trimmed = seq.trimmed()
        assert len(trimmed) == 2
        assert trimmed[0] == s1
        assert trimmed[1] == s2

    def test_hash_deterministic(self):
        seq1 = StateSequence()
        seq2 = StateSequence()
        s = StateID("sdp", 1, 0, 0)
        seq1.append(s)
        seq2.append(s)
        assert seq1.hash() == seq2.hash()

    def test_different_sequences_different_hash(self):
        seq1 = StateSequence()
        seq2 = StateSequence()
        seq1.append(StateID("sdp", 1, 0, 0))
        seq2.append(StateID("sdp", 3, 0, 0))
        assert seq1.hash() != seq2.hash()

    def test_empty_sequence(self):
        seq = StateSequence()
        assert seq.trimmed() == []
        h = seq.hash()
        assert isinstance(h, str)


# ===================================================================
# StateGraph
# ===================================================================

class TestStateGraph:
    def test_add_transition_returns_true_for_new(self):
        g = StateGraph()
        s1 = StateID("sdp", 1, 0, 0)
        s2 = StateID("sdp", 3, 0, 0)
        assert g.add_transition(s1, s2) is True

    def test_add_transition_returns_false_for_duplicate(self):
        g = StateGraph()
        s1 = StateID("sdp", 1, 0, 0)
        s2 = StateID("sdp", 3, 0, 0)
        g.add_transition(s1, s2)
        assert g.add_transition(s1, s2) is False

    def test_node_and_transition_count(self):
        g = StateGraph()
        s1 = StateID("sdp", 1, 0, 0)
        s2 = StateID("sdp", 3, 0, 0)
        s3 = StateID("sdp", 5, 0, 0)
        g.add_transition(s1, s2)
        g.add_transition(s2, s3)
        assert g.node_count() >= 3
        assert g.transition_count() == 2

    def test_serialization_roundtrip(self):
        g = StateGraph()
        s1 = StateID("sdp", 1, 0, 0)
        s2 = StateID("sdp", 3, 0, 0)
        g.add_transition(s1, s2)
        d = g.to_dict()
        g2 = StateGraph.from_dict(d)
        assert g2.transition_count() == 1
        assert g2.node_count() == g.node_count()


# ===================================================================
# StateInfo (AFLNet scoring)
# ===================================================================

class TestStateInfo:
    def test_initial_score(self):
        si = StateInfo(state_id=StateID("sdp", 1, 0, 0))
        si.compute_score()
        assert si.score == 1000.0  # Initial: fuzz_count=0, selected_times=0

    def test_score_decreases_with_exploration(self):
        si = StateInfo(state_id=StateID("sdp", 1, 0, 0))
        si.fuzz_count = 1000
        si.selected_times = 50
        si.compute_score()
        score_heavy = si.score

        si2 = StateInfo(state_id=StateID("sdp", 3, 0, 0))
        si2.fuzz_count = 1
        si2.selected_times = 1
        si2.compute_score()
        score_light = si2.score

        assert score_light > score_heavy

    def test_score_increases_with_discoveries(self):
        si = StateInfo(state_id=StateID("sdp", 1, 0, 0))
        si.paths_discovered = 10
        si.compute_score()
        score_productive = si.score

        si2 = StateInfo(state_id=StateID("sdp", 1, 0, 0))
        si2.paths_discovered = 0
        si2.compute_score()
        score_barren = si2.score

        assert score_productive > score_barren


# ===================================================================
# StateTracker
# ===================================================================

class TestStateTracker:
    def test_record_novel_states(self):
        tracker = StateTracker()
        sdp_error = bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3)
        sdp_rsp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        assert tracker.record("sdp", sdp_error) is True
        assert tracker.record("sdp", sdp_rsp) is True

    def test_auto_seed_registration(self):
        tracker = StateTracker()
        sdp_rsp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        seed = b"\x02\x00\x01\x00\x08\x35\x03"
        tracker.record("sdp", sdp_rsp, seed=seed)
        state = extract_state("sdp", sdp_rsp)
        result = tracker.select_seed_for_state(state)
        assert result is not None

    def test_coverage_stats(self):
        tracker = StateTracker()
        tracker.record("sdp", bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3))
        tracker.record("sdp", bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00")
        cov = tracker.get_state_coverage()
        assert cov["total_states"] >= 2
        assert "sdp" in cov["protocols"]

    def test_serialization_roundtrip(self):
        tracker = StateTracker()
        tracker.record("sdp", bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3))
        d = tracker.to_dict()
        t2 = StateTracker.from_dict(d)
        assert t2.get_state_coverage()["total_states"] == tracker.get_state_coverage()["total_states"]

    def test_finalize_sequence(self):
        tracker = StateTracker()
        tracker.record("sdp", bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3))
        tracker.record("sdp", bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00")
        novel = tracker.finalize_sequence("sdp", seed=b"\x02\x00\x01")
        assert isinstance(novel, bool)

    def test_multiple_protocols(self):
        tracker = StateTracker()
        tracker.record("sdp", bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 3))
        tracker.record("ble-att", bytes([0x01, 0x08, 0x01, 0x00, 0x06]))
        cov = tracker.get_state_coverage()
        assert "sdp" in cov["protocols"]
        assert "ble-att" in cov["protocols"]
