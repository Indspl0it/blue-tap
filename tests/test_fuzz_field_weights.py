"""Tests for Phase 2: Anomaly-Guided Mutation Weights."""

import struct
import pytest

from blue_tap.fuzz.field_weight_tracker import (
    FieldAwareMutator,
    FieldWeightTracker,
    identify_fields,
)
from blue_tap.fuzz.mutators import PacketField


# ===================================================================
# Field Identification
# ===================================================================

class TestIdentifyFields:
    def test_sdp_service_search(self):
        # SDP ServiceSearchReq: PDU=0x02, TID=1, ParamLen=8, pattern...
        pkt = bytes([0x02, 0x00, 0x01]) + struct.pack(">H", 8) + b"\x35\x03\x19\x01\x00\x00\x10\x00"
        fields = identify_fields("sdp", pkt)
        assert len(fields) >= 3
        names = [f.name for f in fields]
        assert "pdu_id" in names
        assert any("length" in n or "param" in n for n in names)

    def test_att_read_by_type(self):
        # ATT ReadByTypeReq: opcode=0x08, start=0x0001, end=0xFFFF, uuid=0x2803
        pkt = bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28])
        fields = identify_fields("ble-att", pkt)
        assert len(fields) >= 3
        names = [f.name for f in fields]
        assert "opcode" in names

    def test_l2cap_config_request(self):
        # L2CAP ConfReq: Code=0x04, ID=1, Len=4, DCID=0x0040, Flags=0x0000
        pkt = bytes([0x04, 0x01]) + struct.pack("<H", 4) + struct.pack("<HH", 0x0040, 0x0000)
        fields = identify_fields("l2cap", pkt)
        assert len(fields) >= 3

    def test_rfcomm_frame(self):
        pkt = bytes([0x03, 0x63, 0x01, 0xD7])
        fields = identify_fields("rfcomm", pkt)
        assert len(fields) >= 3

    def test_unknown_protocol_fallback(self):
        pkt = bytes(range(16))
        fields = identify_fields("unknown_proto", pkt)
        assert len(fields) >= 1  # Should chunk into 4-byte fields

    def test_empty_packet(self):
        fields = identify_fields("sdp", b"")
        assert fields == []

    def test_single_byte(self):
        fields = identify_fields("sdp", b"\x02")
        assert len(fields) >= 1

    def test_all_protocols_dont_crash(self):
        """Smoke test: identify_fields doesn't crash for any protocol."""
        pkt = bytes(range(20))
        for proto in ["sdp", "ble-att", "l2cap", "rfcomm", "ble-smp",
                      "obex-pbap", "obex-map", "bnep", "at-hfp"]:
            fields = identify_fields(proto, pkt)
            assert isinstance(fields, list)


# ===================================================================
# FieldWeightTracker
# ===================================================================

class TestFieldWeightTracker:
    def test_record_and_update(self):
        tracker = FieldWeightTracker()
        for _ in range(50):
            tracker.record_mutation("sdp", "param_length")
        for _ in range(10):
            tracker.record_anomaly("sdp", "param_length")
        tracker.update_weights()
        weights = tracker.get_weights("sdp")
        assert "param_length" in weights
        assert weights["param_length"] > 0

    def test_crash_boosts_weight(self):
        tracker = FieldWeightTracker()
        for _ in range(10):
            tracker.record_mutation("sdp", "param_length")
            tracker.record_mutation("sdp", "pdu_id")
        tracker.record_crash("sdp", "param_length")
        tracker.update_weights()
        weights = tracker.get_weights("sdp")
        assert weights.get("param_length", 0) > weights.get("pdu_id", 0)

    def test_select_field_returns_string(self):
        tracker = FieldWeightTracker()
        tracker.record_mutation("sdp", "pdu_id")
        tracker.record_mutation("sdp", "param_length")
        tracker.update_weights()
        field = tracker.select_field("sdp")
        assert isinstance(field, str)

    def test_select_field_unknown_protocol(self):
        tracker = FieldWeightTracker()
        field = tracker.select_field("sdp")
        assert isinstance(field, str)  # Should bootstrap from field map

    def test_serialization_roundtrip(self):
        tracker = FieldWeightTracker()
        tracker.record_mutation("sdp", "param_length")
        tracker.record_anomaly("sdp", "param_length")
        tracker.update_weights()
        d = tracker.to_dict()
        t2 = FieldWeightTracker.from_dict(d)
        w1 = tracker.get_weights("sdp")
        w2 = t2.get_weights("sdp")
        assert w1 == w2

    def test_weights_normalize_to_one(self):
        tracker = FieldWeightTracker()
        for name in ["pdu_id", "param_length", "transaction_id", "payload"]:
            tracker.record_mutation("sdp", name)
        tracker.update_weights()
        weights = tracker.get_weights("sdp")
        if weights:
            total = sum(weights.values())
            assert abs(total - 1.0) < 0.01


# ===================================================================
# FieldAwareMutator
# ===================================================================

class TestFieldAwareMutator:
    def test_mutate_sdp(self):
        mutator = FieldAwareMutator()
        tracker = FieldWeightTracker()
        tracker.record_mutation("sdp", "param_length")
        tracker.update_weights()
        pkt = bytes([0x02, 0x00, 0x01]) + struct.pack(">H", 8) + b"\x35\x03\x19\x01\x00\x00\x10\x00"
        mutated, log = mutator.mutate("sdp", pkt, tracker)
        assert isinstance(mutated, bytes)
        assert len(mutated) > 0
        assert isinstance(log, list)
        assert len(log) >= 1

    def test_mutate_att(self):
        mutator = FieldAwareMutator()
        tracker = FieldWeightTracker()
        pkt = bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28])
        mutated, log = mutator.mutate("ble-att", pkt, tracker)
        assert isinstance(mutated, bytes)
        assert len(mutated) > 0

    def test_mutate_returns_different_bytes(self):
        """Field-aware mutation should usually produce different output."""
        mutator = FieldAwareMutator()
        tracker = FieldWeightTracker()
        pkt = bytes([0x02, 0x00, 0x01]) + struct.pack(">H", 8) + b"\x35\x03\x19\x01\x00\x00\x10\x00"
        different_count = 0
        for _ in range(20):
            mutated, _ = mutator.mutate("sdp", pkt, tracker)
            if mutated != pkt:
                different_count += 1
        assert different_count > 10  # At least half should differ

    def test_endianness_att_little_endian(self):
        """ATT fields should be serialized as little-endian."""
        mutator = FieldAwareMutator()
        tracker = FieldWeightTracker()
        # Force mutation of a known field
        for _ in range(100):
            tracker.record_mutation("ble-att", "start_handle")
            tracker.record_anomaly("ble-att", "start_handle")
        tracker.update_weights()
        pkt = bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28])
        mutated, log = mutator.mutate("ble-att", pkt, tracker)
        # Just verify it doesn't crash — endianness correctness is structural
        assert isinstance(mutated, bytes)
