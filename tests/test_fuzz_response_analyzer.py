"""Tests for Phase 3+4+5: Structural Validation, Timing, Leak Detection."""

import os
import struct
import pytest

from blue_tap.fuzz.response_analyzer import (
    Anomaly,
    AnomalyType,
    CausalMap,
    ResponseAnalyzer,
    _byte_entropy,
    _check_leak_indicators,
    _detect_heap_patterns,
    _renyi_entropy,
    _sliding_window_entropy,
    _validate_att_structure,
    _validate_l2cap_structure,
    _validate_rfcomm_structure,
    _validate_sdp_structure,
    _STRUCTURAL_VALIDATORS,
    differential_compare,
)


# ===================================================================
# Structural Validators
# ===================================================================

class TestSDPValidator:
    def test_valid_response(self):
        data = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        anomalies = _validate_sdp_structure(data)
        assert len(anomalies) == 0

    def test_length_mismatch(self):
        data = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 100) + b"\x00\x01\x00\x01\x00"
        anomalies = _validate_sdp_structure(data)
        assert any(a.anomaly_type == AnomalyType.LENGTH_MISMATCH for a in anomalies)

    def test_truncated(self):
        anomalies = _validate_sdp_structure(b"\x03\x00")
        assert len(anomalies) >= 1

    def test_invalid_pdu_id(self):
        data = bytes([0x20, 0x00, 0x01]) + struct.pack(">H", 0)
        anomalies = _validate_sdp_structure(data)
        assert any(a.anomaly_type == AnomalyType.UNEXPECTED_OPCODE for a in anomalies)

    def test_invalid_error_code(self):
        data = bytes([0x01, 0x00, 0x01]) + struct.pack(">H", 2) + struct.pack(">H", 0x00FF)
        anomalies = _validate_sdp_structure(data)
        assert any(a.anomaly_type == AnomalyType.STRUCTURAL for a in anomalies)

    def test_empty(self):
        assert _validate_sdp_structure(b"") == []


class TestATTValidator:
    def test_valid_error_response(self):
        data = bytes([0x01, 0x08, 0x01, 0x00, 0x06])
        anomalies = _validate_att_structure(data)
        assert len(anomalies) == 0

    def test_short_error_response(self):
        data = bytes([0x01, 0x08])
        anomalies = _validate_att_structure(data)
        assert any(a.anomaly_type == AnomalyType.STRUCTURAL for a in anomalies)

    def test_invalid_error_code(self):
        data = bytes([0x01, 0x08, 0x01, 0x00, 0x20])  # 0x20 is undefined
        anomalies = _validate_att_structure(data)
        assert any(a.anomaly_type == AnomalyType.STRUCTURAL for a in anomalies)

    def test_request_opcode_in_response(self):
        data = bytes([0x08, 0x01, 0x00, 0xFF, 0xFF])  # ReadByType REQ echoed back
        anomalies = _validate_att_structure(data)
        assert any(a.anomaly_type == AnomalyType.UNEXPECTED_OPCODE for a in anomalies)

    def test_mtu_response_wrong_length(self):
        data = bytes([0x03, 0x17, 0x00, 0x00])  # 4 bytes, should be 3
        anomalies = _validate_att_structure(data)
        assert any(a.anomaly_type == AnomalyType.LENGTH_MISMATCH for a in anomalies)

    def test_empty(self):
        assert _validate_att_structure(b"") == []


class TestL2CAPValidator:
    def test_valid_response(self):
        data = bytes([0x03, 0x01]) + struct.pack("<H", 8)
        data += struct.pack("<HH", 0x0040, 0x0041) + struct.pack("<HH", 0, 0)
        anomalies = _validate_l2cap_structure(data)
        assert len(anomalies) == 0

    def test_length_mismatch(self):
        data = bytes([0x03, 0x01]) + struct.pack("<H", 50) + b"\x00\x00\x00\x00"
        anomalies = _validate_l2cap_structure(data)
        assert any(a.anomaly_type == AnomalyType.LENGTH_MISMATCH for a in anomalies)

    def test_truncated(self):
        anomalies = _validate_l2cap_structure(b"\x03")
        assert len(anomalies) >= 1


class TestAllProtocolValidators:
    def test_all_registered(self):
        expected = ["sdp", "ble-att", "l2cap", "rfcomm", "ble-smp",
                    "obex-pbap", "obex-map", "obex-opp", "bnep",
                    "at-hfp", "at-phonebook", "at-sms", "at-injection"]
        for proto in expected:
            assert proto in _STRUCTURAL_VALIDATORS, f"Missing: {proto}"

    def test_validators_dont_crash_on_random(self):
        """All validators must handle random bytes without crashing."""
        random_data = os.urandom(64)
        for name, validator in _STRUCTURAL_VALIDATORS.items():
            anomalies = validator(random_data)
            assert isinstance(anomalies, list), f"{name} returned {type(anomalies)}"

    def test_validators_dont_crash_on_empty(self):
        for name, validator in _STRUCTURAL_VALIDATORS.items():
            anomalies = validator(b"")
            assert isinstance(anomalies, list), f"{name} crashed on empty"

    def test_smp_pairing_failed_valid(self):
        data = bytes([0x05, 0x04])
        anomalies = _STRUCTURAL_VALIDATORS["ble-smp"](data)
        assert len(anomalies) == 0

    def test_smp_pairing_failed_short(self):
        data = bytes([0x05])
        anomalies = _STRUCTURAL_VALIDATORS["ble-smp"](data)
        assert len(anomalies) >= 1

    def test_obex_valid(self):
        data = bytes([0xA0]) + struct.pack(">H", 3)
        anomalies = _STRUCTURAL_VALIDATORS["obex-pbap"](data)
        assert len(anomalies) == 0

    def test_obex_length_mismatch(self):
        data = bytes([0xA0]) + struct.pack(">H", 100)
        anomalies = _STRUCTURAL_VALIDATORS["obex-pbap"](data)
        assert any(a.anomaly_type == AnomalyType.LENGTH_MISMATCH for a in anomalies)

    def test_at_valid(self):
        anomalies = _STRUCTURAL_VALIDATORS["at-hfp"](b"OK\r\n")
        assert len(anomalies) == 0

    def test_at_binary_in_text(self):
        anomalies = _STRUCTURAL_VALIDATORS["at-hfp"](b"\x00\x01\x02\x03")
        assert len(anomalies) >= 1


# ===================================================================
# Entropy Analysis
# ===================================================================

class TestEntropy:
    def test_byte_entropy_random(self):
        data = os.urandom(1024)
        e = _byte_entropy(data)
        assert e > 6.0

    def test_byte_entropy_constant(self):
        assert _byte_entropy(b"\x00" * 64) == 0.0

    def test_byte_entropy_empty(self):
        assert _byte_entropy(b"") == 0.0

    def test_renyi_entropy_random(self):
        data = os.urandom(1024)
        e = _renyi_entropy(data)
        assert e > 5.0

    def test_renyi_entropy_constant(self):
        e = _renyi_entropy(b"\x00" * 64)
        assert e == 0.0

    def test_renyi_entropy_empty(self):
        assert _renyi_entropy(b"") == 0.0

    def test_sliding_window_entropy(self):
        # Low entropy region + high entropy region
        data = b"\x00" * 32 + os.urandom(32)
        max_e, mean_e, var_e = _sliding_window_entropy(data)
        assert max_e > mean_e  # High entropy window should spike
        assert var_e > 0

    def test_sliding_window_small_data(self):
        max_e, mean_e, var_e = _sliding_window_entropy(b"\x00\x01")
        assert isinstance(max_e, float)


class TestHeapPatterns:
    def test_deadbeef(self):
        data = b"\x00" * 10 + b"\xDE\xAD\xBE\xEF" + b"\x00" * 10
        patterns = _detect_heap_patterns(data)
        assert len(patterns) >= 1
        assert any("DEADBEEF" in desc for _, desc in patterns)

    def test_no_patterns(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        patterns = _detect_heap_patterns(data)
        # May or may not find patterns, but shouldn't crash
        assert isinstance(patterns, list)

    def test_repeated_4byte(self):
        data = b"\xAB\xCD\xEF\x01" * 5
        patterns = _detect_heap_patterns(data)
        assert len(patterns) >= 1

    def test_empty(self):
        assert _detect_heap_patterns(b"") == []


# ===================================================================
# Differential Compare
# ===================================================================

class TestDifferentialCompare:
    def test_identical(self):
        result = differential_compare(b"\x01\x02\x03", b"\x01\x02\x03")
        assert result["change_ratio"] == 0.0

    def test_one_byte_changed(self):
        result = differential_compare(b"\x01\x02\x03", b"\x01\xFF\x03")
        assert len(result["changed_bytes"]) == 1
        assert result["change_ratio"] > 0

    def test_different_lengths(self):
        result = differential_compare(b"\x01\x02", b"\x01\x02\x03\x04")
        assert result["added_bytes"] == 2

    def test_empty(self):
        result = differential_compare(b"", b"")
        assert result["change_ratio"] == 0.0


# ===================================================================
# CausalMap
# ===================================================================

class TestCausalMap:
    def test_record_and_query(self):
        cm = CausalMap()
        cm.record(0, {1, 2, 3})
        cm.record(1, {4, 5})
        cm.record(2, set())
        assert 0 in cm.high_impact_bytes()
        assert 2 in cm.dead_bytes()

    def test_serialization(self):
        cm = CausalMap()
        cm.record(0, {1, 2})
        d = cm.to_dict()
        cm2 = CausalMap.from_dict(d)
        assert cm2.high_impact_bytes() == cm.high_impact_bytes()


# ===================================================================
# ResponseAnalyzer Integration
# ===================================================================

class TestResponseAnalyzer:
    def test_baseline_learning(self):
        analyzer = ResponseAnalyzer()
        for i in range(5):
            resp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
            analyzer.record_baseline("sdp", resp, 5.0 + i)
        analyzer.finalize_baselines()
        assert analyzer.has_baseline("sdp")

    def test_no_anomalies_normal_response(self):
        analyzer = ResponseAnalyzer()
        for i in range(5):
            resp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
            analyzer.record_baseline("sdp", resp, 5.0)
        analyzer.finalize_baselines()
        anomalies = analyzer.analyze("sdp", b"\x02", resp, 5.5)
        structural = [a for a in anomalies if a.anomaly_type == AnomalyType.STRUCTURAL]
        assert len(structural) == 0

    def test_length_mismatch_detected(self):
        analyzer = ResponseAnalyzer()
        bad = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 200) + b"\x00\x01\x00\x01\x00"
        anomalies = analyzer.analyze("sdp", b"\x02", bad, 5.0)
        assert any(a.anomaly_type == AnomalyType.LENGTH_MISMATCH for a in anomalies)

    def test_timing_spike(self):
        analyzer = ResponseAnalyzer()
        resp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        for i in range(10):
            analyzer.record_baseline("sdp", resp, 5.0)
        analyzer.finalize_baselines()
        anomalies = analyzer.analyze("sdp", b"\x02", resp, 500.0)
        timing = [a for a in anomalies if a.anomaly_type == AnomalyType.TIMING]
        assert len(timing) >= 1

    def test_consecutive_timeouts(self):
        analyzer = ResponseAnalyzer()
        for i in range(5):
            anomalies = analyzer.analyze("sdp", b"\x02", None, 0.0)
        behavioral = [a for a in anomalies if a.anomaly_type == AnomalyType.BEHAVIORAL]
        assert len(behavioral) >= 1

    def test_baseline_summary(self):
        analyzer = ResponseAnalyzer()
        resp = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00\x01\x00\x01\x00"
        for i in range(5):
            analyzer.record_baseline("sdp", resp, 5.0 + i)
        analyzer.finalize_baselines()
        summary = analyzer.baseline_summary()
        assert "sdp" in summary
        assert summary["sdp"]["samples"] == 5
