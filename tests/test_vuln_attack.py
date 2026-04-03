"""Unit tests for vulnerability scanner, fleet assessment, KNOB attack, and AVRCP modules."""

import pytest

# ---------------------------------------------------------------------------
# vuln_scanner imports
# ---------------------------------------------------------------------------
from blue_tap.attack.vuln_scanner import (
    _finding,
    _parse_bt_version,
    _check_knob,
    _check_bluffs,
    _check_pin_pairing_bypass,
    _check_bias,
    _check_bias_active,
    HCITOOL_TIMEOUT,
    SDP_BROWSE_TIMEOUT,
    RFCOMM_PROBE_TIMEOUT,
    L2CAP_PROBE_TIMEOUT,
    OBEX_PROBE_TIMEOUT,
    ENCRYPTION_TIMEOUT,
    AT_PROBE_TIMEOUT,
)

# ---------------------------------------------------------------------------
# fleet imports
# ---------------------------------------------------------------------------
from blue_tap.attack.fleet import DeviceClassifier, FleetAssessment

# ---------------------------------------------------------------------------
# knob imports
# ---------------------------------------------------------------------------
from blue_tap.attack.knob import KNOBAttack

# ---------------------------------------------------------------------------
# avrcp imports
# ---------------------------------------------------------------------------
from blue_tap.attack.avrcp import _variant_to_python


# ============================================================================
# vuln_scanner: _finding
# ============================================================================

class TestFinding:
    """Tests for the _finding helper."""

    def test_creates_dict_with_all_nine_fields(self) -> None:
        result = _finding(
            "HIGH",
            "Test Finding",
            "A test description",
            cve="CVE-2024-0001",
            impact="Something bad",
            remediation="Fix it",
            status="confirmed",
            confidence="high",
            evidence="proof",
        )
        assert result == {
            "severity": "HIGH",
            "name": "Test Finding",
            "description": "A test description",
            "cve": "CVE-2024-0001",
            "impact": "Something bad",
            "remediation": "Fix it",
            "status": "confirmed",
            "confidence": "high",
            "evidence": "proof",
        }

    def test_defaults_work_correctly(self) -> None:
        result = _finding("INFO", "Minimal", "desc only")
        assert result["severity"] == "INFO"
        assert result["name"] == "Minimal"
        assert result["description"] == "desc only"
        assert result["cve"] == "N/A"
        assert result["impact"] == ""
        assert result["remediation"] == ""
        assert result["status"] == "potential"
        assert result["confidence"] == "medium"
        assert result["evidence"] == ""

    def test_exactly_nine_keys(self) -> None:
        result = _finding("LOW", "n", "d")
        assert len(result) == 9


# ============================================================================
# vuln_scanner: _parse_bt_version
# ============================================================================

class TestParseBtVersion:
    """Tests for _parse_bt_version."""

    @pytest.mark.parametrize("raw, expected", [
        ("Bluetooth 5.2", 5.2),
        ("LMP 4.0", 4.0),
        ("version 3.0 something", 3.0),
        ("11.0+extra", 11.0),
        ("5", 5.0),
    ])
    def test_extracts_version(self, raw: str, expected: float) -> None:
        assert _parse_bt_version(raw) == expected

    def test_none_input(self) -> None:
        assert _parse_bt_version(None) is None

    def test_empty_string(self) -> None:
        assert _parse_bt_version("") is None

    def test_no_numbers(self) -> None:
        assert _parse_bt_version("no version here") is None


# ============================================================================
# vuln_scanner: _check_knob
# ============================================================================

class TestCheckKnob:
    """Tests for KNOB vulnerability check (CVE-2019-9506)."""

    def test_version_below_5_1_returns_finding(self) -> None:
        findings = _check_knob(4.2, "LMP 4.2")
        assert len(findings) == 1
        f = findings[0]
        assert f["cve"] == "CVE-2019-9506"
        assert f["severity"] == "MEDIUM"
        assert f["status"] == "potential"

    def test_version_at_5_1_returns_empty(self) -> None:
        assert _check_knob(5.1, "BT 5.1") == []

    def test_version_above_5_1_returns_empty(self) -> None:
        assert _check_knob(5.3, "BT 5.3") == []

    def test_none_version_returns_empty(self) -> None:
        assert _check_knob(None, None) == []

    def test_pause_encryption_upgrades_to_high(self) -> None:
        features = {"pause_encryption": True}
        findings = _check_knob(4.0, "LMP 4.0", lmp_features=features)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "pause_encryption" in findings[0]["evidence"]

    def test_no_pause_encryption_stays_medium(self) -> None:
        features = {"pause_encryption": False}
        findings = _check_knob(4.0, "LMP 4.0", lmp_features=features)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"


# ============================================================================
# vuln_scanner: _check_bluffs
# ============================================================================

class TestCheckBluffs:
    """Tests for BLUFFS vulnerability check (CVE-2023-24023)."""

    def test_version_below_5_4_returns_finding(self) -> None:
        findings = _check_bluffs(5.3, "BT 5.3")
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2023-24023"
        assert findings[0]["severity"] == "MEDIUM"

    def test_version_at_5_4_returns_empty(self) -> None:
        assert _check_bluffs(5.4, "BT 5.4") == []

    def test_version_above_5_4_returns_empty(self) -> None:
        assert _check_bluffs(6.0, "BT 6.0") == []

    def test_none_version_returns_empty(self) -> None:
        assert _check_bluffs(None, None) == []


# ============================================================================
# vuln_scanner: _check_pin_pairing_bypass
# ============================================================================

class TestCheckPinPairingBypass:
    """Tests for PIN pairing auth bypass (CVE-2020-26555)."""

    def test_ssp_false_and_version_lte_5_2_returns_high(self) -> None:
        findings = _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=False)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "HIGH"
        assert f["cve"] == "CVE-2020-26555"
        assert f["status"] == "confirmed"

    def test_ssp_false_at_5_2_boundary(self) -> None:
        findings = _check_pin_pairing_bypass(5.2, "BT 5.2", ssp=False)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_ssp_false_above_5_2_returns_empty(self) -> None:
        assert _check_pin_pairing_bypass(5.3, "BT 5.3", ssp=False) == []

    def test_ssp_true_returns_empty(self) -> None:
        assert _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=True) == []

    def test_ssp_none_returns_empty(self) -> None:
        assert _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=None) == []

    def test_version_none_returns_empty(self) -> None:
        assert _check_pin_pairing_bypass(None, None, ssp=False) == []


# ============================================================================
# vuln_scanner: _check_bias
# ============================================================================

class TestCheckBias:
    """Tests for passive BIAS check (CVE-2020-10135)."""

    def test_ssp_false_returns_empty(self) -> None:
        assert _check_bias(ssp=False) == []

    def test_ssp_true_returns_info_finding(self) -> None:
        findings = _check_bias(ssp=True)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"
        assert findings[0]["cve"] == "CVE-2020-10135"
        assert findings[0]["status"] == "unverified"

    def test_ssp_none_returns_info_finding(self) -> None:
        findings = _check_bias(ssp=None)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"


# ============================================================================
# vuln_scanner: _check_bias_active
# ============================================================================

class TestCheckBiasActive:
    """Tests for active BIAS probe (CVE-2020-10135)."""

    def test_no_phone_address_returns_skipped(self) -> None:
        findings = _check_bias_active(
            "AA:BB:CC:DD:EE:FF", "hci0", ssp=True, phone_address=None,
        )
        assert len(findings) == 1
        f = findings[0]
        assert "skipped" in f["name"].lower()
        assert f["cve"] == "CVE-2020-10135"
        assert f["status"] == "unverified"

    def test_ssp_false_returns_skipped(self) -> None:
        findings = _check_bias_active(
            "AA:BB:CC:DD:EE:FF", "hci0", ssp=False, phone_address=None,
        )
        assert len(findings) == 1
        f = findings[0]
        assert "skipped" in f["name"].lower() or "ssp" in f["description"].lower()
        assert f["status"] == "unverified"

    def test_ssp_false_with_phone_still_skips(self) -> None:
        findings = _check_bias_active(
            "AA:BB:CC:DD:EE:FF", "hci0", ssp=False,
            phone_address="11:22:33:44:55:66",
        )
        assert len(findings) == 1
        assert "ssp" in findings[0]["description"].lower()


# ============================================================================
# vuln_scanner: timeout constants
# ============================================================================

class TestTimeoutConstants:
    """Ensure all timeout constants exist and are positive."""

    @pytest.mark.parametrize("const", [
        HCITOOL_TIMEOUT,
        SDP_BROWSE_TIMEOUT,
        RFCOMM_PROBE_TIMEOUT,
        L2CAP_PROBE_TIMEOUT,
        OBEX_PROBE_TIMEOUT,
        ENCRYPTION_TIMEOUT,
        AT_PROBE_TIMEOUT,
    ])
    def test_timeout_positive(self, const: float) -> None:
        assert isinstance(const, (int, float))
        assert const > 0


# ============================================================================
# fleet: DeviceClassifier.classify
# ============================================================================

class TestDeviceClassifier:
    """Tests for DeviceClassifier.classify."""

    def setup_method(self) -> None:
        self.clf = DeviceClassifier()

    def test_hfp_ag_uuid_returns_ivi(self) -> None:
        device = {"service_uuids": ["0x111f"]}
        assert self.clf.classify(device) == "ivi"

    def test_car_audio_class_returns_ivi(self) -> None:
        # 0x200408: major=0x0400 (audio_video), minor=0x02 shifted → minor in hex
        # Actually let's compute: CoD 0x200408 → major = 0x200408 & 0x1F00 = 0x0400
        # minor = (0x200408 >> 2) & 0x3F = (0x080102) & 0x3F = 0x02
        # Wait, the test says 0x200408 is Car Audio. Let me check:
        # major bits 12-8: 0x200408 & 0x1F00 = 0x0400 (audio_video)
        # minor bits 7-2: (0x200408 >> 2) & 0x3F = (0x80102) & 0x3F = 0x02
        # _AV_MINOR_IVI = {0x08}, so 0x02 != 0x08. Need to construct proper CoD.
        # Car Audio minor class = 0x08, which is bits 7-2.
        # To get minor=0x08 from (cod >> 2) & 0x3F, need (cod >> 2) & 0x3F == 0x08
        # So cod bits 7-2 = 0x08, meaning cod & 0xFC = 0x08 << 2 = 0x20
        # Full CoD for Car Audio: major=0x0400 | minor_bits=0x20 = 0x0420
        device = {"class": 0x0420}
        assert self.clf.classify(device) == "ivi"

    def test_phone_class_returns_phone(self) -> None:
        # major = 0x0200 (phone)
        device = {"class": 0x020C}
        assert self.clf.classify(device) == "phone"

    def test_audio_non_car_returns_headset(self) -> None:
        # major = 0x0400 (audio_video), minor != car audio
        # minor = 0x04 (Wearable Headset), bits 7-2: cod & 0xFC = 0x04 << 2 = 0x10
        device = {"class": 0x0404}
        assert self.clf.classify(device) == "headset"

    def test_computer_class_returns_computer(self) -> None:
        device = {"class": 0x0100}
        assert self.clf.classify(device) == "computer"

    def test_name_bmw_returns_ivi(self) -> None:
        device = {"name": "BMW iDrive"}
        assert self.clf.classify(device) == "ivi"

    def test_name_iphone_returns_phone(self) -> None:
        device = {"name": "iPhone 15"}
        assert self.clf.classify(device) == "phone"

    def test_name_airpods_returns_headset(self) -> None:
        device = {"name": "AirPods Pro"}
        assert self.clf.classify(device) == "headset"

    def test_empty_device_returns_unknown(self) -> None:
        assert self.clf.classify({}) == "unknown"

    def test_string_class_hex_parsed(self) -> None:
        # Pass class as hex string "0x0200" → phone
        device = {"class": "0x0200"}
        assert self.clf.classify(device) == "phone"

    def test_uuid_priority_over_class(self) -> None:
        """HFP AG UUID should win even if device class says phone."""
        device = {"service_uuids": ["0x111f"], "class": 0x0200}
        assert self.clf.classify(device) == "ivi"

    def test_wearable_class(self) -> None:
        device = {"class": 0x0700}
        assert self.clf.classify(device) == "wearable"


# ============================================================================
# fleet: _rate_device
# ============================================================================

class TestRateDevice:
    """Tests for FleetAssessment._rate_device."""

    def test_empty_findings_returns_info(self) -> None:
        assert FleetAssessment._rate_device([]) == "INFO"

    def test_critical_finding_returns_critical(self) -> None:
        findings = [{"severity": "CRITICAL"}]
        assert FleetAssessment._rate_device(findings) == "CRITICAL"

    def test_medium_and_low_returns_medium(self) -> None:
        findings = [{"severity": "MEDIUM"}, {"severity": "LOW"}]
        assert FleetAssessment._rate_device(findings) == "MEDIUM"

    def test_info_only_returns_info(self) -> None:
        findings = [{"severity": "INFO"}, {"severity": "INFO"}]
        assert FleetAssessment._rate_device(findings) == "INFO"

    def test_mixed_high_low_returns_high(self) -> None:
        findings = [{"severity": "HIGH"}, {"severity": "LOW"}, {"severity": "INFO"}]
        assert FleetAssessment._rate_device(findings) == "HIGH"

    def test_case_insensitive_severity(self) -> None:
        # Severity is upper-cased by the code via .upper()
        findings = [{"severity": "critical"}]
        assert FleetAssessment._rate_device(findings) == "CRITICAL"

    def test_missing_severity_key_returns_info(self) -> None:
        findings = [{}]
        assert FleetAssessment._rate_device(findings) == "INFO"


# ============================================================================
# fleet: _rate_fleet
# ============================================================================

class TestRateFleet:
    """Tests for FleetAssessment._rate_fleet."""

    def test_empty_results_returns_unknown(self) -> None:
        assert FleetAssessment._rate_fleet([]) == "UNKNOWN"

    def test_mixed_ratings_highest_wins(self) -> None:
        results = [
            {"risk_rating": "LOW"},
            {"risk_rating": "HIGH"},
            {"risk_rating": "MEDIUM"},
        ]
        assert FleetAssessment._rate_fleet(results) == "HIGH"

    def test_all_info_returns_info(self) -> None:
        results = [{"risk_rating": "INFO"}, {"risk_rating": "INFO"}]
        assert FleetAssessment._rate_fleet(results) == "INFO"

    def test_critical_wins_over_all(self) -> None:
        results = [
            {"risk_rating": "HIGH"},
            {"risk_rating": "CRITICAL"},
            {"risk_rating": "LOW"},
        ]
        assert FleetAssessment._rate_fleet(results) == "CRITICAL"

    def test_unknown_only_returns_unknown(self) -> None:
        results = [{"risk_rating": "UNKNOWN"}]
        assert FleetAssessment._rate_fleet(results) == "UNKNOWN"


# ============================================================================
# knob: _parse_acl_from_hcidump
# ============================================================================

class TestParseAclFromHcidump:
    """Tests for KNOBAttack._parse_acl_from_hcidump."""

    def setup_method(self) -> None:
        self.attack = KNOBAttack("AA:BB:CC:DD:EE:FF")

    def test_valid_hex_with_direction_markers(self) -> None:
        # Simulate hcidump -R output: direction marker + hex bytes
        # 4-byte HCI header + 8-byte payload = 12 bytes total
        hci_header = "01 02 03 04"
        payload = "AA BB CC DD EE FF 00 11"
        raw = f"> {hci_header} {payload}\n".encode("ascii")
        result = self.attack._parse_acl_from_hcidump(raw)
        assert result is not None
        assert result == bytes.fromhex("AABBCCDDEEFF0011")

    def test_empty_input_returns_none(self) -> None:
        assert self.attack._parse_acl_from_hcidump(b"") is None

    def test_short_input_returns_none(self) -> None:
        assert self.attack._parse_acl_from_hcidump(b"AA BB") is None

    def test_malformed_hex_returns_none(self) -> None:
        # Less than 8 total bytes after parsing
        raw = b"> ZZ ZZ ZZ ZZ\n"
        # This is 8+ bytes of input but hex parsing will fail
        result = self.attack._parse_acl_from_hcidump(raw)
        assert result is None

    def test_multiple_frames_returns_first(self) -> None:
        frame1 = "> 01 02 03 04 AA BB CC DD EE FF 00 11"
        frame2 = "< 05 06 07 08 22 33 44 55 66 77 88 99"
        raw = f"{frame1}\n{frame2}\n".encode("ascii")
        result = self.attack._parse_acl_from_hcidump(raw)
        assert result is not None
        # Should be payload of first frame (after 4-byte HCI header)
        assert result == bytes.fromhex("AABBCCDDEEFF0011")


# ============================================================================
# knob: brute_force_key
# ============================================================================

class TestBruteForceKey:
    """Tests for KNOBAttack.brute_force_key."""

    def setup_method(self) -> None:
        self.attack = KNOBAttack("AA:BB:CC:DD:EE:FF")

    def test_crafted_1byte_key_found(self) -> None:
        """Craft ACL data that, when XORed with key=0x42, yields a valid L2CAP header."""
        key = 0x42
        # Desired decrypted L2CAP: length=4 (little-endian: 04 00), CID=1 (01 00),
        # then 4 bytes payload
        plaintext = b"\x04\x00\x01\x00ABCD"
        # Encrypt: XOR each byte with 0x42
        acl_data = bytes(b ^ key for b in plaintext)

        result = self.attack.brute_force_key(key_size=1, acl_data=acl_data)
        assert result["key_found"] is True
        assert result["key_hex"] == "42"
        assert result["key_size_bytes"] == 1

    def test_no_valid_l2cap_header_returns_not_found(self) -> None:
        """ACL data that won't match any 1-byte key's L2CAP validation."""
        # All zeros: for key=0x00, decrypted = 00 00 00 00 ... → length=0, CID=0
        # CID must be >= 0x0001, so key=0x00 won't match.
        # For other keys, length won't equal payload_len (4) except by coincidence.
        # Use data designed so no key produces valid L2CAP.
        # 8 bytes of 0xFF: for any 1-byte key k, decrypted[0:2] = (0xFF^k, 0xFF^k)
        # length = (0xFF^k) | ((0xFF^k) << 8), payload_len = 4
        # We need length != 4 for all k. length = (0xFF^k) * 0x0101
        # This equals 4 only if 0xFF^k = 0 (impossible since 0xFF^0xFF=0 → length=0, payload=4, no match)
        # Actually 0xFF^0xFF = 0, length = 0, payload_len = 4, no match. Good.
        # For k=0xFB: 0xFF^0xFB = 0x04, length = 0x04 | (0x04 << 8) = 0x0404, payload = 4. No match.
        # This should work — no key will produce length==4 with uniform bytes.
        acl_data = bytes([0xFF] * 8)
        result = self.attack.brute_force_key(key_size=1, acl_data=acl_data)
        assert result["key_found"] is False

    def test_key_size_above_4_returns_impractical(self) -> None:
        result = self.attack.brute_force_key(key_size=5, acl_data=b"\x00" * 16)
        assert result["key_found"] is False
        assert any("impractical" in d.lower() or "exceeds" in d.lower()
                    for d in result["details"])

    def test_no_acl_data_and_no_connection(self, monkeypatch) -> None:
        """Without acl_data, _try_capture is called; mock it to return None."""
        monkeypatch.setattr(self.attack, "_try_capture_acl_sample", lambda: None)
        result = self.attack.brute_force_key(key_size=1, acl_data=None)
        assert result["key_found"] is False
        assert any("enumeration" in d.lower() or "no captured" in d.lower()
                    for d in result["details"])

    def test_2byte_key_found(self) -> None:
        """Craft data for a 2-byte key."""
        key = 0x1234
        key_bytes = key.to_bytes(2, "big")
        # plaintext: length=2 (02 00), CID=1 (01 00), payload=2 bytes
        plaintext = b"\x02\x00\x01\x00AB"
        key_stream = (key_bytes * 3)[:len(plaintext)]
        acl_data = bytes(a ^ b for a, b in zip(plaintext, key_stream))

        result = self.attack.brute_force_key(key_size=2, acl_data=acl_data)
        assert result["key_found"] is True
        assert result["key_hex"] == "1234"


# ============================================================================
# avrcp: _variant_to_python
# ============================================================================

class TestVariantToPython:
    """Tests for _variant_to_python conversion."""

    def test_plain_string_passthrough(self) -> None:
        assert _variant_to_python("hello") == "hello"

    def test_plain_int_passthrough(self) -> None:
        assert _variant_to_python(42) == 42

    def test_plain_dict_converts_keys_to_str(self) -> None:
        result = _variant_to_python({1: "a", 2: "b"})
        assert result == {"1": "a", "2": "b"}

    def test_plain_list_passthrough(self) -> None:
        result = _variant_to_python([1, "two", 3.0])
        assert result == [1, "two", 3.0]

    def test_nested_dict_recursion(self) -> None:
        nested = {"outer": {"inner": [1, 2, 3]}}
        result = _variant_to_python(nested)
        assert result == {"outer": {"inner": [1, 2, 3]}}

    def test_none_passthrough(self) -> None:
        assert _variant_to_python(None) is None

    def test_bool_passthrough(self) -> None:
        assert _variant_to_python(True) is True

    def test_list_of_dicts(self) -> None:
        data = [{"a": 1}, {"b": 2}]
        result = _variant_to_python(data)
        assert result == [{"a": 1}, {"b": 2}]


class TestVariantToPythonWithDBusFast:
    """Tests using actual dbus_fast Variant objects, if available."""

    @pytest.fixture(autouse=True)
    def _check_dbus_fast(self) -> None:
        pytest.importorskip("dbus_fast")

    def test_variant_string(self) -> None:
        from dbus_fast import Variant
        v = Variant("s", "hello")
        assert _variant_to_python(v) == "hello"

    def test_variant_int(self) -> None:
        from dbus_fast import Variant
        v = Variant("u", 42)
        assert _variant_to_python(v) == 42

    def test_dict_with_variant_values(self) -> None:
        from dbus_fast import Variant
        d = {"Artist": Variant("s", "Beatles"), "Track": Variant("u", 5)}
        result = _variant_to_python(d)
        assert result == {"Artist": "Beatles", "Track": 5}

    def test_list_of_variants(self) -> None:
        from dbus_fast import Variant
        items = [Variant("s", "a"), Variant("s", "b"), Variant("u", 3)]
        result = _variant_to_python(items)
        assert result == ["a", "b", 3]

    def test_nested_variant_dict(self) -> None:
        from dbus_fast import Variant
        inner = Variant("a{sv}", {"key": Variant("s", "val")})
        outer = {"data": inner}
        result = _variant_to_python(outer)
        assert result == {"data": {"key": "val"}}
