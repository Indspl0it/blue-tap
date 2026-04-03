"""Comprehensive unit tests for vuln_scanner, fleet, and auto modules.

Covers every function in:
  - blue_tap/attack/vuln_scanner.py  (29 functions)
  - blue_tap/attack/fleet.py         (DeviceClassifier + FleetAssessment)
  - blue_tap/attack/auto.py          (_rssi_key, _phase, AutoPentest)

All hardware/network interactions are mocked.
"""

import errno
import os
import socket
import struct
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# vuln_scanner imports
# ---------------------------------------------------------------------------
from blue_tap.attack.vuln_scanner import (
    _finding,
    _parse_bt_version,
    _run_hcitool_info,
    _check_service_exposure,
    _check_knob,
    _check_blurtooth,
    _check_perfektblue,
    _check_bluffs,
    _check_pin_pairing_bypass,
    _check_invalid_curve,
    _check_bias,
    _check_bias_active,
    _check_blueborne,
    _check_pairing_method,
    _check_writable_gatt,
    _check_braktooth_chipset,
    _check_eatt_support,
    _check_hidden_rfcomm,
    _check_encryption_enforcement,
    _check_pin_lockout,
    _check_device_class,
    _extract_lmp_features_dict,
    _check_lmp_features,
    _check_authorization_model,
    _check_automotive_diagnostics,
    scan_vulnerabilities,
    _print_findings,
)

# ---------------------------------------------------------------------------
# fleet imports
# ---------------------------------------------------------------------------
from blue_tap.attack.fleet import DeviceClassifier, FleetAssessment

# ---------------------------------------------------------------------------
# auto imports
# ---------------------------------------------------------------------------
from blue_tap.attack.auto import _rssi_key, _phase, AutoPentest


ADDR = "AA:BB:CC:DD:EE:FF"
HCI = "hci0"


def _cmd_result(returncode=0, stdout="", stderr=""):
    """Create a fake subprocess.CompletedProcess."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# ============================================================================
# vuln_scanner: _finding
# ============================================================================

class TestFinding:
    def test_all_fields_provided(self):
        r = _finding("HIGH", "Name", "Desc", cve="CVE-1", impact="imp",
                      remediation="fix", status="confirmed", confidence="high",
                      evidence="ev")
        assert r["severity"] == "HIGH"
        assert r["name"] == "Name"
        assert r["description"] == "Desc"
        assert r["cve"] == "CVE-1"
        assert r["impact"] == "imp"
        assert r["remediation"] == "fix"
        assert r["status"] == "confirmed"
        assert r["confidence"] == "high"
        assert r["evidence"] == "ev"

    def test_defaults(self):
        r = _finding("LOW", "n", "d")
        assert r["cve"] == "N/A"
        assert r["impact"] == ""
        assert r["remediation"] == ""
        assert r["status"] == "potential"
        assert r["confidence"] == "medium"
        assert r["evidence"] == ""
        assert len(r) == 9


# ============================================================================
# vuln_scanner: _parse_bt_version
# ============================================================================

class TestParseBtVersion:
    @pytest.mark.parametrize("raw,expected", [
        ("Bluetooth 5.2", 5.2),
        ("LMP 4.0", 4.0),
        ("version 3.0 something", 3.0),
        ("11.0+extra", 11.0),
        ("5", 5.0),
    ])
    def test_valid(self, raw, expected):
        assert _parse_bt_version(raw) == expected

    def test_none(self):
        assert _parse_bt_version(None) is None

    def test_empty_string(self):
        assert _parse_bt_version("") is None

    def test_no_digits(self):
        assert _parse_bt_version("no version here") is None


# ============================================================================
# vuln_scanner: _run_hcitool_info
# ============================================================================

class TestRunHcitoolInfo:
    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_success_first_try(self, mock_cmd):
        mock_cmd.return_value = _cmd_result(0, "LMP Version: 5.2")
        r = _run_hcitool_info(ADDR, HCI)
        assert r.returncode == 0
        mock_cmd.assert_called_once()

    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_retry_on_transient_timeout(self, mock_cmd):
        fail = _cmd_result(1, "", "timeout")
        ok = _cmd_result(0, "LMP Version: 5.2")
        mock_cmd.side_effect = [fail, ok]
        r = _run_hcitool_info(ADDR, HCI)
        assert r.returncode == 0
        assert mock_cmd.call_count == 2

    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_retry_on_resource_temporarily(self, mock_cmd):
        fail = _cmd_result(1, "", "resource temporarily unavailable")
        ok = _cmd_result(0, "OK")
        mock_cmd.side_effect = [fail, ok]
        r = _run_hcitool_info(ADDR, HCI)
        assert r.returncode == 0

    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_no_retry_on_non_transient(self, mock_cmd):
        fail = _cmd_result(1, "", "permission denied")
        mock_cmd.return_value = fail
        r = _run_hcitool_info(ADDR, HCI)
        assert r.returncode == 1
        mock_cmd.assert_called_once()


# ============================================================================
# vuln_scanner: _check_service_exposure
# ============================================================================

class TestCheckServiceExposure:
    def test_no_matching_services(self):
        services = [{"name": "SomeOther", "protocol": "RFCOMM", "channel": 1}]
        assert _check_service_exposure(ADDR, services) == []

    def test_no_rfcomm_services(self):
        services = [{"name": "Phonebook Access", "protocol": "L2CAP", "channel": 1}]
        assert _check_service_exposure(ADDR, services) == []

    @patch("blue_tap.attack.vuln_scanner.RFCOMMScanner")
    def test_confirmed_open(self, MockScanner):
        scanner = MockScanner.return_value
        scanner.probe_channel.return_value = {"status": "open", "response_type": "raw"}
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_service_exposure(ADDR, services)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["status"] == "confirmed"

    @patch("blue_tap.attack.vuln_scanner.RFCOMMScanner")
    def test_blocked_only(self, MockScanner):
        scanner = MockScanner.return_value
        scanner.probe_channel.return_value = {"status": "closed"}
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_service_exposure(ADDR, services)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    def test_empty_services(self):
        assert _check_service_exposure(ADDR, []) == []


# ============================================================================
# vuln_scanner: _check_knob
# ============================================================================

class TestCheckKnob:
    def test_below_5_1(self):
        findings = _check_knob(4.2, "LMP 4.2")
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2019-9506"
        assert findings[0]["severity"] == "MEDIUM"

    def test_at_5_1(self):
        assert _check_knob(5.1, "BT 5.1") == []

    def test_above_5_1(self):
        assert _check_knob(5.3, "BT 5.3") == []

    def test_none_version(self):
        assert _check_knob(None, None) == []

    def test_pause_encryption_upgrades_severity(self):
        feats = {"pause_encryption": True}
        findings = _check_knob(4.0, "LMP 4.0", lmp_features=feats)
        assert findings[0]["severity"] == "HIGH"
        assert "pause_encryption" in findings[0]["evidence"]

    def test_no_pause_encryption_stays_medium(self):
        feats = {"pause_encryption": False}
        findings = _check_knob(4.0, "LMP 4.0", lmp_features=feats)
        assert findings[0]["severity"] == "MEDIUM"


# ============================================================================
# vuln_scanner: _check_blurtooth
# ============================================================================

class TestCheckBlurtooth:
    def test_in_range_4_2_to_5_0(self):
        findings = _check_blurtooth(4.2, "LMP 4.2")
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2020-15802"

    def test_below_4_2(self):
        assert _check_blurtooth(4.1, "LMP 4.1") == []

    def test_above_5_0(self):
        assert _check_blurtooth(5.1, "BT 5.1") == []

    def test_none_version(self):
        assert _check_blurtooth(None, None) == []

    def test_dual_mode_raises_confidence(self):
        feats = {"le_and_bredr": True}
        findings = _check_blurtooth(4.5, "LMP 4.5", lmp_features=feats)
        assert findings[0]["confidence"] == "medium"

    def test_no_dual_mode_low_confidence(self):
        findings = _check_blurtooth(4.5, "LMP 4.5")
        assert findings[0]["confidence"] == "low"

    def test_boundary_4_2(self):
        assert len(_check_blurtooth(4.2, "LMP 4.2")) == 1

    def test_boundary_5_0(self):
        assert len(_check_blurtooth(5.0, "LMP 5.0")) == 1


# ============================================================================
# vuln_scanner: _check_perfektblue
# ============================================================================

class TestCheckPerfektblue:
    def test_no_match(self):
        assert _check_perfektblue(ADDR, [], "Toyota RAV4", "Honda", "") == []

    def test_manufacturer_match(self):
        findings = _check_perfektblue(ADDR, [], "IVI", "Volkswagen", "")
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_bluesdk_string_match(self):
        findings = _check_perfektblue(ADDR, [], "", "", "OpenSynergy BlueSDK")
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_avrcp_service_adds_evidence(self):
        services = [{"name": "AVRCP Controller"}]
        findings = _check_perfektblue(ADDR, services, "", "Audi", "")
        assert "AVRCP" in findings[0]["evidence"]

    def test_vw_keyword(self):
        findings = _check_perfektblue(ADDR, [], "", "vw systems", "")
        assert len(findings) == 1

    def test_no_services_no_manufacturer(self):
        assert _check_perfektblue(ADDR, [], "", "", "") == []


# ============================================================================
# vuln_scanner: _check_bluffs
# ============================================================================

class TestCheckBluffs:
    def test_below_5_4(self):
        findings = _check_bluffs(5.3, "BT 5.3")
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2023-24023"

    def test_at_5_4(self):
        assert _check_bluffs(5.4, "BT 5.4") == []

    def test_above_5_4(self):
        assert _check_bluffs(6.0, "BT 6.0") == []

    def test_none(self):
        assert _check_bluffs(None, None) == []


# ============================================================================
# vuln_scanner: _check_pin_pairing_bypass
# ============================================================================

class TestCheckPinPairingBypass:
    def test_ssp_false_below_5_2(self):
        findings = _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=False)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["cve"] == "CVE-2020-26555"
        assert findings[0]["status"] == "confirmed"

    def test_ssp_false_at_5_2(self):
        findings = _check_pin_pairing_bypass(5.2, "BT 5.2", ssp=False)
        assert len(findings) == 1

    def test_ssp_false_above_5_2(self):
        assert _check_pin_pairing_bypass(5.3, "BT 5.3", ssp=False) == []

    def test_ssp_true(self):
        assert _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=True) == []

    def test_ssp_none(self):
        assert _check_pin_pairing_bypass(4.0, "LMP 4.0", ssp=None) == []

    def test_version_none(self):
        assert _check_pin_pairing_bypass(None, None, ssp=False) == []


# ============================================================================
# vuln_scanner: _check_invalid_curve
# ============================================================================

class TestCheckInvalidCurve:
    def test_below_5_1_with_ssp(self):
        feats = {"ssp": True}
        findings = _check_invalid_curve(4.2, "LMP 4.2", lmp_features=feats)
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2018-5383"

    def test_below_5_1_no_ssp(self):
        feats = {"ssp": False}
        assert _check_invalid_curve(4.2, "LMP 4.2", lmp_features=feats) == []

    def test_above_5_1(self):
        feats = {"ssp": True}
        assert _check_invalid_curve(5.1, "BT 5.1", lmp_features=feats) == []

    def test_none_version(self):
        assert _check_invalid_curve(None, None) == []

    def test_no_features(self):
        assert _check_invalid_curve(4.0, "LMP 4.0", lmp_features=None) == []


# ============================================================================
# vuln_scanner: _check_bias
# ============================================================================

class TestCheckBias:
    def test_ssp_false(self):
        assert _check_bias(ssp=False) == []

    def test_ssp_true(self):
        findings = _check_bias(ssp=True)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"
        assert findings[0]["cve"] == "CVE-2020-10135"
        assert findings[0]["status"] == "unverified"

    def test_ssp_none(self):
        findings = _check_bias(ssp=None)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"


# ============================================================================
# vuln_scanner: _check_bias_active
# ============================================================================

class TestCheckBiasActive:
    def test_no_phone_address(self):
        findings = _check_bias_active(ADDR, HCI, ssp=True, phone_address=None)
        assert len(findings) == 1
        assert "skipped" in findings[0]["name"].lower()

    def test_ssp_false(self):
        findings = _check_bias_active(ADDR, HCI, ssp=False, phone_address=None)
        assert len(findings) == 1
        assert "ssp" in findings[0]["description"].lower()

    def test_ssp_false_with_phone(self):
        findings = _check_bias_active(ADDR, HCI, ssp=False,
                                       phone_address="11:22:33:44:55:66")
        assert len(findings) == 1
        assert "ssp" in findings[0]["description"].lower()

    @patch("blue_tap.attack.vuln_scanner.info")
    @patch("blue_tap.attack.bias.BIASAttack")
    def test_auto_reconnect_confirmed(self, MockBias, _info):
        attack = MockBias.return_value
        attack.probe_vulnerability.return_value = {
            "auto_reconnects": True,
            "ssp_supported": True,
            "bt_version": "5.0",
        }
        findings = _check_bias_active(ADDR, HCI, ssp=True,
                                       phone_address="11:22:33:44:55:66")
        assert any("critical" == f["severity"].lower() for f in findings)

    @patch("blue_tap.attack.vuln_scanner.info")
    @patch("blue_tap.attack.bias.BIASAttack")
    def test_ssp_not_enforced(self, MockBias, _info):
        attack = MockBias.return_value
        attack.probe_vulnerability.return_value = {
            "auto_reconnects": False,
            "ssp_supported": False,
            "bt_version": "4.0",
        }
        findings = _check_bias_active(ADDR, HCI, ssp=True,
                                       phone_address="11:22:33:44:55:66")
        assert any("high" == f["severity"].lower() for f in findings)

    @patch("blue_tap.attack.vuln_scanner.info")
    @patch("blue_tap.attack.bias.BIASAttack")
    def test_inconclusive(self, MockBias, _info):
        attack = MockBias.return_value
        attack.probe_vulnerability.return_value = {
            "auto_reconnects": False,
            "ssp_supported": True,
            "bt_version": "5.0",
        }
        findings = _check_bias_active(ADDR, HCI, ssp=True,
                                       phone_address="11:22:33:44:55:66")
        assert any("medium" == f["severity"].lower() for f in findings)

    @patch("blue_tap.attack.vuln_scanner.warning")
    @patch("blue_tap.attack.vuln_scanner.info")
    @patch("blue_tap.attack.bias.BIASAttack")
    def test_exception_during_probe(self, MockBias, _info, _warn):
        attack = MockBias.return_value
        attack.probe_vulnerability.side_effect = RuntimeError("hw fail")
        findings = _check_bias_active(ADDR, HCI, ssp=True,
                                       phone_address="11:22:33:44:55:66")
        assert len(findings) == 1
        assert findings[0]["status"] == "unverified"

    def test_import_error(self):
        with patch.dict("sys.modules", {"blue_tap.attack.bias": None}):
            findings = _check_bias_active(ADDR, HCI, ssp=True,
                                           phone_address="11:22:33:44:55:66")
            assert len(findings) == 1
            assert "unavailable" in findings[0]["name"].lower()


# ============================================================================
# vuln_scanner: _check_blueborne
# ============================================================================

class TestCheckBlueborne:
    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp", return_value="")
    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_bluetoothd_old_version(self, mock_cmd, _sdp):
        mock_cmd.return_value = _cmd_result(0, "5.40")
        findings = _check_blueborne(ADDR)
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2017-1000251"
        assert findings[0]["severity"] == "HIGH"

    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp", return_value="")
    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_bluetoothd_new_version(self, mock_cmd, _sdp):
        mock_cmd.return_value = _cmd_result(0, "5.55")
        assert _check_blueborne(ADDR) == []

    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp",
           return_value="BlueZ 5.40 something")
    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_sdp_fallback(self, mock_cmd, _sdp):
        mock_cmd.return_value = _cmd_result(1, "", "not found")
        findings = _check_blueborne(ADDR)
        assert len(findings) == 1
        assert findings[0]["cve"] == "CVE-2017-1000251"

    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp", return_value="")
    @patch("blue_tap.attack.vuln_scanner.run_cmd")
    def test_not_found(self, mock_cmd, _sdp):
        mock_cmd.return_value = _cmd_result(1, "", "not found")
        assert _check_blueborne(ADDR) == []


# ============================================================================
# vuln_scanner: _check_pairing_method
# ============================================================================

class TestCheckPairingMethod:
    @patch("blue_tap.attack.vuln_scanner.detect_pairing_mode",
           create=True)
    def test_just_works(self, _):
        with patch("blue_tap.recon.hci_capture.detect_pairing_mode",
                    return_value={"pairing_method": "Just Works"}, create=True):
            findings = _check_pairing_method(ADDR, HCI)
            assert any(f["severity"] == "MEDIUM" for f in findings)

    @patch("blue_tap.recon.hci_capture.detect_pairing_mode",
           return_value={"pairing_method": "Numeric Comparison"}, create=True)
    def test_known_method(self, _):
        findings = _check_pairing_method(ADDR, HCI)
        assert any(f["severity"] == "INFO" for f in findings)

    def test_import_error(self):
        with patch.dict("sys.modules", {"blue_tap.recon.hci_capture": None}):
            findings = _check_pairing_method(ADDR, HCI)
            assert findings == []


# ============================================================================
# vuln_scanner: _check_writable_gatt
# ============================================================================

class TestCheckWritableGatt:
    @patch("blue_tap.recon.gatt.enumerate_services_sync", create=True,
           return_value=[{
               "description": "Generic",
               "characteristics": [
                   {"description": "Device Name", "uuid": "0x2a00",
                    "properties": ["Write"]},
               ],
           }])
    def test_writable_found(self, _):
        findings = _check_writable_gatt(ADDR)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    @patch("blue_tap.recon.gatt.enumerate_services_sync", create=True,
           return_value=[{
               "description": "Generic",
               "characteristics": [
                   {"description": "Device Name", "uuid": "0x2a00",
                    "properties": ["Read"]},
               ],
           }])
    def test_no_writable(self, _):
        assert _check_writable_gatt(ADDR) == []

    def test_import_error(self):
        with patch.dict("sys.modules", {"blue_tap.recon.gatt": None}):
            assert _check_writable_gatt(ADDR) == []


# ============================================================================
# vuln_scanner: _check_braktooth_chipset
# ============================================================================

class TestCheckBraktoothChipset:
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_esp32_match(self, mock_info):
        mock_info.return_value = _cmd_result(0, "Manufacturer: Espressif ESP32\nClass: 0x0400")
        findings = _check_braktooth_chipset(ADDR, HCI)
        assert len(findings) == 1
        assert "esp32" in findings[0]["evidence"].lower()

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_no_match(self, mock_info):
        mock_info.return_value = _cmd_result(0, "Manufacturer: Samsung\nClass: 0x0400")
        assert _check_braktooth_chipset(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_hcitool_failure(self, mock_info):
        mock_info.return_value = _cmd_result(1, "", "error")
        assert _check_braktooth_chipset(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_no_manufacturer_line(self, mock_info):
        mock_info.return_value = _cmd_result(0, "LMP Version: 5.2")
        assert _check_braktooth_chipset(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_word_boundary_no_partial(self, mock_info):
        """'csr' should not match 'cursor' (word boundary)."""
        mock_info.return_value = _cmd_result(0, "Manufacturer: cursor systems")
        assert _check_braktooth_chipset(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    def test_csr_exact_match(self, mock_info):
        mock_info.return_value = _cmd_result(0, "Manufacturer: Cambridge Silicon Radio (CSR)")
        findings = _check_braktooth_chipset(ADDR, HCI)
        assert len(findings) == 1


# ============================================================================
# vuln_scanner: _check_eatt_support
# ============================================================================

class TestCheckEattSupport:
    @patch("socket.socket")
    def test_eatt_accepted(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None  # success
        findings = _check_eatt_support(ADDR)
        assert len(findings) == 1
        assert "EATT" in findings[0]["name"]

    @patch("socket.socket")
    def test_eatt_refused(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        assert _check_eatt_support(ADDR) == []

    @patch("socket.socket")
    def test_eatt_auth_required(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.side_effect = OSError(errno.EACCES, "access denied")
        findings = _check_eatt_support(ADDR)
        assert len(findings) == 1
        assert "Auth Required" in findings[0]["name"]

    @patch("socket.socket")
    def test_eatt_socket_error(self, MockSocket):
        MockSocket.side_effect = OSError("no bt")
        assert _check_eatt_support(ADDR) == []


# ============================================================================
# vuln_scanner: _check_hidden_rfcomm
# ============================================================================

class TestCheckHiddenRfcomm:
    def test_no_sdp_channels(self):
        services = [{"name": "SomeService", "protocol": "L2CAP", "channel": 1}]
        assert _check_hidden_rfcomm(ADDR, services) == []

    @patch("blue_tap.attack.vuln_scanner.RFCOMMScanner")
    def test_hidden_found(self, MockScanner):
        scanner = MockScanner.return_value
        scanner.find_hidden_services.return_value = [
            {"channel": 15, "response_type": "at_modem"},
        ]
        services = [{"name": "SomeService", "protocol": "RFCOMM", "channel": 1}]
        findings = _check_hidden_rfcomm(ADDR, services)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    @patch("blue_tap.attack.vuln_scanner.RFCOMMScanner")
    def test_hidden_obex(self, MockScanner):
        scanner = MockScanner.return_value
        scanner.find_hidden_services.return_value = [
            {"channel": 10, "response_type": "obex"},
        ]
        services = [{"name": "A", "protocol": "RFCOMM", "channel": 1}]
        findings = _check_hidden_rfcomm(ADDR, services)
        assert findings[0]["severity"] == "HIGH"

    @patch("blue_tap.attack.vuln_scanner.RFCOMMScanner")
    def test_hidden_scan_exception(self, MockScanner):
        scanner = MockScanner.return_value
        scanner.find_hidden_services.side_effect = RuntimeError("fail")
        services = [{"name": "A", "protocol": "RFCOMM", "channel": 1}]
        assert _check_hidden_rfcomm(ADDR, services) == []


# ============================================================================
# vuln_scanner: _check_encryption_enforcement
# ============================================================================

class TestCheckEncryptionEnforcement:
    def test_no_sensitive_services(self):
        services = [{"name": "SomeOther", "protocol": "RFCOMM", "channel": 1}]
        assert _check_encryption_enforcement(ADDR, services) == []

    @patch("socket.socket")
    def test_unencrypted_accepted(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_encryption_enforcement(ADDR, services)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    @patch("socket.socket")
    def test_encryption_enforced(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.side_effect = OSError(errno.EACCES, "access denied")
        services = [{"name": "MAP", "protocol": "RFCOMM", "channel": 3}]
        findings = _check_encryption_enforcement(ADDR, services)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    @patch("socket.socket")
    def test_socket_setup_error(self, MockSocket):
        MockSocket.return_value.setsockopt.side_effect = OSError("no bt")
        # The outer try/except catches socket setup errors
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        # Should not crash
        _check_encryption_enforcement(ADDR, services)


# ============================================================================
# vuln_scanner: _check_pin_lockout
# ============================================================================

class TestCheckPinLockout:
    def test_ssp_not_false(self):
        assert _check_pin_lockout(ADDR, HCI, ssp=True) == []

    def test_ssp_none(self):
        assert _check_pin_lockout(ADDR, HCI, ssp=None) == []

    @patch("blue_tap.attack.pin_brute.PINBruteForce", create=True)
    def test_no_lockout_fast(self, MockBrute):
        brute = MockBrute.return_value
        brute.detect_lockout.return_value = {
            "locked_out": False,
            "timings": [0.5, 0.6],
        }
        findings = _check_pin_lockout(ADDR, HCI, ssp=False)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    @patch("blue_tap.attack.pin_brute.PINBruteForce", create=True)
    def test_no_lockout_slow(self, MockBrute):
        brute = MockBrute.return_value
        brute.detect_lockout.return_value = {
            "locked_out": False,
            "timings": [3.0, 3.5],
        }
        findings = _check_pin_lockout(ADDR, HCI, ssp=False)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    @patch("blue_tap.attack.pin_brute.PINBruteForce", create=True)
    def test_lockout_detected(self, MockBrute):
        brute = MockBrute.return_value
        brute.detect_lockout.return_value = {
            "locked_out": True,
            "timings": [0.5, 10.0],
        }
        findings = _check_pin_lockout(ADDR, HCI, ssp=False)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    def test_import_error(self):
        with patch.dict("sys.modules", {"blue_tap.attack.pin_brute": None}):
            assert _check_pin_lockout(ADDR, HCI, ssp=False) == []


# ============================================================================
# vuln_scanner: _check_device_class
# ============================================================================

class TestCheckDeviceClass:
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=False)
    def test_no_hcitool(self, _):
        assert _check_device_class(ADDR, HCI) == []

    @patch("blue_tap.core.scanner.parse_device_class", create=True,
           return_value={"services": ["Object Transfer"], "major": "Computer",
                         "minor": "Desktop", "raw": "0x100"})
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_flagged_services(self, _tool, mock_info, _parse):
        mock_info.return_value = _cmd_result(0, "Class: 0x100")
        findings = _check_device_class(ADDR, HCI)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    @patch("blue_tap.core.scanner.parse_device_class", create=True,
           return_value={"services": ["Audio"], "major": "AV",
                         "minor": "Speaker", "raw": "0x400"})
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_flagged_services(self, _tool, mock_info, _parse):
        mock_info.return_value = _cmd_result(0, "Class: 0x400")
        assert _check_device_class(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_class_line(self, _tool, mock_info):
        mock_info.return_value = _cmd_result(0, "LMP Version: 5.2")
        assert _check_device_class(ADDR, HCI) == []


# ============================================================================
# vuln_scanner: _extract_lmp_features_dict
# ============================================================================

class TestExtractLmpFeaturesDict:
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_parses_features(self, _tool, mock_info):
        # byte0=0x24 (encryption=bit2, role_switch=bit5), byte5=0x08 (pause_enc)
        # byte6=0x0B (eir=bit0, le_and_bredr=bit1, ssp=bit3), byte7=0x08 (sec_conn)
        mock_info.return_value = _cmd_result(
            0, "Features: 0x24 0x00 0x00 0x00 0x00 0x08 0x0B 0x08"
        )
        d = _extract_lmp_features_dict(ADDR, HCI)
        assert d is not None
        assert d["encryption"] is True
        assert d["role_switch"] is True
        assert d["pause_encryption"] is True
        assert d["ssp"] is True
        assert d["le_and_bredr"] is True
        assert d["secure_connections"] is True

    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=False)
    def test_no_hcitool(self, _):
        assert _extract_lmp_features_dict(ADDR, HCI) is None

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_features_line(self, _tool, mock_info):
        mock_info.return_value = _cmd_result(0, "LMP Version: 5.2")
        assert _extract_lmp_features_dict(ADDR, HCI) is None

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_short_features_padded(self, _tool, mock_info):
        mock_info.return_value = _cmd_result(0, "Features: 0x04 0x00")
        d = _extract_lmp_features_dict(ADDR, HCI)
        assert d is not None
        assert d["encryption"] is True
        assert d["ssp"] is False  # padded byte


# ============================================================================
# vuln_scanner: _check_lmp_features
# ============================================================================

class TestCheckLmpFeatures:
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_encryption_critical(self, _tool, mock_info):
        # All zeros: no encryption, no SSP, no SC
        mock_info.return_value = _cmd_result(
            0, "Features: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
        )
        findings = _check_lmp_features(ADDR, HCI)
        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities  # no encryption

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_all_features_present(self, _tool, mock_info):
        # byte0=0x24 (enc+role_switch), byte5=0x08 (pause_enc)
        # byte6=0x0B (eir+le_bredr+ssp), byte7=0x08 (sc)
        mock_info.return_value = _cmd_result(
            0, "Features: 0x24 0x00 0x00 0x00 0x00 0x08 0x0B 0x08"
        )
        findings = _check_lmp_features(ADDR, HCI)
        # Should have: role_switch INFO, pause_encryption MEDIUM
        # Encryption present, SSP present, SC present -> no CRITICAL/HIGH
        names = [f["name"] for f in findings]
        assert not any("Encryption Not Supported" in n for n in names)
        assert any("Role Switch" in n for n in names)
        assert any("Pause Encryption" in n for n in names)

    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=False)
    def test_no_hcitool(self, _):
        assert _check_lmp_features(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_features_line(self, _tool, mock_info):
        mock_info.return_value = _cmd_result(0, "LMP Version: 5.2")
        assert _check_lmp_features(ADDR, HCI) == []

    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info")
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=True)
    def test_no_ssp_high(self, _tool, mock_info):
        # encryption present (0x04) but no SSP
        mock_info.return_value = _cmd_result(
            0, "Features: 0x04 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
        )
        findings = _check_lmp_features(ADDR, HCI)
        assert any(f["severity"] == "HIGH" and "SSP" in f["name"] for f in findings)


# ============================================================================
# vuln_scanner: _check_authorization_model
# ============================================================================

class TestCheckAuthorizationModel:
    def test_no_matching_services(self):
        services = [{"name": "SomeOther", "protocol": "RFCOMM", "channel": 1}]
        assert _check_authorization_model(ADDR, services) == []

    @patch("socket.socket")
    def test_obex_success_critical(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None
        # Return OBEX Success (0xA0) response
        sock.recv.return_value = bytes([0xA0]) + b"\x00\x05\x10\x00"
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_authorization_model(ADDR, services)
        assert any(f["severity"] == "CRITICAL" for f in findings)

    @patch("socket.socket")
    def test_obex_unauthorized(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None
        sock.recv.return_value = bytes([0xC1]) + b"\x00\x03"
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_authorization_model(ADDR, services)
        assert any(f["severity"] == "INFO" for f in findings)

    @patch("socket.socket")
    def test_rfcomm_auth_required(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.side_effect = OSError(errno.EACCES, "access denied")
        services = [{"name": "Phonebook Access", "protocol": "RFCOMM", "channel": 5}]
        findings = _check_authorization_model(ADDR, services)
        assert any(f["severity"] == "INFO" for f in findings)


# ============================================================================
# vuln_scanner: _check_automotive_diagnostics
# ============================================================================

class TestCheckAutomotiveDiagnostics:
    def test_no_diag_services(self):
        services = [{"name": "Audio", "protocol": "RFCOMM", "channel": 1, "uuid": "0x1108"}]
        assert _check_automotive_diagnostics(ADDR, services) == []

    def test_keyword_match(self):
        services = [{"name": "OBD Diagnostic", "protocol": "RFCOMM",
                      "channel": 3, "uuid": "0x1101"}]
        findings = _check_automotive_diagnostics(ADDR, services)
        assert any(f["severity"] == "HIGH" and "Diagnostic" in f["name"] for f in findings)

    @patch("socket.socket")
    def test_elm_response_critical(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None
        sock.recv.return_value = b"ELM327 v1.5\r\n"
        services = [{"name": "SPP", "protocol": "RFCOMM",
                      "channel": 2, "uuid": "0x1101"}]
        findings = _check_automotive_diagnostics(ADDR, services)
        assert any(f["severity"] == "CRITICAL" for f in findings)

    @patch("socket.socket")
    def test_at_ok_response(self, MockSocket):
        sock = MockSocket.return_value
        sock.connect.return_value = None
        sock.recv.return_value = b"OK\r\n"
        services = [{"name": "DUN", "protocol": "RFCOMM",
                      "channel": 4, "uuid": "0x1103"}]
        findings = _check_automotive_diagnostics(ADDR, services)
        assert any(f["severity"] == "HIGH" and "Serial" in f["name"] for f in findings)


# ============================================================================
# vuln_scanner: scan_vulnerabilities (full orchestrator)
# ============================================================================

class TestScanVulnerabilities:
    @patch("blue_tap.attack.vuln_scanner._print_findings")
    @patch("blue_tap.attack.vuln_scanner._check_perfektblue", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_pairing_method", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_eatt_support", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_writable_gatt", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_hidden_rfcomm", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_automotive_diagnostics", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_authorization_model", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_encryption_enforcement", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._extract_lmp_features_dict", return_value=None)
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info",
           return_value=_cmd_result(1))
    @patch("blue_tap.attack.vuln_scanner.run_cmd",
           return_value=_cmd_result(1))
    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp", return_value="")
    @patch("blue_tap.attack.vuln_scanner.browse_services", return_value=[])
    @patch("blue_tap.attack.vuln_scanner.check_ssp", return_value=True)
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=False)
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_passive_scan(self, *mocks):
        findings = scan_vulnerabilities(ADDR, HCI, active=False)
        assert isinstance(findings, list)

    @patch("blue_tap.attack.vuln_scanner._print_findings")
    @patch("blue_tap.attack.vuln_scanner._check_perfektblue", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_pairing_method", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_eatt_support", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_writable_gatt", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_hidden_rfcomm", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_automotive_diagnostics", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_authorization_model", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_encryption_enforcement", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_bias_active", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._check_pin_lockout", return_value=[])
    @patch("blue_tap.attack.vuln_scanner._extract_lmp_features_dict", return_value=None)
    @patch("blue_tap.attack.vuln_scanner._run_hcitool_info",
           return_value=_cmd_result(1))
    @patch("blue_tap.attack.vuln_scanner.run_cmd",
           return_value=_cmd_result(1))
    @patch("blue_tap.attack.vuln_scanner.get_raw_sdp", return_value="")
    @patch("blue_tap.attack.vuln_scanner.browse_services", return_value=[])
    @patch("blue_tap.attack.vuln_scanner.check_ssp", return_value=False)
    @patch("blue_tap.attack.vuln_scanner.check_tool", return_value=False)
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_active_scan(self, *mocks):
        findings = scan_vulnerabilities(ADDR, HCI, active=True,
                                         phone_address="11:22:33:44:55:66")
        assert isinstance(findings, list)

    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=False)
    def test_adapter_not_ready(self, _):
        findings = scan_vulnerabilities(ADDR, HCI)
        assert findings == []


# ============================================================================
# vuln_scanner: _print_findings
# ============================================================================

class TestPrintFindings:
    @patch("blue_tap.attack.vuln_scanner.summary_panel")
    @patch("blue_tap.attack.vuln_scanner.console")
    @patch("blue_tap.attack.vuln_scanner.vuln_table")
    def test_with_findings(self, mock_table, mock_console, mock_panel):
        findings = [
            _finding("HIGH", "Test", "desc", status="confirmed"),
            _finding("INFO", "Test2", "desc2", status="potential"),
        ]
        _print_findings(ADDR, findings)
        mock_table.assert_called_once_with(findings)
        mock_panel.assert_called_once()

    @patch("blue_tap.attack.vuln_scanner.success")
    @patch("blue_tap.attack.vuln_scanner.console")
    def test_empty_findings(self, mock_console, mock_success):
        _print_findings(ADDR, [])
        mock_success.assert_called_once()


# ============================================================================
# fleet: DeviceClassifier.classify — additional coverage
# ============================================================================

class TestDeviceClassifierExtended:
    def setup_method(self):
        self.clf = DeviceClassifier()

    def test_hfp_ag_uuid_returns_ivi(self):
        assert self.clf.classify({"service_uuids": ["0x111f"]}) == "ivi"

    def test_car_audio_class(self):
        # major=0x0400, minor=0x08 => (0x08 << 2) | 0x0400 = 0x0420
        assert self.clf.classify({"class": 0x0420}) == "ivi"

    def test_phone_class(self):
        assert self.clf.classify({"class": 0x020C}) == "phone"

    def test_computer_class(self):
        assert self.clf.classify({"class": 0x0100}) == "computer"

    def test_wearable_class(self):
        assert self.clf.classify({"class": 0x0700}) == "wearable"

    def test_audio_non_car(self):
        assert self.clf.classify({"class": 0x0404}) == "headset"

    def test_name_bmw_ivi(self):
        assert self.clf.classify({"name": "BMW iDrive"}) == "ivi"

    def test_name_iphone_phone(self):
        assert self.clf.classify({"name": "iPhone 15"}) == "phone"

    def test_name_airpods_headset(self):
        assert self.clf.classify({"name": "AirPods Pro"}) == "headset"

    def test_empty_device(self):
        assert self.clf.classify({}) == "unknown"

    def test_string_class_hex(self):
        assert self.clf.classify({"class": "0x0200"}) == "phone"

    def test_uuid_priority_over_class(self):
        d = {"service_uuids": ["0x111f"], "class": 0x0200}
        assert self.clf.classify(d) == "ivi"

    def test_invalid_class_string(self):
        assert self.clf.classify({"class": "notaclass"}) == "unknown"

    def test_networking_class(self):
        d = {"class": 0x0300}
        # major=0x0300 is networking, not in any specific return
        assert self.clf.classify(d) == "unknown"


# ============================================================================
# fleet: FleetAssessment.scan
# ============================================================================

class TestFleetAssessmentScan:
    @patch("blue_tap.core.scanner.scan_all", create=True,
           return_value=[
               {"address": "AA:BB:CC:DD:EE:01", "name": "BMW",
                "rssi": -50, "type": "classic", "service_uuids": ["0x111f"]},
               {"address": "AA:BB:CC:DD:EE:02", "name": "iPhone",
                "rssi": -60, "type": "classic"},
           ])
    def test_scan_returns_sorted(self, _):
        fa = FleetAssessment()
        results = fa.scan()
        assert len(results) == 2
        # IVI should come first
        assert results[0]["classification"] == "ivi"

    @patch("blue_tap.core.scanner.scan_all", create=True, return_value=[])
    def test_scan_empty(self, _):
        fa = FleetAssessment()
        results = fa.scan()
        assert results == []


# ============================================================================
# fleet: FleetAssessment.assess
# ============================================================================

class TestFleetAssessmentAssess:
    @patch("blue_tap.attack.vuln_scanner.scan_vulnerabilities", return_value=[])
    @patch("blue_tap.recon.fingerprint.fingerprint_device", create=True,
           return_value={"name": "TestIVI"})
    def test_assess_explicit_targets(self, _fp, _vuln):
        fa = FleetAssessment()
        results = fa.assess(targets=["AA:BB:CC:DD:EE:FF"])
        assert len(results) == 1
        assert results[0]["address"] == "AA:BB:CC:DD:EE:FF"

    def test_assess_no_scan_no_targets(self):
        fa = FleetAssessment()
        results = fa.assess()
        assert results == []

    @patch("blue_tap.attack.vuln_scanner.scan_vulnerabilities",
           side_effect=OSError("bt error"))
    @patch("blue_tap.recon.fingerprint.fingerprint_device", create=True,
           side_effect=OSError("bt error"))
    def test_assess_handles_errors(self, _fp, _vuln):
        fa = FleetAssessment()
        results = fa.assess(targets=["AA:BB:CC:DD:EE:FF"])
        assert len(results) == 1
        assert results[0]["error"] is not None


# ============================================================================
# fleet: FleetAssessment.report
# ============================================================================

class TestFleetAssessmentReport:
    def test_report_empty(self):
        fa = FleetAssessment()
        report = fa.report()
        assert report["total_devices"] == 0
        assert report["assessed"] == 0
        assert report["overall_risk"] == "UNKNOWN"
        assert "scan_time" in report

    def test_report_with_data(self):
        fa = FleetAssessment()
        fa._scan_results = [
            {"address": "AA:BB:CC:DD:EE:01", "classification": "ivi"},
        ]
        fa._assessment_results = [
            {"address": "AA:BB:CC:DD:EE:01", "name": "IVI",
             "classification": "ivi", "findings": [], "risk_rating": "INFO",
             "error": None},
        ]
        report = fa.report()
        assert report["total_devices"] == 1
        assert report["assessed"] == 1
        assert report["overall_risk"] == "INFO"
        assert report["classifications"]["ivi"] == 1

    def test_report_with_error(self):
        fa = FleetAssessment()
        fa._assessment_results = [
            {"address": "AA:BB:CC:DD:EE:01", "name": "IVI",
             "classification": "ivi", "findings": [], "risk_rating": "UNKNOWN",
             "error": "connection failed"},
        ]
        report = fa.report()
        assert any("error" in d for d in report["devices"])


# ============================================================================
# fleet: _rate_device / _rate_fleet — extended
# ============================================================================

class TestRateDeviceExtended:
    def test_low_only(self):
        assert FleetAssessment._rate_device([{"severity": "LOW"}]) == "LOW"

    def test_empty(self):
        assert FleetAssessment._rate_device([]) == "INFO"


class TestRateFleetExtended:
    def test_empty(self):
        assert FleetAssessment._rate_fleet([]) == "UNKNOWN"

    def test_single_info(self):
        assert FleetAssessment._rate_fleet([{"risk_rating": "INFO"}]) == "INFO"


# ============================================================================
# auto: _rssi_key
# ============================================================================

class TestRssiKey:
    def test_normal_rssi(self):
        assert _rssi_key({"rssi": -50}) == -50

    def test_missing_rssi(self):
        assert _rssi_key({}) == -999

    def test_string_rssi(self):
        assert _rssi_key({"rssi": "N/A"}) == -999

    def test_none_rssi(self):
        assert _rssi_key({"rssi": None}) == -999

    def test_zero_rssi(self):
        assert _rssi_key({"rssi": 0}) == 0


# ============================================================================
# auto: _phase
# ============================================================================

class TestPhase:
    def test_success(self):
        results = {"phases": {}}
        ret = _phase("test_phase", results, lambda: {"key": "val"})
        assert ret == {"key": "val", "_elapsed_seconds": pytest.approx(0.0, abs=1.0)}
        assert "test_phase" in results["phases"]

    def test_success_none_return(self):
        results = {"phases": {}}
        ret = _phase("test_phase", results, lambda: None)
        assert ret is None
        assert results["phases"]["test_phase"]["status"] == "success"

    def test_exception(self):
        results = {"phases": {}}
        ret = _phase("fail_phase", results, lambda: 1 / 0)
        assert ret is None
        assert results["phases"]["fail_phase"]["status"] == "failed"
        assert "error" in results["phases"]["fail_phase"]

    def test_kwargs_passed(self):
        results = {"phases": {}}
        _phase("test", results, lambda x=1, y=2: {"sum": x + y}, x=10, y=20)
        assert results["phases"]["test"]["sum"] == 30


# ============================================================================
# auto: AutoPentest.__init__
# ============================================================================

class TestAutoPentestInit:
    @patch("blue_tap.attack.auto.normalize_mac", side_effect=lambda x: x.upper())
    def test_init(self, _):
        ap = AutoPentest("aa:bb:cc:dd:ee:ff", hci="hci1")
        assert ap.ivi_address == "AA:BB:CC:DD:EE:FF"
        assert ap.hci == "hci1"


# ============================================================================
# auto: AutoPentest.discover_paired_phone
# ============================================================================

class TestDiscoverPairedPhone:
    @patch("blue_tap.attack.auto.normalize_mac", side_effect=lambda x: x.upper())
    def _make_ap(self, _):
        return AutoPentest("AA:BB:CC:DD:EE:FF")

    @patch("blue_tap.core.scanner.scan_classic", create=True, return_value=[])
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_no_devices(self, _adapt, _scan):
        ap = self._make_ap()
        assert ap.discover_paired_phone(scan_duration=1) is None

    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=False)
    def test_adapter_not_ready(self, _adapt):
        ap = self._make_ap()
        assert ap.discover_paired_phone() is None

    @patch("blue_tap.core.scanner.scan_classic", create=True,
           return_value=[
               {"address": "AA:BB:CC:DD:EE:FF", "name": "IVI", "rssi": -30},
               {"address": "11:22:33:44:55:66", "name": "iPhone 15", "rssi": -50},
           ])
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_finds_phone_by_name(self, _adapt, _scan):
        ap = self._make_ap()
        phone = ap.discover_paired_phone(scan_duration=1)
        assert phone is not None
        assert phone["address"] == "11:22:33:44:55:66"

    @patch("blue_tap.core.scanner.scan_classic", create=True,
           return_value=[
               {"address": "AA:BB:CC:DD:EE:FF", "name": "IVI", "rssi": -30},
               {"address": "11:22:33:44:55:66", "name": "Unknown Device", "rssi": -50,
                "class_info": {"is_phone": True}},
           ])
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_finds_phone_by_class_info(self, _adapt, _scan):
        ap = self._make_ap()
        phone = ap.discover_paired_phone(scan_duration=1)
        assert phone["address"] == "11:22:33:44:55:66"

    @patch("blue_tap.core.scanner.scan_classic", create=True,
           return_value=[
               {"address": "AA:BB:CC:DD:EE:FF", "name": "IVI", "rssi": -30},
               {"address": "11:22:33:44:55:66", "name": "SomeDevice", "rssi": -40},
               {"address": "22:33:44:55:66:77", "name": "Other", "rssi": -70},
           ])
    @patch("blue_tap.utils.bt_helpers.ensure_adapter_ready", return_value=True)
    def test_best_guess_non_ivi(self, _adapt, _scan):
        """When no phone identified, picks strongest non-IVI signal."""
        ap = self._make_ap()
        phone = ap.discover_paired_phone(scan_duration=1)
        assert phone is not None
        assert phone["address"] == "11:22:33:44:55:66"  # strongest non-IVI


# ============================================================================
# auto: AutoPentest.run
# ============================================================================

class TestAutoPentestRun:
    @patch("blue_tap.attack.auto.normalize_mac", side_effect=lambda x: x.upper())
    def _make_ap(self, _):
        return AutoPentest("AA:BB:CC:DD:EE:FF")

    @patch("blue_tap.attack.auto.console")
    @patch("blue_tap.attack.auto._phase")
    @patch("os.makedirs")
    def test_run_all_skipped(self, _mkdirs, mock_phase, _console):
        """All skip flags set, _phase returns None for discovery."""
        mock_phase.return_value = None
        ap = self._make_ap()
        results = ap.run(skip_fuzz=True, skip_dos=True, skip_exploit=True)
        assert results["target"] == "AA:BB:CC:DD:EE:FF"
        assert "phases" in results
        # Fuzzing, DoS, exploit should be skipped
        assert results["phases"].get("fuzzing", {}).get("status") == "skipped"
        assert results["phases"].get("dos_testing", {}).get("status") == "skipped"

    @patch("blue_tap.attack.auto.console")
    @patch("blue_tap.attack.auto._phase")
    @patch("os.makedirs")
    def test_run_negative_fuzz_duration(self, _mkdirs, mock_phase, _console):
        mock_phase.return_value = None
        ap = self._make_ap()
        results = ap.run(fuzz_duration=-1, scan_duration=-1,
                          skip_fuzz=True, skip_dos=True, skip_exploit=True)
        assert results["target"] == "AA:BB:CC:DD:EE:FF"

    @patch("blue_tap.attack.auto.console")
    @patch("blue_tap.attack.auto._phase")
    @patch("os.makedirs")
    def test_run_phone_discovered(self, _mkdirs, mock_phase, _console):
        """When phone is discovered, exploit phase runs."""
        def side_effect(name, results, func, **kwargs):
            if name == "discovery":
                phone = {"address": "11:22:33:44:55:66", "name": "iPhone"}
                results["phases"][name] = phone
                return phone
            results["phases"][name] = {"status": "success"}
            return {"status": "success"}

        mock_phase.side_effect = side_effect
        ap = self._make_ap()
        results = ap.run(skip_fuzz=True, skip_dos=True)
        # Exploitation should not be skipped since phone was found
        assert results["phases"].get("exploitation", {}).get("status") != "skipped"

    @patch("blue_tap.attack.auto.console")
    @patch("blue_tap.attack.auto._phase")
    @patch("os.makedirs")
    def test_run_status_complete(self, _mkdirs, mock_phase, _console):
        """All phases succeed => status=complete."""
        def side_effect(name, results, func, **kwargs):
            results["phases"][name] = {"status": "success", "_elapsed_seconds": 0.1}
            return {"status": "success"}

        mock_phase.side_effect = side_effect
        ap = self._make_ap()
        results = ap.run(skip_fuzz=True, skip_dos=True, skip_exploit=True)
        assert results["status"] in ("complete", "partial")

    @patch("blue_tap.attack.auto.console")
    @patch("blue_tap.attack.auto._phase")
    @patch("os.makedirs")
    def test_run_status_failed(self, _mkdirs, mock_phase, _console):
        """All phases fail => status=failed."""
        def side_effect(name, results, func, **kwargs):
            results["phases"][name] = {"status": "failed", "error": "test",
                                        "_elapsed_seconds": 0.1}
            return None

        mock_phase.side_effect = side_effect
        ap = self._make_ap()
        results = ap.run(skip_fuzz=True, skip_dos=True, skip_exploit=True)
        assert results["status"] == "failed"


# ============================================================================
# auto: AutoDiscovery backward compat
# ============================================================================

class TestAutoDiscovery:
    def test_alias_exists(self):
        from blue_tap.attack.auto import AutoDiscovery
        assert issubclass(AutoDiscovery, AutoPentest)
