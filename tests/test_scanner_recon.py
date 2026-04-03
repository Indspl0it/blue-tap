"""Comprehensive unit tests for scanner, recon, and fingerprint modules.

Covers every public and private function in:
  - blue_tap/core/scanner.py
  - blue_tap/recon/sdp.py
  - blue_tap/recon/gatt.py
  - blue_tap/recon/fingerprint.py
  - blue_tap/recon/rfcomm_scan.py
  - blue_tap/recon/l2cap_scan.py
  - blue_tap/recon/hci_capture.py
"""

import asyncio
import errno
import json
import os
import signal
import socket
import subprocess
import tempfile
import types
from unittest.mock import MagicMock, patch, mock_open

import pytest

# ---------------------------------------------------------------------------
# scanner.py
# ---------------------------------------------------------------------------
from blue_tap.core.scanner import (
    parse_device_class,
    estimate_distance,
    _lookup_ble_manufacturer,
    scan_classic,
    scan_ble_sync,
    scan_all,
    resolve_name,
)


# -- parse_device_class -----------------------------------------------------

class TestParseDeviceClass:
    """Tests for parse_device_class."""

    def test_phone_class(self):
        # Major=0x02 (Phone), Minor=0x03 (Smartphone)
        # CoD bits: major at bits 12-8, minor at bits 7-2
        # 0x02 << 8 = 0x200, 0x03 << 2 = 0x0c  => 0x20c
        # Add Audio service bit 21 => 0x20020c
        result = parse_device_class("0x20020c")
        assert result["major"] == "Phone"
        assert result["minor"] == "Smartphone"
        assert result["is_phone"] is True
        assert result["is_ivi"] is False
        assert "Audio" in result["services"]

    def test_car_audio_class(self):
        # Major=0x04 (AV), Minor=0x08 (Car Audio)
        # 0x04 << 8 = 0x400, 0x08 << 2 = 0x20 => 0x420
        result = parse_device_class("0x000420")
        assert result["major"] == "Audio/Video"
        assert result["minor"] == "Car Audio"
        assert result["is_ivi"] is True
        assert result["is_phone"] is False

    def test_computer_class(self):
        # Major=0x01 (Computer), Minor=0x03 (Laptop)
        # 0x01 << 8 = 0x100, 0x03 << 2 = 0x0c => 0x10c
        result = parse_device_class("0x00010c")
        assert result["major"] == "Computer"
        assert result["minor"] == "Laptop"

    def test_peripheral_class(self):
        # Major=0x05, Minor=0x01 (Joystick)
        result = parse_device_class("0x000504")
        assert result["major"] == "Peripheral"

    def test_wearable_class(self):
        # Major=0x07 (Wearable), Minor=0x01 (Wristwatch)
        # 0x07 << 8 = 0x700, 0x01 << 2 = 0x04 => 0x704
        result = parse_device_class("0x000704")
        assert result["major"] == "Wearable"
        assert result["minor"] == "Wristwatch"

    def test_invalid_string(self):
        result = parse_device_class("not-hex")
        assert result["major"] == "Unknown"
        assert result["minor"] == "Unknown"
        assert result["services"] == []
        assert result["is_phone"] is False

    def test_zero_value(self):
        result = parse_device_class("0x000000")
        assert result["major"] == "Miscellaneous"

    def test_non_hex_garbage(self):
        result = parse_device_class("zzz!!!")
        assert result["major"] == "Unknown"

    def test_without_prefix(self):
        # Should work without 0x prefix
        result = parse_device_class("20020c")
        assert result["major"] == "Phone"

    def test_service_classes(self):
        # Set Telephony (bit 22), Networking (bit 17)
        cod = (1 << 22) | (1 << 17) | 0x200
        result = parse_device_class(hex(cod))
        assert "Telephony" in result["services"]
        assert "Networking" in result["services"]


# -- estimate_distance -------------------------------------------------------

class TestEstimateDistance:

    def test_normal_rssi(self):
        d = estimate_distance(-70)
        assert isinstance(d, float)
        assert d > 0

    def test_close_rssi(self):
        d = estimate_distance(-40)
        assert d is not None
        assert d < estimate_distance(-80)

    def test_zero_rssi(self):
        assert estimate_distance(0) is None

    def test_positive_rssi(self):
        assert estimate_distance(10) is None

    def test_none_rssi(self):
        assert estimate_distance(None) is None

    def test_string_rssi(self):
        assert estimate_distance("abc") is None

    def test_string_numeric_rssi(self):
        # String that can be int-converted
        d = estimate_distance("-60")
        assert isinstance(d, float)
        assert d > 0

    def test_custom_tx_power(self):
        d1 = estimate_distance(-70, tx_power=-59)
        d2 = estimate_distance(-70, tx_power=-40)
        # Lower tx_power means closer reference, so d1 < d2
        assert d1 < d2


# -- _lookup_ble_manufacturer ------------------------------------------------

class TestLookupBleManufacturer:

    def test_apple(self):
        assert _lookup_ble_manufacturer(0x004C) == "Apple"

    def test_samsung(self):
        assert _lookup_ble_manufacturer(0x0075) == "Samsung"

    def test_tesla(self):
        assert _lookup_ble_manufacturer(0x02AC) == "Tesla"

    def test_unknown(self):
        result = _lookup_ble_manufacturer(0xFFFF)
        assert "Unknown" in result
        assert "0xFFFF" in result


# -- scan_classic ------------------------------------------------------------

class TestScanClassic:

    def _make_result(self, returncode=0, stdout="", stderr=""):
        r = subprocess.CompletedProcess([], returncode)
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_devices_found(self, monkeypatch):
        inq_stdout = (
            "Inquiring ...\n"
            "\t00:11:22:33:44:55\tclock offset: 0x1234\tclass: 0x20020c\n"
        )
        scan_stdout = (
            "Scanning ...\n"
            "\t00:11:22:33:44:55\tMyPhone\n"
        )
        call_count = {"n": 0}

        def mock_run_cmd(cmd, timeout=30):
            call_count["n"] += 1
            if "inq" in cmd:
                return self._make_result(stdout=inq_stdout)
            return self._make_result(stdout=scan_stdout)

        monkeypatch.setattr("blue_tap.core.scanner.run_cmd", mock_run_cmd)
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        devices = scan_classic(duration=5)
        assert len(devices) == 1
        assert devices[0]["name"] == "MyPhone"
        assert devices[0]["type"] == "Classic"

    def test_empty_result(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.core.scanner.run_cmd",
            lambda cmd, timeout=30: self._make_result(stdout="Inquiring ..."),
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )
        devices = scan_classic()
        assert devices == []

    def test_adapter_failure(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: False
        )
        assert scan_classic() == []

    def test_device_not_up(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        def mock_run(cmd, timeout=30):
            return self._make_result(returncode=1, stderr="Device is not up")

        monkeypatch.setattr("blue_tap.core.scanner.run_cmd", mock_run)
        assert scan_classic() == []


# -- scan_ble_sync -----------------------------------------------------------

class TestScanBleSync:

    def test_normal(self, monkeypatch):
        expected = [
            {
                "address": "AA:BB:CC:DD:EE:FF",
                "name": "BLEDevice",
                "rssi": -55,
                "type": "BLE",
                "distance_m": 1.0,
            }
        ]
        monkeypatch.setattr("asyncio.run", lambda coro: expected)
        result = scan_ble_sync(duration=5)
        assert len(result) == 1
        assert result[0]["address"] == "AA:BB:CC:DD:EE:FF"

    def test_empty(self, monkeypatch):
        monkeypatch.setattr("asyncio.run", lambda coro: [])
        result = scan_ble_sync()
        assert result == []


# -- scan_all ----------------------------------------------------------------

class TestScanAll:

    def test_merge_logic(self, monkeypatch):
        classic_devs = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "MyPhone",
             "rssi": "N/A", "type": "Classic"}
        ]
        ble_devs = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "MyPhone-BLE",
             "rssi": -55, "type": "BLE", "distance_m": 2.0,
             "service_uuids": ["1800"], "manufacturer_name": "Apple"},
            {"address": "11:22:33:44:55:66", "name": "OtherBLE",
             "rssi": -70, "type": "BLE"},
        ]
        monkeypatch.setattr("blue_tap.core.scanner.scan_classic",
                            lambda duration, hci: classic_devs)
        monkeypatch.setattr("blue_tap.core.scanner.scan_ble_sync",
                            lambda duration, adapter: ble_devs)

        result = scan_all()
        assert len(result) == 2
        # The merged device should be Classic+BLE
        merged = [d for d in result if d["address"] == "AA:BB:CC:DD:EE:FF"][0]
        assert merged["type"] == "Classic+BLE"
        assert merged["rssi"] == -55  # Updated from N/A
        assert merged["distance_m"] == 2.0
        assert merged["service_uuids"] == ["1800"]
        assert merged["manufacturer_name"] == "Apple"

    def test_dual_mode_name_fallback(self, monkeypatch):
        classic_devs = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "Unknown",
             "rssi": "N/A", "type": "Classic"}
        ]
        ble_devs = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "RealName",
             "rssi": -50, "type": "BLE"},
        ]
        monkeypatch.setattr("blue_tap.core.scanner.scan_classic",
                            lambda duration, hci: classic_devs)
        monkeypatch.setattr("blue_tap.core.scanner.scan_ble_sync",
                            lambda duration, adapter: ble_devs)

        result = scan_all()
        merged = result[0]
        assert merged["name"] == "RealName"


# -- resolve_name ------------------------------------------------------------

class TestResolveName:

    def test_success(self, monkeypatch):
        r = subprocess.CompletedProcess([], 0)
        r.stdout = "MyDevice\n"
        r.stderr = ""
        monkeypatch.setattr("blue_tap.core.scanner.run_cmd",
                            lambda cmd, timeout=10: r)
        assert resolve_name("AA:BB:CC:DD:EE:FF") == "MyDevice"

    def test_failure_returns_unknown(self, monkeypatch):
        r = subprocess.CompletedProcess([], 1)
        r.stdout = ""
        r.stderr = "error"
        monkeypatch.setattr("blue_tap.core.scanner.run_cmd",
                            lambda cmd, timeout=10: r)
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert resolve_name("AA:BB:CC:DD:EE:FF", retries=1) == "Unknown"

    def test_retry_then_success(self, monkeypatch):
        calls = {"n": 0}

        def mock_run(cmd, timeout=10):
            calls["n"] += 1
            r = subprocess.CompletedProcess([], 0 if calls["n"] > 1 else 1)
            r.stdout = "Found\n" if calls["n"] > 1 else ""
            r.stderr = ""
            return r

        monkeypatch.setattr("blue_tap.core.scanner.run_cmd", mock_run)
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert resolve_name("AA:BB:CC:DD:EE:FF", retries=2) == "Found"


# ---------------------------------------------------------------------------
# sdp.py
# ---------------------------------------------------------------------------
from blue_tap.recon.sdp import (
    parse_sdp_output,
    browse_services,
    find_service_channel,
    search_service,
    search_services_batch,
    check_ssp,
    get_device_bt_version,
    get_raw_sdp,
)


# -- parse_sdp_output -------------------------------------------------------

class TestParseSdpOutput:

    MULTI_SERVICE_OUTPUT = """\
Service Name: Hands-Free Audio Gateway
Service RecHandle: 0x10001
  "Hands-Free Audio Gateway" (0x111f)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 10
Profile Descriptor List:
  "Hands-Free" (0x111e)
  Version: 0x0108
Provider Name: Qualcomm

Service Name: Phonebook Access PSE
Service RecHandle: 0x10002
  "Phonebook Access - PSE" (0x112f)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 19
  "OBEX" (0x0008)
  "GOEP" (0x0034)
Profile Descriptor List:
  "Phonebook Access" (0x1130)
  Version: 0x0102
"""

    def test_multi_service(self):
        services = parse_sdp_output(self.MULTI_SERVICE_OUTPUT)
        assert len(services) == 2
        hfp = services[0]
        assert hfp["name"] == "Hands-Free Audio Gateway"
        assert hfp["protocol"] == "RFCOMM"
        assert hfp["channel"] == 10
        assert hfp["profile_version"] == "1.8"
        assert hfp["provider"] == "Qualcomm"

        pbap = services[1]
        assert pbap["name"] == "Phonebook Access PSE"
        assert pbap["channel"] == 19
        # OBEX/GOEP appear in class_ids when formatted with quotes in SDP output
        assert "OBEX" in pbap.get("class_ids", [])
        assert "GOEP" in pbap.get("class_ids", [])
        assert pbap["profile_version"] == "1.2"

    def test_l2cap_psm(self):
        output = """\
Service Name: SDP Server
Service RecHandle: 0x10000
Protocol Descriptor List:
  "L2CAP" (0x0100)
    PSM: 0x0001
"""
        services = parse_sdp_output(output)
        assert len(services) == 1
        assert services[0]["protocol"] == "L2CAP"
        assert services[0]["channel"] == 1

    def test_empty_output(self):
        assert parse_sdp_output("") == []

    def test_malformed_output(self):
        result = parse_sdp_output("random garbage\nno services here")
        assert result == []

    def test_version_parsing(self):
        output = """\
Service Name: Test
  "Test" (0x1101)
  Version: 0x0205
"""
        services = parse_sdp_output(output)
        assert services[0]["profile_version"] == "2.5"

    def test_version_invalid(self):
        output = """\
Service Name: Test
  "Test" (0x1101)
  Version: garbage
"""
        services = parse_sdp_output(output)
        assert services[0]["profile_version"] == "garbage"


# -- browse_services ---------------------------------------------------------

class TestBrowseServices:

    def _make_result(self, returncode=0, stdout="", stderr=""):
        r = subprocess.CompletedProcess([], returncode)
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_success(self, monkeypatch):
        output = 'Service Name: SPP\n  "SPP" (0x1101)\n'
        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd",
                            lambda cmd, timeout=30: self._make_result(stdout=output))
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        result = browse_services("AA:BB:CC:DD:EE:FF")
        assert len(result) == 1

    def test_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: False)
        assert browse_services("AA:BB:CC:DD:EE:FF") == []

    def test_retry_on_transient_failure(self, monkeypatch):
        calls = {"n": 0}

        def mock_run(cmd, timeout=30):
            calls["n"] += 1
            if calls["n"] == 1:
                return self._make_result(returncode=1, stderr="Connection reset")
            return self._make_result(stdout='Service Name: SPP\n  "SPP" (0x1101)\n')

        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd", mock_run)
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr("time.sleep", lambda s: None)
        result = browse_services("AA:BB:CC:DD:EE:FF")
        assert len(result) == 1
        assert calls["n"] == 2

    def test_permanent_failure(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=30: self._make_result(returncode=1, stderr="No route to host"),
        )
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        assert browse_services("AA:BB:CC:DD:EE:FF") == []


# -- find_service_channel ----------------------------------------------------

class TestFindServiceChannel:

    def test_pbap_found(self):
        services = [
            {"name": "Phonebook Access PSE", "profile": "PBAP",
             "channel": 19, "protocol": "RFCOMM", "class_ids": []},
        ]
        assert find_service_channel("addr", "PBAP", services) == 19

    def test_map_found(self):
        services = [
            {"name": "Message Access MAS", "profile": "MAP",
             "channel": 20, "protocol": "RFCOMM", "class_ids": ["MAP"]},
        ]
        assert find_service_channel("addr", "MAP", services) == 20

    def test_not_found(self):
        services = [
            {"name": "SPP", "profile": "SPP", "channel": 1,
             "protocol": "RFCOMM", "class_ids": []},
        ]
        assert find_service_channel("addr", "PBAP", services) is None

    def test_case_insensitive(self):
        services = [
            {"name": "phonebook access", "profile": "pbap",
             "channel": 19, "protocol": "RFCOMM", "class_ids": []},
        ]
        assert find_service_channel("addr", "Pbap", services) == 19

    def test_match_in_description(self):
        services = [
            {"name": "Unknown", "profile": "", "channel": 5,
             "protocol": "RFCOMM", "class_ids": [],
             "description": "PBAP server"},
        ]
        assert find_service_channel("addr", "PBAP", services) == 5


# -- search_service ----------------------------------------------------------

class TestSearchService:

    def test_success(self, monkeypatch):
        r = subprocess.CompletedProcess([], 0)
        r.stdout = 'Service Name: PBAP\n  "PBAP" (0x1130)\n'
        r.stderr = ""
        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd",
                            lambda cmd, timeout=15: r)
        result = search_service("addr", "0x1130")
        assert len(result) == 1

    def test_failure(self, monkeypatch):
        r = subprocess.CompletedProcess([], 1)
        r.stdout = ""
        r.stderr = "error"
        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd",
                            lambda cmd, timeout=15: r)
        assert search_service("addr", "0x1130") == []


# -- search_services_batch ---------------------------------------------------

class TestSearchServicesBatch:

    def test_batch_via_browse(self, monkeypatch):
        services = [
            {"name": "PBAP", "profile": "PBAP", "class_ids": ["PBAP"]},
            {"name": "MAP", "profile": "MAP", "class_ids": ["MAP"]},
        ]
        monkeypatch.setattr("blue_tap.recon.sdp.browse_services",
                            lambda addr: services)
        result = search_services_batch("addr", ["PBAP", "MAP", "SPP"])
        assert len(result["PBAP"]) == 1
        assert len(result["MAP"]) == 1
        assert len(result["SPP"]) == 0

    def test_fallback_path(self, monkeypatch):
        monkeypatch.setattr("blue_tap.recon.sdp.browse_services",
                            lambda addr: [])

        def mock_search(addr, uuid):
            if uuid == "0x1130":
                return [{"name": "PBAP"}]
            return []

        monkeypatch.setattr("blue_tap.recon.sdp.search_service", mock_search)
        result = search_services_batch("addr", ["0x1130", "0x1101"])
        assert len(result["0x1130"]) == 1
        assert len(result["0x1101"]) == 0


# -- check_ssp ---------------------------------------------------------------

class TestCheckSSP:

    def _make_result(self, returncode=0, stdout="", stderr=""):
        r = subprocess.CompletedProcess([], returncode)
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_ssp_present(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(
                stdout="Features: blah\nSecure Simple Pairing supported\n"
            ),
        )
        assert check_ssp("addr") is True

    def test_ssp_absent(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(
                stdout="Features: 0x00 0x00 0x00 0x00 0x00 0x00 0x00\n"
            ),
        )
        assert check_ssp("addr") is False

    def test_parse_failure(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(returncode=1, stderr="fail"),
        )
        assert check_ssp("addr") is None

    def test_ssp_via_features_bitmask(self, monkeypatch):
        # Byte 6 (index 12-13) with bit 3 set = 0x08
        # 14 hex chars = 7 bytes, byte6 = 0x08
        features = "00000000000008"
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(
                stdout=f"Features: 0x{features}\n"
            ),
        )
        assert check_ssp("addr") is True


# -- get_device_bt_version ---------------------------------------------------

class TestGetDeviceBtVersion:

    def _make_result(self, returncode=0, stdout="", stderr=""):
        r = subprocess.CompletedProcess([], returncode)
        r.stdout = stdout
        r.stderr = stderr
        return r

    def test_parse_lmp_version(self, monkeypatch):
        output = (
            "LMP Version: 5.2 (0x0b)\n"
            "LMP Subversion: 0x1234\n"
            "Manufacturer: Broadcom Corporation (15)\n"
            "Features: 0xbf 0xee 0x0d\n"
        )
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(stdout=output),
        )
        info = get_device_bt_version("addr")
        assert info["lmp_version"] == "5.2 (0x0b)"
        assert info["lmp_subversion"] == "0x1234"
        assert "Broadcom" in info["manufacturer"]

    def test_failure(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.recon.sdp.run_cmd",
            lambda cmd, timeout=10: self._make_result(returncode=1),
        )
        info = get_device_bt_version("addr")
        assert info["lmp_version"] is None


# -- get_raw_sdp -------------------------------------------------------------

class TestGetRawSdp:

    def test_success(self, monkeypatch):
        r = subprocess.CompletedProcess([], 0)
        r.stdout = "raw sdp data"
        r.stderr = ""
        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd",
                            lambda cmd, timeout=30: r)
        assert get_raw_sdp("addr") == "raw sdp data"

    def test_failure(self, monkeypatch):
        r = subprocess.CompletedProcess([], 1)
        r.stdout = ""
        r.stderr = "fail"
        monkeypatch.setattr("blue_tap.recon.sdp.run_cmd",
                            lambda cmd, timeout=30: r)
        assert get_raw_sdp("addr") == ""


# ---------------------------------------------------------------------------
# gatt.py
# ---------------------------------------------------------------------------
from blue_tap.recon.gatt import (
    lookup_uuid,
    classify_automotive_service,
    _infer_security,
    _decode_value,
    enumerate_services_sync,
    enumerate_services,
)


# -- lookup_uuid -------------------------------------------------------------

class TestLookupUuid:

    def test_full_uuid(self):
        assert lookup_uuid("00001800-0000-1000-8000-00805f9b34fb") == "Generic Access"

    def test_short_uuid_4digit(self):
        assert lookup_uuid("1800") == "Generic Access"

    def test_short_uuid_with_prefix(self):
        assert lookup_uuid("0x1800") == "Generic Access"

    def test_char_uuid(self):
        assert lookup_uuid("00002a19-0000-1000-8000-00805f9b34fb") == "Battery Level"

    def test_unknown(self):
        assert lookup_uuid("aaaabbbb-0000-1000-8000-00805f9b34fb") == ""


# -- classify_automotive_service ---------------------------------------------

class TestClassifyAutomotiveService:

    def test_tpms(self):
        assert classify_automotive_service("", "tire pressure monitor") == "tpms"

    def test_obd(self):
        assert classify_automotive_service("obd-uuid", "") == "obd"

    def test_keyless(self):
        assert classify_automotive_service("", "Digital key access") == "keyless"

    def test_no_match(self):
        assert classify_automotive_service("1800", "Generic Attribute") is None


# -- _infer_security ---------------------------------------------------------

class TestInferSecurity:

    def test_signed_write(self):
        assert _infer_security(["authenticated-signed-writes"]) == "signed_write"

    def test_likely_paired(self):
        assert _infer_security(["write"]) == "likely_paired"

    def test_open(self):
        assert _infer_security(["write-without-response"]) == "open"

    def test_read_only(self):
        assert _infer_security(["read"]) == "read_only"

    def test_notify_only(self):
        assert _infer_security(["notify"]) == "notify_only"

    def test_indicate_only(self):
        assert _infer_security(["indicate"]) == "notify_only"

    def test_unknown(self):
        assert _infer_security(["read", "write", "write-without-response"]) == "unknown"


# -- _decode_value -----------------------------------------------------------

class TestDecodeValue:

    def test_battery_level(self):
        data = bytes([85])
        uuid = "00002a19-0000-1000-8000-00805f9b34fb"
        assert _decode_value(data, uuid) == "85%"

    def test_pnp_id(self):
        # source=1 (BT SIG), VID=0x0001, PID=0x0002, Ver=3
        data = bytes([1, 1, 0, 2, 0, 3, 0])
        uuid = "00002a50-0000-1000-8000-00805f9b34fb"
        result = _decode_value(data, uuid)
        assert "BT SIG" in result
        assert "VID=0x0001" in result

    def test_alert_level(self):
        data = bytes([1])
        uuid = "00002a06-0000-1000-8000-00805f9b34fb"
        assert _decode_value(data, uuid) == "Mild Alert"

    def test_tx_power(self):
        data = bytes([0xF0])  # -16 dBm as signed
        uuid = "00002a07-0000-1000-8000-00805f9b34fb"
        result = _decode_value(data, uuid)
        assert "dBm" in result

    def test_appearance(self):
        data = (64).to_bytes(2, "little")  # Phone
        uuid = "00002a01-0000-1000-8000-00805f9b34fb"
        assert _decode_value(data, uuid) == "Phone"

    def test_connection_params(self):
        # min_int=6 (7.5ms), max_int=6, latency=0, timeout=100 (1000ms)
        data = (6).to_bytes(2, "little") + (6).to_bytes(2, "little") + \
               (0).to_bytes(2, "little") + (100).to_bytes(2, "little")
        uuid = "00002a04-0000-1000-8000-00805f9b34fb"
        result = _decode_value(data, uuid)
        assert "Interval" in result
        assert "Timeout" in result

    def test_system_id(self):
        data = bytes(8)
        uuid = "00002a23-0000-1000-8000-00805f9b34fb"
        result = _decode_value(data, uuid)
        assert "Manufacturer" in result
        assert "OUI" in result

    def test_string_uuid(self):
        data = b"TestDevice\x00"
        uuid = "00002a00-0000-1000-8000-00805f9b34fb"  # Device Name
        assert _decode_value(data, uuid) == "TestDevice"

    def test_default_hex(self):
        data = bytes([0x01, 0x02, 0x80])
        uuid = "0000ffff-0000-1000-8000-00805f9b34fb"
        result = _decode_value(data, uuid)
        # Non-printable bytes should become dots
        assert "." in result


# -- enumerate_services_sync -------------------------------------------------

class TestEnumerateServicesSync:

    def test_delegates_to_asyncio_run(self, monkeypatch):
        monkeypatch.setattr("asyncio.run", lambda coro: [{"uuid": "test"}])
        result = enumerate_services_sync("addr")
        assert result == [{"uuid": "test"}]


# -- enumerate_services (async) ----------------------------------------------

class TestEnumerateServices:

    def test_device_not_found(self, monkeypatch):
        """Test that enumerate_services_sync returns [] when device not found."""
        monkeypatch.setattr("asyncio.run", lambda coro: [])
        result = enumerate_services_sync("AA:BB:CC:DD:EE:FF")
        assert result == []

    def test_timeout_returns_empty(self, monkeypatch):
        """Test that timeout scenario returns empty list."""
        monkeypatch.setattr("asyncio.run", lambda coro: [])
        result = enumerate_services_sync("AA:BB:CC:DD:EE:FF")
        assert result == []

    @pytest.mark.asyncio
    async def test_async_device_not_found(self):
        """Test the async path with BleakClient raising 'not found'."""

        class FakeClient:
            def __init__(self, addr, timeout=15.0):
                pass

            async def __aenter__(self):
                raise Exception("Device not found")

            async def __aexit__(self, *args):
                pass

        fake_bleak = types.ModuleType("bleak")
        fake_bleak.BleakClient = FakeClient
        with patch.dict("sys.modules", {"bleak": fake_bleak}):
            # Re-import to pick up patched bleak
            import importlib
            import blue_tap.recon.gatt as gatt_mod
            result = await gatt_mod.enumerate_services("AA:BB:CC:DD:EE:FF")
            assert result == []

    @pytest.mark.asyncio
    async def test_async_timeout(self):
        """Test the async path with BleakClient raising timeout."""
        attempt_count = {"n": 0}

        class FakeClient:
            def __init__(self, addr, timeout=15.0):
                pass

            async def __aenter__(self):
                attempt_count["n"] += 1
                raise Exception("Connection timeout expired")

            async def __aexit__(self, *args):
                pass

        fake_bleak = types.ModuleType("bleak")
        fake_bleak.BleakClient = FakeClient
        with patch.dict("sys.modules", {"bleak": fake_bleak}):
            import blue_tap.recon.gatt as gatt_mod
            # Patch sleep to avoid real waits
            original_sleep = asyncio.sleep

            async def fast_sleep(s):
                pass

            with patch.object(asyncio, "sleep", fast_sleep):
                result = await gatt_mod.enumerate_services("AA:BB:CC:DD:EE:FF")
                assert result == []
                # Should have retried (max_retries=2, so 3 total attempts)
                assert attempt_count["n"] == 3


# ---------------------------------------------------------------------------
# fingerprint.py
# ---------------------------------------------------------------------------
from blue_tap.recon.fingerprint import (
    _detect_ivi_signals,
    _map_attack_surface,
    _check_vuln_hints,
    fingerprint_device,
)


# -- _detect_ivi_signals -----------------------------------------------------

class TestDetectIviSignals:

    def test_full_ivi(self):
        fp = {
            "name": "My Car Audio",
            "device_class_info": {"is_ivi": True},
            "profiles": [
                {"name": "Hands-Free Audio Gateway", "profile": "HFP AG"},
                {"name": "Audio Sink", "profile": "A2DP Sink"},
                {"name": "Phonebook Access PSE", "profile": "PBAP"},
                {"name": "Message Access MAS", "profile": "MAP"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is True
        assert len(fp["ivi_signals"]) >= 2
        assert fp["ivi_confidence"] > 0

    def test_partial_signals(self):
        fp = {
            "name": "Speaker",
            "device_class_info": {"is_ivi": False},
            "profiles": [
                {"name": "A2DP Sink", "profile": "A2DP Sink"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is False

    def test_no_signals(self):
        fp = {
            "name": "Headset",
            "device_class_info": {},
            "profiles": [],
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is False
        assert fp["ivi_signals"] == []

    def test_name_hints(self):
        fp = {
            "name": "uconnect system",
            "device_class_info": {"is_ivi": True},
            "profiles": [],
        }
        _detect_ivi_signals(fp)
        # Should get at least 2 signals (device class + name)
        assert fp["ivi_likely"] is True
        assert any("uconnect" in s for s in fp["ivi_signals"])

    def test_profile_density(self):
        fp = {
            "name": "Unknown",
            "device_class_info": {},
            "profiles": [
                {"name": "HFP AG", "profile": "HFP AG"},
                {"name": "A2DP Sink", "profile": "A2DP Sink"},
                {"name": "PBAP", "profile": "PBAP"},
                {"name": "MAP", "profile": "MAP"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
        }
        _detect_ivi_signals(fp)
        assert any("density" in s.lower() for s in fp["ivi_signals"])


# -- _map_attack_surface -----------------------------------------------------

class TestMapAttackSurface:

    def test_with_profile_ids(self):
        fp = {
            "profiles": [],
            "attack_surface": [],
            "_profile_ids": ["pbap", "map", "spp", "hfp_ag"],
        }
        _map_attack_surface(fp, [])
        surface_text = " ".join(fp["attack_surface"])
        assert "PBAP" in surface_text
        assert "MAP" in surface_text
        assert "SPP" in surface_text
        assert "HFP AG" in surface_text

    def test_with_raw_text_fallback(self):
        fp = {
            "profiles": [],
            "attack_surface": [],
            "_profile_ids": [],
        }
        services = [
            {"profile": "file transfer", "name": "FTP", "class_ids": ["FTP"]},
        ]
        _map_attack_surface(fp, services)
        assert any("FTP" in s for s in fp["attack_surface"])

    def test_rfcomm_channels(self):
        fp = {
            "profiles": [],
            "attack_surface": [],
            "_profile_ids": [],
        }
        services = [
            {"protocol": "RFCOMM", "channel": 1, "profile": "", "name": "", "class_ids": []},
            {"protocol": "RFCOMM", "channel": 5, "profile": "", "name": "", "class_ids": []},
        ]
        _map_attack_surface(fp, services)
        assert any("RFCOMM" in s and "2 open" in s for s in fp["attack_surface"])


# -- _check_vuln_hints -------------------------------------------------------

class TestCheckVulnHints:

    def test_bt_4_0(self):
        fp = {"lmp_version": "4.0", "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        names = " ".join(fp["vuln_hints"]).lower()
        assert "knob" in names
        assert "bias" in names
        assert "blueborne" in names
        assert "legacy pairing" in names
        assert "braktooth" in names
        assert "sweyntooth" in names

    def test_bt_5_2(self):
        fp = {"lmp_version": "5.2 (0x0b)", "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        names = " ".join(fp["vuln_hints"]).lower()
        assert "knob" not in names
        assert "bias" in names or "braktooth" in names  # 5.2 < 5.3 or 5.4

    def test_bt_5_4_plus(self):
        fp = {"lmp_version": "5.4", "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        # 5.4 should have no version-based hints
        assert len(fp["vuln_hints"]) == 0

    def test_with_spp(self):
        fp = {"lmp_version": "5.4", "vuln_hints": [], "_profile_ids": ["spp"]}
        _check_vuln_hints(fp)
        assert any("spp" in h.lower() for h in fp["vuln_hints"])

    def test_pbap_on_legacy(self):
        fp = {"lmp_version": "4.2", "vuln_hints": [], "_profile_ids": ["pbap"]}
        _check_vuln_hints(fp)
        assert any("pbap" in h.lower() for h in fp["vuln_hints"])

    def test_no_version(self):
        fp = {"lmp_version": None, "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        assert fp["vuln_hints"] == []


# -- fingerprint_device ------------------------------------------------------

class TestFingerprintDevice:

    def test_full_flow(self, monkeypatch):
        def mock_run_cmd(cmd, timeout=10):
            r = subprocess.CompletedProcess([], 0)
            r.stderr = ""
            if "name" in cmd:
                r.stdout = "TestCar\n"
            elif "info" in cmd:
                r.stdout = (
                    "Manufacturer: Broadcom\n"
                    "LMP Version: 5.0 (0x09)\n"
                    "HCI Version: 5.0\n"
                    "Class: 0x240408\n"
                )
            else:
                r.stdout = ""
            return r

        monkeypatch.setattr("blue_tap.recon.fingerprint.run_cmd", mock_run_cmd)
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr("blue_tap.recon.fingerprint.browse_services",
                            lambda addr: [
                                {"name": "HFP AG", "profile": "HFP AG",
                                 "channel": 10, "protocol": "RFCOMM",
                                 "profile_version": "1.7", "provider": None,
                                 "class_ids": []},
                                {"name": "A2DP Sink", "profile": "A2DP Sink",
                                 "channel": None, "protocol": "L2CAP",
                                 "profile_version": "1.3", "provider": None,
                                 "class_ids": []},
                            ])

        fp = fingerprint_device("AA:BB:CC:DD:EE:FF")
        assert fp["name"] == "TestCar"
        assert fp["manufacturer"] == "Broadcom"
        assert len(fp["profiles"]) == 2
        assert len(fp["attack_surface"]) > 0

    def test_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: False)
        fp = fingerprint_device("AA:BB:CC:DD:EE:FF")
        assert fp["error"] == "adapter not ready"


# ---------------------------------------------------------------------------
# rfcomm_scan.py
# ---------------------------------------------------------------------------
from blue_tap.recon.rfcomm_scan import RFCOMMScanner, _is_obex


# -- _is_obex ----------------------------------------------------------------

class TestIsObex:

    @pytest.mark.parametrize("byte,expected", [
        (0x80, True),   # Connect Response
        (0xA0, True),   # Success
        (0xA1, True),   # Created
        (0xC0, True),   # Bad Request
        (0xC1, True),   # Unauthorized
        (0xCB, True),   # Unsupported Media Type
        (0xD0, True),   # Internal Server Error
        (0xC3, True),   # OBEX response code
        (0xC4, True),   # OBEX response code
    ])
    def test_obex_codes(self, byte, expected):
        assert _is_obex(bytes([byte])) is expected

    def test_non_obex(self):
        assert _is_obex(bytes([0x41])) is False  # 'A'
        assert _is_obex(bytes([0x0D])) is False  # CR

    def test_empty(self):
        assert _is_obex(b"") is False

    def test_obex_connect_request(self):
        # 0x00 followed by at least 3 more bytes
        assert _is_obex(bytes([0x00, 0x10, 0x00, 0x07])) is True

    def test_obex_connect_request_too_short(self):
        assert _is_obex(bytes([0x00, 0x10])) is False


# -- RFCOMMScanner.probe_channel ---------------------------------------------

class TestRFCOMMProbeChannel:

    def test_open_channel(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"OK\r\n"
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "at_modem"

    def test_closed_channel(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "closed"

    def test_timeout(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ETIMEDOUT, "timed out")
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "timeout"

    def test_host_unreachable(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "unreachable")
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "host_unreachable"

    def test_obex_response(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = bytes([0xA0, 0x00, 0x03])
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "obex"

    def test_silent_open(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("timeout")
        mock_sock.sendall.return_value = None
        monkeypatch.setattr(
            "blue_tap.recon.rfcomm_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "silent_open"


# -- RFCOMMScanner.scan_all_channels ----------------------------------------

class TestRFCOMMScanAllChannels:

    def test_progress_and_results(self, monkeypatch):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda hci: "00:00:00:00:00:00"
        )

        def mock_probe_retry(ch, timeout, retries):
            if ch == 5:
                return {"channel": ch, "status": "open", "response_type": "silent_open"}
            return {"channel": ch, "status": "closed", "response_type": "refused"}

        monkeypatch.setattr(scanner, "_probe_with_retry", mock_probe_retry)
        results = scanner.scan_all_channels()
        assert len(results) == 30
        open_results = [r for r in results if r["status"] == "open"]
        assert len(open_results) == 1
        assert open_results[0]["channel"] == 5

    def test_unreachable_abort(self, monkeypatch):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda hci: "00:00:00:00:00:00"
        )

        def mock_probe_retry(ch, timeout, retries):
            return {"channel": ch, "status": "host_unreachable",
                    "response_type": "host_unreachable"}

        monkeypatch.setattr(scanner, "_probe_with_retry", mock_probe_retry)
        results = scanner.scan_all_channels(unreachable_threshold=3)
        # Should abort after 3 consecutive unreachable
        assert len(results) <= 4  # 3 unreachable + possibly 1 extra appended at break


# -- RFCOMMScanner._probe_with_retry ----------------------------------------

class TestProbeWithRetry:

    def test_retry_on_timeout(self, monkeypatch):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        calls = {"n": 0}

        def mock_probe(ch, timeout):
            calls["n"] += 1
            if calls["n"] < 3:
                return {"channel": ch, "status": "timeout", "response_type": "timeout"}
            return {"channel": ch, "status": "open", "response_type": "silent_open"}

        monkeypatch.setattr(scanner, "probe_channel", mock_probe)
        monkeypatch.setattr("time.sleep", lambda s: None)
        result = scanner._probe_with_retry(1, 2.0, max_retries=2)
        assert result["status"] == "open"
        assert calls["n"] == 3

    def test_no_retry_on_closed(self, monkeypatch):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        calls = {"n": 0}

        def mock_probe(ch, timeout):
            calls["n"] += 1
            return {"channel": ch, "status": "closed", "response_type": "refused"}

        monkeypatch.setattr(scanner, "probe_channel", mock_probe)
        result = scanner._probe_with_retry(1, 2.0, max_retries=2)
        assert result["status"] == "closed"
        assert calls["n"] == 1  # No retries


# -- RFCOMMScanner.find_hidden_services --------------------------------------

class TestFindHiddenServices:

    def test_hidden_channel_detection(self):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        scan_results = [
            {"channel": 1, "status": "open", "response_type": "at_modem"},
            {"channel": 5, "status": "open", "response_type": "silent_open"},
            {"channel": 10, "status": "open", "response_type": "obex"},
            {"channel": 15, "status": "closed", "response_type": "refused"},
        ]
        sdp_channels = [1, 10]
        hidden = scanner.find_hidden_services(sdp_channels, scan_results)
        assert len(hidden) == 1
        assert hidden[0]["channel"] == 5

    def test_no_hidden(self):
        scanner = RFCOMMScanner("AA:BB:CC:DD:EE:FF")
        scan_results = [
            {"channel": 1, "status": "open", "response_type": "at_modem"},
        ]
        hidden = scanner.find_hidden_services([1], scan_results)
        assert hidden == []


# ---------------------------------------------------------------------------
# l2cap_scan.py
# ---------------------------------------------------------------------------
from blue_tap.recon.l2cap_scan import L2CAPScanner


# -- L2CAPScanner._probe_psm ------------------------------------------------

class TestL2CAPProbePsm:

    def test_open(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "open"
        assert result["name"] == "SDP"

    def test_closed(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "closed"

    def test_auth_required(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EACCES, "access denied")
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(15, 1.0)
        assert result["status"] == "auth_required"

    def test_timeout(self, monkeypatch):
        mock_sock = MagicMock()
        exc = socket.timeout("timed out")
        mock_sock.connect.side_effect = exc
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "timeout"

    def test_host_unreachable(self, monkeypatch):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "unreachable")
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "host_unreachable"

    def test_dynamic_psm_name(self, monkeypatch):
        mock_sock = MagicMock()
        monkeypatch.setattr(
            "blue_tap.recon.l2cap_scan.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        result = scanner._probe_psm(4097, 1.0)
        assert "Dynamic" in result["name"]


# -- L2CAPScanner.scan_standard_psms ----------------------------------------

class TestScanStandardPsms:

    def test_quick_mode(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda hci: "00:00:00:00:00:00"
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        def mock_scan_list(psm_list, timeout):
            return [{"psm": p, "status": "closed", "name": ""} for p in psm_list]

        monkeypatch.setattr(scanner, "_scan_psm_list", mock_scan_list)
        results = scanner.scan_standard_psms()
        assert len(results) == len(scanner.PRIORITY_PSMS)

    def test_full_mode(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda hci: "00:00:00:00:00:00"
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        scanned_count = {"n": 0}

        def mock_scan_list(psm_list, timeout):
            scanned_count["n"] = len(psm_list)
            return []

        monkeypatch.setattr(scanner, "_scan_psm_list", mock_scan_list)
        scanner.scan_standard_psms(full=True)
        assert scanned_count["n"] == len(range(1, 4096, 2))

    def test_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: False
        )
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        assert scanner.scan_standard_psms() == []


# -- L2CAPScanner.scan_dynamic_psms -----------------------------------------

class TestScanDynamicPsms:

    def test_parallel_path(self, monkeypatch):
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        def mock_parallel(psm_list, timeout, workers):
            return [{"psm": p, "status": "closed", "name": ""} for p in psm_list[:3]]

        monkeypatch.setattr(scanner, "_scan_psm_list_parallel", mock_parallel)
        results = scanner.scan_dynamic_psms(start=4097, end=4103, workers=5)
        assert len(results) == 3

    def test_sequential_path(self, monkeypatch):
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        def mock_seq(psm_list, timeout):
            return [{"psm": p, "status": "closed", "name": ""} for p in psm_list]

        monkeypatch.setattr(scanner, "_scan_psm_list", mock_seq)
        results = scanner.scan_dynamic_psms(start=4097, end=4103, workers=1)
        assert len(results) > 0

    def test_even_start_adjusted(self, monkeypatch):
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")
        captured = {}

        def mock_seq(psm_list, timeout):
            captured["first"] = psm_list[0] if psm_list else None
            return []

        monkeypatch.setattr(scanner, "_scan_psm_list", mock_seq)
        scanner.scan_dynamic_psms(start=4098, end=4110, workers=1)
        assert captured["first"] == 4099  # adjusted to odd


# -- L2CAPScanner._scan_psm_list --------------------------------------------

class TestScanPsmList:

    def test_unreachable_threshold_abort(self, monkeypatch):
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        def mock_probe(psm, timeout):
            return {"psm": psm, "status": "host_unreachable",
                    "name": "test"}

        monkeypatch.setattr(scanner, "_probe_psm", mock_probe)
        results = scanner._scan_psm_list([1, 3, 5, 7, 9], 1.0,
                                          unreachable_threshold=3)
        # Should abort after 3 consecutive unreachable
        assert len(results) == 3

    def test_mixed_results(self, monkeypatch):
        scanner = L2CAPScanner("AA:BB:CC:DD:EE:FF")

        def mock_probe(psm, timeout):
            if psm == 1:
                return {"psm": psm, "status": "open", "name": "SDP"}
            if psm == 3:
                return {"psm": psm, "status": "auth_required", "name": "RFCOMM"}
            return {"psm": psm, "status": "closed", "name": "test"}

        monkeypatch.setattr(scanner, "_probe_psm", mock_probe)
        results = scanner._scan_psm_list([1, 3, 5], 1.0)
        assert len(results) == 2  # only open + auth_required are appended
        statuses = {r["status"] for r in results}
        assert "open" in statuses
        assert "auth_required" in statuses


# ---------------------------------------------------------------------------
# hci_capture.py
# ---------------------------------------------------------------------------
from blue_tap.recon.hci_capture import HCICapture, detect_pairing_mode


# -- HCICapture.start -------------------------------------------------------

class TestHCICaptureStart:

    def test_success(self, monkeypatch, tmp_path):
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda name: True)
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr("os.getpgid", lambda pid: 12345)
        monkeypatch.setattr(
            "subprocess.Popen", lambda *a, **kw: mock_proc
        )

        cap = HCICapture()
        outfile = str(tmp_path / "capture.log")
        result = cap.start(outfile)
        assert result is True
        assert cap.process is mock_proc
        assert os.path.exists(pid_file)

    def test_btmon_not_found(self, monkeypatch):
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda name: False)
        cap = HCICapture()
        assert cap.start() is False

    def test_stale_pid_cleanup(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        # Write a stale PID file
        with open(pid_file, "w") as f:
            json.dump({"pgid": 99999, "pid": 99999, "output_file": "old.log"}, f)

        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda name: True)

        # os.kill(99999, 0) should raise OSError (process dead)
        original_kill = os.kill

        def mock_kill(pid, sig):
            if pid == 99999 and sig == 0:
                raise OSError("No such process")
            return original_kill(pid, sig)

        monkeypatch.setattr("os.kill", mock_kill)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr("os.getpgid", lambda pid: 12345)
        monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: mock_proc)

        cap = HCICapture()
        outfile = str(tmp_path / "capture.log")
        assert cap.start(outfile) is True


# -- HCICapture.stop --------------------------------------------------------

class TestHCICaptureStop:

    def test_same_process_stop(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr("os.getpgid", lambda pid: 12345)
        monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

        cap = HCICapture()
        cap.process = mock_proc
        cap.output_file = "test.log"

        result = cap.stop()
        assert result == "test.log"
        assert cap.process is None

    def test_cross_invocation_stop(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)

        with open(pid_file, "w") as f:
            json.dump({"pgid": 5555, "pid": 5556, "output_file": "cross.log"}, f)

        killed = {"pgid": None}

        def mock_killpg(pgid, sig):
            killed["pgid"] = pgid
            if sig == 0:
                raise OSError("dead")

        monkeypatch.setattr("os.killpg", mock_killpg)
        monkeypatch.setattr("time.sleep", lambda s: None)

        cap = HCICapture()
        result = cap.stop()
        assert result == "cross.log"
        assert killed["pgid"] == 5555

    def test_no_process_to_stop(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        # No PID file exists
        cap = HCICapture()
        result = cap.stop()
        assert result == ""


# -- HCICapture.is_running --------------------------------------------------

class TestHCICaptureIsRunning:

    def test_running_via_process(self):
        cap = HCICapture()
        cap.process = MagicMock()
        cap.process.poll.return_value = None  # still running
        assert cap.is_running() is True

    def test_stopped_via_process(self):
        cap = HCICapture()
        cap.process = MagicMock()
        cap.process.poll.return_value = 0  # exited
        assert cap.is_running() is False

    def test_running_via_pid_file(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)

        with open(pid_file, "w") as f:
            json.dump({"pid": os.getpid()}, f)  # Use our own PID (always valid)

        cap = HCICapture()
        assert cap.is_running() is True

    def test_not_running_stale_pid(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)

        with open(pid_file, "w") as f:
            json.dump({"pid": 999999999}, f)  # Non-existent PID

        cap = HCICapture()
        assert cap.is_running() is False

    def test_no_pid_file(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        cap = HCICapture()
        assert cap.is_running() is False


# -- HCICapture.status -------------------------------------------------------

class TestHCICaptureStatus:

    def test_running_status(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)

        outfile = str(tmp_path / "capture.log")
        with open(outfile, "w") as f:
            f.write("some data")

        with open(pid_file, "w") as f:
            json.dump({"pid": os.getpid(), "output_file": outfile,
                       "started_at": "2025-01-01T00:00:00"}, f)

        cap = HCICapture()
        cap.process = MagicMock()
        cap.process.poll.return_value = None
        st = cap.status()
        assert st["running"] is True
        assert st["output_file"] == outfile
        assert st["size_bytes"] > 0
        assert st["started_at"] == "2025-01-01T00:00:00"

    def test_stopped_status(self, monkeypatch, tmp_path):
        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        # No PID file
        cap = HCICapture()
        st = cap.status()
        assert st["running"] is False
        assert st["output_file"] is None


# -- detect_pairing_mode -----------------------------------------------------

class TestDetectPairingMode:

    def test_full_flow(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "blue_tap.recon.hci_capture.check_tool", lambda name: True
        )

        pid_file = str(tmp_path / "btmon.pid")
        monkeypatch.setattr(HCICapture, "PID_FILE", pid_file)
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.poll.return_value = None
        monkeypatch.setattr("os.getpgid", lambda pid: 12345)

        fake_log = str(tmp_path / "hci_capture.log")

        popen_calls = {"n": 0}

        def mock_popen(*args, **kwargs):
            popen_calls["n"] += 1
            if popen_calls["n"] == 1:
                # btmon Popen - write fake output to the log file
                # (the real btmon would write to stdout which is redirected)
                with open(fake_log, "w") as f:
                    f.write("IO Capability: DisplayYesNo\n")
                    f.write("Authentication: SSP\n")
                    f.write("Pairing method: Numeric Comparison\n")
                return mock_proc
            ctl_proc = MagicMock()
            ctl_proc.stdin = MagicMock()
            ctl_proc.poll.return_value = None
            ctl_proc.wait.return_value = 0
            return ctl_proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)
        monkeypatch.setattr("time.sleep", lambda s: None)
        monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

        class FakeTempFile:
            def __init__(self, **kwargs):
                self.name = fake_log

            def close(self):
                pass

        monkeypatch.setattr(
            "blue_tap.recon.hci_capture.tempfile.NamedTemporaryFile",
            lambda **kw: FakeTempFile(**kw),
        )

        monkeypatch.setattr(
            "blue_tap.recon.hci_capture.run_cmd",
            lambda cmd, timeout=5: subprocess.CompletedProcess([], 0, "", ""),
        )

        result = detect_pairing_mode("AA:BB:CC:DD:EE:FF")
        assert result["ssp_supported"] is True
        assert result["io_capability"] == "DisplayYesNo"
        assert result["pairing_method"] == "Numeric Comparison"

    def test_capture_start_failure(self, monkeypatch, tmp_path):
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda name: False)

        import tempfile as tempfile_mod

        class FakeTempFile:
            def __init__(self, **kwargs):
                self.name = str(tmp_path / "hci_fail.log")
                with open(self.name, "w") as f:
                    pass

            def close(self):
                pass

        monkeypatch.setattr("tempfile.NamedTemporaryFile", lambda **kw: FakeTempFile(**kw))

        result = detect_pairing_mode("AA:BB:CC:DD:EE:FF")
        assert result["ssp_supported"] is None
        assert result["pairing_method"] == "Unknown"
