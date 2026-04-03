"""Tests for blue_tap/recon/ -- SDP, GATT, fingerprint, RFCOMM, L2CAP, HCI capture, sniffer.

Covers every function in all 7 recon modules.
"""

import asyncio
import errno
import json
import os
import re
import signal
import socket
import subprocess
import types
from unittest.mock import MagicMock, patch, mock_open, call

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(stdout="", stderr="", returncode=0):
    """Build a CompletedProcess stub."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ===========================================================================
# SDP
# ===========================================================================

class TestSDP:
    """Tests for blue_tap.recon.sdp."""

    # -- parse_sdp_output ---------------------------------------------------

    REALISTIC_SDP = """\
Service Name: Headset Audio Gateway
Service RecHandle: 0x10001
Service Class ID List:
  "Headset Audio Gateway" (0x1112)
  "Generic Audio" (0x1203)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 2
Profile Descriptor List:
  "Headset" (0x1108)
    Version: 0x0102

Service Name: PBAP Server
Service RecHandle: 0x10002
Service Class ID List:
  "PBAP PSE" (0x112f)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 19
  "OBEX" (0x0008)
Profile Descriptor List:
  "PBAP" (0x1130)
    Version: 0x0102
Provider Name: BlueZ
"""

    def test_parse_sdp_output_multi_service(self):
        from blue_tap.recon.sdp import parse_sdp_output

        services = parse_sdp_output(self.REALISTIC_SDP)
        assert len(services) == 2

        headset = services[0]
        assert headset["name"] == "Headset Audio Gateway"
        assert headset["protocol"] == "RFCOMM"
        assert headset["channel"] == 2
        assert headset["profile_version"] == "1.2"
        assert "Headset Audio Gateway" in headset["class_ids"]

        pbap = services[1]
        assert pbap["name"] == "PBAP Server"
        assert pbap["channel"] == 19
        # OBEX appears in class_ids when formatted as '"OBEX" (0x0008)'
        assert "OBEX" in pbap.get("class_ids", [])
        assert pbap.get("provider") == "BlueZ"

    def test_parse_sdp_output_empty(self):
        from blue_tap.recon.sdp import parse_sdp_output
        assert parse_sdp_output("") == []

    def test_parse_sdp_output_l2cap_psm(self):
        from blue_tap.recon.sdp import parse_sdp_output

        sdp = """\
Service Name: ATT
Service RecHandle: 0x10003
Protocol Descriptor List:
  "L2CAP" (0x0100)
    PSM: 0x001f
"""
        services = parse_sdp_output(sdp)
        assert len(services) == 1
        assert services[0]["protocol"] == "L2CAP"
        assert services[0]["channel"] == 0x001f

    def test_parse_sdp_output_version_parse_error(self):
        from blue_tap.recon.sdp import parse_sdp_output
        sdp = """\
Service Name: Foo
Service RecHandle: 0x10001
  Version: not_a_hex
"""
        services = parse_sdp_output(sdp)
        assert services[0].get("profile_version") == "not_a_hex"

    def test_parse_sdp_output_goep(self):
        from blue_tap.recon.sdp import parse_sdp_output
        sdp = """\
Service Name: MAP
Service RecHandle: 0x10001
  "MAP" (0x1134)
  GOEP layer
"""
        services = parse_sdp_output(sdp)
        assert "GOEP" in services[0].get("protocols", [])

    def test_parse_sdp_output_service_without_name(self):
        from blue_tap.recon.sdp import parse_sdp_output
        sdp = """\
Service RecHandle: 0x10001
  "SDP" (0x0001)
"""
        services = parse_sdp_output(sdp)
        assert len(services) == 1
        assert services[0]["name"] == "Unknown"

    def test_parse_sdp_output_rfcomm_inline(self):
        from blue_tap.recon.sdp import parse_sdp_output
        sdp = """\
Service Name: SPP
Service RecHandle: 0x10001
  RFCOMM Channel: 5
"""
        services = parse_sdp_output(sdp)
        assert services[0]["protocol"] == "RFCOMM"
        assert services[0]["channel"] == 5

    def test_parse_sdp_output_l2cap_psm_invalid(self):
        from blue_tap.recon.sdp import parse_sdp_output
        sdp = """\
Service Name: Foo
Service RecHandle: 0x10001
Protocol Descriptor List:
  "L2CAP" (0x0100)
    PSM: invalid
"""
        services = parse_sdp_output(sdp)
        # Invalid PSM stored as string
        assert services[0]["channel"] == "invalid"

    # -- browse_services ----------------------------------------------------

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_browse_services_success(self, mock_run, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        mock_run.return_value = _completed(
            stdout="Service Name: SPP\nService RecHandle: 0x10001\n"
        )
        from blue_tap.recon.sdp import browse_services
        services = browse_services("AA:BB:CC:DD:EE:FF")
        assert len(services) == 1
        assert services[0]["name"] == "SPP"

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_browse_services_retry_on_reset(self, mock_run, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        # First call fails with reset, second succeeds
        mock_run.side_effect = [
            _completed(returncode=1, stderr="connection reset"),
            _completed(stdout="Service Name: SPP\nService RecHandle: 0x10001\n"),
        ]
        from blue_tap.recon.sdp import browse_services
        with patch("time.sleep"):
            services = browse_services("AA:BB:CC:DD:EE:FF", retries=2)
        assert len(services) == 1

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_browse_services_permanent_failure(self, mock_run, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        mock_run.return_value = _completed(returncode=1, stderr="no route to host")
        from blue_tap.recon.sdp import browse_services
        result = browse_services("AA:BB:CC:DD:EE:FF")
        assert result == []

    def test_browse_services_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: False
        )
        from blue_tap.recon.sdp import browse_services
        assert browse_services("AA:BB:CC:DD:EE:FF") == []

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_browse_services_all_retries_exhausted(self, mock_run, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        mock_run.return_value = _completed(returncode=1, stderr="timeout waiting")
        from blue_tap.recon.sdp import browse_services
        with patch("time.sleep"):
            result = browse_services("AA:BB:CC:DD:EE:FF", retries=1)
        assert result == []

    # -- find_service_channel -----------------------------------------------

    def test_find_service_channel_found(self):
        from blue_tap.recon.sdp import find_service_channel

        services = [
            {"name": "Phonebook Access", "profile": "PBAP", "protocol": "RFCOMM",
             "channel": 19, "class_ids": ["PBAP PSE"]},
        ]
        ch = find_service_channel("AA:BB:CC:DD:EE:FF", "PBAP", services=services)
        assert ch == 19

    def test_find_service_channel_not_found(self):
        from blue_tap.recon.sdp import find_service_channel
        ch = find_service_channel("AA:BB:CC:DD:EE:FF", "NONEXISTENT", services=[])
        assert ch is None

    def test_find_service_channel_match_in_description(self):
        from blue_tap.recon.sdp import find_service_channel
        services = [
            {"name": "Unknown", "profile": "", "protocol": "RFCOMM",
             "channel": 5, "class_ids": [], "description": "serial port profile"},
        ]
        ch = find_service_channel("AA:BB:CC:DD:EE:FF", "serial", services=services)
        assert ch == 5

    def test_find_service_channel_l2cap_skipped(self):
        from blue_tap.recon.sdp import find_service_channel
        services = [
            {"name": "ATT", "profile": "att", "protocol": "L2CAP",
             "channel": 31, "class_ids": []},
        ]
        ch = find_service_channel("AA:BB:CC:DD:EE:FF", "att", services=services)
        assert ch is None  # Only RFCOMM channels returned

    @patch("blue_tap.recon.sdp.browse_services")
    def test_find_service_channel_browses_when_no_services(self, mock_browse):
        from blue_tap.recon.sdp import find_service_channel
        mock_browse.return_value = [
            {"name": "HFP", "profile": "HFP AG", "protocol": "RFCOMM",
             "channel": 7, "class_ids": []},
        ]
        ch = find_service_channel("AA:BB:CC:DD:EE:FF", "HFP")
        assert ch == 7
        mock_browse.assert_called_once()

    # -- search_service -----------------------------------------------------

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_search_service_success(self, mock_run):
        mock_run.return_value = _completed(
            stdout="Service Name: PBAP\nService RecHandle: 0x10001\n"
        )
        from blue_tap.recon.sdp import search_service
        result = search_service("AA:BB:CC:DD:EE:FF", "0x1130")
        assert len(result) == 1

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_search_service_failure(self, mock_run):
        mock_run.return_value = _completed(returncode=1)
        from blue_tap.recon.sdp import search_service
        assert search_service("AA:BB:CC:DD:EE:FF", "0x1130") == []

    # -- search_services_batch ----------------------------------------------

    @patch("blue_tap.recon.sdp.browse_services")
    def test_search_services_batch_via_browse(self, mock_browse):
        mock_browse.return_value = [
            {"name": "PBAP", "profile": "pbap", "class_ids": ["0x1130"]},
            {"name": "MAP", "profile": "map", "class_ids": ["0x1134"]},
        ]
        from blue_tap.recon.sdp import search_services_batch
        results = search_services_batch("AA:BB:CC:DD:EE:FF", ["0x1130", "0xFFFF"])
        assert len(results["0x1130"]) == 1
        assert len(results["0xFFFF"]) == 0

    @patch("blue_tap.recon.sdp.search_service")
    @patch("blue_tap.recon.sdp.browse_services", return_value=[])
    def test_search_services_batch_fallback(self, _browse, mock_search):
        mock_search.return_value = [{"name": "PBAP"}]
        from blue_tap.recon.sdp import search_services_batch
        results = search_services_batch("AA:BB:CC:DD:EE:FF", ["0x1130"])
        assert len(results["0x1130"]) == 1
        mock_search.assert_called_once()

    # -- check_ssp ----------------------------------------------------------

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_check_ssp_true_text(self, mock_run):
        mock_run.return_value = _completed(stdout="Features: Secure Simple Pairing\n")
        from blue_tap.recon.sdp import check_ssp
        assert check_ssp("AA:BB:CC:DD:EE:FF") is True

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_check_ssp_true_bitmask(self, mock_run):
        # byte6 = 0x08 means SSP bit set
        # 14 hex chars for 7 bytes: 00000000000008
        mock_run.return_value = _completed(
            stdout="Features: 0x00000000000008\n"
        )
        from blue_tap.recon.sdp import check_ssp
        assert check_ssp("AA:BB:CC:DD:EE:FF") is True

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_check_ssp_false(self, mock_run):
        mock_run.return_value = _completed(
            stdout="Features: 0x00000000000000\n"
        )
        from blue_tap.recon.sdp import check_ssp
        assert check_ssp("AA:BB:CC:DD:EE:FF") is False

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_check_ssp_command_failure(self, mock_run):
        mock_run.return_value = _completed(returncode=1)
        from blue_tap.recon.sdp import check_ssp
        assert check_ssp("AA:BB:CC:DD:EE:FF") is None

    # -- get_raw_sdp --------------------------------------------------------

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_get_raw_sdp_success(self, mock_run):
        mock_run.return_value = _completed(stdout="raw sdp data")
        from blue_tap.recon.sdp import get_raw_sdp
        assert get_raw_sdp("AA:BB:CC:DD:EE:FF") == "raw sdp data"

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_get_raw_sdp_failure(self, mock_run):
        mock_run.return_value = _completed(returncode=1)
        from blue_tap.recon.sdp import get_raw_sdp
        assert get_raw_sdp("AA:BB:CC:DD:EE:FF") == ""

    # -- get_device_bt_version ----------------------------------------------

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_get_device_bt_version_success(self, mock_run):
        mock_run.return_value = _completed(
            stdout=(
                "LMP Version: 5.2 (0x0b)\n"
                "LMP Subversion: 0x1234\n"
                "Manufacturer: Broadcom\n"
                "Features: 0xff\n"
            )
        )
        from blue_tap.recon.sdp import get_device_bt_version
        v = get_device_bt_version("AA:BB:CC:DD:EE:FF")
        assert v["lmp_version"] == "5.2 (0x0b)"
        assert v["lmp_subversion"] == "0x1234"
        assert v["manufacturer"] == "Broadcom"
        assert v["features_raw"] == "0xff"

    @patch("blue_tap.recon.sdp.run_cmd")
    def test_get_device_bt_version_failure(self, mock_run):
        mock_run.return_value = _completed(returncode=1)
        from blue_tap.recon.sdp import get_device_bt_version
        v = get_device_bt_version("AA:BB:CC:DD:EE:FF")
        assert v["lmp_version"] is None


# ===========================================================================
# GATT
# ===========================================================================

class TestGATT:
    """Tests for blue_tap.recon.gatt."""

    # -- lookup_uuid --------------------------------------------------------

    def test_lookup_uuid_service(self):
        from blue_tap.recon.gatt import lookup_uuid
        assert lookup_uuid("00001800-0000-1000-8000-00805f9b34fb") == "Generic Access"

    def test_lookup_uuid_characteristic(self):
        from blue_tap.recon.gatt import lookup_uuid
        assert lookup_uuid("00002a00-0000-1000-8000-00805f9b34fb") == "Device Name"

    def test_lookup_uuid_short_format(self):
        from blue_tap.recon.gatt import lookup_uuid
        assert lookup_uuid("1800") == "Generic Access"

    def test_lookup_uuid_short_with_prefix(self):
        from blue_tap.recon.gatt import lookup_uuid
        assert lookup_uuid("0x1800") == "Generic Access"

    def test_lookup_uuid_unknown(self):
        from blue_tap.recon.gatt import lookup_uuid
        assert lookup_uuid("deadbeef-0000-1000-8000-00805f9b34fb") == ""

    # -- classify_automotive_service ----------------------------------------

    def test_classify_automotive_tpms(self):
        from blue_tap.recon.gatt import classify_automotive_service
        assert classify_automotive_service("1234", "tire pressure") == "tpms"

    def test_classify_automotive_obd(self):
        from blue_tap.recon.gatt import classify_automotive_service
        assert classify_automotive_service("1234", "OBD diagnostic") == "obd"

    def test_classify_automotive_keyless(self):
        from blue_tap.recon.gatt import classify_automotive_service
        assert classify_automotive_service("1234", "digital key lock") == "keyless"

    def test_classify_automotive_ble_key(self):
        from blue_tap.recon.gatt import classify_automotive_service
        # "key" in "phone as key" and "digital key" matches keyless first
        # because keyless comes before ble_phone_as_key in dict ordering
        assert classify_automotive_service("1234", "phone as key") == "keyless"
        assert classify_automotive_service("1234", "digital key service") == "keyless"
        # "ccc" is unique to ble_phone_as_key (no overlap with keyless keywords)
        assert classify_automotive_service("1234", "ccc standard") == "ble_phone_as_key"

    def test_classify_automotive_none(self):
        from blue_tap.recon.gatt import classify_automotive_service
        assert classify_automotive_service("1234", "generic service") is None

    # -- _infer_security ----------------------------------------------------

    def test_infer_security_signed_write(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["authenticated-signed-writes"]) == "signed_write"

    def test_infer_security_likely_paired(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["write"]) == "likely_paired"

    def test_infer_security_open(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["write-without-response"]) == "open"

    def test_infer_security_read_only(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["read"]) == "read_only"

    def test_infer_security_notify_only(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["notify"]) == "notify_only"

    def test_infer_security_indicate_only(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["indicate"]) == "notify_only"

    def test_infer_security_unknown(self):
        from blue_tap.recon.gatt import _infer_security
        assert _infer_security(["read", "write", "write-without-response"]) == "unknown"

    # -- _decode_value — every UUID handler ---------------------------------

    def test_decode_value_device_name(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a00-0000-1000-8000-00805f9b34fb"
        assert _decode_value(b"MyDevice\x00", uuid) == "MyDevice"

    def test_decode_value_model_number(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a24-0000-1000-8000-00805f9b34fb"
        assert _decode_value(b"Model-X", uuid) == "Model-X"

    def test_decode_value_battery_level(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a19-0000-1000-8000-00805f9b34fb"
        assert _decode_value(bytes([85]), uuid) == "85%"

    def test_decode_value_pnp_id_bt_sig(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a50-0000-1000-8000-00805f9b34fb"
        data = bytes([1]) + (0x004C).to_bytes(2, "little") + (0x0001).to_bytes(2, "little") + (0x0100).to_bytes(2, "little")
        result = _decode_value(data, uuid)
        assert "BT SIG" in result
        assert "004c" in result.lower()

    def test_decode_value_pnp_id_usb(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a50-0000-1000-8000-00805f9b34fb"
        data = bytes([2]) + b"\x00" * 6
        result = _decode_value(data, uuid)
        assert "USB" in result

    def test_decode_value_alert_level(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a06-0000-1000-8000-00805f9b34fb"
        assert _decode_value(bytes([0]), uuid) == "No Alert"
        assert _decode_value(bytes([1]), uuid) == "Mild Alert"
        assert _decode_value(bytes([2]), uuid) == "High Alert"
        assert "Unknown" in _decode_value(bytes([99]), uuid)

    def test_decode_value_tx_power(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a07-0000-1000-8000-00805f9b34fb"
        # -10 dBm in signed int8
        data = (-10).to_bytes(1, "little", signed=True)
        assert _decode_value(data, uuid) == "-10 dBm"

    def test_decode_value_appearance(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a01-0000-1000-8000-00805f9b34fb"
        data = (64).to_bytes(2, "little")
        assert _decode_value(data, uuid) == "Phone"

    def test_decode_value_appearance_unknown(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a01-0000-1000-8000-00805f9b34fb"
        data = (9999).to_bytes(2, "little")
        assert "Category" in _decode_value(data, uuid)

    def test_decode_value_connection_params(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a04-0000-1000-8000-00805f9b34fb"
        data = (6).to_bytes(2, "little") + (12).to_bytes(2, "little") + \
               (0).to_bytes(2, "little") + (100).to_bytes(2, "little")
        result = _decode_value(data, uuid)
        assert "Interval" in result
        assert "Latency" in result
        assert "Timeout" in result

    def test_decode_value_system_id(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a23-0000-1000-8000-00805f9b34fb"
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = _decode_value(data, uuid)
        assert "Manufacturer" in result
        assert "OUI" in result

    def test_decode_value_fallback_printable(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00009999-0000-1000-8000-00805f9b34fb"
        assert _decode_value(b"hello", uuid) == "hello"

    def test_decode_value_fallback_non_printable(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00009999-0000-1000-8000-00805f9b34fb"
        result = _decode_value(bytes([0x01, 0x02, 0x41]), uuid)
        assert result == "..A"

    def test_decode_value_string_with_bad_utf8(self):
        from blue_tap.recon.gatt import _decode_value
        uuid = "00002a24-0000-1000-8000-00805f9b34fb"
        # Invalid UTF-8 falls through to default handler
        result = _decode_value(b"\xff\xfe", uuid)
        assert isinstance(result, str)

    # -- enumerate_services (async) -----------------------------------------

    @pytest.mark.asyncio
    async def test_enumerate_services_bleak_not_installed(self, monkeypatch):
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "bleak":
                raise ImportError("no bleak")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        from blue_tap.recon.gatt import enumerate_services
        result = await enumerate_services("AA:BB:CC:DD:EE:FF")
        assert result == []

    @pytest.mark.asyncio
    async def test_enumerate_services_not_found(self):
        mock_client_cls = MagicMock()
        mock_client_cls.return_value.__aenter__ = MagicMock(
            side_effect=Exception("Device not found")
        )
        mock_client_cls.return_value.__aexit__ = MagicMock(return_value=False)
        with patch.dict("sys.modules", {"bleak": MagicMock(BleakClient=mock_client_cls)}):
            from blue_tap.recon import gatt
            # Force reimport to pick up mock
            import importlib
            importlib.reload(gatt)
            result = await gatt.enumerate_services("AA:BB:CC:DD:EE:FF")
            assert result == []

    # -- read_characteristic ------------------------------------------------

    @pytest.mark.asyncio
    async def test_read_characteristic_bleak_missing(self, monkeypatch):
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "bleak":
                raise ImportError
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        from blue_tap.recon.gatt import read_characteristic
        result = await read_characteristic("AA:BB:CC:DD:EE:FF", "2a00")
        assert result is None

    # -- write_characteristic -----------------------------------------------

    @pytest.mark.asyncio
    async def test_write_characteristic_bleak_missing(self, monkeypatch):
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "bleak":
                raise ImportError
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        from blue_tap.recon.gatt import write_characteristic
        result = await write_characteristic("AA:BB:CC:DD:EE:FF", "2a00", b"\x01")
        assert result is False

    # -- subscribe_notifications --------------------------------------------

    @pytest.mark.asyncio
    async def test_subscribe_notifications_bleak_missing(self, monkeypatch):
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "bleak":
                raise ImportError
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        from blue_tap.recon.gatt import subscribe_notifications
        result = await subscribe_notifications("AA:BB:CC:DD:EE:FF", "2a00")
        assert result == []


# ===========================================================================
# Fingerprint
# ===========================================================================

class TestFingerprint:
    """Tests for blue_tap.recon.fingerprint."""

    # -- _parse_hcitool_info ------------------------------------------------

    def test_parse_hcitool_info_full(self):
        from blue_tap.recon.fingerprint import _parse_hcitool_info
        fp = {"manufacturer": "Unknown", "lmp_version": None,
              "bt_version": None, "device_class": None}
        output = (
            "Manufacturer: Broadcom Corporation\n"
            "LMP Version: 5.2 (0x0b)\n"
            "HCI Version: 5.2 (0x0b)\n"
            "Class: 0x200408\n"
        )
        _parse_hcitool_info(output, fp)
        assert fp["manufacturer"] == "Broadcom Corporation"
        assert fp["lmp_version"] == "5.2 (0x0b)"
        assert fp["bt_version"] == "5.2 (0x0b)"
        assert fp["device_class"] == "0x200408"

    def test_parse_hcitool_info_device_class(self):
        from blue_tap.recon.fingerprint import _parse_hcitool_info
        fp = {"manufacturer": "Unknown", "lmp_version": None,
              "bt_version": None, "device_class": None}
        _parse_hcitool_info("Device Class: 0x240404\n", fp)
        assert fp["device_class"] == "0x240404"

    # -- _detect_ivi_signals ------------------------------------------------

    def test_detect_ivi_signals_full_ivi(self):
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {
            "name": "My Car",
            "profiles": [
                {"name": "Hands-Free Audio Gateway", "profile": "HFP AG"},
                {"name": "Audio Sink", "profile": "A2DP Sink"},
                {"name": "PBAP Server", "profile": "PBAP PSE"},
                {"name": "MAP Server", "profile": "MAP MAS"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
            "device_class_info": {"is_ivi": True},
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is True
        assert fp["is_ivi"] is True
        assert len(fp["ivi_signals"]) >= 2
        assert fp["ivi_confidence"] > 0.0

    def test_detect_ivi_signals_headphones_not_ivi(self):
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {
            "name": "Beats Solo",
            "profiles": [
                {"name": "A2DP", "profile": "A2DP Source"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
            "device_class_info": {},
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is False
        assert len(fp["ivi_signals"]) < 2

    def test_detect_ivi_signals_name_hint(self):
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {
            "name": "Ford SYNC 4",
            "profiles": [
                {"name": "HFP AG", "profile": "HFP AG"},
                {"name": "A2DP Sink", "profile": "A2DP Sink"},
            ],
            "device_class_info": {},
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is True
        assert any("sync" in s.lower() for s in fp["ivi_signals"])

    def test_detect_ivi_signals_profile_density(self):
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {
            "name": "Unknown",
            "profiles": [
                {"name": "HFP AG", "profile": "HFP AG"},
                {"name": "A2DP Sink", "profile": "A2DP Sink"},
                {"name": "PBAP", "profile": "PBAP"},
                {"name": "MAP", "profile": "MAP MAS"},
                {"name": "AVRCP", "profile": "AVRCP"},
            ],
            "device_class_info": {},
        }
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is True
        assert any("density" in s.lower() for s in fp["ivi_signals"])

    def test_detect_ivi_signals_no_profiles(self):
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {"name": "", "profiles": [], "device_class_info": {}}
        _detect_ivi_signals(fp)
        assert fp["ivi_likely"] is False
        assert fp["ivi_confidence"] == 0.0

    def test_detect_ivi_signals_profile_normalization(self):
        """Test that various profile name formats are normalized correctly."""
        from blue_tap.recon.fingerprint import _detect_ivi_signals
        fp = {
            "name": "",
            "profiles": [
                {"name": "Handsfree AG", "profile": ""},
                {"name": "Audio Sink A2DP", "profile": ""},
                {"name": "Phone Book Access", "profile": "phonebook"},
            ],
            "device_class_info": {},
        }
        _detect_ivi_signals(fp)
        assert "hfp_ag" in fp["_profile_ids"]
        assert "a2dp_sink" in fp["_profile_ids"]
        assert "pbap" in fp["_profile_ids"]

    # -- _map_attack_surface ------------------------------------------------

    def test_map_attack_surface_with_profiles(self):
        from blue_tap.recon.fingerprint import _map_attack_surface
        fp = {
            "profiles": [],
            "attack_surface": [],
            "_profile_ids": ["pbap", "map", "hfp_ag", "spp"],
        }
        _map_attack_surface(fp, [])
        assert any("PBAP" in s for s in fp["attack_surface"])
        assert any("MAP" in s for s in fp["attack_surface"])
        assert any("SPP" in s for s in fp["attack_surface"])

    def test_map_attack_surface_rfcomm_channels(self):
        from blue_tap.recon.fingerprint import _map_attack_surface
        fp = {"profiles": [], "attack_surface": [], "_profile_ids": []}
        services = [
            {"protocol": "RFCOMM", "channel": 1},
            {"protocol": "RFCOMM", "channel": 5},
        ]
        _map_attack_surface(fp, services)
        assert any("RFCOMM" in s and "2 open" in s for s in fp["attack_surface"])

    def test_map_attack_surface_fallback_patterns(self):
        from blue_tap.recon.fingerprint import _map_attack_surface
        # No _profile_ids key triggers fallback path using raw service data
        fp = {"profiles": [], "attack_surface": []}
        services = [{"profile": "ftp", "name": "file transfer", "class_ids": ["FTP"]}]
        _map_attack_surface(fp, services)
        assert any("FTP" in s for s in fp["attack_surface"])

    # -- _check_vuln_hints --------------------------------------------------

    def test_check_vuln_hints_old_bt(self):
        from blue_tap.recon.fingerprint import _check_vuln_hints
        fp = {"lmp_version": "4.0 (0x06)", "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        assert any("KNOB" in h for h in fp["vuln_hints"])
        assert any("BIAS" in h for h in fp["vuln_hints"])
        assert any("Legacy pairing" in h for h in fp["vuln_hints"])
        assert any("BlueBorne" in h for h in fp["vuln_hints"])
        assert any("BrakTooth" in h for h in fp["vuln_hints"])
        assert any("SweynTooth" in h for h in fp["vuln_hints"])

    def test_check_vuln_hints_new_bt(self):
        from blue_tap.recon.fingerprint import _check_vuln_hints
        fp = {"lmp_version": "5.4 (0x0d)", "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        assert len(fp["vuln_hints"]) == 0

    def test_check_vuln_hints_no_version(self):
        from blue_tap.recon.fingerprint import _check_vuln_hints
        fp = {"lmp_version": None, "vuln_hints": [], "_profile_ids": []}
        _check_vuln_hints(fp)
        assert len(fp["vuln_hints"]) == 0

    def test_check_vuln_hints_spp_exposed(self):
        from blue_tap.recon.fingerprint import _check_vuln_hints
        fp = {"lmp_version": "5.4 (0x0d)", "vuln_hints": [], "_profile_ids": ["spp"]}
        _check_vuln_hints(fp)
        assert any("SPP exposed" in h for h in fp["vuln_hints"])

    def test_check_vuln_hints_pbap_legacy(self):
        from blue_tap.recon.fingerprint import _check_vuln_hints
        fp = {"lmp_version": "4.2 (0x08)", "vuln_hints": [], "_profile_ids": ["pbap"]}
        _check_vuln_hints(fp)
        assert any("PBAP on legacy" in h for h in fp["vuln_hints"])

    # -- fingerprint_device -------------------------------------------------

    @patch("blue_tap.recon.fingerprint.browse_services", return_value=[])
    @patch("blue_tap.recon.fingerprint.run_cmd")
    def test_fingerprint_device_adapter_not_ready(self, mock_run, _browse, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: False
        )
        from blue_tap.recon.fingerprint import fingerprint_device
        fp = fingerprint_device("AA:BB:CC:DD:EE:FF")
        assert fp["error"] == "adapter not ready"
        assert fp["ivi_likely"] is False

    @patch("blue_tap.recon.fingerprint.browse_services", return_value=[])
    @patch("blue_tap.recon.fingerprint.run_cmd")
    def test_fingerprint_device_success(self, mock_run, _browse, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "blue_tap.core.scanner.parse_device_class", lambda x: {"is_ivi": False}
        )
        # name result, info result
        mock_run.side_effect = [
            _completed(stdout="TestDevice\n"),
            _completed(stdout="Manufacturer: Qualcomm\nClass: 0x200408\n"),
        ]
        from blue_tap.recon.fingerprint import fingerprint_device
        fp = fingerprint_device("AA:BB:CC:DD:EE:FF")
        assert fp["name"] == "TestDevice"
        assert fp["manufacturer"] == "Qualcomm"


# ===========================================================================
# RFCOMM Scanner
# ===========================================================================

class TestRFCOMMScanner:
    """Tests for blue_tap.recon.rfcomm_scan."""

    def _make_scanner(self):
        from blue_tap.recon.rfcomm_scan import RFCOMMScanner
        return RFCOMMScanner("AA:BB:CC:DD:EE:FF")

    # -- _is_obex -----------------------------------------------------------

    def test_is_obex_response_code(self):
        from blue_tap.recon.rfcomm_scan import _is_obex
        assert _is_obex(bytes([0xA0])) is True
        assert _is_obex(bytes([0x80])) is True
        assert _is_obex(bytes([0xC0])) is True
        assert _is_obex(bytes([0xC1])) is True
        assert _is_obex(bytes([0xD0])) is True

    def test_is_obex_connect_request(self):
        from blue_tap.recon.rfcomm_scan import _is_obex
        assert _is_obex(bytes([0x00, 0x01, 0x02, 0x03])) is True

    def test_is_obex_empty(self):
        from blue_tap.recon.rfcomm_scan import _is_obex
        assert _is_obex(b"") is False

    def test_is_obex_not_obex(self):
        from blue_tap.recon.rfcomm_scan import _is_obex
        assert _is_obex(b"AT\r\n") is False

    def test_is_obex_short_connect(self):
        from blue_tap.recon.rfcomm_scan import _is_obex
        # 0x00 with < 4 bytes -> not obex
        assert _is_obex(bytes([0x00, 0x01])) is False

    # -- probe_channel ------------------------------------------------------

    def test_probe_channel_connection_refused(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "closed"
        assert result["response_type"] == "refused"

    def test_probe_channel_timeout(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ETIMEDOUT, "timed out")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "timeout"

    def test_probe_channel_host_unreachable(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "unreachable")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "host_unreachable"

    def test_probe_channel_host_down(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTDOWN, "down")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "host_unreachable"

    def test_probe_channel_eacces(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EACCES, "permission denied")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "closed"  # Falls through to default

    def test_probe_channel_open_at_modem(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.recv.return_value = b"OK\r\n"
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "at_modem"

    def test_probe_channel_open_obex(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.recv.return_value = bytes([0xA0, 0x00, 0x10])
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "obex"

    def test_probe_channel_open_silent(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.recv.side_effect = TimeoutError()
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "silent_open"

    def test_probe_channel_open_raw_data(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.recv.return_value = b"\x01\x02\x03"
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "raw_data"

    def test_probe_channel_open_oserror_on_send(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        mock_sock.sendall.side_effect = OSError("broken pipe")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner.probe_channel(1)
        assert result["status"] == "open"
        assert result["response_type"] == "silent_open"

    def test_probe_channel_with_local_addr(self, monkeypatch):
        scanner = self._make_scanner()
        scanner._local_addr = "11:22:33:44:55:66"
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        scanner.probe_channel(1)
        mock_sock.bind.assert_called_once_with(("11:22:33:44:55:66", 0))

    # -- _probe_with_retry --------------------------------------------------

    def test_probe_with_retry_success_first_try(self, monkeypatch):
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "probe_channel",
                            lambda ch, t: {"status": "open", "channel": ch})
        result = scanner._probe_with_retry(1, 2.0, 2)
        assert result["status"] == "open"

    def test_probe_with_retry_timeout_then_success(self, monkeypatch):
        scanner = self._make_scanner()
        results = iter([
            {"status": "timeout", "channel": 1},
            {"status": "open", "channel": 1},
        ])
        monkeypatch.setattr(scanner, "probe_channel",
                            lambda ch, t: next(results))
        with patch("time.sleep"):
            result = scanner._probe_with_retry(1, 2.0, 1)
        assert result["status"] == "open"

    # -- scan_all_channels --------------------------------------------------

    def test_scan_all_channels_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: False
        )
        scanner = self._make_scanner()
        assert scanner.scan_all_channels() == []

    def test_scan_all_channels_unreachable_threshold(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda *a, **kw: "11:22:33:44:55:66"
        )
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "_probe_with_retry",
                            lambda ch, t, r: {"status": "host_unreachable",
                                              "channel": ch, "response_type": "host_unreachable"})
        results = scanner.scan_all_channels(unreachable_threshold=3)
        # Should abort after 3 consecutive unreachable
        assert len(results) == 3

    # -- find_hidden_services -----------------------------------------------

    def test_find_hidden_services(self, monkeypatch):
        scanner = self._make_scanner()
        scan_results = [
            {"channel": 1, "status": "open", "response_type": "at_modem"},
            {"channel": 5, "status": "open", "response_type": "silent_open"},
            {"channel": 10, "status": "closed", "response_type": "refused"},
        ]
        hidden = scanner.find_hidden_services([1], scan_results=scan_results)
        assert len(hidden) == 1
        assert hidden[0]["channel"] == 5

    def test_find_hidden_services_none_hidden(self, monkeypatch):
        scanner = self._make_scanner()
        scan_results = [
            {"channel": 1, "status": "open", "response_type": "at_modem"},
        ]
        hidden = scanner.find_hidden_services([1], scan_results=scan_results)
        assert hidden == []

    def test_find_hidden_services_auto_scan(self, monkeypatch):
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "scan_all_channels", lambda: [
            {"channel": 3, "status": "open", "response_type": "raw_data"},
        ])
        hidden = scanner.find_hidden_services([1])
        assert len(hidden) == 1


# ===========================================================================
# L2CAP Scanner
# ===========================================================================

class TestL2CAPScanner:
    """Tests for blue_tap.recon.l2cap_scan."""

    def _make_scanner(self):
        from blue_tap.recon.l2cap_scan import L2CAPScanner
        return L2CAPScanner("AA:BB:CC:DD:EE:FF")

    # -- _probe_psm ---------------------------------------------------------

    def test_probe_psm_open(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "open"
        assert result["name"] == "SDP"

    def test_probe_psm_closed(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "closed"

    def test_probe_psm_auth_required(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EACCES, "auth")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(15, 1.0)
        assert result["status"] == "auth_required"
        assert result["name"] == "HID-Control"

    def test_probe_psm_host_unreachable(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "unreachable")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "host_unreachable"

    def test_probe_psm_timeout(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "timeout"

    def test_probe_psm_host_down(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTDOWN, "down")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "host_unreachable"

    def test_probe_psm_network_down(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ENETDOWN, "net down")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "host_unreachable"

    def test_probe_psm_unknown_dynamic(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.return_value = None
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(4097, 1.0)
        assert "Dynamic" in result["name"]

    def test_probe_psm_with_local_addr(self, monkeypatch):
        scanner = self._make_scanner()
        scanner._local_addr = "11:22:33:44:55:66"
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ECONNREFUSED, "refused")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        scanner._probe_psm(1, 1.0)
        mock_sock.bind.assert_called_once()

    def test_probe_psm_unknown_oserror(self, monkeypatch):
        scanner = self._make_scanner()
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.ENODEV, "no device")
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: mock_sock)
        result = scanner._probe_psm(1, 1.0)
        assert result["status"] == "closed"

    # -- scan_standard_psms -------------------------------------------------

    def test_scan_standard_psms_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: False
        )
        scanner = self._make_scanner()
        assert scanner.scan_standard_psms() == []

    def test_scan_standard_psms_success(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda *a, **kw: "11:22:33:44:55:66"
        )
        scanner = self._make_scanner()
        # Mock _probe_psm to return open for SDP, closed for rest
        def mock_probe(psm, timeout):
            return {"psm": psm, "status": "open" if psm == 1 else "closed",
                    "name": "SDP" if psm == 1 else "other"}
        monkeypatch.setattr(scanner, "_probe_psm", mock_probe)
        results = scanner.scan_standard_psms()
        # Only open and auth_required are appended
        assert any(r["psm"] == 1 and r["status"] == "open" for r in results)

    def test_scan_standard_psms_unreachable_abort(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.get_adapter_address", lambda *a, **kw: "11:22:33:44:55:66"
        )
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "_probe_psm",
                            lambda psm, t: {"psm": psm, "status": "host_unreachable",
                                            "name": "test"})
        results = scanner.scan_standard_psms()
        # Should abort after 3 consecutive unreachable
        assert len(results) == 3

    # -- scan_dynamic_psms --------------------------------------------------

    def test_scan_dynamic_psms_even_start(self, monkeypatch):
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "_scan_psm_list", lambda pl, t, **kw: pl)
        # Even start should be bumped to odd
        result = scanner.scan_dynamic_psms(start=4098, end=4099, workers=1)
        assert result[0] == 4099

    def test_scan_dynamic_psms_parallel(self, monkeypatch):
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "_scan_psm_list_parallel",
                            lambda pl, t, w: [{"psm": pl[0], "status": "open", "name": "test"}])
        result = scanner.scan_dynamic_psms(start=4097, end=4097, workers=5)
        assert len(result) == 1

    # -- _scan_psm_list_parallel --------------------------------------------

    def test_scan_psm_list_parallel(self, monkeypatch):
        scanner = self._make_scanner()
        monkeypatch.setattr(scanner, "_probe_psm",
                            lambda psm, t: {"psm": psm, "status": "open", "name": "test"})
        results = scanner._scan_psm_list_parallel([4097, 4099], 1.0, workers=2)
        assert len(results) == 2
        assert results[0]["psm"] < results[1]["psm"]


# ===========================================================================
# HCI Capture
# ===========================================================================

class TestHCICapture:
    """Tests for blue_tap.recon.hci_capture."""

    def _make_capture(self):
        from blue_tap.recon.hci_capture import HCICapture
        return HCICapture()

    # -- start --------------------------------------------------------------

    def test_start_btmon_not_found(self, monkeypatch):
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: False)
        cap = self._make_capture()
        assert cap.start("test.log") is False

    def test_start_already_running(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)

        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pgid": os.getpid(), "pid": os.getpid(),
                               "output_file": "old.log"})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        cap = HCICapture()
        # os.kill(os.getpid(), 0) succeeds = process exists
        assert cap.start("test.log") is False

    def test_start_stale_pid_cleaned(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)

        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pgid": 999999, "pid": 999999,
                               "output_file": "old.log"})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "setsid", lambda: None)

        cap = HCICapture()
        result = cap.start(str(tmp_path / "test.log"))
        assert result is True

    def test_start_text_mode(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "setsid", lambda: None)

        cap = HCICapture()
        assert cap.start(str(tmp_path / "test.log"), pcap=False) is True
        assert cap.output_file == str(tmp_path / "test.log")

    def test_start_pcap_mode(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "setsid", lambda: None)

        cap = HCICapture()
        assert cap.start(str(tmp_path / "test.pcap"), pcap=True) is True

    def test_start_with_hci(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        captured_args = {}
        def mock_popen(cmd, **kwargs):
            captured_args["cmd"] = cmd
            m = MagicMock()
            m.pid = 12345
            return m
        monkeypatch.setattr(subprocess, "Popen", mock_popen)
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "setsid", lambda: None)

        cap = HCICapture()
        cap.start(str(tmp_path / "test.log"), hci="hci1", pcap=True)
        assert "-i" in captured_args["cmd"]
        assert "1" in captured_args["cmd"]

    def test_start_oserror(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        monkeypatch.setattr(subprocess, "Popen",
                            MagicMock(side_effect=OSError("popen failed")))
        monkeypatch.setattr(os, "setsid", lambda: None)

        cap = HCICapture()
        assert cap.start(str(tmp_path / "test.log")) is False

    # -- stop ---------------------------------------------------------------

    def test_stop_with_process(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))

        cap = HCICapture()
        cap.process = MagicMock()
        cap.process.pid = 12345
        cap.output_file = "test.log"
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "killpg", lambda pgid, sig: None)
        cap.process.wait.return_value = None

        result = cap.stop()
        assert result == "test.log"
        assert cap.process is None

    def test_stop_from_pid_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pgid": 99999, "pid": 99999,
                               "output_file": "saved.log"})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))

        cap = HCICapture()
        monkeypatch.setattr(os, "killpg", lambda pgid, sig: None)

        result = cap.stop()
        assert result == "saved.log"

    def test_stop_no_process_no_pid_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "nonexistent.pid"))

        cap = HCICapture()
        result = cap.stop()
        assert result == ""

    # -- is_running ---------------------------------------------------------

    def test_is_running_with_process(self):
        cap = self._make_capture()
        cap.process = MagicMock()
        cap.process.poll.return_value = None
        assert cap.is_running() is True

    def test_is_running_process_dead(self):
        cap = self._make_capture()
        cap.process = MagicMock()
        cap.process.poll.return_value = 0
        assert cap.is_running() is False

    def test_is_running_from_pid_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pid": os.getpid()})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))

        cap = HCICapture()
        assert cap.is_running() is True

    def test_is_running_stale_pid(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pid": 999999})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))

        cap = HCICapture()
        assert cap.is_running() is False

    def test_is_running_no_pid_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "nope.pid"))
        cap = HCICapture()
        assert cap.is_running() is False

    # -- status -------------------------------------------------------------

    def test_status_running(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({
            "pid": os.getpid(), "pgid": os.getpid(),
            "output_file": "test.log", "started_at": "2025-01-01T00:00:00",
        })
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))

        cap = HCICapture()
        s = cap.status()
        assert s["running"] is True
        assert s["output_file"] == "test.log"
        assert s["started_at"] == "2025-01-01T00:00:00"

    def test_status_not_running(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "nope.pid"))
        cap = HCICapture()
        s = cap.status()
        assert s["running"] is False
        assert s["output_file"] is None

    # -- _read_pid_file -----------------------------------------------------

    def test_read_pid_file_valid(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_data = json.dumps({"pgid": 100, "pid": 200, "output_file": "out.log"})
        pid_file.write_text(pid_data)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))
        pgid, pid, out = HCICapture._read_pid_file()
        assert pgid == 100
        assert pid == 200
        assert out == "out.log"

    def test_read_pid_file_missing(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "nope.pid"))
        pgid, pid, out = HCICapture._read_pid_file()
        assert (pgid, pid, out) == (None, None, None)

    def test_read_pid_file_corrupt(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import HCICapture
        pid_file = tmp_path / "btmon.pid"
        pid_file.write_text("not json")
        monkeypatch.setattr(HCICapture, "PID_FILE", str(pid_file))
        pgid, pid, out = HCICapture._read_pid_file()
        assert (pgid, pid, out) == (None, None, None)

    # -- detect_pairing_mode ------------------------------------------------

    def test_detect_pairing_mode_just_works(self, monkeypatch, tmp_path):
        from blue_tap.recon.hci_capture import detect_pairing_mode, HCICapture

        monkeypatch.setattr("blue_tap.recon.hci_capture.check_tool", lambda n: True)
        monkeypatch.setattr(HCICapture, "PID_FILE", str(tmp_path / "btmon.pid"))
        monkeypatch.setattr(HCICapture, "_PID_DIR", str(tmp_path))

        # Pre-create the log file path
        tmp_log = tmp_path / "bttap_hci_test.log"

        # Mock the btmon Popen (for HCICapture.start)
        btmon_proc = MagicMock()
        btmon_proc.pid = 12345
        btmon_proc.poll.return_value = None
        btmon_proc.wait.return_value = None

        # Mock bluetoothctl Popen
        bt_proc = MagicMock()
        bt_proc.stdin = MagicMock()
        bt_proc.poll.return_value = None
        bt_proc.wait.return_value = None

        popen_calls = [0]
        def mock_popen(*args, **kwargs):
            popen_calls[0] += 1
            if popen_calls[0] == 1:
                return btmon_proc
            # Before bluetoothctl runs, write btmon output to the log file
            # (simulating btmon having captured HCI data)
            tmp_log.write_text(
                "IO Capability: NoInputNoOutput\n"
                "Authentication: SSP\n"
                "Pairing method: Just Works\n"
            )
            return bt_proc

        monkeypatch.setattr(subprocess, "Popen", mock_popen)
        monkeypatch.setattr(os, "getpgid", lambda pid: 12345)
        monkeypatch.setattr(os, "killpg", lambda pgid, sig: None)
        monkeypatch.setattr(os, "setsid", lambda: None)
        monkeypatch.setattr("blue_tap.recon.hci_capture.run_cmd", lambda *a, **kw: _completed())

        with patch("time.sleep"), \
             patch("tempfile.NamedTemporaryFile") as mock_tmp:
            mock_tmp.return_value.name = str(tmp_log)
            mock_tmp.return_value.close = lambda: None
            result = detect_pairing_mode("AA:BB:CC:DD:EE:FF")

        assert result["ssp_supported"] is True
        assert result["io_capability"] == "NoInputNoOutput"
        assert result["pairing_method"] == "Just Works"

    @patch("blue_tap.recon.hci_capture.HCICapture.start", return_value=False)
    def test_detect_pairing_mode_capture_failed(self, _start, monkeypatch, tmp_path):
        with patch("tempfile.NamedTemporaryFile") as mock_tmp:
            mock_tmp.return_value.name = str(tmp_path / "bttap_hci_test.log")
            mock_tmp.return_value.close = lambda: None
            from blue_tap.recon.hci_capture import detect_pairing_mode
            result = detect_pairing_mode("AA:BB:CC:DD:EE:FF")
        assert result["ssp_supported"] is None
        assert result["pairing_method"] == "Unknown"


# ===========================================================================
# Sniffer
# ===========================================================================

class TestNRFBLESniffer:
    """Tests for blue_tap.recon.sniffer.NRFBLESniffer."""

    # -- is_available -------------------------------------------------------

    def test_is_available_tshark_with_extcap(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: n == "tshark")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(stdout="1. nrf_sniffer_ble"))
        assert NRFBLESniffer.is_available() is True

    def test_is_available_nrfutil_only(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool",
                            lambda n: n == "nrfutil")
        assert NRFBLESniffer.is_available() is True

    def test_is_available_nothing(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        assert NRFBLESniffer.is_available() is False

    def test_is_available_tshark_without_extcap(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool",
                            lambda n: n == "tshark")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(stdout="1. eth0"))
        assert NRFBLESniffer.is_available() is False

    # -- scan_advertisers ---------------------------------------------------

    def test_scan_advertisers_no_tshark(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        s = NRFBLESniffer()
        assert s.scan_advertisers() == []

    def test_scan_advertisers_success(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="aa:bb:cc:dd:ee:ff\tMyDevice\naa:bb:cc:dd:ee:ff\tDup\n11:22:33:44:55:66\t\n"
                            ))
        s = NRFBLESniffer()
        results = s.scan_advertisers(duration=1)
        assert len(results) == 2  # deduped by address
        assert results[0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert results[0]["name"] == "MyDevice"
        assert results[1]["name"] == "(unknown)"

    def test_scan_advertisers_empty(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(returncode=1))
        s = NRFBLESniffer()
        assert s.scan_advertisers(duration=1) == []

    # -- sniff_connection ---------------------------------------------------

    def test_sniff_connection_no_tools(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        s = NRFBLESniffer()
        result = s.sniff_connection("AA:BB:CC:DD:EE:FF")
        assert result["success"] is False

    def test_sniff_connection_tshark(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool",
                            lambda n: n == "tshark")

        pcap = str(tmp_path / "test.pcap")
        # Create a fake output file
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 100)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)

        # Mock subprocess.run for the tshark filter pass
        filtered_pcap = pcap + ".filtered"
        with open(filtered_pcap, "wb") as f:
            f.write(b"\x00" * 80)
        filter_result = MagicMock()
        filter_result.returncode = 0
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: filter_result)

        s = NRFBLESniffer()
        result = s.sniff_connection("AA:BB:CC:DD:EE:FF", output_pcap=pcap, duration=1)
        assert result["success"] is True

    # -- sniff_pairing ------------------------------------------------------

    def test_sniff_pairing_no_tools(self, monkeypatch):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        s = NRFBLESniffer()
        result = s.sniff_pairing()
        assert result["success"] is False

    def test_sniff_pairing_nrfutil(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool",
                            lambda n: n == "nrfutil")

        pcap = str(tmp_path / "pairing.pcap")
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 50)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)

        s = NRFBLESniffer()
        result = s.sniff_pairing(output_pcap=pcap, duration=1, target="AA:BB:CC:DD:EE:FF")
        assert result["success"] is True

    # -- _sniff_via_tshark target filter ------------------------------------

    def test_sniff_via_tshark_with_filter(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer

        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 100)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0

        filter_result = MagicMock()
        filter_result.returncode = 0

        popen_calls = []
        def mock_popen(*a, **kw):
            popen_calls.append(a)
            return mock_proc

        monkeypatch.setattr(subprocess, "Popen", mock_popen)

        # Mock subprocess.run for the filter pass
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: filter_result)

        # Create filtered file for the os.path.exists check
        filtered = pcap + ".filtered"
        with open(filtered, "wb") as f:
            f.write(b"\x00" * 80)

        s = NRFBLESniffer()
        result = s._sniff_via_tshark("AA:BB:CC:DD:EE:FF", pcap, 1)
        assert result["success"] is True

    # -- _sniff_via_nrfutil -------------------------------------------------

    def test_sniff_via_nrfutil_file_not_found(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        monkeypatch.setattr(subprocess, "Popen",
                            MagicMock(side_effect=FileNotFoundError))
        s = NRFBLESniffer()
        result = s._sniff_via_nrfutil("AA:BB:CC:DD:EE:FF",
                                       str(tmp_path / "nope.pcap"), 1)
        assert result["success"] is False

    # -- _check_pcap_output -------------------------------------------------

    def test_check_pcap_output_exists(self, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 200)
        s = NRFBLESniffer()
        result = s._check_pcap_output(pcap, 10, "AA:BB:CC:DD:EE:FF")
        assert result["success"] is True
        assert result["target"] == "AA:BB:CC:DD:EE:FF"
        assert result["size"] == 200

    def test_check_pcap_output_no_file(self, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        s = NRFBLESniffer()
        result = s._check_pcap_output(str(tmp_path / "nope.pcap"), 10, None)
        assert result["success"] is False

    def test_check_pcap_output_no_target(self, tmp_path):
        from blue_tap.recon.sniffer import NRFBLESniffer
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 50)
        s = NRFBLESniffer()
        result = s._check_pcap_output(pcap, 10, None)
        assert "target" not in result

    # -- stop ---------------------------------------------------------------

    def test_stop_with_process(self):
        from blue_tap.recon.sniffer import NRFBLESniffer
        s = NRFBLESniffer()
        s._proc = MagicMock()
        s._proc.send_signal.return_value = None
        s._proc.wait.return_value = None
        s.stop()
        assert s._proc is None

    def test_stop_no_process(self):
        from blue_tap.recon.sniffer import NRFBLESniffer
        s = NRFBLESniffer()
        s.stop()  # should not raise

    def test_stop_timeout(self):
        from blue_tap.recon.sniffer import NRFBLESniffer
        s = NRFBLESniffer()
        s._proc = MagicMock()
        s._proc.send_signal.return_value = None
        s._proc.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        s._proc.kill.return_value = None
        s.stop()
        assert s._proc is None


class TestUSRPCapture:
    """Tests for blue_tap.recon.sniffer.USRPCapture."""

    # -- is_available -------------------------------------------------------

    def test_is_available_true(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        assert USRPCapture.is_available() is True

    def test_is_available_false(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        assert USRPCapture.is_available() is False

    # -- scan_piconets ------------------------------------------------------

    def test_scan_piconets_no_uhd(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        u = USRPCapture()
        assert u.scan_piconets() == []

    def test_scan_piconets_btbb_rx(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        def mock_check(n):
            return n in ("uhd_find_devices", "btbb_rx")
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", mock_check)
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="LAP=AABBCC UAP=DD\nLAP=AABBCC UAP=DD\nLAP=112233\n"
                            ))
        u = USRPCapture()
        piconets = u.scan_piconets(duration=1)
        assert len(piconets) == 2  # deduped
        assert piconets[0]["lap"] == "AABBCC"
        assert piconets[0]["uap"] == "DD"
        assert piconets[1]["uap"] == "??"  # no UAP found

    def test_scan_piconets_no_btbb_rx_fallback(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        def mock_check(n):
            return n == "uhd_find_devices"
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", mock_check)

        # Mock capture_raw_iq
        monkeypatch.setattr(USRPCapture, "capture_raw_iq",
                            lambda self, *a, **kw: {"success": True, "file": "test.cfile"})

        u = USRPCapture()
        with patch("time.time", return_value=1000):
            result = u.scan_piconets(duration=1)
        assert result == []  # Returns empty list (raw IQ for offline)

    # -- follow_piconet -----------------------------------------------------

    def test_follow_piconet_no_uhd(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        u = USRPCapture()
        result = u.follow_piconet("AA:BB:CC:DD:EE:FF")
        assert result["success"] is False

    def test_follow_piconet_invalid_mac(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        u = USRPCapture()
        result = u.follow_piconet("INVALID")
        assert result["success"] is False
        assert "invalid" in result["error"].lower()

    def test_follow_piconet_btrx(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool",
                            lambda n: n in ("uhd_find_devices", "btrx"))

        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "wb") as f:
            f.write(b"\x00" * 100)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)

        u = USRPCapture()
        result = u.follow_piconet("AA:BB:CC:DD:EE:FF", output_pcap=pcap, duration=1)
        assert result["success"] is True
        assert result["lap"] == "DDEEFF"

    def test_follow_piconet_no_btrx_fallback(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture

        def mock_check(n):
            return n == "uhd_find_devices"
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", mock_check)

        monkeypatch.setattr(USRPCapture, "capture_raw_iq",
                            lambda self, *a, **kw: {"success": True, "file": "test.cfile"})

        u = USRPCapture()
        result = u.follow_piconet("AA:BB:CC:DD:EE:FF", duration=1)
        assert result.get("note") is not None

    # -- _follow_via_btrx ---------------------------------------------------

    def test_follow_via_btrx_file_not_found(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr(subprocess, "Popen",
                            MagicMock(side_effect=FileNotFoundError))
        u = USRPCapture()
        result = u._follow_via_btrx("AABBCC", str(tmp_path / "nope.pcap"), 1)
        assert result["success"] is False

    def test_follow_via_btrx_no_output(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)
        u = USRPCapture()
        result = u._follow_via_btrx("AABBCC", str(tmp_path / "nope.pcap"), 1)
        assert result["success"] is False

    # -- capture_raw_iq -----------------------------------------------------

    def test_capture_raw_iq_no_uhd(self, monkeypatch):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        u = USRPCapture()
        result = u.capture_raw_iq()
        assert result["success"] is False

    def test_capture_raw_iq_success(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)

        outfile = str(tmp_path / "test.cfile")
        # Create file with size = 80 bytes = 10 complex float32 samples
        with open(outfile, "wb") as f:
            f.write(b"\x00" * 80)

        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.wait.return_value = 0
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: mock_proc)

        u = USRPCapture()
        result = u.capture_raw_iq(output_file=outfile, duration=1)
        assert result["success"] is True
        assert result["size"] == 80

    def test_capture_raw_iq_file_not_found(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        monkeypatch.setattr(subprocess, "Popen",
                            MagicMock(side_effect=FileNotFoundError))
        u = USRPCapture()
        result = u.capture_raw_iq(output_file=str(tmp_path / "test.cfile"), duration=1)
        assert result["success"] is False

    def test_capture_raw_iq_custom_freq(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import USRPCapture
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)

        outfile = str(tmp_path / "test.cfile")
        with open(outfile, "wb") as f:
            f.write(b"\x00" * 16)

        captured = {}
        def mock_popen(cmd, **kw):
            captured["cmd"] = cmd
            m = MagicMock()
            m.pid = 1
            m.wait.return_value = 0
            return m
        monkeypatch.setattr(subprocess, "Popen", mock_popen)

        u = USRPCapture()
        result = u.capture_raw_iq(output_file=outfile, duration=1, freq=2.441e9)
        assert result["freq"] == 2.441e9

    # -- stop ---------------------------------------------------------------

    def test_usrp_stop_with_process(self):
        from blue_tap.recon.sniffer import USRPCapture
        u = USRPCapture()
        u._proc = MagicMock()
        u.stop()
        assert u._proc is None

    def test_usrp_stop_no_process(self):
        from blue_tap.recon.sniffer import USRPCapture
        u = USRPCapture()
        u.stop()  # should not raise

    def test_usrp_stop_timeout(self):
        from blue_tap.recon.sniffer import USRPCapture
        u = USRPCapture()
        u._proc = MagicMock()
        u._proc.send_signal.return_value = None
        u._proc.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        u._proc.kill.return_value = None
        u.stop()
        assert u._proc is None


class TestCrackleRunner:
    """Tests for blue_tap.recon.sniffer.CrackleRunner."""

    # -- is_available -------------------------------------------------------

    def test_is_available(self, monkeypatch):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: n == "crackle")
        assert CrackleRunner.is_available() is True

    def test_not_available(self, monkeypatch):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        assert CrackleRunner.is_available() is False

    # -- crack_ble ----------------------------------------------------------

    def test_crack_ble_not_installed(self, monkeypatch):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        c = CrackleRunner()
        result = c.crack_ble("test.pcap")
        assert result["success"] is False
        assert "not installed" in result["error"]

    def test_crack_ble_file_not_found(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        c = CrackleRunner()
        result = c.crack_ble(str(tmp_path / "nonexistent.pcap"))
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_crack_ble_success(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake pcap")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="TK found: 000000\nLTK found: aabbccdd11223344\nSuccessfully cracked\n"
                            ))
        c = CrackleRunner()
        result = c.crack_ble(pcap)
        assert result["success"] is True
        assert result["tk"] == "000000"
        assert result["ltk"] == "aabbccdd11223344"

    def test_crack_ble_with_output(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(stdout="no pairing"))
        c = CrackleRunner()
        result = c.crack_ble(pcap, output_pcap=str(tmp_path / "out.pcap"))
        assert result["success"] is False

    def test_crack_ble_secure_connections(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import CrackleRunner
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="Secure Connections detected\n"
                            ))
        c = CrackleRunner()
        result = c.crack_ble(pcap)
        assert result["success"] is False

    # -- _parse_crackle_output ----------------------------------------------

    def test_parse_crackle_output_tk_only(self):
        from blue_tap.recon.sniffer import CrackleRunner
        c = CrackleRunner()
        result = c._parse_crackle_output("TK found: 000000")
        assert result["tk"] == "000000"
        assert result["success"] is True

    def test_parse_crackle_output_ltk_only(self):
        from blue_tap.recon.sniffer import CrackleRunner
        c = CrackleRunner()
        result = c._parse_crackle_output("LTK = AABB")
        assert result["ltk"] == "AABB"
        assert result["success"] is True

    def test_parse_crackle_output_successfully(self):
        from blue_tap.recon.sniffer import CrackleRunner
        c = CrackleRunner()
        result = c._parse_crackle_output("Successfully cracked the pairing")
        assert result["success"] is True

    def test_parse_crackle_output_nothing(self):
        from blue_tap.recon.sniffer import CrackleRunner
        c = CrackleRunner()
        result = c._parse_crackle_output("no keys found")
        assert result["success"] is False
        assert result["tk"] is None
        assert result["ltk"] is None


class TestLinkKeyExtractor:
    """Tests for blue_tap.recon.sniffer.LinkKeyExtractor."""

    # -- extract_from_pcap --------------------------------------------------

    def test_extract_no_tshark(self, monkeypatch):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: False)
        lk = LinkKeyExtractor()
        result = lk.extract_from_pcap("test.pcap")
        assert result["success"] is False

    def test_extract_file_not_found(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        lk = LinkKeyExtractor()
        result = lk.extract_from_pcap(str(tmp_path / "nope.pcap"))
        assert result["success"] is False

    def test_extract_success(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="11\tAABBCCDDEEFF00112233445566778899\n"
                            ))
        lk = LinkKeyExtractor()
        result = lk.extract_from_pcap(pcap)
        assert result["success"] is True
        assert "AABBCCDDEEFF00112233445566778899" in result["keys"]

    def test_extract_no_keys(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(stdout=""))
        lk = LinkKeyExtractor()
        result = lk.extract_from_pcap(pcap)
        assert result["success"] is False

    def test_extract_tshark_failed(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.check_tool", lambda n: True)
        pcap = str(tmp_path / "test.pcap")
        with open(pcap, "w") as f:
            f.write("fake")
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(returncode=1, stderr="error"))
        lk = LinkKeyExtractor()
        result = lk.extract_from_pcap(pcap)
        assert result["success"] is False

    # -- inject_link_key ----------------------------------------------------

    def test_inject_link_key_bad_length(self):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        lk = LinkKeyExtractor()
        assert lk.inject_link_key("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66",
                                   "short") is False

    def test_inject_link_key_new_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr(LinkKeyExtractor, "BLUEZ_BT_DIR", str(tmp_path))
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed())
        monkeypatch.setattr("time.sleep", lambda s: None)

        lk = LinkKeyExtractor()
        key = "A" * 32
        assert lk.inject_link_key("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66",
                                   key) is True

        info_file = tmp_path / "AA:BB:CC:DD:EE:FF" / "11:22:33:44:55:66" / "info"
        content = info_file.read_text()
        assert "[LinkKey]" in content
        assert f"Key={key}" in content

    def test_inject_link_key_existing_file(self, monkeypatch, tmp_path):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr(LinkKeyExtractor, "BLUEZ_BT_DIR", str(tmp_path))
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed())
        monkeypatch.setattr("time.sleep", lambda s: None)

        # Create existing info file with a LinkKey section
        info_dir = tmp_path / "AA:BB:CC:DD:EE:FF" / "11:22:33:44:55:66"
        info_dir.mkdir(parents=True)
        info_file = info_dir / "info"
        info_file.write_text("[General]\nName=MyDevice\n\n[LinkKey]\nKey=OLD\nType=4\nPINLength=0\n\n[General2]\nFoo=bar\n")

        lk = LinkKeyExtractor()
        new_key = "B" * 32
        assert lk.inject_link_key("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66",
                                   new_key) is True

        content = info_file.read_text()
        assert f"Key={new_key}" in content
        assert "OLD" not in content
        assert "[General2]" in content  # Preserved other sections

    # -- get_adapter_mac ----------------------------------------------------

    def test_get_adapter_mac_success(self, monkeypatch):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(
                                stdout="hci0: ...\n  BD Address: AA:BB:CC:DD:EE:FF\n"
                            ))
        lk = LinkKeyExtractor()
        assert lk.get_adapter_mac() == "AA:BB:CC:DD:EE:FF"

    def test_get_adapter_mac_failure(self, monkeypatch):
        from blue_tap.recon.sniffer import LinkKeyExtractor
        monkeypatch.setattr("blue_tap.recon.sniffer.run_cmd",
                            lambda cmd, **kw: _completed(returncode=1))
        lk = LinkKeyExtractor()
        assert lk.get_adapter_mac() is None
