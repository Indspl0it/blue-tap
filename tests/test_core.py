"""Tests for blue_tap/core/ -- scanner, spoofer, adapter.

Covers every function in:
- scanner.py: parse_device_class, estimate_distance, _lookup_ble_manufacturer,
  scan_classic, scan_ble_sync, scan_all, resolve_name
- spoofer.py: save_original_mac, get_original_mac, restore_original_mac,
  spoof_bdaddr, spoof_spooftooph, spoof_btmgmt, spoof_address, clone_device_identity
- adapter.py: ALL adapter management functions
"""

import json
import os
import subprocess
import types
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _completed(stdout="", stderr="", returncode=0):
    """Shorthand for subprocess.CompletedProcess."""
    return subprocess.CompletedProcess([], returncode=returncode, stdout=stdout, stderr=stderr)


# ============================================================================
# TestScanner
# ============================================================================

class TestScanner:
    """Tests for blue_tap.core.scanner."""

    # ------------------------------------------------------------------
    # parse_device_class
    # ------------------------------------------------------------------

    def test_parse_device_class_phone_smartphone(self):
        from blue_tap.core.scanner import parse_device_class
        result = parse_device_class("0x5a020c")
        assert result["major"] == "Phone"
        assert result["minor"] == "Smartphone"
        assert result["is_phone"] is True
        assert result["is_ivi"] is False
        assert isinstance(result["services"], list)

    def test_parse_device_class_car_audio(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x04 (AV), minor=0x08 (Car Audio) => cod bits: major at bits 12-8, minor at bits 7-2
        # major=0x04 => 0x04 << 8 = 0x0400; minor=0x08 => 0x08 << 2 = 0x20
        # so cod = 0x200420
        result = parse_device_class("0x200420")
        assert result["major"] == "Audio/Video"
        assert result["minor"] == "Car Audio"
        assert result["is_ivi"] is True
        assert result["is_phone"] is False

    def test_parse_device_class_computer_laptop(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x01 (Computer), minor=0x03 (Laptop) => 0x01<<8=0x0100, 0x03<<2=0x0C
        result = parse_device_class("0x00010c")
        assert result["major"] == "Computer"
        assert result["minor"] == "Laptop"

    def test_parse_device_class_peripheral_gamepad(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x05 (Peripheral), minor=0x02 (Gamepad)
        result = parse_device_class("0x000508")
        assert result["major"] == "Peripheral"
        assert result["minor"] == "Gamepad"

    def test_parse_device_class_wearable_wristwatch(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x07 (Wearable), minor=0x01 (Wristwatch)
        result = parse_device_class("0x000704")
        assert result["major"] == "Wearable"
        assert result["minor"] == "Wristwatch"

    def test_parse_device_class_with_services(self):
        from blue_tap.core.scanner import parse_device_class
        # 0x5a020c has service bits set for Audio (bit 21), Telephony (bit 22), etc.
        result = parse_device_class("0x5a020c")
        assert "services" in result
        assert len(result["services"]) > 0

    def test_parse_device_class_invalid_string(self):
        from blue_tap.core.scanner import parse_device_class
        result = parse_device_class("not_hex")
        assert result["major"] == "Unknown"
        assert result["minor"] == "Unknown"
        assert result["services"] == []
        assert result["is_phone"] is False
        assert result["is_ivi"] is False

    def test_parse_device_class_none(self):
        from blue_tap.core.scanner import parse_device_class
        result = parse_device_class(None)
        assert result["major"] == "Unknown"

    def test_parse_device_class_no_prefix(self):
        from blue_tap.core.scanner import parse_device_class
        result = parse_device_class("5a020c")
        assert result["major"] == "Phone"

    def test_parse_device_class_zero(self):
        from blue_tap.core.scanner import parse_device_class
        result = parse_device_class("0x000000")
        assert result["major"] == "Miscellaneous"
        assert result["is_phone"] is False

    def test_parse_device_class_reserved_major(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x1F is not in the dict
        result = parse_device_class("0x001F00")
        assert "Reserved" in result["major"]

    def test_parse_device_class_unknown_minor(self):
        from blue_tap.core.scanner import parse_device_class
        # major=0x02 (Phone), minor=0x3F (not in dict)
        result = parse_device_class("0x0002FC")
        assert result["major"] == "Phone"
        assert "Unknown" in result["minor"]

    # ------------------------------------------------------------------
    # estimate_distance
    # ------------------------------------------------------------------

    def test_estimate_distance_typical(self):
        from blue_tap.core.scanner import estimate_distance
        dist = estimate_distance(-70)
        assert dist is not None
        assert isinstance(dist, float)
        assert dist > 0

    def test_estimate_distance_very_close(self):
        from blue_tap.core.scanner import estimate_distance
        dist = estimate_distance(-40)
        assert dist is not None
        assert dist < 1.0

    def test_estimate_distance_far(self):
        from blue_tap.core.scanner import estimate_distance
        dist = estimate_distance(-90)
        assert dist is not None
        assert dist > 5.0

    def test_estimate_distance_custom_tx_power(self):
        from blue_tap.core.scanner import estimate_distance
        d1 = estimate_distance(-70, tx_power=-59)
        d2 = estimate_distance(-70, tx_power=-40)
        assert d1 is not None
        assert d2 is not None
        assert d2 > d1  # weaker tx_power reference means farther

    def test_estimate_distance_zero_rssi_invalid(self):
        from blue_tap.core.scanner import estimate_distance
        assert estimate_distance(0) is None

    def test_estimate_distance_positive_rssi_invalid(self):
        from blue_tap.core.scanner import estimate_distance
        assert estimate_distance(10) is None

    def test_estimate_distance_non_numeric(self):
        from blue_tap.core.scanner import estimate_distance
        assert estimate_distance("abc") is None

    def test_estimate_distance_none(self):
        from blue_tap.core.scanner import estimate_distance
        assert estimate_distance(None) is None

    # ------------------------------------------------------------------
    # _lookup_ble_manufacturer
    # ------------------------------------------------------------------

    def test_lookup_ble_manufacturer_apple(self):
        from blue_tap.core.scanner import _lookup_ble_manufacturer
        assert _lookup_ble_manufacturer(0x004C) == "Apple"

    def test_lookup_ble_manufacturer_unknown(self):
        from blue_tap.core.scanner import _lookup_ble_manufacturer
        result = _lookup_ble_manufacturer(0xFFFF)
        assert "Unknown" in result
        assert "0xFFFF" in result

    @pytest.mark.parametrize("cid,expected", [
        (0x0006, "Microsoft"),
        (0x00E0, "Google"),
        (0x0075, "Samsung"),
        (0x0047, "Intel"),
    ])
    def test_lookup_ble_manufacturer_known_ids(self, cid, expected):
        from blue_tap.core.scanner import _lookup_ble_manufacturer
        assert _lookup_ble_manufacturer(cid) == expected

    # ------------------------------------------------------------------
    # scan_classic
    # ------------------------------------------------------------------

    def test_scan_classic_success(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        inq_stdout = (
            "Inquiring ...\n"
            "\t00:11:22:33:44:55\tclock offset: 0x1234\tclass: 0x5a020c\n"
        )
        scan_stdout = (
            "Scanning ...\n"
            "\t00:11:22:33:44:55\tMyPhone\n"
        )

        call_count = [0]
        def fake_run_cmd(cmd, timeout=30):
            call_count[0] += 1
            if "inq" in cmd:
                return _completed(stdout=inq_stdout)
            elif "scan" in cmd:
                return _completed(stdout=scan_stdout)
            elif "name" in cmd:
                return _completed(stdout="FallbackName")
            return _completed()

        monkeypatch.setattr(scanner, "run_cmd", fake_run_cmd)

        devices = scanner.scan_classic(duration=5, hci="hci0")
        assert len(devices) == 1
        assert devices[0]["address"] == "00:11:22:33:44:55"
        assert devices[0]["name"] == "MyPhone"
        assert devices[0]["type"] == "Classic"
        assert "class_info" in devices[0]

    def test_scan_classic_adapter_not_ready(self, monkeypatch):
        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: False
        )
        from blue_tap.core.scanner import scan_classic
        assert scan_classic() == []

    def test_scan_classic_inquiry_fails_device_not_up(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        def fake_run_cmd(cmd, timeout=30):
            if "inq" in cmd:
                return _completed(returncode=1, stderr="device is not up")
            return _completed(returncode=1, stderr="fail")

        monkeypatch.setattr(scanner, "run_cmd", fake_run_cmd)
        devices = scanner.scan_classic()
        assert devices == []

    def test_scan_classic_no_devices(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        def fake_run_cmd(cmd, timeout=30):
            return _completed(stdout="Inquiring ...\n")

        monkeypatch.setattr(scanner, "run_cmd", fake_run_cmd)
        devices = scanner.scan_classic()
        assert devices == []

    def test_scan_classic_resolves_unnamed_device(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(
            "blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda hci: True
        )

        inq_stdout = "\t00:11:22:33:44:55\tclock offset: 0x1234\tclass: 0x5a020c\n"

        def fake_run_cmd(cmd, timeout=30):
            if "inq" in cmd:
                return _completed(stdout=inq_stdout)
            elif "scan" in cmd:
                return _completed(stdout="Scanning ...\n")
            elif "name" in cmd:
                return _completed(stdout="ResolvedName")
            return _completed()

        monkeypatch.setattr(scanner, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        devices = scanner.scan_classic()
        assert len(devices) == 1
        assert devices[0]["name"] == "ResolvedName"

    # ------------------------------------------------------------------
    # scan_ble_sync
    # ------------------------------------------------------------------

    def test_scan_ble_sync_success(self, monkeypatch):
        from blue_tap.core import scanner

        mock_device = MagicMock()
        mock_device.address = "AA:BB:CC:DD:EE:FF"
        mock_device.name = "BLE-Device"
        mock_device.rssi = -65
        mock_device.metadata = {
            "manufacturer_data": {0x004C: b"\x01\x02"},
            "uuids": ["0000180f-0000-1000-8000-00805f9b34fb"],
            "tx_power": -55,
        }

        async def fake_discover(**kwargs):
            return [mock_device]

        mock_bleak = types.ModuleType("bleak")
        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakScanner.discover = fake_discover
        monkeypatch.setitem(__import__("sys").modules, "bleak", mock_bleak)

        devices = scanner.scan_ble_sync(duration=1)
        assert len(devices) == 1
        assert devices[0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert devices[0]["name"] == "BLE-Device"
        assert devices[0]["type"] == "BLE"
        assert devices[0]["manufacturer_name"] == "Apple"
        assert "service_uuids" in devices[0]
        assert devices[0]["tx_power"] == -55

    def test_scan_ble_sync_no_bleak(self, monkeypatch):
        """When bleak is not installed, scan_ble returns []."""
        from blue_tap.core import scanner
        import sys

        # Remove bleak from modules if present, make import fail
        monkeypatch.delitem(sys.modules, "bleak", raising=False)

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fail_bleak(name, *args, **kwargs):
            if name == "bleak":
                raise ImportError("no bleak")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fail_bleak)

        devices = scanner.scan_ble_sync(duration=1)
        assert devices == []

    def test_scan_ble_sync_exception(self, monkeypatch):
        from blue_tap.core import scanner

        async def fail_discover(**kwargs):
            raise RuntimeError("dbus error")

        mock_bleak = types.ModuleType("bleak")
        mock_bleak.BleakScanner = MagicMock()
        mock_bleak.BleakScanner.discover = fail_discover
        monkeypatch.setitem(__import__("sys").modules, "bleak", mock_bleak)

        devices = scanner.scan_ble_sync(duration=1)
        assert devices == []

    # ------------------------------------------------------------------
    # scan_all
    # ------------------------------------------------------------------

    def test_scan_all_merges_classic_and_ble(self, monkeypatch):
        from blue_tap.core import scanner

        classic_devices = [
            {"address": "00:11:22:33:44:55", "name": "PhoneClassic",
             "rssi": "N/A", "type": "Classic"},
        ]
        ble_devices = [
            {"address": "00:11:22:33:44:55", "name": "PhoneBLE",
             "rssi": -60, "type": "BLE", "distance_m": 2.0,
             "service_uuids": ["1800"], "manufacturer_name": "Apple"},
            {"address": "AA:BB:CC:DD:EE:FF", "name": "BLE-Only",
             "rssi": -70, "type": "BLE"},
        ]

        monkeypatch.setattr(scanner, "scan_classic", lambda duration, hci: classic_devices)
        monkeypatch.setattr(scanner, "scan_ble_sync", lambda duration, adapter: ble_devices)

        result = scanner.scan_all(duration=5, hci="hci0")
        assert len(result) == 2

        # Find the merged device
        merged = [d for d in result if d["address"] == "00:11:22:33:44:55"][0]
        assert merged["type"] == "Classic+BLE"
        assert merged["rssi"] == -60  # BLE rssi replaces N/A
        assert merged["distance_m"] == 2.0
        assert merged["service_uuids"] == ["1800"]
        assert merged["manufacturer_name"] == "Apple"

        ble_only = [d for d in result if d["address"] == "AA:BB:CC:DD:EE:FF"][0]
        assert ble_only["type"] == "BLE"

    def test_scan_all_no_overlap(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(scanner, "scan_classic", lambda d, h: [
            {"address": "11:11:11:11:11:11", "name": "C", "rssi": "N/A", "type": "Classic"},
        ])
        monkeypatch.setattr(scanner, "scan_ble_sync", lambda d, adapter: [
            {"address": "22:22:22:22:22:22", "name": "B", "rssi": -70, "type": "BLE"},
        ])

        result = scanner.scan_all()
        assert len(result) == 2

    def test_scan_all_empty(self, monkeypatch):
        from blue_tap.core import scanner
        monkeypatch.setattr(scanner, "scan_classic", lambda d, h: [])
        monkeypatch.setattr(scanner, "scan_ble_sync", lambda d, adapter: [])
        assert scanner.scan_all() == []

    def test_scan_all_merge_prefers_known_name(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(scanner, "scan_classic", lambda d, h: [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "Unknown",
             "rssi": "N/A", "type": "Classic"},
        ])
        monkeypatch.setattr(scanner, "scan_ble_sync", lambda d, adapter: [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "RealName",
             "rssi": -50, "type": "BLE"},
        ])

        result = scanner.scan_all()
        assert result[0]["name"] == "RealName"

    # ------------------------------------------------------------------
    # resolve_name
    # ------------------------------------------------------------------

    def test_resolve_name_success_first_attempt(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(scanner, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="  MyDevice  "))

        name = scanner.resolve_name("00:11:22:33:44:55")
        assert name == "MyDevice"

    def test_resolve_name_success_after_retry(self, monkeypatch):
        from blue_tap.core import scanner

        attempts = [0]

        def fake_run_cmd(cmd, timeout=30):
            attempts[0] += 1
            if attempts[0] < 3:
                return _completed(stdout="", returncode=1)
            return _completed(stdout="FoundIt")

        monkeypatch.setattr(scanner, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        name = scanner.resolve_name("00:11:22:33:44:55", retries=2)
        assert name == "FoundIt"
        assert attempts[0] == 3

    def test_resolve_name_all_retries_fail(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(scanner, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="", returncode=1))
        monkeypatch.setattr("time.sleep", lambda s: None)

        name = scanner.resolve_name("00:11:22:33:44:55", retries=1)
        assert name == "Unknown"

    def test_resolve_name_empty_stdout(self, monkeypatch):
        from blue_tap.core import scanner

        monkeypatch.setattr(scanner, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="  "))
        monkeypatch.setattr("time.sleep", lambda s: None)

        name = scanner.resolve_name("00:11:22:33:44:55", retries=0)
        assert name == "Unknown"


# ============================================================================
# TestSpoofer
# ============================================================================

class TestSpoofer:
    """Tests for blue_tap.core.spoofer."""

    # ------------------------------------------------------------------
    # save_original_mac
    # ------------------------------------------------------------------

    def test_save_original_mac_new_file(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")

        spoofer.save_original_mac("hci0")

        with open(mac_file) as f:
            data = json.load(f)
        assert data["hci0"] == "AA:BB:CC:DD:EE:FF"

    def test_save_original_mac_idempotent(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        # Pre-seed with existing data
        with open(mac_file, "w") as f:
            json.dump({"hci0": "11:22:33:44:55:66"}, f)

        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")

        spoofer.save_original_mac("hci0")

        with open(mac_file) as f:
            data = json.load(f)
        # Should NOT overwrite existing entry
        assert data["hci0"] == "11:22:33:44:55:66"

    def test_save_original_mac_no_address(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: None)

        spoofer.save_original_mac("hci0")
        # File should not be created
        import os
        assert not os.path.exists(mac_file)

    def test_save_original_mac_corrupt_json(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        # Write corrupt JSON
        with open(mac_file, "w") as f:
            f.write("{invalid json")

        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")

        spoofer.save_original_mac("hci0")

        with open(mac_file) as f:
            data = json.load(f)
        assert data["hci0"] == "AA:BB:CC:DD:EE:FF"
        # Backup file should exist
        import os
        assert os.path.exists(mac_file + ".bak")

    def test_save_original_mac_adds_second_adapter(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            json.dump({"hci0": "11:22:33:44:55:66"}, f)

        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")

        spoofer.save_original_mac("hci1")

        with open(mac_file) as f:
            data = json.load(f)
        assert data["hci0"] == "11:22:33:44:55:66"
        assert data["hci1"] == "AA:BB:CC:DD:EE:FF"

    # ------------------------------------------------------------------
    # get_original_mac
    # ------------------------------------------------------------------

    def test_get_original_mac_exists(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            json.dump({"hci0": "AA:BB:CC:DD:EE:FF"}, f)

        assert spoofer.get_original_mac("hci0") == "AA:BB:CC:DD:EE:FF"

    def test_get_original_mac_missing_adapter(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            json.dump({"hci0": "AA:BB:CC:DD:EE:FF"}, f)

        assert spoofer.get_original_mac("hci1") is None

    def test_get_original_mac_no_file(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE",
                            str(tmp_path / "nonexistent.json"))
        assert spoofer.get_original_mac("hci0") is None

    def test_get_original_mac_corrupt_file(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            f.write("corrupt")

        assert spoofer.get_original_mac("hci0") is None

    # ------------------------------------------------------------------
    # restore_original_mac
    # ------------------------------------------------------------------

    def test_restore_original_mac_success(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            json.dump({"hci0": "AA:BB:CC:DD:EE:FF"}, f)

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac, method: True)

        result = spoofer.restore_original_mac("hci0")
        assert result is True

        # Entry should be removed
        with open(mac_file) as f:
            data = json.load(f)
        assert "hci0" not in data

    def test_restore_original_mac_no_saved(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE",
                            str(tmp_path / "nonexistent.json"))

        result = spoofer.restore_original_mac("hci0")
        assert result is False

    def test_restore_original_mac_spoof_fails(self, tmp_path, monkeypatch):
        from blue_tap.core import spoofer

        mac_file = str(tmp_path / "mac.json")
        monkeypatch.setattr(spoofer, "_ORIGINAL_MAC_FILE", mac_file)

        with open(mac_file, "w") as f:
            json.dump({"hci0": "AA:BB:CC:DD:EE:FF"}, f)

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac, method: False)

        result = spoofer.restore_original_mac("hci0")
        assert result is False

        # Entry should still be there
        with open(mac_file) as f:
            data = json.load(f)
        assert "hci0" in data

    # ------------------------------------------------------------------
    # spoof_bdaddr
    # ------------------------------------------------------------------

    def test_spoof_bdaddr_success(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="ok"))
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_bdaddr("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is True

    def test_spoof_bdaddr_tool_missing(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: False)

        result = spoofer.spoof_bdaddr("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_bdaddr_hardware_rejection(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "11:22:33:44:55:66")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(
                                stdout="hardware does not allow"))
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_bdaddr("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_bdaddr_command_fails(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "11:22:33:44:55:66")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(
                                returncode=1, stderr="error"))
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_bdaddr("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_bdaddr_verify_mismatch(self, monkeypatch):
        from blue_tap.core import spoofer

        call_n = [0]

        def fake_get_addr(hci):
            call_n[0] += 1
            if call_n[0] == 1:
                return "11:22:33:44:55:66"  # original
            return "11:22:33:44:55:66"  # still original after reset

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address", fake_get_addr)
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="ok"))
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_bdaddr("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    # ------------------------------------------------------------------
    # spoof_spooftooph
    # ------------------------------------------------------------------

    def test_spoof_spooftooph_success(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="ok"))

        result = spoofer.spoof_spooftooph("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is True

    def test_spoof_spooftooph_tool_missing(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: False)

        result = spoofer.spoof_spooftooph("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_spooftooph_hardware_rejection(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "11:22:33:44:55:66")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(
                                stdout="can't set bdaddr"))

        result = spoofer.spoof_spooftooph("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_spooftooph_returncode_fail(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(
                                returncode=1, stderr="fail"))

        result = spoofer.spoof_spooftooph("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_spooftooph_verify_mismatch(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "check_tool", lambda name: True)
        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "11:22:33:44:55:66")  # doesn't match target
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="ok"))

        result = spoofer.spoof_spooftooph("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    # ------------------------------------------------------------------
    # spoof_btmgmt
    # ------------------------------------------------------------------

    def test_spoof_btmgmt_success(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "AA:BB:CC:DD:EE:FF")

        def fake_run_cmd(cmd, timeout=30):
            return _completed(stdout="ok")

        monkeypatch.setattr(spoofer, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_btmgmt("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is True

    def test_spoof_btmgmt_power_off_fails(self, monkeypatch):
        from blue_tap.core import spoofer

        def fake_run_cmd(cmd, timeout=30):
            if "power" in cmd and "off" in cmd:
                return _completed(returncode=1, stderr="fail")
            return _completed()

        monkeypatch.setattr(spoofer, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_btmgmt("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_btmgmt_public_addr_not_supported(self, monkeypatch):
        from blue_tap.core import spoofer

        def fake_run_cmd(cmd, timeout=30):
            if "public-addr" in cmd:
                return _completed(returncode=1, stderr="not supported")
            return _completed()

        monkeypatch.setattr(spoofer, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_btmgmt("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_btmgmt_verify_mismatch(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "get_adapter_address",
                            lambda hci: "11:22:33:44:55:66")
        monkeypatch.setattr(spoofer, "run_cmd",
                            lambda cmd, timeout=30: _completed(stdout="ok"))
        monkeypatch.setattr("time.sleep", lambda s: None)

        result = spoofer.spoof_btmgmt("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_btmgmt_power_on_retry(self, monkeypatch):
        from blue_tap.core import spoofer

        power_on_calls = [0]

        def fake_run_cmd(cmd, timeout=30):
            if "public-addr" in cmd:
                return _completed(returncode=1, stderr="not supported")
            if "power" in cmd and "on" in cmd:
                power_on_calls[0] += 1
                if power_on_calls[0] == 1:
                    return _completed(returncode=1, stderr="busy")
                return _completed()
            return _completed()

        monkeypatch.setattr(spoofer, "run_cmd", fake_run_cmd)
        monkeypatch.setattr("time.sleep", lambda s: None)

        # Still fails overall because public-addr failed
        result = spoofer.spoof_btmgmt("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False
        assert power_on_calls[0] >= 2  # retried power on

    # ------------------------------------------------------------------
    # spoof_address
    # ------------------------------------------------------------------

    def test_spoof_address_specific_method_bdaddr(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr(spoofer, "save_original_mac", lambda hci: None)
        monkeypatch.setattr(spoofer, "spoof_bdaddr", lambda hci, mac: True)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF", method="bdaddr")
        assert result is True

    def test_spoof_address_specific_method_spooftooph(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr(spoofer, "save_original_mac", lambda hci: None)
        monkeypatch.setattr(spoofer, "spoof_spooftooph", lambda hci, mac: True)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF", method="spooftooph")
        assert result is True

    def test_spoof_address_specific_method_btmgmt(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr(spoofer, "save_original_mac", lambda hci: None)
        monkeypatch.setattr(spoofer, "spoof_btmgmt", lambda hci, mac: True)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF", method="btmgmt")
        assert result is True

    def test_spoof_address_adapter_not_ready(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: False)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF")
        assert result is False

    def test_spoof_address_auto_tries_all(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr(spoofer, "save_original_mac", lambda hci: None)

        tried = []

        def track_bdaddr(hci, mac):
            tried.append("bdaddr")
            return False

        def track_spooftooph(hci, mac):
            tried.append("spooftooph")
            return False

        def track_btmgmt(hci, mac):
            tried.append("btmgmt")
            return False

        monkeypatch.setattr(spoofer, "spoof_bdaddr", track_bdaddr)
        monkeypatch.setattr(spoofer, "spoof_spooftooph", track_spooftooph)
        monkeypatch.setattr(spoofer, "spoof_btmgmt", track_btmgmt)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF", method="auto")
        assert result is False
        assert tried == ["bdaddr", "spooftooph", "btmgmt"]

    def test_spoof_address_auto_stops_on_first_success(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready",
                            lambda hci: True)
        monkeypatch.setattr(spoofer, "save_original_mac", lambda hci: None)

        tried = []

        def track_bdaddr(hci, mac):
            tried.append("bdaddr")
            return False

        def track_spooftooph(hci, mac):
            tried.append("spooftooph")
            return True  # success

        def track_btmgmt(hci, mac):
            tried.append("btmgmt")
            return False

        monkeypatch.setattr(spoofer, "spoof_bdaddr", track_bdaddr)
        monkeypatch.setattr(spoofer, "spoof_spooftooph", track_spooftooph)
        monkeypatch.setattr(spoofer, "spoof_btmgmt", track_btmgmt)

        result = spoofer.spoof_address("hci0", "AA:BB:CC:DD:EE:FF", method="auto")
        assert result is True
        assert tried == ["bdaddr", "spooftooph"]  # btmgmt not tried

    # ------------------------------------------------------------------
    # clone_device_identity
    # ------------------------------------------------------------------

    def test_clone_device_identity_success(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_name",
                            lambda hci, name: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_class",
                            lambda hci, cls: True)

        result = spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is True

    def test_clone_device_identity_spoof_fails(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: False)

        result = spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    def test_clone_device_identity_name_fails(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_name",
                            lambda hci, name: False)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_class",
                            lambda hci, cls: True)

        result = spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    def test_clone_device_identity_class_fails(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_name",
                            lambda hci, name: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_class",
                            lambda hci, cls: False)

        result = spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    def test_clone_device_identity_exception(self, monkeypatch):
        from blue_tap.core import spoofer

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_name",
                            lambda hci, name: (_ for _ in ()).throw(RuntimeError("boom")))
        # set_device_name will raise before set_device_class is called

        result = spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    def test_clone_device_identity_custom_class(self, monkeypatch):
        from blue_tap.core import spoofer

        received_class = []

        monkeypatch.setattr(spoofer, "spoof_address", lambda hci, mac: True)
        monkeypatch.setattr("blue_tap.core.adapter.set_device_name",
                            lambda hci, name: True)

        def capture_class(hci, cls):
            received_class.append(cls)
            return True

        monkeypatch.setattr("blue_tap.core.adapter.set_device_class", capture_class)

        spoofer.clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "Phone",
                                      device_class="0x200404")
        assert received_class == ["0x200404"]


# ============================================================================
# TestAdapter
# ============================================================================

class TestAdapter:
    """Tests for blue_tap.core.adapter."""

    # ------------------------------------------------------------------
    # _adapter_exists
    # ------------------------------------------------------------------

    def test_adapter_exists_true(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stdout="hci0: ..."))
        assert adapter._adapter_exists("hci0") is True

    def test_adapter_exists_false_returncode(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1, stderr="No such device"))
        assert adapter._adapter_exists("hci0") is False

    def test_adapter_exists_false_stderr(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stderr="No such device"))
        assert adapter._adapter_exists("hci0") is False

    # ------------------------------------------------------------------
    # list_adapters
    # ------------------------------------------------------------------

    def test_list_adapters_none(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "get_hci_adapters", lambda: [])
        result = adapter.list_adapters()
        assert result == []

    def test_list_adapters_with_enrichment(self, monkeypatch):
        from blue_tap.core import adapter

        raw = [{"name": "hci0", "address": "AA:BB:CC:DD:EE:FF", "status": "UP"}]
        monkeypatch.setattr(adapter, "get_hci_adapters", lambda: raw)
        monkeypatch.setattr(adapter, "get_adapter_info",
                            lambda hci: {"chipset": "CSR 8510", "features": ["LE"]})

        result = adapter.list_adapters()
        assert len(result) == 1
        assert result[0]["chipset"] == "CSR 8510"
        assert result[0]["name"] == "hci0"

    # ------------------------------------------------------------------
    # get_adapter_info
    # ------------------------------------------------------------------

    def test_get_adapter_info_full(self, monkeypatch):
        from blue_tap.core import adapter

        hciconfig_output = (
            "hci0:   Type: Primary  Bus: USB\n"
            "        BD Address: AA:BB:CC:DD:EE:FF  ACL MTU: 1021:8  SCO MTU: 64:1\n"
            "        UP RUNNING\n"
            "        RX bytes:0 acl:0 sco:0 events:0 errors:0\n"
            "        Manufacturer: Cambridge Silicon Radio (10)\n"
            "        HCI Version: 4.0 (0x6)  Revision: 0x22bb\n"
            "        Features: 0xff 0xff 0x8f 0xfe 0xdb\n"
            "        <le> <bredr> <ssp> <inquiry> <sniff>\n"
        )

        btmgmt_output = (
            "hci0:   Primary controller\n"
            "        supported settings: powered connectable discoverable "
            "bondable link-security ssp br/edr le secure-conn static-addr "
            "debug-keys privacy wide-band-speech\n"
        )

        def fake_run_cmd(cmd):
            if "hciconfig" in cmd:
                return _completed(stdout=hciconfig_output)
            if "btmgmt" in cmd:
                return _completed(stdout=btmgmt_output)
            return _completed()

        monkeypatch.setattr(adapter, "run_cmd", fake_run_cmd)
        monkeypatch.setattr(adapter, "_detect_chipset",
                            lambda hci, hciconfig_output="": "CSR 8510")

        info = adapter.get_adapter_info("hci0")
        assert info["manufacturer"] == "Cambridge Silicon Radio (10)"
        assert info["bt_version"] == "4.0 (0x6)  Revision: 0x22bb"
        assert info["capabilities"]["le"] is True
        assert info["capabilities"]["bredr"] is True
        assert info["capabilities"]["ssp"] is True
        assert info["capabilities"]["dual_mode"] is True
        assert "LE" in info["features"]
        assert "BR/EDR" in info["features"]
        assert "SSP" in info["features"]
        assert "Dual-Mode" in info["features"]
        assert "Inquiry" in info["features"]
        assert "Sniff" in info["features"]
        # btmgmt extras
        assert "SC" in info["features"]
        assert "Static-Addr" in info["features"]
        assert "Debug-Keys" in info["features"]
        assert "Privacy" in info["features"]
        assert "WBS" in info["features"]

    def test_get_adapter_info_hciconfig_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1, stderr="fail"))

        info = adapter.get_adapter_info("hci0")
        assert info["chipset"] == ""
        assert info["capabilities"]["le"] is False

    def test_get_adapter_info_csr_chipset_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        hci_out = "Manufacturer: Cambridge Silicon Radio\n<le> <bredr>\n"
        btmgmt_out = "supported settings: powered\n"

        def fake_run_cmd(cmd):
            if "hciconfig" in cmd:
                return _completed(stdout=hci_out)
            if "btmgmt" in cmd:
                return _completed(stdout=btmgmt_out)
            return _completed()

        monkeypatch.setattr(adapter, "run_cmd", fake_run_cmd)
        monkeypatch.setattr(adapter, "_detect_chipset",
                            lambda hci, hciconfig_output="": "CSR")

        info = adapter.get_adapter_info("hci0")
        assert info["capabilities"]["address_change"] is True

    def test_get_adapter_info_intel_not_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        hci_out = "Manufacturer: Intel\n<le> <bredr>\n"

        def fake_run_cmd(cmd):
            if "hciconfig" in cmd:
                return _completed(stdout=hci_out)
            if "btmgmt" in cmd:
                return _completed(stdout="supported settings: powered\n")
            return _completed()

        monkeypatch.setattr(adapter, "run_cmd", fake_run_cmd)
        monkeypatch.setattr(adapter, "_detect_chipset",
                            lambda hci, hciconfig_output="": "Intel AX201")

        info = adapter.get_adapter_info("hci0")
        assert info["capabilities"]["address_change"] is False

    def test_get_adapter_info_broadcom_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        hci_out = "Manufacturer: Broadcom\n<le> <bredr>\n"

        def fake_run_cmd(cmd):
            if "hciconfig" in cmd:
                return _completed(stdout=hci_out)
            if "btmgmt" in cmd:
                return _completed(stdout="supported settings: powered\n")
            return _completed()

        monkeypatch.setattr(adapter, "run_cmd", fake_run_cmd)
        monkeypatch.setattr(adapter, "_detect_chipset",
                            lambda hci, hciconfig_output="": "BCM20702")

        info = adapter.get_adapter_info("hci0")
        assert info["capabilities"]["address_change"] is True

    # ------------------------------------------------------------------
    # _detect_chipset
    # ------------------------------------------------------------------

    def test_detect_chipset_from_sysfs_product(self, monkeypatch, tmp_path):
        from blue_tap.core import adapter

        # Create a fake sysfs structure with a product file
        hci_dir = tmp_path / "hci0"
        device_dir = hci_dir / "device_real"
        device_dir.mkdir(parents=True)
        (device_dir / "product").write_text("CSR8510 A10")

        # Create a symlink for the "device" path
        device_link = hci_dir / "device"
        device_link.symlink_to(device_dir)

        # Capture originals before patching
        _orig_exists = os.path.exists
        _orig_islink = os.path.islink
        _orig_realpath = os.path.realpath
        _orig_open = open
        prefix = "/sys/class/bluetooth/hci0"

        def _rewrite(p):
            return str(hci_dir) + p[len(prefix):] if p.startswith(prefix) else p

        monkeypatch.setattr("os.path.exists",
                            lambda p: _orig_exists(_rewrite(p)) if p.startswith(prefix) or p == prefix else _orig_exists(p))
        monkeypatch.setattr("os.path.islink",
                            lambda p: _orig_islink(_rewrite(p)) if p.startswith(prefix) else _orig_islink(p))
        monkeypatch.setattr("os.path.realpath",
                            lambda p: _orig_realpath(_rewrite(p)) if p.startswith(prefix) else _orig_realpath(p))
        monkeypatch.setattr("builtins.open",
                            lambda path, *a, **kw: _orig_open(_rewrite(str(path)), *a, **kw)
                            if str(path).startswith(prefix) else _orig_open(path, *a, **kw))

        result = adapter._detect_chipset("hci0")
        assert result == "CSR8510 A10"

    def test_detect_chipset_fallback_hciconfig(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr("os.path.exists", lambda p: False)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stdout="Manufacturer: Texas Instruments"))

        result = adapter._detect_chipset("hci0")
        assert result == "Texas Instruments"

    def test_detect_chipset_unknown(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr("os.path.exists", lambda p: False)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1))

        result = adapter._detect_chipset("hci0")
        assert result == "Unknown"

    def test_detect_chipset_from_hciconfig_output_param(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr("os.path.exists", lambda p: False)

        result = adapter._detect_chipset("hci0",
                                          hciconfig_output="Manufacturer: Nordic Semi")
        assert result == "Nordic Semi"

    # ------------------------------------------------------------------
    # _lookup_usb_chipset
    # ------------------------------------------------------------------

    def test_lookup_usb_chipset_known(self):
        from blue_tap.core.adapter import _lookup_usb_chipset
        assert _lookup_usb_chipset("0A12", "0001") == "CSR 8510 A10"

    def test_lookup_usb_chipset_unknown(self):
        from blue_tap.core.adapter import _lookup_usb_chipset
        result = _lookup_usb_chipset("DEAD", "BEEF")
        assert result == "USB DEAD:BEEF"

    @pytest.mark.parametrize("vid,pid,expected", [
        ("8087", "0029", "Intel AX200"),
        ("0BDA", "8771", "Realtek RTL8761B"),
        ("0A5C", "21E8", "Broadcom BCM20702A0"),
    ])
    def test_lookup_usb_chipset_parametrized(self, vid, pid, expected):
        from blue_tap.core.adapter import _lookup_usb_chipset
        assert _lookup_usb_chipset(vid, pid) == expected

    # ------------------------------------------------------------------
    # recommend_adapter_roles
    # ------------------------------------------------------------------

    def test_recommend_adapter_roles_no_adapters(self, monkeypatch):
        from blue_tap.core import adapter
        monkeypatch.setattr(adapter, "list_adapters", lambda: [])

        result = adapter.recommend_adapter_roles()
        assert result["scan"] is None
        assert result["spoof"] is None
        assert "No adapters found" in result["notes"][0]

    def test_recommend_adapter_roles_single_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        adapters = [{
            "name": "hci0", "status": "UP",
            "chipset": "CSR 8510",
            "capabilities": {"address_change": True},
        }]

        result = adapter.recommend_adapter_roles(adapters=adapters)
        assert result["scan"] == "hci0"
        assert result["spoof"] == "hci0"

    def test_recommend_adapter_roles_single_not_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        adapters = [{
            "name": "hci0", "status": "UP",
            "chipset": "Intel AX201",
            "capabilities": {"address_change": False},
        }]

        result = adapter.recommend_adapter_roles(adapters=adapters)
        assert result["scan"] == "hci0"
        assert result["spoof"] == "hci0"
        assert any("does not support" in n for n in result["notes"])

    def test_recommend_adapter_roles_single_unknown_spoofability(self, monkeypatch):
        from blue_tap.core import adapter

        adapters = [{
            "name": "hci0", "status": "UP",
            "chipset": "Unknown",
            "capabilities": {"address_change": None},
        }]

        result = adapter.recommend_adapter_roles(adapters=adapters)
        assert result["scan"] == "hci0"
        assert result["spoof"] == "hci0"
        assert any("test which spoofing" in n for n in result["notes"])

    def test_recommend_adapter_roles_two_adapters_one_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        adapters = [
            {"name": "hci0", "status": "UP",
             "capabilities": {"address_change": False}, "chipset": "Intel"},
            {"name": "hci1", "status": "UP",
             "capabilities": {"address_change": True}, "chipset": "CSR 8510"},
        ]

        result = adapter.recommend_adapter_roles(adapters=adapters)
        assert result["spoof"] == "hci1"
        assert result["scan"] == "hci0"

    def test_recommend_adapter_roles_two_adapters_none_spoofable(self, monkeypatch):
        from blue_tap.core import adapter

        adapters = [
            {"name": "hci0", "status": "UP",
             "capabilities": {"address_change": False}},
            {"name": "hci1", "status": "UP",
             "capabilities": {"address_change": False}},
        ]

        result = adapter.recommend_adapter_roles(adapters=adapters)
        assert result["scan"] == "hci0"
        assert result["spoof"] == "hci1"
        assert any("No confirmed spoofable" in n for n in result["notes"])

    def test_recommend_adapter_roles_passed_none_calls_list(self, monkeypatch):
        from blue_tap.core import adapter

        called = [False]

        def fake_list():
            called[0] = True
            return []

        monkeypatch.setattr(adapter, "list_adapters", fake_list)
        adapter.recommend_adapter_roles(adapters=None)
        assert called[0] is True

    # ------------------------------------------------------------------
    # _hci_cmd
    # ------------------------------------------------------------------

    def test_hci_cmd_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed())
        assert adapter._hci_cmd("hci0", "up") is True

    def test_hci_cmd_failure(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1, stderr="err"))
        assert adapter._hci_cmd("hci0", "up") is False

    # ------------------------------------------------------------------
    # adapter_up / adapter_down / adapter_reset
    # ------------------------------------------------------------------

    def test_adapter_up_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.adapter_up("hci0") is True

    def test_adapter_up_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.adapter_up("hci0") is False

    def test_adapter_up_cmd_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: False)
        assert adapter.adapter_up("hci0") is False

    def test_adapter_down_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.adapter_down("hci0") is True

    def test_adapter_down_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.adapter_down("hci0") is False

    def test_adapter_reset_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.adapter_reset("hci0") is True

    def test_adapter_reset_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.adapter_reset("hci0") is False

    def test_adapter_reset_cmd_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: False)
        assert adapter.adapter_reset("hci0") is False

    # ------------------------------------------------------------------
    # set_device_class / set_device_name
    # ------------------------------------------------------------------

    def test_set_device_class_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.set_device_class("hci0", "0x5a020c") is True

    def test_set_device_class_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.set_device_class("hci0") is False

    def test_set_device_class_cmd_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: False)
        assert adapter.set_device_class("hci0") is False

    def test_set_device_name_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.set_device_name("hci0", "TestPhone") is True

    def test_set_device_name_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.set_device_name("hci0", "TestPhone") is False

    def test_set_device_name_cmd_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: False)
        assert adapter.set_device_name("hci0", "TestPhone") is False

    # ------------------------------------------------------------------
    # enable_page_scan / disable_page_scan
    # ------------------------------------------------------------------

    def test_enable_page_scan_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.enable_page_scan("hci0") is True

    def test_enable_page_scan_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.enable_page_scan("hci0") is False

    def test_disable_page_scan_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "_hci_cmd", lambda hci, *a: True)
        assert adapter.disable_page_scan("hci0") is True

    def test_disable_page_scan_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.disable_page_scan("hci0") is False

    # ------------------------------------------------------------------
    # enable_ssp / disable_ssp
    # ------------------------------------------------------------------

    def test_enable_ssp_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stdout="ok"))
        assert adapter.enable_ssp("hci0") is True

    def test_enable_ssp_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.enable_ssp("hci0") is False

    def test_enable_ssp_not_supported(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stdout="not supported"))
        assert adapter.enable_ssp("hci0") is False

    def test_enable_ssp_command_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1, stderr="error"))
        assert adapter.enable_ssp("hci0") is False

    def test_disable_ssp_success(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stdout="ok"))
        assert adapter.disable_ssp("hci0") is True

    def test_disable_ssp_not_exists(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: False)
        assert adapter.disable_ssp("hci0") is False

    def test_disable_ssp_not_supported(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(stderr="not supported"))
        assert adapter.disable_ssp("hci0") is False

    def test_disable_ssp_command_fails(self, monkeypatch):
        from blue_tap.core import adapter

        monkeypatch.setattr(adapter, "_adapter_exists", lambda hci: True)
        monkeypatch.setattr(adapter, "run_cmd",
                            lambda cmd: _completed(returncode=1, stderr="fail"))
        assert adapter.disable_ssp("hci0") is False
