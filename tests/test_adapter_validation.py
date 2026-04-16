"""Tests for adapter input validation and structured returns (Phase 2)."""

from unittest.mock import MagicMock, patch

import pytest

from blue_tap.hardware.adapter import (
    adapter_up,
    set_device_class,
    set_device_name,
)
from blue_tap.hardware.spoofer import clone_device_identity


# ---------------------------------------------------------------------------
# set_device_class — input validation
# ---------------------------------------------------------------------------

def test_device_class_rejects_invalid_hex():
    """Non-hex string raises ValueError with clear message."""
    with pytest.raises(ValueError, match="valid hex string"):
        set_device_class("hci0", "notahex")


def test_device_class_rejects_partially_invalid_hex():
    """Hex prefix with invalid body raises ValueError."""
    with pytest.raises(ValueError, match="valid hex string"):
        set_device_class("hci0", "0xGGGGGG")


def test_device_class_rejects_out_of_range():
    """Value > 0xFFFFFF raises ValueError."""
    with pytest.raises(ValueError, match="range 0x000000-0xFFFFFF"):
        set_device_class("hci0", "0x1000000")


def test_device_class_accepts_valid_with_prefix():
    """Valid hex with 0x prefix proceeds past validation (no ValueError)."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_class("hci0", "0x5a020c")
    # adapter doesn't exist → success=False, but no ValueError raised
    assert result["success"] is False
    assert result["device_class"] == "0x5a020c"
    assert result["hci"] == "hci0"


def test_device_class_accepts_valid_without_prefix():
    """Valid hex without 0x prefix is normalised and accepted."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_class("hci0", "5a020c")
    assert result["success"] is False
    assert result["device_class"] == "0x5a020c"


def test_device_class_accepts_boundary_zero():
    """0x000000 is on the lower boundary and must be accepted."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_class("hci0", "0x000000")
    assert result["device_class"] == "0x000000"


def test_device_class_accepts_boundary_max():
    """0xFFFFFF is on the upper boundary and must be accepted."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_class("hci0", "0xFFFFFF")
    assert result["device_class"] == "0xFFFFFF"


# ---------------------------------------------------------------------------
# set_device_name — input validation
# ---------------------------------------------------------------------------

def test_device_name_rejects_too_long():
    """Name exceeding 248 UTF-8 bytes raises ValueError."""
    long_name = "A" * 249  # 249 ASCII bytes = 249 UTF-8 bytes > 248
    with pytest.raises(ValueError, match="too long"):
        set_device_name("hci0", long_name)


def test_device_name_rejects_multibyte_overflow():
    """Name that is short in chars but long in UTF-8 bytes raises ValueError."""
    # Each '€' is 3 UTF-8 bytes; 83 × 3 = 249 bytes
    long_name = "€" * 83
    assert len(long_name.encode("utf-8", errors="replace")) > 248
    with pytest.raises(ValueError, match="too long"):
        set_device_name("hci0", long_name)


def test_device_name_accepts_valid():
    """Normal ASCII name proceeds past validation without raising."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_name("hci0", "TestPhone")
    assert result["success"] is False  # adapter missing, but no ValueError
    assert result["name"] == "TestPhone"
    assert result["hci"] == "hci0"


def test_device_name_accepts_exactly_248_bytes():
    """Name of exactly 248 ASCII bytes is at the limit and must be accepted."""
    name_at_limit = "B" * 248
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = set_device_name("hci0", name_at_limit)
    assert result["name"] == name_at_limit


# ---------------------------------------------------------------------------
# adapter_up — structured return shape
# ---------------------------------------------------------------------------

def test_adapter_up_returns_dict():
    """adapter_up always returns a dict with the required keys."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = adapter_up("hci0")
    assert isinstance(result, dict)
    assert "success" in result
    assert "hci" in result
    assert "operation" in result
    assert "error" in result


def test_adapter_up_returns_false_when_adapter_missing():
    """adapter_up returns success=False when the adapter doesn't exist."""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=False):
        result = adapter_up("hci99")
    assert result["success"] is False
    assert result["hci"] == "hci99"
    assert result["operation"] == "up"
    assert result["error"] is not None


def test_adapter_up_returns_true_on_success():
    """adapter_up returns success=True when hciconfig succeeds."""
    mock_run = MagicMock()
    mock_run.returncode = 0
    mock_run.stderr = ""
    with patch("blue_tap.hardware.adapter._adapter_exists", return_value=True), \
         patch("blue_tap.hardware.adapter.run_cmd", return_value=mock_run), \
         patch("blue_tap.hardware.adapter.success"):
        result = adapter_up("hci0")
    assert result["success"] is True
    assert result["operation"] == "up"
    assert result["error"] is None


def test_clone_device_identity_checks_structured_helper_success_flags():
    """clone_device_identity must not treat failed helper result dicts as truthy success."""
    with patch("blue_tap.hardware.spoofer.get_adapter_address", return_value="11:22:33:44:55:66"), \
         patch("blue_tap.hardware.spoofer.spoof_address", return_value={"success": True}), \
         patch("blue_tap.hardware.adapter.set_device_name", return_value={"success": False, "name": "Phone", "previous_name": "Old"}), \
         patch("blue_tap.hardware.adapter.set_device_class", return_value={"success": False, "device_class": "0x5a020c"}):
        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "Phone", "0x5a020c")

    assert result["success"] is False
    assert result["mac_spoofed"] is True
    assert result["name_set"] is False
    assert result["class_set"] is False
