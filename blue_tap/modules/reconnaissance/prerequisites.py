"""Prerequisite evaluation for recon collectors."""

from __future__ import annotations

from typing import Any

from blue_tap.modules.reconnaissance.sniffer import DarkFirmwareSniffer, NRFBLESniffer
from blue_tap.utils.bt_helpers import check_tool, ensure_adapter_ready


def evaluate_recon_prerequisites(
    *,
    target_capability: str,
    classic_adapter: str = "hci0",
    below_hci_adapter: str = "hci1",
) -> dict[str, Any]:
    classic_ready = ensure_adapter_ready(classic_adapter)
    hci_capture_available = check_tool("btmon")
    nrf_available = NRFBLESniffer.is_available()
    darkfirmware_available = DarkFirmwareSniffer(hci_dev=_normalize_hci_index(below_hci_adapter)).is_available()

    checks = {
        "classic_adapter_ready": {
            "available": classic_ready,
            "reason": "" if classic_ready else f"{classic_adapter} not ready",
        },
        "hci_capture": {
            "available": hci_capture_available,
            "reason": "" if hci_capture_available else "btmon not installed",
        },
        "nrf_ble_sniffer": {
            "available": nrf_available and target_capability in {"ble_only", "dual_mode"},
            "reason": _nrf_reason(nrf_available, target_capability),
        },
        "darkfirmware_lmp": {
            "available": darkfirmware_available and target_capability in {"classic_only", "dual_mode"},
            "reason": _darkfirmware_reason(darkfirmware_available, target_capability, below_hci_adapter),
        },
    }
    checks["combined_capture"] = {
        "available": checks["nrf_ble_sniffer"]["available"] and checks["darkfirmware_lmp"]["available"],
        "reason": _combined_reason(checks),
    }
    return checks


def prerequisite_skip_reason(prerequisites: dict[str, Any], key: str, title: str) -> str:
    item = prerequisites.get(key, {})
    reason = item.get("reason", "") or "unsatisfied prerequisites"
    return f"{title} skipped because {reason}"


def _normalize_hci_index(hci_value: str | int) -> int:
    if isinstance(hci_value, int):
        return hci_value
    text = str(hci_value)
    if text.startswith("hci"):
        text = text[3:]
    try:
        return int(text)
    except ValueError:
        return 1


def _nrf_reason(nrf_available: bool, target_capability: str) -> str:
    if target_capability not in {"ble_only", "dual_mode"}:
        return "target does not expose BLE support"
    if not nrf_available:
        return "nRF52840 BLE sniffer is unavailable"
    return ""


def _darkfirmware_reason(darkfirmware_available: bool, target_capability: str, adapter: str) -> str:
    if target_capability not in {"classic_only", "dual_mode"}:
        return "target does not expose BR/EDR support"
    if not darkfirmware_available:
        return f"DarkFirmware adapter {adapter} is unavailable"
    return ""


def _combined_reason(checks: dict[str, Any]) -> str:
    if not checks["nrf_ble_sniffer"]["available"]:
        return checks["nrf_ble_sniffer"]["reason"]
    if not checks["darkfirmware_lmp"]["available"]:
        return checks["darkfirmware_lmp"]["reason"]
    return ""
