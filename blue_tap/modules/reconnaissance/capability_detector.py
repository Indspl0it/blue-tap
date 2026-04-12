"""Target transport capability detection for reconnaissance workflows."""

from __future__ import annotations

from typing import Any

from blue_tap.modules.reconnaissance.gatt import enumerate_services_detailed_sync
from blue_tap.modules.reconnaissance.sdp import browse_services
from blue_tap.utils.bt_helpers import ensure_adapter_ready, run_cmd


def detect_target_capabilities(address: str, hci: str = "hci0") -> dict[str, Any]:
    """Determine whether a target supports BR/EDR, BLE, or both.

    The detector intentionally uses low-cost probes first and preserves
    the evidence behind the final classification so recon automation can
    explain why steps were executed or skipped.
    """
    adapter_ready = ensure_adapter_ready(hci)
    classic = {
        "supported": False,
        "signals": [],
        "details": {},
    }
    ble = {
        "supported": False,
        "signals": [],
        "details": {},
    }

    if not adapter_ready:
        return {
            "classification": "undetermined",
            "adapter": hci,
            "adapter_ready": False,
            "classic": classic,
            "ble": ble,
            "observations": [f"adapter={hci}", "adapter_ready=false"],
        }

    name_result = run_cmd(["hcitool", "-i", hci, "name", address], timeout=8)
    if name_result.returncode == 0 and name_result.stdout.strip():
        classic["supported"] = True
        classic["signals"].append("remote_name_resolved")
        classic["details"]["name"] = name_result.stdout.strip()
    elif name_result.stderr.strip():
        classic["details"]["name_error"] = name_result.stderr.strip()

    info_result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=10)
    if info_result.returncode == 0 and info_result.stdout.strip():
        classic["supported"] = True
        classic["signals"].append("hcitool_info")
        classic["details"]["info_excerpt"] = _first_nonempty_line(info_result.stdout)
    elif info_result.stderr.strip():
        classic["details"]["info_error"] = info_result.stderr.strip()

    services = browse_services(address, hci=hci)
    if services:
        classic["supported"] = True
        classic["signals"].append("sdp_services")
        classic["details"]["service_count"] = len(services)
        classic["details"]["profiles"] = sorted(
            {
                service.get("profile", "")
                for service in services
                if isinstance(service, dict) and service.get("profile")
            }
        )
    else:
        classic["details"]["service_count"] = 0

    try:
        gatt_result = enumerate_services_detailed_sync(address, adapter=hci)
    except TypeError:
        gatt_result = enumerate_services_detailed_sync(address)
    if gatt_result.get("connected") or gatt_result.get("service_count", 0) > 0:
        ble["supported"] = True
        ble["signals"].append("gatt_connect")
    if gatt_result.get("service_count", 0) > 0:
        ble["signals"].append("gatt_services")
    ble["details"] = {
        "status": gatt_result.get("status", "unknown"),
        "service_count": gatt_result.get("service_count", 0),
        "characteristic_count": gatt_result.get("characteristic_count", 0),
        "error": gatt_result.get("error", ""),
    }

    if classic["supported"] and ble["supported"]:
        classification = "dual_mode"
    elif classic["supported"]:
        classification = "classic_only"
    elif ble["supported"]:
        classification = "ble_only"
    else:
        classification = "undetermined"

    observations = [
        f"adapter={hci}",
        f"classic_supported={str(classic['supported']).lower()}",
        f"ble_supported={str(ble['supported']).lower()}",
        f"classification={classification}",
    ]
    observations.extend(f"classic_signal={signal}" for signal in classic["signals"])
    observations.extend(f"ble_signal={signal}" for signal in ble["signals"])

    return {
        "classification": classification,
        "adapter": hci,
        "adapter_ready": True,
        "classic": classic,
        "ble": ble,
        "observations": observations,
    }


def _first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
