"""Target transport capability detection for reconnaissance workflows.

Owns ``detect_target_capabilities`` (used by recon campaign orchestration)
plus the native internal ``CapabilityDetectorModule``.
"""

from __future__ import annotations

import logging
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptString
from blue_tap.framework.registry import ModuleFamily
from blue_tap.modules.reconnaissance.gatt import enumerate_services_detailed_sync
from blue_tap.modules.reconnaissance.sdp import browse_services
from blue_tap.utils.bt_helpers import ensure_adapter_ready, run_cmd

logger = logging.getLogger(__name__)


def detect_target_capabilities(address: str, hci: str | None = None) -> dict[str, Any]:
    """Determine whether a target supports BR/EDR, BLE, or both.

    The detector intentionally uses low-cost probes first and preserves
    the evidence behind the final classification so recon automation can
    explain why steps were executed or skipped.
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
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


# ── Native Module class ─────────────────────────────────────────────────────

class CapabilityDetectorModule(Module):
    """Capability Detector (internal).

    Decide whether a target supports BR/EDR, BLE, or both. Delegates to the
    ``detect_target_capabilities`` helper in this same file. This is an
    internal module used primarily by recon campaign orchestration; it is
    hidden from the default ``list-modules`` output.
    """

    module_id = "reconnaissance.capability_detector"
    family = ModuleFamily.RECONNAISSANCE
    name = "Capability Detector"
    description = "Decide if a target supports BR/EDR, BLE, or both"
    protocols = ("Classic", "BLE")
    requires = ("target",)
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = False
    internal = True
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target Bluetooth address"),
        OptString("HCI", default="", description="Local HCI adapter"),
    )

    def run(self, ctx: RunContext) -> dict:
        target = str(ctx.options.get("RHOST", ""))
        hci = str(ctx.options.get("HCI", ""))
        started_at = ctx.started_at

        error_msg: str | None = None
        result: dict = {}
        try:
            result = detect_target_capabilities(target, hci=hci)
            if not isinstance(result, dict):
                result = {"classification": "undetermined", "raw": result}
        except Exception as exc:
            logger.exception("Capability detection failed for %s", target)
            error_msg = str(exc)
            result = {"classification": "undetermined", "error": error_msg}

        classification = str(result.get("classification", "undetermined"))
        classic_supported = bool((result.get("classic") or {}).get("supported", False))
        ble_supported = bool((result.get("ble") or {}).get("supported", False))

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        elif classic_supported or ble_supported:
            execution_status = "completed"
            outcome = "observed"
        else:
            execution_status = "completed"
            outcome = "partial" if classification != "undetermined" else "not_applicable"

        summary_text = (
            f"Capability detection error: {error_msg}"
            if error_msg
            else f"Classification: {classification} (classic={classic_supported}, ble={ble_supported})"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module="capability_detector",
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="capability_detect",
                    kind="collector",
                    id="capability_detect",
                    title="Capability Detection",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "classification": classification,
                            "classic": classic_supported,
                            "ble": ble_supported,
                            "error": error_msg,
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "classification": classification,
                "classic": classic_supported,
                "ble": ble_supported,
                "error": error_msg,
            },
            module_data=result,
            run_id=ctx.run_id,
        )
