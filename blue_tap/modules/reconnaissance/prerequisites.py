"""Prerequisite evaluation for recon collectors.

Owns ``evaluate_recon_prerequisites`` (consumed by recon campaign
orchestration) plus the native internal ``PrerequisitesModule``.
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
from blue_tap.framework.module.options import OptChoice, OptString
from blue_tap.framework.registry import ModuleFamily
from blue_tap.modules.reconnaissance.sniffer import DarkFirmwareSniffer, NRFBLESniffer
from blue_tap.utils.bt_helpers import check_tool, ensure_adapter_ready

logger = logging.getLogger(__name__)


def evaluate_recon_prerequisites(
    *,
    target_capability: str,
    classic_adapter: str = "",
    below_hci_adapter: str = "hci1",
) -> dict[str, Any]:
    classic_ready = ensure_adapter_ready(classic_adapter)
    hci_capture_available = check_tool("btmon")
    nrf_available = NRFBLESniffer.is_available()
    darkfirmware_available = DarkFirmwareSniffer(hci_dev=_normalize_hci_index(below_hci_adapter)).is_available()

    nrf_applicable = target_capability in {"ble_only", "dual_mode"}
    dark_applicable = target_capability in {"classic_only", "dual_mode"}
    checks = {
        "classic_adapter_ready": {
            "available": classic_ready,
            "applicable": True,
            "reason": "" if classic_ready else f"{classic_adapter} not ready",
        },
        "hci_capture": {
            "available": hci_capture_available,
            "applicable": True,
            "reason": "" if hci_capture_available else "btmon not installed",
        },
        "nrf_ble_sniffer": {
            "available": nrf_available and nrf_applicable,
            "applicable": nrf_applicable,
            "reason": _nrf_reason(nrf_available, target_capability),
        },
        "darkfirmware_lmp": {
            "available": darkfirmware_available and dark_applicable,
            "applicable": dark_applicable,
            "reason": _darkfirmware_reason(darkfirmware_available, target_capability, below_hci_adapter),
        },
    }
    checks["combined_capture"] = {
        "available": checks["nrf_ble_sniffer"]["available"] and checks["darkfirmware_lmp"]["available"],
        "applicable": nrf_applicable and dark_applicable,
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


# ── Native Module class ─────────────────────────────────────────────────────

class PrerequisitesModule(Module):
    """Recon Prerequisites (internal).

    Evaluate whether the operator's environment has the tooling required
    for a given recon capability target (``classic_only``, ``ble_only``,
    or ``dual_mode``). Calls ``evaluate_recon_prerequisites`` in this
    same file.
    """

    module_id = "reconnaissance.prerequisites"
    family = ModuleFamily.RECONNAISSANCE
    name = "Recon Prerequisites"
    description = "Check tooling and adapter prerequisites for recon"
    protocols = ()
    requires = ()
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = False
    internal = True
    references = ()
    options = (
        OptChoice(
            "CAPABILITY",
            choices=("classic_only", "ble_only", "dual_mode"),
            default="dual_mode",
            description="Target capability profile to evaluate against",
        ),
        OptString("CLASSIC_HCI", default="", description="Classic BT adapter"),
        OptString("BELOW_HCI", default="hci1", description="Below-HCI (DarkFirmware) adapter"),
    )

    def run(self, ctx: RunContext) -> dict:
        capability = str(ctx.options.get("CAPABILITY", "dual_mode"))
        classic_hci = str(ctx.options.get("CLASSIC_HCI", ""))
        below_hci = str(ctx.options.get("BELOW_HCI", "hci1"))
        started_at = ctx.started_at

        error_msg: str | None = None
        checks: dict = {}
        try:
            checks = evaluate_recon_prerequisites(
                target_capability=capability,
                classic_adapter=classic_hci,
                below_hci_adapter=below_hci,
            )
        except Exception as exc:
            logger.exception("Prerequisite evaluation failed")
            error_msg = str(exc)

        missing = [
            name for name, item in checks.items()
            if isinstance(item, dict)
            and item.get("applicable", True)
            and not item.get("available", False)
        ]
        all_present = bool(checks) and not missing

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        elif all_present:
            execution_status = "completed"
            outcome = "observed"
        else:
            execution_status = "completed"
            outcome = "partial"

        summary_text = (
            f"Prerequisite error: {error_msg}"
            if error_msg
            else (
                "All prerequisites met"
                if all_present
                else f"Missing {len(missing)} item(s): {', '.join(missing)}"
            )
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            module_id=self.module_id,
            target="",
            adapter=classic_hci,
            started_at=started_at,
            executions=[
                make_execution(
                    module_id="reconnaissance.prerequisites",
                    execution_id="prereq_check",
                    kind="check",
                    id="prereq_check",
                    title="Prerequisites Check",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "capability": capability,
                            "missing_count": len(missing),
                            "all_present": all_present,
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
                "all_present": all_present,
                "missing": missing,
                "capability": capability,
                "error": error_msg,
            },
            module_data={"checks": checks},
            run_id=ctx.run_id,
        )
