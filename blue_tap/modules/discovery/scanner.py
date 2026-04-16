"""Discovery scanner — native Module.

Discovers nearby Classic and BLE devices by delegating to the real scanner
implementations in ``blue_tap.hardware.scanner``. There is no wrapper layer:
this file is the home of ``ScannerModule``, and it is the sole entry point
for the ``discovery.scanner`` module_id.
"""

from __future__ import annotations

import logging

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptBool, OptInt, OptString
from blue_tap.framework.registry import ModuleFamily

logger = logging.getLogger(__name__)


class ScannerModule(Module):
    """Bluetooth Scanner.

    Discover nearby Classic and BLE devices via HCI inquiry and LE scan.
    The MODE option selects which scan to run (classic | ble | all).
    """

    module_id = "discovery.scanner"
    family = ModuleFamily.DISCOVERY
    name = "Bluetooth Scanner"
    description = "Discover nearby Classic and BLE devices via HCI inquiry and LE scan"
    protocols = ("Classic", "BLE")
    requires = ("adapter",)
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.scan.result"
    has_report_adapter = True
    references = ()
    options = (
        OptString("HCI", default="", description="Local HCI adapter"),
        OptString("MODE", default="all", description="Scan mode: classic|ble|all"),
        OptInt("DURATION", default=10, description="Scan duration in seconds"),
        OptBool(
            "PASSIVE",
            default=False,
            description="Use passive scanning for BLE (no scan requests)",
        ),
    )

    def run(self, ctx: RunContext) -> dict:
        """Execute the Bluetooth device scan end-to-end.

        Uses the lower-level scan functions (device-list returning) so this
        module builds exactly one RunEnvelope. The *_result hardware helpers
        already build their own envelopes internally — using them here would
        produce a double-wrapped result.

        On hardware error, returns an envelope with ``execution_status="failed"``
        and ``module_outcome="not_applicable"`` instead of raising.
        """
        from blue_tap.hardware.scanner import (
            scan_all,
            scan_ble_sync,
            scan_classic,
        )

        hci = ctx.options.get("HCI", "")
        mode = str(ctx.options.get("MODE", "all")).lower()
        duration = ctx.options.get("DURATION", 10)
        passive = ctx.options.get("PASSIVE", False)
        started_at = ctx.started_at

        devices: list[dict]
        execution_status: str
        error_msg: str | None = None

        try:
            if mode == "classic":
                devices = scan_classic(duration=duration, hci=hci)
            elif mode == "ble":
                devices = scan_ble_sync(duration=duration, passive=passive, adapter=hci)
            else:
                devices = scan_all(duration=duration, hci=hci)
            execution_status = "completed"
        except Exception as exc:
            logger.exception("Bluetooth scan failed (mode=%s, hci=%s)", mode, hci)
            error_msg = str(exc)
            devices = []
            execution_status = "failed"

        # Hardware scanner returns type as "Classic" / "BLE" (title/upper case)
        classic_count = sum(1 for d in devices if str(d.get("type", "")).lower() == "classic")
        ble_count = sum(1 for d in devices if str(d.get("type", "")).lower() == "ble")
        total_count = len(devices)

        # Discovery family outcomes: observed / merged / correlated / partial / not_applicable
        if error_msg is not None:
            # Scan attempted but hardware/driver failure — partial, not "not_applicable"
            outcome = "partial"
        elif total_count > 0:
            outcome = "observed"
        else:
            outcome = "not_applicable"

        summary_text = (
            f"Scan failed: {error_msg}"
            if error_msg
            else f"Found {total_count} devices ({classic_count} Classic, {ble_count} BLE)"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            target="",
            adapter=hci,
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="scan",
                    kind="collector",
                    id="scan",
                    title=f"Bluetooth Scan ({mode})",
                    module=self.module_id,
                    module_id=self.module_id,
                    protocol="Discovery",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "total": total_count,
                            "classic": classic_count,
                            "ble": ble_count,
                            "mode": mode,
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
                "device_count": total_count,
                "classic_count": classic_count,
                "ble_count": ble_count,
                "mode": mode,
                "error": error_msg,
            },
            module_data={"devices": devices, "scan_mode": mode},
            run_id=ctx.run_id,
        )
