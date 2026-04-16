"""VulnscanModule — Module wrapper for the vulnerability scanner.

This module wraps the existing run_vulnerability_scan function to enable
invocation via `blue-tap run assessment.vulnscan RHOST=...`.

Future work (Phase 6.6-6.7): Refactor to iterate the registry and invoke
individual CVE modules via the Invoker rather than calling check functions
directly.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptBool, OptString
from blue_tap.framework.registry import ModuleFamily

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class VulnscanModule(Module):
    """Full vulnerability and attack-surface scan.

    Runs all CVE and non-CVE assessment checks against a target device.
    Individual checks can be run via `blue-tap run assessment.cve_XXXX`.
    """

    module_id = "assessment.vulnscan_meta"
    family = ModuleFamily.ASSESSMENT
    name = "Vulnerability Scanner"
    description = "Run all CVE probes and non-CVE posture checks against a target"
    protocols = (
        "Classic", "BLE", "L2CAP", "SDP", "GATT", "RFCOMM", "BNEP", "HID",
        "SMP", "AVRCP", "A2MP", "EATT", "HFP", "ACL",
    )
    requires = ("adapter", "classic_target")
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.vulnscan.result"
    has_report_adapter = True
    category = "scanner"
    references = ()

    options = (
        OptAddress("RHOST", required=True, description="Target BR/EDR or BLE address"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptBool("ACTIVE", default=False, description="Run active/destructive probes"),
        OptAddress("PHONE", default="", description="Phone address for BIAS probe"),
    )

    def run(self, ctx: RunContext) -> dict:
        """Execute the full vulnerability scan."""
        from blue_tap.modules.assessment.vuln_scanner import run_vulnerability_scan

        target = ctx.options.get("RHOST", "")
        hci = ctx.options.get("HCI", "")
        active = ctx.options.get("ACTIVE", False)
        phone = ctx.options.get("PHONE") or None

        logger.info(
            "VulnscanModule.run: target=%s, hci=%s, active=%s",
            target, hci, active,
        )

        return run_vulnerability_scan(
            address=target,
            hci=hci,
            active=active,
            phone_address=phone,
        )
