"""Vulnerability and posture checks."""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry

_registry = get_registry()

def _register_once(descriptor: ModuleDescriptor) -> None:
    try:
        _registry.get(descriptor.module_id)
    except KeyError:
        _registry.register(descriptor)


_register_once(
    ModuleDescriptor(
        module_id="assessment.vuln_scanner",
        family=ModuleFamily.ASSESSMENT,
        name="Vulnerability Scanner",
        description="CVE and non-CVE vulnerability assessment with structured evidence",
        protocols=("Classic", "BLE", "L2CAP", "SDP", "GATT", "RFCOMM", "BNEP", "HID", "SMP"),
        requires=("adapter", "classic_target"),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.vulnscan.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.assessment.vuln_scanner:VulnScannerModule",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="assessment.fleet",
        family=ModuleFamily.ASSESSMENT,
        name="Fleet Assessment",
        description="Scan, classify, and assess nearby targets at fleet scope",
        protocols=("Classic", "BLE", "SDP", "GATT", "RFCOMM"),
        requires=("adapter", "scan_target_set"),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.fleet.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.assessment.fleet:FleetModule",
    )
)

# Import checks files to trigger auto-registration of native Module subclasses
from blue_tap.modules.assessment.checks import (  # noqa: F401
    cve_sdp,
    cve_l2cap,
    cve_bnep,
    cve_avrcp,
    cve_gatt,
    cve_airoha,
    cve_ble_smp,
    cve_pairing,
    cve_hid,
    cve_raw_acl,
    non_cve_ble,
    non_cve_rfcomm,
    non_cve_posture,
)

# Import vulnscan meta-module for auto-registration
from blue_tap.modules.assessment import vulnscan_module as _vulnscan_module  # noqa: F401
