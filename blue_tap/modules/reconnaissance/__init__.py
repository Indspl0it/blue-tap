"""Deep per-target enumeration, fingerprinting, service mapping, and protocol surface analysis."""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry

_registry = get_registry()


def _register_once(descriptor: ModuleDescriptor) -> None:
    try:
        _registry.get(descriptor.module_id)
    except KeyError:
        _registry.register(descriptor)


# ── Public modules ────────────────────────────────────────────────────────────

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.campaign",
        family=ModuleFamily.RECONNAISSANCE,
        name="Auto Recon Campaign",
        description="Orchestrate full per-target recon: SDP, GATT, fingerprint, L2CAP, RFCOMM, HCI capture",
        protocols=("Classic", "BLE", "SDP", "GATT", "L2CAP", "RFCOMM"),
        requires=("adapter", "target"),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.campaign:run_auto_recon",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.sdp",
        family=ModuleFamily.RECONNAISSANCE,
        name="SDP Service Discovery",
        description="Enumerate SDP service records and decode attributes",
        protocols=("Classic", "SDP", "L2CAP"),
        requires=("classic_target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.sdp:SDPScanner",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.gatt",
        family=ModuleFamily.RECONNAISSANCE,
        name="GATT Enumeration",
        description="Walk the GATT attribute tree and decode service/characteristic UUIDs",
        protocols=("BLE", "GATT", "ATT"),
        requires=("ble_target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.gatt:GATTEnumerator",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.fingerprint",
        family=ModuleFamily.RECONNAISSANCE,
        name="Device Fingerprinting",
        description="Infer chipset, firmware, and OS from LMP and GATT feature bits",
        protocols=("Classic", "BLE", "LMP", "GATT"),
        requires=("target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.fingerprint:fingerprint_device",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.l2cap_scan",
        family=ModuleFamily.RECONNAISSANCE,
        name="L2CAP Channel Scan",
        description="Probe L2CAP PSM space and classify open channels",
        protocols=("Classic", "L2CAP"),
        requires=("classic_target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.l2cap_scan:scan_l2cap",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.rfcomm_scan",
        family=ModuleFamily.RECONNAISSANCE,
        name="RFCOMM Channel Scan",
        description="Probe RFCOMM server channels and detect exposed profiles",
        protocols=("Classic", "RFCOMM"),
        requires=("classic_target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=True,
        entry_point="blue_tap.modules.reconnaissance.rfcomm_scan:scan_rfcomm",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.hci_capture",
        family=ModuleFamily.RECONNAISSANCE,
        name="HCI Capture",
        description="Record HCI traffic to pcap for offline analysis",
        protocols=("Classic", "BLE", "HCI"),
        requires=("adapter",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.hci_capture:HCICapture",
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.sniffer",
        family=ModuleFamily.RECONNAISSANCE,
        name="Bluetooth Sniffer",
        description="Capture BR/EDR or BLE air traffic via nRF or combined interface",
        protocols=("Classic", "BLE"),
        requires=("sniffer_adapter",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.sniffer:BluetoothSniffer",
    )
)

# ── Internal modules (hidden from list-modules) ───────────────────────────────

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.capability_detector",
        family=ModuleFamily.RECONNAISSANCE,
        name="Capability Detector",
        description="Infer protocol capability support from observed traffic",
        protocols=("Classic", "BLE"),
        requires=("target",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.capability_detector:CapabilityDetector",
        internal=True,
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.capture_analysis",
        family=ModuleFamily.RECONNAISSANCE,
        name="Capture Analysis",
        description="Analyze pcap captures for SMP keys and pairing signals",
        protocols=("Classic", "BLE"),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.capture_analysis:analyze_pcap",
        internal=True,
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.correlation",
        family=ModuleFamily.RECONNAISSANCE,
        name="Recon Correlation",
        description="Correlate multi-source recon findings into unified device model",
        protocols=("Classic", "BLE"),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.correlation:correlate_findings",
        internal=True,
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.prerequisites",
        family=ModuleFamily.RECONNAISSANCE,
        name="Recon Prerequisites",
        description="Check tooling prerequisites before running recon",
        protocols=(),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.prerequisites:check_prerequisites",
        internal=True,
    )
)

_register_once(
    ModuleDescriptor(
        module_id="reconnaissance.spec_interpretation",
        family=ModuleFamily.RECONNAISSANCE,
        name="Spec Interpretation",
        description="Map raw Bluetooth spec values to human-readable descriptions",
        protocols=("Classic", "BLE"),
        requires=(),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.recon.result",
        has_report_adapter=False,
        entry_point="blue_tap.modules.reconnaissance.spec_interpretation:interpret_features",
        internal=True,
    )
)
