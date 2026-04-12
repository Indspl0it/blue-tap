"""Target discovery and inventory collection."""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry

_registry = get_registry()


def _register_once(descriptor: ModuleDescriptor) -> None:
    try:
        _registry.get(descriptor.module_id)
    except KeyError:
        _registry.register(descriptor)


_register_once(
    ModuleDescriptor(
        module_id="discovery.scanner",
        family=ModuleFamily.DISCOVERY,
        name="Bluetooth Scanner",
        description="Discover nearby Classic and BLE devices via HCI inquiry and LE scan",
        protocols=("Classic", "BLE"),
        requires=("adapter",),
        destructive=False,
        requires_pairing=False,
        schema_prefix="blue_tap.scan.result",
        has_report_adapter=True,
        entry_point="blue_tap.hardware.scanner:BluetoothScanner",
    )
)
