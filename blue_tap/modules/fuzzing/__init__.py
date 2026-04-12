"""Protocol-aware Bluetooth fuzzing package."""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry
from blue_tap.modules.fuzzing.transport import (
    BLETransport,
    BluetoothTransport,
    L2CAPTransport,
    RFCOMMTransport,
    TransportStats,
)
from blue_tap.modules.fuzzing.crash_db import CrashDB, CrashSeverity, CrashType
from blue_tap.modules.fuzzing.mutators import (
    CorpusMutator,
    FieldMutator,
    IntegerMutator,
    LengthMutator,
    MutationLog,
    PacketField,
    ProtocolMutator,
)
from blue_tap.modules.fuzzing.corpus import Corpus, CorpusStats
from blue_tap.modules.fuzzing.engine import (
    CampaignStats,
    FuzzCampaign,
    PROTOCOL_TRANSPORT_MAP,
    parse_duration,
)
from blue_tap.modules.fuzzing.minimizer import (
    BinarySearchReducer,
    CrashMinimizer,
    DeltaDebugReducer,
    FieldReducer,
    MinimizationResult,
)

_registry = get_registry()


def _register_once(descriptor: ModuleDescriptor) -> None:
    try:
        _registry.get(descriptor.module_id)
    except KeyError:
        _registry.register(descriptor)


_register_once(ModuleDescriptor(
    module_id="fuzzing.engine",
    family=ModuleFamily.FUZZING,
    name="Fuzz Campaign",
    description="Run multi-protocol Bluetooth fuzzing campaigns with crash tracking",
    protocols=("Classic", "BLE", "L2CAP", "RFCOMM", "SDP", "OBEX", "ATT", "SMP", "BNEP", "LMP"),
    requires=("adapter", "target"),
    destructive=True,
    requires_pairing=False,
    schema_prefix="blue_tap.fuzz.result",
    has_report_adapter=True,
    entry_point="blue_tap.modules.fuzzing.engine:FuzzCampaign",
))
_register_once(ModuleDescriptor(
    module_id="fuzzing.transport",
    family=ModuleFamily.FUZZING,
    name="Fuzz Transport",
    description="Bluetooth transport abstractions for L2CAP, RFCOMM, BLE, and raw ACL fuzzing",
    protocols=("Classic", "BLE", "L2CAP", "RFCOMM", "ATT", "SMP", "LMP"),
    requires=("adapter", "target"),
    destructive=True,
    requires_pairing=False,
    schema_prefix="blue_tap.fuzz.result",
    has_report_adapter=False,
    entry_point="blue_tap.modules.fuzzing.transport:BluetoothTransport",
))
_register_once(ModuleDescriptor(
    module_id="fuzzing.minimizer",
    family=ModuleFamily.FUZZING,
    name="Crash Minimizer",
    description="Minimize fuzzing crash inputs and replay them deterministically",
    protocols=("Classic", "BLE", "L2CAP", "RFCOMM", "OBEX", "SDP", "ATT", "SMP", "BNEP", "LMP"),
    requires=("target",),
    destructive=True,
    requires_pairing=False,
    schema_prefix="blue_tap.fuzz.result",
    has_report_adapter=False,
    entry_point="blue_tap.modules.fuzzing.minimizer:CrashMinimizer",
))

__all__ = [
    "BluetoothTransport",
    "L2CAPTransport",
    "RFCOMMTransport",
    "BLETransport",
    "TransportStats",
    "CrashDB",
    "CrashSeverity",
    "CrashType",
    "FieldMutator",
    "IntegerMutator",
    "LengthMutator",
    "PacketField",
    "ProtocolMutator",
    "CorpusMutator",
    "MutationLog",
    "Corpus",
    "CorpusStats",
    "FuzzCampaign",
    "CampaignStats",
    "parse_duration",
    "PROTOCOL_TRANSPORT_MAP",
    "BinarySearchReducer",
    "DeltaDebugReducer",
    "FieldReducer",
    "CrashMinimizer",
    "MinimizationResult",
]
