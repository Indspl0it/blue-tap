"""Protocol-aware Bluetooth fuzzing package.

NOTE: Legacy ModuleDescriptor registrations have been removed. All fuzzing
modules are now registered via Module subclass auto-registration when the
modules package is imported.
"""

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

# Import native Module files to trigger auto-registration via __init_subclass__
# Former wrapper layer (modules/fuzzing/modules/) was collapsed on 2026-04-12
from blue_tap.modules.fuzzing import campaign as _campaign  # noqa: F401
from blue_tap.modules.fuzzing import minimizer as _minimizer_mod  # noqa: F401
from blue_tap.modules.fuzzing import transport as _transport_mod  # noqa: F401

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
