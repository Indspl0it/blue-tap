"""Protocol-aware Bluetooth fuzzer package.

Provides transport abstractions, crash database, mutation engines,
protocol builders, and campaign orchestration for multi-hour fuzzing
campaigns against Bluetooth stack implementations.
"""

from bt_tap.fuzz.transport import (
    BluetoothTransport,
    L2CAPTransport,
    RFCOMMTransport,
    BLETransport,
    TransportStats,
)
from bt_tap.fuzz.crash_db import (
    CrashDB,
    CrashSeverity,
    CrashType,
)
from bt_tap.fuzz.mutators import (
    FieldMutator,
    IntegerMutator,
    LengthMutator,
    PacketField,
    ProtocolMutator,
    CorpusMutator,
    MutationLog,
)
from bt_tap.fuzz.corpus import (
    Corpus,
    CorpusStats,
)
from bt_tap.fuzz.engine import (
    FuzzCampaign,
    CampaignStats,
    parse_duration,
    PROTOCOL_TRANSPORT_MAP,
)
from bt_tap.fuzz.minimizer import (
    BinarySearchReducer,
    DeltaDebugReducer,
    FieldReducer,
    CrashMinimizer,
    MinimizationResult,
)

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
