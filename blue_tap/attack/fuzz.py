"""Backward compatibility shim -- imports from blue_tap.fuzz.legacy.

The original fuzzer classes have been moved to blue_tap.fuzz.legacy as part
of the protocol-aware fuzzer rewrite.  This module re-exports them so
existing code that imports from blue_tap.attack.fuzz continues to work.

For new fuzzing work, use ``blue-tap fuzz campaign`` or import directly
from ``blue_tap.fuzz.engine``.
"""

from blue_tap.fuzz.legacy import (
    L2CAPFuzzer,
    RFCOMMFuzzer,
    SDPFuzzer,
    bss_wrapper,
    _check_target_alive,
)

__all__ = ["L2CAPFuzzer", "RFCOMMFuzzer", "SDPFuzzer", "bss_wrapper", "_check_target_alive"]
