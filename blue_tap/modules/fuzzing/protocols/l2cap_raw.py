"""Raw L2CAP frame builders and fuzz test cases for below-stack injection.

These frames are sent via DarkFirmware's raw ACL injection (HCIVSCSocket.send_raw_acl),
bypassing BlueZ entirely.  The controller encrypts and transmits whatever payload is
provided — no L2CAP validation occurs.  This enables injection of malformed frames
that BlueZ would normally drop before they leave the host.

Ported from DarkFirmware's l2cap_fuzzer.py (15 test cases).
"""

from __future__ import annotations

import os
import struct


# ---------------------------------------------------------------------------
# L2CAP frame builders
# ---------------------------------------------------------------------------

def build_l2cap(cid: int, payload: bytes = b"") -> bytes:
    """Build an L2CAP frame: [length:2B LE] [CID:2B LE] [payload]."""
    return struct.pack("<HH", len(payload), cid) + payload


def build_l2cap_signaling(code: int, identifier: int, data: bytes = b"") -> bytes:
    """Build an L2CAP signaling command on CID 0x0001.

    Signaling format: [code:1B] [identifier:1B] [length:2B LE] [data]
    """
    sig = struct.pack("<BBH", code, identifier, len(data)) + data
    return build_l2cap(0x0001, sig)


def build_l2cap_echo_req(identifier: int = 0x01, data: bytes = b"PING") -> bytes:
    """Build L2CAP Echo Request (signaling CID 0x0001, code 0x08)."""
    return build_l2cap_signaling(0x08, identifier, data)


def build_l2cap_conn_req(psm: int, scid: int, identifier: int = 0x01) -> bytes:
    """Build L2CAP Connection Request (code 0x02)."""
    data = struct.pack("<HH", psm, scid)
    return build_l2cap_signaling(0x02, identifier, data)


def build_l2cap_config_req(dcid: int, flags: int = 0, identifier: int = 0x01) -> bytes:
    """Build L2CAP Configuration Request (code 0x04)."""
    data = struct.pack("<HH", dcid, flags)
    return build_l2cap_signaling(0x04, identifier, data)


def build_l2cap_disconn_req(dcid: int, scid: int, identifier: int = 0x01) -> bytes:
    """Build L2CAP Disconnection Request (code 0x06)."""
    data = struct.pack("<HH", dcid, scid)
    return build_l2cap_signaling(0x06, identifier, data)


def build_l2cap_info_req(info_type: int, identifier: int = 0x01) -> bytes:
    """Build L2CAP Information Request (code 0x0A)."""
    data = struct.pack("<H", info_type)
    return build_l2cap_signaling(0x0A, identifier, data)


# ---------------------------------------------------------------------------
# CID constants
# ---------------------------------------------------------------------------

CID_SIGNALING = 0x0001      # L2CAP Signaling
CID_CONNLESS = 0x0002       # Connectionless reception
CID_AMP = 0x0003            # AMP Manager
CID_ATT = 0x0004            # Attribute Protocol (BLE)
CID_LE_SIGNALING = 0x0005   # LE L2CAP Signaling
CID_SMP = 0x0006            # Security Manager Protocol
CID_BR_SMP = 0x0007         # BR/EDR Security Manager


# ---------------------------------------------------------------------------
# Fuzz test cases — malformed L2CAP frames
# ---------------------------------------------------------------------------

L2CAP_RAW_FUZZ_TESTS: list[dict] = [
    {
        "name": "zero_length_l2cap",
        "desc": "L2CAP with length=0",
        "frame": build_l2cap(CID_SIGNALING, b""),
    },
    {
        "name": "max_length_l2cap",
        "desc": "L2CAP claiming 0xFFFF length with short payload",
        "frame": struct.pack("<HH", 0xFFFF, CID_SIGNALING) + b"\x01\x02\x03\x04",
    },
    {
        "name": "bad_cid_zero",
        "desc": "CID=0 (reserved/invalid)",
        "frame": build_l2cap(0x0000, b"\x01\x02\x03\x04"),
    },
    {
        "name": "bad_cid_0002",
        "desc": "CID=0x0002 (connectionless reception)",
        "frame": build_l2cap(CID_CONNLESS, b"\x01\x02\x03\x04"),
    },
    {
        "name": "bad_cid_ffff",
        "desc": "CID=0xFFFF (maximum)",
        "frame": build_l2cap(0xFFFF, b"\x01\x02\x03\x04"),
    },
    {
        "name": "smp_on_classic",
        "desc": "SMP (CID 0x0006) on Classic BR/EDR connection",
        "frame": build_l2cap(CID_SMP, b"\x01\x00"),
    },
    {
        "name": "truncated_l2cap_header",
        "desc": "Only 2 bytes (missing CID field)",
        "frame": b"\x04\x00",
    },
    {
        "name": "signaling_bad_code",
        "desc": "Invalid signaling command code 0xFF",
        "frame": build_l2cap_signaling(0xFF, 0x01, b"\x00\x00"),
    },
    {
        "name": "signaling_truncated",
        "desc": "Truncated L2CAP signaling (header only, no data)",
        "frame": build_l2cap(CID_SIGNALING, b"\x08\x01"),
    },
    {
        "name": "echo_oversized",
        "desc": "L2CAP Echo Request with 500 bytes data",
        "frame": build_l2cap_echo_req(data=os.urandom(500)),
    },
    {
        "name": "info_req_invalid_type",
        "desc": "Information Request with invalid type 0xFFFF",
        "frame": build_l2cap_info_req(0xFFFF),
    },
    {
        "name": "conn_req_psm_zero",
        "desc": "Connection Request with PSM=0 (invalid)",
        "frame": build_l2cap_conn_req(psm=0, scid=0x0040),
    },
    {
        "name": "conn_req_psm_sdp",
        "desc": "Connection Request for SDP (PSM 0x0001)",
        "frame": build_l2cap_conn_req(psm=1, scid=0x0041),
    },
    {
        "name": "config_req_no_conn",
        "desc": "Config Request for nonexistent channel 0xFFFF",
        "frame": build_l2cap_config_req(dcid=0xFFFF),
    },
    {
        "name": "disconnect_req_invalid",
        "desc": "Disconnect Request for invalid DCID/SCID",
        "frame": build_l2cap_disconn_req(dcid=0xFFFF, scid=0xFFFF),
    },
]


def _frames_matching(prefixes: tuple[str, ...]) -> list[bytes]:
    """Return raw L2CAP frames whose test names begin with *prefixes*."""
    frames: list[bytes] = []
    for case in L2CAP_RAW_FUZZ_TESTS:
        name = str(case.get("name", ""))
        if any(name.startswith(prefix) for prefix in prefixes):
            frame = case.get("frame", b"")
            if isinstance(frame, bytes):
                frames.append(frame)
    return frames


def fuzz_raw_cid_manipulation() -> list[bytes]:
    """Malformed raw frames that target CID parsing and dispatch."""
    return _frames_matching(
        (
            "zero_length_l2cap",
            "max_length_l2cap",
            "bad_cid_",
            "smp_on_classic",
            "truncated_l2cap_header",
        )
    )


def fuzz_raw_config_signaling() -> list[bytes]:
    """Connection/config/disconnect state-machine frames on CID 0x0001."""
    return _frames_matching(("conn_req_", "config_req_", "disconnect_req_"))


def fuzz_raw_echo_requests() -> list[bytes]:
    """Echo/signaling header mismatch cases for the raw ACL path."""
    cases = _frames_matching(("echo_", "signaling_truncated"))
    cases.extend(
        [
            build_l2cap(CID_SIGNALING, struct.pack("<BBH", 0x08, 0x01, 0xFFFF) + b"PING"),
            build_l2cap(CID_SIGNALING, struct.pack("<BBH", 0x08, 0x01, 0x0000) + b"PING"),
        ]
    )
    return cases


def fuzz_raw_info_requests() -> list[bytes]:
    """Information-request oriented raw signaling frames."""
    return _frames_matching(("info_req_",))


def generate_all_l2cap_sig_fuzz_cases() -> list[bytes]:
    """Return full BR/EDR signaling-channel L2CAP frames for raw ACL injection."""
    cases: list[bytes] = []
    seen: set[bytes] = set()
    for group in (
        fuzz_raw_cid_manipulation(),
        fuzz_raw_config_signaling(),
        fuzz_raw_echo_requests(),
        fuzz_raw_info_requests(),
        [case["frame"] for case in L2CAP_RAW_FUZZ_TESTS if isinstance(case.get("frame"), bytes)],
    ):
        for frame in group:
            if frame not in seen:
                seen.add(frame)
                cases.append(frame)
    return cases
