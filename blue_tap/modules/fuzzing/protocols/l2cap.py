"""L2CAP signaling packet builder, fuzz case generator, and Scapy transport.

Constructs well-formed and malformed L2CAP signaling commands for protocol-aware
fuzzing.  All multi-byte fields are little-endian per Bluetooth Core Spec Vol 3,
Part A (L2CAP).

L2CAP signaling uses CID 0x0001 (BR/EDR) or 0x0005 (BLE LE).  The signaling
command header is 4 bytes:
  Code (1) + Identifier (1) + Length (2 LE)

This module provides:
  - Signaling command constants and builders
  - Configuration option encoders (MTU, flush timeout, QoS, FCS)
  - Fuzz case generators for CID manipulation, config option attacks,
    Echo flooding, and Info request probing
  - ScapyL2CAPTransport for raw frame injection (optional scapy dependency)

Reference: Bluetooth Core Spec v5.4, Vol 3, Part A (L2CAP)
CVE targets: CVE-2017-0781 (Android BNEP via L2CAP), CVE-2020-0022 (BlueFrag)
"""

from __future__ import annotations

import logging
import struct

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# L2CAP Signaling Command Codes (Bluetooth Core Spec Vol 3, Part A, Sec 4)
# ---------------------------------------------------------------------------

L2CAP_CMD_REJECT           = 0x01
L2CAP_CONN_REQ             = 0x02
L2CAP_CONN_RSP             = 0x03
L2CAP_CONF_REQ             = 0x04
L2CAP_CONF_RSP             = 0x05
L2CAP_DISCONN_REQ          = 0x06
L2CAP_DISCONN_RSP          = 0x07
L2CAP_ECHO_REQ             = 0x08
L2CAP_ECHO_RSP             = 0x09
L2CAP_INFO_REQ             = 0x0A
L2CAP_INFO_RSP             = 0x0B
L2CAP_CONN_PARAM_UPDATE_REQ = 0x12
L2CAP_CONN_PARAM_UPDATE_RSP = 0x13
L2CAP_LE_CREDIT_CONN_REQ  = 0x14
L2CAP_LE_CREDIT_CONN_RSP  = 0x15
L2CAP_FLOW_CTRL_CREDIT     = 0x16

CMD_NAMES: dict[int, str] = {
    L2CAP_CMD_REJECT:           "CommandReject",
    L2CAP_CONN_REQ:             "ConnectionRequest",
    L2CAP_CONN_RSP:             "ConnectionResponse",
    L2CAP_CONF_REQ:             "ConfigurationRequest",
    L2CAP_CONF_RSP:             "ConfigurationResponse",
    L2CAP_DISCONN_REQ:          "DisconnectionRequest",
    L2CAP_DISCONN_RSP:          "DisconnectionResponse",
    L2CAP_ECHO_REQ:             "EchoRequest",
    L2CAP_ECHO_RSP:             "EchoResponse",
    L2CAP_INFO_REQ:             "InformationRequest",
    L2CAP_INFO_RSP:             "InformationResponse",
    L2CAP_CONN_PARAM_UPDATE_REQ: "ConnectionParameterUpdateRequest",
    L2CAP_CONN_PARAM_UPDATE_RSP: "ConnectionParameterUpdateResponse",
    L2CAP_LE_CREDIT_CONN_REQ:  "LECreditConnectionRequest",
    L2CAP_LE_CREDIT_CONN_RSP:  "LECreditConnectionResponse",
    L2CAP_FLOW_CTRL_CREDIT:     "FlowControlCredit",
}


# ---------------------------------------------------------------------------
# Well-known PSM values
# ---------------------------------------------------------------------------

PSM_SDP    = 0x0001
PSM_RFCOMM = 0x0003
PSM_BNEP   = 0x000F
PSM_HID_CTRL = 0x0011
PSM_HID_INTR = 0x0013
PSM_AVCTP  = 0x0017
PSM_AVDTP  = 0x0019
PSM_ATT    = 0x001F

ALL_PSMS: list[int] = [
    PSM_SDP, PSM_RFCOMM, PSM_BNEP, PSM_HID_CTRL,
    PSM_HID_INTR, PSM_AVCTP, PSM_AVDTP, PSM_ATT,
]


# ---------------------------------------------------------------------------
# Fixed L2CAP CIDs
# ---------------------------------------------------------------------------

CID_SIGNALING      = 0x0001
CID_CONNECTIONLESS = 0x0002
CID_AMP_MANAGER    = 0x0003
CID_BLE_ATT        = 0x0004
CID_BLE_SIGNALING  = 0x0005
CID_BLE_SMP        = 0x0006
CID_BREDR_SMP      = 0x0007


# ---------------------------------------------------------------------------
# L2CAP Configuration Option Types
# ---------------------------------------------------------------------------

L2CAP_OPT_MTU            = 0x01
L2CAP_OPT_FLUSH_TIMEOUT  = 0x02
L2CAP_OPT_QOS            = 0x03
L2CAP_OPT_RETRANSMISSION = 0x04
L2CAP_OPT_FCS            = 0x05
L2CAP_OPT_EXT_FLOW_SPEC  = 0x06
L2CAP_OPT_EXT_WINDOW     = 0x07


# ===========================================================================
# Signaling Command Builders
# ===========================================================================

def build_signaling_cmd(code: int, identifier: int, data: bytes) -> bytes:
    """Build a single L2CAP signaling command (4-byte header + data).

    Args:
        code: Command code (0x01-0x16).
        identifier: Request/response identifier (non-zero for requests).
        data: Command-specific payload.

    Returns:
        Raw signaling command bytes.
    """
    return struct.pack("<BBH", code, identifier, len(data)) + data


def build_l2cap_frame(cid: int, payload: bytes) -> bytes:
    """Build a complete L2CAP Basic frame (4-byte header + payload).

    L2CAP Basic header:
      Length (2 LE) + CID (2 LE) + payload

    Args:
        cid: Channel ID (0x0001 for signaling, dynamic for connections).
        payload: L2CAP information payload.

    Returns:
        Complete L2CAP frame bytes.
    """
    return struct.pack("<HH", len(payload), cid) + payload


def build_signaling_frame(code: int, identifier: int, data: bytes) -> bytes:
    """Build a complete L2CAP signaling frame (L2CAP header + command).

    Convenience function combining build_l2cap_frame and build_signaling_cmd.
    Uses CID 0x0001 (BR/EDR signaling).
    """
    cmd = build_signaling_cmd(code, identifier, data)
    return build_l2cap_frame(CID_SIGNALING, cmd)


# ===========================================================================
# Specific Command Builders
# ===========================================================================

def build_conn_req(psm: int, scid: int, identifier: int = 1) -> bytes:
    """Build L2CAP Connection Request (code 0x02).

    Args:
        psm: Protocol/Service Multiplexer.
        scid: Source Channel ID (local channel).
        identifier: Command identifier.
    """
    data = struct.pack("<HH", psm, scid)
    return build_signaling_cmd(L2CAP_CONN_REQ, identifier, data)


def build_conn_rsp(
    dcid: int,
    scid: int,
    result: int = 0,
    status: int = 0,
    identifier: int = 1,
) -> bytes:
    """Build L2CAP Connection Response (code 0x03).

    Args:
        dcid: Destination Channel ID (remote's source CID).
        scid: Source Channel ID (our local CID).
        result: Connection result (0=success, 1=pending, 2=PSM not supported, etc).
        status: Status if result is pending.
        identifier: Command identifier.
    """
    data = struct.pack("<HHHH", dcid, scid, result, status)
    return build_signaling_cmd(L2CAP_CONN_RSP, identifier, data)


def build_conf_req(
    dcid: int,
    flags: int = 0,
    options: bytes = b"",
    identifier: int = 1,
) -> bytes:
    """Build L2CAP Configuration Request (code 0x04).

    Args:
        dcid: Destination CID of the channel being configured.
        flags: Configuration flags (bit 0 = continuation).
        options: Encoded configuration option TLVs.
        identifier: Command identifier.
    """
    data = struct.pack("<HH", dcid, flags) + options
    return build_signaling_cmd(L2CAP_CONF_REQ, identifier, data)


def build_disconn_req(dcid: int, scid: int, identifier: int = 1) -> bytes:
    """Build L2CAP Disconnection Request (code 0x06).

    Args:
        dcid: Destination Channel ID.
        scid: Source Channel ID.
        identifier: Command identifier.
    """
    data = struct.pack("<HH", dcid, scid)
    return build_signaling_cmd(L2CAP_DISCONN_REQ, identifier, data)


def build_echo_req(echo_data: bytes = b"", identifier: int = 1) -> bytes:
    """Build L2CAP Echo Request (code 0x08).

    Args:
        echo_data: Optional echo payload (reflected in Echo Response).
        identifier: Command identifier.
    """
    return build_signaling_cmd(L2CAP_ECHO_REQ, identifier, echo_data)


def build_info_req(info_type: int, identifier: int = 1) -> bytes:
    """Build L2CAP Information Request (code 0x0A).

    Args:
        info_type: Information type (1=Connectionless MTU, 2=Extended Features,
                   3=Fixed Channels Supported).
        identifier: Command identifier.
    """
    data = struct.pack("<H", info_type)
    return build_signaling_cmd(L2CAP_INFO_REQ, identifier, data)


# ===========================================================================
# Configuration Option Encoders
# ===========================================================================

def encode_opt_mtu(mtu: int) -> bytes:
    """Encode MTU configuration option (type 0x01, length 2)."""
    return struct.pack("<BBH", L2CAP_OPT_MTU, 2, mtu)


def encode_opt_flush_timeout(timeout: int) -> bytes:
    """Encode Flush Timeout option (type 0x02, length 2)."""
    return struct.pack("<BBH", L2CAP_OPT_FLUSH_TIMEOUT, 2, timeout)


def encode_opt_fcs(fcs_type: int) -> bytes:
    """Encode FCS option (type 0x05, length 1). 0=No FCS, 1=16-bit FCS."""
    return struct.pack("<BBB", L2CAP_OPT_FCS, 1, fcs_type)


def encode_opt_unknown(opt_type: int, data: bytes) -> bytes:
    """Encode an arbitrary configuration option (for fuzzing unknown types).

    The length field is a single byte, so it is clamped to 255.  When data
    exceeds 255 bytes, the length field reports 255 but the full data follows
    -- this is intentional for fuzzing (creates a length-mismatch fuzz case).
    """
    length = min(len(data), 255)
    return struct.pack("<BB", opt_type, length) + data


# ===========================================================================
# Fuzz Case Generators
# ===========================================================================

# ---------------------------------------------------------------------------
# Config option fuzz cases
# ---------------------------------------------------------------------------

def fuzz_config_options() -> list[bytes]:
    """Generate L2CAP Configuration Request fuzz cases with malformed options.

    Targets:
      - MTU boundary values (0, 1, 47, 48, 0xFFFF)
      - Oversized option length fields
      - Unknown option types
      - Nested/repeated options
      - Truncated options (length exceeds data)
      - Zero-length options
    """
    cases: list[bytes] = []
    dcid = 0x0040  # Typical first dynamic CID

    # MTU boundary values
    for mtu in (0, 1, 23, 47, 48, 672, 0x7FFF, 0xFFFF):
        cases.append(build_conf_req(dcid, options=encode_opt_mtu(mtu)))

    # Flush timeout boundaries
    for timeout in (0, 1, 0x7FFF, 0xFFFF):
        cases.append(build_conf_req(dcid, options=encode_opt_flush_timeout(timeout)))

    # FCS option with invalid values
    for fcs in (0, 1, 2, 0xFF):
        cases.append(build_conf_req(dcid, options=encode_opt_fcs(fcs)))

    # Unknown option types (0x08-0xFF)
    for opt_type in (0x08, 0x10, 0x20, 0x40, 0x80, 0xFE, 0xFF):
        cases.append(build_conf_req(
            dcid, options=encode_opt_unknown(opt_type, b"\x41\x42\x43\x44"),
        ))

    # Oversized option: length says 255 but only 4 bytes follow
    cases.append(build_conf_req(
        dcid, options=struct.pack("<BB", L2CAP_OPT_MTU, 0xFF) + b"\x00\x01\x00\x02",
    ))

    # Zero-length option
    cases.append(build_conf_req(
        dcid, options=struct.pack("<BB", L2CAP_OPT_MTU, 0),
    ))

    # Repeated MTU options (conflicting values)
    cases.append(build_conf_req(
        dcid,
        options=encode_opt_mtu(48) + encode_opt_mtu(0xFFFF) + encode_opt_mtu(0),
    ))

    # Many options at once
    many_opts = b""
    for i in range(50):
        many_opts += encode_opt_unknown(0x80 + (i % 128), b"\xFF" * 4)
    cases.append(build_conf_req(dcid, options=many_opts))

    # Empty config request (no options)
    cases.append(build_conf_req(dcid, options=b""))

    # Config with continuation flag set
    cases.append(build_conf_req(dcid, flags=0x0001, options=encode_opt_mtu(672)))

    return cases


# ---------------------------------------------------------------------------
# CID manipulation fuzz cases
# ---------------------------------------------------------------------------

def fuzz_cid_manipulation() -> list[bytes]:
    """Generate L2CAP commands targeting CID boundary conditions.

    Targets:
      - Reserved CIDs (0x0000, 0x0001-0x003F used as DCID/SCID)
      - Maximum CID values
      - CID zero in connection responses
      - Disconnect with non-existent CIDs
      - Connection requests to fixed CIDs
    """
    cases: list[bytes] = []

    # Connection requests with boundary SCIDs
    for scid in (0x0000, 0x0001, 0x003F, 0x0040, 0x7FFF, 0xFFFF):
        cases.append(build_conn_req(PSM_SDP, scid))

    # Connection requests for each well-known PSM with high SCID
    for psm in ALL_PSMS:
        cases.append(build_conn_req(psm, 0xFFFF))

    # Connection requests with invalid PSMs
    for psm in (0x0000, 0x0002, 0x0004, 0xFFFF, 0xFFFE):
        cases.append(build_conn_req(psm, 0x0040))

    # Connection responses with boundary DCIDs
    for dcid in (0x0000, 0x0001, 0x003F, 0x0040, 0xFFFF):
        cases.append(build_conn_rsp(dcid, 0x0040, result=0))

    # Disconnection with non-existent CIDs
    for dcid, scid in [(0x0000, 0x0000), (0xFFFF, 0xFFFF), (0x0001, 0x0040)]:
        cases.append(build_disconn_req(dcid, scid))

    # Config requests targeting fixed CIDs
    for cid in (CID_SIGNALING, CID_CONNECTIONLESS, CID_BLE_ATT, CID_BLE_SMP):
        cases.append(build_conf_req(cid, options=encode_opt_mtu(672)))

    return cases


# ---------------------------------------------------------------------------
# Echo request fuzz cases
# ---------------------------------------------------------------------------

def fuzz_echo_requests() -> list[bytes]:
    """Generate L2CAP Echo Request fuzz cases.

    Targets:
      - Empty echo data
      - Oversized echo data (trigger buffer allocation)
      - Rapid sequential echoes with incrementing identifiers
      - Echo with maximum payload
    """
    cases: list[bytes] = []

    # Empty echo
    cases.append(build_echo_req(b""))

    # Small echo
    cases.append(build_echo_req(b"PING"))

    # Various sizes
    for size in (64, 128, 256, 512, 1024, 2048):
        cases.append(build_echo_req(b"\x41" * size))

    # Maximum L2CAP payload size echo
    cases.append(build_echo_req(b"\xFF" * 65535))

    # Rapid echoes with different identifiers
    for ident in range(1, 51):
        cases.append(build_echo_req(b"\x42" * 32, identifier=ident))

    return cases


# ---------------------------------------------------------------------------
# Information request fuzz cases
# ---------------------------------------------------------------------------

def fuzz_info_requests() -> list[bytes]:
    """Generate L2CAP Information Request fuzz cases.

    Targets:
      - All valid info types (1=Connectionless MTU, 2=Extended Features, 3=Fixed Channels)
      - Invalid/reserved info types
      - Rapid sequential info requests
    """
    cases: list[bytes] = []

    # Valid info types
    for info_type in (1, 2, 3):
        cases.append(build_info_req(info_type))

    # Invalid info types
    for info_type in (0, 4, 5, 0x00FF, 0x7FFF, 0xFFFF):
        cases.append(build_info_req(info_type))

    # Rapid sequential
    for i in range(1, 21):
        cases.append(build_info_req(2, identifier=i))

    return cases


# ---------------------------------------------------------------------------
# Command Reject fuzz cases
# ---------------------------------------------------------------------------

def fuzz_command_reject() -> list[bytes]:
    """Generate L2CAP Command Reject packets sent TO the target.

    Targets how the target handles receiving reject packets it didn't expect.
    """
    cases: list[bytes] = []

    # Reason: Command not understood (0x0000)
    cases.append(build_signaling_cmd(L2CAP_CMD_REJECT, 1, struct.pack("<H", 0x0000)))

    # Reason: Signaling MTU exceeded (0x0001) + actual MTU
    cases.append(build_signaling_cmd(
        L2CAP_CMD_REJECT, 1, struct.pack("<HH", 0x0001, 48),
    ))

    # Reason: Invalid CID in request (0x0002) + local CID + remote CID
    cases.append(build_signaling_cmd(
        L2CAP_CMD_REJECT, 1, struct.pack("<HHH", 0x0002, 0x0040, 0x0041),
    ))

    # Invalid reason codes
    for reason in (0x0003, 0x00FF, 0xFFFF):
        cases.append(build_signaling_cmd(
            L2CAP_CMD_REJECT, 1, struct.pack("<H", reason),
        ))

    return cases


# ---------------------------------------------------------------------------
# Signaling length mismatch fuzz cases
# ---------------------------------------------------------------------------

def fuzz_signaling_length_mismatch() -> list[bytes]:
    """Generate signaling commands where Length field mismatches actual data.

    Tests:
      - Length claims more data than present
      - Length claims 0 but data present
      - Length = 0xFFFF with minimal data
    """
    cases: list[bytes] = []

    # Normal data for an Echo Request
    echo_data = b"HELLO"

    # Length says 100, only 5 bytes present
    cases.append(struct.pack("<BBH", L2CAP_ECHO_REQ, 1, 100) + echo_data)

    # Length says 0, but data present
    cases.append(struct.pack("<BBH", L2CAP_ECHO_REQ, 1, 0) + echo_data)

    # Length says 0xFFFF, minimal data
    cases.append(struct.pack("<BBH", L2CAP_ECHO_REQ, 1, 0xFFFF) + echo_data)

    # Connection request with truncated data (length says 4, only 2 bytes)
    cases.append(struct.pack("<BBH", L2CAP_CONN_REQ, 1, 4) + b"\x01\x00")

    # Config request with 0 length but options present
    cases.append(struct.pack("<BBH", L2CAP_CONF_REQ, 1, 0)
                 + struct.pack("<HH", 0x0040, 0) + encode_opt_mtu(672))

    return cases


# ---------------------------------------------------------------------------
# Reserved/unknown command codes
# ---------------------------------------------------------------------------

def fuzz_reserved_codes() -> list[bytes]:
    """Generate signaling commands with reserved/undefined command codes.

    Codes 0x00 and 0x17-0xFF are undefined in L2CAP signaling.
    """
    cases: list[bytes] = []
    dummy_data = b"\x00" * 4

    for code in (0x00, 0x17, 0x20, 0x40, 0x80, 0xFE, 0xFF):
        cases.append(build_signaling_cmd(code, 1, dummy_data))

    return cases


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_l2cap_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all L2CAP signaling fuzz payloads.

    Each entry is a raw signaling command suitable for sending over
    L2CAP CID 0x0001 (signaling channel).

    Returns:
        List of fuzz case bytes.
    """
    cases: list[bytes] = []

    cases.extend(fuzz_config_options())
    cases.extend(fuzz_cid_manipulation())
    cases.extend(fuzz_echo_requests())
    cases.extend(fuzz_info_requests())
    cases.extend(fuzz_command_reject())
    cases.extend(fuzz_signaling_length_mismatch())
    cases.extend(fuzz_reserved_codes())

    return cases


# ===========================================================================
# Scapy L2CAP Transport
# ===========================================================================

class ScapyL2CAPTransport:
    """Send raw L2CAP frames via Scapy's Bluetooth layer.

    This bypasses the kernel's L2CAP state machine, allowing injection of
    raw signaling commands, malformed CIDs, and config option manipulation.

    Requires: scapy with bluetooth support (``pip install scapy``)
    Falls back gracefully if scapy is not installed.

    Args:
        target: BD_ADDR of the target device.
        hci: HCI interface to use (default: ``<hciX>``).
        handle: ACL connection handle to use in HCI ACL headers.
            Default is ``0x0040`` (typical first handle assigned by
            the controller).
    """

    AVAILABLE = False  # Set to True if scapy imports succeed

    def __init__(self, target: str, hci: str | None = None, handle: int = 0x0040) -> None:
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        self.target = target
        self.hci = hci
        self._sock = None
        self._handle: int = handle

        if not ScapyL2CAPTransport.AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed or does not have Bluetooth support. "
                "Install with: pip install 'blue-tap[fuzz]' or pip install scapy"
            )

    def connect(self) -> bool:
        """Establish a raw HCI connection to the target.

        Uses Scapy's BluetoothUserSocket or BluetoothHCISocket to get a
        raw HCI handle. Returns True on success.
        """
        try:
            from scapy.layers.bluetooth import BluetoothUserSocket
            self._sock = BluetoothUserSocket(self.hci)
            return True
        except Exception as exc:
            logger.info("BluetoothUserSocket failed for %s: %s", self.hci, exc)

        try:
            from scapy.layers.bluetooth import BluetoothHCISocket
            self._sock = BluetoothHCISocket(self.hci)
            return True
        except Exception as exc:
            logger.info("BluetoothHCISocket failed for %s: %s", self.hci, exc)
            return False

    def send_l2cap_frame(self, cid: int, payload: bytes) -> bool:
        """Send a raw L2CAP frame with arbitrary CID and payload.

        Constructs an HCI ACL data packet wrapping the L2CAP frame and
        sends it through the raw Scapy socket.

        Args:
            cid: L2CAP Channel ID (can be any value, including reserved CIDs).
            payload: Raw L2CAP payload bytes.

        Returns:
            True if the frame was sent successfully.
        """
        if self._sock is None:
            return False

        try:
            from scapy.layers.bluetooth import HCI_Hdr, HCI_ACL_Hdr, L2CAP_Hdr

            l2cap = L2CAP_Hdr(len=len(payload), cid=cid) / payload
            # HCI ACL: PB=0x02 (first automatically flushable), BC=0x00
            acl = HCI_ACL_Hdr(handle=self._handle, PB=0x02, BC=0x00)
            pkt = HCI_Hdr(type=0x02) / acl / l2cap
            self._sock.send(pkt)
            return True
        except Exception as exc:
            logger.info("Failed to send L2CAP frame (CID=0x%04x): %s", cid, exc)
            return False

    def send_config_req(self, dcid: int, options: bytes) -> bool:
        """Send an L2CAP Configuration Request with arbitrary options.

        Args:
            dcid: Destination Channel ID to configure.
            options: Raw configuration option TLV bytes.

        Returns:
            True if sent successfully.
        """
        cmd = build_conf_req(dcid, options=options)
        return self.send_l2cap_frame(CID_SIGNALING, cmd)

    def send_signaling(self, code: int, identifier: int, data: bytes) -> bool:
        """Send a raw L2CAP signaling command.

        Args:
            code: Signaling command code.
            identifier: Command identifier byte.
            data: Command-specific payload bytes.

        Returns:
            True if sent successfully.
        """
        cmd = build_signaling_cmd(code, identifier, data)
        return self.send_l2cap_frame(CID_SIGNALING, cmd)

    def close(self) -> None:
        """Close the raw socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Attempt to import scapy and enable the transport
# ---------------------------------------------------------------------------

try:
    from scapy.layers.bluetooth import (  # noqa: F401
        HCI_Hdr, HCI_ACL_Hdr, L2CAP_Hdr,
    )
    ScapyL2CAPTransport.AVAILABLE = True
except ImportError:
    pass
