"""RFCOMM frame builder and fuzz case generator.

Raw RFCOMM frame construction for protocol-aware fuzzing. Frames are sent
via L2CAP PSM 0x0003 to bypass the kernel RFCOMM layer, allowing direct
manipulation of frame fields (address, control, length, FCS).

RFCOMM is based on 3GPP TS 07.10 (GSM MUX). Frame format:
  Address (1) + Control (1) + Length (1-2) + Information (0-N) + FCS (1)

Multiplexer commands (PN, MSC, RPN, RLS, Test) are sent on DLCI 0 as UIH
frames with their own TLV-like encoding in the information field.

This module provides:
  - GSM 07.10 CRC-8 table and FCS calculator
  - Address byte, length field, and complete frame builders
  - Convenience builders for SABM, UA, DM, DISC, UIH frames
  - Multiplexer command builders (PN, MSC, RPN, RLS, Test)
  - Fuzz case generators for FCS, length, control bytes, DLCIs, and sequences

Reference: Bluetooth Core Spec v5.4, Vol 3, Part D (RFCOMM) / 3GPP TS 07.10
"""

from __future__ import annotations

import struct


# ---------------------------------------------------------------------------
# RFCOMM Frame Types (Control byte values)
# With P/F (Poll/Final) bit set (bit 4)
# ---------------------------------------------------------------------------

RFCOMM_SABM = 0x3F      # Set Asynchronous Balanced Mode (P/F set)
RFCOMM_UA = 0x73         # Unnumbered Acknowledgement (P/F set)
RFCOMM_DM = 0x1F         # Disconnected Mode (P/F set)
RFCOMM_DISC = 0x53       # Disconnect (P/F set)
RFCOMM_UIH = 0xFF        # Unnumbered Information with Header check (P/F set)

# Without P/F bit
RFCOMM_SABM_NP = 0x2F
RFCOMM_UA_NP = 0x63
RFCOMM_DM_NP = 0x0F
RFCOMM_DISC_NP = 0x43
RFCOMM_UIH_NP = 0xEF

# All valid control byte values (with and without P/F)
_VALID_CONTROL_BYTES = frozenset({
    RFCOMM_SABM, RFCOMM_UA, RFCOMM_DM, RFCOMM_DISC, RFCOMM_UIH,
    RFCOMM_SABM_NP, RFCOMM_UA_NP, RFCOMM_DM_NP, RFCOMM_DISC_NP, RFCOMM_UIH_NP,
})

# Frame types that use FCS over Address + Control + Length (not just Address + Control)
_FCS_OVER_ALL = frozenset({
    RFCOMM_SABM, RFCOMM_UA, RFCOMM_DM, RFCOMM_DISC,
    RFCOMM_SABM_NP, RFCOMM_UA_NP, RFCOMM_DM_NP, RFCOMM_DISC_NP,
})

# Human-readable names for logging/reporting
FRAME_TYPE_NAMES: dict[int, str] = {
    RFCOMM_SABM: "SABM",
    RFCOMM_UA: "UA",
    RFCOMM_DM: "DM",
    RFCOMM_DISC: "DISC",
    RFCOMM_UIH: "UIH",
    RFCOMM_SABM_NP: "SABM(NP)",
    RFCOMM_UA_NP: "UA(NP)",
    RFCOMM_DM_NP: "DM(NP)",
    RFCOMM_DISC_NP: "DISC(NP)",
    RFCOMM_UIH_NP: "UIH(NP)",
}


# ---------------------------------------------------------------------------
# Multiplexer Command Types
# Sent on DLCI 0 as UIH frames. Format: type(1) + length(1-2) + value(N)
# Type byte: command_type << 2 | EA << 1 | C/R
# EA=1 (single byte type), C/R=1 (command) or 0 (response)
# ---------------------------------------------------------------------------

MUX_PN = 0x83            # Parameter Negotiation (0x20 << 2 | 0x02 | 0x01)
MUX_MSC = 0xE3           # Modem Status Command (0x38 << 2 | 0x02 | 0x01)
MUX_RPN = 0x93           # Remote Port Negotiation (0x24 << 2 | 0x02 | 0x01)
MUX_RLS = 0x53           # Remote Line Status (0x14 << 2 | 0x02 | 0x01)
MUX_TEST = 0x23          # Test Command (0x08 << 2 | 0x02 | 0x01)
MUX_FCON = 0xA3          # Flow Control On (0x28 << 2 | 0x02 | 0x01)
MUX_FCOFF = 0x63         # Flow Control Off (0x18 << 2 | 0x02 | 0x01)
MUX_NSC = 0x13           # Non-Supported Command (0x04 << 2 | 0x02 | 0x01)

MUX_COMMAND_NAMES: dict[int, str] = {
    MUX_PN: "PN",
    MUX_MSC: "MSC",
    MUX_RPN: "RPN",
    MUX_RLS: "RLS",
    MUX_TEST: "Test",
    MUX_FCON: "FCon",
    MUX_FCOFF: "FCoff",
    MUX_NSC: "NSC",
}


# ---------------------------------------------------------------------------
# CRC-8 Table for GSM 07.10 FCS Calculation
# Polynomial: x^8 + x^2 + x + 1 (0x07, reversed: 0xE0)
# This is the standard reversed-bit CRC table used by RFCOMM/TS 07.10.
# ---------------------------------------------------------------------------

CRC_TABLE: tuple[int, ...] = (
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
)


def calculate_fcs(data: bytes) -> int:
    """Calculate the RFCOMM Frame Check Sequence (CRC-8) per GSM 07.10.

    The FCS is computed as 0xFF minus the CRC remainder after processing
    all input bytes through the CRC-8 table.

    For SABM/UA/DM/DISC frames: FCS covers Address + Control + Length bytes.
    For UIH frames: FCS covers Address + Control only (NOT Length or Info).

    Args:
        data: Bytes to compute FCS over (caller must select the right fields).

    Returns:
        Single-byte FCS value (0x00-0xFF).
    """
    fcs = 0xFF
    for b in data:
        fcs = CRC_TABLE[fcs ^ b]
    return 0xFF - fcs


# ===========================================================================
# Frame Component Builders
# ===========================================================================

def build_address(dlci: int, cr: int = 1, ea: int = 1) -> int:
    """Build an RFCOMM address byte.

    Address byte layout:
      Bit 0:    EA (Extension bit) -- always 1 for RFCOMM
      Bit 1:    C/R (Command/Response)
      Bits 2-7: DLCI (Data Link Connection Identifier)

    Args:
        dlci: DLCI value (0-63). DLCI 0 = mux control, 2-61 = data channels.
        cr: Command/Response bit (1 = command, 0 = response).
        ea: Extension bit (always 1 for RFCOMM, included for fuzz flexibility).

    Returns:
        Single address byte value.
    """
    return ((dlci & 0x3F) << 2) | ((cr & 0x01) << 1) | (ea & 0x01)


def build_length(length: int) -> bytes:
    """Build an RFCOMM length field (1 or 2 bytes).

    Length encoding:
      - If bit 0 (EA) = 1: single byte, length in bits 1-7 (max 127)
      - If bit 0 (EA) = 0: two bytes, length in bits 1-15 (max 32767)

    Args:
        length: Payload length in bytes (0-32767).

    Returns:
        1 or 2 bytes encoding the length with EA bit.
    """
    if length <= 127:
        return bytes([(length << 1) | 0x01])
    else:
        return bytes([(length << 1) & 0xFE, (length >> 7) & 0xFF])


# ===========================================================================
# Complete Frame Builders
# ===========================================================================

def build_rfcomm_frame(
    dlci: int,
    control: int,
    information: bytes = b"",
    fcs: int | None = None,
) -> bytes:
    """Build a complete RFCOMM frame with address, control, length, info, and FCS.

    Frame format:
      Address (1) + Control (1) + Length (1-2) + Information (0-N) + FCS (1)

    FCS calculation differs by frame type:
      - SABM/UA/DM/DISC: FCS over Address + Control + Length
      - UIH: FCS over Address + Control only

    Args:
        dlci: DLCI for the address byte (0-63).
        control: Control byte value (RFCOMM_SABM, RFCOMM_UIH, etc.).
        information: Payload data bytes.
        fcs: Override FCS value. If None, calculates the correct FCS.
             Provide an explicit value for fuzzing incorrect checksums.

    Returns:
        Complete RFCOMM frame bytes ready to send over L2CAP PSM 3.
    """
    addr = build_address(dlci)
    length_bytes = build_length(len(information))
    frame_body = bytes([addr, control]) + length_bytes + information

    if fcs is None:
        if control in _FCS_OVER_ALL:
            # FCS over address + control + length
            fcs = calculate_fcs(bytes([addr, control]) + length_bytes)
        else:
            # UIH: FCS over address + control only
            fcs = calculate_fcs(bytes([addr, control]))

    return frame_body + bytes([fcs])


def build_sabm(dlci: int) -> bytes:
    """Build a SABM (Set Asynchronous Balanced Mode) frame with P/F bit set.

    SABM is used to establish a connection on a DLCI. The P bit is always
    set for SABM frames.

    Args:
        dlci: DLCI to open (0 for mux control, 2-61 for data channels).

    Returns:
        Complete SABM frame with correct FCS.
    """
    return build_rfcomm_frame(dlci, RFCOMM_SABM)


def build_ua(dlci: int) -> bytes:
    """Build a UA (Unnumbered Acknowledgement) response frame.

    UA acknowledges SABM or DISC frames. The F bit is set to match
    the P bit in the received command.

    Args:
        dlci: DLCI being acknowledged.

    Returns:
        Complete UA frame with correct FCS.
    """
    return build_rfcomm_frame(dlci, RFCOMM_UA)


def build_disc(dlci: int) -> bytes:
    """Build a DISC (Disconnect) frame.

    DISC requests disconnection of the specified DLCI. The P bit is
    always set.

    Args:
        dlci: DLCI to disconnect.

    Returns:
        Complete DISC frame with correct FCS.
    """
    return build_rfcomm_frame(dlci, RFCOMM_DISC)


def build_dm(dlci: int) -> bytes:
    """Build a DM (Disconnected Mode) response frame.

    DM indicates that the specified DLCI is not open or the connection
    has been refused.

    Args:
        dlci: DLCI for the DM response.

    Returns:
        Complete DM frame with correct FCS.
    """
    return build_rfcomm_frame(dlci, RFCOMM_DM)


def build_uih(dlci: int, data: bytes = b"") -> bytes:
    """Build a UIH (Unnumbered Information with Header check) data frame.

    UIH carries user data on established DLCIs. FCS covers only the
    address and control bytes (not the information field), allowing
    data to be processed even if the info payload is corrupted.

    Args:
        dlci: DLCI to send data on.
        data: Payload data bytes.

    Returns:
        Complete UIH frame with correct FCS.
    """
    return build_rfcomm_frame(dlci, RFCOMM_UIH, data)


def build_uih_with_credits(dlci: int, data: bytes = b"", credits: int = 0) -> bytes:
    """Build a UIH frame with credit-based flow control.

    When credit-based flow control is negotiated (via PN), the UIH frame
    includes a 1-byte credits field between the length and information fields.
    The P/F bit in the control byte is set to indicate credits are present.

    Frame format with credits:
      Address (1) + Control=0xFF (1) + Length (1-2) + Credits (1) + Info (N) + FCS (1)

    Args:
        dlci: DLCI to send data on.
        data: Payload data bytes.
        credits: Number of credits to grant (0-255).

    Returns:
        Complete UIH frame with credits field and correct FCS.
    """
    addr = build_address(dlci)
    # Length covers credits byte + data
    length_bytes = build_length(len(data) + 1)
    fcs = calculate_fcs(bytes([addr, RFCOMM_UIH]))

    return (
        bytes([addr, RFCOMM_UIH])
        + length_bytes
        + bytes([credits & 0xFF])
        + data
        + bytes([fcs])
    )


# ===========================================================================
# Multiplexer Command Builders (DLCI 0 UIH frames)
# ===========================================================================

def _build_mux_length(length: int) -> bytes:
    """Build a multiplexer command length field (1 or 2 bytes).

    Same encoding as RFCOMM length: EA bit in bit 0.

    Args:
        length: Value length in bytes.

    Returns:
        1 or 2 bytes encoding the length.
    """
    if length <= 127:
        return bytes([(length << 1) | 0x01])
    else:
        return bytes([(length << 1) & 0xFE, (length >> 7) & 0xFF])


def build_mux_command(type_byte: int, length: int, data: bytes) -> bytes:
    """Build a multiplexer command message (sent as UIH payload on DLCI 0).

    Multiplexer command format:
      Type (1) + Length (1-2) + Value (N)

    The command is then wrapped in a UIH frame on DLCI 0 by the caller
    or by the convenience builders below.

    Args:
        type_byte: Command type byte (MUX_PN, MUX_MSC, etc.).
        length: Length field value. If different from len(data), creates
                a length mismatch for fuzzing.
        data: Command-specific value bytes.

    Returns:
        Raw multiplexer command bytes (NOT wrapped in UIH frame).
    """
    return bytes([type_byte]) + _build_mux_length(length) + data


def build_pn(
    dlci: int,
    cl: int = 0xE0,
    priority: int = 0,
    frame_size: int = 127,
    credits: int = 7,
) -> bytes:
    """Build a Parameter Negotiation (PN) multiplexer command as a UIH frame.

    PN is used to negotiate DLCI parameters before opening a channel with SABM.
    The PN value is 8 bytes:
      DLCI (1) + CL (1) + Priority (1) + Timer (1) + Frame Size (2 LE) + N1 (1) + Credits (1)

    Args:
        dlci: DLCI to negotiate parameters for.
        cl: Convergence layer byte (0xE0 = credit-based flow control).
        priority: Priority level (0-63).
        frame_size: Maximum frame size in bytes (little-endian uint16).
        credits: Initial credit count.

    Returns:
        Complete UIH frame on DLCI 0 containing the PN command.
    """
    pn_data = struct.pack(
        "<BBBBHBB",
        dlci & 0x3F,       # DLCI
        cl & 0xFF,          # Convergence Layer
        priority & 0xFF,    # Priority
        0x00,               # Timer T1 (not used in BT)
        frame_size & 0xFFFF,  # Max frame size (LE)
        0x00,               # N2 retransmissions (not used)
        credits & 0xFF,     # Initial credits
    )
    mux_cmd = build_mux_command(MUX_PN, len(pn_data), pn_data)
    return build_uih(0, mux_cmd)


def build_msc(
    dlci: int,
    fc: bool = False,
    rtc: bool = True,
    rtr: bool = True,
    ic: bool = False,
    dv: bool = True,
) -> bytes:
    """Build a Modem Status Command (MSC) as a UIH frame on DLCI 0.

    MSC carries virtual modem signals for a data channel. The V.24 signals
    byte layout:
      Bit 0: EA (always 1)
      Bit 1: FC (Flow Control)
      Bit 2: RTC (Ready To Communicate)
      Bit 3: RTR (Ready To Receive)
      Bit 4: Reserved (0)
      Bit 5: Reserved (0)
      Bit 6: IC (Incoming Call)
      Bit 7: DV (Data Valid)

    Args:
        dlci: DLCI this MSC applies to.
        fc: Flow Control signal.
        rtc: Ready To Communicate signal.
        rtr: Ready To Receive signal.
        ic: Incoming Call indicator.
        dv: Data Valid signal.

    Returns:
        Complete UIH frame on DLCI 0 containing the MSC command.
    """
    # Address byte for the DLCI within the MSC (EA=1, C/R=1)
    dlci_byte = ((dlci & 0x3F) << 2) | 0x02 | 0x01

    signals = (
        0x01  # EA bit
        | ((1 if fc else 0) << 1)
        | ((1 if rtc else 0) << 2)
        | ((1 if rtr else 0) << 3)
        | ((1 if ic else 0) << 6)
        | ((1 if dv else 0) << 7)
    )

    msc_data = bytes([dlci_byte, signals])
    mux_cmd = build_mux_command(MUX_MSC, len(msc_data), msc_data)
    return build_uih(0, mux_cmd)


def build_rpn(
    dlci: int,
    baud_rate: int = 3,
    data_bits: int = 3,
    stop_bits: int = 0,
    parity: int = 0,
    parity_type: int = 0,
) -> bytes:
    """Build a Remote Port Negotiation (RPN) command as a UIH frame on DLCI 0.

    RPN negotiates serial port parameters (baud rate, data bits, etc.) for
    a virtual serial port on the specified DLCI.

    Args:
        dlci: DLCI for port negotiation.
        baud_rate: Baud rate index (0=2400, 1=4800, 2=7200, 3=9600, 4=19200,
                   5=38400, 6=57600, 7=115200, 8=230400).
        data_bits: Data bits (0=5, 1=6, 2=7, 3=8).
        stop_bits: Stop bits (0=1, 1=1.5).
        parity: Parity enable (0=none, 1=enabled).
        parity_type: Parity type (0=odd, 1=even, 2=mark, 3=space).

    Returns:
        Complete UIH frame on DLCI 0 containing the RPN command.
    """
    dlci_byte = ((dlci & 0x3F) << 2) | 0x02 | 0x01

    # Line settings byte: data_bits(2) | stop_bits(1) | parity(1) | parity_type(2)
    line_settings = (
        (data_bits & 0x03)
        | ((stop_bits & 0x01) << 2)
        | ((parity & 0x01) << 3)
        | ((parity_type & 0x03) << 4)
    )

    rpn_data = bytes([
        dlci_byte,
        baud_rate & 0xFF,
        line_settings,
        0x00,  # Flow control (none)
        0x00,  # XON char
        0x00,  # XOFF char
        0xFF, 0xFF,  # Parameter mask (all params valid)
    ])
    mux_cmd = build_mux_command(MUX_RPN, len(rpn_data), rpn_data)
    return build_uih(0, mux_cmd)


def build_rls(dlci: int, line_status: int = 0) -> bytes:
    """Build a Remote Line Status (RLS) command as a UIH frame on DLCI 0.

    RLS reports error conditions on a virtual serial port.

    Args:
        dlci: DLCI reporting the line status.
        line_status: Line status byte.
            Bit 0: always 1 (EA)
            Bit 1: Overrun error
            Bit 2: Parity error
            Bit 3: Framing error

    Returns:
        Complete UIH frame on DLCI 0 containing the RLS command.
    """
    dlci_byte = ((dlci & 0x3F) << 2) | 0x02 | 0x01
    rls_data = bytes([dlci_byte, line_status & 0xFF])
    mux_cmd = build_mux_command(MUX_RLS, len(rls_data), rls_data)
    return build_uih(0, mux_cmd)


def build_test(data: bytes = b"") -> bytes:
    """Build a Test command as a UIH frame on DLCI 0.

    The Test command sends data that should be echoed back by the remote end.
    Useful for testing connectivity and also for probing buffer handling
    with various payload sizes.

    Args:
        data: Test pattern data to be echoed.

    Returns:
        Complete UIH frame on DLCI 0 containing the Test command.
    """
    mux_cmd = build_mux_command(MUX_TEST, len(data), data)
    return build_uih(0, mux_cmd)


# ===========================================================================
# Fuzz Generators
# ===========================================================================

def fuzz_fcs() -> list[bytes]:
    """Generate frames with incorrect FCS values.

    Creates SABM and UIH frames with:
      - Correct FCS (baseline)
      - FCS = 0x00 (zeroed)
      - FCS = 0xFF (maxed)
      - FCS with single bit flipped from correct value
      - FCS inverted (bitwise NOT of correct)

    Returns:
        List of raw RFCOMM frame bytes with various FCS manipulations.
    """
    cases: list[bytes] = []

    for dlci in (0, 2):
        # SABM with bad FCS
        correct_sabm = build_sabm(dlci)
        correct_fcs = correct_sabm[-1]

        cases.append(correct_sabm)  # Baseline: correct
        cases.append(build_rfcomm_frame(dlci, RFCOMM_SABM, fcs=0x00))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_SABM, fcs=0xFF))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_SABM, fcs=correct_fcs ^ 0x01))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_SABM, fcs=correct_fcs ^ 0x80))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_SABM, fcs=(~correct_fcs) & 0xFF))

        # UIH with bad FCS
        correct_uih = build_uih(dlci, b"test")
        correct_fcs = correct_uih[-1]

        cases.append(correct_uih)  # Baseline: correct
        cases.append(build_rfcomm_frame(dlci, RFCOMM_UIH, b"test", fcs=0x00))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_UIH, b"test", fcs=0xFF))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_UIH, b"test", fcs=correct_fcs ^ 0x01))
        cases.append(build_rfcomm_frame(dlci, RFCOMM_UIH, b"test", fcs=(~correct_fcs) & 0xFF))

    return cases


def fuzz_length_mismatch() -> list[bytes]:
    """Generate frames where the length field does not match actual data.

    Tests:
      - Length=0 with actual data present
      - Length too short (half of actual)
      - Length too long (claims more than present)
      - Length=0x7FFF (maximum 2-byte value) with minimal data

    Returns:
        List of raw RFCOMM frame bytes with length mismatches.
    """
    cases: list[bytes] = []
    dlci = 2

    # Build a normal UIH frame, then surgically replace the length field
    test_data = b"Hello, World!"  # 13 bytes

    # Length=0 (EA=1) with actual data
    addr = build_address(dlci)
    fcs = calculate_fcs(bytes([addr, RFCOMM_UIH]))
    cases.append(bytes([addr, RFCOMM_UIH, 0x01]) + test_data + bytes([fcs]))

    # Length=3 (too short) with 13 bytes of data
    cases.append(bytes([addr, RFCOMM_UIH, (3 << 1) | 0x01]) + test_data + bytes([fcs]))

    # Length=200 (too long) with 13 bytes of data
    # 200 > 127, so use 2-byte length encoding
    len_bytes = bytes([(200 << 1) & 0xFE, (200 >> 7) & 0xFF])
    cases.append(bytes([addr, RFCOMM_UIH]) + len_bytes + test_data + bytes([fcs]))

    # Length=0x7FFF (max 2-byte) with 4 bytes of data
    max_len = 0x7FFF
    len_bytes = bytes([(max_len << 1) & 0xFE, (max_len >> 7) & 0xFF])
    cases.append(bytes([addr, RFCOMM_UIH]) + len_bytes + b"test" + bytes([fcs]))

    # Length=0 with no data (minimal frame)
    cases.append(bytes([addr, RFCOMM_UIH, 0x01]) + bytes([fcs]))

    return cases


def fuzz_invalid_control_bytes() -> list[bytes]:
    """Generate frames with control byte values that are not valid RFCOMM types.

    Valid control bytes (with/without P/F) are: SABM, UA, DM, DISC, UIH.
    This generates frames for a selection of invalid values.

    Returns:
        List of raw RFCOMM frame bytes with invalid control bytes.
    """
    cases: list[bytes] = []
    dlci = 2

    # Test a range of invalid control values
    invalid_controls = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x60,
        0x7F, 0x80, 0xA0, 0xC0, 0xFE,
    ]

    for ctrl in invalid_controls:
        if ctrl not in _VALID_CONTROL_BYTES:
            cases.append(build_rfcomm_frame(dlci, ctrl, b"test"))

    return cases


def fuzz_dlci_range() -> list[bytes]:
    """Generate frames for each frame type across interesting DLCI values.

    Tests boundary DLCIs:
      - 0: Multiplexer control channel
      - 1: Invalid (reserved per RFCOMM, odd DLCIs have restrictions)
      - 2: First valid data channel
      - 31: Mid-range
      - 32: Mid-range boundary
      - 61: Last valid data channel
      - 62: Above valid range
      - 63: Maximum DLCI value

    Returns:
        List of raw RFCOMM frame bytes for each DLCI x frame type combination.
    """
    cases: list[bytes] = []
    dlcis = (0, 1, 2, 31, 32, 61, 62, 63)
    frame_types = (RFCOMM_SABM, RFCOMM_UA, RFCOMM_DM, RFCOMM_DISC, RFCOMM_UIH)

    for dlci in dlcis:
        for ft in frame_types:
            if ft == RFCOMM_UIH:
                cases.append(build_rfcomm_frame(dlci, ft, b"test"))
            else:
                cases.append(build_rfcomm_frame(dlci, ft))

    return cases


def fuzz_pn_params() -> list[bytes]:
    """Generate PN commands with boundary and invalid parameter values.

    Tests:
      - frame_size=0: Zero-byte frames
      - frame_size=0x7FFF: Maximum possible frame size
      - credits=0: No initial credits
      - credits=0xFF: Maximum credit count (uint8)
      - priority=0xFF: Maximum priority value (spec allows 0-63)
      - cl=0x00: No convergence layer
      - cl=0xFF: All bits set

    Returns:
        List of raw RFCOMM frames (UIH on DLCI 0) with PN commands.
    """
    cases: list[bytes] = []

    # Boundary frame sizes
    cases.append(build_pn(2, frame_size=0))
    cases.append(build_pn(2, frame_size=1))
    cases.append(build_pn(2, frame_size=0x7FFF))

    # Boundary credits
    cases.append(build_pn(2, credits=0))
    cases.append(build_pn(2, credits=0xFF))

    # Invalid priority (spec: 0-63)
    cases.append(build_pn(2, priority=0xFF))

    # Convergence layer values
    cases.append(build_pn(2, cl=0x00))
    cases.append(build_pn(2, cl=0xFF))

    # All extreme values combined
    cases.append(build_pn(2, cl=0xFF, priority=0xFF, frame_size=0x7FFF, credits=0xFF))
    cases.append(build_pn(2, cl=0x00, priority=0x00, frame_size=0, credits=0))

    # PN on DLCI 0 (mux control -- normally you negotiate data DLCIs)
    cases.append(build_pn(0, frame_size=127))

    # PN on high DLCIs
    cases.append(build_pn(61, frame_size=127))
    cases.append(build_pn(63, frame_size=127))

    return cases


def fuzz_msc_signals() -> list[bytes]:
    """Generate MSC commands with all combinations of modem status signals.

    There are 5 boolean signals (FC, RTC, RTR, IC, DV) = 32 combinations.
    Tests whether the receiver handles each signal combination correctly.

    Returns:
        List of raw RFCOMM frames (UIH on DLCI 0) with MSC commands.
    """
    cases: list[bytes] = []

    # All 32 combinations of the 5 signals
    for bits in range(32):
        fc = bool(bits & 0x01)
        rtc = bool(bits & 0x02)
        rtr = bool(bits & 0x04)
        ic = bool(bits & 0x08)
        dv = bool(bits & 0x10)
        cases.append(build_msc(2, fc=fc, rtc=rtc, rtr=rtr, ic=ic, dv=dv))

    # MSC on DLCI 0 (should only be for data channels)
    cases.append(build_msc(0))

    # MSC on unopened high DLCIs
    cases.append(build_msc(61))
    cases.append(build_msc(63))

    return cases


def fuzz_rapid_sabm() -> list[bytes]:
    """Generate multiple SABM frames without waiting for UA response.

    Tests how the receiver handles rapid connection attempts. The frames
    are returned as a list that should be sent in quick succession.

    Patterns:
      - Multiple SABMs on the same DLCI
      - SABMs on different DLCIs without prior PN
      - SABM on DLCI 0 (must be opened first per spec)

    Returns:
        List of SABM frame bytes to send in rapid succession.
    """
    cases: list[bytes] = []

    # 10 rapid SABMs on the same channel
    for _ in range(10):
        cases.append(build_sabm(2))

    # SABMs on sequential DLCIs without PN
    for dlci in range(2, 20):
        cases.append(build_sabm(dlci))

    # SABM on DLCI 0 repeated (mux control)
    for _ in range(5):
        cases.append(build_sabm(0))

    return cases


def fuzz_data_without_sabm() -> list[bytes]:
    """Generate UIH data frames on channels that were never opened.

    Sends data on DLCIs without prior SABM/UA handshake. Tests whether
    the receiver validates channel state before accepting data.

    Returns:
        List of UIH frame bytes for unopened channels.
    """
    cases: list[bytes] = []

    # Data on various unopened DLCIs
    for dlci in (2, 5, 10, 31, 61):
        cases.append(build_uih(dlci, b"data on unopened channel"))
        cases.append(build_uih(dlci, b"\x00" * 127))  # Max single-byte length

    # Mux commands on DLCI 0 without DLCI 0 being opened
    cases.append(build_pn(2))
    cases.append(build_msc(2))

    return cases


def fuzz_double_disc() -> list[bytes]:
    """Generate DISC frames for channels that may already be disconnected.

    Sends DISC followed by another DISC on the same DLCI. Tests double-free
    or use-after-free vulnerabilities in connection teardown.

    Returns:
        List of DISC frame pairs to send sequentially.
    """
    cases: list[bytes] = []

    for dlci in (0, 2, 5, 31):
        # Two consecutive DISCs on the same channel
        cases.append(build_disc(dlci))
        cases.append(build_disc(dlci))

    # DISC on never-opened channel
    for dlci in (10, 61, 63):
        cases.append(build_disc(dlci))

    return cases


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_rfcomm_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all RFCOMM fuzz payloads.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a raw byte sequence suitable for sending over L2CAP PSM 3.

    Returns:
        List of fuzz case bytes. Typical count: ~200-300 cases depending
        on configuration.
    """
    cases: list[bytes] = []

    # FCS manipulation
    cases.extend(fuzz_fcs())

    # Length field mismatches
    cases.extend(fuzz_length_mismatch())

    # Invalid control bytes
    cases.extend(fuzz_invalid_control_bytes())

    # DLCI range for all frame types
    cases.extend(fuzz_dlci_range())

    # PN parameter boundary values
    cases.extend(fuzz_pn_params())

    # MSC signal combinations
    cases.extend(fuzz_msc_signals())

    # Rapid SABM without UA
    cases.extend(fuzz_rapid_sabm())

    # Data on unopened channels
    cases.extend(fuzz_data_without_sabm())

    # Double disconnect
    cases.extend(fuzz_double_disc())

    return cases
