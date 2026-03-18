"""BLE SMP (Security Manager Protocol) command builder and fuzz case generator.

Constructs well-formed and malformed SMP commands for protocol-aware fuzzing.
All multi-byte fields are little-endian per Bluetooth Core Spec Vol 3, Part H.

SMP runs on L2CAP CID 0x0006 (LE) or 0x0007 (BR/EDR). Maximum PDU size is
65 bytes (Pairing Public Key). Command format:
  Code (1) + Data (variable, fixed per command type)

This module provides:
  - SMP command code, IO capability, and error constants
  - Command builders for all SMP operations (pairing, key distribution,
    Secure Connections ECDH)
  - Fuzz case generators targeting IO capability validation, key size
    negotiation, AuthReq bit manipulation, invalid ECDH curve points
    (CVE-2018-5383), out-of-sequence attacks, and PDU truncation/extension

Reference: Bluetooth Core Spec v5.4, Vol 3, Part H (SMP)
CVE targets: CVE-2018-5383 (Invalid Curve), CVE-2020-26558 (Passkey Bypass)
"""

from __future__ import annotations

import os
import struct


# ---------------------------------------------------------------------------
# SMP Command Codes (Bluetooth Core Spec Vol 3, Part H, Section 3.3)
# ---------------------------------------------------------------------------

SMP_PAIRING_REQUEST = 0x01
SMP_PAIRING_RESPONSE = 0x02
SMP_PAIRING_CONFIRM = 0x03
SMP_PAIRING_RANDOM = 0x04
SMP_PAIRING_FAILED = 0x05
SMP_ENCRYPTION_INFO = 0x06
SMP_CENTRAL_ID = 0x07
SMP_IDENTITY_INFO = 0x08
SMP_IDENTITY_ADDR_INFO = 0x09
SMP_SIGNING_INFO = 0x0A
SMP_SECURITY_REQUEST = 0x0B
SMP_PAIRING_PUBLIC_KEY = 0x0C
SMP_PAIRING_DHKEY_CHECK = 0x0D
SMP_KEYPRESS_NTF = 0x0E

# Human-readable names for logging/reporting
COMMAND_NAMES: dict[int, str] = {
    SMP_PAIRING_REQUEST: "Pairing Request",
    SMP_PAIRING_RESPONSE: "Pairing Response",
    SMP_PAIRING_CONFIRM: "Pairing Confirm",
    SMP_PAIRING_RANDOM: "Pairing Random",
    SMP_PAIRING_FAILED: "Pairing Failed",
    SMP_ENCRYPTION_INFO: "Encryption Information",
    SMP_CENTRAL_ID: "Central Identification",
    SMP_IDENTITY_INFO: "Identity Information",
    SMP_IDENTITY_ADDR_INFO: "Identity Address Information",
    SMP_SIGNING_INFO: "Signing Information",
    SMP_SECURITY_REQUEST: "Security Request",
    SMP_PAIRING_PUBLIC_KEY: "Pairing Public Key",
    SMP_PAIRING_DHKEY_CHECK: "Pairing DHKey Check",
    SMP_KEYPRESS_NTF: "Keypress Notification",
}

# Set of all defined command codes
DEFINED_COMMANDS: frozenset[int] = frozenset(COMMAND_NAMES.keys())

# Expected PDU sizes (code byte + data) for each command
COMMAND_SIZES: dict[int, int] = {
    SMP_PAIRING_REQUEST: 7,
    SMP_PAIRING_RESPONSE: 7,
    SMP_PAIRING_CONFIRM: 17,
    SMP_PAIRING_RANDOM: 17,
    SMP_PAIRING_FAILED: 2,
    SMP_ENCRYPTION_INFO: 17,
    SMP_CENTRAL_ID: 11,
    SMP_IDENTITY_INFO: 17,
    SMP_IDENTITY_ADDR_INFO: 8,
    SMP_SIGNING_INFO: 17,
    SMP_SECURITY_REQUEST: 2,
    SMP_PAIRING_PUBLIC_KEY: 65,
    SMP_PAIRING_DHKEY_CHECK: 17,
    SMP_KEYPRESS_NTF: 2,
}


# ---------------------------------------------------------------------------
# IO Capabilities (Bluetooth Core Spec Vol 3, Part H, Section 2.3.2)
# ---------------------------------------------------------------------------

IO_DISPLAY_ONLY = 0x00
IO_DISPLAY_YESNO = 0x01
IO_KEYBOARD_ONLY = 0x02
IO_NO_INPUT_OUTPUT = 0x03
IO_KEYBOARD_DISPLAY = 0x04

IO_CAPABILITY_NAMES: dict[int, str] = {
    IO_DISPLAY_ONLY: "DisplayOnly",
    IO_DISPLAY_YESNO: "DisplayYesNo",
    IO_KEYBOARD_ONLY: "KeyboardOnly",
    IO_NO_INPUT_OUTPUT: "NoInputNoOutput",
    IO_KEYBOARD_DISPLAY: "KeyboardDisplay",
}

# Values 0x05-0xFF are reserved (fuzzing targets)
IO_MAX_VALID = 0x04


# ---------------------------------------------------------------------------
# AuthReq Bits (Bluetooth Core Spec Vol 3, Part H, Section 2.3.1)
# ---------------------------------------------------------------------------

AUTH_BONDING_MASK = 0x03       # Bits 0-1: Bonding Flags
AUTH_NO_BONDING = 0x00
AUTH_BONDING = 0x01
AUTH_MITM = 0x04               # Bit 2: MITM protection
AUTH_SC = 0x08                 # Bit 3: Secure Connections
AUTH_KEYPRESS = 0x10           # Bit 4: Keypress notifications
AUTH_CT2 = 0x20                # Bit 5: Cross-Transport Key Derivation (BT 5.0+)
AUTH_RESERVED_MASK = 0xC0      # Bits 6-7: Reserved (must be 0)

# Common AuthReq combinations
AUTH_LEGACY_NO_BOND = 0x00
AUTH_LEGACY_BOND = 0x01
AUTH_LEGACY_BOND_MITM = 0x05
AUTH_SC_BOND = 0x09
AUTH_SC_BOND_MITM = 0x0D
AUTH_SC_BOND_MITM_KEYPRESS = 0x1D


# ---------------------------------------------------------------------------
# Key Distribution Bits (Bluetooth Core Spec Vol 3, Part H, Section 2.4.3)
# ---------------------------------------------------------------------------

KEY_DIST_ENC_KEY = 0x01        # Bit 0: LTK + EDIV + Rand
KEY_DIST_ID_KEY = 0x02         # Bit 1: IRK + BD_ADDR
KEY_DIST_SIGN_KEY = 0x04       # Bit 2: CSRK
KEY_DIST_LINK_KEY = 0x08       # Bit 3: BR/EDR Link Key (SC only)
KEY_DIST_RESERVED_MASK = 0xF0  # Bits 4-7: Reserved

# Common key distribution combinations
KEY_DIST_ALL = KEY_DIST_ENC_KEY | KEY_DIST_ID_KEY | KEY_DIST_SIGN_KEY  # 0x07
KEY_DIST_ALL_WITH_LINK = KEY_DIST_ALL | KEY_DIST_LINK_KEY              # 0x0F


# ---------------------------------------------------------------------------
# OOB Data Flag
# ---------------------------------------------------------------------------

OOB_NOT_PRESENT = 0x00
OOB_PRESENT = 0x01
# Values 0x02-0xFF are reserved (fuzzing targets)


# ---------------------------------------------------------------------------
# Keypress Notification Types (Bluetooth Core Spec Vol 3, Part H, Section 3.5.8)
# ---------------------------------------------------------------------------

KEYPRESS_STARTED = 0x00
KEYPRESS_DIGIT_ENTERED = 0x01
KEYPRESS_DIGIT_ERASED = 0x02
KEYPRESS_CLEARED = 0x03
KEYPRESS_COMPLETED = 0x04
# Values 0x05-0xFF are reserved


# ---------------------------------------------------------------------------
# Pairing Failed Reason Codes (Bluetooth Core Spec Vol 3, Part H, Section 3.5.5)
# ---------------------------------------------------------------------------

SMP_ERR_PASSKEY_ENTRY_FAILED = 0x01
SMP_ERR_OOB_NOT_AVAILABLE = 0x02
SMP_ERR_AUTH_REQUIREMENTS = 0x03
SMP_ERR_CONFIRM_VALUE_FAILED = 0x04
SMP_ERR_PAIRING_NOT_SUPPORTED = 0x05
SMP_ERR_ENC_KEY_SIZE = 0x06
SMP_ERR_CMD_NOT_SUPPORTED = 0x07
SMP_ERR_UNSPECIFIED = 0x08
SMP_ERR_REPEATED_ATTEMPTS = 0x09
SMP_ERR_INVALID_PARAMS = 0x0A
SMP_ERR_DHKEY_CHECK_FAILED = 0x0B
SMP_ERR_NUMERIC_COMPARISON_FAILED = 0x0C
SMP_ERR_BREDR_PAIRING_IN_PROGRESS = 0x0D
SMP_ERR_CT_KEY_DERIVATION_NOT_ALLOWED = 0x0E

FAILURE_REASON_NAMES: dict[int, str] = {
    SMP_ERR_PASSKEY_ENTRY_FAILED: "Passkey Entry Failed",
    SMP_ERR_OOB_NOT_AVAILABLE: "OOB Not Available",
    SMP_ERR_AUTH_REQUIREMENTS: "Authentication Requirements",
    SMP_ERR_CONFIRM_VALUE_FAILED: "Confirm Value Failed",
    SMP_ERR_PAIRING_NOT_SUPPORTED: "Pairing Not Supported",
    SMP_ERR_ENC_KEY_SIZE: "Encryption Key Size",
    SMP_ERR_CMD_NOT_SUPPORTED: "Command Not Supported",
    SMP_ERR_UNSPECIFIED: "Unspecified Reason",
    SMP_ERR_REPEATED_ATTEMPTS: "Repeated Attempts",
    SMP_ERR_INVALID_PARAMS: "Invalid Parameters",
    SMP_ERR_DHKEY_CHECK_FAILED: "DHKey Check Failed",
    SMP_ERR_NUMERIC_COMPARISON_FAILED: "Numeric Comparison Failed",
    SMP_ERR_BREDR_PAIRING_IN_PROGRESS: "BR/EDR Pairing In Progress",
    SMP_ERR_CT_KEY_DERIVATION_NOT_ALLOWED: "CT Key Derivation Not Allowed",
}


# ===========================================================================
# Command Builders — All multi-byte fields are LITTLE-ENDIAN
# ===========================================================================

def build_pairing_request(
    io_cap: int = IO_NO_INPUT_OUTPUT,
    oob: int = OOB_NOT_PRESENT,
    auth_req: int = AUTH_BONDING,
    max_key_size: int = 16,
    init_key_dist: int = KEY_DIST_ALL,
    resp_key_dist: int = KEY_DIST_ALL,
) -> bytes:
    """Build a Pairing Request command (code 0x01).

    Initiates the pairing process. Sent by the initiator (central) to the
    responder (peripheral).

    Args:
        io_cap: IO capability of the initiator (0x00-0x04 valid).
        oob: OOB authentication data flag (0x00 or 0x01).
        auth_req: Authentication requirements bitfield.
        max_key_size: Maximum encryption key size (7-16 valid).
        init_key_dist: Initiator key distribution flags.
        resp_key_dist: Responder key distribution flags.

    Returns:
        7-byte PDU: code(1) + IOCap(1) + OOB(1) + AuthReq(1) +
                    MaxKeySize(1) + InitKeyDist(1) + RespKeyDist(1).
    """
    return struct.pack(
        "BBBBBBB",
        SMP_PAIRING_REQUEST,
        io_cap & 0xFF,
        oob & 0xFF,
        auth_req & 0xFF,
        max_key_size & 0xFF,
        init_key_dist & 0xFF,
        resp_key_dist & 0xFF,
    )


def build_pairing_response(
    io_cap: int = IO_NO_INPUT_OUTPUT,
    oob: int = OOB_NOT_PRESENT,
    auth_req: int = AUTH_BONDING,
    max_key_size: int = 16,
    init_key_dist: int = KEY_DIST_ALL,
    resp_key_dist: int = KEY_DIST_ALL,
) -> bytes:
    """Build a Pairing Response command (code 0x02).

    Sent by the responder (peripheral) after receiving a Pairing Request.

    Args:
        io_cap: IO capability of the responder.
        oob: OOB authentication data flag.
        auth_req: Authentication requirements bitfield.
        max_key_size: Maximum encryption key size.
        init_key_dist: Initiator key distribution flags.
        resp_key_dist: Responder key distribution flags.

    Returns:
        7-byte PDU: code(1) + IOCap(1) + OOB(1) + AuthReq(1) +
                    MaxKeySize(1) + InitKeyDist(1) + RespKeyDist(1).
    """
    return struct.pack(
        "BBBBBBB",
        SMP_PAIRING_RESPONSE,
        io_cap & 0xFF,
        oob & 0xFF,
        auth_req & 0xFF,
        max_key_size & 0xFF,
        init_key_dist & 0xFF,
        resp_key_dist & 0xFF,
    )


def build_pairing_confirm(confirm_value: bytes) -> bytes:
    """Build a Pairing Confirm command (code 0x03).

    Contains the 128-bit confirm value calculated from TK (legacy) or
    ECDH shared secret (Secure Connections).

    Args:
        confirm_value: 16-byte confirm value. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + ConfirmValue(16).
    """
    padded = confirm_value[:16].ljust(16, b"\x00")
    return bytes([SMP_PAIRING_CONFIRM]) + padded


def build_pairing_random(random_value: bytes) -> bytes:
    """Build a Pairing Random command (code 0x04).

    Contains the 128-bit random value used to compute the confirm value.
    The receiving side verifies the confirm using this random.

    Args:
        random_value: 16-byte random value. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + RandomValue(16).
    """
    padded = random_value[:16].ljust(16, b"\x00")
    return bytes([SMP_PAIRING_RANDOM]) + padded


def build_pairing_failed(reason: int = SMP_ERR_UNSPECIFIED) -> bytes:
    """Build a Pairing Failed command (code 0x05).

    Terminates the pairing procedure with a reason code.

    Args:
        reason: Failure reason code (0x01-0x0E valid).

    Returns:
        2-byte PDU: code(1) + Reason(1).
    """
    return bytes([SMP_PAIRING_FAILED, reason & 0xFF])


def build_encryption_info(ltk: bytes) -> bytes:
    """Build an Encryption Information command (code 0x06).

    Distributes the Long Term Key (LTK) from responder to initiator
    during legacy pairing key distribution phase.

    Args:
        ltk: 16-byte Long Term Key. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + LTK(16).
    """
    padded = ltk[:16].ljust(16, b"\x00")
    return bytes([SMP_ENCRYPTION_INFO]) + padded


def build_central_identification(ediv: int, rand: bytes) -> bytes:
    """Build a Central Identification command (code 0x07).

    Distributes the EDIV and Rand values used to identify the LTK.
    Sent after Encryption Information during key distribution.

    Args:
        ediv: 16-bit Encrypted Diversifier (little-endian).
        rand: 8-byte random number. Padded/truncated to 8 bytes.

    Returns:
        11-byte PDU: code(1) + EDIV(2 LE) + Rand(8).
    """
    rand_padded = rand[:8].ljust(8, b"\x00")
    return bytes([SMP_CENTRAL_ID]) + struct.pack("<H", ediv & 0xFFFF) + rand_padded


def build_identity_info(irk: bytes) -> bytes:
    """Build an Identity Information command (code 0x08).

    Distributes the Identity Resolving Key (IRK) used to resolve
    resolvable private addresses.

    Args:
        irk: 16-byte Identity Resolving Key. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + IRK(16).
    """
    padded = irk[:16].ljust(16, b"\x00")
    return bytes([SMP_IDENTITY_INFO]) + padded


def build_identity_addr_info(addr_type: int, address: bytes) -> bytes:
    """Build an Identity Address Information command (code 0x09).

    Distributes the public or static random address associated with
    the IRK. Sent after Identity Information.

    Args:
        addr_type: 0x00 = public, 0x01 = static random.
        address: 6-byte BD_ADDR (little-endian). Padded/truncated to 6 bytes.

    Returns:
        8-byte PDU: code(1) + AddrType(1) + BD_ADDR(6).
    """
    addr_padded = address[:6].ljust(6, b"\x00")
    return bytes([SMP_IDENTITY_ADDR_INFO, addr_type & 0xFF]) + addr_padded


def build_signing_info(csrk: bytes) -> bytes:
    """Build a Signing Information command (code 0x0A).

    Distributes the Connection Signature Resolving Key (CSRK) used
    for data signing (ATT Signed Write Command).

    Args:
        csrk: 16-byte CSRK. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + CSRK(16).
    """
    padded = csrk[:16].ljust(16, b"\x00")
    return bytes([SMP_SIGNING_INFO]) + padded


def build_security_request(auth_req: int = AUTH_BONDING) -> bytes:
    """Build a Security Request command (code 0x0B).

    Sent by the peripheral (responder) to request the central to
    initiate security procedures (pairing or encryption).

    Args:
        auth_req: Authentication requirements bitfield.

    Returns:
        2-byte PDU: code(1) + AuthReq(1).
    """
    return bytes([SMP_SECURITY_REQUEST, auth_req & 0xFF])


def build_pairing_public_key(x: bytes, y: bytes) -> bytes:
    """Build a Pairing Public Key command (code 0x0C).

    Exchanges ECDH P-256 public keys during Secure Connections pairing.
    This is the largest SMP PDU at 65 bytes.

    Args:
        x: 32-byte X coordinate of the P-256 public key.
        y: 32-byte Y coordinate of the P-256 public key.

    Returns:
        65-byte PDU: code(1) + PublicKey_X(32) + PublicKey_Y(32).
    """
    x_padded = x[:32].ljust(32, b"\x00")
    y_padded = y[:32].ljust(32, b"\x00")
    return bytes([SMP_PAIRING_PUBLIC_KEY]) + x_padded + y_padded


def build_pairing_dhkey_check(check: bytes) -> bytes:
    """Build a Pairing DHKey Check command (code 0x0D).

    Verifies the ECDH shared secret during Secure Connections pairing.
    Both sides send this to prove they computed the same DHKey.

    Args:
        check: 16-byte DHKey check value. Padded/truncated to 16 bytes.

    Returns:
        17-byte PDU: code(1) + DHKeyCheck(16).
    """
    padded = check[:16].ljust(16, b"\x00")
    return bytes([SMP_PAIRING_DHKEY_CHECK]) + padded


def build_keypress_notification(notification_type: int = KEYPRESS_STARTED) -> bytes:
    """Build a Keypress Notification command (code 0x0E).

    Sent during passkey entry to indicate keypress events. Only valid
    when both sides have set the Keypress bit in AuthReq.

    Args:
        notification_type: 0x00-0x04 valid (started/entered/erased/cleared/completed).

    Returns:
        2-byte PDU: code(1) + NotificationType(1).
    """
    return bytes([SMP_KEYPRESS_NTF, notification_type & 0xFF])


# ===========================================================================
# Fuzz Case Generators
# ===========================================================================

def fuzz_io_capabilities() -> list[bytes]:
    """Generate Pairing Requests with all 256 IO capability values.

    Valid IO capabilities are 0x00-0x04. Values 0x05-0xFF are reserved
    and should be rejected. Tests IO capability validation.

    Returns:
        List of 256 Pairing Request PDU bytes, one per IO capability value.
    """
    return [build_pairing_request(io_cap=i) for i in range(256)]


def fuzz_max_key_size() -> list[bytes]:
    """Generate Pairing Requests with boundary encryption key sizes.

    Valid range is 7-16 per spec. Tests: 0 (zero), 1 (below minimum),
    6 (just below valid), 7 (minimum valid), 8 (common), 16 (maximum),
    17 (just above), 255 (uint8 max).

    Returns:
        List of Pairing Request PDU bytes with various MaxKeySize values.
    """
    return [
        build_pairing_request(max_key_size=k)
        for k in [0, 1, 6, 7, 8, 16, 17, 255]
    ]


def fuzz_auth_req() -> list[bytes]:
    """Generate Pairing Requests with interesting AuthReq combinations.

    Tests no bonding, legacy bonding, legacy+MITM, SC+bonding, SC+MITM,
    all valid bits, reserved bits set, and all bits set.

    Returns:
        List of Pairing Request PDU bytes with various AuthReq values.
    """
    return [
        build_pairing_request(auth_req=a)
        for a in [
            0x00,  # No bonding, no MITM, legacy
            0x01,  # Bonding, no MITM, legacy
            0x05,  # Bonding + MITM, legacy
            0x09,  # Bonding + SC
            0x0D,  # Bonding + MITM + SC
            0x1D,  # Bonding + MITM + SC + Keypress
            0x3F,  # All defined bits set (including CT2)
            0x40,  # Reserved bit 6 set
            0x80,  # Reserved bit 7 set
            0xC0,  # Both reserved bits set
            0xFF,  # All bits set
        ]
    ]


def fuzz_oob_flag() -> list[bytes]:
    """Generate Pairing Requests with various OOB data flag values.

    Valid values: 0x00 (not present), 0x01 (present). Values 0x02-0xFF
    are reserved and should be rejected.

    Returns:
        List of Pairing Request PDU bytes with various OOB values.
    """
    return [
        build_pairing_request(oob=v)
        for v in [0x00, 0x01, 0x02, 0x80, 0xFF]
    ]


def fuzz_key_dist() -> list[bytes]:
    """Generate Pairing Requests with various key distribution flags.

    Tests all valid combinations, reserved bits, and full byte values
    for both initiator and responder key distribution fields.

    Returns:
        List of Pairing Request PDU bytes with various key distribution values.
    """
    cases: list[bytes] = []
    interesting_values = [
        0x00,  # No keys
        0x01,  # EncKey only
        0x02,  # IdKey only
        0x04,  # SignKey only
        0x07,  # All legacy keys
        0x08,  # LinkKey only (SC only)
        0x0F,  # All keys including LinkKey
        0x10,  # Reserved bit 4
        0xF0,  # All reserved bits
        0xFF,  # All bits set
    ]
    for val in interesting_values:
        # Test in initiator key dist
        cases.append(build_pairing_request(init_key_dist=val))
        # Test in responder key dist
        cases.append(build_pairing_request(resp_key_dist=val))
    return cases


def fuzz_public_key_invalid_curve() -> list[bytes]:
    """Generate Pairing Public Key commands with invalid ECDH P-256 points.

    CVE-2018-5383 pattern: implementations that do not validate that the
    received public key is on the P-256 curve can be exploited to derive
    the shared secret using a small-subgroup attack.

    Tests:
      - Zero point (0, 0) — identity element, not on curve
      - Max values (0xFF..., 0xFF...) — not on curve
      - Random bytes — statistically not on curve
      - Generator point G — valid but reveals private key if accepted without check
      - Point with y=0 — edge case for point validation

    Returns:
        List of Pairing Public Key PDU bytes with invalid curve points.
    """
    # P-256 generator point (little-endian)
    gx = bytes.fromhex(
        "96c298d84539a1f4a033eb2d817d0377f240a463e5e6bcf847422ce1f2d1176b"
    )
    gy = bytes.fromhex(
        "f551bf376840b6cbce5e316b5733ce2b169e0f7c4aeb7e8e9b7f1afe2e342e4f"
    )

    return [
        build_pairing_public_key(b"\x00" * 32, b"\x00" * 32),       # Zero point
        build_pairing_public_key(b"\xFF" * 32, b"\xFF" * 32),       # Max values
        build_pairing_public_key(os.urandom(32), os.urandom(32)),   # Random (not on curve)
        build_pairing_public_key(os.urandom(32), os.urandom(32)),   # Another random
        build_pairing_public_key(gx, gy),                            # Generator point
        build_pairing_public_key(os.urandom(32), b"\x00" * 32),    # y=0 (edge case)
        build_pairing_public_key(b"\x01" + b"\x00" * 31, b"\x00" * 32),  # Small x, y=0
    ]


def fuzz_out_of_sequence() -> list[list[bytes]]:
    """Generate out-of-order SMP command sequences.

    SMP has a strict state machine: Request -> Response -> Confirm -> Random
    (-> Public Key -> DHKey Check for SC). Sending commands out of order
    tests state machine validation.

    Returns:
        List of command sequences (each a list of PDU bytes) that violate
        the expected SMP state machine order.
    """
    return [
        # Confirm without Request (Phase 2 before Phase 1)
        [build_pairing_confirm(os.urandom(16))],

        # Random without Confirm
        [build_pairing_random(os.urandom(16))],

        # Public Key without Request (SC Phase 2 before Phase 1)
        [build_pairing_public_key(os.urandom(32), os.urandom(32))],

        # DHKey Check without Public Key exchange
        [build_pairing_dhkey_check(os.urandom(16))],

        # Failed then continue pairing (should have terminated)
        [build_pairing_failed(SMP_ERR_UNSPECIFIED),
         build_pairing_confirm(os.urandom(16))],

        # Key distribution before pairing completes
        [build_encryption_info(os.urandom(16))],
        [build_central_identification(0x1234, os.urandom(8))],
        [build_identity_info(os.urandom(16))],

        # Security Request then immediate Confirm (skipping Request/Response)
        [build_security_request(AUTH_SC_BOND_MITM),
         build_pairing_confirm(os.urandom(16))],

        # Double Request (send Request twice)
        [build_pairing_request(), build_pairing_request()],

        # Response without Request (peripheral role confusion)
        [build_pairing_response()],

        # Keypress without active passkey entry
        [build_keypress_notification(KEYPRESS_DIGIT_ENTERED)],
    ]


def fuzz_repeated_pairing(count: int = 50) -> list[bytes]:
    """Generate rapid-fire Pairing Requests (DoS pattern).

    Flooding a device with Pairing Requests tests rate limiting and
    resource exhaustion in the SMP state machine.

    Args:
        count: Number of rapid requests to generate. Default 50.

    Returns:
        List of identical Pairing Request PDU bytes.
    """
    return [build_pairing_request() for _ in range(count)]


def fuzz_oversized_pdus() -> list[bytes]:
    """Generate SMP commands with extra trailing bytes beyond expected size.

    Tests whether implementations strictly validate PDU length or
    silently accept extra data (which could contain exploit payloads).

    Returns:
        List of oversized SMP PDU bytes.
    """
    cases: list[bytes] = []
    extra = os.urandom(32)  # Extra trailing data

    # Pairing Request + extra bytes
    cases.append(build_pairing_request() + extra)

    # Pairing Confirm + extra bytes
    cases.append(build_pairing_confirm(os.urandom(16)) + extra)

    # Pairing Failed + extra bytes
    cases.append(build_pairing_failed(SMP_ERR_UNSPECIFIED) + extra)

    # Security Request + extra bytes
    cases.append(build_security_request() + extra)

    # Public Key + extra bytes (already 65 bytes, adding more)
    cases.append(build_pairing_public_key(os.urandom(32), os.urandom(32)) + extra)

    # Keypress Notification + extra bytes
    cases.append(build_keypress_notification() + extra)

    # DHKey Check + extra bytes
    cases.append(build_pairing_dhkey_check(os.urandom(16)) + extra)

    return cases


def fuzz_truncated_pdus() -> list[bytes]:
    """Generate SMP commands with missing bytes (shorter than expected).

    Tests bounds checking when the PDU is shorter than the command's
    expected fixed size. Each command is truncated to various lengths.

    Returns:
        List of truncated SMP PDU bytes.
    """
    cases: list[bytes] = []

    # Full PDUs to truncate
    full_pdus: list[tuple[str, bytes]] = [
        ("PairingRequest", build_pairing_request()),
        ("PairingConfirm", build_pairing_confirm(os.urandom(16))),
        ("PairingRandom", build_pairing_random(os.urandom(16))),
        ("EncryptionInfo", build_encryption_info(os.urandom(16))),
        ("CentralId", build_central_identification(0x1234, os.urandom(8))),
        ("IdentityInfo", build_identity_info(os.urandom(16))),
        ("IdentityAddrInfo", build_identity_addr_info(0x00, os.urandom(6))),
        ("SigningInfo", build_signing_info(os.urandom(16))),
        ("PublicKey", build_pairing_public_key(os.urandom(32), os.urandom(32))),
        ("DHKeyCheck", build_pairing_dhkey_check(os.urandom(16))),
    ]

    for _name, pdu in full_pdus:
        # Just the command code (1 byte, missing all data)
        cases.append(pdu[:1])
        # Half the expected data
        half = max(2, len(pdu) // 2)
        cases.append(pdu[:half])
        # One byte short of full
        if len(pdu) > 2:
            cases.append(pdu[:-1])

    return cases


def fuzz_unknown_commands() -> list[bytes]:
    """Generate PDUs with undefined SMP command codes (0x0F-0xFF).

    Per spec, undefined command codes should result in a Pairing Failed
    response with reason 0x07 (Command Not Supported).

    Returns:
        List of PDU bytes with undefined command codes, each with 16 bytes
        of dummy data.
    """
    return [
        bytes([code]) + b"\x00" * 16
        for code in range(0x0F, 0x100)
    ]


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_smp_fuzz_cases() -> list[bytes]:
    """Generate a combined list of all SMP fuzz payloads.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a raw SMP PDU suitable for sending over L2CAP CID 0x0006.
    Out-of-sequence tests are flattened (each command in each sequence
    is included individually).

    Returns:
        List of fuzz case bytes. Typical count: ~500-700 cases.
    """
    cases: list[bytes] = []

    # IO capability sweep (256 cases)
    cases.extend(fuzz_io_capabilities())

    # Key size boundary tests
    cases.extend(fuzz_max_key_size())

    # AuthReq bit manipulation
    cases.extend(fuzz_auth_req())

    # OOB flag tests
    cases.extend(fuzz_oob_flag())

    # Key distribution flag tests
    cases.extend(fuzz_key_dist())

    # Invalid ECDH curve points (CVE-2018-5383)
    cases.extend(fuzz_public_key_invalid_curve())

    # Out-of-sequence commands (flattened)
    for sequence in fuzz_out_of_sequence():
        cases.extend(sequence)

    # Repeated pairing (DoS)
    cases.extend(fuzz_repeated_pairing())

    # Oversized PDUs
    cases.extend(fuzz_oversized_pdus())

    # Truncated PDUs
    cases.extend(fuzz_truncated_pdus())

    # Unknown command codes
    cases.extend(fuzz_unknown_commands())

    return cases
