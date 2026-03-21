"""State Machine Fuzzing Strategy — multi-step protocol sequence attacks.

Models Bluetooth protocol state machines and generates:
  1. Valid sequences with mutations at each step
  2. Invalid state transitions (out-of-order commands)
  3. State regression attacks (go backwards in state machine)
  4. State skipping attacks (jump ahead, omit mandatory steps)
  5. Repeated state attacks (same command twice)

Supported protocol state machines:
  - OBEX (PBAP / MAP profiles): Connect -> SetPath -> Get/Put -> Disconnect
  - HFP Service Level Connection: BRSF -> BAC -> CIND -> CMER -> CHLD -> SLC
  - SMP Pairing (Legacy and Secure Connections): Request -> keys -> paired
  - ATT Service Discovery: MTU -> primary services -> characteristics -> read/write

Each model defines:
  - Named states and valid transitions between them
  - Packet builders for entering each state (using real protocol builders)
  - Pre-built invalid transition sequences with descriptions
  - Methods for generating valid-with-mutation, skip, regression, and
    repeated-state attack sequences

Reference: lessons-from-bluetooth-specifications.md, Sections 5, 6, 9
"""

from __future__ import annotations

import os
import random
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from blue_tap.fuzz.mutators import CorpusMutator

# ---------------------------------------------------------------------------
# Core abstractions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProtocolState:
    """A single state in a protocol state machine.

    Attributes:
        name: Human-readable state name (e.g. ``"connected"``).
        valid_transitions: Names of states reachable from this state.
        entry_packets: Packet(s) to send to enter this state from the
            previous state in the canonical (valid) sequence.  Empty for
            the initial state.
    """

    name: str
    valid_transitions: tuple[str, ...] = field(default_factory=tuple)
    entry_packets: tuple[bytes, ...] = field(default_factory=tuple)


class StateMachineModel(ABC):
    """Abstract model of a protocol's state machine.

    Subclasses define the concrete states, transitions, and packet
    builders for a specific Bluetooth protocol.
    """

    #: Ordered dict of state name -> ProtocolState.
    states: dict[str, ProtocolState]

    #: Name of the initial state.
    initial_state: str

    #: Ordered list of state names representing the canonical valid path
    #: from initial to terminal state.
    canonical_path: list[str]

    @abstractmethod
    def _build_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Return pre-built invalid transition sequences.

        Each entry is ``(packets, description_log)`` where *packets* is
        a list of bytes to send sequentially and *description_log*
        contains human-readable descriptions of what the sequence tests.
        """
        ...

    # ------------------------------------------------------------------
    # Sequence generators
    # ------------------------------------------------------------------

    def valid_sequence(self, target_state: str) -> list[bytes]:
        """Generate the packet sequence to reach *target_state* from initial.

        Walks the canonical path, collecting entry packets for each
        intermediate state up to and including *target_state*.

        Raises:
            ValueError: If *target_state* is not in :attr:`canonical_path`.
        """
        if target_state not in self.canonical_path:
            raise ValueError(
                f"State {target_state!r} not in canonical path "
                f"{self.canonical_path}"
            )
        packets: list[bytes] = []
        for state_name in self.canonical_path:
            state = self.states[state_name]
            packets.extend(state.entry_packets)
            if state_name == target_state:
                break
        return packets

    def invalid_transition(self, from_state: str) -> list[bytes]:
        """Generate a packet for a transition NOT in *from_state*'s valid set.

        Picks a random state that is *not* reachable from *from_state*
        and returns its entry packets.  Falls back to a random state's
        entry packets if all transitions are valid.
        """
        state = self.states.get(from_state)
        if state is None:
            return []
        invalid_targets = [
            s for s in self.states
            if s != from_state and s not in state.valid_transitions
            and self.states[s].entry_packets
        ]
        if not invalid_targets:
            # All transitions valid — just pick a non-adjacent state
            invalid_targets = [
                s for s in self.states
                if s != from_state and self.states[s].entry_packets
            ]
        if not invalid_targets:
            return []
        target = random.choice(invalid_targets)
        # Build path to from_state, then jump to invalid target
        path = self.valid_sequence(from_state) if from_state != self.initial_state else []
        path.extend(self.states[target].entry_packets)
        return path

    def all_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Return all pre-built invalid transition sequences."""
        return self._build_invalid_transitions()


# ===========================================================================
# OBEX State Machine
# ===========================================================================


class OBEXStateMachine(StateMachineModel):
    """OBEX protocol state machine for PBAP/MAP profile fuzzing.

    Models the OBEX session lifecycle:
        disconnected -> connected -> navigated -> getting/putting

    The ``profile`` parameter controls which Target UUID and packet types
    are used for connection and operations.
    """

    def __init__(self, profile: str = "pbap") -> None:
        from blue_tap.fuzz.protocols.obex import (
            OBEX_CONNECT,
            OBEX_CONTINUE,
            OBEX_DISCONNECT,
            OBEX_GET_FINAL,
            OBEX_PUT_FINAL,
            OBEX_SUCCESS,
            HI_BODY,
            HI_CONNECTION_ID,
            HI_END_OF_BODY,
            HI_TYPE,
            MAP_MAS_TARGET_UUID,
            MAP_TYPE_FOLDER_LIST,
            MAP_TYPE_MSG_LISTING,
            PBAP_TARGET_UUID,
            PBAP_TYPE_PHONEBOOK,
            PBAP_TYPE_VCARD_LIST,
            build_abort,
            build_byte4_header,
            build_byteseq_header,
            build_connect,
            build_disconnect,
            build_get,
            build_map_connect,
            build_obex_packet,
            build_pbap_connect,
            build_pbap_pull_phonebook,
            build_pbap_pull_vcard_listing,
            build_put,
            build_setpath,
            build_unicode_header,
        )

        self.profile = profile
        self._obex = {
            "build_connect": build_connect,
            "build_disconnect": build_disconnect,
            "build_get": build_get,
            "build_put": build_put,
            "build_setpath": build_setpath,
            "build_abort": build_abort,
            "build_obex_packet": build_obex_packet,
            "build_byte4_header": build_byte4_header,
            "build_byteseq_header": build_byteseq_header,
            "build_unicode_header": build_unicode_header,
            "build_pbap_connect": build_pbap_connect,
            "build_pbap_pull_phonebook": build_pbap_pull_phonebook,
            "build_pbap_pull_vcard_listing": build_pbap_pull_vcard_listing,
            "build_map_connect": build_map_connect,
            "OBEX_CONNECT": OBEX_CONNECT,
            "OBEX_DISCONNECT": OBEX_DISCONNECT,
            "OBEX_GET_FINAL": OBEX_GET_FINAL,
            "OBEX_PUT_FINAL": OBEX_PUT_FINAL,
            "OBEX_SUCCESS": OBEX_SUCCESS,
            "OBEX_CONTINUE": OBEX_CONTINUE,
            "HI_BODY": HI_BODY,
            "HI_CONNECTION_ID": HI_CONNECTION_ID,
            "HI_END_OF_BODY": HI_END_OF_BODY,
            "HI_TYPE": HI_TYPE,
            "PBAP_TARGET_UUID": PBAP_TARGET_UUID,
            "MAP_MAS_TARGET_UUID": MAP_MAS_TARGET_UUID,
            "PBAP_TYPE_PHONEBOOK": PBAP_TYPE_PHONEBOOK,
            "PBAP_TYPE_VCARD_LIST": PBAP_TYPE_VCARD_LIST,
            "MAP_TYPE_FOLDER_LIST": MAP_TYPE_FOLDER_LIST,
            "MAP_TYPE_MSG_LISTING": MAP_TYPE_MSG_LISTING,
        }

        # Select profile-specific builders
        if profile == "map":
            connect_pkt = build_map_connect()
            get_pkt = build_get(1, "inbox", MAP_TYPE_MSG_LISTING)
            type_str = MAP_TYPE_FOLDER_LIST
        else:
            connect_pkt = build_pbap_connect()
            get_pkt = build_pbap_pull_phonebook()
            type_str = PBAP_TYPE_PHONEBOOK

        put_pkt = build_put(
            "test.vcf", b"text/x-vcard", b"BEGIN:VCARD\r\nEND:VCARD",
            final=True, connection_id=1,
        )
        setpath_pkt = build_setpath(name="telecom")
        disconnect_pkt = build_disconnect(connection_id=1)
        abort_pkt = build_abort(connection_id=1)

        self.initial_state = "disconnected"
        self.canonical_path = [
            "disconnected", "connected", "navigated", "getting", "putting",
        ]

        self.states = {
            "disconnected": ProtocolState(
                name="disconnected",
                valid_transitions=("connected",),
                entry_packets=(),
            ),
            "connected": ProtocolState(
                name="connected",
                valid_transitions=(
                    "navigated", "getting", "putting", "disconnected",
                ),
                entry_packets=(connect_pkt,),
            ),
            "navigated": ProtocolState(
                name="navigated",
                valid_transitions=(
                    "navigated", "getting", "putting", "disconnected",
                ),
                entry_packets=(setpath_pkt,),
            ),
            "getting": ProtocolState(
                name="getting",
                valid_transitions=("connected",),
                entry_packets=(get_pkt,),
            ),
            "putting": ProtocolState(
                name="putting",
                valid_transitions=("connected",),
                entry_packets=(put_pkt,),
            ),
        }

        # Store for invalid transition building
        self._connect_pkt = connect_pkt
        self._get_pkt = get_pkt
        self._put_pkt = put_pkt
        self._setpath_pkt = setpath_pkt
        self._disconnect_pkt = disconnect_pkt
        self._abort_pkt = abort_pkt
        self._type_str = type_str

    def _build_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Build all pre-defined invalid OBEX state transitions."""
        o = self._obex
        sequences: list[tuple[list[bytes], list[str]]] = []

        # 1. Get before Connect (disconnected -> getting)
        sequences.append((
            [self._get_pkt],
            ["INVALID: Get before Connect (disconnected -> getting)"],
        ))

        # 2. SetPath before Connect (disconnected -> navigated)
        sequences.append((
            [self._setpath_pkt],
            ["INVALID: SetPath before Connect (disconnected -> navigated)"],
        ))

        # 3. Put during Get (getting -> putting)
        sequences.append((
            [
                self._connect_pkt,
                o["build_get"](1, "pb.vcf", o["PBAP_TYPE_PHONEBOOK"], final=False),
                self._put_pkt,
            ],
            ["INVALID: Put during active Get (getting -> putting)"],
        ))

        # 4. Double Connect (connected -> connected)
        sequences.append((
            [self._connect_pkt, self._connect_pkt],
            ["INVALID: Double Connect (connected -> connected)"],
        ))

        # 5. Double Disconnect (disconnected -> disconnected)
        sequences.append((
            [self._connect_pkt, self._disconnect_pkt, self._disconnect_pkt],
            ["INVALID: Double Disconnect (disconnected -> disconnected)"],
        ))

        # 6. Disconnect then Get (use after disconnect)
        sequences.append((
            [self._connect_pkt, self._disconnect_pkt, self._get_pkt],
            ["INVALID: Get after Disconnect (disconnected -> getting)"],
        ))

        # 7. Client sends server response codes
        success_response = o["build_obex_packet"](o["OBEX_SUCCESS"], b"")
        continue_response = o["build_obex_packet"](o["OBEX_CONTINUE"], b"")
        sequences.append((
            [self._connect_pkt, success_response],
            ["INVALID: Client sends Success response code (role confusion)"],
        ))
        sequences.append((
            [self._connect_pkt, continue_response],
            ["INVALID: Client sends Continue response code (role confusion)"],
        ))

        # 8. Abort without pending operation
        sequences.append((
            [self._connect_pkt, self._abort_pkt],
            ["INVALID: Abort without pending operation"],
        ))

        # 9. Interleaved Put and Get
        sequences.append((
            [
                self._connect_pkt,
                o["build_put"](
                    "test.vcf", b"text/x-vcard", b"BEGIN:VCARD",
                    final=False, connection_id=1,
                ),
                self._get_pkt,
            ],
            ["INVALID: Get during active Put (interleaved operations)"],
        ))

        # 10. Stale Connection-ID after reconnect
        sequences.append((
            [
                self._connect_pkt,
                self._disconnect_pkt,
                self._connect_pkt,
                o["build_get"](0xDEADBEEF, "pb.vcf", o["PBAP_TYPE_PHONEBOOK"]),
            ],
            ["INVALID: Stale Connection-ID from prior session"],
        ))

        # 11. Rapid connect/disconnect (resource exhaustion)
        rapid = []
        for _ in range(50):
            rapid.append(self._connect_pkt)
            rapid.append(self._disconnect_pkt)
        sequences.append((
            rapid,
            ["INVALID: Rapid connect/disconnect x50 (resource exhaustion)"],
        ))

        return sequences


# ===========================================================================
# HFP Service Level Connection State Machine
# ===========================================================================


class HFPStateMachine(StateMachineModel):
    """HFP Service Level Connection (SLC) state machine.

    Models the mandatory SLC establishment sequence:
        idle -> brsf -> bac -> cind_test -> cind_read -> cmer -> chld ->
        slc_established

    Post-SLC states are also modeled for call-control fuzzing.
    """

    def __init__(self) -> None:
        from blue_tap.fuzz.protocols.at_commands import at_cmd

        self._at_cmd = at_cmd

        # SLC establishment packets
        brsf_pkt = at_cmd("AT+BRSF=1023")
        bac_pkt = at_cmd("AT+BAC=1,2")
        cind_test_pkt = at_cmd("AT+CIND=?")
        cind_read_pkt = at_cmd("AT+CIND?")
        cmer_pkt = at_cmd("AT+CMER=3,0,0,1")
        chld_pkt = at_cmd("AT+CHLD=?")

        # Post-SLC call control packets
        dial_pkt = at_cmd("ATD5551234;")
        hangup_pkt = at_cmd("AT+CHUP")
        answer_pkt = at_cmd("ATA")
        dtmf_pkt = at_cmd("AT+VTS=1")
        volume_pkt = at_cmd("AT+VGS=10")

        self.initial_state = "idle"
        self.canonical_path = [
            "idle", "brsf", "bac", "cind_test", "cind_read",
            "cmer", "chld", "slc_established",
        ]

        self.states = {
            "idle": ProtocolState(
                name="idle",
                valid_transitions=("brsf",),
                entry_packets=(),
            ),
            "brsf": ProtocolState(
                name="brsf",
                valid_transitions=("bac",),
                entry_packets=(brsf_pkt,),
            ),
            "bac": ProtocolState(
                name="bac",
                valid_transitions=("cind_test",),
                entry_packets=(bac_pkt,),
            ),
            "cind_test": ProtocolState(
                name="cind_test",
                valid_transitions=("cind_read",),
                entry_packets=(cind_test_pkt,),
            ),
            "cind_read": ProtocolState(
                name="cind_read",
                valid_transitions=("cmer",),
                entry_packets=(cind_read_pkt,),
            ),
            "cmer": ProtocolState(
                name="cmer",
                valid_transitions=("chld",),
                entry_packets=(cmer_pkt,),
            ),
            "chld": ProtocolState(
                name="chld",
                valid_transitions=("slc_established",),
                entry_packets=(chld_pkt,),
            ),
            "slc_established": ProtocolState(
                name="slc_established",
                valid_transitions=(),  # terminal for SLC sequence
                entry_packets=(),
            ),
        }

        # Store for invalid transitions
        self._brsf_pkt = brsf_pkt
        self._bac_pkt = bac_pkt
        self._cind_test_pkt = cind_test_pkt
        self._cind_read_pkt = cind_read_pkt
        self._cmer_pkt = cmer_pkt
        self._chld_pkt = chld_pkt
        self._dial_pkt = dial_pkt
        self._hangup_pkt = hangup_pkt
        self._answer_pkt = answer_pkt
        self._dtmf_pkt = dtmf_pkt
        self._volume_pkt = volume_pkt

    def _build_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Build all pre-defined invalid HFP SLC state transitions."""
        at = self._at_cmd
        sequences: list[tuple[list[bytes], list[str]]] = []

        # 1. Skip BRSF — send CMER directly (idle -> cmer)
        sequences.append((
            [self._cmer_pkt],
            ["INVALID: AT+CMER before BRSF/CIND (idle -> cmer, skip feature exchange)"],
        ))

        # 2. Skip everything — send CHLD directly (idle -> chld)
        sequences.append((
            [self._chld_pkt],
            ["INVALID: AT+CHLD=? before any SLC step (idle -> chld)"],
        ))

        # 3. Skip CIND/CMER — BRSF then CHLD (brsf -> chld)
        sequences.append((
            [self._brsf_pkt, self._chld_pkt],
            ["INVALID: AT+CHLD=? after BRSF, skip CIND/CMER (brsf -> chld)"],
        ))

        # 4. Go backwards — CIND_TEST then BRSF again (cind_test -> brsf)
        sequences.append((
            [
                self._brsf_pkt,
                self._bac_pkt,
                self._cind_test_pkt,
                self._brsf_pkt,  # regression
            ],
            ["INVALID: AT+BRSF after CIND=? (cind_test -> brsf, state regression)"],
        ))

        # 5. Restart SLC while established (slc_established -> brsf)
        sequences.append((
            [
                self._brsf_pkt,
                self._bac_pkt,
                self._cind_test_pkt,
                self._cind_read_pkt,
                self._cmer_pkt,
                self._chld_pkt,
                # SLC now established, restart
                self._brsf_pkt,
            ],
            ["INVALID: AT+BRSF after SLC established (restart SLC)"],
        ))

        # 6. Call commands before SLC complete
        sequences.append((
            [self._dial_pkt],
            ["INVALID: ATD before SLC established (call before setup)"],
        ))

        sequences.append((
            [self._brsf_pkt, self._answer_pkt],
            ["INVALID: ATA after only BRSF (answer before SLC)"],
        ))

        # 7. AT+CHUP before any call (no active call to hang up)
        sequences.append((
            [
                self._brsf_pkt,
                self._bac_pkt,
                self._cind_test_pkt,
                self._cind_read_pkt,
                self._cmer_pkt,
                self._chld_pkt,
                self._hangup_pkt,
            ],
            ["INVALID: AT+CHUP without active call (post-SLC, no call)"],
        ))

        # 8. AT+VTS without active call
        sequences.append((
            [
                self._brsf_pkt,
                self._bac_pkt,
                self._cind_test_pkt,
                self._cind_read_pkt,
                self._cmer_pkt,
                self._chld_pkt,
                self._dtmf_pkt,
            ],
            ["INVALID: AT+VTS without active call (DTMF with no call)"],
        ))

        # 9. Double BRSF (repeated state)
        sequences.append((
            [self._brsf_pkt, self._brsf_pkt],
            ["INVALID: Double AT+BRSF (repeated feature exchange)"],
        ))

        # 10. CMER with wrong arguments after valid sequence prefix
        sequences.append((
            [
                self._brsf_pkt,
                self._bac_pkt,
                self._cind_test_pkt,
                self._cind_read_pkt,
                at("AT+CMER=255,255,255,255"),  # invalid values
            ],
            ["INVALID: AT+CMER with all-255 arguments"],
        ))

        # 11. Volume before SLC
        sequences.append((
            [self._volume_pkt],
            ["INVALID: AT+VGS before SLC (volume control before setup)"],
        ))

        return sequences


# ===========================================================================
# SMP Pairing State Machine
# ===========================================================================


class SMPStateMachine(StateMachineModel):
    """SMP (Security Manager Protocol) pairing state machine.

    Models both LE Legacy pairing and LE Secure Connections sequences.

    LE Legacy:
        idle -> feature_exchange -> confirm -> random -> key_distribution -> paired

    LE Secure Connections:
        idle -> feature_exchange -> public_key -> confirm -> random ->
        dhkey_check -> key_distribution -> paired
    """

    def __init__(self, secure_connections: bool = True) -> None:
        from blue_tap.fuzz.protocols.smp import (
            AUTH_BONDING,
            AUTH_SC_BOND_MITM,
            IO_NO_INPUT_OUTPUT,
            KEY_DIST_ALL,
            SMP_ERR_UNSPECIFIED,
            build_central_identification,
            build_encryption_info,
            build_identity_addr_info,
            build_identity_info,
            build_pairing_confirm,
            build_pairing_dhkey_check,
            build_pairing_failed,
            build_pairing_public_key,
            build_pairing_random,
            build_pairing_request,
            build_pairing_response,
            build_security_request,
            build_signing_info,
        )

        self.secure_connections = secure_connections
        self._smp = {
            "build_pairing_request": build_pairing_request,
            "build_pairing_response": build_pairing_response,
            "build_pairing_confirm": build_pairing_confirm,
            "build_pairing_random": build_pairing_random,
            "build_pairing_failed": build_pairing_failed,
            "build_pairing_public_key": build_pairing_public_key,
            "build_pairing_dhkey_check": build_pairing_dhkey_check,
            "build_encryption_info": build_encryption_info,
            "build_central_identification": build_central_identification,
            "build_identity_info": build_identity_info,
            "build_identity_addr_info": build_identity_addr_info,
            "build_signing_info": build_signing_info,
            "build_security_request": build_security_request,
        }

        # Common packet instances
        auth = AUTH_SC_BOND_MITM if secure_connections else AUTH_BONDING
        request_pkt = build_pairing_request(
            io_cap=IO_NO_INPUT_OUTPUT, auth_req=auth,
            max_key_size=16, init_key_dist=KEY_DIST_ALL,
            resp_key_dist=KEY_DIST_ALL,
        )
        response_pkt = build_pairing_response(
            io_cap=IO_NO_INPUT_OUTPUT, auth_req=auth,
            max_key_size=16, init_key_dist=KEY_DIST_ALL,
            resp_key_dist=KEY_DIST_ALL,
        )
        confirm_pkt = build_pairing_confirm(os.urandom(16))
        random_pkt = build_pairing_random(os.urandom(16))
        pubkey_pkt = build_pairing_public_key(os.urandom(32), os.urandom(32))
        dhkey_pkt = build_pairing_dhkey_check(os.urandom(16))
        failed_pkt = build_pairing_failed(SMP_ERR_UNSPECIFIED)

        # Key distribution packets
        enc_info_pkt = build_encryption_info(os.urandom(16))
        central_id_pkt = build_central_identification(0x1234, os.urandom(8))
        identity_pkt = build_identity_info(os.urandom(16))
        identity_addr_pkt = build_identity_addr_info(0x00, os.urandom(6))
        signing_pkt = build_signing_info(os.urandom(16))

        self.initial_state = "idle"

        if secure_connections:
            self.canonical_path = [
                "idle", "feature_exchange", "public_key", "confirm",
                "random", "dhkey_check", "key_distribution", "paired",
            ]
            self.states = {
                "idle": ProtocolState(
                    name="idle",
                    valid_transitions=("feature_exchange",),
                    entry_packets=(),
                ),
                "feature_exchange": ProtocolState(
                    name="feature_exchange",
                    valid_transitions=("public_key",),
                    entry_packets=(request_pkt, response_pkt),
                ),
                "public_key": ProtocolState(
                    name="public_key",
                    valid_transitions=("confirm",),
                    entry_packets=(pubkey_pkt, pubkey_pkt),  # both sides
                ),
                "confirm": ProtocolState(
                    name="confirm",
                    valid_transitions=("random",),
                    entry_packets=(confirm_pkt,),
                ),
                "random": ProtocolState(
                    name="random",
                    valid_transitions=("dhkey_check",),
                    entry_packets=(random_pkt,),
                ),
                "dhkey_check": ProtocolState(
                    name="dhkey_check",
                    valid_transitions=("key_distribution",),
                    entry_packets=(dhkey_pkt, dhkey_pkt),  # both sides
                ),
                "key_distribution": ProtocolState(
                    name="key_distribution",
                    valid_transitions=("paired",),
                    entry_packets=(
                        enc_info_pkt, central_id_pkt,
                        identity_pkt, identity_addr_pkt, signing_pkt,
                    ),
                ),
                "paired": ProtocolState(
                    name="paired",
                    valid_transitions=(),
                    entry_packets=(),
                ),
            }
        else:
            # LE Legacy pairing (no public key / DHKey check)
            self.canonical_path = [
                "idle", "feature_exchange", "confirm", "random",
                "key_distribution", "paired",
            ]
            self.states = {
                "idle": ProtocolState(
                    name="idle",
                    valid_transitions=("feature_exchange",),
                    entry_packets=(),
                ),
                "feature_exchange": ProtocolState(
                    name="feature_exchange",
                    valid_transitions=("confirm",),
                    entry_packets=(request_pkt, response_pkt),
                ),
                "confirm": ProtocolState(
                    name="confirm",
                    valid_transitions=("random",),
                    entry_packets=(confirm_pkt, confirm_pkt),  # I + R
                ),
                "random": ProtocolState(
                    name="random",
                    valid_transitions=("key_distribution",),
                    entry_packets=(random_pkt, random_pkt),  # I + R
                ),
                "key_distribution": ProtocolState(
                    name="key_distribution",
                    valid_transitions=("paired",),
                    entry_packets=(
                        enc_info_pkt, central_id_pkt,
                        identity_pkt, identity_addr_pkt, signing_pkt,
                    ),
                ),
                "paired": ProtocolState(
                    name="paired",
                    valid_transitions=(),
                    entry_packets=(),
                ),
            }

        # Store for building invalid transitions
        self._request_pkt = request_pkt
        self._response_pkt = response_pkt
        self._confirm_pkt = confirm_pkt
        self._random_pkt = random_pkt
        self._pubkey_pkt = pubkey_pkt
        self._dhkey_pkt = dhkey_pkt
        self._failed_pkt = failed_pkt
        self._enc_info_pkt = enc_info_pkt
        self._central_id_pkt = central_id_pkt
        self._identity_pkt = identity_pkt
        self._signing_pkt = signing_pkt

    def _build_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Build all pre-defined invalid SMP state transitions."""
        sequences: list[tuple[list[bytes], list[str]]] = []

        # 1. Confirm without feature exchange (idle -> confirm)
        sequences.append((
            [self._confirm_pkt],
            ["INVALID: PairingConfirm before Request/Response (idle -> confirm)"],
        ))

        # 2. Random without anything (idle -> random)
        sequences.append((
            [self._random_pkt],
            ["INVALID: PairingRandom before any setup (idle -> random)"],
        ))

        # 3. Random without confirm (feature_exchange -> random, skip confirm)
        sequences.append((
            [self._request_pkt, self._response_pkt, self._random_pkt],
            ["INVALID: PairingRandom skipping Confirm (feature_exchange -> random)"],
        ))

        if self.secure_connections:
            # 4. Public key before request (idle -> public_key)
            sequences.append((
                [self._pubkey_pkt],
                ["INVALID: PublicKey before Request (idle -> public_key)"],
            ))

            # 5. Confirm before public key (wrong order for SC)
            sequences.append((
                [
                    self._request_pkt,
                    self._response_pkt,
                    self._confirm_pkt,  # should be pubkey first
                ],
                ["INVALID: Confirm before PublicKey (SC wrong order)"],
            ))

            # 6. DHKey check without public key exchange
            sequences.append((
                [self._request_pkt, self._response_pkt, self._dhkey_pkt],
                ["INVALID: DHKeyCheck without PublicKey exchange"],
            ))

        # 7. Restart pairing while bonded (paired -> request)
        full_path = []
        for state_name in self.canonical_path:
            full_path.extend(self.states[state_name].entry_packets)
        full_path.append(self._request_pkt)
        sequences.append((
            full_path,
            ["INVALID: PairingRequest after pairing complete (paired -> restart)"],
        ))

        # 8. PairingFailed then continue (should terminate)
        sequences.append((
            [
                self._request_pkt,
                self._response_pkt,
                self._failed_pkt,
                self._confirm_pkt,  # continue after failure
            ],
            ["INVALID: PairingConfirm after PairingFailed (continue after abort)"],
        ))

        # 9. Key distribution before pairing completes
        sequences.append((
            [self._enc_info_pkt],
            ["INVALID: EncryptionInfo before pairing (premature key distribution)"],
        ))

        sequences.append((
            [self._request_pkt, self._response_pkt, self._central_id_pkt],
            ["INVALID: CentralID during feature exchange (premature key dist)"],
        ))

        # 10. Double PairingRequest
        sequences.append((
            [self._request_pkt, self._request_pkt],
            ["INVALID: Double PairingRequest"],
        ))

        # 11. PairingResponse without PairingRequest (role confusion)
        sequences.append((
            [self._response_pkt],
            ["INVALID: PairingResponse without Request (peripheral role confusion)"],
        ))

        # 12. Identity info before pairing
        sequences.append((
            [self._identity_pkt],
            ["INVALID: IdentityInfo before pairing (premature identity)"],
        ))

        return sequences


# ===========================================================================
# ATT Service Discovery State Machine
# ===========================================================================


class ATTStateMachine(StateMachineModel):
    """ATT (Attribute Protocol) service discovery state machine.

    Models the normal BLE service discovery sequence:
        idle -> mtu_exchanged -> services_discovered ->
        characteristics_discovered -> values_read -> notifications_enabled
    """

    def __init__(self) -> None:
        from blue_tap.fuzz.protocols.att import (
            UUID_CCCD,
            UUID_CHARACTERISTIC,
            UUID_PRIMARY_SERVICE,
            build_exchange_mtu_req,
            build_execute_write_req,
            build_prepare_write_req,
            build_read_blob_req,
            build_read_by_group_type_req,
            build_read_by_type_req,
            build_read_req,
            build_write_req,
        )

        self._att = {
            "build_exchange_mtu_req": build_exchange_mtu_req,
            "build_read_by_group_type_req": build_read_by_group_type_req,
            "build_read_by_type_req": build_read_by_type_req,
            "build_read_req": build_read_req,
            "build_read_blob_req": build_read_blob_req,
            "build_write_req": build_write_req,
            "build_prepare_write_req": build_prepare_write_req,
            "build_execute_write_req": build_execute_write_req,
            "UUID_PRIMARY_SERVICE": UUID_PRIMARY_SERVICE,
            "UUID_CHARACTERISTIC": UUID_CHARACTERISTIC,
            "UUID_CCCD": UUID_CCCD,
        }

        import struct
        mtu_pkt = build_exchange_mtu_req(517)
        discover_services_pkt = build_read_by_group_type_req(
            0x0001, 0xFFFF, UUID_PRIMARY_SERVICE,
        )
        discover_chars_pkt = build_read_by_type_req(
            0x0001, 0xFFFF, UUID_CHARACTERISTIC,
        )
        read_value_pkt = build_read_req(0x0003)
        write_cccd_pkt = build_write_req(
            0x0004, struct.pack("<H", 0x0001),  # enable notifications
        )

        self.initial_state = "idle"
        self.canonical_path = [
            "idle", "mtu_exchanged", "services_discovered",
            "characteristics_discovered", "values_read",
            "notifications_enabled",
        ]

        self.states = {
            "idle": ProtocolState(
                name="idle",
                valid_transitions=("mtu_exchanged",),
                entry_packets=(),
            ),
            "mtu_exchanged": ProtocolState(
                name="mtu_exchanged",
                valid_transitions=("services_discovered",),
                entry_packets=(mtu_pkt,),
            ),
            "services_discovered": ProtocolState(
                name="services_discovered",
                valid_transitions=("characteristics_discovered",),
                entry_packets=(discover_services_pkt,),
            ),
            "characteristics_discovered": ProtocolState(
                name="characteristics_discovered",
                valid_transitions=("values_read",),
                entry_packets=(discover_chars_pkt,),
            ),
            "values_read": ProtocolState(
                name="values_read",
                valid_transitions=("notifications_enabled",),
                entry_packets=(read_value_pkt,),
            ),
            "notifications_enabled": ProtocolState(
                name="notifications_enabled",
                valid_transitions=(),
                entry_packets=(write_cccd_pkt,),
            ),
        }

        # Store for invalid transitions
        self._mtu_pkt = mtu_pkt
        self._discover_services_pkt = discover_services_pkt
        self._discover_chars_pkt = discover_chars_pkt
        self._read_value_pkt = read_value_pkt
        self._write_cccd_pkt = write_cccd_pkt

    def _build_invalid_transitions(self) -> list[tuple[list[bytes], list[str]]]:
        """Build all pre-defined invalid ATT state transitions."""
        att = self._att
        import struct
        sequences: list[tuple[list[bytes], list[str]]] = []

        # 1. Write CCCD before discovering services (idle -> notifications)
        sequences.append((
            [self._write_cccd_pkt],
            ["INVALID: Write CCCD before service discovery (idle -> notifications)"],
        ))

        # 2. Read Blob without prior Read
        sequences.append((
            [att["build_read_blob_req"](0x0003, 0)],
            ["INVALID: Read Blob without prior Read (no context)"],
        ))

        # 3. Execute Write without Prepare Write
        sequences.append((
            [att["build_execute_write_req"](0x01)],
            ["INVALID: Execute Write without Prepare Write (empty queue commit)"],
        ))

        # 4. Execute Write cancel without Prepare Write
        sequences.append((
            [att["build_execute_write_req"](0x00)],
            ["INVALID: Execute Write cancel without Prepare Write"],
        ))

        # 5. Multiple pending requests (send Read before prior Read response)
        sequences.append((
            [
                att["build_read_req"](0x0001),
                att["build_read_req"](0x0002),
                att["build_read_req"](0x0003),
            ],
            ["INVALID: Multiple pending Read Requests (ATT sequential violation)"],
        ))

        # 6. Write CCCD with invalid value after normal discovery
        sequences.append((
            [
                self._mtu_pkt,
                self._discover_services_pkt,
                self._discover_chars_pkt,
                att["build_write_req"](0x0004, struct.pack("<H", 0xFFFF)),
            ],
            ["INVALID: Write CCCD with all bits set (reserved bits)"],
        ))

        # 7. Characteristics discovery before service discovery
        sequences.append((
            [self._mtu_pkt, self._discover_chars_pkt],
            ["INVALID: Discover characteristics before services"],
        ))

        # 8. Read value before any discovery
        sequences.append((
            [self._read_value_pkt],
            ["INVALID: Read attribute before MTU exchange or discovery"],
        ))

        # 9. Prepare Write with huge offset, no prior Prepare
        sequences.append((
            [
                att["build_prepare_write_req"](0x0003, 0xFFFF, os.urandom(100)),
                att["build_execute_write_req"](0x01),
            ],
            ["INVALID: Prepare Write with max offset then Execute"],
        ))

        # 10. Rapid MTU exchange (should only happen once)
        sequences.append((
            [
                att["build_exchange_mtu_req"](23),
                att["build_exchange_mtu_req"](517),
                att["build_exchange_mtu_req"](0xFFFF),
            ],
            ["INVALID: Multiple MTU exchanges (should be once per connection)"],
        ))

        # 11. Write to handle 0x0000 (invalid handle)
        sequences.append((
            [att["build_write_req"](0x0000, b"\x01\x00")],
            ["INVALID: Write to handle 0x0000 (invalid handle)"],
        ))

        # 12. Read Blob with large offset
        sequences.append((
            [
                att["build_read_req"](0x0003),
                att["build_read_blob_req"](0x0003, 0xFFFF),
            ],
            ["INVALID: Read Blob with max offset (offset overflow)"],
        ))

        return sequences


# ===========================================================================
# StateMachineStrategy — the main entry point
# ===========================================================================


class StateMachineStrategy:
    """Multi-step protocol fuzzing with state machine violations.

    Models protocol state machines and generates:
      1. Valid sequences with mutations at each step
      2. Invalid state transitions (out-of-order commands)
      3. State regression attacks (go backwards in state machine)
      4. State skipping attacks (jump ahead)
      5. Repeated state attacks (same command twice)

    Each ``generate*`` method returns a tuple of
    ``(list_of_packets_to_send_sequentially, description_log)``.

    Supported protocol models:
      - ``"obex-pbap"`` / ``"obex-map"``: OBEX session lifecycle
      - ``"hfp"``: HFP Service Level Connection sequence
      - ``"smp-legacy"``: SMP LE Legacy pairing
      - ``"smp-sc"``: SMP LE Secure Connections pairing
      - ``"att"``: ATT service discovery sequence
    """

    # Shared model registry — intentionally class-level (singleton pattern).
    # Models are expensive to construct so they are built once and shared
    # across all instances.  The lock ensures safe lazy init when multiple
    # threads instantiate simultaneously.
    MODELS: dict[str, StateMachineModel] = {}
    _MODELS_LOCK: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        # Lazily build models on first access to avoid import-time overhead.
        if not StateMachineStrategy.MODELS:
            with StateMachineStrategy._MODELS_LOCK:
                # Double-checked locking — another thread may have built
                # them while we waited for the lock.
                if not StateMachineStrategy.MODELS:
                    StateMachineStrategy.MODELS = {
                        "obex-pbap": OBEXStateMachine("pbap"),
                        "obex-map": OBEXStateMachine("map"),
                        "hfp": HFPStateMachine(),
                        "smp-legacy": SMPStateMachine(secure_connections=False),
                        "smp-sc": SMPStateMachine(secure_connections=True),
                        "att": ATTStateMachine(),
                    }

        self._stats_generated: int = 0
        self._stats_valid_mutated: int = 0
        self._stats_invalid: int = 0
        self._stats_skip: int = 0
        self._stats_regression: int = 0
        self._stats_repeated: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, protocol: str) -> tuple[list[bytes], list[str]]:
        """Generate a multi-step fuzz sequence for the given protocol.

        Randomly selects one of the attack strategies:
          - 30% valid sequence with mutations
          - 30% invalid transition (pre-built)
          - 15% state skip
          - 15% state regression
          - 10% repeated state

        Args:
            protocol: Protocol model name (see :attr:`MODELS`).

        Returns:
            Tuple of (packets_to_send_sequentially, description_log).

        Raises:
            ValueError: If *protocol* is not a supported model.
        """
        roll = random.random()

        if roll < 0.30:
            result = self.generate_valid_with_mutations(protocol)
        elif roll < 0.60:
            result = self.generate_invalid_transition(protocol)
        elif roll < 0.75:
            result = self.generate_state_skip(protocol)
        elif roll < 0.90:
            result = self.generate_state_regression(protocol)
        else:
            result = self._generate_repeated_state(protocol)

        self._stats_generated += 1
        return result

    def generate_valid_with_mutations(
        self, protocol: str,
    ) -> tuple[list[bytes], list[str]]:
        """Walk the valid state machine path, mutating one random step.

        Generates the full canonical sequence, then applies byte-level
        mutations to one randomly selected packet in the sequence.

        Args:
            protocol: Protocol model name.

        Returns:
            Tuple of (packets, description_log).
        """
        model = self._get_model(protocol)
        terminal = model.canonical_path[-1]
        packets = model.valid_sequence(terminal)

        if not packets:
            return [], [f"valid_mutated({protocol}): empty sequence"]

        # Pick a random packet to mutate
        idx = random.randint(0, len(packets) - 1)
        original = packets[idx]
        num_mutations = random.randint(1, 3)
        packets[idx] = CorpusMutator.mutate(original, num_mutations=num_mutations)

        self._stats_valid_mutated += 1
        return packets, [
            f"valid_mutated({protocol}): "
            f"mutated step {idx}/{len(packets)} "
            f"({len(original)}B -> {len(packets[idx])}B, x{num_mutations} mutations)"
        ]

    def generate_invalid_transition(
        self, protocol: str,
    ) -> tuple[list[bytes], list[str]]:
        """Generate an invalid state transition from the pre-built set.

        Selects a random pre-built invalid transition sequence for the
        given protocol model.

        Args:
            protocol: Protocol model name.

        Returns:
            Tuple of (packets, description_log).
        """
        model = self._get_model(protocol)
        all_invalid = model.all_invalid_transitions()
        if not all_invalid:
            return [], [f"invalid_transition({protocol}): no transitions defined"]

        packets, log = random.choice(all_invalid)
        self._stats_invalid += 1
        return list(packets), list(log)

    def generate_state_skip(
        self, protocol: str,
    ) -> tuple[list[bytes], list[str]]:
        """Skip one or more states in the canonical sequence.

        Picks a random pair of non-adjacent states in the canonical path
        and generates a sequence that jumps directly between them.

        Args:
            protocol: Protocol model name.

        Returns:
            Tuple of (packets, description_log).
        """
        model = self._get_model(protocol)
        path = model.canonical_path

        if len(path) < 3:
            return [], [f"state_skip({protocol}): path too short to skip"]

        # Pick start state and skip at least one state
        start_idx = random.randint(0, len(path) - 3)
        # Skip 1 to (remaining - 1) states
        max_skip = len(path) - start_idx - 2
        skip_count = random.randint(1, max(1, max_skip))
        target_idx = start_idx + skip_count + 1

        if target_idx >= len(path):
            target_idx = len(path) - 1

        # Build: valid path to start_state, then jump to target_state entry
        packets: list[bytes] = []
        start_state = path[start_idx]
        target_state = path[target_idx]
        skipped_states = path[start_idx + 1:target_idx]

        # Walk valid path to start state
        for state_name in path:
            state = model.states[state_name]
            packets.extend(state.entry_packets)
            if state_name == start_state:
                break

        # Jump directly to target state's entry packets
        target = model.states[target_state]
        packets.extend(target.entry_packets)

        self._stats_skip += 1
        return packets, [
            f"state_skip({protocol}): "
            f"{start_state} -> {target_state} "
            f"(skipped: {', '.join(skipped_states)})"
        ]

    def generate_state_regression(
        self, protocol: str,
    ) -> tuple[list[bytes], list[str]]:
        """Go backwards in the state machine.

        Walks partway through the canonical path, then sends an entry
        packet for an earlier state, testing whether the implementation
        handles backwards transitions correctly.

        Args:
            protocol: Protocol model name.

        Returns:
            Tuple of (packets, description_log).
        """
        model = self._get_model(protocol)
        path = model.canonical_path

        if len(path) < 3:
            return [], [f"state_regression({protocol}): path too short"]

        # Walk to some state past the start, then regress to an earlier state
        forward_idx = random.randint(2, len(path) - 1)
        regress_idx = random.randint(1, forward_idx - 1)

        forward_state = path[forward_idx]
        regress_state = path[regress_idx]

        # Build valid path to forward state
        packets = model.valid_sequence(forward_state)

        # Then send the regress state's entry packets
        regress = model.states[regress_state]
        packets.extend(regress.entry_packets)

        self._stats_regression += 1
        return packets, [
            f"state_regression({protocol}): "
            f"advanced to {forward_state}, regressed to {regress_state}"
        ]

    def generate_all_sequences(
        self, protocol: str,
    ) -> list[tuple[list[bytes], list[str]]]:
        """Generate all pre-built invalid sequences for a protocol.

        Returns every pre-defined invalid transition plus one instance
        each of valid-with-mutation, state-skip, and state-regression.

        Args:
            protocol: Protocol model name.

        Returns:
            List of (packets, description_log) tuples.
        """
        model = self._get_model(protocol)
        results: list[tuple[list[bytes], list[str]]] = []

        # All pre-built invalid transitions
        results.extend(model.all_invalid_transitions())

        # One of each dynamic strategy
        results.append(self.generate_valid_with_mutations(protocol))
        results.append(self.generate_state_skip(protocol))
        results.append(self.generate_state_regression(protocol))
        results.append(self._generate_repeated_state(protocol))

        return results

    def list_models(self) -> list[str]:
        """List supported protocol state machine names.

        Returns:
            Sorted list of protocol model names.
        """
        return sorted(self.MODELS.keys())

    def stats(self) -> dict[str, int]:
        """Return generation statistics.

        Returns:
            Dictionary of counter name -> count.
        """
        return {
            "generated_total": self._stats_generated,
            "valid_mutated": self._stats_valid_mutated,
            "invalid_transitions": self._stats_invalid,
            "state_skips": self._stats_skip,
            "state_regressions": self._stats_regression,
            "repeated_state": self._stats_repeated,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_model(self, protocol: str) -> StateMachineModel:
        """Look up a protocol model, raising ValueError if not found."""
        model = self.MODELS.get(protocol)
        if model is None:
            raise ValueError(
                f"Unknown protocol {protocol!r}. "
                f"Valid: {', '.join(sorted(self.MODELS.keys()))}"
            )
        return model

    def _generate_repeated_state(
        self, protocol: str,
    ) -> tuple[list[bytes], list[str]]:
        """Send the same state's entry packets twice in a row.

        Tests how the implementation handles a repeated/duplicate
        command that should only be sent once.

        Args:
            protocol: Protocol model name.

        Returns:
            Tuple of (packets, description_log).
        """
        model = self._get_model(protocol)
        # Pick a state that has entry packets
        candidates = [
            s for s in model.canonical_path
            if model.states[s].entry_packets
        ]
        if not candidates:
            return [], [f"repeated_state({protocol}): no states with entry packets"]

        state_name = random.choice(candidates)
        state = model.states[state_name]

        # Walk to just before this state, then send entry packets twice
        idx = model.canonical_path.index(state_name)
        if idx > 0:
            prev_state = model.canonical_path[idx - 1]
            packets = model.valid_sequence(prev_state)
        else:
            packets = []

        # First (valid) entry
        packets.extend(state.entry_packets)
        # Second (repeated) entry
        packets.extend(state.entry_packets)

        self._stats_repeated += 1
        return packets, [
            f"repeated_state({protocol}): "
            f"double entry to {state_name!r} "
            f"({len(state.entry_packets)} packets x2)"
        ]
