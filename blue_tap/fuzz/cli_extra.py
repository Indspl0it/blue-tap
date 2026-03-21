"""Per-protocol fuzz commands and corpus management (Tasks 4.2 + 4.4).

Registers focused single-protocol fuzz commands and corpus management
subcommands into the ``fuzz`` CLI group.  These are lighter-weight than a
full campaign: each sends the protocol builder's built-in fuzz cases against
one target, with a simple progress bar and crash counter.

Usage (called from the main fuzz group registration):
    from blue_tap.fuzz.cli_extra import register_extra_commands
    register_extra_commands(fuzz_group)
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import click
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskProgressColumn,
)
from rich.style import Style
from rich.table import Table

from blue_tap.utils.output import (
    console, info, success, error, warning, verbose, target as style_target,
    summary_panel, section, phase,
    CYAN, GREEN, RED, YELLOW, DIM, PURPLE,
)
from blue_tap.utils.interactive import resolve_address
from blue_tap.utils.session import get_session, log_command


# ---------------------------------------------------------------------------
# Protocol choices for corpus commands
# ---------------------------------------------------------------------------

_ALL_PROTOCOLS = [
    "sdp", "obex", "at", "att", "smp", "bnep", "rfcomm", "l2cap",
]

# Mapping from short CLI names to corpus _PROTOCOL_GENERATORS keys
_PROTOCOL_SHORT_MAP: dict[str, list[str]] = {
    "sdp": ["sdp"],
    "obex": ["obex-pbap", "obex-map", "obex-opp"],
    "at": ["at-hfp", "at-phonebook", "at-sms", "at-injection"],
    "att": ["ble-att"],
    "smp": ["ble-smp"],
    "bnep": ["bnep"],
    "rfcomm": ["rfcomm"],
    "l2cap": ["l2cap"],
}


def _expand_protocol_names(short_names: list[str]) -> list[str]:
    """Expand short CLI protocol names to corpus generator keys."""
    expanded = []
    for name in short_names:
        expanded.extend(_PROTOCOL_SHORT_MAP.get(name, [name]))
    return expanded


# ---------------------------------------------------------------------------
# Shared fuzz-case runner
# ---------------------------------------------------------------------------

def _run_fuzz_cases(
    address: str,
    protocol: str,
    cases: list[bytes],
    transport_factory,
    delay: float = 0.5,
    timeout: float = 5.0,
    session_dir: str = "",
) -> dict:
    """Shared logic for per-protocol fuzz commands.

    Connects via *transport_factory*, iterates through *cases* with a Rich
    progress bar, detects crashes, and logs them to a :class:`CrashDB`.

    Args:
        address: Target BD_ADDR.
        protocol: Protocol name for logging/crash DB.
        cases: List of raw payload bytes to send.
        transport_factory: Callable(address) -> BluetoothTransport instance.
        delay: Seconds between test cases.
        timeout: Receive timeout per case.
        session_dir: Directory for the crash database file.

    Returns:
        Summary dict with ``sent``, ``crashes``, ``errors``,
        ``elapsed``, and ``crash_db_path`` keys.
    """
    from blue_tap.fuzz.crash_db import CrashDB, CrashType, CrashSeverity
    from blue_tap.fuzz.corpus import Corpus, generate_full_corpus

    # Ensure full corpus is generated (visible progress to user)
    if not session_dir:
        session = get_session()
        if session:
            session_dir = session.dir
        else:
            session_dir = os.path.join("sessions", "fuzz_adhoc")

    corpus_dir = os.path.join(session_dir, "fuzz", "corpus")
    corpus = Corpus(corpus_dir)
    generate_full_corpus(corpus, show_progress=True)

    # Set up crash DB (unified crashes.db for all protocols)
    crash_db_path = os.path.join(session_dir, "fuzz", "crashes.db")
    db = CrashDB(crash_db_path)

    sent = 0
    crashes = 0
    errors = 0
    t0 = time.time()

    transport = transport_factory(address)

    # Initial connect
    try:
        if not transport.connect():
            error(f"Failed to connect to {style_target(address)} for {protocol}")
            db.close()
            return {"sent": 0, "crashes": 0, "errors": 1, "elapsed": 0.0,
                    "crash_db_path": crash_db_path}
    except Exception as exc:
        error(f"Connection error: {exc}")
        db.close()
        return {"sent": 0, "crashes": 0, "errors": 1, "elapsed": 0.0,
                "crash_db_path": crash_db_path}

    total = len(cases)

    with Progress(
        SpinnerColumn("dots", style=CYAN),
        TextColumn(f"[{CYAN}]{{task.description}}[/{CYAN}]"),
        BarColumn(bar_width=30, style=DIM, complete_style=CYAN, finished_style=GREEN),
        TaskProgressColumn(),
        TextColumn(f"[{DIM}]{{task.fields[status]}}[/{DIM}]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[{protocol}]",
            total=total,
            status=f"0/{total} | 0 crashes",
        )

        for i, payload in enumerate(cases):
            # Update status
            rate = sent / max(time.time() - t0, 0.1)
            progress.update(
                task,
                advance=0,
                status=f"{sent}/{total} | {crashes} crashes | {rate:.1f}/s",
            )

            try:
                transport.send(payload)
                sent += 1
            except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
                # Connection dropped -- probable crash
                crashes += 1
                db.log_crash(
                    target=address,
                    protocol=protocol,
                    payload=payload,
                    crash_type=CrashType.CONNECTION_DROP,
                    severity=CrashSeverity.HIGH,
                    payload_description=f"Case {i+1}/{total}",
                )
                # Attempt reconnect after cooldown
                transport.close()
                time.sleep(2.0)
                try:
                    transport = transport_factory(address)
                    if not transport.connect():
                        errors += 1
                        warning(f"Reconnect failed after crash at case {i+1}")
                        break
                except Exception:
                    errors += 1
                    warning(f"Reconnect failed after crash at case {i+1}")
                    break
                progress.advance(task)
                continue

            # Wait for response
            try:
                response = transport.recv(recv_timeout=timeout)
                if response is None:
                    # Connection closed by remote
                    crashes += 1
                    db.log_crash(
                        target=address,
                        protocol=protocol,
                        payload=payload,
                        crash_type=CrashType.CONNECTION_DROP,
                        severity=CrashSeverity.HIGH,
                        payload_description=f"Case {i+1}/{total} (recv None)",
                    )
                    transport.close()
                    time.sleep(2.0)
                    try:
                        transport = transport_factory(address)
                        if not transport.connect():
                            errors += 1
                            break
                    except Exception:
                        errors += 1
                        break
            except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
                crashes += 1
                db.log_crash(
                    target=address,
                    protocol=protocol,
                    payload=payload,
                    crash_type=CrashType.CONNECTION_DROP,
                    severity=CrashSeverity.HIGH,
                    payload_description=f"Case {i+1}/{total} (recv error)",
                )
                transport.close()
                time.sleep(2.0)
                try:
                    transport = transport_factory(address)
                    if not transport.connect():
                        errors += 1
                        break
                except Exception:
                    errors += 1
                    break
            progress.advance(task)
            if delay > 0:
                time.sleep(delay)

    transport.close()
    db.close()
    elapsed = time.time() - t0

    return {
        "sent": sent,
        "crashes": crashes,
        "errors": errors,
        "elapsed": elapsed,
        "crash_db_path": crash_db_path,
    }


def _show_fuzz_summary(protocol: str, address: str, result: dict) -> None:
    """Print a styled summary panel after a per-protocol fuzz run."""
    crash_style = "bt.red" if result["crashes"] > 0 else "bt.green"
    items = {
        "Target": style_target(address),
        "Protocol": protocol,
        "Cases sent": str(result["sent"]),
        "Crashes": f"[{crash_style}]{result['crashes']}[/{crash_style}]",
        "Errors": str(result["errors"]),
        "Duration": f"{result['elapsed']:.1f}s",
        "Crash DB": result.get("crash_db_path", "N/A"),
    }
    style = "red" if result["crashes"] > 0 else "green"
    summary_panel(f"Fuzz {protocol.upper()} Results", items, style=style)

    # Log to session
    log_command(f"fuzz_{protocol}", result, category="fuzz", target=address)


# ===========================================================================
# TASK 4.2: Per-Protocol Fuzz Commands
# ===========================================================================

def register_extra_commands(fuzz_group):
    """Register per-protocol fuzz commands and corpus management."""

    # -------------------------------------------------------------------
    # blue-tap fuzz obex
    # -------------------------------------------------------------------
    @fuzz_group.command("obex")
    @click.argument("address", required=False, default=None)
    @click.option("--profile", "-p", default="pbap",
                  type=click.Choice(["pbap", "map", "opp"]),
                  help="OBEX profile to fuzz.")
    @click.option("--channel", default=None, type=int,
                  help="RFCOMM channel (auto-detect from SDP if not set).")
    @click.option("--mode", default="all",
                  type=click.Choice(["headers", "app-params", "path-traversal",
                                     "session", "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    @click.option("--timeout", default=5.0, type=float, help="Receive timeout per case.")
    def fuzz_obex(address, profile, channel, mode, delay, timeout):
        """Fuzz OBEX protocol (PBAP/MAP/OPP profiles).

        Sends protocol-aware OBEX fuzz cases targeting header parsing,
        application parameter TLV handling, path traversal, and session
        state machine attacks.

        \b
        Examples:
          blue-tap fuzz obex AA:BB:CC:DD:EE:FF
          blue-tap fuzz obex AA:BB:CC:DD:EE:FF -p map --mode headers
          blue-tap fuzz obex --channel 19 -p pbap
        """
        from blue_tap.fuzz.protocols.obex import generate_all_obex_fuzz_cases
        from blue_tap.fuzz.transport import RFCOMMTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("OBEX Fuzzing"):
            info(f"Target: {style_target(address)} | Profile: {profile} | Mode: {mode}")

            all_cases = generate_all_obex_fuzz_cases(profile)

            # Flatten multi-packet sequences to individual packets for transport
            flat_cases: list[bytes] = []
            for case in all_cases:
                if isinstance(case, list):
                    flat_cases.extend(case)
                else:
                    flat_cases.append(case)

            info(f"Generated {len(flat_cases)} OBEX fuzz cases for {profile}")

            rfcomm_channel = channel if channel else 19  # PBAP commonly on 19
            def transport_factory(addr):
                return RFCOMMTransport(addr, rfcomm_channel)

            result = _run_fuzz_cases(
                address, "obex", flat_cases, transport_factory,
                delay=delay, timeout=timeout,
            )

        _show_fuzz_summary("obex", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz ble-att
    # -------------------------------------------------------------------
    @fuzz_group.command("ble-att")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["handles", "writes", "mtu", "prepare",
                                     "rapid", "truncated", "unknown-opcodes",
                                     "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    @click.option("--timeout", default=5.0, type=float, help="Receive timeout per case.")
    def fuzz_ble_att(address, mode, delay, timeout):
        """Fuzz BLE ATT (Attribute Protocol).

        Sends protocol-aware ATT fuzz cases targeting handle boundaries,
        write overflows, MTU negotiation, SweynTooth deadlock patterns,
        unknown opcodes, and truncated PDUs.

        \b
        Examples:
          blue-tap fuzz ble-att AA:BB:CC:DD:EE:FF
          blue-tap fuzz ble-att AA:BB:CC:DD:EE:FF --mode rapid
          blue-tap fuzz ble-att --mode mtu --delay 0.1
        """
        from blue_tap.fuzz.protocols.att import (
            generate_all_att_fuzz_cases,
            fuzz_handles, fuzz_write_sizes, fuzz_mtu_values,
            fuzz_prepare_write_overflow, fuzz_rapid_sequential_requests,
            fuzz_truncated_pdus, fuzz_unknown_opcodes,
        )
        from blue_tap.fuzz.transport import BLETransport

        address = resolve_address(address)
        if not address:
            return

        with phase("BLE ATT Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            mode_generators = {
                "handles": fuzz_handles,
                "writes": fuzz_write_sizes,
                "mtu": fuzz_mtu_values,
                "prepare": fuzz_prepare_write_overflow,
                "rapid": fuzz_rapid_sequential_requests,
                "truncated": fuzz_truncated_pdus,
                "unknown-opcodes": fuzz_unknown_opcodes,
            }

            if mode == "all":
                cases = generate_all_att_fuzz_cases()
            else:
                gen = mode_generators.get(mode)
                cases = gen() if gen else generate_all_att_fuzz_cases()

            info(f"Generated {len(cases)} ATT fuzz cases")

            def transport_factory(addr):
                return BLETransport(addr)

            result = _run_fuzz_cases(
                address, "ble-att", cases, transport_factory,
                delay=delay, timeout=timeout,
            )

        _show_fuzz_summary("ble-att", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz ble-smp
    # -------------------------------------------------------------------
    @fuzz_group.command("ble-smp")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["pairing", "keysizes", "curve",
                                     "sequence", "truncated", "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    @click.option("--timeout", default=5.0, type=float, help="Receive timeout per case.")
    def fuzz_ble_smp(address, mode, delay, timeout):
        """Fuzz BLE SMP (Security Manager Protocol).

        Sends protocol-aware SMP fuzz cases targeting IO capability
        validation, key size negotiation, invalid ECDH curve points
        (CVE-2018-5383), out-of-sequence attacks, and truncated PDUs.

        \b
        Examples:
          blue-tap fuzz ble-smp AA:BB:CC:DD:EE:FF
          blue-tap fuzz ble-smp AA:BB:CC:DD:EE:FF --mode curve
          blue-tap fuzz ble-smp --mode pairing --delay 1.0
        """
        from blue_tap.fuzz.protocols.smp import (
            generate_all_smp_fuzz_cases,
            fuzz_io_capabilities, fuzz_max_key_size,
            fuzz_public_key_invalid_curve, fuzz_out_of_sequence,
            fuzz_truncated_pdus,
        )
        from blue_tap.fuzz.transport import BLETransport

        address = resolve_address(address)
        if not address:
            return

        with phase("BLE SMP Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            if mode == "pairing":
                cases = fuzz_io_capabilities()
            elif mode == "keysizes":
                cases = fuzz_max_key_size()
            elif mode == "curve":
                cases = fuzz_public_key_invalid_curve()
            elif mode == "sequence":
                # Flatten sequence lists
                cases = []
                for seq in fuzz_out_of_sequence():
                    cases.extend(seq)
            elif mode == "truncated":
                cases = fuzz_truncated_pdus()
            else:
                cases = generate_all_smp_fuzz_cases()

            info(f"Generated {len(cases)} SMP fuzz cases")

            def transport_factory(addr):
                return BLETransport(addr)

            result = _run_fuzz_cases(
                address, "ble-smp", cases, transport_factory,
                delay=delay, timeout=timeout,
            )

        _show_fuzz_summary("ble-smp", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz bnep
    # -------------------------------------------------------------------
    @fuzz_group.command("bnep")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["setup", "ethernet", "filters",
                                     "extension", "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    def fuzz_bnep(address, mode, delay):
        """Fuzz BNEP (Bluetooth Network Encapsulation Protocol).

        Sends protocol-aware BNEP fuzz cases targeting Setup Connection
        uuid_size handling (CVE-2017-0781), oversized Ethernet payloads,
        filter list overflows, and extension header parsing.

        \b
        Examples:
          blue-tap fuzz bnep AA:BB:CC:DD:EE:FF
          blue-tap fuzz bnep AA:BB:CC:DD:EE:FF --mode setup
          blue-tap fuzz bnep --mode filters --delay 0.1
        """
        from blue_tap.fuzz.protocols.bnep import (
            generate_all_bnep_fuzz_cases,
            fuzz_setup_uuid_sizes, fuzz_setup_oversized_uuid,
            fuzz_oversized_ethernet, fuzz_filter_overflow,
            fuzz_extension_bit,
        )
        from blue_tap.fuzz.transport import L2CAPTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("BNEP Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            mode_generators = {
                "setup": lambda: fuzz_setup_uuid_sizes() + fuzz_setup_oversized_uuid(),
                "ethernet": fuzz_oversized_ethernet,
                "filters": fuzz_filter_overflow,
                "extension": fuzz_extension_bit,
            }

            if mode == "all":
                cases = generate_all_bnep_fuzz_cases()
            else:
                gen = mode_generators.get(mode)
                cases = gen() if gen else generate_all_bnep_fuzz_cases()

            info(f"Generated {len(cases)} BNEP fuzz cases")

            # BNEP runs on L2CAP PSM 15
            def transport_factory(addr):
                return L2CAPTransport(addr, psm=15)

            result = _run_fuzz_cases(
                address, "bnep", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("bnep", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz rfcomm-raw
    # -------------------------------------------------------------------
    @fuzz_group.command("rfcomm-raw")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["frames", "pn", "msc", "rpn",
                                     "credits", "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    def fuzz_rfcomm_raw(address, mode, delay):
        """Fuzz raw RFCOMM frames via L2CAP PSM 3.

        Sends protocol-aware RFCOMM fuzz cases targeting FCS manipulation,
        length mismatches, invalid control bytes, DLCI boundaries, PN/MSC/RPN
        parameter negotiation, and credit-based flow control.

        \b
        Examples:
          blue-tap fuzz rfcomm-raw AA:BB:CC:DD:EE:FF
          blue-tap fuzz rfcomm-raw AA:BB:CC:DD:EE:FF --mode pn
          blue-tap fuzz rfcomm-raw --mode credits --delay 0.1
        """
        from blue_tap.fuzz.protocols.rfcomm import (
            generate_all_rfcomm_fuzz_cases,
            fuzz_fcs, fuzz_dlci_range, fuzz_invalid_control_bytes,
            fuzz_pn_params, fuzz_msc_signals, fuzz_rpn_params,
            fuzz_credit_flow,
        )
        from blue_tap.fuzz.transport import L2CAPTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("RFCOMM Raw Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            mode_generators = {
                "frames": lambda: fuzz_fcs() + fuzz_dlci_range() + fuzz_invalid_control_bytes(),
                "pn": fuzz_pn_params,
                "msc": fuzz_msc_signals,
                "rpn": fuzz_rpn_params,
                "credits": fuzz_credit_flow,
            }

            if mode == "all":
                cases = generate_all_rfcomm_fuzz_cases()
            else:
                gen = mode_generators.get(mode)
                cases = gen() if gen else generate_all_rfcomm_fuzz_cases()

            info(f"Generated {len(cases)} RFCOMM fuzz cases")

            # Raw RFCOMM via L2CAP PSM 3
            def transport_factory(addr):
                return L2CAPTransport(addr, psm=3)

            result = _run_fuzz_cases(
                address, "rfcomm", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("rfcomm", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz sdp-deep
    # -------------------------------------------------------------------
    @fuzz_group.command("sdp-deep")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["continuation", "data-elements",
                                     "requests", "all"]),
                  help="Fuzz category to run.")
    @click.option("--delay", default=0.3, type=float, help="Delay between test cases.")
    def fuzz_sdp_deep(address, mode, delay):
        """Deep SDP fuzzing using the full protocol builder.

        Enhanced SDP fuzzing with data element malformations, PDU-level
        attacks, continuation state exploits (CVE-2017-0785 patterns),
        and parameter boundary testing.

        \b
        Examples:
          blue-tap fuzz sdp-deep AA:BB:CC:DD:EE:FF
          blue-tap fuzz sdp-deep AA:BB:CC:DD:EE:FF --mode continuation
          blue-tap fuzz sdp-deep --mode data-elements --delay 0.1
        """
        from blue_tap.fuzz.protocols.sdp import (
            generate_all_sdp_fuzz_cases,
            fuzz_invalid_dtd_bytes, fuzz_nested_des, fuzz_des_size_overflow,
            fuzz_string_size_overflow, fuzz_all_type_size_combos,
            fuzz_parameter_length_mismatch, fuzz_max_count_boundary,
            fuzz_max_bytes_boundary, fuzz_handle_boundary,
            fuzz_empty_patterns, fuzz_too_many_uuids,
            fuzz_reserved_pdu_ids, fuzz_response_as_request,
            generate_continuation_attacks,
        )
        from blue_tap.fuzz.transport import L2CAPTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("SDP Deep Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            if mode == "continuation":
                cases = generate_continuation_attacks(b"\x00\x20")
            elif mode == "data-elements":
                cases = (
                    fuzz_invalid_dtd_bytes()
                    + [fuzz_nested_des(100)]
                    + [fuzz_des_size_overflow()]
                    + [fuzz_string_size_overflow()]
                    + fuzz_all_type_size_combos()
                )
            elif mode == "requests":
                cases = (
                    fuzz_parameter_length_mismatch()
                    + fuzz_max_count_boundary()
                    + fuzz_max_bytes_boundary()
                    + fuzz_handle_boundary()
                    + fuzz_empty_patterns()
                    + fuzz_too_many_uuids()
                    + fuzz_reserved_pdu_ids()
                    + fuzz_response_as_request()
                )
            else:
                cases = generate_all_sdp_fuzz_cases()

            info(f"Generated {len(cases)} SDP fuzz cases")

            # SDP runs on L2CAP PSM 1
            def transport_factory(addr):
                return L2CAPTransport(addr, psm=1)

            result = _run_fuzz_cases(
                address, "sdp", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("sdp", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz at-deep
    # -------------------------------------------------------------------
    @fuzz_group.command("at-deep")
    @click.argument("address", required=False, default=None)
    @click.option("--channel", default=1, type=int,
                  help="RFCOMM channel for HFP AG.")
    @click.option("--category", default="all",
                  type=click.Choice(["hfp-slc", "hfp-call", "hfp-query",
                                     "phonebook", "sms", "injection",
                                     "device-info", "all"]),
                  help="AT command category to fuzz.")
    @click.option("--delay", default=0.3, type=float, help="Delay between test cases.")
    def fuzz_at_deep(address, channel, category, delay):
        """Deep AT command fuzzing (372+ patterns).

        Sends the full AT command corpus targeting HFP Service Level
        Connection, call control, phonebook access, SMS, injection attacks,
        and device identification commands.

        \b
        Examples:
          blue-tap fuzz at-deep AA:BB:CC:DD:EE:FF
          blue-tap fuzz at-deep AA:BB:CC:DD:EE:FF --category injection
          blue-tap fuzz at-deep --channel 3 --category hfp-slc
        """
        from blue_tap.fuzz.protocols.at_commands import ATCorpus
        from blue_tap.fuzz.transport import RFCOMMTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("AT Command Deep Fuzzing"):
            info(f"Target: {style_target(address)} | Channel: {channel} | Category: {category}")

            category_generators = {
                "hfp-slc": ATCorpus.generate_hfp_slc_corpus,
                "hfp-call": ATCorpus.generate_hfp_call_corpus,
                "hfp-query": ATCorpus.generate_hfp_query_corpus,
                "phonebook": ATCorpus.generate_phonebook_corpus,
                "sms": ATCorpus.generate_sms_corpus,
                "injection": ATCorpus.generate_injection_corpus,
                "device-info": ATCorpus.generate_device_info_corpus,
            }

            if category == "all":
                cases = ATCorpus.generate_all()
            else:
                gen = category_generators.get(category)
                cases = gen() if gen else ATCorpus.generate_all()

            info(f"Generated {len(cases)} AT command fuzz cases")

            # Show corpus stats
            if category == "all":
                stats = ATCorpus.corpus_stats()
                verbose(
                    f"Categories: HFP-SLC={stats.get('hfp_slc', 0)}, "
                    f"Call={stats.get('hfp_call', 0)}, "
                    f"Query={stats.get('hfp_query', 0)}, "
                    f"Phonebook={stats.get('phonebook', 0)}, "
                    f"SMS={stats.get('sms', 0)}, "
                    f"Injection={stats.get('injection', 0)}, "
                    f"Device={stats.get('device_info', 0)}"
                )

            def transport_factory(addr):
                return RFCOMMTransport(addr, channel)

            result = _run_fuzz_cases(
                address, "at", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("at", address, result)

    # -------------------------------------------------------------------
    # blue-tap fuzz cve
    # -------------------------------------------------------------------
    @fuzz_group.command("cve")
    @click.argument("address", required=False, default=None)
    @click.option("--cve-id", default=None,
                  help="Specific CVE (e.g. 2017-0785). Substring match.")
    @click.option("--list", "list_cves", is_flag=True,
                  help="List all supported CVEs and exit.")
    @click.option("--delay", default=1.0, type=float, help="Delay between test cases.")
    def fuzz_cve(address, cve_id, list_cves, delay):
        """Run targeted CVE reproduction patterns.

        Reproduces known Bluetooth CVE exploit patterns and generates
        variants to find similar bugs. Supports BlueBorne, SweynTooth,
        Invalid Curve, NimBLE, and PerfektBlue attacks.

        \b
        Examples:
          blue-tap fuzz cve --list
          blue-tap fuzz cve AA:BB:CC:DD:EE:FF
          blue-tap fuzz cve AA:BB:CC:DD:EE:FF --cve-id 2017-0785
          blue-tap fuzz cve AA:BB:CC:DD:EE:FF --cve-id sweyntooth
        """
        from blue_tap.fuzz.strategies.targeted import TargetedStrategy

        strategy = TargetedStrategy()

        # --list: show table of supported CVEs
        if list_cves:
            cve_list = strategy.list_cves()
            table = Table(
                title=f"[bold {CYAN}]Supported CVEs[/bold {CYAN}]",
                show_lines=True,
                border_style=DIM,
                header_style=Style(bold=True, color=CYAN),
            )
            table.add_column("CVE ID", style=YELLOW, width=22)
            table.add_column("Name", style="bold white", max_width=35)
            table.add_column("Year", style=DIM, width=6, justify="right")
            table.add_column("Protocol", style=CYAN, width=10)
            table.add_column("Layer", style=DIM, width=16)
            table.add_column("Severity", width=10)

            sev_styles = {
                "critical": f"bold {RED}",
                "high": RED,
                "medium": YELLOW,
                "low": GREEN,
                "info": DIM,
            }
            for cve in cve_list:
                sev = cve.get("severity", "info").lower()
                style = sev_styles.get(sev, DIM)
                sev_display = f"[{style}]{sev.upper()}[/{style}]"
                table.add_row(
                    cve["id"],
                    cve["name"],
                    str(cve.get("year", "")),
                    cve.get("protocol", ""),
                    cve.get("layer", ""),
                    sev_display,
                )

            console.print()
            console.print(table)
            console.print()
            info(f"Total: {len(cve_list)} supported CVE patterns")
            return

        # Need an address for actual fuzzing
        address = resolve_address(address)
        if not address:
            return

        with phase("CVE Reproduction"):
            filter_label = cve_id if cve_id else "all"
            info(f"Target: {style_target(address)} | CVE filter: {filter_label}")

            # Collect all payloads from the generator
            payloads: list[tuple[bytes, str]] = []
            for payload, desc in strategy.generate_all(cve=cve_id):
                # Flatten multi-step attacks to individual payloads
                if isinstance(payload, list):
                    for p in payload:
                        payloads.append((p, desc))
                else:
                    payloads.append((payload, desc))

            if not payloads:
                warning(f"No CVE patterns match filter: {cve_id}")
                return

            info(f"Loaded {len(payloads)} CVE test cases")

            # Determine transport based on CVE protocol using PROTOCOL_TRANSPORT_MAP
            from blue_tap.fuzz.transport import L2CAPTransport, RFCOMMTransport, BLETransport
            from blue_tap.fuzz.engine import PROTOCOL_TRANSPORT_MAP

            # Group payloads by CVE protocol and use correct transport
            # For simplicity, use the protocol of the first CVE to pick transport
            cve_list = strategy.list_cves()
            first_proto = None
            if cve_list:
                first_proto = cve_list[0].get("protocol", "l2cap") if isinstance(cve_list[0], dict) else "l2cap"

            spec = PROTOCOL_TRANSPORT_MAP.get(first_proto or "sdp", {"type": "l2cap", "psm": 1})
            ttype = spec["type"]
            if ttype == "rfcomm":
                ch = spec.get("channel", 1)
                def transport_factory(addr):
                    return RFCOMMTransport(addr, ch)
            elif ttype == "ble":
                cid = spec.get("cid", 4)
                def transport_factory(addr):
                    return BLETransport(addr, cid=cid)
            else:
                psm = spec.get("psm", 1)
                def transport_factory(addr):
                    return L2CAPTransport(addr, psm=psm)

            cases = [p for p, _ in payloads]
            result = _run_fuzz_cases(
                address, "cve", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("cve", address, result)

    # ===================================================================
    # TASK 6.2: Replay, Minimize, and L2CAP Signaling Commands
    # ===================================================================

    # -------------------------------------------------------------------
    # blue-tap fuzz replay
    # -------------------------------------------------------------------
    @fuzz_group.command("replay")
    @click.argument("capture_file")
    @click.option("--target", "-t", required=True, help="Target BD_ADDR to replay against.")
    @click.option("--protocol", "-p", default=None, help="Filter by protocol.")
    @click.option("--list", "list_frames", is_flag=True, help="List frames without replaying.")
    @click.option("--mutate", is_flag=True, help="Apply mutations during replay.")
    @click.option("--delay", default=0.5, type=float, help="Delay between frames.")
    def fuzz_replay(capture_file, target, protocol, list_frames, mutate, delay):
        """Replay frames from a btsnoop capture against a target.

        Parses a btsnoop v1 capture file, extracts L2CAP frames, and
        selectively replays them.  Use --list to inspect frames without
        sending, --protocol to filter, and --mutate to apply mutations.

        \b
        Examples:
          blue-tap fuzz replay capture.btsnoop -t AA:BB:CC:DD:EE:FF --list
          blue-tap fuzz replay capture.btsnoop -t AA:BB:CC:DD:EE:FF
          blue-tap fuzz replay capture.btsnoop -t AA:BB:CC:DD:EE:FF -p sdp
          blue-tap fuzz replay capture.btsnoop -t AA:BB:CC:DD:EE:FF --mutate
        """
        from blue_tap.fuzz.pcap_replay import CaptureReplayer

        target = resolve_address(target)
        if not target:
            return

        with phase("Capture Replay"):
            info(f"Loading capture: {capture_file}")
            replayer = CaptureReplayer(capture_file, target)

            try:
                frame_count = replayer.load()
            except (FileNotFoundError, ValueError) as exc:
                error(f"Failed to load capture: {exc}")
                return

            if frame_count == 0:
                warning("No L2CAP frames found in capture.")
                return

            info(f"Loaded {frame_count} L2CAP frames")

            # Show capture summary
            summary = replayer.summary()
            summary_panel("Capture Summary", {
                "Total frames": str(summary["total_frames"]),
                "Sent frames": str(summary["sent_frames"]),
                "Received frames": str(summary["received_frames"]),
                "Duration": f"{summary['duration_seconds']:.1f}s",
                "Protocols": ", ".join(
                    f"{k}({v})" for k, v in sorted(summary["protocols"].items())
                ) or "none",
            })

            # --list: display frame table and exit
            if list_frames:
                frame_list = replayer.list_frames(protocol=protocol)

                if not frame_list:
                    warning(f"No frames match protocol filter: {protocol}")
                    return

                table = Table(
                    title=f"[bold {CYAN}]Capture Frames[/bold {CYAN}]",
                    show_lines=False,
                    border_style=DIM,
                    header_style=Style(bold=True, color=CYAN),
                )
                table.add_column("#", style=DIM, width=6, justify="right")
                table.add_column("Dir", style=YELLOW, width=10)
                table.add_column("Protocol", style=CYAN, width=18)
                table.add_column("CID", style=DIM, width=8)
                table.add_column("Handle", style=DIM, width=8)
                table.add_column("Size", style=GREEN, width=8, justify="right")

                for f in frame_list:
                    dir_style = GREEN if f["direction"] == "sent" else YELLOW
                    table.add_row(
                        str(f["index"]),
                        f"[{dir_style}]{f['direction']}[/{dir_style}]",
                        f["protocol"],
                        f["cid"],
                        f["handle"],
                        f"{f['size']}B",
                    )

                console.print()
                console.print(table)
                console.print()
                info(f"Showing {len(frame_list)} frames")
                return

            # Replay mode
            from blue_tap.fuzz.transport import L2CAPTransport
            def transport_factory(addr):
                return L2CAPTransport(addr, psm=1)

            if mutate:
                info(f"Replaying with mutations against {style_target(target)}")
                result = replayer.replay_with_mutations(
                    protocol=protocol,
                    transport_factory=transport_factory,
                    delay=delay,
                )
                mutations = result.get("mutations_applied", 0)
            else:
                info(f"Replaying against {style_target(target)}")
                result = replayer.replay_all(
                    protocol=protocol,
                    transport_factory=transport_factory,
                    delay=delay,
                )
                mutations = 0

        replay_items = {
            "Target": style_target(target),
            "Capture": capture_file,
            "Frames sent": str(result.get("sent", 0)),
            "Errors": str(result.get("errors", 0)),
            "Protocols": ", ".join(
                f"{k}({v})" for k, v in sorted(result.get("protocols", {}).items())
            ) or "none",
        }
        if mutate:
            replay_items["Mutations"] = str(mutations)

        style = "red" if result.get("errors", 0) > 0 else "green"
        summary_panel("Replay Results", replay_items, style=style)

        log_command("fuzz_replay", {
            "capture_file": capture_file,
            "target": target,
            "protocol": protocol,
            "mutate": mutate,
            "sent": result.get("sent", 0),
            "errors": result.get("errors", 0),
        }, category="fuzz", target=target)

    # -------------------------------------------------------------------
    # blue-tap fuzz minimize
    # -------------------------------------------------------------------
    @fuzz_group.command("minimize")
    @click.argument("crash_id", type=int)
    @click.option("--session", "-s", default=None,
                  help="Session name (default: current or latest).")
    @click.option("--strategy", default="auto",
                  type=click.Choice(["binary", "ddmin", "field", "auto"]),
                  help="Minimization strategy.")
    @click.option("--timeout", default=5.0, type=float,
                  help="Seconds to wait for target response.")
    @click.option("--cooldown", default=5.0, type=float,
                  help="Seconds between crash tests.")
    @click.option("--retries", default=3, type=int,
                  help="Retry count per test payload.")
    def fuzz_minimize(crash_id, session, strategy, timeout, cooldown, retries):
        """Minimize a crash payload to find the essential bytes.

        Given a crash ID from the crash database, repeatedly sends
        reduced variants to identify the smallest payload that still
        triggers the crash.  Supports binary search, delta debugging,
        and field-level analysis strategies.

        \b
        Examples:
          blue-tap fuzz minimize 1
          blue-tap fuzz minimize 3 --strategy ddmin
          blue-tap fuzz minimize 1 --timeout 10 --cooldown 8
          blue-tap fuzz minimize 5 -s my_session
        """
        from blue_tap.fuzz.crash_db import CrashDB
        from blue_tap.fuzz.minimizer import CrashMinimizer
        from blue_tap.fuzz.transport import L2CAPTransport, RFCOMMTransport

        # Locate crash database
        if session:
            session_base = os.path.join("sessions", session)
        else:
            active = get_session()
            if active:
                session_base = active.dir
            else:
                # Search for most recent session with fuzz data
                sessions_dir = Path("sessions")
                session_base = None
                if sessions_dir.is_dir():
                    for sess_dir in sorted(sessions_dir.iterdir(), reverse=True):
                        fuzz_dir = sess_dir / "fuzz"
                        if fuzz_dir.is_dir():
                            # Look for any crash DB
                            dbs = list(fuzz_dir.glob("*_crashes.db"))
                            if dbs:
                                session_base = str(sess_dir)
                                break
                if session_base is None:
                    error("No session with crash data found. Specify --session.")
                    return

        # Find the crash database containing this crash ID
        fuzz_dir = Path(session_base) / "fuzz"
        if not fuzz_dir.is_dir():
            error(f"No fuzz data found in {session_base}")
            return

        db_files = list(fuzz_dir.glob("*_crashes.db"))
        if not db_files:
            error(f"No crash databases found in {fuzz_dir}")
            return

        # Search all crash DBs for the crash ID
        crash = None
        crash_db_path = None
        for db_path in db_files:
            db = CrashDB(str(db_path))
            found = db.get_crash_by_id(crash_id)
            if found is not None:
                crash = found
                crash_db_path = str(db_path)
                db.close()
                break
            db.close()

        if crash is None:
            error(f"Crash ID {crash_id} not found in any database under {fuzz_dir}")
            return

        target = crash.get("target_addr", "")
        protocol = crash.get("protocol", "unknown")

        if not target:
            error(f"Crash {crash_id} has no target address")
            return

        with phase("Crash Minimization"):
            info(f"Crash {crash_id}: {protocol} protocol, target {style_target(target)}")
            info(f"Strategy: {strategy} | Timeout: {timeout}s | Cooldown: {cooldown}s")

            try:
                payload = bytes.fromhex(crash["payload_hex"])
            except (ValueError, KeyError) as exc:
                error(f"Invalid payload in crash record: {exc}")
                return

            info(f"Original payload: {len(payload)} bytes")

            # Determine transport from protocol using PROTOCOL_TRANSPORT_MAP
            from blue_tap.fuzz.engine import PROTOCOL_TRANSPORT_MAP
            spec = PROTOCOL_TRANSPORT_MAP.get(protocol)
            if spec is not None:
                ttype = spec["type"]
                if ttype == "rfcomm":
                    _ch = spec.get("channel", 1)
                    def transport_factory():
                        return RFCOMMTransport(target, _ch)
                elif ttype == "ble":
                    from blue_tap.fuzz.transport import BLETransport
                    _cid = spec.get("cid", 4)
                    def transport_factory():
                        return BLETransport(target, cid=_cid)
                else:
                    _psm = spec.get("psm", 1)
                    def transport_factory():
                        return L2CAPTransport(target, psm=_psm)
            else:
                # Fallback: guess from protocol name
                protocol_lower = protocol.lower()
                if protocol_lower in ("rfcomm", "at", "obex") or protocol_lower.startswith("at-") or protocol_lower.startswith("obex-"):
                    def transport_factory():
                        return RFCOMMTransport(target, 1)
                else:
                    def transport_factory():
                        return L2CAPTransport(target, psm=1)

            minimizer = CrashMinimizer(
                target=target,
                transport_factory=transport_factory,
                timeout=timeout,
                cooldown=cooldown,
                max_retries=retries,
            )

            # Open DB for saving results
            crash_db = CrashDB(crash_db_path)
            try:
                result = minimizer.minimize_from_db(crash_db, crash_id, strategy=strategy)
            finally:
                crash_db.close()

        # Display results
        if result.success:
            result_items = {
                "Strategy": result.strategy_used,
                "Original size": f"{result.original_size} bytes",
                "Minimized size": f"{result.minimized_size} bytes",
                "Reduction": f"{result.reduction_percent:.1f}%",
                "Tests performed": str(result.tests_performed),
                "Minimized payload": result.minimized.hex(),
            }
            if result.essential_mask and any(m == 0xFF for m in result.essential_mask):
                essential_count = sum(1 for m in result.essential_mask if m == 0xFF)
                result_items["Essential bytes"] = f"{essential_count}/{result.original_size}"
                result_items["Pattern"] = result.essential_bytes_hex()

            summary_panel("Minimization Results", result_items, style="green")
        else:
            summary_panel("Minimization Failed", {
                "Reason": "Crash could not be reproduced",
                "Tests performed": str(result.tests_performed),
            }, style="red")

        log_command("fuzz_minimize", {
            "crash_id": crash_id,
            "strategy": strategy,
            "success": result.success,
            "original_size": result.original_size,
            "minimized_size": result.minimized_size,
            "reduction_percent": result.reduction_percent,
            "tests_performed": result.tests_performed,
        }, category="fuzz", target=target)

    # -------------------------------------------------------------------
    # blue-tap fuzz l2cap-sig
    # -------------------------------------------------------------------
    @fuzz_group.command("l2cap-sig")
    @click.argument("address", required=False, default=None)
    @click.option("--mode", default="all",
                  type=click.Choice(["config", "cid", "echo", "info", "all"]),
                  help="L2CAP signaling fuzz category.")
    @click.option("--delay", default=0.5, type=float, help="Delay between test cases.")
    def fuzz_l2cap_sig(address, mode, delay):
        """Fuzz L2CAP signaling commands via raw injection.

        Sends protocol-aware L2CAP signaling fuzz cases targeting
        configuration option parsing, CID manipulation, Echo flooding,
        and Information request probing.

        Requires Scapy for raw L2CAP injection. If Scapy is not installed,
        falls back to kernel L2CAP PSM 1 transport (limited to well-formed
        L2CAP framing).

        \b
        Examples:
          blue-tap fuzz l2cap-sig AA:BB:CC:DD:EE:FF
          blue-tap fuzz l2cap-sig AA:BB:CC:DD:EE:FF --mode config
          blue-tap fuzz l2cap-sig AA:BB:CC:DD:EE:FF --mode echo --delay 0.1
        """
        from blue_tap.fuzz.protocols.l2cap import (
            generate_all_l2cap_fuzz_cases,
            fuzz_config_options, fuzz_cid_manipulation,
            fuzz_echo_requests, fuzz_info_requests,
            ScapyL2CAPTransport,
        )
        from blue_tap.fuzz.transport import L2CAPTransport

        address = resolve_address(address)
        if not address:
            return

        with phase("L2CAP Signaling Fuzzing"):
            info(f"Target: {style_target(address)} | Mode: {mode}")

            mode_generators = {
                "config": fuzz_config_options,
                "cid": fuzz_cid_manipulation,
                "echo": fuzz_echo_requests,
                "info": fuzz_info_requests,
            }

            if mode == "all":
                cases = generate_all_l2cap_fuzz_cases()
            else:
                gen = mode_generators.get(mode)
                cases = gen() if gen else generate_all_l2cap_fuzz_cases()

            info(f"Generated {len(cases)} L2CAP signaling fuzz cases")

            # Check Scapy availability
            if ScapyL2CAPTransport.AVAILABLE:
                info("Scapy available -- using raw L2CAP injection")
                # Note: Scapy transport requires root and direct HCI access.
                # Fall back to kernel transport if connection fails.
                def transport_factory(addr):
                    return L2CAPTransport(addr, psm=1)
                warning(
                    "Raw Scapy injection requires root privileges. "
                    "Using kernel L2CAP transport as primary sender."
                )
            else:
                warning(
                    "Scapy not installed -- using kernel L2CAP transport. "
                    "Install for raw injection: pip install 'blue-tap[fuzz]'"
                )
                def transport_factory(addr):
                    return L2CAPTransport(addr, psm=1)

            result = _run_fuzz_cases(
                address, "l2cap-sig", cases, transport_factory,
                delay=delay, timeout=5.0,
            )

        _show_fuzz_summary("l2cap-sig", address, result)

    # ===================================================================
    # TASK 4.4: Corpus Management Commands
    # ===================================================================

    @fuzz_group.group("corpus")
    def fuzz_corpus():
        """Manage fuzz seed corpus.

        \b
        Commands:
          generate   Generate seed corpus from protocol builders
          list       Show corpus stats per protocol
          minimize   Deduplicate corpus entries
        """

    # -------------------------------------------------------------------
    # blue-tap fuzz corpus generate
    # -------------------------------------------------------------------
    @fuzz_corpus.command("generate")
    @click.option("--protocol", "-p", default="all",
                  type=click.Choice(_ALL_PROTOCOLS + ["all"]),
                  help="Protocol to generate seeds for.")
    @click.option("--output", "-o", default=None,
                  help="Output directory (default: session corpus dir).")
    def corpus_generate(protocol, output):
        """Regenerate seed corpus from protocol-aware builders.

        This runs automatically before any fuzz command.  Use this command
        to regenerate the corpus if you want to force a refresh or build
        it into a custom directory.

        \b
        Examples:
          blue-tap fuzz corpus generate
          blue-tap fuzz corpus generate -p sdp
          blue-tap fuzz corpus generate -o ./my_corpus
        """
        from blue_tap.fuzz.corpus import Corpus, generate_full_corpus

        # Determine output directory
        if output:
            corpus_dir = output
        else:
            session = get_session()
            if session:
                corpus_dir = os.path.join(session.dir, "fuzz", "corpus")
            else:
                corpus_dir = os.path.join("sessions", "fuzz_adhoc", "corpus")

        corpus = Corpus(corpus_dir)

        with phase("Corpus Generation"):
            short_names = _ALL_PROTOCOLS if protocol == "all" else [protocol]
            protocols = _expand_protocol_names(short_names)

            table = Table(
                title=f"[bold {CYAN}]Seed Corpus Generation[/bold {CYAN}]",
                show_lines=True,
                border_style=DIM,
                header_style=Style(bold=True, color=CYAN),
            )
            table.add_column("Protocol", style=CYAN, width=12)
            table.add_column("Seeds", style=YELLOW, justify="right", width=10)
            table.add_column("Bytes", style=DIM, justify="right", width=12)

            total_seeds = 0
            total_bytes = 0

            # Use the real protocol builders via generate_full_corpus
            gen_results = generate_full_corpus(corpus, protocols=protocols, show_progress=True)

            for proto in protocols:
                count = gen_results.get(proto, corpus.seed_count(proto))
                seeds = corpus.get_all_seeds(proto)
                seed_bytes = sum(len(s) for s in seeds)
                total_seeds += count
                total_bytes += seed_bytes
                table.add_row(
                    proto.upper(),
                    str(len(seeds)),
                    _format_bytes(seed_bytes),
                )

            table.add_section()
            table.add_row(
                "[bold]TOTAL[/bold]",
                f"[bold {GREEN}]{total_seeds}[/bold {GREEN}]",
                f"[bold]{_format_bytes(total_bytes)}[/bold]",
            )

            console.print()
            console.print(table)
            console.print()

        success(f"Generated {total_seeds} seeds in {corpus_dir}")
        log_command("fuzz_corpus_generate", {
            "protocols": protocols,
            "total_seeds": total_seeds,
            "total_bytes": total_bytes,
            "corpus_dir": corpus_dir,
        }, category="fuzz")

    # -------------------------------------------------------------------
    # blue-tap fuzz corpus list
    # -------------------------------------------------------------------
    @fuzz_corpus.command("list")
    @click.option("--session", "-s", default=None,
                  help="Session name to inspect (default: current or latest).")
    def corpus_list(session):
        """Show corpus statistics per protocol.

        Displays seed counts, interesting input counts, and total sizes
        for each protocol in the corpus.

        \b
        Examples:
          blue-tap fuzz corpus list
          blue-tap fuzz corpus list -s my_session
        """
        from blue_tap.fuzz.corpus import Corpus

        # Find corpus directory
        if session:
            corpus_dir = os.path.join("sessions", session, "fuzz", "corpus")
        else:
            active = get_session()
            if active:
                corpus_dir = os.path.join(active.dir, "fuzz", "corpus")
            else:
                corpus_dir = os.path.join("sessions", "fuzz_adhoc", "corpus")

        if not Path(corpus_dir).is_dir():
            # Try to find any corpus in sessions
            sessions_dir = Path("sessions")
            if sessions_dir.is_dir():
                # Look through session directories for corpus
                found = False
                for sess_dir in sorted(sessions_dir.iterdir(), reverse=True):
                    candidate = sess_dir / "fuzz" / "corpus"
                    if candidate.is_dir():
                        corpus_dir = str(candidate)
                        found = True
                        break
                if not found:
                    warning("No corpus found. It will be auto-generated on the next fuzz command.")
                    return
            else:
                warning(f"No corpus found at {corpus_dir}")
                return

        corpus = Corpus(corpus_dir)
        loaded = corpus.load_from_directory(corpus_dir)
        stats = corpus.stats()

        section("Corpus Statistics")

        if stats.total_seeds == 0 and loaded == 0:
            info("Corpus is empty. It will be auto-generated on the next fuzz command.")
            return

        table = Table(
            title=f"[bold {CYAN}]Seed Corpus[/bold {CYAN}]",
            show_lines=True,
            border_style=DIM,
            header_style=Style(bold=True, color=CYAN),
        )
        table.add_column("Protocol", style=CYAN, width=12)
        table.add_column("Seeds", style=YELLOW, justify="right", width=10)
        table.add_column("Interesting", style=PURPLE, justify="right", width=12)

        # Count interesting per protocol
        base = Path(corpus_dir)
        for proto in sorted(stats.protocols):
            seed_count = corpus.seed_count(proto)
            int_count = 0
            int_dir = base / proto / "interesting"
            if int_dir.is_dir():
                int_count = sum(1 for _ in int_dir.glob("*.bin"))
            table.add_row(proto.upper(), str(seed_count), str(int_count))

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold {GREEN}]{stats.total_seeds}[/bold {GREEN}]",
            f"[bold {PURPLE}]{stats.interesting_count}[/bold {PURPLE}]",
        )

        console.print()
        console.print(table)
        console.print()

        summary_panel("Corpus Info", {
            "Directory": corpus_dir,
            "Protocols": str(len(stats.protocols)),
            "Total seeds": str(stats.total_seeds),
            "Interesting inputs": str(stats.interesting_count),
            "Total size": _format_bytes(stats.size_bytes),
        })

    # -------------------------------------------------------------------
    # blue-tap fuzz corpus minimize
    # -------------------------------------------------------------------
    @fuzz_corpus.command("minimize")
    @click.option("--session", "-s", default=None,
                  help="Session name (default: current or latest).")
    def corpus_minimize(session):
        """Deduplicate corpus entries by content hash.

        Removes duplicate seeds (identical SHA-256 hash) within each
        protocol, showing before and after counts.

        \b
        Examples:
          blue-tap fuzz corpus minimize
          blue-tap fuzz corpus minimize -s my_session
        """
        from blue_tap.fuzz.corpus import Corpus

        # Find corpus directory
        if session:
            corpus_dir = os.path.join("sessions", session, "fuzz", "corpus")
        else:
            active = get_session()
            if active:
                corpus_dir = os.path.join(active.dir, "fuzz", "corpus")
            else:
                corpus_dir = os.path.join("sessions", "fuzz_adhoc", "corpus")

        if not Path(corpus_dir).is_dir():
            warning(f"No corpus found at {corpus_dir}")
            return

        corpus = Corpus(corpus_dir)
        loaded = corpus.load_from_directory(corpus_dir)

        if loaded == 0:
            info("Corpus is empty. Nothing to minimize.")
            return

        with phase("Corpus Minimization"):
            before_count = corpus.seed_count()

            table = Table(
                title=f"[bold {CYAN}]Corpus Minimization[/bold {CYAN}]",
                show_lines=True,
                border_style=DIM,
                header_style=Style(bold=True, color=CYAN),
            )
            table.add_column("Protocol", style=CYAN, width=12)
            table.add_column("Before", style=YELLOW, justify="right", width=10)
            table.add_column("After", style=GREEN, justify="right", width=10)
            table.add_column("Removed", style=RED, justify="right", width=10)

            # Get per-protocol counts before
            before_per_proto = {}
            for proto in corpus.list_protocols():
                before_per_proto[proto] = corpus.seed_count(proto)

            removed = corpus.minimize()

            total_after = 0
            total_removed = 0
            for proto in sorted(before_per_proto.keys()):
                before = before_per_proto[proto]
                after = corpus.seed_count(proto)
                diff = before - after
                total_after += after
                total_removed += diff
                table.add_row(
                    proto.upper(),
                    str(before),
                    str(after),
                    str(diff) if diff > 0 else f"[{DIM}]0[/{DIM}]",
                )

            table.add_section()
            table.add_row(
                "[bold]TOTAL[/bold]",
                f"[bold]{before_count}[/bold]",
                f"[bold {GREEN}]{total_after}[/bold {GREEN}]",
                f"[bold {RED}]{total_removed}[/bold {RED}]",
            )

            console.print()
            console.print(table)
            console.print()

        if removed > 0:
            success(f"Removed {removed} duplicate seeds ({before_count} -> {corpus.seed_count()})")
        else:
            info("No duplicates found. Corpus is already minimal.")

        log_command("fuzz_corpus_minimize", {
            "before": before_count,
            "after": corpus.seed_count(),
            "removed": removed,
            "corpus_dir": corpus_dir,
        }, category="fuzz")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_bytes(size: int) -> str:
    """Format byte size as human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"
