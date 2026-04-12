"""Fuzzing CLI — campaign mode, legacy fuzzers, and crash management."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup
from blue_tap.utils.output import info, success, error, warning
from blue_tap.utils.interactive import resolve_address


# ============================================================================
# FUZZ - Protocol Fuzzing
# ============================================================================

@click.group(cls=LoggedGroup)
def fuzz():
    """Protocol fuzzing -- campaign mode, legacy fuzzers, and crash management.

    \b
    Campaign (multi-protocol, dashboard):
      blue-tap fuzz campaign AA:BB:CC:DD:EE:FF
      blue-tap fuzz campaign -p sdp -p rfcomm --duration 30m --capture
      blue-tap fuzz campaign --resume

    \b
    Crash management:
      blue-tap fuzz crashes list
      blue-tap fuzz crashes show 1
      blue-tap fuzz crashes replay 1
      blue-tap fuzz crashes export

    \b
    Legacy single-protocol fuzzers:
      blue-tap fuzz l2cap AA:BB:CC:DD:EE:FF
      blue-tap fuzz rfcomm AA:BB:CC:DD:EE:FF
      blue-tap fuzz at AA:BB:CC:DD:EE:FF
      blue-tap fuzz sdp AA:BB:CC:DD:EE:FF
      blue-tap fuzz bss AA:BB:CC:DD:EE:FF
    """


@fuzz.command("l2cap")
@click.argument("address", required=False, default=None)
@click.option("--psm", default=1, help="L2CAP PSM to fuzz")
@click.option("--count", default=100, help="Number of packets")
@click.option("--mode", default="malformed",
              type=click.Choice(["oversized", "malformed", "null"]))
def fuzz_l2cap(address, psm, count, mode):
    """Fuzz L2CAP protocol."""
    error(
        "'fuzz l2cap' has been removed. "
        "Use [bold]blue-tap fuzz run --protocol l2cap[/bold] for the campaign engine "
        "(coverage-guided, crash management, session persistence)."
    )


@fuzz.command("rfcomm")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--mode", default="exhaust",
              type=click.Choice(["exhaust", "overflow", "at"]))
def fuzz_rfcomm(address, channel, mode):
    """Fuzz RFCOMM protocol."""
    error(
        "'fuzz rfcomm' has been removed. "
        "Use [bold]blue-tap fuzz run --protocol rfcomm[/bold] for the campaign engine "
        "(coverage-guided, crash management, session persistence)."
    )


@fuzz.command("at")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--patterns", default="long,null,format,unicode,overflow",
              help="Comma-separated: long,null,format,unicode,overflow")
def fuzz_at(address, channel, patterns):
    """AT command fuzzing with malformed inputs."""
    error(
        "'fuzz at' has been removed. "
        "Use [bold]blue-tap fuzz run --protocol at-hfp[/bold] (or at-phonebook, at-sms, at-injection) "
        "for the campaign engine with protocol-aware mutation."
    )


@fuzz.command("sdp")
@click.argument("address", required=False, default=None)
def fuzz_sdp(address):
    """SDP continuation state probe (BlueBorne CVE-2017-0785 vector)."""
    error(
        "'fuzz sdp' has been removed. "
        "Use [bold]blue-tap fuzz run --protocol sdp[/bold] for the campaign engine "
        "with coverage-guided mutation and session persistence."
    )


@fuzz.command("bss")
@click.argument("address", required=False, default=None)
def fuzz_bss(address):
    """Run Bluetooth Stack Smasher (external tool)."""
    error(
        "'fuzz bss' has been removed. "
        "For integrated protocol fuzzing use [bold]blue-tap fuzz run[/bold] "
        "which provides coverage-guided mutation and crash management."
    )


@fuzz.command("lmp")
@click.argument("address", required=False, default=None)
@click.option("-c", "--count", default=1000, type=int, help="Number of fuzz iterations")
@click.option("-m", "--mode", default="all",
              type=click.Choice(["all", "knob", "features", "truncated", "oversized", "io_cap"]),
              help="Fuzz mode")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
def fuzz_lmp(address, count, mode, hci):
    """LMP protocol fuzzing via DarkFirmware RTL8761B.

    \b
    Sends malformed LMP packets directly at the Link Manager layer,
    bypassing the HCI boundary.  Requires an active connection to the
    target device.

    \b
    Modes: all (comprehensive), knob (CVE-2019-9506), features, truncated,
    oversized, io_cap (IO capability manipulation).
    """
    from blue_tap.framework.contracts.result_schema import make_run_id
    from blue_tap.framework.runtime.cli_events import emit_cli_event

    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz lmp' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol lmp --strategy coverage_guided[/bold] "
        "for the full campaign engine (17-byte PDUs, response analysis, session persistence)."
    )
    from blue_tap.hardware.hci_vsc import HCIVSCSocket
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.modules.fuzzing.protocols import lmp as lmp_proto

    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(f"hci{hci_dev}"):
        error("DarkFirmware not loaded. Run: blue-tap adapter firmware-status")
        return

    # Select fuzz generator based on mode
    generators = {
        "all": lmp_proto.generate_all_lmp_fuzz_cases,
        "knob": lmp_proto.fuzz_enc_key_size,
        "features": lmp_proto.fuzz_features,
        "truncated": lmp_proto.fuzz_truncated,
        "oversized": lmp_proto.fuzz_oversized,
        "io_cap": lmp_proto.fuzz_io_capabilities,
    }
    gen_func = generators.get(mode, lmp_proto.generate_all_lmp_fuzz_cases)

    run_id = make_run_id("fuzz")
    emit_cli_event(event_type="run_started", module="fuzz", run_id=run_id, target=address or "",
                   message=f"Starting LMP fuzz (mode={mode}, count={count})",
                   details={"mode": mode, "count": count, "hci": hci})
    info(f"Starting LMP fuzzing (mode={mode}, count={count})")

    try:
        with HCIVSCSocket(hci_dev) as vsc:
            sent = 0
            errors = 0
            for label, payload in gen_func():
                if sent >= count:
                    break
                try:
                    ok = vsc.send_lmp(payload)
                    if ok:
                        sent += 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1

                if sent % 100 == 0 and sent > 0:
                    info(f"  Progress: {sent}/{count} sent, {errors} errors")

            result = {"mode": mode, "sent": sent, "errors": errors, "count": count}
            from blue_tap.framework.sessions.store import log_command
            from blue_tap.framework.envelopes.fuzz import build_fuzz_operation_result
            envelope = build_fuzz_operation_result(
                target=address or "",
                adapter=hci,
                operation="fuzz_lmp",
                title="LMP Ad Hoc Fuzz Run",
                protocol="lmp",
                summary_data={"mode": mode, "sent": sent, "errors": errors, "count": count},
                observations=[
                    f"mode={mode}",
                    f"sent={sent}",
                    f"errors={errors}",
                    f"count={count}",
                ],
                module_data=result,
            )
            log_command("fuzz_lmp", envelope, category="fuzz", target=address or "")
            emit_cli_event(event_type="execution_result", module="fuzz", run_id=run_id, target=address or "",
                           message=f"LMP fuzz complete: {sent} sent, {errors} errors",
                           details={"mode": mode, "sent": sent, "errors": errors, "count": count})
            success(f"LMP fuzzing complete: {sent} packets sent, {errors} errors")
    except Exception as exc:
        error(f"LMP fuzzing failed: {exc}")
    emit_cli_event(event_type="run_completed", module="fuzz", run_id=run_id, target=address or "",
                   message="LMP fuzz run completed")


# Register new protocol-aware fuzz commands (campaign dashboard + crash management)
try:
    from blue_tap.modules.fuzzing.cli_commands import register_fuzz_commands
    register_fuzz_commands(fuzz)
except ImportError as exc:
    warning(f"Extended fuzz commands unavailable: {exc}")


__all__ = ["fuzz"]
