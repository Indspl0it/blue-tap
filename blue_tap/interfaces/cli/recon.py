"""CLI facade for target reconnaissance and enumeration."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke_or_exit, resolve_target
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup, TargetSubcommandGroup


@click.group(cls=TargetSubcommandGroup)
@click.argument("target", required=False, default=None)
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.pass_context
def recon(ctx, target, hci):
    """Enumerate services and fingerprint a target.

    \b
    Examples:
      blue-tap recon AA:BB:CC:DD:EE:FF sdp              # Scan specific target
      blue-tap recon sdp                                 # Interactive device picker
    """
    import sys as _sys

    ctx.ensure_object(dict)
    # If the user asked for help on a subcommand, don't run the interactive
    # target picker — Click is about to print help text and exit.
    if any(a in ("--help", "-h") for a in _sys.argv[1:]):
        ctx.obj["target"] = target or ""
        ctx.obj["hci"] = hci
        return
    target = resolve_target(target, hci=hci, prompt="Select target for reconnaissance")
    if not target:
        raise SystemExit(1)
    ctx.obj["target"] = target
    ctx.obj["hci"] = hci


def _base_opts(ctx) -> dict[str, str]:
    opts = {"RHOST": ctx.obj["target"]}
    if ctx.obj["hci"]:
        opts["HCI"] = ctx.obj["hci"]
    return opts


@recon.command("sdp", cls=LoggedCommand)
@click.option("--retries", default=None, type=int, help="Retry count on transient failures (default: 2)")
@click.pass_context
def recon_sdp(ctx, retries):
    """SDP service enumeration — discover profiles and channels."""
    opts = _base_opts(ctx)
    if retries is not None:
        opts["RETRIES"] = str(retries)
    invoke_or_exit("reconnaissance.sdp", opts)


@recon.command("gatt", cls=LoggedCommand)
@click.pass_context
def recon_gatt(ctx):
    """BLE GATT attribute discovery — services, characteristics, descriptors."""
    invoke_or_exit("reconnaissance.gatt", _base_opts(ctx))


@recon.command("l2cap", cls=LoggedCommand)
@click.option("--start-psm", default=None, type=int, help="Start PSM (default: 1)")
@click.option("--end-psm", default=None, type=int, help="End PSM (default: 4097)")
@click.option("--timeout", default=None, type=int, help="Per-probe timeout in ms (default: 1000)")
@click.pass_context
def recon_l2cap(ctx, start_psm, end_psm, timeout):
    """L2CAP channel scanning — probe for open PSM channels."""
    opts = _base_opts(ctx)
    if start_psm is not None:
        opts["START_PSM"] = str(start_psm)
    if end_psm is not None:
        opts["END_PSM"] = str(end_psm)
    if timeout is not None:
        opts["TIMEOUT_MS"] = str(timeout)
    invoke_or_exit("reconnaissance.l2cap_scan", opts)


@recon.command("rfcomm", cls=LoggedCommand)
@click.option("--start-channel", default=None, type=int, help="First channel (default: 1)")
@click.option("--end-channel", default=None, type=int, help="Last channel (default: 30)")
@click.option("--timeout", default=None, type=int, help="Per-channel timeout in ms (default: 2000)")
@click.pass_context
def recon_rfcomm(ctx, start_channel, end_channel, timeout):
    """RFCOMM channel scanning — find open serial port channels."""
    opts = _base_opts(ctx)
    if start_channel is not None:
        opts["START_CHANNEL"] = str(start_channel)
    if end_channel is not None:
        opts["END_CHANNEL"] = str(end_channel)
    if timeout is not None:
        opts["TIMEOUT_MS"] = str(timeout)
    invoke_or_exit("reconnaissance.rfcomm_scan", opts)


@recon.command("fingerprint", cls=LoggedCommand)
@click.pass_context
def recon_fingerprint(ctx):
    """Device fingerprinting — OS detection, chipset, firmware version."""
    invoke_or_exit("reconnaissance.fingerprint", _base_opts(ctx))


@recon.command("capture", cls=LoggedCommand)
@click.option("--duration", "-d", default=None, type=int, help="Capture duration in seconds (default: 30)")
@click.option("--output", "-o", default=None, help="Output file path (default: hci_capture.pcap)")
@click.pass_context
def recon_capture(ctx, duration, output):
    """HCI traffic capture via btmon — save to pcap for Wireshark analysis."""
    opts = _base_opts(ctx)
    if duration is not None:
        opts["DURATION"] = str(duration)
    if output:
        opts["OUTPUT"] = output
    invoke_or_exit("reconnaissance.hci_capture", opts)


@recon.command("sniff", cls=LoggedCommand)
@click.option("--mode", "-m", default=None,
              type=click.Choice(["ble", "ble_connection", "ble_pairing", "lmp", "combined"]),
              help="Sniffing mode (default: ble)")
@click.option("--duration", "-d", default=None, type=int, help="Capture duration in seconds (default: 60)")
@click.option("--output", "-o", default=None, help="Output file path")
@click.pass_context
def recon_sniff(ctx, mode, duration, output):
    """BLE/LMP sniffing via nRF52840 or DarkFirmware."""
    opts = _base_opts(ctx)
    if mode:
        opts["MODE"] = mode
    if duration is not None:
        opts["DURATION"] = str(duration)
    if output:
        opts["OUTPUT"] = output
    invoke_or_exit("reconnaissance.sniffer", opts)


@recon.command("auto", cls=LoggedCommand)
@click.pass_context
def recon_auto(ctx):
    """Run all reconnaissance collectors against the target."""
    invoke_or_exit("reconnaissance.campaign", _base_opts(ctx))


@recon.command("capabilities", cls=LoggedCommand)
@click.pass_context
def recon_capabilities(ctx):
    """Detect target capabilities — supported profiles, transports, features."""
    invoke_or_exit("reconnaissance.capability_detector", _base_opts(ctx))


@recon.command("analyze", cls=LoggedCommand)
@click.option("--pcap", "-f", default=None, type=click.Path(exists=True),
              help="Path to pcap file (default: latest capture)")
@click.pass_context
def recon_analyze(ctx, pcap):
    """Analyze a captured pcap — protocol breakdown, anomalies, key events."""
    opts = _base_opts(ctx)
    if pcap:
        opts["PCAP"] = pcap
    invoke_or_exit("reconnaissance.capture_analysis", opts)


@recon.command("correlate", cls=LoggedCommand)
@click.pass_context
def recon_correlate(ctx):
    """Correlate findings from multiple collectors into a unified profile."""
    invoke_or_exit("reconnaissance.correlation", _base_opts(ctx))


@recon.command("interpret", cls=LoggedCommand)
@click.pass_context
def recon_interpret(ctx):
    """Interpret Bluetooth spec data — feature flags, version strings, class codes."""
    invoke_or_exit("reconnaissance.spec_interpretation", _base_opts(ctx))
