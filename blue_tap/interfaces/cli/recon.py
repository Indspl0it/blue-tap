"""CLI facade for target reconnaissance and enumeration."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup


@click.group(cls=LoggedGroup)
@click.argument("target")
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.pass_context
def recon(ctx, target, hci):
    """Enumerate services and fingerprint a target."""
    ctx.ensure_object(dict)
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
    invoke("reconnaissance.sdp", opts)


@recon.command("gatt", cls=LoggedCommand)
@click.pass_context
def recon_gatt(ctx):
    """BLE GATT attribute discovery — services, characteristics, descriptors."""
    invoke("reconnaissance.gatt", _base_opts(ctx))


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
    invoke("reconnaissance.l2cap_scan", opts)


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
    invoke("reconnaissance.rfcomm_scan", opts)


@recon.command("fingerprint", cls=LoggedCommand)
@click.pass_context
def recon_fingerprint(ctx):
    """Device fingerprinting — OS detection, chipset, firmware version."""
    invoke("reconnaissance.fingerprint", _base_opts(ctx))


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
    invoke("reconnaissance.hci_capture", opts)


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
    invoke("reconnaissance.sniffer", opts)


@recon.command("auto", cls=LoggedCommand)
@click.pass_context
def recon_auto(ctx):
    """Run all reconnaissance collectors against the target."""
    invoke("reconnaissance.campaign", _base_opts(ctx))


@recon.command("capabilities", cls=LoggedCommand)
@click.pass_context
def recon_capabilities(ctx):
    """Detect target capabilities — supported profiles, transports, features."""
    invoke("reconnaissance.capability_detector", _base_opts(ctx))


@recon.command("analyze", cls=LoggedCommand)
@click.option("--pcap", "-f", default=None, type=click.Path(exists=True),
              help="Path to pcap file (default: latest capture)")
@click.pass_context
def recon_analyze(ctx, pcap):
    """Analyze a captured pcap — protocol breakdown, anomalies, key events."""
    opts = _base_opts(ctx)
    if pcap:
        opts["PCAP"] = pcap
    invoke("reconnaissance.capture_analysis", opts)


@recon.command("correlate", cls=LoggedCommand)
@click.pass_context
def recon_correlate(ctx):
    """Correlate findings from multiple collectors into a unified profile."""
    invoke("reconnaissance.correlation", _base_opts(ctx))


@recon.command("interpret", cls=LoggedCommand)
@click.pass_context
def recon_interpret(ctx):
    """Interpret Bluetooth spec data — feature flags, version strings, class codes."""
    invoke("reconnaissance.spec_interpretation", _base_opts(ctx))
