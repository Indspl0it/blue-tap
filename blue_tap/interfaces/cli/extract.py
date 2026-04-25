"""CLI facade for post-exploitation data extraction."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli._module_runner import invoke_or_exit, resolve_target
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup, TargetSubcommandGroup


@click.group(cls=TargetSubcommandGroup)
@click.argument("target", required=False, default=None)
@click.option("--hci", "-a", default=None, help="HCI adapter (e.g. hci0)")
@click.pass_context
def extract(ctx, target, hci):
    """Pull data from a target device.

    \b
    Examples:
      blue-tap extract AA:BB:CC:DD:EE:FF contacts        # Extract from specific target
      blue-tap extract contacts                           # Interactive device picker
    """
    import sys as _sys

    ctx.ensure_object(dict)
    if any(a in ("--help", "-h") for a in _sys.argv[1:]):
        ctx.obj["target"] = target or ""
        ctx.obj["hci"] = hci
        return
    target = resolve_target(target, hci=hci, prompt="Select target for data extraction")
    if not target:
        raise SystemExit(1)
    ctx.obj["target"] = target
    ctx.obj["hci"] = hci


def _base_opts(ctx) -> dict[str, str]:
    opts = {"RHOST": ctx.obj["target"]}
    if ctx.obj["hci"]:
        opts["HCI"] = ctx.obj["hci"]
    return opts


@extract.command("contacts", cls=LoggedCommand)
@click.option("--phonebook", "-p", default=None,
              type=click.Choice(["pb", "ich", "och", "mch", "cch"]),
              help="Phonebook to extract (default: pb)")
@click.option("--all", "all_books", is_flag=True, help="Extract all phonebooks and call logs")
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_contacts(ctx, phonebook, all_books, channel):
    """Download phonebook and call logs via PBAP."""
    opts = _base_opts(ctx)
    if phonebook:
        opts["PHONEBOOK"] = phonebook
    if all_books:
        opts["ALL"] = "true"
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.pbap", opts)


@extract.command("messages", cls=LoggedCommand)
@click.option("--folder", "-f", default=None, help="Message folder (default: inbox)")
@click.option("--max-count", default=None, type=int, help="Maximum messages to list (default: 100)")
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_messages(ctx, folder, max_count, channel):
    """Download SMS/MMS messages via MAP."""
    opts = _base_opts(ctx)
    if folder:
        opts["FOLDER"] = folder
    if max_count is not None:
        opts["MAX_COUNT"] = str(max_count)
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.map", opts)


@extract.command("audio", cls=LoggedCommand)
@click.option("--action", default=None, type=click.Choice(["status", "dial", "answer", "hangup", "record"]),
              help="HFP action (default: status)")
@click.option("--number", default=None, help="Phone number for dial action")
@click.option("--duration", "-d", default=None, type=float, help="Recording duration in seconds (default: 10)")
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_audio(ctx, action, number, duration, channel):
    """HFP call audio — status, dial, record, or control calls."""
    opts = _base_opts(ctx)
    if action:
        opts["ACTION"] = action
    if number:
        opts["NUMBER"] = number
    if duration is not None:
        opts["DURATION"] = str(duration)
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.hfp", opts)


@extract.command("media", cls=LoggedCommand)
@click.option("--action", default=None, type=click.Choice(["status", "play", "pause", "next", "prev", "volume"]),
              help="AVRCP action (default: status)")
@click.option("--volume", default=None, type=int, help="Volume level 0-127 (for volume action)")
@click.pass_context
def extract_media(ctx, action, volume):
    """AVRCP media control — play, pause, skip, volume."""
    opts = _base_opts(ctx)
    if action:
        opts["ACTION"] = action
    if volume is not None:
        opts["VOLUME"] = str(volume)
    invoke_or_exit("post_exploitation.avrcp", opts)


@extract.command("stream", cls=LoggedCommand)
@click.option("--action", default=None, type=click.Choice(["record", "inject", "route"]),
              help="A2DP action (default: record)")
@click.option("--duration", "-d", default=None, type=float, help="Recording duration in seconds (default: 10)")
@click.option("--file", "audio_file", default=None, type=click.Path(exists=True),
              help="Audio file for inject action")
@click.option("--output", "-o", default=None, help="Output file for record action (default: a2dp_capture.wav)")
@click.pass_context
def extract_stream(ctx, action, duration, audio_file, output):
    """A2DP audio streaming — capture, record, eavesdrop, loopback."""
    opts = _base_opts(ctx)
    if action:
        opts["ACTION"] = action
    if duration is not None:
        opts["DURATION"] = str(duration)
    if audio_file:
        opts["FILE"] = audio_file
    if output:
        opts["OUTPUT"] = output
    invoke_or_exit("post_exploitation.a2dp", opts)


@extract.command("push", cls=LoggedCommand)
@click.argument("file", type=click.Path(exists=True))
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_push(ctx, file, channel):
    """Push a file to the device via OPP."""
    opts = _base_opts(ctx)
    opts["FILE"] = file
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.opp", opts)


@extract.command("snarf", cls=LoggedCommand)
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_snarf(ctx, channel):
    """Extract phonebook via Bluesnarfer AT commands."""
    opts = _base_opts(ctx)
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.bluesnarfer", opts)


@extract.command("at", cls=LoggedCommand)
@click.option("--command", "-c", "at_command", default=None,
              help="AT command: CPBR, CMGL, CGSN, CGMI, CGMR, DUMP, or raw AT command")
@click.option("--channel", default=None, type=int, help="RFCOMM channel (0=auto-discover)")
@click.pass_context
def extract_at(ctx, at_command, channel):
    """AT command data extraction via RFCOMM."""
    opts = _base_opts(ctx)
    if at_command:
        opts["COMMAND"] = at_command
    if channel is not None:
        opts["CHANNEL"] = str(channel)
    invoke_or_exit("post_exploitation.bluesnarfer", opts)
