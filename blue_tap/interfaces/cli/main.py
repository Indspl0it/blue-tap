"""Blue-Tap CLI entry point — modular Bluetooth security toolkit.

Phase-verb architecture: top-level commands map to assessment phases.
"""

from __future__ import annotations

import os
import sys

import rich_click as click

from blue_tap import __version__
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup
from blue_tap.utils.output import banner, info, error, warning

# ── Rich-Click Configuration ─────────────────────────────────────────
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.MAX_WIDTH = 120
click.rich_click.USE_CLICK_SHORT_HELP = False
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_OPTION = "bold"
click.rich_click.STYLE_ARGUMENT = "bold"
click.rich_click.STYLE_COMMAND = "bold"

# Command grouping — pentest workflow order. Top-level help shows only real
# Click commands and groups; users drill into each group's --help to discover
# subcommands (the standard pattern used by git, kubectl, gh, docker).
click.rich_click.COMMAND_GROUPS = {
    "blue-tap": [
        {"name": "Blue-Tap Workflow", "commands": [
            "discover", "recon", "vulnscan", "exploit", "dos", "extract", "fuzz", "report",
        ]},
        {"name": "Automation", "commands": ["auto", "fleet", "run-playbook"]},
        {"name": "Utilities", "commands": ["adapter", "session", "doctor", "spoof"]},
    ],
    "blue-tap discover": [
        {"name": "Discovery", "commands": ["classic", "ble", "all"]},
    ],
    "blue-tap recon": [
        {"name": "Service Enumeration", "commands": ["sdp", "gatt", "l2cap", "rfcomm"]},
        {"name": "Identity & Capability", "commands": [
            "fingerprint", "capabilities", "interpret",
        ]},
        {"name": "Capture & Analysis", "commands": ["capture", "sniff", "analyze"]},
        {"name": "Aggregation", "commands": ["auto", "correlate"]},
    ],
    "blue-tap exploit *": [
        {"name": "Crypto & Key Attacks", "commands": [
            "bias", "bluffs", "knob", "ctkd", "enc-downgrade", "ssp-downgrade",
        ]},
        {"name": "Full Chain", "commands": ["hijack", "pin-brute"]},
    ],
    "blue-tap extract *": [
        {"name": "Contacts", "commands": ["contacts", "messages"]},
        {"name": "Media", "commands": ["audio", "media", "stream"]},
        {"name": "Files", "commands": ["push", "snarf", "at"]},
    ],
    "blue-tap fuzz": [
        {"name": "Protocols", "commands": [
            "campaign", "sdp-deep", "l2cap-sig", "rfcomm-raw", "ble-att", "ble-smp",
            "bnep", "obex", "at-deep",
        ]},
        {"name": "Analysis", "commands": ["crashes", "minimize", "cve", "replay"]},
        {"name": "Corpus", "commands": ["corpus"]},
    ],
}


# Subcommands of these groups that don't touch hardware.
_NO_HW_SUBCOMMANDS = {
    "fuzz": {"crashes", "corpus", "minimize"},
}

# Top-level commands whose entire surface is on-disk / registry-only and
# therefore needs neither root nor an RTL8761B dongle. Both the privilege
# gate and the chipset gate consult ``_subcommand_needs_hw()`` (which reads
# this set), so these two gates always agree on what a "read-only" path is.
_NO_HW_INVOKED = {
    "session", "doctor", "demo", "report",
    "search", "info", "show-options", "plugins",
}


def _help_in_argv() -> bool:
    return any(a in ("--help", "-h") for a in sys.argv[1:])


def _subcommand_needs_hw(invoked: str) -> bool:
    """Return False if the invoked subcommand path doesn't need Bluetooth hardware."""
    if invoked in _NO_HW_INVOKED:
        return False
    if invoked == "run-playbook" and "--list" in sys.argv:
        return False
    sub_skip = _NO_HW_SUBCOMMANDS.get(invoked)
    if sub_skip:
        # Find the second positional after the group name (skipping global flags).
        positional: list[str] = []
        skip_next = False
        global_value_flags = {"-s", "--session"}
        for token in sys.argv[1:]:
            if skip_next:
                skip_next = False
                continue
            if token in global_value_flags:
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            positional.append(token)
        if len(positional) >= 2 and positional[1] in sub_skip:
            return False
    return True


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, metavar="",
              help="Increase verbosity: pass -v for verbose, -vv for debug.")
@click.option("-s", "--session", "session_name", default=None,
              help="Session name (default: auto-generated). Use to resume a session.")
@click.option("--config", "config_path", default=None,
              type=click.Path(dir_okay=False),
              help="Path to a blue-tap TOML config file (overrides $BLUE_TAP_CONFIG and ~/.config/blue-tap/config.toml).")
@click.option("--dry-run", "dry_run", is_flag=True, default=False,
              help="Print the resolved plan and exit without touching hardware or sending packets. "
                   "Honors $BLUE_TAP_DRY_RUN=1 as an alternative.")
@click.pass_context
def cli(ctx, verbose, session_name, config_path, dry_run):
    """Blue-Tap: Bluetooth Security Toolkit for Automotive & IoT.

    \b
    Quick start:
      blue-tap discover classic                       # 1. Find targets
      blue-tap recon AA:BB:CC:DD:EE:FF sdp            # 2. Enumerate services
      blue-tap vulnscan AA:BB:CC:DD:EE:FF             # 3. Vulnerability scan
      blue-tap exploit AA:BB:CC:DD:EE:FF knob         # 4. Run exploit
      blue-tap extract AA:BB:CC:DD:EE:FF contacts     # 5. Extract data
      blue-tap report                                 # 6. Generate report

    \b
    Sessions (automatic — all output is always saved):
      blue-tap -s mytest vulnscan TARGET              # named session
      blue-tap session list                           # see all sessions
      blue-tap report                                 # report from latest session
    """
    from blue_tap.utils.output import set_verbosity
    set_verbosity(verbose)

    # Dry-run: root flag OR $BLUE_TAP_DRY_RUN=1. Stored in ctx.obj so every
    # subcommand reads from a single place. Env-var honoring lets the playbook
    # executor scope dry-run across re-entered ``make_context`` calls without
    # leaking process-wide state between independent invocations.
    dry_run = bool(dry_run) or os.environ.get("BLUE_TAP_DRY_RUN", "").lower() in ("1", "true", "yes")
    ctx.ensure_object(dict)
    ctx.obj["dry_run"] = dry_run
    if dry_run:
        info("[bt.yellow]Dry-run mode[/bt.yellow] — no hardware will be touched.")

    # Load user config (~/.config/blue-tap/config.toml etc). Failures are
    # surfaced loudly so a typo never silently disables the override.
    from blue_tap.framework.config import (
        ConfigError,
        build_default_map,
        load_config,
    )
    try:
        user_cfg = load_config(config_path, cli_root=cli)
    except ConfigError as cfg_exc:
        error(str(cfg_exc))
        sys.exit(2)

    if user_cfg is not None:
        # ``[default].session`` covers the root ``-s/--session`` option,
        # which is parsed before the subcommand context exists — Click's
        # ``default_map`` cannot reach back to it. Apply manually.
        if session_name is None and "session" in user_cfg.default:
            session_name = user_cfg.default["session"]
        # Subcommand options (``--hci`` on every subcommand that has it,
        # etc.) flow naturally through ``ctx.default_map``.
        ctx.default_map = build_default_map(cli, user_cfg)

    invoked = ctx.invoked_subcommand or ""
    if not invoked:
        return

    # ``--help`` / ``-h`` anywhere on the line means the user wants help text,
    # not to actually run anything — bypass privilege/hardware gates and let
    # Click's help mechanism take over.
    if _help_in_argv():
        return

    # Root + RTL gates run AFTER Click has resolved the subcommand, so an
    # unknown command name or missing required argument surfaces with Click's
    # native error before we ever reach a privilege/hardware check. The two
    # gates share one skip predicate: if the subcommand path doesn't touch
    # Bluetooth hardware, it doesn't need root either (both gates exist for
    # raw-HCI access).
    # Dry-run skips the privilege + RTL dongle gates: the whole point is to
    # preview without touching hardware, so root and a present dongle are not
    # prerequisites.
    if dry_run:
        return

    if _subcommand_needs_hw(invoked):
        if not _check_privileges():
            error(
                "Blue-Tap requires root for Bluetooth operations.\n"
                "\n"
                "  Run with: [bold]sudo blue-tap[/bold] <command>\n"
                "\n"
                "  Or: sudo setcap cap_net_raw+eip $(which python3)\n"
                "\n"
                "  [dim]No root needed: --help, --version, doctor, demo, session, "
                "report, fuzz crashes/corpus/minimize, run-playbook --list, "
                "search, info, show-options, plugins[/dim]"
            )
            sys.exit(1)
        _check_rtl_dongle()

    # Session creation — skip for read-only and help-only invocations.
    if _help_in_argv():
        return

    _NO_SESSION_COMMANDS = {
        "session", "report", "adapter", "plugins", "doctor",
        "run", "run-playbook", "search", "info", "show-options",
    }
    if not session_name and invoked in _NO_SESSION_COMMANDS:
        return
    if invoked == "run-playbook" and "--list" in sys.argv:
        return
    # Read-only subcommands (e.g. ``fuzz crashes list``) don't need a session
    # either — they only inspect prior on-disk artefacts.
    if not session_name and not _subcommand_needs_hw(invoked):
        return

    from blue_tap.framework.sessions.store import Session, set_session
    from datetime import datetime
    if not session_name:
        session_name = datetime.now().strftime("blue-tap_%Y%m%d_%H%M%S")
    session = Session(session_name)
    set_session(session)
    info(f"Session: [bold]{session_name}[/bold]")


def _init_darkfirmware_hooks(dongle_hci: str) -> None:
    """Initialize DarkFirmware hooks and start watchdog on the detected dongle."""
    os.environ["BT_TAP_DARKFIRMWARE_HCI"] = dongle_hci

    from blue_tap.hardware.firmware import DarkFirmwareManager, DarkFirmwareWatchdog

    fw = DarkFirmwareManager()
    hook_status = fw.init_hooks(dongle_hci)
    if hook_status.get("all_ok"):
        info(f"[bt.green]DarkFirmware ready[/bt.green] on {dongle_hci}")
    else:
        active = [k for k in ("hook1", "hook2", "hook3", "hook4") if hook_status.get(k)]
        warning(f"DarkFirmware partial: {', '.join(active)} active")

    watchdog = DarkFirmwareWatchdog(dongle_hci, poll_interval=30.0)
    watchdog.start()


# ── Import and register commands ─────────────────────────────────────────────

# Assessment workflow
from blue_tap.interfaces.cli.discover import discover  # noqa: E402
from blue_tap.interfaces.cli.recon import recon  # noqa: E402
from blue_tap.interfaces.cli.vulnscan import vulnscan  # noqa: E402
from blue_tap.interfaces.cli.exploit import exploit  # noqa: E402
from blue_tap.interfaces.cli.dos import dos  # noqa: E402
from blue_tap.interfaces.cli.extract import extract  # noqa: E402
from blue_tap.interfaces.cli.fuzz import fuzz  # noqa: E402
from blue_tap.interfaces.cli.reporting import report_cmd, run_playbook_cmd, session  # noqa: E402

cli.add_command(discover)
cli.add_command(recon)
cli.add_command(vulnscan)
cli.add_command(exploit)
cli.add_command(dos)
cli.add_command(extract)
cli.add_command(fuzz)
cli.add_command(report_cmd)

# Automation
from blue_tap.interfaces.cli.auto import auto  # noqa: E402
from blue_tap.interfaces.cli.fleet import fleet  # noqa: E402

cli.add_command(auto)
cli.add_command(fleet)

# Utilities
from blue_tap.interfaces.cli.adapter import adapter  # noqa: E402
from blue_tap.interfaces.cli.doctor import doctor  # noqa: E402
from blue_tap.interfaces.cli.spoof import spoof  # noqa: E402

cli.add_command(adapter)
cli.add_command(session)
cli.add_command(doctor)
cli.add_command(spoof)

# Hidden power-user commands (not shown in --help, still functional)
from blue_tap.interfaces.cli.runner import run_cmd, search_cmd, info_cmd, show_options_cmd  # noqa: E402
from blue_tap.interfaces.cli.plugins import plugins  # noqa: E402

cli.add_command(run_cmd, "run")
cli.add_command(search_cmd, "search")
cli.add_command(info_cmd, "info")
cli.add_command(show_options_cmd, "show-options")
cli.add_command(plugins)
cli.add_command(run_playbook_cmd)

# Mark hidden — power-user commands stay off the main help.
# ``run-playbook`` is a real workflow command and is intentionally listed.
for _name in ("run", "search", "info", "show-options", "plugins"):
    _cmd = cli.commands.get(_name)
    if _cmd:
        _cmd.hidden = True


# ── Demo command (hidden) ─────────────────────────────────────────────────────

@cli.command("demo", hidden=True)
@click.option("-o", "--output", default="demo_output", help="Output directory")
def demo_cmd(output):
    """Run a demo with simulated data (no hardware needed)."""
    from blue_tap.demo.runner import run_demo
    run_demo(output_dir=output)


# ── Entry point ───────────────────────────────────────────────────────────────

def _check_privileges() -> bool:
    """Check if running with root/sudo.

    Honors ``BLUE_TAP_SKIP_ROOT_CHECK=1`` so test runners and CI can exercise
    hardware-gated subcommands without holding raw-HCI capabilities. The bypass
    is intentionally opt-in via an explicit env var — never inferred.
    """
    if os.environ.get("BLUE_TAP_SKIP_ROOT_CHECK") == "1":
        return True
    return os.geteuid() == 0


def _check_rtl_dongle() -> None:
    """Detect RTL8761B dongle at startup and offer to flash DarkFirmware."""
    if os.environ.get("BLUE_TAP_SKIP_ROOT_CHECK") == "1":
        return
    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        from blue_tap.utils.output import console
        from rich.prompt import Confirm
    except ImportError:
        return

    fw = DarkFirmwareManager()

    try:
        dongle_hci = fw.find_rtl8761b_hci()
    except Exception:
        dongle_hci = None

    if dongle_hci is None:
        console.print(
            "[bold red]No RTL8761B / TP-Link UB500 dongle detected.[/bold red] "
            "Blue-tap requires a Realtek RTL8761B chipset."
        )
        sys.exit(1)

    try:
        from blue_tap.utils.bt_helpers import get_hci_adapters
        adapters = {a["name"]: a for a in get_hci_adapters()}
        if adapters.get(dongle_hci, {}).get("status") != "UP":
            return
    except Exception:
        pass

    try:
        df_loaded = fw.is_darkfirmware_loaded(dongle_hci)
    except Exception:
        info(f"[dim]RTL8761B detected on {dongle_hci} — firmware status unavailable[/dim]")
        return

    if df_loaded:
        _init_darkfirmware_hooks(dongle_hci)
        return

    console.print()
    console.print(
        f"[bold bt.yellow]RTL8761B dongle detected[/bold bt.yellow] on [bold]{dongle_hci}[/bold] "
        f"— [bt.yellow]stock firmware[/bt.yellow] is loaded."
    )
    console.print(
        "  DarkFirmware enables LMP injection, BDADDR spoofing, and below-HCI attacks\n"
        "  (BIAS, BLUFFS, KNOB, CTKD, LMP fuzzing).\n"
        "  The bundled firmware binary is a patched Realtek image with four hook points;\n"
        "  original firmware is backed up and restorable via [bold]blue-tap adapter firmware-install --restore[/bold]."
    )
    console.print()

    try:
        flash = Confirm.ask(
            "  [bold]Flash DarkFirmware now?[/bold] (original will be backed up)",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        info(f"[dim]Skipping firmware flash (non-interactive). "
             f"Run: blue-tap adapter firmware-install[/dim]")
        console.print()
        return

    console.print()
    if not flash:
        info(
            "[dim]Continuing with stock firmware. "
            "Run [bold]blue-tap adapter firmware-install[/bold] to enable LMP-level features.[/dim]"
        )
        console.print()
        return

    info(f"Installing DarkFirmware on {dongle_hci}…")
    try:
        ok = fw.install_firmware()
    except Exception as exc:
        error(f"Firmware install failed: {exc}")
        console.print()
        return

    if not ok:
        error(
            "Firmware install returned failure. "
            "Retry manually: [bold]sudo blue-tap adapter firmware-install[/bold]"
        )
        console.print()
        return

    info("Resetting USB dongle to load new firmware…")
    try:
        new_hci = fw.usb_reset_and_wait()
    except Exception as exc:
        warning(f"USB reset failed ({exc}). Unplug and re-plug the dongle to activate DarkFirmware.")
        console.print()
        return

    if new_hci is None:
        warning(
            f"Firmware installed, but adapter did not re-enumerate cleanly. "
            f"Unplug and re-plug the dongle to activate DarkFirmware."
        )
        console.print()
        return

    info(f"[bold green]DarkFirmware installed and active on {new_hci}.[/bold green]")
    console.print()


def main():
    """Entry point — shows banner, loads modules, and dispatches to Click.

    Privilege/hardware gates have moved inside the :func:`cli` callback so
    that Click's argument parsing (unknown command, missing required arg)
    surfaces with its native error message before any of those gates fire.
    """
    _SILENT_COMMANDS = {
        "search", "info", "show-options", "plugins",
        "adapter", "session", "report", "doctor",
    }
    _first_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    _is_help_or_version = (
        not sys.argv[1:] or
        any(a in ("--help", "-h", "--version") for a in sys.argv[1:])
    )
    _is_silent = (
        _is_help_or_version or
        _first_arg in _SILENT_COMMANDS or
        (_first_arg == "run-playbook" and "--list" in sys.argv)
    )

    if not _is_silent:
        banner()

    try:
        from blue_tap.framework.module import autoload_builtin_modules
        from blue_tap.framework.module.loader import get_plugin_registry
        from blue_tap.framework.registry import get_registry

        autoload_builtin_modules()

        registry = get_registry()
        total = len([m for m in registry.list_all() if not getattr(m, "internal", False)])

        if not _is_silent:
            plugin_registry = get_plugin_registry()
            if plugin_registry:
                loaded = [n for n, d in plugin_registry.items() if d.get("loaded")]
                failed = [n for n, d in plugin_registry.items() if not d.get("loaded")]
                if loaded:
                    info(f"[dim]{total} modules loaded (+{len(loaded)} plugin(s))[/dim]")
                for name in failed:
                    warning(f"[dim]Plugin '{name}' failed to load[/dim]")
            else:
                info(f"[dim]{total} modules loaded[/dim]")

    except Exception as e:
        warning(f"Module loading failed: {e}")

    cli()


if __name__ == "__main__":
    main()
