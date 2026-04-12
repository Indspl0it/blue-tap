"""Blue-Tap CLI entry point — wires all family modules into the main group."""

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
click.rich_click.STYLE_OPTION = "bold cyan"
click.rich_click.STYLE_ARGUMENT = "bold cyan"
click.rich_click.STYLE_COMMAND = "bold"

# Command grouping — pentest flow order
click.rich_click.COMMAND_GROUPS = {
    "blue-tap": [
        {"name": "Assessment", "commands": ["vulnscan", "fleet"]},
        {"name": "Discovery & Reconnaissance", "commands": ["scan", "recon", "adapter"]},
        {"name": "Exploitation", "commands": ["hijack", "bias", "knob", "bluffs", "encryption-downgrade", "ssp-downgrade", "spoof"]},
        {"name": "Data Extraction & Audio", "commands": ["pbap", "map", "at", "opp", "hfp", "audio", "avrcp"]},
        {"name": "Fuzzing & Stress Testing", "commands": ["fuzz", "dos"]},
        {"name": "Reporting & Automation", "commands": ["session", "report", "auto", "run"]},
        {"name": "Module Registry", "commands": ["list-modules", "module-info", "list-families"]},
    ],
}


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Verbosity: -v verbose, -vv debug")
@click.option("-s", "--session", "session_name", default=None,
              help="Session name (default: auto-generated from date/time). "
                   "Use to resume a previous session.")
def cli(verbose, session_name):
    """Blue-Tap: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI.

    \b
    Quick start:
      blue-tap adapter list                        # check adapters
      blue-tap scan classic                        # discover devices
      blue-tap vulnscan AA:BB:CC:DD:EE:FF          # vulnerability scan
      blue-tap hijack IVI_MAC PHONE_MAC            # full attack chain

    \b
    Sessions (automatic — all output is always saved):
      blue-tap scan classic                        # auto-session created
      blue-tap -s mytest scan classic              # named session
      blue-tap -s mytest vulnscan TARGET           # resume named session
      blue-tap session list                        # see all sessions
      blue-tap report                              # report from latest session
    """
    from blue_tap.utils.output import set_verbosity
    set_verbosity(verbose)

    # Determine the subcommand from Click context (works for both CLI and
    # in-process invocation via CliRunner or cli.make_context).
    ctx = click.get_current_context()
    invoked = ctx.invoked_subcommand or ""

    # Skip session creation for help and read-only commands
    if not invoked:
        return
    _NO_SESSION_COMMANDS = {"session", "report", "adapter"}
    if not session_name and invoked in _NO_SESSION_COMMANDS:
        return

    # Create session for active commands
    from blue_tap.framework.sessions.store import Session, set_session
    from datetime import datetime
    if not session_name:
        session_name = datetime.now().strftime("blue-tap_%Y%m%d_%H%M%S")
    session = Session(session_name)
    set_session(session)
    info(f"Session: [bold]{session_name}[/bold] -> {session.dir}")

    # ---- Hardware detection, DarkFirmware auto-flash, hook init, watchdog ----
    try:
        _startup_hardware_check(invoked, sys.argv[1:])
    except Exception:
        pass  # Don't let hardware detection break CLI startup


def _command_needs_darkfirmware_bootstrap(invoked: str, argv: list[str]) -> bool:
    """Return whether this invocation should auto-init DarkFirmware hooks."""
    root = (invoked or "").strip().lower()
    args = [str(item).strip().lower() for item in argv if str(item).strip()]

    if root in {"adapter", "doctor", "report", "session", "scan"}:
        return False
    if root in {"auto", "bias", "bluffs", "ctkd", "encryption-downgrade", "knob", "ssp-downgrade", "vulnscan"}:
        return True
    if root == "fuzz":
        return any(token in {"l2cap-sig", "lmp"} for token in args)
    if root == "recon":
        return any(token in {"combined-sniff", "lmp-monitor", "lmp-sniff"} for token in args)
    return False


def _startup_hardware_check(invoked: str, argv: list[str] | None = None) -> None:
    """Non-blocking hardware detection and DarkFirmware initialization.

    Sequence:
      1. Detect RTL8761B dongle via lsusb / sysfs
      2. If not found → warn about unavailable features, skip DarkFirmware
      3. If found → auto-flash DarkFirmware if not loaded
      4. Init all 4 hooks (RAM writes for Hooks 3+4)
      5. Start watchdog for USB reset/replug recovery
    """
    from blue_tap.hardware.firmware import DarkFirmwareManager, DarkFirmwareWatchdog
    from blue_tap.utils.bt_helpers import run_cmd

    argv = list(argv or [])
    fw = DarkFirmwareManager()

    # Step 1: Detect RTL8761B hardware — prefer sysfs/hciconfig detection
    # which is per-HCI, over lsusb which is global.
    # Try hci0 first since it's the most common index for USB dongles.
    dongle_hci = None
    for hci_dev in ("hci0", "hci1", "hci2"):
        if fw.detect_rtl8761b(hci_dev):
            dongle_hci = hci_dev
            break

    if dongle_hci is None:
        # Check if any BT adapter is present at all
        bt_result = run_cmd(["hciconfig"])
        has_any_adapter = bt_result.returncode == 0 and "hci" in bt_result.stdout.lower()

        if has_any_adapter:
            info(
                "RTL8761B dongle not detected — using system Bluetooth adapter.\n"
                "  [dim]Features unavailable without RTL8761B (TP-Link UB500):[/dim]\n"
                "  [dim]  - LMP injection/monitoring (BLUFFS, KNOB via LMP, BIAS via LMP)[/dim]\n"
                "  [dim]  - Encryption downgrade attacks[/dim]\n"
                "  [dim]  - LMP fuzzing and state confusion tests[/dim]\n"
                "  [dim]  - Below-stack L2CAP injection[/dim]\n"
                "  [dim]  - Connection table inspection[/dim]\n"
                "  [dim]All HCI-level features (scan, recon, vulnscan, hijack, fuzz L2CAP/RFCOMM/BLE, DoS) work normally.[/dim]"
            )
        else:
            warning(
                "No Bluetooth adapter detected.\n"
                "  [dim]Plug in a USB Bluetooth adapter and retry.[/dim]\n"
                "  [dim]Recommended: TP-Link UB500 (RTL8761B) for full feature access.[/dim]"
            )
        return

    if not _command_needs_darkfirmware_bootstrap(invoked, argv):
        return

    # Step 2: Check if DarkFirmware is loaded — prompt to install if not
    # (Don't auto-flash: user may have custom firmware or not want changes)
    if not fw.is_darkfirmware_loaded(dongle_hci):
        warning(
            f"RTL8761B detected on {dongle_hci} but DarkFirmware not loaded.\n"
            f"  Install with: [bold]sudo blue-tap adapter firmware-install --hci {dongle_hci}[/bold]\n"
            f"  [dim]Without DarkFirmware: LMP injection, BLUFFS, encryption downgrade, "
            f"and LMP fuzzing are unavailable.[/dim]"
        )
        return

    # Step 3: Initialize all 4 hooks (Hooks 3+4 need RAM writes)
    hook_status = fw.init_hooks(dongle_hci)
    if hook_status.get("all_ok"):
        info(
            f"[green]DarkFirmware active on {dongle_hci}[/green] — "
            f"all 4 hooks initialized (LMP inject/monitor, LC TX/RX logging)"
        )
    else:
        active = [k for k in ("hook1", "hook2", "hook3", "hook4") if hook_status.get(k)]
        failed = [k for k in ("hook1", "hook2", "hook3", "hook4") if not hook_status.get(k)]
        warning(
            f"DarkFirmware partially initialized on {dongle_hci} — "
            f"hooks: active=[{', '.join(active)}] failed=[{', '.join(failed)}]"
        )

    # Step 4: Start watchdog for USB reset/replug recovery
    watchdog = DarkFirmwareWatchdog(dongle_hci, poll_interval=30.0)
    watchdog.start()


# ── Wire sub-groups into the main CLI ────────────────────────────────────────

from blue_tap.interfaces.cli.adapter import adapter  # noqa: E402
from blue_tap.interfaces.cli.discovery import scan  # noqa: E402
from blue_tap.interfaces.cli.reconnaissance import recon  # noqa: E402
from blue_tap.interfaces.cli.post_exploitation import (  # noqa: E402
    pbap, map_cmd, doctor, hfp, audio, opp, at_cmd, avrcp,
)
from blue_tap.interfaces.cli.exploitation import (  # noqa: E402
    spoof, hijack, bias, dos, ssp_downgrade, knob, bluffs_attack, ctkd_cmd, encryption_downgrade,
)
from blue_tap.interfaces.cli.assessment import vulnscan, fleet  # noqa: E402
from blue_tap.interfaces.cli.fuzzing import fuzz  # noqa: E402
from blue_tap.interfaces.cli.reporting import report_cmd, auto_cmd, run_cmd_seq, session  # noqa: E402

cli.add_command(adapter)
cli.add_command(scan)
cli.add_command(recon)

# Post-exploitation
cli.add_command(pbap)
cli.add_command(map_cmd)
cli.add_command(doctor)
cli.add_command(hfp)
cli.add_command(audio)
cli.add_command(opp)
cli.add_command(at_cmd)
cli.add_command(avrcp)

# Exploitation
cli.add_command(spoof)
cli.add_command(hijack)
cli.add_command(bias)
cli.add_command(dos)
cli.add_command(ssp_downgrade)
cli.add_command(knob)
cli.add_command(bluffs_attack)
cli.add_command(ctkd_cmd)
cli.add_command(encryption_downgrade)

# Assessment
cli.add_command(vulnscan)
cli.add_command(fleet)

# Fuzzing
cli.add_command(fuzz)

# Reporting
cli.add_command(report_cmd)
cli.add_command(auto_cmd)
cli.add_command(run_cmd_seq)
cli.add_command(session)


# ── Module registry commands ──────────────────────────────────────────────────

@click.command("list-modules")
@click.option("--family", default=None, help="Filter by family (discovery, reconnaissance, assessment, exploitation, post_exploitation, fuzzing)")
@click.option("--all", "show_all", is_flag=True, help="Include internal modules")
def list_modules_cmd(family, show_all):
    """List all registered Blue-Tap modules grouped by family."""
    import blue_tap.modules.assessment  # trigger registration
    import blue_tap.modules.exploitation
    import blue_tap.modules.fuzzing
    import blue_tap.modules.post_exploitation
    import blue_tap.modules.reconnaissance
    import blue_tap.modules.discovery
    from blue_tap.framework.registry import get_registry
    from blue_tap.utils.output import info, console
    from rich.table import Table

    registry = get_registry()
    modules = registry.list_all()

    if not show_all:
        modules = [m for m in modules if not getattr(m, "internal", False)]
    if family:
        modules = [m for m in modules if m.family.value == family]

    if not modules:
        info("No modules registered" + (f" for family '{family}'" if family else ""))
        return

    # Group by family
    from collections import defaultdict
    by_family = defaultdict(list)
    for m in modules:
        by_family[m.family.value].append(m)

    for fam, mods in sorted(by_family.items()):
        table = Table(title=f"[bold]{fam}[/bold]", show_header=True)
        table.add_column("Module ID", style="cyan")
        table.add_column("Name")
        table.add_column("Description")
        table.add_column("Destructive", justify="center")
        for m in sorted(mods, key=lambda x: x.module_id):
            table.add_row(
                m.module_id,
                m.name,
                m.description,
                "[red]yes[/red]" if m.destructive else "[green]no[/green]",
            )
        console.print(table)


@click.command("module-info")
@click.argument("module_id")
def module_info_cmd(module_id):
    """Show metadata for a registered module."""
    import blue_tap.modules.assessment
    import blue_tap.modules.exploitation
    import blue_tap.modules.fuzzing
    import blue_tap.modules.post_exploitation
    import blue_tap.modules.reconnaissance
    import blue_tap.modules.discovery
    from blue_tap.framework.registry import get_registry
    from blue_tap.utils.output import info, error, console
    from rich.table import Table

    registry = get_registry()
    try:
        desc = registry.get(module_id)
    except KeyError:
        error(f"Module not found: {module_id}")
        return

    table = Table(title=f"Module: [bold]{module_id}[/bold]", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("ID", desc.module_id)
    table.add_row("Family", desc.family.value)
    table.add_row("Name", desc.name)
    table.add_row("Description", desc.description)
    table.add_row("Protocols", ", ".join(desc.protocols))
    table.add_row("Requires", ", ".join(desc.requires))
    table.add_row("Destructive", "[red]yes[/red]" if desc.destructive else "[green]no[/green]")
    table.add_row("Requires Pairing", "yes" if desc.requires_pairing else "no")
    table.add_row("Has Report Adapter", "yes" if desc.has_report_adapter else "no")
    table.add_row("Entry Point", desc.entry_point)
    table.add_row("Internal", "yes" if getattr(desc, "internal", False) else "no")
    console.print(table)


@click.command("list-families")
def list_families_cmd():
    """Show all module families with registration counts."""
    import blue_tap.modules.assessment
    import blue_tap.modules.exploitation
    import blue_tap.modules.fuzzing
    import blue_tap.modules.post_exploitation
    import blue_tap.modules.reconnaissance
    import blue_tap.modules.discovery
    from blue_tap.framework.registry import get_registry
    from blue_tap.utils.output import console
    from rich.table import Table
    from collections import defaultdict

    registry = get_registry()
    by_family = defaultdict(int)
    for m in registry.list_all():
        by_family[m.family.value] += 1

    table = Table(title="Module Families", show_header=True)
    table.add_column("Family", style="cyan")
    table.add_column("Modules", justify="right")
    for fam, count in sorted(by_family.items()):
        table.add_row(fam, str(count))
    console.print(table)


cli.add_command(list_modules_cmd)
cli.add_command(module_info_cmd)
cli.add_command(list_families_cmd)


# ── Demo command (hidden) ─────────────────────────────────────────────────────

@cli.command("demo", hidden=True)
@click.option("-o", "--output", default="demo_output", help="Output directory")
def demo_cmd(output):
    """Run a full demo pentest with simulated IVI data (no hardware needed)."""
    from blue_tap.demo.runner import run_demo
    run_demo(output_dir=output)


# ── Entry point ───────────────────────────────────────────────────────────────

def _check_privileges() -> bool:
    """Check if running with root/sudo.  Returns True if privileged."""
    return os.geteuid() == 0


# Commands that can run without root
_NO_ROOT_COMMANDS = {"--help", "-h", "--version", "demo"}


def main():
    """Entry point that shows the banner before any Click processing."""
    banner()

    # Allow --help, --version, and demo without root
    args_lower = {a.lower().lstrip("-") for a in sys.argv[1:]}
    raw_args = set(sys.argv[1:])

    needs_root_check = True
    if not sys.argv[1:]:
        needs_root_check = False  # No args = show help
    elif raw_args & {"--help", "-h", "--version"}:
        needs_root_check = False
    elif args_lower & {"help", "version"}:
        needs_root_check = False
    elif "demo" in args_lower:
        needs_root_check = False

    if needs_root_check and not _check_privileges():
        error(
            "Blue-Tap requires root privileges for most operations.\n"
            "\n"
            "  Why: Raw HCI sockets, L2CAP/RFCOMM sockets, adapter control,\n"
            "       DarkFirmware VSC commands, and firmware writes all require\n"
            "       root or CAP_NET_RAW.\n"
            "\n"
            "  Run with:  [bold]sudo blue-tap[/bold] <command>\n"
            "\n"
            "  Or grant capabilities:  sudo setcap cap_net_raw+eip $(which python3)\n"
            "\n"
            "  Commands that work without root: --help, --version, demo"
        )
        sys.exit(1)

    cli()


if __name__ == "__main__":
    main()
