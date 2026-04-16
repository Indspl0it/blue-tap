"""Adapter management CLI commands."""

from __future__ import annotations

import rich_click as click

from blue_tap.framework.runtime.cli_events import emit_cli_event
from blue_tap.hardware.adapter import resolve_active_hci
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup
from blue_tap.utils.output import (
    info, success, error, warning, verbose, console, summary_panel, bare_table, print_table,
)


def _resolve_df_hci(hci: str | None) -> str | None:
    """Resolve the DarkFirmware HCI device.

    Resolution order:
      1. Explicit ``--hci`` value from the user
      2. ``BT_TAP_DARKFIRMWARE_HCI`` env var (set at startup by main.py)
      3. USB VID:PID discovery via DarkFirmwareManager.find_rtl8761b_hci()
    """
    import os as _os
    if hci:
        return hci
    env_hci = _os.environ.get("BT_TAP_DARKFIRMWARE_HCI")
    if env_hci:
        return env_hci
    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        return DarkFirmwareManager().find_rtl8761b_hci()
    except Exception:
        return None


@click.group(cls=LoggedGroup)
def adapter():
    """HCI Bluetooth adapter management."""


@adapter.command("list")
def adapter_list():
    """List available Bluetooth adapters with chipset and capability info."""
    from blue_tap.hardware.adapter import list_adapters, recommend_adapter_roles

    adapters = list_adapters()
    if not adapters:
        return

    table = bare_table()
    table.title = "[bold]HCI Adapters[/bold]"
    table.add_column("Name", style="bold")
    table.add_column("Address", style="bt.purple")
    table.add_column("Chipset")
    table.add_column("BT Ver")
    table.add_column("Features")
    table.add_column("Spoof?")
    table.add_column("Status")

    for a in adapters:
        status_style = "bt.green" if a["status"] == "UP" else "bt.red"
        chipset = a.get("chipset", a.get("type", ""))
        bt_ver = a.get("bt_version", "")
        features = ", ".join(a.get("features", [])[:5])
        can_spoof = a.get("capabilities", {}).get("address_change")
        spoof_str = {True: "[bt.green]Yes[/bt.green]", False: "[bt.red]No[/bt.red]", None: "[bt.dim]?[/bt.dim]"}[can_spoof]
        table.add_row(a["name"], a["address"], chipset, bt_ver, features, spoof_str,
                       f"[{status_style}]{a['status']}[/{status_style}]")

    print_table(table)

    if len(adapters) >= 1:
        rec = recommend_adapter_roles(adapters)
        for note in rec.get("notes", []):
            info(note)


@adapter.command("info")
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def adapter_info(hci):
    """Show detailed adapter info: chipset, features, capabilities."""
    from blue_tap.hardware.adapter import get_adapter_info, _adapter_exists
    hci = _resolve_df_hci(hci) or resolve_active_hci()
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
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def up(hci):
    """Bring adapter up."""
    hci = _resolve_df_hci(hci) or resolve_active_hci()
    from blue_tap.hardware.adapter import adapter_up
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    started = now_iso()
    run_id = make_run_id("general")
    emit_cli_event(
        event_type="run_started", module="general", run_id=run_id,
        adapter=hci, message=f"Bringing adapter {hci} up",
        echo=False,
    )
    result = adapter_up(hci)
    ok = result["success"]
    emit_cli_event(
        event_type="execution_result", module="general", run_id=run_id,
        adapter=hci, message=f"adapter up {'succeeded' if ok else 'failed'} on {hci}",
        details={"success": ok, "error": result.get("error")},
        echo=False,
    )
    envelope = build_run_envelope(
        schema="blue_tap.general.result",
        module="general",
        target=hci,
        adapter=hci,
        operator_context={"operation": "adapter_up"},
        summary={"success": ok},
        executions=[],
        module_data={"operation": "adapter_up", "hci": hci, "success": ok, "error": result.get("error")},
        started_at=started,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="general", run_id=run_id, adapter=hci,
        message=f"adapter up {'complete' if ok else 'failed'}: {hci}",
        details={"success": ok},
        echo=False,
    )
    log_command("adapter_up", envelope, category="general")


@adapter.command()
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def down(hci):
    """Bring adapter down."""
    hci = _resolve_df_hci(hci) or resolve_active_hci()
    from blue_tap.hardware.adapter import adapter_down
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    started = now_iso()
    run_id = make_run_id("general")
    emit_cli_event(
        event_type="run_started", module="general", run_id=run_id,
        adapter=hci, message=f"Bringing adapter {hci} down",
        echo=False,
    )
    result = adapter_down(hci)
    ok = result["success"]
    emit_cli_event(
        event_type="execution_result", module="general", run_id=run_id,
        adapter=hci, message=f"adapter down {'succeeded' if ok else 'failed'} on {hci}",
        details={"success": ok, "error": result.get("error")},
        echo=False,
    )
    envelope = build_run_envelope(
        schema="blue_tap.general.result",
        module="general",
        target=hci,
        adapter=hci,
        operator_context={"operation": "adapter_down"},
        summary={"success": ok},
        executions=[],
        module_data={"operation": "adapter_down", "hci": hci, "success": ok, "error": result.get("error")},
        started_at=started,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="general", run_id=run_id, adapter=hci,
        message=f"adapter down {'complete' if ok else 'failed'}: {hci}",
        details={"success": ok},
        echo=False,
    )
    log_command("adapter_down", envelope, category="general")


@adapter.command()
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def reset(hci):
    """Reset adapter."""
    hci = _resolve_df_hci(hci) or resolve_active_hci()
    from blue_tap.hardware.adapter import adapter_reset
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    started = now_iso()
    run_id = make_run_id("general")
    emit_cli_event(
        event_type="run_started", module="general", run_id=run_id,
        adapter=hci, message=f"Resetting adapter {hci}",
        echo=False,
    )
    result = adapter_reset(hci)
    ok = result["success"]
    emit_cli_event(
        event_type="execution_result", module="general", run_id=run_id,
        adapter=hci, message=f"adapter reset {'succeeded' if ok else 'failed'} on {hci}",
        details={"success": ok, "error": result.get("error")},
        echo=False,
    )
    envelope = build_run_envelope(
        schema="blue_tap.general.result",
        module="general",
        target=hci,
        adapter=hci,
        operator_context={"operation": "adapter_reset"},
        summary={"success": ok},
        executions=[],
        module_data={"operation": "adapter_reset", "hci": hci, "success": ok, "error": result.get("error")},
        started_at=started,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="general", run_id=run_id, adapter=hci,
        message=f"adapter reset {'complete' if ok else 'failed'}: {hci}",
        details={"success": ok},
        echo=False,
    )
    log_command("adapter_reset", envelope, category="general")


@adapter.command("set-name")
@click.argument("name")
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def set_name(name, hci):
    """Set adapter Bluetooth name (for impersonation)."""
    hci = _resolve_df_hci(hci) or resolve_active_hci()
    from blue_tap.hardware.adapter import set_device_name
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    started = now_iso()
    run_id = make_run_id("general")
    emit_cli_event(
        event_type="run_started", module="general", run_id=run_id,
        adapter=hci, message=f"Setting adapter {hci} name to {name!r}",
        echo=False,
    )
    try:
        result = set_device_name(hci, name)
    except ValueError as exc:
        error(str(exc))
        emit_cli_event(
            event_type="run_error", module="general", run_id=run_id,
            adapter=hci, message=f"adapter set-name validation failed: {exc}",
            details={"error": str(exc)},
            echo=False,
        )
        return
    ok = result["success"]
    emit_cli_event(
        event_type="execution_result", module="general", run_id=run_id,
        adapter=hci, message=f"adapter name set to {result['name']!r} on {hci}",
        details={"success": ok, "name": result["name"], "previous_name": result.get("previous_name")},
        echo=False,
    )
    envelope = build_run_envelope(
        schema="blue_tap.general.result",
        module="general",
        target=hci,
        adapter=hci,
        operator_context={"operation": "adapter_set_name", "name": name},
        summary={"success": ok},
        executions=[],
        module_data={
            "operation": "adapter_set_name",
            "hci": hci,
            "name": result["name"],
            "previous_name": result.get("previous_name"),
            "success": ok,
        },
        started_at=started,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="general", run_id=run_id, adapter=hci,
        message=f"adapter set-name {'complete' if ok else 'failed'}: {name!r} on {hci}",
        details={"success": ok},
        echo=False,
    )
    log_command("adapter_set_name", envelope, category="general")


_DEVICE_CLASS_PRESETS = {
    "phone":      "0x5a020c",  # Smartphone
    "laptop":     "0x5a0100",  # Laptop/notebook
    "headset":    "0x200404",  # Headset (audio)
    "headphones": "0x240404",  # Headphones
    "speaker":    "0x240414",  # Portable audio speaker
    "keyboard":   "0x002540",  # HID keyboard
    "mouse":      "0x002580",  # HID mouse
    "gamepad":    "0x002508",  # HID gamepad
    "car":        "0x200420",  # Hands-free car kit
    "watch":      "0x70020c",  # Wearable/smartwatch
    "tablet":     "0x5a0100",  # Tablet (same CoD as laptop)
    "printer":    "0x040680",  # Printer
    "camera":     "0x040100",  # Imaging/camera
}

_PRESET_HELP = "\b\nPresets (use name or raw hex):\n" + "\n".join(
    f"  {name:<12} {code}  {desc}"
    for (name, code), desc in zip(
        _DEVICE_CLASS_PRESETS.items(),
        ["Smartphone", "Laptop", "Headset", "Headphones", "Speaker",
         "Keyboard", "Mouse", "Gamepad", "Hands-free car kit",
         "Smartwatch", "Tablet", "Printer", "Camera"],
    )
)


@adapter.command("set-class")
@click.argument("device_class", default="phone")
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def set_class(device_class, hci):
    """Set device class for impersonation. Accepts a preset name or raw hex (e.g. 0x5a020c).

    \b
    Presets:
      phone        0x5a020c  Smartphone
      laptop       0x5a0100  Laptop
      headset      0x200404  Headset (audio)
      headphones   0x240404  Headphones
      speaker      0x240414  Portable speaker
      keyboard     0x002540  HID keyboard
      mouse        0x002580  HID mouse
      gamepad      0x002508  HID gamepad
      car          0x200420  Hands-free car kit
      watch        0x70020c  Smartwatch
      tablet       0x5a0100  Tablet
      printer      0x040680  Printer
      camera       0x040100  Camera
    """
    hci = _resolve_df_hci(hci) or resolve_active_hci()
    # Resolve preset name to hex
    device_class = _DEVICE_CLASS_PRESETS.get(device_class.lower(), device_class)
    from blue_tap.hardware.adapter import set_device_class
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    started = now_iso()
    run_id = make_run_id("general")
    emit_cli_event(
        event_type="run_started", module="general", run_id=run_id,
        adapter=hci, message=f"Setting adapter {hci} device class to {device_class}",
        echo=False,
    )
    try:
        result = set_device_class(hci, device_class)
    except ValueError as exc:
        error(str(exc))
        emit_cli_event(
            event_type="run_error", module="general", run_id=run_id,
            adapter=hci, message=f"adapter set-class validation failed: {exc}",
            details={"error": str(exc)},
            echo=False,
        )
        return
    ok = result["success"]
    emit_cli_event(
        event_type="execution_result", module="general", run_id=run_id,
        adapter=hci, message=f"adapter device class set to {result['device_class']} on {hci}",
        details={"success": ok, "device_class": result["device_class"]},
        echo=False,
    )
    envelope = build_run_envelope(
        schema="blue_tap.general.result",
        module="general",
        target=hci,
        adapter=hci,
        operator_context={"operation": "adapter_set_class", "device_class": device_class},
        summary={"success": ok},
        executions=[],
        module_data={
            "operation": "adapter_set_class",
            "hci": hci,
            "device_class": result["device_class"],
            "success": ok,
        },
        started_at=started,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="general", run_id=run_id, adapter=hci,
        message=f"adapter set-class {'complete' if ok else 'failed'}: {device_class} on {hci}",
        details={"success": ok},
        echo=False,
    )
    log_command("adapter_set_class", envelope, category="general")


@adapter.command("firmware-status")
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
def adapter_firmware_status(hci):
    """Check DarkFirmware status on RTL8761B adapter."""
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.framework.envelopes.firmware import build_firmware_status_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message="Firmware status check",
        echo=False,
    )

    fw = DarkFirmwareManager()
    status = fw.get_firmware_status(hci)

    info(f"RTL8761B detected: {status.get('installed', False)}")
    info(f"DarkFirmware loaded: {status.get('loaded', False)}")
    info(f"Current BDADDR: {status.get('bdaddr', 'unknown')}")
    info(f"Original firmware backed up: {status.get('original_backed_up', False)}")
    if status.get("capabilities"):
        info(f"Capabilities: {', '.join(status['capabilities'])}")

    envelope = build_firmware_status_result(adapter=hci, status=status, started_at=started_at, run_id=run_id)
    emit_cli_event(
        event_type="run_completed", module="firmware", run_id=run_id,
        adapter=hci, message="Firmware status complete",
        echo=False,
    )
    log_command("firmware_status", envelope, category="general", target=hci)


@adapter.command("firmware-install")
@click.option("--source", default=None, type=click.Path(exists=True),
              help="Path to custom firmware binary (default: bundled DarkFirmware)")
@click.option("--restore", is_flag=True, help="Restore original Realtek firmware")
@click.option("--hci", default=None, help="HCI device (auto-detected when omitted)")
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
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.framework.envelopes.firmware import build_firmware_operation_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso

    hci = _resolve_df_hci(hci)
    if hci is None and not restore:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return
    if hci is None:
        # Restore doesn't need live detection; the driver reloads firmware on
        # the next USB reset regardless of which hci slot it ends up on.
        hci = resolve_active_hci()
    from blue_tap.framework.sessions.store import log_command

    run_id = make_firmware_run_id()
    started_at = now_iso()
    operation = "restore" if restore else "install"
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message=f"Firmware {operation}",
        echo=False,
    )

    fw = DarkFirmwareManager()
    ok = False

    if restore:
        if fw.restore_firmware():
            info("Resetting adapter to load original firmware...")
            fw.usb_reset()
            import time
            time.sleep(2.5)
            success("Original Realtek firmware restored")
            ok = True
        else:
            error("Failed to restore firmware")
        envelope = build_firmware_operation_result(
            adapter=hci, operation=operation,
            title="Firmware Restore",
            success=ok,
            observations=["Original Realtek firmware restored" if ok else "Restore failed"],
            module_data={"source": source, "restore": restore},
            started_at=started_at, run_id=run_id,
        )
        emit_cli_event(
            event_type="run_completed" if ok else "run_error",
            module="firmware", run_id=run_id, adapter=hci,
            message=f"Firmware restore {'succeeded' if ok else 'failed'}",
            echo=False,
        )
        log_command("firmware_install", envelope, category="general", target=hci)
        return

    if not fw.detect_rtl8761b(hci):
        error(f"No RTL8761B adapter detected on {hci}. "
              f"This command only works with TP-Link UB500 or compatible RTL8761B dongles.")
        envelope = build_firmware_operation_result(
            adapter=hci, operation=operation,
            title="DarkFirmware Install",
            success=False,
            observations=[f"No RTL8761B detected on {hci}"],
            module_data={"source": source, "restore": restore},
            started_at=started_at, run_id=run_id,
        )
        emit_cli_event(
            event_type="run_error", module="firmware", run_id=run_id, adapter=hci,
            message=f"No RTL8761B detected on {hci}",
            echo=False,
        )
        log_command("firmware_install", envelope, category="general", target=hci)
        return

    verified = False
    if fw.install_firmware(source):
        info("Resetting adapter to load DarkFirmware...")
        fw.usb_reset()
        import time
        time.sleep(2.5)

        if fw.is_darkfirmware_loaded(hci):
            success("DarkFirmware installed and verified!")
            ok = True
            verified = True
        else:
            warning("Firmware installed but DarkFirmware not detected — "
                    "adapter may need manual replug")
            ok = True
    else:
        error("Firmware installation failed")

    observations = []
    if ok and verified:
        observations.append("DarkFirmware installed and verified active")
    elif ok:
        observations.append("DarkFirmware installed; verification inconclusive — replug adapter")
    else:
        observations.append("Firmware installation failed")

    envelope = build_firmware_operation_result(
        adapter=hci, operation=operation,
        title="DarkFirmware Install",
        success=ok,
        observations=observations,
        module_data={"source": source, "restore": restore, "verified": verified},
        started_at=started_at, run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="firmware", run_id=run_id, adapter=hci,
        message=f"Firmware install {'succeeded' if ok else 'failed'}",
        details={"verified": verified},
        echo=False,
    )
    log_command("firmware_install", envelope, category="general", target=hci)


@adapter.command("firmware-init")
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
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
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.framework.envelopes.firmware import build_firmware_operation_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message="Firmware hook initialization",
        echo=False,
    )

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not detected on {hci}")
        envelope = build_firmware_operation_result(
            adapter=hci, operation="init",
            title="DarkFirmware Hook Init",
            success=False,
            observations=[f"DarkFirmware not detected on {hci}"],
            started_at=started_at, run_id=run_id,
        )
        emit_cli_event(
            event_type="run_error", module="firmware", run_id=run_id, adapter=hci,
            message=f"DarkFirmware not detected on {hci}",
            echo=False,
        )
        log_command("firmware_init", envelope, category="general", target=hci)
        return

    result = fw.init_hooks(hci)
    ok = bool(result.get("all_ok"))
    if ok:
        success("All 4 hooks initialized")
    else:
        for hook in ("hook1", "hook2", "hook3", "hook4"):
            hook_status = "active" if result.get(hook) else "FAILED"
            info(f"  {hook}: {hook_status}")

    hook_observations = [
        f"{hook}: {'active' if result.get(hook) else 'FAILED'}"
        for hook in ("hook1", "hook2", "hook3", "hook4")
    ]
    envelope = build_firmware_operation_result(
        adapter=hci, operation="init",
        title="DarkFirmware Hook Init",
        success=ok,
        observations=hook_observations,
        module_data=result,
        started_at=started_at, run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="firmware", run_id=run_id, adapter=hci,
        message=f"Firmware init {'all hooks active' if ok else 'some hooks failed'}",
        details=result,
        echo=False,
    )
    log_command("firmware_init", envelope, category="general", target=hci)


@adapter.command("connection-inspect")
@click.option("--conn", type=int, default=-1, help="Slot 0-11, or -1 for all")
@click.option("--watch", is_flag=True, help="Continuous monitoring")
@click.option("--interval", type=float, default=3.0, help="Watch interval (seconds)")
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
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
    from blue_tap.hardware.firmware import ConnectionInspector, DarkFirmwareManager
    from blue_tap.hardware.hci_vsc import HCIVSCSocket
    from blue_tap.framework.envelopes.firmware import build_connection_inspect_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message=f"Connection inspect on {hci} (watch={watch})",
        echo=False,
    )

    # DarkFirmware was confirmed by startup (_check_rtl_dongle). Skip redundant
    # re-probe here to avoid duplicate "DarkFirmware confirmed" log lines.
    # _resolve_df_hci() already verified the adapter is reachable.
    fw = DarkFirmwareManager()
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
        emit_cli_event(
            event_type="run_aborted", module="firmware", run_id=run_id, adapter=hci,
            message="Connection watch stopped by operator",
            echo=False,
        )
    else:
        connections = []
        try:
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                if conn >= 0:
                    r = inspector.inspect_connection(sock, conn)
                    connections = [r]
                    console.print()
                    if r.get("active"):
                        _display_connection(None, r)
                    else:
                        info(f"Slot {conn}: no active connection")
                else:
                    active = inspector.scan_all_connections(sock)
                    connections = active or []
                    console.print()
                    if active:
                        info(f"[bold]Connection table[/bold]  ({len(active)} active slot(s))")
                        console.print()
                        for r in active:
                            _display_connection(None, r)
                    else:
                        info("Connection table: 12 slots scanned, [bold]0 active[/bold]")
        except Exception as exc:
            error(f"Connection inspect failed: {exc}")

        envelope = build_connection_inspect_result(
            adapter=hci, connections=connections,
            started_at=started_at, run_id=run_id,
        )
        active_count = len([c for c in connections if c.get("active")])
        emit_cli_event(
            event_type="run_completed", module="firmware", run_id=run_id, adapter=hci,
            message=f"Connection inspect complete: {active_count} active",
            echo=False,
        )
        log_command("connection_inspect", envelope, category="general", target=hci)


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

    if enc and key_size is not None:
        if key_size == 1:
            warning(f"  [!!!] KNOB VULNERABLE — 1-byte encryption key!")
        elif key_size < 7:
            warning(f"  [!!] WEAK ENCRYPTION — key_size={key_size} bytes")

    key_copy = r.get("key_material_copy", "")
    if key_copy and key_copy != "00" * 32:
        info(f"  Key material: {key_copy[:32]}...")


@adapter.command("firmware-spoof")
@click.argument("address", required=False, default=None)
@click.option("--restore", is_flag=True, help="Restore original BDADDR from backup")
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
def adapter_firmware_spoof(address, restore, hci):
    """Spoof the Bluetooth address (BDADDR) via DarkFirmware.

    \b
    Patches the firmware binary and USB-resets the adapter.
    The original BDADDR is saved automatically on first spoof and can be
    restored with --restore (no need to remember the original address).

    \b
    Examples:
      sudo blue-tap adapter firmware-spoof                    # scan and pick target
      sudo blue-tap adapter firmware-spoof AA:BB:CC:DD:EE:FF  # direct
      sudo blue-tap adapter firmware-spoof --restore          # revert to original
    """
    import pathlib
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.framework.envelopes.firmware import build_firmware_operation_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    _backup_path = pathlib.Path.home() / ".blue-tap" / f"{hci}_original_bdaddr"

    if restore:
        if not _backup_path.exists():
            error(
                f"No original BDADDR backup found for {hci}.\n"
                "  Run [bold]blue-tap adapter firmware-spoof[/bold] at least once to save it."
            )
            return
        address = _backup_path.read_text().strip()
        info(f"Restoring original BDADDR: [bold]{address}[/bold]")
    else:
        if not address:
            from blue_tap.utils.interactive import resolve_address
            address = resolve_address(None, prompt="Select device to impersonate", hci=hci)
            if not address:
                return

        # Back up the current (original) BDADDR before the first spoof
        if not _backup_path.exists():
            try:
                fw_tmp = DarkFirmwareManager()
                orig = fw_tmp.get_current_bdaddr(hci)
                if orig:
                    _backup_path.parent.mkdir(parents=True, exist_ok=True)
                    _backup_path.write_text(orig)
                    info(f"Original BDADDR saved: [dim]{orig}[/dim]  (--restore to revert)")
            except Exception:
                pass

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, target=address,
        message=f"Firmware BDADDR spoof to {address} on {hci}",
        echo=False,
    )

    fw = DarkFirmwareManager()
    info(f"Patching BDADDR to [bold]{address}[/bold] on {hci} (RAM, no USB reset)...")
    ok = fw.patch_bdaddr_ram(address, hci)
    if ok:
        success(f"BDADDR set to {address}")
    else:
        error("BDADDR patching failed")

    emit_cli_event(
        event_type="execution_result", module="firmware", run_id=run_id,
        adapter=hci, target=address,
        message=f"BDADDR patch {'succeeded' if ok else 'failed'}: {address}",
        details={"success": ok, "address": address},
        echo=False,
    )
    envelope = build_firmware_operation_result(
        adapter=hci,
        operation="spoof",
        title=f"BDADDR spoof to {address}",
        success=ok,
        observations=[f"Target BDADDR: {address}", f"Adapter: {hci}"],
        module_data={"address": address, "hci": hci},
        started_at=started_at,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="firmware", run_id=run_id, adapter=hci, target=address,
        message=f"Firmware BDADDR spoof {'complete' if ok else 'failed'}: {address}",
        details={"success": ok},
        echo=False,
    )
    log_command("firmware_spoof", envelope, category="general", target=hci)


@adapter.command("firmware-set")
@click.argument("setting", type=click.Choice(["lmp-size", "lmp-slot"]))
@click.argument("value", type=int)
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
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
    from blue_tap.hardware.firmware import DarkFirmwareManager
    from blue_tap.framework.envelopes.firmware import build_firmware_operation_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message=f"Firmware set {setting}={value} on {hci}",
        echo=False,
    )

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        emit_cli_event(
            event_type="run_error", module="firmware", run_id=run_id,
            adapter=hci, message=f"DarkFirmware not loaded on {hci}",
            details={"error": "darkfirmware_not_loaded"},
            echo=False,
        )
        return

    ok = False
    if setting == "lmp-size":
        ok = fw.patch_send_length(value, hci)
        if ok:
            success(f"LMP send size set to {value} bytes")
        else:
            error(f"Failed to set LMP send size to {value}")
    elif setting == "lmp-slot":
        ok = fw.patch_connection_index(value, hci)
        if ok:
            success(f"LMP injection slot set to {value}")
        else:
            error(f"Failed to set LMP slot to {value}")

    emit_cli_event(
        event_type="execution_result", module="firmware", run_id=run_id,
        adapter=hci, message=f"firmware-set {setting}={value} {'succeeded' if ok else 'failed'}",
        details={"success": ok, "setting": setting, "value": value},
        echo=False,
    )
    envelope = build_firmware_operation_result(
        adapter=hci,
        operation="set",
        title=f"Firmware set {setting}={value}",
        success=ok,
        observations=[f"Setting: {setting}", f"Value: {value}", f"Adapter: {hci}"],
        module_data={"setting": setting, "value": value, "hci": hci},
        started_at=started_at,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="firmware", run_id=run_id, adapter=hci,
        message=f"firmware-set {'complete' if ok else 'failed'}: {setting}={value}",
        details={"success": ok},
        echo=False,
    )
    log_command("firmware_set", envelope, category="general", target=hci)


@adapter.command("firmware-dump")
@click.option("--start", type=str, default=None, help="Start address (hex, e.g., 0x80000000)")
@click.option("--end", type=str, default=None, help="End address (hex)")
@click.option("--region", type=click.Choice(["rom", "ram", "patch", "hooks"]), default=None,
              help="Preset memory region")
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
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
    import os as _os
    from blue_tap.hardware.firmware import DarkFirmwareManager, MEMORY_REGIONS
    from blue_tap.framework.envelopes.firmware import build_firmware_dump_result, make_firmware_run_id
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.framework.sessions.store import log_command

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    run_id = make_firmware_run_id()
    started_at = now_iso()
    emit_cli_event(
        event_type="run_started", module="firmware", run_id=run_id,
        adapter=hci, message=f"Firmware memory dump to {output}",
        echo=False,
    )

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        emit_cli_event(
            event_type="run_error", module="firmware", run_id=run_id, adapter=hci,
            message=f"DarkFirmware not loaded on {hci}",
            echo=False,
        )
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
            emit_cli_event(
                event_type="run_error", module="firmware", run_id=run_id, adapter=hci,
                message="Invalid address format",
                echo=False,
            )
            return
    else:
        error("Provide either --region or both --start and --end")
        emit_cli_event(
            event_type="run_error", module="firmware", run_id=run_id, adapter=hci,
            message="No address range specified",
            echo=False,
        )
        return

    ok = fw.dump_memory(start_addr, end_addr, output, hci)
    if ok:
        success(f"Dump saved to {output}")
        emit_cli_event(
            event_type="artifact_saved", module="firmware", run_id=run_id, adapter=hci,
            message=f"Memory dump saved: {output}",
            details={"path": output},
            echo=False,
        )
    else:
        error("Memory dump failed")

    file_size = 0
    if ok and _os.path.exists(output):
        file_size = _os.path.getsize(output)

    envelope = build_firmware_dump_result(
        adapter=hci,
        start_addr=start_addr,
        end_addr=end_addr,
        output_path=output,
        success=ok,
        file_size=file_size,
        started_at=started_at,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed" if ok else "run_error",
        module="firmware", run_id=run_id, adapter=hci,
        message=f"Firmware dump {'complete' if ok else 'failed'}: {output}",
        details={"success": ok, "file_size": file_size},
        echo=False,
    )
    log_command("firmware_dump", envelope, category="general", target=hci)


@adapter.command("connections")
@click.option("--dump", is_flag=True, help="Full hex dump of all 12 slots")
@click.option("--slot", type=int, default=None, help="Dump specific slot (0-11)")
@click.option("-o", "--output", default=None, help="Save raw dump to file")
@click.option("--hci", default=None, hidden=True, help="HCI device (auto-detected)")
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
    from blue_tap.hardware.firmware import DarkFirmwareManager

    hci = _resolve_df_hci(hci)
    if hci is None:
        error("No RTL8761B dongle detected. Connect a TP-Link UB500.")
        return

    fw = DarkFirmwareManager()
    if not fw.is_darkfirmware_loaded(hci):
        error(f"DarkFirmware not loaded on {hci}")
        return

    if slot is not None:
        if not 0 <= slot <= 11:
            error("Slot must be 0-11")
            return
        info(f"Dumping raw connection slot {slot}...")
        raw = fw.dump_connection_raw(slot, hci)
        if not raw:
            error(f"Failed to read slot {slot}")
            return
        for i in range(0, len(raw), 16):
            hex_part = " ".join(f"{b:02X}" for b in raw[i:i+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[i:i+16])
            info(f"  {i:04X}: {hex_part:<48s}  {ascii_part}")
        if output:
            with open(output, "wb") as f:
                f.write(raw)
            success(f"Slot {slot} raw dump saved to {output} ({len(raw)} bytes)")
        return

    info("Reading connection table from firmware RAM...")
    connections = fw.dump_connections(hci)
    if not connections:
        warning("No connection data retrieved")
        return

    table = bare_table()
    table.title = "[bold]Connection Slots[/bold]"
    table.add_column("Slot", style="bt.cyan", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("BD_ADDR", style="bt.purple")
    table.add_column("Address", style="bt.purple")
    if dump:
        table.add_column("First 32 bytes (hex)", style="dim")

    for conn in connections:
        status = "[bt.green]ACTIVE[/bt.green]" if conn["active"] else "[bt.dim]inactive[/bt.dim]"
        row = [str(conn["slot"]), status, conn["bd_addr"] or "-", conn["address"]]
        if dump:
            raw_hex = conn["raw_hex"][:64]
            formatted = " ".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))
            row.append(formatted)
        table.add_row(*row)

    print_table(table)

    active = sum(1 for c in connections if c["active"])
    info(f"Summary: {active} active / {len(connections)} total connection slots")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump(connections, f, indent=2)
        success(f"Connection data saved to {output}")
