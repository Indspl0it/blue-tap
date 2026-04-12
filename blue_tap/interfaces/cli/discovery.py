"""Discovery CLI — scan group for Bluetooth Classic and BLE device discovery."""

from __future__ import annotations

import rich_click as click

from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup, _save_json
from blue_tap.utils.output import info, success, warning, device_table, console


@click.group(cls=LoggedGroup)
def scan():
    """Discover Bluetooth Classic and BLE devices."""


@scan.command("classic")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_classic(duration, hci, output):
    """Scan for Bluetooth Classic devices."""
    from blue_tap.hardware.scanner import scan_classic_result
    from blue_tap.framework.sessions.store import log_command

    info(f"Scanning for Classic BT devices on {hci} ({duration}s)...")
    result = scan_classic_result(duration, hci)
    devices = result.get("module_data", {}).get("devices", [])
    log_command("scan_classic", result, category="scan")
    if devices:
        success(f"Scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "Classic BT Devices"))
    else:
        warning("Scan complete: no devices found")
    if output:
        _save_json(result, output)


@scan.command("ble")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-p", "--passive", is_flag=True, help="Passive scan (no SCAN_REQ, stealthier)")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_ble(duration, hci, passive, output):
    """Scan for BLE devices. Use --passive for stealth mode."""
    from blue_tap.hardware.scanner import scan_ble_result_sync
    from blue_tap.framework.sessions.store import log_command

    mode = "passive" if passive else "active"
    info(f"Scanning for BLE devices on {hci} ({duration}s, {mode} mode)...")
    result = scan_ble_result_sync(duration, passive=passive, adapter=hci)
    devices = result.get("module_data", {}).get("devices", [])
    log_command("scan_ble", result, category="scan")
    if devices:
        success(f"BLE scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "BLE Devices"))
    else:
        warning("BLE scan complete: no devices found")
    if output:
        _save_json(result, output)


@scan.command("all")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_all(duration, hci, output):
    """Scan both Classic BT and BLE simultaneously."""
    from blue_tap.hardware.scanner import scan_all_result
    from blue_tap.framework.sessions.store import log_command

    info(f"Scanning for Classic BT + BLE devices on {hci} ({duration}s)...")
    result = scan_all_result(duration, hci)
    devices = result.get("module_data", {}).get("devices", [])
    log_command("scan_all", result, category="scan")
    if devices:
        success(f"Scan complete: {len(devices)} device(s) discovered")
        console.print(device_table(devices, "All Bluetooth Devices"))
    else:
        warning("Scan complete: no devices found")
    if output:
        _save_json(result, output)


__all__ = ["scan"]
