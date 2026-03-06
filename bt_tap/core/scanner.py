"""Bluetooth Classic and BLE scanning."""

import asyncio
import re
import subprocess

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.utils.output import info, success, error


def scan_classic(duration: int = 10, hci: str = "hci0") -> list[dict]:
    """Scan for Bluetooth Classic devices using hcitool inquiry."""
    info(f"Scanning Classic BT for {duration}s on {hci}...")

    # hcitool scan has no --length flag; it runs for ~10s by default.
    # We use it as-is and supplement with hcitool inq for device class info.
    result = run_cmd(
        ["hcitool", "-i", hci, "scan"],
        timeout=duration + 15,
    )

    devices = []
    if result.returncode != 0:
        error(f"Classic scan failed: {result.stderr.strip()}")
        return devices

    for line in result.stdout.strip().splitlines():
        m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(.*)", line)
        if m:
            addr, name = m.group(1), m.group(2).strip()
            devices.append({
                "address": addr,
                "name": name if name else "Unknown",
                "rssi": "N/A",
                "type": "Classic",
            })

    # Try to get device class via hcitool inq
    rssi_result = run_cmd(
        ["hcitool", "-i", hci, "inq"],
        timeout=duration + 15,
    )
    if rssi_result.returncode == 0:
        for line in rssi_result.stdout.splitlines():
            m = re.match(
                r"\s*([0-9A-Fa-f:]{17})\s+clock offset:\s*\S+\s+class:\s*(\S+)",
                line,
            )
            if m:
                addr = m.group(1)
                dev_class = m.group(2)
                for d in devices:
                    if d["address"] == addr:
                        d["class"] = dev_class

    success(f"Found {len(devices)} Classic device(s)")
    return devices


async def scan_ble(duration: int = 10) -> list[dict]:
    """Scan for BLE devices using bleak."""
    from bleak import BleakScanner

    info(f"Scanning BLE for {duration}s...")
    discovered = await BleakScanner.discover(timeout=duration)
    discovered = sorted(discovered, key=lambda d: d.rssi, reverse=True)

    devices = []
    for d in discovered:
        devices.append({
            "address": d.address,
            "name": d.name or "Unknown",
            "rssi": d.rssi,
            "type": "BLE",
            "metadata": d.metadata if hasattr(d, "metadata") else {},
        })

    success(f"Found {len(devices)} BLE device(s)")
    return devices


def scan_ble_sync(duration: int = 10) -> list[dict]:
    """Synchronous wrapper for BLE scanning."""
    return asyncio.run(scan_ble(duration))


def scan_all(duration: int = 10, hci: str = "hci0") -> list[dict]:
    """Scan both Classic and BLE simultaneously."""
    classic = scan_classic(duration, hci)
    ble = scan_ble_sync(duration)

    # Merge, dedup by address
    seen = set()
    merged = []
    for dev in classic + ble:
        if dev["address"] not in seen:
            seen.add(dev["address"])
            merged.append(dev)
        else:
            # Update existing with BLE info if both found
            for existing in merged:
                if existing["address"] == dev["address"]:
                    existing["type"] = "Classic+BLE"
                    if existing.get("rssi") == "N/A" and dev.get("rssi") != "N/A":
                        existing["rssi"] = dev["rssi"]

    return merged


def resolve_name(address: str, hci: str = "hci0") -> str:
    """Resolve the friendly name of a BT device."""
    result = run_cmd(["hcitool", "-i", hci, "name", address], timeout=10)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return "Unknown"
