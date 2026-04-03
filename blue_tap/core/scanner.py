"""Bluetooth Classic and BLE scanning with extended data extraction."""

import asyncio
import re

from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.utils.output import info, success, error, verbose


# ============================================================================
# Device Class (CoD) Parsing
# ============================================================================

# Major Device Classes (bits 12-8 of CoD)
MAJOR_DEVICE_CLASSES = {
    0x00: "Miscellaneous",
    0x01: "Computer",
    0x02: "Phone",
    0x03: "LAN/Network Access",
    0x04: "Audio/Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
}

# Minor classes for Phone (major=0x02)
PHONE_MINOR_CLASSES = {
    0x00: "Uncategorized",
    0x01: "Cellular",
    0x02: "Cordless",
    0x03: "Smartphone",
    0x04: "Wired Modem / Voice Gateway",
    0x05: "Common ISDN",
}

# Minor classes for Audio/Video (major=0x04) — relevant for IVI
AV_MINOR_CLASSES = {
    0x01: "Wearable Headset",
    0x02: "Hands-Free Device",
    0x04: "Microphone",
    0x05: "Loudspeaker",
    0x06: "Headphones",
    0x07: "Portable Audio",
    0x08: "Car Audio",
    0x09: "Set-Top Box",
    0x0A: "HiFi Audio",
    0x0B: "VCR",
    0x0C: "Video Camera",
    0x0D: "Camcorder",
    0x0E: "Video Monitor",
    0x0F: "Video Display + Loudspeaker",
}

# Minor classes for Computer (major=0x01)
COMPUTER_MINOR_CLASSES = {
    0x00: "Uncategorized",
    0x01: "Desktop Workstation",
    0x02: "Server-class Computer",
    0x03: "Laptop",
    0x04: "Handheld PC/PDA",
    0x05: "Palm-size PC/PDA",
    0x06: "Wearable Computer",
    0x07: "Tablet",
}

# Minor classes for Peripheral (major=0x05)
PERIPHERAL_MINOR_CLASSES = {
    0x00: "Uncategorized",
    0x01: "Joystick",
    0x02: "Gamepad",
    0x03: "Remote Control",
    0x04: "Sensing Device",
    0x05: "Digitizer Tablet",
    0x06: "Card Reader",
    0x07: "Digital Pen",
    0x08: "Handheld Scanner",
    0x09: "Handheld Gestural Input",
}

# Minor classes for Wearable (major=0x07)
WEARABLE_MINOR_CLASSES = {
    0x01: "Wristwatch",
    0x02: "Pager",
    0x03: "Jacket",
    0x04: "Helmet",
    0x05: "Glasses",
}

# Major Service Classes (bits 23-13 of CoD)
SERVICE_CLASS_BITS = {
    13: "Limited Discoverable",
    16: "Positioning",
    17: "Networking",
    18: "Rendering",
    19: "Capturing",
    20: "Object Transfer",
    21: "Audio",
    22: "Telephony",
    23: "Information",
}


def parse_device_class(cod_str: str) -> dict:
    """Parse a Bluetooth Class of Device into human-readable components.

    Args:
        cod_str: hex string like "0x5a020c" or "5a020c"

    Returns:
        {"raw": "0x5a020c", "major": "Phone", "minor": "Smartphone",
         "services": ["Audio", "Telephony", "Object Transfer"],
         "is_phone": True, "is_ivi": False}
    """
    try:
        cod_int = int(cod_str, 16) if isinstance(cod_str, str) else int(cod_str)
    except (ValueError, TypeError):
        return {"raw": str(cod_str), "major": "Unknown", "minor": "Unknown",
                "services": [], "is_phone": False, "is_ivi": False}

    major_num = (cod_int >> 8) & 0x1F
    minor_num = (cod_int >> 2) & 0x3F
    major = MAJOR_DEVICE_CLASSES.get(major_num, f"Reserved (0x{major_num:02x})")

    # Get minor class based on major
    minor = "Unknown"
    if major_num == 0x01:
        minor = COMPUTER_MINOR_CLASSES.get(minor_num, f"Unknown (0x{minor_num:02x})")
    elif major_num == 0x02:
        minor = PHONE_MINOR_CLASSES.get(minor_num, f"Unknown (0x{minor_num:02x})")
    elif major_num == 0x04:
        minor = AV_MINOR_CLASSES.get(minor_num, f"Unknown (0x{minor_num:02x})")
    elif major_num == 0x05:
        minor = PERIPHERAL_MINOR_CLASSES.get(minor_num, f"Unknown (0x{minor_num:02x})")
    elif major_num == 0x07:
        minor = WEARABLE_MINOR_CLASSES.get(minor_num, f"Unknown (0x{minor_num:02x})")

    # Parse service class bits
    services = []
    for bit, name in SERVICE_CLASS_BITS.items():
        if cod_int & (1 << bit):
            services.append(name)

    return {
        "raw": f"0x{cod_int:06x}",
        "major": major,
        "minor": minor,
        "services": services,
        "is_phone": major_num == 0x02,
        "is_ivi": major_num == 0x04 and minor_num == 0x08,
    }


def estimate_distance(rssi: int, tx_power: int = -59) -> float | None:
    """Estimate distance in meters from RSSI using log-distance path loss model.

    Args:
        rssi: Received signal strength in dBm
        tx_power: Measured RSSI at 1 meter (default -59 dBm typical for BLE)

    Returns:
        Estimated distance in meters, or None if RSSI is invalid
    """
    try:
        rssi = int(rssi)
    except (ValueError, TypeError):
        return None
    if rssi >= 0:
        return None
    # Path loss exponent: ~2 for free space, ~3 for indoors
    n = 2.5
    return round(10 ** ((tx_power - rssi) / (10 * n)), 1)


# ============================================================================
# Classic Bluetooth Scanning
# ============================================================================

def scan_classic(duration: int = 10, hci: str = "hci0") -> list[dict]:
    """Scan for Bluetooth Classic devices using hcitool.

    Performs both 'hcitool scan' (names) and 'hcitool inq' (class + clock offset)
    and merges results into enriched device records.
    """
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return []

    info(f"Scanning Classic BT for {duration}s on {hci}...")

    # Run inquiry first (gives class + clock offset, no names)
    # --length is in units of 1.28 seconds, not seconds
    inq_length = max(int(duration / 1.28), 4)
    inq_result = run_cmd(
        ["hcitool", "-i", hci, "inq", "--length", str(inq_length)],
        timeout=duration + 15,
    )

    # Build device map from inquiry
    device_map = {}
    if inq_result.returncode == 0:
        for line in inq_result.stdout.splitlines():
            m = re.match(
                r"\s*([0-9A-Fa-f:]{17})\s+clock offset:\s*(\S+)\s+class:\s*(\S+)",
                line,
            )
            if m:
                addr = m.group(1).upper()
                device_map[addr] = {
                    "address": m.group(1),
                    "name": "",
                    "rssi": "N/A",
                    "type": "Classic",
                    "class": m.group(3),
                    "clock_offset": m.group(2),
                    "class_info": parse_device_class(m.group(3)),
                }
    else:
        # Fallback: check if adapter is up
        if "device is not up" in inq_result.stderr.lower():
            error(f"{hci} is not up. Run: blue-tap adapter up {hci}")
            return []

    # Run scan for names
    scan_result = run_cmd(
        ["hcitool", "-i", hci, "scan"],
        timeout=duration + 15,
    )
    if scan_result.returncode == 0:
        for line in scan_result.stdout.strip().splitlines():
            m = re.match(r"\s*([0-9A-Fa-f:]{17})\s+(.*)", line)
            if m:
                addr = m.group(1).upper()
                name = m.group(2).strip()
                if addr in device_map:
                    device_map[addr]["name"] = name if name else "Unknown"
                else:
                    device_map[addr] = {
                        "address": m.group(1),
                        "name": name if name else "Unknown",
                        "rssi": "N/A",
                        "type": "Classic",
                    }
    elif not device_map:
        error(f"Classic scan failed: {scan_result.stderr.strip()}")
        return []

    devices = list(device_map.values())

    # Resolve names for devices found only via inquiry
    for dev in devices:
        if not dev.get("name") or dev["name"] == "":
            dev["name"] = resolve_name(dev["address"], hci)

    if not devices:
        info("Scan completed — no devices in range")
    else:
        success(f"Found {len(devices)} Classic device(s)")
    return devices


# ============================================================================
# BLE Scanning
# ============================================================================

async def scan_ble(duration: int = 10, passive: bool = False, adapter: str = "") -> list[dict]:
    """Scan for BLE devices using bleak with advertising data parsing.

    Args:
        duration: Scan duration in seconds
        passive: If True, only listen for broadcasts (no scan requests).
                 Note: passive mode depends on adapter and OS support.
    """
    try:
        from bleak import BleakScanner
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return []

    info(f"Scanning BLE for {duration}s {'(passive)' if passive else ''}...")

    # bleak's scanning_mode parameter: "active" sends SCAN_REQ, "passive" does not
    scanning_mode = "passive" if passive else "active"
    try:
        kwargs = {"timeout": duration, "scanning_mode": scanning_mode}
        if adapter:
            kwargs["adapter"] = adapter
        discovered = await BleakScanner.discover(**kwargs)
    except Exception as e:
        error(f"BLE scan failed: {e}")
        return []

    discovered = sorted(discovered, key=lambda d: d.rssi, reverse=True)

    devices = []
    for d in discovered:
        dev = {
            "address": d.address,
            "name": d.name or "Unknown",
            "rssi": d.rssi,
            "type": "BLE",
            "distance_m": estimate_distance(d.rssi),
        }

        # Parse advertising data if available
        if hasattr(d, "metadata") and d.metadata:
            dev["metadata"] = d.metadata
            # Extract manufacturer-specific data
            mfr_data = d.metadata.get("manufacturer_data", {})
            if mfr_data:
                dev["manufacturer_ids"] = list(mfr_data.keys())
                dev["manufacturer_name"] = _lookup_ble_manufacturer(
                    list(mfr_data.keys())[0] if mfr_data else 0
                )

            # Extract service UUIDs
            uuids = d.metadata.get("uuids", [])
            if uuids:
                dev["service_uuids"] = uuids

            # TX Power level (used for distance estimation)
            tx_power = d.metadata.get("tx_power")
            if tx_power is not None:
                dev["tx_power"] = tx_power
                dev["distance_m"] = estimate_distance(d.rssi, tx_power)

        devices.append(dev)

    success(f"Found {len(devices)} BLE device(s)")
    return devices


# Common BLE company IDs (Bluetooth SIG assigned numbers)
_BLE_MANUFACTURERS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x0059: "Nordic Semiconductor",
    0x000D: "Texas Instruments",
    0x0046: "MediaTek",
    0x001D: "Qualcomm",
    0x000F: "Broadcom",
    0x0131: "Xiaomi",
    0x0157: "Huawei",
    0x0310: "Garmin",
    0x00B0: "Continental Automotive",
    0x038F: "Harman International",
    0x0087: "Denso",
    0x02E5: "Bosch",
    0x00D2: "Dialog Semiconductor",
    0x0171: "Amazon",
    0x022B: "Fitbit",
    0x0499: "Ruuvi",
    0x02FF: "Bose",
    0x0302: "JBL (Harman)",
    0x0094: "Realtek",
    0x00CD: "Microchip (Atmel)",
    0x0047: "Intel",
    0x0038: "Renesas",
    0x004F: "Continental Automotive",
    0x0080: "Mitsumi",
    0x02D5: "Peloton",
    0x03DA: "Sonos",
    0x0226: "Dyson",
    0x02AC: "Tesla",
}


def _lookup_ble_manufacturer(company_id: int) -> str:
    """Look up BLE company ID to manufacturer name."""
    return _BLE_MANUFACTURERS.get(company_id, f"Unknown (0x{company_id:04X})")


def scan_ble_sync(duration: int = 10, passive: bool = False, adapter: str = "") -> list[dict]:
    """Synchronous wrapper for BLE scanning."""
    return asyncio.run(scan_ble(duration, passive, adapter=adapter))


# ============================================================================
# Combined Scanning
# ============================================================================

def scan_all(duration: int = 10, hci: str = "hci0") -> list[dict]:
    """Scan both Classic and BLE, merge and deduplicate results.

    Classic scan runs first (uses hcitool), then BLE scan (uses bleak).
    Both are needed sequentially because bleak requires the main thread
    event loop on Linux (D-Bus).
    """
    classic = scan_classic(duration, hci)
    ble = scan_ble_sync(duration, adapter=hci)

    # Merge, dedup by address, prefer richer records
    seen = {}
    for dev in classic:
        seen[dev["address"].upper()] = dev

    for dev in ble:
        addr = dev["address"].upper()
        if addr in seen:
            # Device found in both — mark as dual-mode and merge data
            existing = seen[addr]
            existing["type"] = "Classic+BLE"
            if existing.get("rssi") == "N/A" and dev.get("rssi") != "N/A":
                existing["rssi"] = dev["rssi"]
            if dev.get("distance_m"):
                existing["distance_m"] = dev["distance_m"]
            if dev.get("service_uuids"):
                existing["service_uuids"] = dev["service_uuids"]
            if dev.get("manufacturer_name"):
                existing["manufacturer_name"] = dev["manufacturer_name"]
            if not existing.get("name") or existing["name"] == "Unknown":
                existing["name"] = dev.get("name", "Unknown")
        else:
            seen[addr] = dev

    return list(seen.values())


# ============================================================================
# Name Resolution
# ============================================================================

def resolve_name(address: str, hci: str = "hci0", retries: int = 2) -> str:
    """Resolve the friendly name of a BT device with retry."""
    for attempt in range(retries + 1):
        result = run_cmd(["hcitool", "-i", hci, "name", address], timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if attempt < retries:
            import time
            time.sleep(1)
    return "Unknown"
