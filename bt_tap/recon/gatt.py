"""BLE GATT service enumeration and characteristic reading."""

import asyncio

from bt_tap.utils.output import info, success, error, warning


# Standard GATT Service UUIDs (Bluetooth SIG assigned)
GATT_SERVICE_UUIDS = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "HID (Human Interface Device)",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "00001816-0000-1000-8000-00805f9b34fb": "Cycling Speed and Cadence",
    "00001808-0000-1000-8000-00805f9b34fb": "Glucose",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "0000fef5-0000-1000-8000-00805f9b34fb": "Dialog Semiconductor",
}

# Standard GATT Characteristic UUIDs
GATT_CHAR_UUIDS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
}

# Automotive-relevant BLE service UUIDs (vendor-specific)
AUTOMOTIVE_SERVICE_HINTS = {
    "tpms": ["tire", "pressure", "tpms"],
    "obd": ["obd", "diagnostic", "vehicle", "elm327"],
    "keyless": ["key", "lock", "unlock", "access"],
    "ble_phone_as_key": ["digital key", "ccc", "phone as key"],
}


def lookup_uuid(uuid: str) -> str:
    """Look up a GATT UUID to get a human-readable name."""
    uuid_lower = uuid.lower()
    if uuid_lower in GATT_SERVICE_UUIDS:
        return GATT_SERVICE_UUIDS[uuid_lower]
    if uuid_lower in GATT_CHAR_UUIDS:
        return GATT_CHAR_UUIDS[uuid_lower]
    # Check for short UUID format (0xNNNN)
    if len(uuid) == 4 or (uuid.startswith("0x") and len(uuid) == 6):
        short = uuid.replace("0x", "").lower()
        full = f"0000{short}-0000-1000-8000-00805f9b34fb"
        if full in GATT_SERVICE_UUIDS:
            return GATT_SERVICE_UUIDS[full]
        if full in GATT_CHAR_UUIDS:
            return GATT_CHAR_UUIDS[full]
    return ""


def classify_automotive_service(uuid: str, description: str) -> str | None:
    """Check if a GATT service looks automotive-related."""
    combined = (uuid + " " + description).lower()
    for category, keywords in AUTOMOTIVE_SERVICE_HINTS.items():
        if any(kw in combined for kw in keywords):
            return category
    return None


async def enumerate_services(address: str) -> list[dict]:
    """Enumerate all GATT services and characteristics on a BLE device.

    Enriches results with standard UUID lookups, security level hints,
    and automotive-relevant service detection.
    """
    try:
        from bleak import BleakClient
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return []

    info(f"Connecting to {address} for GATT enumeration...")

    try:
        async with BleakClient(address, timeout=15.0) as client:
            if not client.is_connected:
                error(f"Failed to connect to {address}")
                return []

            success(f"Connected to {address}")
            services_list = []

            for service in client.services:
                svc_name = lookup_uuid(service.uuid) or service.description or "Unknown Service"
                auto_category = classify_automotive_service(service.uuid, svc_name)

                svc_info = {
                    "uuid": service.uuid,
                    "handle": service.handle,
                    "description": svc_name,
                    "is_standard": bool(lookup_uuid(service.uuid)),
                    "automotive_category": auto_category,
                    "characteristics": [],
                }

                for char in service.characteristics:
                    char_name = lookup_uuid(char.uuid) or char.description or "Unknown"
                    char_info = {
                        "uuid": char.uuid,
                        "handle": char.handle,
                        "description": char_name,
                        "properties": char.properties,
                        "value": None,
                        "security_hint": _infer_security(char.properties),
                    }

                    # Try to read if readable
                    if "read" in char.properties:
                        try:
                            data = await client.read_gatt_char(char.uuid)
                            char_info["value_hex"] = data.hex()
                            char_info["value_str"] = _decode_value(data, char.uuid)
                        except Exception as e:
                            err_str = str(e).lower()
                            if "auth" in err_str or "encrypt" in err_str or "security" in err_str:
                                char_info["value_hex"] = "auth_required"
                                char_info["security_hint"] = "encrypted/authenticated"
                            elif "not permitted" in err_str or "denied" in err_str:
                                char_info["value_hex"] = "access_denied"
                                char_info["security_hint"] = "access_denied"
                            else:
                                char_info["value_hex"] = "read_error"

                    # List descriptors
                    char_info["descriptors"] = [
                        {"uuid": d.uuid, "handle": d.handle,
                         "description": lookup_uuid(d.uuid) or ""}
                        for d in char.descriptors
                    ]

                    svc_info["characteristics"].append(char_info)

                services_list.append(svc_info)

            success(f"Enumerated {len(services_list)} GATT service(s)")

            # Summary of findings
            auto_services = [s for s in services_list if s.get("automotive_category")]
            if auto_services:
                for s in auto_services:
                    info(f"  Automotive: {s['description']} ({s['automotive_category']})")

            auth_chars = sum(
                1 for s in services_list for c in s["characteristics"]
                if c.get("security_hint") in ("encrypted/authenticated", "access_denied")
            )
            if auth_chars:
                info(f"  {auth_chars} characteristic(s) require authentication")

            return services_list

    except Exception as e:
        err_str = str(e)
        if "not found" in err_str.lower() or "not discovered" in err_str.lower():
            error(f"Device {address} not found. Run a BLE scan first.")
        elif "timeout" in err_str.lower():
            error(f"Connection to {address} timed out. Device may be out of range.")
        else:
            error(f"GATT enumeration failed: {e}")
        return []


def _infer_security(properties: list[str]) -> str:
    """Infer security requirements from characteristic properties."""
    props = [p.lower() for p in properties]
    if "authenticated-signed-writes" in props:
        return "signed_write"
    # If only write-without-response, likely no auth needed
    if "write-without-response" in props and "write" not in props:
        return "open"
    return "unknown"


def _decode_value(data: bytes, uuid: str) -> str:
    """Try to decode a characteristic value intelligently based on UUID."""
    # String-type characteristics (Device Info service)
    string_uuids = {
        "00002a00", "00002a24", "00002a25", "00002a26",
        "00002a27", "00002a28", "00002a29",
    }
    uuid_short = uuid[:8].lower()
    if uuid_short in string_uuids:
        try:
            return data.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            pass

    # Battery Level (uint8 percentage)
    if uuid_short == "00002a19" and len(data) == 1:
        return f"{data[0]}%"

    # PnP ID
    if uuid_short == "00002a50" and len(data) >= 7:
        source = {1: "BT SIG", 2: "USB"}
        src = source.get(data[0], f"0x{data[0]:02x}")
        vid = int.from_bytes(data[1:3], "little")
        pid = int.from_bytes(data[3:5], "little")
        ver = int.from_bytes(data[5:7], "little")
        return f"Source={src} VID=0x{vid:04x} PID=0x{pid:04x} Ver={ver}"

    # Default: printable ASCII or hex
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def enumerate_services_sync(address: str) -> list[dict]:
    """Synchronous wrapper for GATT enumeration."""
    return asyncio.run(enumerate_services(address))


async def read_characteristic(address: str, uuid: str) -> bytes | None:
    """Read a specific GATT characteristic."""
    try:
        from bleak import BleakClient
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return None

    try:
        async with BleakClient(address, timeout=10.0) as client:
            data = await client.read_gatt_char(uuid)
            return data
    except Exception as e:
        error(f"Read failed: {e}")
        return None


async def write_characteristic(address: str, uuid: str, data: bytes,
                                response: bool = True) -> bool:
    """Write data to a GATT characteristic."""
    try:
        from bleak import BleakClient
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return False

    try:
        async with BleakClient(address, timeout=10.0) as client:
            await client.write_gatt_char(uuid, data, response=response)
            success(f"Wrote {len(data)} bytes to {uuid}")
            return True
    except Exception as e:
        error(f"Write failed: {e}")
        return False


async def subscribe_notifications(address: str, uuid: str, duration: int = 30):
    """Subscribe to GATT notifications for a characteristic."""
    try:
        from bleak import BleakClient
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return []

    notifications = []

    def callback(sender, data):
        hex_data = data.hex()
        char_uuid = sender.uuid if hasattr(sender, 'uuid') else str(sender)
        str_data = _decode_value(data, char_uuid)
        info(f"Notification from {sender}: {hex_data} | {str_data}")
        notifications.append({"sender": str(sender), "hex": hex_data, "str": str_data})

    try:
        async with BleakClient(address, timeout=10.0) as client:
            await client.start_notify(uuid, callback)
            info(f"Listening for notifications on {uuid} for {duration}s...")
            await asyncio.sleep(duration)
            await client.stop_notify(uuid)
    except Exception as e:
        error(f"Notification subscribe failed: {e}")

    return notifications
