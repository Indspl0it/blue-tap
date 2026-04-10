"""BLE GATT service enumeration and characteristic reading."""

import asyncio

from blue_tap.utils.output import info, success, error, warning


# Standard GATT Service UUIDs (Bluetooth SIG assigned)
GATT_SERVICE_UUIDS = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "HID (Human Interface Device)",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "0000181e-0000-1000-8000-00805f9b34fb": "Bond Management",
    "00001824-0000-1000-8000-00805f9b34fb": "Transport Discovery",
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
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a06-0000-1000-8000-00805f9b34fb": "Alert Level",
    "00002a07-0000-1000-8000-00805f9b34fb": "Tx Power Level",
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


async def enumerate_services(address: str, adapter: str | None = None) -> list[dict]:
    result = await enumerate_services_detailed(address, adapter=adapter)
    return result.get("services", [])


async def enumerate_services_detailed(address: str, adapter: str | None = None) -> dict:
    """Enumerate all GATT services and characteristics on a BLE device.

    Enriches results with standard UUID lookups, security level hints,
    and automotive-relevant service detection.
    """
    try:
        from bleak import BleakClient
    except ImportError:
        error("bleak not installed. Install: pip install bleak")
        return {
            "connected": False,
            "status": "collector_unavailable",
            "error": "bleak not installed",
            "services": [],
            "service_count": 0,
            "characteristic_count": 0,
            "observations": ["collector=bleak", "status=collector_unavailable"],
        }

    info(f"Connecting to {address} for GATT enumeration...")

    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            client_kwargs = {"timeout": 15.0}
            if adapter:
                client_kwargs["adapter"] = adapter
            async with BleakClient(address, **client_kwargs) as client:
                if not client.is_connected:
                    error(f"Failed to connect to {address}")
                    return {
                        "connected": False,
                        "status": "not_connectable",
                        "error": "failed to connect",
                        "services": [],
                        "service_count": 0,
                        "characteristic_count": 0,
                        "observations": ["connected=false", "status=not_connectable"],
                    }

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

                return {
                    "connected": True,
                    "status": "completed" if services_list else "no_services",
                    "error": "",
                    "services": services_list,
                    "service_count": len(services_list),
                    "characteristic_count": sum(len(service["characteristics"]) for service in services_list),
                    "observations": [
                        "connected=true",
                        f"service_count={len(services_list)}",
                        f"characteristic_count={sum(len(service['characteristics']) for service in services_list)}",
                        f"auth_required_characteristics={auth_chars}",
                    ],
                    "security_summary": summarize_gatt_security(services_list),
                }

        except Exception as e:
            err_str = str(e).lower()
            if "not found" in err_str or "not discovered" in err_str:
                error(f"Device {address} not found. Run a BLE scan first.")
                return _gatt_error_result("not_found", str(e))
            if attempt < max_retries:
                wait = (attempt + 1) * 2
                warning(f"GATT enumeration failed ({e}), retrying in {wait}s...")
                await asyncio.sleep(wait)
                continue
            if "timeout" in err_str:
                error(f"Connection to {address} timed out after {max_retries + 1} attempts.")
                return _gatt_error_result("timeout", str(e))
            if "auth" in err_str or "encrypt" in err_str or "security" in err_str:
                return _gatt_error_result("auth_required", str(e))
            else:
                error(f"GATT enumeration failed: {e}")
            return _gatt_error_result("error", str(e))

    return _gatt_error_result("error", "unexpected enumeration state")


def _infer_security(properties: list[str]) -> str:
    """Infer security requirements from characteristic properties.

    Uses the combination of properties to estimate the security posture:
    - authenticated-signed-writes → requires signing (MITM protection)
    - write but no write-without-response → likely requires pairing
    - notify/indicate without read → may be protected
    - write-without-response only → typically open
    """
    props = {p.lower() for p in properties}

    if "authenticated-signed-writes" in props:
        return "signed_write"
    if "write" in props and "write-without-response" not in props:
        return "likely_paired"
    if "write-without-response" in props and "write" not in props:
        return "open"
    if props == {"read"}:
        return "read_only"
    if "notify" in props or "indicate" in props:
        if "read" not in props:
            return "notify_only"
    return "unknown"


def _decode_value(data: bytes, uuid: str) -> str:
    """Try to decode a characteristic value intelligently based on UUID."""
    uuid_short = uuid[:8].lower()

    # String-type characteristics (Device Info service)
    string_uuids = {
        "00002a00", "00002a24", "00002a25", "00002a26",
        "00002a27", "00002a28", "00002a29",
    }
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

    # Alert Level (uint8: 0=None, 1=Mild, 2=High) — used by Immediate Alert / Link Loss
    if uuid_short == "00002a06" and len(data) == 1:
        levels = {0: "No Alert", 1: "Mild Alert", 2: "High Alert"}
        return levels.get(data[0], f"Unknown ({data[0]})")

    # Tx Power Level (int8 dBm) — used for proximity/distance estimation
    if uuid_short == "00002a07" and len(data) == 1:
        tx = int.from_bytes(data, "little", signed=True)
        return f"{tx} dBm"

    # Appearance (uint16 enum) — identifies device type (phone, headset, car kit, etc.)
    if uuid_short == "00002a01" and len(data) >= 2:
        appearance = int.from_bytes(data[:2], "little")
        appearances = {
            0: "Unknown", 64: "Phone", 128: "Computer",
            192: "Watch", 320: "Display",
            384: "Remote Control",
            640: "Media Player",
            960: "HID", 961: "Keyboard", 962: "Mouse",
            # Audio categories (BLE Audio / headsets / earbuds)
            941: "Earbud", 942: "Headset", 943: "Headphones",
            944: "Speaker", 945: "Soundbar",
        }
        return appearances.get(appearance, f"Category 0x{appearance:04x}")

    # Connection Parameters
    if uuid_short == "00002a04" and len(data) >= 8:
        min_int = int.from_bytes(data[0:2], "little") * 1.25
        max_int = int.from_bytes(data[2:4], "little") * 1.25
        latency = int.from_bytes(data[4:6], "little")
        timeout = int.from_bytes(data[6:8], "little") * 10
        return f"Interval={min_int:.1f}-{max_int:.1f}ms Latency={latency} Timeout={timeout}ms"

    # System ID
    if uuid_short == "00002a23" and len(data) >= 8:
        mfr = int.from_bytes(data[0:5], "little")
        oui = int.from_bytes(data[5:8], "little")
        return f"Manufacturer=0x{mfr:010x} OUI=0x{oui:06x}"

    # Default: printable ASCII or hex
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def enumerate_services_sync(address: str, adapter: str | None = None) -> list[dict]:
    """Synchronous wrapper for GATT enumeration."""
    return asyncio.run(enumerate_services(address, adapter=adapter))


def enumerate_services_detailed_sync(address: str, adapter: str | None = None) -> dict:
    """Synchronous wrapper for detailed GATT enumeration."""
    return asyncio.run(enumerate_services_detailed(address, adapter=adapter))


def flatten_gatt_entries(services: list[dict]) -> list[dict]:
    """Build summary rows for reports while preserving the full tree elsewhere."""
    flat_entries = []
    for service in services:
        flat_entries.append(
            {
                "kind": "service",
                "handle": service.get("handle"),
                "uuid": service.get("uuid"),
                "name": service.get("description"),
                "properties": "",
                "automotive_category": service.get("automotive_category"),
            }
        )
        for char in service.get("characteristics", []):
            flat_entries.append(
                {
                    "kind": "characteristic",
                    "handle": char.get("handle"),
                    "uuid": char.get("uuid"),
                    "name": char.get("description"),
                    "properties": ",".join(char.get("properties", [])),
                    "security_hint": char.get("security_hint"),
                    "value_preview": char.get("value_str") or char.get("value_hex"),
                }
            )
    return flat_entries


def summarize_gatt_security(services: list[dict]) -> dict:
    writable = 0
    notify = 0
    protected = 0
    readable = 0
    for service in services:
        for char in service.get("characteristics", []):
            props = {prop.lower() for prop in char.get("properties", [])}
            if "read" in props:
                readable += 1
            if "write" in props or "write-without-response" in props:
                writable += 1
            if "notify" in props or "indicate" in props:
                notify += 1
            if char.get("security_hint") in {"encrypted/authenticated", "access_denied", "likely_paired", "signed_write"}:
                protected += 1
    return {
        "readable_characteristics": readable,
        "writable_characteristics": writable,
        "notify_characteristics": notify,
        "protected_characteristics": protected,
    }


def _gatt_error_result(status: str, message: str) -> dict:
    return {
        "connected": False,
        "status": status,
        "error": message,
        "services": [],
        "service_count": 0,
        "characteristic_count": 0,
        "observations": [f"connected=false", f"status={status}", f"error={message}"],
    }


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
