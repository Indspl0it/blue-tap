"""BLE GATT service enumeration and characteristic reading."""

import asyncio
from bleak import BleakClient, BleakScanner

from bt_tap.utils.output import info, success, error


async def enumerate_services(address: str) -> list[dict]:
    """Enumerate all GATT services and characteristics on a BLE device."""
    info(f"Connecting to {address} for GATT enumeration...")

    try:
        async with BleakClient(address, timeout=15.0) as client:
            if not client.is_connected:
                error(f"Failed to connect to {address}")
                return []

            success(f"Connected to {address}")
            services_list = []

            for service in client.services:
                svc_info = {
                    "uuid": service.uuid,
                    "handle": service.handle,
                    "description": service.description or "Unknown Service",
                    "characteristics": [],
                }

                for char in service.characteristics:
                    char_info = {
                        "uuid": char.uuid,
                        "handle": char.handle,
                        "description": char.description or "Unknown",
                        "properties": char.properties,
                        "value": None,
                    }

                    # Try to read if readable
                    if "read" in char.properties:
                        try:
                            data = await client.read_gatt_char(char.uuid)
                            char_info["value_hex"] = data.hex()
                            char_info["value_str"] = "".join(
                                chr(b) if 32 <= b <= 127 else "." for b in data
                            )
                        except Exception:
                            char_info["value_hex"] = "read_error"

                    # List descriptors
                    char_info["descriptors"] = [
                        {"uuid": d.uuid, "handle": d.handle}
                        for d in char.descriptors
                    ]

                    svc_info["characteristics"].append(char_info)

                services_list.append(svc_info)

            success(f"Enumerated {len(services_list)} GATT service(s)")
            return services_list

    except Exception as e:
        error(f"GATT enumeration failed: {e}")
        return []


def enumerate_services_sync(address: str) -> list[dict]:
    return asyncio.run(enumerate_services(address))


async def read_characteristic(address: str, uuid: str) -> bytes | None:
    """Read a specific GATT characteristic."""
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
        async with BleakClient(address, timeout=10.0) as client:
            await client.write_gatt_char(uuid, data, response=response)
            success(f"Wrote {len(data)} bytes to {uuid}")
            return True
    except Exception as e:
        error(f"Write failed: {e}")
        return False


async def subscribe_notifications(address: str, uuid: str, duration: int = 30):
    """Subscribe to GATT notifications for a characteristic."""
    notifications = []

    def callback(sender, data):
        hex_data = data.hex()
        str_data = "".join(chr(b) if 32 <= b <= 127 else "." for b in data)
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
