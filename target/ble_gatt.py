#!/usr/bin/env python3
"""BLE GATT server for the Vulnerable IVI Simulator.

Exposes Device Information, Battery, and a custom IVI service over
BLE using the BlueZ D-Bus GATT API.  The OTA Update characteristic is
intentionally vulnerable (write-only, no auth) to exercise BLE attack
tooling.

Usage:
    sudo python3 ble_gatt.py [--hci hci0]
"""

import argparse
import signal
import struct
import sys

import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from ivi_config import (
    BLE_BATTERY_LEVEL,
    BLE_BATTERY_LEVEL_CHR,
    BLE_BATTERY_SVC,
    BLE_CUSTOM_IVI_SVC,
    BLE_DEVICE_INFO_SVC,
    BLE_DIAG_DATA_CHR,
    BLE_FIRMWARE_REV,
    BLE_FIRMWARE_REV_CHR,
    BLE_MANUFACTURER_NAME,
    BLE_MANUFACTURER_NAME_CHR,
    BLE_MODEL_NUMBER,
    BLE_MODEL_NUMBER_CHR,
    BLE_OTA_UPDATE_CHR,
    BLE_PNP_ID,
    BLE_PNP_ID_CHR,
    BLE_SOFTWARE_REV,
    BLE_SOFTWARE_REV_CHR,
    BLE_VEHICLE_SPEED_CHR,
    IVI_NAME,
)
from ivi_log import log

# ---------------------------------------------------------------------------
# D-Bus / BlueZ constants
# ---------------------------------------------------------------------------

BLUEZ_SERVICE = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
GATT_DESC_IFACE = "org.bluez.GattDescriptor1"

LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

APP_PATH = "/org/bluez/ivi"


# ---------------------------------------------------------------------------
# Exceptions raised to BlueZ via D-Bus
# ---------------------------------------------------------------------------

class InvalidArgsException(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


class NotSupportedException(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotSupported"


class NotPermittedException(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.NotPermitted"


# ---------------------------------------------------------------------------
# Base classes following the standard BlueZ GATT example pattern
# ---------------------------------------------------------------------------

class Application(dbus.service.Object):
    """BlueZ GATT Application (ObjectManager of services)."""

    def __init__(self, bus):
        self.path = APP_PATH
        self.services: list["Service"] = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service: "Service"):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response: dict = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            for chrc in service.characteristics:
                response[chrc.get_path()] = chrc.get_properties()
                for desc in chrc.descriptors:
                    response[desc.get_path()] = desc.get_properties()
        return response


class Service(dbus.service.Object):
    """BlueZ GATT Service."""

    PATH_BASE = APP_PATH + "/service"

    def __init__(self, bus, index: int, uuid: str, primary: bool = True):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics: list["Characteristic"] = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, chrc: "Characteristic"):
        self.characteristics.append(chrc)

    def get_properties(self) -> dict:
        return {
            GATT_SERVICE_IFACE: {
                "UUID": self.uuid,
                "Primary": self.primary,
                "Characteristics": dbus.Array(
                    [c.get_path() for c in self.characteristics],
                    signature="o",
                ),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s",
                          out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_SERVICE_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_SERVICE_IFACE]


class Characteristic(dbus.service.Object):
    """BlueZ GATT Characteristic."""

    def __init__(self, bus, index: int, uuid: str, flags: list[str],
                 service: Service):
        self.path = service.path + "/char" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.descriptors: list["Descriptor"] = []
        self.notifying = False
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_descriptor(self, descriptor: "Descriptor"):
        self.descriptors.append(descriptor)

    def get_properties(self) -> dict:
        return {
            GATT_CHRC_IFACE: {
                "Service": self.service.get_path(),
                "UUID": self.uuid,
                "Flags": dbus.Array(self.flags, signature="s"),
                "Descriptors": dbus.Array(
                    [d.get_path() for d in self.descriptors],
                    signature="o",
                ),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s",
                          out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_CHRC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_CHRC_IFACE]

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="a{sv}",
                          out_signature="ay")
    def ReadValue(self, options):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        raise NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        raise NotSupportedException()

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class Descriptor(dbus.service.Object):
    """BlueZ GATT Descriptor."""

    def __init__(self, bus, index: int, uuid: str, flags: list[str],
                 characteristic: Characteristic):
        self.path = characteristic.path + "/desc" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.characteristic = characteristic
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self) -> dict:
        return {
            GATT_DESC_IFACE: {
                "Characteristic": self.characteristic.get_path(),
                "UUID": self.uuid,
                "Flags": dbus.Array(self.flags, signature="s"),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s",
                          out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_DESC_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[GATT_DESC_IFACE]

    @dbus.service.method(GATT_DESC_IFACE, in_signature="a{sv}",
                          out_signature="ay")
    def ReadValue(self, options):
        raise NotSupportedException()

    @dbus.service.method(GATT_DESC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        raise NotSupportedException()


# ---------------------------------------------------------------------------
# LE Advertisement
# ---------------------------------------------------------------------------

class IVIAdvertisement(dbus.service.Object):
    """BLE LE advertisement for the IVI simulator."""

    PATH = APP_PATH + "/advertisement0"

    def __init__(self, bus):
        self.bus = bus
        dbus.service.Object.__init__(self, bus, self.PATH)

    def get_path(self):
        return dbus.ObjectPath(self.PATH)

    def get_properties(self) -> dict:
        return {
            LE_ADVERTISEMENT_IFACE: {
                "Type": "peripheral",
                "LocalName": dbus.String(IVI_NAME),
                "ServiceUUIDs": dbus.Array(
                    [BLE_DEVICE_INFO_SVC, BLE_BATTERY_SVC, BLE_CUSTOM_IVI_SVC],
                    signature="s",
                ),
                "Includes": dbus.Array(["tx-power"], signature="s"),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s",
                          out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise InvalidArgsException()
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature="",
                          out_signature="")
    def Release(self):
        log.ble("ADV", "Advertisement released by BlueZ")


# ---------------------------------------------------------------------------
# Service 1: Device Information (0x180A)
# ---------------------------------------------------------------------------

class DeviceInfoService(Service):
    def __init__(self, bus, index: int):
        super().__init__(bus, index, BLE_DEVICE_INFO_SVC, primary=True)

        # Manufacturer Name
        self.add_characteristic(ReadOnlyCharacteristic(
            bus, 0, BLE_MANUFACTURER_NAME_CHR, self,
            list(BLE_MANUFACTURER_NAME.encode("utf-8")),
        ))
        # Model Number
        self.add_characteristic(ReadOnlyCharacteristic(
            bus, 1, BLE_MODEL_NUMBER_CHR, self,
            list(BLE_MODEL_NUMBER.encode("utf-8")),
        ))
        # Firmware Revision
        self.add_characteristic(ReadOnlyCharacteristic(
            bus, 2, BLE_FIRMWARE_REV_CHR, self,
            list(BLE_FIRMWARE_REV.encode("utf-8")),
        ))
        # Software Revision
        self.add_characteristic(ReadOnlyCharacteristic(
            bus, 3, BLE_SOFTWARE_REV_CHR, self,
            list(BLE_SOFTWARE_REV.encode("utf-8")),
        ))
        # PnP ID
        self.add_characteristic(ReadOnlyCharacteristic(
            bus, 4, BLE_PNP_ID_CHR, self,
            list(BLE_PNP_ID),
        ))


class ReadOnlyCharacteristic(Characteristic):
    """Simple read-only characteristic with a static value."""

    def __init__(self, bus, index: int, uuid: str, service: Service,
                 value: list[int]):
        super().__init__(bus, index, uuid, ["read"], service)
        self.value = dbus.Array(value, signature="y")

    def ReadValue(self, options):
        log.ble("GATT", f"Read {self.uuid}")
        return self.value


# ---------------------------------------------------------------------------
# Service 2: Battery (0x180F)
# ---------------------------------------------------------------------------

class BatteryService(Service):
    def __init__(self, bus, index: int):
        super().__init__(bus, index, BLE_BATTERY_SVC, primary=True)
        self.add_characteristic(BatteryLevelCharacteristic(bus, 0, self))


class BatteryLevelCharacteristic(Characteristic):
    """Battery Level with read + notify support."""

    def __init__(self, bus, index: int, service: Service):
        super().__init__(bus, index, BLE_BATTERY_LEVEL_CHR,
                         ["read", "notify"], service)
        self.level = BLE_BATTERY_LEVEL
        self._notify_timer = None

    def ReadValue(self, options):
        log.ble("GATT", f"Read battery level: {self.level}%")
        return dbus.Array([dbus.Byte(self.level)], signature="y")

    def StartNotify(self):
        if self.notifying:
            return
        self.notifying = True
        log.ble("GATT", "Battery notify ON")
        self._notify_timer = GLib.timeout_add(5000, self._send_notification)

    def StopNotify(self):
        if not self.notifying:
            return
        self.notifying = False
        log.ble("GATT", "Battery notify OFF")
        if self._notify_timer is not None:
            GLib.source_remove(self._notify_timer)
            self._notify_timer = None

    def _send_notification(self) -> bool:
        if not self.notifying:
            return False
        value = dbus.Array([dbus.Byte(self.level)], signature="y")
        self.PropertiesChanged(
            GATT_CHRC_IFACE, {"Value": value}, [],
        )
        return True  # keep the timer running


# ---------------------------------------------------------------------------
# Service 3: Custom IVI (12345678-1234-5678-1234-56789abcdef0)
# ---------------------------------------------------------------------------

class CustomIVIService(Service):
    def __init__(self, bus, index: int):
        super().__init__(bus, index, BLE_CUSTOM_IVI_SVC, primary=True)

        self.add_characteristic(VehicleSpeedCharacteristic(bus, 0, self))
        self.add_characteristic(DiagnosticDataCharacteristic(bus, 1, self))
        self.add_characteristic(OTAUpdateCharacteristic(bus, 2, self))


class VehicleSpeedCharacteristic(Characteristic):
    """Vehicle speed (uint16 LE, km/h) -- read-only."""

    def __init__(self, bus, index: int, service: Service):
        super().__init__(bus, index, BLE_VEHICLE_SPEED_CHR,
                         ["read"], service)
        self.speed = 0  # km/h

    def ReadValue(self, options):
        value = struct.pack("<H", self.speed)
        log.ble("GATT", f"Read vehicle speed: {self.speed} km/h")
        return dbus.Array(list(value), signature="y")


class DiagnosticDataCharacteristic(Characteristic):
    """DTC diagnostic data -- read + write."""

    def __init__(self, bus, index: int, service: Service):
        super().__init__(bus, index, BLE_DIAG_DATA_CHR,
                         ["read", "write"], service)
        self.value = list(b"DTC:P0000 OK")

    def ReadValue(self, options):
        log.ble("GATT", f"Read diagnostic data ({len(self.value)} bytes)")
        return dbus.Array(self.value, signature="y")

    def WriteValue(self, value, options):
        self.value = list(value)
        written = bytes(value).decode("utf-8", errors="replace")
        log.ble("GATT", f"Write diagnostic data: {written!r}")


class OTAUpdateCharacteristic(Characteristic):
    """OTA firmware update -- write-only, NO authentication.

    This is intentionally vulnerable: any connected BLE client can push
    arbitrary bytes.  Writes are logged as attack activity.
    """

    def __init__(self, bus, index: int, service: Service):
        super().__init__(bus, index, BLE_OTA_UPDATE_CHR,
                         ["write-without-response"], service)

    def WriteValue(self, value, options):
        payload = bytes(value)
        device = options.get("device", "unknown")
        log.attack(
            "BLE-OTA",
            str(device),
            f"Unauthenticated OTA write ({len(payload)} bytes): "
            f"{payload[:32].hex()}{'...' if len(payload) > 32 else ''}",
        )


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------

def _register_app(bus, adapter_path: str, app: Application):
    """Register the GATT application with BlueZ."""
    manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE, adapter_path),
        GATT_MANAGER_IFACE,
    )

    def _reply():
        log.ble("GATT", "Application registered")

    def _error(error):
        log.error("GATT", f"Failed to register application: {error}")
        if mainloop is not None:
            mainloop.quit()

    manager.RegisterApplication(
        app.get_path(), {},
        reply_handler=_reply,
        error_handler=_error,
    )


def _register_advertisement(bus, adapter_path: str, adv: IVIAdvertisement):
    """Register the LE advertisement with BlueZ."""
    manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE, adapter_path),
        LE_ADVERTISING_MANAGER_IFACE,
    )

    def _reply():
        log.ble("ADV", "Advertisement registered")

    def _error(error):
        log.error("ADV", f"Failed to register advertisement: {error}")
        if mainloop is not None:
            mainloop.quit()

    manager.RegisterAdvertisement(
        adv.get_path(), {},
        reply_handler=_reply,
        error_handler=_error,
    )


def _find_adapter(bus, hci: str) -> str:
    """Return the D-Bus object path for the requested HCI adapter."""
    proxy = bus.get_object(BLUEZ_SERVICE, "/")
    om = dbus.Interface(proxy, DBUS_OM_IFACE)
    objects = om.GetManagedObjects()

    for path, interfaces in objects.items():
        if GATT_MANAGER_IFACE not in interfaces:
            continue
        if path.endswith("/" + hci):
            return path

    return None


# ---------------------------------------------------------------------------
# Module-level mainloop (referenced by callbacks)
# ---------------------------------------------------------------------------

mainloop: GLib.MainLoop = None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global mainloop

    parser = argparse.ArgumentParser(
        description="BLE GATT server for the Vulnerable IVI Simulator",
    )
    parser.add_argument(
        "--hci", default="hci0",
        help="HCI adapter to use (default: hci0)",
    )
    args = parser.parse_args()

    # Initialize D-Bus with GLib main loop integration
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # Find the adapter
    adapter_path = _find_adapter(bus, args.hci)
    if adapter_path is None:
        log.error("BLE", f"Adapter {args.hci} not found or does not support "
                         "GATT (GattManager1 interface missing)")
        sys.exit(1)

    log.ble("GATT", f"Using adapter {adapter_path}")

    # Build the GATT application
    app = Application(bus)
    app.add_service(DeviceInfoService(bus, 0))
    app.add_service(BatteryService(bus, 1))
    app.add_service(CustomIVIService(bus, 2))

    # Build the advertisement
    adv = IVIAdvertisement(bus)

    # Register with BlueZ
    _register_app(bus, adapter_path, app)
    _register_advertisement(bus, adapter_path, adv)

    mainloop = GLib.MainLoop()

    # ---- Graceful shutdown ------------------------------------------------

    def _shutdown(signum, _frame):
        sig_name = signal.Signals(signum).name
        log.ble("GATT", f"Received {sig_name}, shutting down...")

        # Attempt to unregister cleanly -- ignore errors on teardown
        try:
            mgr = dbus.Interface(
                bus.get_object(BLUEZ_SERVICE, adapter_path),
                GATT_MANAGER_IFACE,
            )
            mgr.UnregisterApplication(app.get_path())
        except Exception:
            pass

        try:
            adv_mgr = dbus.Interface(
                bus.get_object(BLUEZ_SERVICE, adapter_path),
                LE_ADVERTISING_MANAGER_IFACE,
            )
            adv_mgr.UnregisterAdvertisement(adv.get_path())
        except Exception:
            pass

        if mainloop is not None:
            mainloop.quit()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ---- Run --------------------------------------------------------------

    log.ble("GATT", f"BLE GATT server running on {args.hci} "
                     f"(LocalName={IVI_NAME!r})")
    log.ble("GATT", "Services: DeviceInfo, Battery, CustomIVI")
    log.ble("GATT", "Press Ctrl+C to stop")

    try:
        mainloop.run()
    except Exception as exc:
        log.error("BLE", f"Main loop error: {exc}")
    finally:
        log.ble("GATT", "Stopped")


if __name__ == "__main__":
    main()
