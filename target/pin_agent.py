#!/usr/bin/env python3
"""BlueZ D-Bus pairing agent for the Vulnerable IVI Simulator.

Registers as org.bluez.Agent1 with capability "KeyboardDisplay".
Handles PIN/passkey requests and enforces bond-state checks on
authorization requests.

Usage:
    sudo python3 pin_agent.py [--hci hci0] [--phone-mac AA:BB:CC:DD:EE:FF]
"""

import argparse
import signal
import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from ivi_config import DEFAULT_PIN, read_phone_mac, read_profile
from ivi_log import log

# ── D-Bus constants ───────────────────────────────────────────────────────

BLUEZ_BUS = "org.bluez"
AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_MANAGER_INTERFACE = "org.bluez.AgentManager1"
DEVICE_INTERFACE = "org.bluez.Device1"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"

AGENT_PATH = "/ivi/agent"
CAPABILITY = "KeyboardDisplay"


# ── Agent implementation ──────────────────────────────────────────────────

class IVIPairingAgent(dbus.service.Object):
    """BlueZ pairing agent that auto-accepts known devices."""

    def __init__(self, bus, path, hci="hci0"):
        super().__init__(bus, path)
        self._bus = bus
        self._hci = hci

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _get_address(device_path: str) -> str:
        """Extract a MAC address from a D-Bus device path.

        Path format: /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF
        """
        return device_path.split("/")[-1].removeprefix("dev_").replace("_", ":")

    def _is_bonded(self, addr: str) -> bool:
        """Query BlueZ for the Paired property of a device."""
        try:
            # Reconstruct the object path from the address
            dev_path = addr.replace(":", "_")
            obj_path = f"/org/bluez/{self._hci}/dev_{dev_path}"
            device = self._bus.get_object(BLUEZ_BUS, obj_path)
            props = dbus.Interface(device, DBUS_PROPERTIES)
            paired = props.Get(DEVICE_INTERFACE, "Paired")
            return bool(paired)
        except Exception:
            return False

    # ── org.bluez.Agent1 methods ─────────────────────────────────────

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Release(self):
        log.info("AGENT", "Agent released by BlueZ")

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        addr = self._get_address(device)
        log.info("AGENT", f"PIN requested by {addr} -> returning {DEFAULT_PIN}")
        return dbus.String(DEFAULT_PIN)

    @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        addr = self._get_address(device)
        log.info("AGENT", f"DisplayPinCode for {addr}: {pincode}")

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        addr = self._get_address(device)
        passkey = int(DEFAULT_PIN)
        log.info("AGENT", f"Passkey requested by {addr} -> returning {passkey}")
        return dbus.UInt32(passkey)

    @dbus.service.method(AGENT_INTERFACE, in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device, passkey, entered):
        addr = self._get_address(device)
        log.info("AGENT", f"DisplayPasskey for {addr}: {passkey:06d} (entered {entered})")

    @dbus.service.method(AGENT_INTERFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        addr = self._get_address(device)
        log.info("AGENT", f"Auto-confirming SSP passkey {passkey:06d} for {addr}")
        # Auto-accept (Just Works / SSP)

    @dbus.service.method(AGENT_INTERFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        addr = self._get_address(device)
        if self._is_bonded(addr):
            log.info("AGENT", f"Authorization granted for bonded device {addr}")
            return
        log.warn("AGENT", f"Authorization REJECTED for unbonded device {addr}")
        raise dbus.DBusException(
            name="org.bluez.Error.Rejected",
            message=f"Device {addr} is not bonded",
        )

    @dbus.service.method(AGENT_INTERFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        addr = self._get_address(device)
        if self._is_bonded(addr):
            log.info("AGENT", f"Service {uuid} authorized for bonded device {addr}")
            return
        log.warn("AGENT", f"Service {uuid} REJECTED for unbonded device {addr}")
        raise dbus.DBusException(
            name="org.bluez.Error.Rejected",
            message=f"Device {addr} is not bonded — service {uuid} denied",
        )

    @dbus.service.method(AGENT_INTERFACE, in_signature="", out_signature="")
    def Cancel(self):
        log.info("AGENT", "Pairing cancelled by BlueZ")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IVI BlueZ pairing agent")
    parser.add_argument("--hci", default="hci0", help="HCI adapter name (default: hci0)")
    parser.add_argument("--phone-mac", default=None,
                        help="Expected phone MAC (default: read from .ivi_phone)")
    args = parser.parse_args()

    phone_mac = args.phone_mac or read_phone_mac()
    profile = read_profile()

    # GLib/D-Bus setup — set default loop BEFORE getting the bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    mainloop = GLib.MainLoop()

    # Create agent object
    agent = IVIPairingAgent(bus, AGENT_PATH, hci=args.hci)

    # Register with BlueZ AgentManager
    manager_obj = bus.get_object(BLUEZ_BUS, "/org/bluez")
    manager = dbus.Interface(manager_obj, AGENT_MANAGER_INTERFACE)

    try:
        manager.RegisterAgent(AGENT_PATH, CAPABILITY)
    except dbus.DBusException as exc:
        # Already registered is fine; anything else is fatal
        if "AlreadyExists" not in str(exc):
            log.error("AGENT", f"Failed to register agent: {exc}")
            sys.exit(1)
        log.warn("AGENT", "Agent was already registered — continuing")

    try:
        manager.RequestDefaultAgent(AGENT_PATH)
    except dbus.DBusException as exc:
        log.warn("AGENT", f"RequestDefaultAgent failed: {exc}")

    log.info("AGENT", f"Pairing agent registered on {AGENT_PATH}")
    log.info("AGENT", f"Profile: {profile}  |  Phone MAC: {phone_mac}  |  HCI: {args.hci}")
    log.info("AGENT", f"Capability: {CAPABILITY}  |  PIN: {DEFAULT_PIN}")
    # Keep a strong reference for the lifetime of mainloop.
    log.info("AGENT", f"Agent object active: {agent.__class__.__name__}")

    # Graceful shutdown
    def _shutdown(signum, frame):
        log.info("AGENT", "Caught SIGINT — unregistering agent")
        try:
            manager.UnregisterAgent(AGENT_PATH)
        except dbus.DBusException:
            pass
        mainloop.quit()

    signal.signal(signal.SIGINT, _shutdown)

    try:
        mainloop.run()
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()
