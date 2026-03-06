"""HCI Bluetooth adapter management."""

import subprocess

from bt_tap.utils.bt_helpers import run_cmd, get_hci_adapters
from bt_tap.utils.output import info, success, error, warning


def list_adapters() -> list[dict]:
    """List and display all HCI adapters."""
    adapters = get_hci_adapters()
    if not adapters:
        error("No HCI adapters found. Ensure Bluetooth hardware is connected.")
    return adapters


def _hci_cmd(hci: str, *args: str) -> bool:
    """Run hciconfig command with error handling."""
    result = run_cmd(["sudo", "hciconfig", hci, *args])
    if result.returncode != 0:
        error(f"hciconfig {hci} {' '.join(args)} failed: {result.stderr.strip()}")
        return False
    return True


def adapter_up(hci: str = "hci0"):
    """Bring an adapter up."""
    if _hci_cmd(hci, "up"):
        success(f"{hci} is UP")


def adapter_down(hci: str = "hci0"):
    """Bring an adapter down."""
    if _hci_cmd(hci, "down"):
        info(f"{hci} is DOWN")


def adapter_reset(hci: str = "hci0"):
    """Reset an adapter."""
    if _hci_cmd(hci, "reset"):
        info(f"{hci} reset complete")


def set_device_class(hci: str, device_class: str = "0x5a020c"):
    """Set the Bluetooth device class.

    Common classes for IVI impersonation:
      0x200404 - Audio/Video: Car Audio
      0x200408 - Audio/Video: Portable Audio
      0x5a020c - Phone (smartphone)
      0x7a020c - Smart Phone
    """
    if _hci_cmd(hci, "class", device_class):
        success(f"{hci} device class set to {device_class}")


def set_device_name(hci: str, name: str):
    """Set the Bluetooth device name (useful for impersonation)."""
    if _hci_cmd(hci, "name", name):
        success(f"{hci} name set to '{name}'")


def enable_page_scan(hci: str):
    """Make device discoverable (page scan) and connectable."""
    if _hci_cmd(hci, "piscan"):
        success(f"{hci} set to discoverable + connectable")


def disable_page_scan(hci: str):
    """Make device non-discoverable."""
    if _hci_cmd(hci, "noscan"):
        info(f"{hci} set to non-discoverable")


def enable_ssp(hci: str):
    """Enable Secure Simple Pairing on the adapter."""
    idx = hci.replace("hci", "")
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "on"])
    if result.returncode == 0:
        success(f"SSP enabled on {hci}")
    else:
        error(f"Failed to enable SSP: {result.stderr.strip()}")


def disable_ssp(hci: str):
    """Disable SSP (force legacy PIN pairing)."""
    idx = hci.replace("hci", "")
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "off"])
    if result.returncode == 0:
        warning(f"SSP disabled on {hci} - legacy PIN pairing mode")
    else:
        error(f"Failed to disable SSP: {result.stderr.strip()}")
