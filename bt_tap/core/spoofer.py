"""Bluetooth MAC address spoofing."""

import json
import os
import subprocess

from bt_tap.utils.bt_helpers import (
    run_cmd, validate_mac, normalize_mac, check_tool,
    check_root, get_adapter_address,
)
from bt_tap.utils.output import info, success, error, warning

# File to persist original MAC for restore
_ORIGINAL_MAC_FILE = os.path.expanduser("~/.bt_tap_original_mac.json")


def save_original_mac(hci: str):
    """Save the adapter's current MAC before spoofing so it can be restored."""
    addr = get_adapter_address(hci)
    if not addr:
        return
    data = {}
    if os.path.exists(_ORIGINAL_MAC_FILE):
        try:
            with open(_ORIGINAL_MAC_FILE) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    if hci not in data:  # Only save if not already stored (idempotent)
        data[hci] = addr
        with open(_ORIGINAL_MAC_FILE, "w") as f:
            json.dump(data, f)
        info(f"Saved original MAC for {hci}: {addr}")


def get_original_mac(hci: str) -> str | None:
    """Get the saved original MAC for an adapter."""
    if not os.path.exists(_ORIGINAL_MAC_FILE):
        return None
    try:
        with open(_ORIGINAL_MAC_FILE) as f:
            data = json.load(f)
        return data.get(hci)
    except (json.JSONDecodeError, OSError):
        return None


def restore_original_mac(hci: str, method: str = "auto") -> bool:
    """Restore the adapter's original MAC address."""
    original = get_original_mac(hci)
    if not original:
        warning(f"No saved original MAC for {hci}. Reboot to restore.")
        return False
    info(f"Restoring {hci} to original MAC: {original}")
    result = spoof_address(hci, original, method)
    if result:
        # Remove saved entry
        try:
            with open(_ORIGINAL_MAC_FILE) as f:
                data = json.load(f)
            data.pop(hci, None)
            with open(_ORIGINAL_MAC_FILE, "w") as f:
                json.dump(data, f)
        except (json.JSONDecodeError, OSError):
            pass
    return result


def spoof_bdaddr(hci: str, target_mac: str) -> bool:
    """Spoof adapter MAC address using bdaddr (CSR chipset tool).

    Requirements: bdaddr tool (typically build from source, or use distro package if available)
    Works with: CSR-based USB Bluetooth adapters
    """
    if not check_tool("bdaddr"):
        error("bdaddr not found. Install from your distro package if available, or build from BlueZ source")
        return False

    target_mac = normalize_mac(target_mac)
    original = get_adapter_address(hci)
    info(f"Original address: {original}")
    info(f"Spoofing {hci} -> {target_mac}")

    try:
        # Write new address
        result = run_cmd(["sudo", "bdaddr", "-i", hci, target_mac])
        if result.returncode != 0:
            error(f"bdaddr failed: {result.stderr.strip()}")
            return False

        # Reset adapter to apply
        run_cmd(["sudo", "hciconfig", hci, "reset"])
        run_cmd(["sudo", "hciconfig", hci, "down"])
        run_cmd(["sudo", "hciconfig", hci, "up"])

        # Verify
        new_addr = get_adapter_address(hci)
        if new_addr and new_addr.upper() == target_mac.upper():
            success(f"Spoofed successfully: {hci} = {new_addr}")
            return True
        else:
            warning(f"Address after reset: {new_addr} (expected {target_mac})")
            warning("Some adapters need physical replug to apply. Try spooftooph as alternative.")
            return False

    except subprocess.CalledProcessError as e:
        error(f"Spoof failed: {e}")
        return False


def spoof_spooftooph(hci: str, target_mac: str) -> bool:
    """Spoof using spooftooph (supports more chipsets).

    Requirements: spooftooph (apt install spooftooph on Kali)
    """
    if not check_tool("spooftooph"):
        error("spooftooph not found. Install: apt install spooftooph")
        return False

    target_mac = normalize_mac(target_mac)
    info(f"Spoofing {hci} -> {target_mac} via spooftooph")

    result = run_cmd(["sudo", "spooftooph", "-i", hci, "-a", target_mac])
    if result.returncode == 0:
        success(f"Spoofed {hci} to {target_mac}")
        return True
    else:
        error(f"spooftooph failed: {result.stderr.strip()}")
        return False


def spoof_btmgmt(hci: str, target_mac: str) -> bool:
    """Spoof using btmgmt (BlueZ management interface).

    This method works on many modern adapters without extra tools.
    """
    target_mac = normalize_mac(target_mac)
    idx = hci.replace("hci", "")
    info(f"Spoofing via btmgmt index {idx} -> {target_mac}")

    # Power down first
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])

    # Set public address
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "public-addr", target_mac])
    if result.returncode != 0:
        warning(f"btmgmt public-addr failed: {result.stderr.strip()}")
        # Try static-addr for BLE
        result = run_cmd(["sudo", "btmgmt", "--index", idx, "static-addr", target_mac])

    # Power back on
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])

    new_addr = get_adapter_address(hci)
    if new_addr and new_addr.upper() == target_mac.upper():
        success(f"Spoofed via btmgmt: {hci} = {new_addr}")
        return True
    else:
        warning(f"btmgmt method may not be supported on this adapter (got: {new_addr})")
        return False


def spoof_address(hci: str, target_mac: str, method: str = "auto") -> bool:
    """Spoof MAC address using the best available method.

    Methods: auto, bdaddr, spooftooph, btmgmt
    """
    target_mac = normalize_mac(target_mac)

    # Save original MAC before any spoofing attempt
    save_original_mac(hci)

    if method == "bdaddr":
        return spoof_bdaddr(hci, target_mac)
    elif method == "spooftooph":
        return spoof_spooftooph(hci, target_mac)
    elif method == "btmgmt":
        return spoof_btmgmt(hci, target_mac)
    else:
        # Auto: try each method
        for name, fn in [
            ("bdaddr", spoof_bdaddr),
            ("spooftooph", spoof_spooftooph),
            ("btmgmt", spoof_btmgmt),
        ]:
            info(f"Trying method: {name}")
            if fn(hci, target_mac):
                return True
            warning(f"{name} did not work, trying next...")
        error("All spoofing methods failed")
        return False


def clone_device_identity(hci: str, target_mac: str, target_name: str,
                          device_class: str = "0x5a020c") -> bool:
    """Full device identity clone: MAC + name + device class.

    This is the key step for impersonating a paired phone to an IVI.
    """
    from bt_tap.core.adapter import set_device_name, set_device_class

    info(f"Cloning device identity: {target_mac} '{target_name}'")

    if not spoof_address(hci, target_mac):
        return False

    try:
        set_device_name(hci, target_name)
        set_device_class(hci, device_class)
        success(f"Full identity clone complete on {hci}")
        return True
    except Exception as e:
        error(f"Identity clone partial failure: {e}")
        return False
