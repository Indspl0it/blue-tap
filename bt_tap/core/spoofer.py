"""Bluetooth MAC address spoofing."""

import json
import os

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

    # Write new address
    result = run_cmd(["sudo", "bdaddr", "-i", hci, target_mac])
    combined_output = (result.stdout + result.stderr).lower()

    # Check for hardware rejection even on exit code 0
    rejection_patterns = [
        "hardware does not allow",
        "not supported",
        "operation not permitted",
        "input/output error",
        "command disallowed",
    ]
    for pattern in rejection_patterns:
        if pattern in combined_output:
            error(f"bdaddr: hardware rejected change ({pattern})")
            return False

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
    combined_output = (result.stdout + result.stderr).lower()

    # Check for hardware rejection messages even if return code is 0
    rejection_patterns = [
        "hardware does not allow",
        "not supported",
        "can't set bdaddr",
        "operation not permitted",
        "input/output error",
        "not possible",
        "command disallowed",
    ]
    for pattern in rejection_patterns:
        if pattern in combined_output:
            error(f"spooftooph: hardware rejected change ({pattern})")
            return False

    if result.returncode != 0:
        error(f"spooftooph failed: {result.stderr.strip()}")
        return False

    # Verify the address actually changed (return code alone is unreliable)
    new_addr = get_adapter_address(hci)
    if new_addr and new_addr.upper() == target_mac.upper():
        success(f"Spoofed {hci} to {target_mac} (verified)")
        return True
    else:
        warning(f"spooftooph returned success but address is still {new_addr} (expected {target_mac})")
        warning("Hardware likely does not support MAC spoofing via this method.")
        return False


def spoof_btmgmt(hci: str, target_mac: str) -> bool:
    """Spoof using btmgmt (BlueZ management interface).

    This method works on many modern adapters without extra tools.
    """
    target_mac = normalize_mac(target_mac)
    idx = hci.replace("hci", "")
    info(f"Spoofing via btmgmt index {idx} -> {target_mac}")

    rejection_patterns = [
        "not supported",
        "invalid params",
        "rejected",
        "not powered",
        "command disallowed",
        "hardware does not allow",
    ]

    # Power down first
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])

    # Try public-addr first (changes BD_ADDR for BR/EDR + BLE public)
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "public-addr", target_mac])
    combined = (result.stdout + result.stderr).lower()
    public_failed = result.returncode != 0 or any(p in combined for p in rejection_patterns)

    if public_failed:
        warning(f"btmgmt public-addr not supported: {result.stderr.strip() or result.stdout.strip()}")
        # static-addr only sets BLE random address, not the BD_ADDR visible in
        # hciconfig. It won't help for BR/EDR spoofing so skip it to avoid
        # false hope.
        info("static-addr only affects BLE random address, skipping for BR/EDR spoof")

    # Power back on
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])

    if public_failed:
        warning(f"btmgmt method not supported on this adapter")
        return False

    # Verify address actually changed
    new_addr = get_adapter_address(hci)
    if new_addr and new_addr.upper() == target_mac.upper():
        success(f"Spoofed via btmgmt: {hci} = {new_addr}")
        return True
    else:
        warning(f"btmgmt returned success but address is still {new_addr} (expected {target_mac})")
        warning("Hardware accepted command but did not change address.")
        return False


def spoof_address(hci: str, target_mac: str, method: str = "auto") -> bool:
    """Spoof MAC address using the best available method.

    Methods: auto, bdaddr, spooftooph, btmgmt
    """
    from bt_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return False

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
        name_ok = set_device_name(hci, target_name)
        class_ok = set_device_class(hci, device_class)
        if name_ok and class_ok:
            success(f"Full identity clone complete on {hci}")
            return True
        else:
            failed = []
            if not name_ok:
                failed.append("name")
            if not class_ok:
                failed.append("class")
            warning(f"Identity clone partial: MAC spoofed but {', '.join(failed)} set failed")
            return True  # MAC is spoofed, which is the critical part
    except Exception as e:
        error(f"Identity clone partial failure: {e}")
        return False
