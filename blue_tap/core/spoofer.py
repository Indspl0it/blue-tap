"""Bluetooth MAC address spoofing."""

import json
import os

from blue_tap.utils.bt_helpers import (
    run_cmd, normalize_mac, check_tool,
    get_adapter_address,
)
from blue_tap.utils.output import info, success, error, warning

# File to persist original MAC for restore
_ORIGINAL_MAC_FILE = os.path.expanduser("~/.blue_tap_original_mac.json")


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
        except json.JSONDecodeError:
            warning(f"MAC backup file corrupted — backing up and starting fresh")
            try:
                import shutil
                shutil.copy2(_ORIGINAL_MAC_FILE, _ORIGINAL_MAC_FILE + ".bak")
            except OSError:
                pass
            data = {}
        except OSError:
            data = {}
    if hci not in data:  # Only save if not already stored (idempotent)
        data[hci] = addr
        tmp_path = _ORIGINAL_MAC_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, _ORIGINAL_MAC_FILE)
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
    import time
    run_cmd(["sudo", "hciconfig", hci, "reset"])
    time.sleep(1)
    run_cmd(["sudo", "hciconfig", hci, "down"])
    time.sleep(1)
    run_cmd(["sudo", "hciconfig", hci, "up"])
    time.sleep(1)  # Give adapter time to stabilize

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
    power_off = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
    if power_off.returncode != 0:
        error(f"btmgmt power off failed: {power_off.stderr.strip()}")
        return False

    # Try public-addr first (changes BD_ADDR for BR/EDR + BLE public)
    try:
        result = run_cmd(["sudo", "btmgmt", "--index", idx, "public-addr", target_mac])
        combined = (result.stdout + result.stderr).lower()
        public_failed = result.returncode != 0 or any(p in combined for p in rejection_patterns)

        if public_failed:
            warning(f"btmgmt public-addr not supported: {result.stderr.strip() or result.stdout.strip()}")
            # static-addr only sets BLE random address, not the BD_ADDR visible in
            # hciconfig. It won't help for BR/EDR spoofing so skip it to avoid
            # false hope.
            info("static-addr only affects BLE random address, skipping for BR/EDR spoof")
    finally:
        # Power back on — always runs even if public-addr fails
        import time
        power_on = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])
        if power_on.returncode != 0:
            warning(f"btmgmt power on failed — retrying in 2s...")
            time.sleep(2)
            power_on = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])
            if power_on.returncode != 0:
                error(f"Adapter {hci} may be stuck in DOWN state — run: sudo hciconfig {hci} up")

    if public_failed:
        warning("btmgmt method not supported on this adapter")
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


def spoof_rtl8761b(hci: str, target_mac: str) -> bool:
    """Spoof BDADDR on RTL8761B via DarkFirmware firmware patching.

    Patches the firmware binary at the BDADDR offset and performs a USB
    reset to reload the firmware with the new address.  This is the only
    reliable spoofing method for Realtek chipsets (bdaddr, spooftooph,
    and btmgmt all return 'Unsupported manufacturer').
    """
    try:
        from blue_tap.core.firmware import DarkFirmwareManager
        fw = DarkFirmwareManager()
        if not fw.detect_rtl8761b(hci):
            return False
        return fw.patch_bdaddr(target_mac, hci)
    except Exception as exc:
        error(f"RTL8761B BDADDR spoofing failed: {exc}")
        return False


def spoof_address(hci: str, target_mac: str, method: str = "auto") -> bool:
    """Spoof MAC address using the best available method.

    Methods: auto, bdaddr, spooftooph, btmgmt
    """
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
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
    elif method == "rtl8761b":
        return spoof_rtl8761b(hci, target_mac)
    else:
        # Try RTL8761B firmware patching first (only method that works on Realtek)
        try:
            from blue_tap.core.firmware import DarkFirmwareManager
            fw = DarkFirmwareManager()
            if fw.detect_rtl8761b(hci):
                info("Detected RTL8761B — using firmware BDADDR patching")
                if spoof_rtl8761b(hci, target_mac):
                    return True
                warning("RTL8761B firmware patching failed, trying other methods...")
        except ImportError:
            pass

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
    from blue_tap.core.adapter import set_device_name, set_device_class

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
            error(f"Identity clone incomplete: MAC spoofed but {', '.join(failed)} failed — IVI may reject connection")
            return False
    except Exception as e:
        error(f"Identity clone partial failure: {e}")
        return False
