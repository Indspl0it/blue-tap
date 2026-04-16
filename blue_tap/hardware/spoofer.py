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


def restore_original_mac(hci: str, method: str = "auto") -> dict:
    """Restore the adapter's original MAC address."""
    original = get_original_mac(hci)
    if not original:
        warning(f"No saved original MAC for {hci}. Reboot to restore.")
        return {"success": False, "restored_mac": "", "hci": hci, "method": method,
                "error": f"no saved original MAC for {hci}"}
    info(f"Restoring {hci} to original MAC: {original}")
    spoof_result = spoof_address(hci, original, method)
    if spoof_result["success"]:
        # Remove saved entry using atomic write (tmp → rename) so the MAC file
        # is never in a partially-written state.
        try:
            with open(_ORIGINAL_MAC_FILE) as f:
                data = json.load(f)
            data.pop(hci, None)
            tmp_path = _ORIGINAL_MAC_FILE + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, _ORIGINAL_MAC_FILE)
        except (json.JSONDecodeError, OSError):
            pass
    return {"success": spoof_result["success"],
            "restored_mac": original if spoof_result["success"] else "",
            "hci": hci,
            "method": spoof_result.get("method_used") or method,
            "error": spoof_result.get("error", "")}


def spoof_bdaddr(hci: str, target_mac: str) -> dict:
    """Spoof adapter MAC address using bdaddr (CSR chipset tool).

    Requirements: bdaddr tool (typically build from source, or use distro package if available)
    Works with: CSR-based USB Bluetooth adapters
    """
    original = get_adapter_address(hci) or ""

    if not check_tool("bdaddr"):
        error("bdaddr not found. Install from your distro package if available, or build from BlueZ source")
        return {"success": False, "method": "bdaddr", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": "bdaddr not found"}

    target_mac = normalize_mac(target_mac)
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
            return {"success": False, "method": "bdaddr", "original_mac": original,
                    "target_mac": target_mac, "verified": False, "hci": hci,
                    "error": f"hardware rejected change ({pattern})"}

    if result.returncode != 0:
        err_msg = result.stderr.strip()
        error(f"bdaddr failed: {err_msg}")
        return {"success": False, "method": "bdaddr", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": err_msg}

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
    verified = bool(new_addr and new_addr.upper() == target_mac.upper())
    if verified:
        success(f"Spoofed successfully: {hci} = {new_addr}")
        return {"success": True, "method": "bdaddr", "original_mac": original,
                "target_mac": target_mac, "verified": True, "hci": hci, "error": ""}
    else:
        warning(f"Address after reset: {new_addr} (expected {target_mac})")
        warning("Some adapters need physical replug to apply. Try spooftooph as alternative.")
        return {"success": False, "method": "bdaddr", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": f"address after reset is {new_addr}, expected {target_mac}"}


def spoof_spooftooph(hci: str, target_mac: str) -> dict:
    """Spoof using spooftooph (supports more chipsets).

    Requirements: spooftooph (apt install spooftooph on Kali)
    """
    original = get_adapter_address(hci) or ""

    if not check_tool("spooftooph"):
        error("spooftooph not found. Install: apt install spooftooph")
        return {"success": False, "method": "spooftooph", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": "spooftooph not found"}

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
            return {"success": False, "method": "spooftooph", "original_mac": original,
                    "target_mac": target_mac, "verified": False, "hci": hci,
                    "error": f"hardware rejected change ({pattern})"}

    if result.returncode != 0:
        err_msg = result.stderr.strip()
        error(f"spooftooph failed: {err_msg}")
        return {"success": False, "method": "spooftooph", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": err_msg}

    # Verify the address actually changed (return code alone is unreliable)
    new_addr = get_adapter_address(hci)
    verified = bool(new_addr and new_addr.upper() == target_mac.upper())
    if verified:
        success(f"Spoofed {hci} to {target_mac} (verified)")
        return {"success": True, "method": "spooftooph", "original_mac": original,
                "target_mac": target_mac, "verified": True, "hci": hci, "error": ""}
    else:
        warning(f"spooftooph returned success but address is still {new_addr} (expected {target_mac})")
        warning("Hardware likely does not support MAC spoofing via this method.")
        return {"success": False, "method": "spooftooph", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": f"address still {new_addr} after spoof, expected {target_mac}"}


def spoof_btmgmt(hci: str, target_mac: str) -> dict:
    """Spoof using btmgmt (BlueZ management interface).

    This method works on many modern adapters without extra tools.
    """
    original = get_adapter_address(hci) or ""
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
        err_msg = power_off.stderr.strip()
        error(f"btmgmt power off failed: {err_msg}")
        return {"success": False, "method": "btmgmt", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": f"power off failed: {err_msg}"}

    # Try public-addr first (changes BD_ADDR for BR/EDR + BLE public)
    public_failed = True
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
    except Exception as exc:
        warning(f"btmgmt public-addr call failed: {exc}")
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
        return {"success": False, "method": "btmgmt", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": "btmgmt public-addr not supported on this adapter"}

    # Verify address actually changed
    new_addr = get_adapter_address(hci)
    verified = bool(new_addr and new_addr.upper() == target_mac.upper())
    if verified:
        success(f"Spoofed via btmgmt: {hci} = {new_addr}")
        return {"success": True, "method": "btmgmt", "original_mac": original,
                "target_mac": target_mac, "verified": True, "hci": hci, "error": ""}
    else:
        warning(f"btmgmt returned success but address is still {new_addr} (expected {target_mac})")
        warning("Hardware accepted command but did not change address.")
        return {"success": False, "method": "btmgmt", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": f"address still {new_addr} after btmgmt, expected {target_mac}"}


def spoof_rtl8761b(hci: str, target_mac: str) -> dict:
    """Spoof BDADDR on RTL8761B via DarkFirmware.

    Preferred method: RAM-only live patch (instant, no USB reset, volatile).
    Fallback: firmware file patch + USB reset (persistent, slower).

    The RAM method writes the new BDADDR directly to all copies in
    controller memory, then verifies via hciconfig.  If hciconfig still
    shows the old address after RAM patching (host stack cache stale),
    falls back to the firmware file method with USB reset.
    """
    original = get_adapter_address(hci) or ""
    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        fw = DarkFirmwareManager()
        if not fw.detect_rtl8761b(hci):
            return {"success": False, "method": "rtl8761b", "original_mac": original,
                    "target_mac": target_mac, "verified": False, "hci": hci,
                    "error": "RTL8761B not detected on this adapter"}

        # Preferred: RAM-only live patch (no file modification, instant)
        if fw.is_darkfirmware_loaded(hci):
            info("Attempting RAM-only BDADDR patch (preferred, no USB reset)...")
            if fw.patch_bdaddr_ram(target_mac, hci):
                new_addr = get_adapter_address(hci) or ""
                verified = new_addr.upper() == target_mac.upper()
                return {"success": True, "method": "rtl8761b", "original_mac": original,
                        "target_mac": target_mac, "verified": verified, "hci": hci, "error": ""}
            warning("RAM patch did not verify — falling back to firmware file patch")

        # Fallback: firmware file patch + USB reset (persistent, slower)
        info("Using firmware file BDADDR patch (USB reset required)...")
        ok = fw.patch_bdaddr(target_mac, hci)
        if ok:
            new_addr = get_adapter_address(hci) or ""
            verified = new_addr.upper() == target_mac.upper()
            return {"success": True, "method": "rtl8761b", "original_mac": original,
                    "target_mac": target_mac, "verified": verified, "hci": hci, "error": ""}
        return {"success": False, "method": "rtl8761b", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci,
                "error": "firmware file BDADDR patch failed"}
    except Exception as exc:
        error(f"RTL8761B BDADDR spoofing failed: {exc}")
        return {"success": False, "method": "rtl8761b", "original_mac": original,
                "target_mac": target_mac, "verified": False, "hci": hci, "error": str(exc)}


def spoof_address(hci: str, target_mac: str, method: str = "auto") -> dict:
    """Spoof MAC address using the best available method.

    Methods: auto, bdaddr, spooftooph, btmgmt
    """
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        original = get_adapter_address(hci) or ""
        return {"success": False, "method_used": "", "methods_tried": [],
                "original_mac": original, "target_mac": target_mac,
                "verified": False, "hci": hci, "error": "adapter not ready"}

    original = get_adapter_address(hci) or ""
    target_mac = normalize_mac(target_mac)

    # Save original MAC before any spoofing attempt
    save_original_mac(hci)

    if method == "bdaddr":
        sub = spoof_bdaddr(hci, target_mac)
        return {"success": sub["success"], "method_used": "bdaddr" if sub["success"] else "",
                "methods_tried": ["bdaddr"], "original_mac": original,
                "target_mac": target_mac, "verified": sub["verified"],
                "hci": hci, "error": sub["error"]}
    elif method == "spooftooph":
        sub = spoof_spooftooph(hci, target_mac)
        return {"success": sub["success"], "method_used": "spooftooph" if sub["success"] else "",
                "methods_tried": ["spooftooph"], "original_mac": original,
                "target_mac": target_mac, "verified": sub["verified"],
                "hci": hci, "error": sub["error"]}
    elif method == "btmgmt":
        sub = spoof_btmgmt(hci, target_mac)
        return {"success": sub["success"], "method_used": "btmgmt" if sub["success"] else "",
                "methods_tried": ["btmgmt"], "original_mac": original,
                "target_mac": target_mac, "verified": sub["verified"],
                "hci": hci, "error": sub["error"]}
    elif method == "rtl8761b":
        sub = spoof_rtl8761b(hci, target_mac)
        return {"success": sub["success"], "method_used": "rtl8761b" if sub["success"] else "",
                "methods_tried": ["rtl8761b"], "original_mac": original,
                "target_mac": target_mac, "verified": sub["verified"],
                "hci": hci, "error": sub["error"]}
    else:
        methods_tried: list[str] = []

        # Try RTL8761B firmware patching first (only method that works on Realtek)
        try:
            from blue_tap.hardware.firmware import DarkFirmwareManager
            fw = DarkFirmwareManager()
            if fw.detect_rtl8761b(hci):
                info("Detected RTL8761B — using firmware BDADDR patching")
                methods_tried.append("rtl8761b")
                sub = spoof_rtl8761b(hci, target_mac)
                if sub["success"]:
                    return {"success": True, "method_used": "rtl8761b",
                            "methods_tried": methods_tried, "original_mac": original,
                            "target_mac": target_mac, "verified": sub["verified"],
                            "hci": hci, "error": ""}
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
            methods_tried.append(name)
            sub = fn(hci, target_mac)
            if sub["success"]:
                return {"success": True, "method_used": name,
                        "methods_tried": methods_tried, "original_mac": original,
                        "target_mac": target_mac, "verified": sub["verified"],
                        "hci": hci, "error": ""}
            warning(f"{name} did not work, trying next...")

        error("All spoofing methods failed")
        return {"success": False, "method_used": "", "methods_tried": methods_tried,
                "original_mac": original, "target_mac": target_mac,
                "verified": False, "hci": hci, "error": "all spoofing methods failed"}


def clone_device_identity(hci: str, target_mac: str, target_name: str,
                          device_class: str = "0x5a020c") -> dict:
    """Full device identity clone: MAC + name + device class.

    This is the key step for impersonating a paired phone to an IVI.
    """
    from blue_tap.hardware.adapter import set_device_name, set_device_class

    original = get_adapter_address(hci) or ""
    info(f"Cloning device identity: {target_mac} '{target_name}'")

    spoof_result = spoof_address(hci, target_mac)
    if not spoof_result["success"]:
        return {"success": False, "mac_spoofed": False, "name_set": False, "class_set": False,
                "original_mac": original, "target_mac": target_mac,
                "target_name": target_name, "device_class": device_class,
                "hci": hci, "error": spoof_result.get("error", "MAC spoof failed")}

    try:
        name_result = set_device_name(hci, target_name)
        class_result = set_device_class(hci, device_class)
        name_ok = bool(name_result.get("success"))
        class_ok = bool(class_result.get("success"))
        if name_ok and class_ok:
            success(f"Full identity clone complete on {hci}")
            return {"success": True, "mac_spoofed": True, "name_set": True, "class_set": True,
                    "original_mac": original, "target_mac": target_mac,
                    "target_name": target_name, "device_class": device_class,
                    "hci": hci, "error": ""}
        else:
            failed = []
            if not name_ok:
                failed.append("name")
            if not class_ok:
                failed.append("class")
            error(f"Identity clone incomplete: MAC spoofed but {', '.join(failed)} failed — IVI may reject connection")
            return {"success": False, "mac_spoofed": True,
                    "name_set": bool(name_ok), "class_set": bool(class_ok),
                    "original_mac": original, "target_mac": target_mac,
                    "target_name": target_name, "device_class": device_class,
                    "hci": hci, "error": f"{', '.join(failed)} failed"}
    except Exception as e:
        error(f"Identity clone partial failure: {e}")
        return {"success": False, "mac_spoofed": True, "name_set": False, "class_set": False,
                "original_mac": original, "target_mac": target_mac,
                "target_name": target_name, "device_class": device_class,
                "hci": hci, "error": str(e)}
