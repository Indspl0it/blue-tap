"""HCI Bluetooth adapter management and capability detection."""

import logging
import os
import re

from blue_tap.utils.bt_helpers import run_cmd, get_hci_adapters
from blue_tap.utils.output import info, success, error, warning

logger = logging.getLogger(__name__)


# Module-level cache for the resolved active HCI. Populated on first call and
# reused for the lifetime of the process so every module sees the same adapter
# the startup DarkFirmware probe chose. Cleared by ``reset_active_hci_cache()``
# when hardware state changes (adapter list refreshed, hot-plug).
_ACTIVE_HCI_CACHE: str | None = None


def resolve_active_hci(explicit: str | None = None) -> str:
    """Return the HCI adapter modules should use by default.

    Resolution order:
      1. ``explicit`` argument (caller passed one — always wins).
      2. ``BT_TAP_DARKFIRMWARE_HCI`` env var (set by ``_init_darkfirmware_hooks``
         at CLI startup so every subsequent module inherits the dongle HCI).
      3. ``DarkFirmwareManager.find_rtl8761b_hci()`` — USB VID:PID probe for the
         RTL8761B dongle (matches what startup does).
      4. First UP adapter reported by ``hciconfig`` — graceful fallback when no
         Realtek dongle is present (e.g. during non-DarkFirmware smoke tests).
      5. ``"hci0"`` — last-resort literal so callers always get a string.

    Result is cached for the life of the process after the first successful
    hardware probe so repeated calls don't re-run ``lsusb``/``hciconfig``.
    """
    global _ACTIVE_HCI_CACHE

    if explicit:
        return explicit

    if _ACTIVE_HCI_CACHE is not None:
        return _ACTIVE_HCI_CACHE

    env_hci = os.environ.get("BT_TAP_DARKFIRMWARE_HCI")
    if env_hci:
        _ACTIVE_HCI_CACHE = env_hci
        logger.debug("Active HCI resolved from env", extra={"hci": env_hci})
        return env_hci

    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        rtl_hci = DarkFirmwareManager().find_rtl8761b_hci()
        if rtl_hci:
            _ACTIVE_HCI_CACHE = rtl_hci
            logger.debug("Active HCI resolved from RTL8761B probe", extra={"hci": rtl_hci})
            return rtl_hci
    except Exception as exc:
        logger.debug("RTL8761B probe failed during resolve_active_hci: %s", exc)

    try:
        for adapter in get_hci_adapters() or []:
            if adapter.get("status") == "UP":
                name = adapter["name"]
                _ACTIVE_HCI_CACHE = name
                logger.debug("Active HCI resolved from first UP adapter", extra={"hci": name})
                return name
    except Exception as exc:
        logger.debug("hciconfig probe failed during resolve_active_hci: %s", exc)

    logger.warning("No active HCI could be resolved — defaulting to hci0")
    return "hci0"


def reset_active_hci_cache() -> None:
    """Clear the cached active HCI.

    Call when adapters are added/removed (hot-plug, firmware reload, test setup)
    so the next ``resolve_active_hci()`` re-probes the hardware.
    """
    global _ACTIVE_HCI_CACHE
    _ACTIVE_HCI_CACHE = None


def is_darkfirmware_active(hci: str | None = None) -> bool:
    """Return True if DarkFirmware is currently loaded on ``hci``.

    When ``hci`` is None, resolves via ``resolve_active_hci()`` so callers that
    just want "is DarkFirmware up anywhere" don't need to know the adapter.
    """
    target_hci = hci or resolve_active_hci()
    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        return DarkFirmwareManager().is_darkfirmware_loaded(target_hci)
    except Exception as exc:
        logger.debug("DarkFirmware probe failed on %s: %s", target_hci, exc)
        return False


def _adapter_exists(hci: str) -> bool:
    """Check if an HCI adapter exists on the system."""
    result = run_cmd(["hciconfig", hci])
    if result.returncode != 0 or "No such device" in result.stderr:
        error(f"Adapter {hci} not found. Run 'blue-tap adapter list' to see available adapters.")
        return False
    return True


def list_adapters() -> list[dict]:
    """List all HCI adapters with extended info (chipset, features, BT version)."""
    adapters = get_hci_adapters()
    if not adapters:
        error("No HCI adapters found. Ensure Bluetooth hardware is connected.")
        return adapters

    # Enrich each adapter with extended info
    for adapter in adapters:
        hci = adapter["name"]
        ext = get_adapter_info(hci)
        adapter.update(ext)

    return adapters


def get_adapter_info(hci: str) -> dict:
    """Get extended adapter information: chipset, features, BT version, capabilities.

    Reads from hciconfig -a, btmgmt info, and /sys/class/bluetooth/ to build
    a complete picture of what this adapter can do.
    """
    ext = {
        "chipset": "",
        "manufacturer": "",
        "bt_version": "",
        "firmware": "",
        "features": [],
        "capabilities": {
            "le": False,
            "bredr": False,
            "ssp": False,
            "sc": False,          # Secure Connections
            "dual_mode": False,   # Simultaneous LE + BR/EDR
            "address_change": None,  # None=unknown, True/False=tested
        },
        "power_class": "",
    }

    # --- hciconfig -a for detailed adapter info ---
    result = run_cmd(["hciconfig", "-a", hci])
    if result.returncode != 0:
        return ext

    output = result.stdout

    # Parse manufacturer
    m = re.search(r"Manufacturer:\s*(.+)", output)
    if m:
        ext["manufacturer"] = m.group(1).strip()

    # Parse HCI/LMP version
    m = re.search(r"HCI Version:\s*(.+)", output)
    if m:
        ext["bt_version"] = m.group(1).strip()

    # Parse features from hciconfig -a
    feature_flags = output.lower()
    if "<le>" in feature_flags:
        ext["capabilities"]["le"] = True
        ext["features"].append("LE")
    if "<bredr>" in feature_flags or "br/edr" in feature_flags:
        ext["capabilities"]["bredr"] = True
        ext["features"].append("BR/EDR")
    if "<ssp>" in feature_flags:
        ext["capabilities"]["ssp"] = True
        ext["features"].append("SSP")
    if "<sc>" in feature_flags or "secure conn" in feature_flags:
        ext["capabilities"]["sc"] = True
        ext["features"].append("SC")
    if ext["capabilities"]["le"] and ext["capabilities"]["bredr"]:
        ext["capabilities"]["dual_mode"] = True
        ext["features"].append("Dual-Mode")
    if "<inquiry>" in feature_flags:
        ext["features"].append("Inquiry")
    if "<sniff>" in feature_flags:
        ext["features"].append("Sniff")

    # --- Chipset detection from /sys/class/bluetooth ---
    ext["chipset"] = _detect_chipset(hci, hciconfig_output=output)

    # Infer address change capability from chipset
    chipset_lower = ext["chipset"].lower()
    manufacturer_lower = ext["manufacturer"].lower()
    if any(kw in chipset_lower or kw in manufacturer_lower
           for kw in ("csr", "cambridge")):
        ext["capabilities"]["address_change"] = True
    elif any(kw in chipset_lower or kw in manufacturer_lower
             for kw in ("intel",)):
        ext["capabilities"]["address_change"] = False
    # Broadcom/Cypress: usually works with bdaddr
    elif any(kw in chipset_lower or kw in manufacturer_lower
             for kw in ("broadcom", "cypress", "bcm", "cyw")):
        ext["capabilities"]["address_change"] = True
    # Realtek RTL8761B: address_change = True (via firmware patching with DarkFirmware)
    elif any(kw in chipset_lower or kw in manufacturer_lower
             for kw in ("realtek", "rtl8761", "rtl87")):
        ext["capabilities"]["address_change"] = True

    # Check for DarkFirmware enhanced capabilities on Realtek adapters
    if ext["capabilities"].get("address_change") and any(
        kw in chipset_lower or kw in manufacturer_lower
        for kw in ("realtek", "rtl8761", "rtl87")
    ):
        try:
            from blue_tap.hardware.firmware import DarkFirmwareManager
            fw = DarkFirmwareManager()
            if fw.is_darkfirmware_loaded(hci):
                ext["capabilities"]["lmp_injection"] = True
                ext["capabilities"]["lmp_monitoring"] = True
                ext["capabilities"]["memory_rw"] = True
                if "DarkFirmware" not in ext.get("features", []):
                    ext.setdefault("features", []).append("DarkFirmware")
        except Exception as exc:
            logger.warning(
                "DarkFirmware detection skipped: %s: %s",
                type(exc).__name__, exc,
                extra={"hci": hci},
            )

    # --- btmgmt info for management-level details ---
    idx = hci.replace("hci", "")
    mgmt = run_cmd(["btmgmt", "--index", idx, "info"])
    if mgmt.returncode == 0:
        mgmt_out = mgmt.stdout.lower()
        # Parse supported settings
        settings_m = re.search(r"supported settings:\s*(.+)", mgmt_out)
        if settings_m:
            settings = settings_m.group(1)
            if "secure-conn" in settings and "SC" not in ext["features"]:
                ext["capabilities"]["sc"] = True
                ext["features"].append("SC")
            if "static-addr" in settings and "Static-Addr" not in ext["features"]:
                ext["features"].append("Static-Addr")
            if "debug-keys" in settings:
                ext["features"].append("Debug-Keys")
            if "privacy" in settings:
                ext["features"].append("Privacy")
            if "wide-band-speech" in settings:
                ext["features"].append("WBS")

    return ext


def _detect_chipset(hci: str, hciconfig_output: str = "") -> str:
    """Detect adapter chipset from /sys/class/bluetooth and USB info.

    Args:
        hci: HCI adapter name (e.g., "<hciX>")
        hciconfig_output: Pre-fetched hciconfig -a output to avoid redundant call
    """
    sys_path = f"/sys/class/bluetooth/{hci}"

    # Try reading device info from sysfs
    if os.path.exists(sys_path):
        # USB device path
        device_path = os.path.join(sys_path, "device")
        if os.path.islink(device_path):
            real_path = os.path.realpath(device_path)
            # Try to read USB product string
            for parent in [real_path, os.path.dirname(real_path)]:
                product_file = os.path.join(parent, "product")
                if os.path.exists(product_file):
                    try:
                        with open(product_file) as f:
                            return f.read().strip()
                    except OSError:
                        pass
                # Try modalias for vendor:product identification
                modalias_file = os.path.join(parent, "modalias")
                if os.path.exists(modalias_file):
                    try:
                        with open(modalias_file) as f:
                            modalias = f.read().strip()
                        # Parse USB modalias: usb:vXXXXpXXXX...
                        um = re.match(r"usb:v([0-9A-F]{4})p([0-9A-F]{4})", modalias)
                        if um:
                            vid, pid = um.group(1), um.group(2)
                            return _lookup_usb_chipset(vid, pid)
                    except OSError:
                        pass

    # Fallback: use pre-fetched hciconfig output or run fresh
    output = hciconfig_output
    if not output:
        result = run_cmd(["hciconfig", "-a", hci])
        if result.returncode == 0:
            output = result.stdout

    if output:
        mfr_m = re.search(r"Manufacturer:\s*(.+)", output)
        if mfr_m:
            return mfr_m.group(1).strip()

    return "Unknown"


# Common USB Bluetooth chipset vendor:product IDs
_USB_CHIPSETS = {
    ("0A12", "0001"): "CSR 8510 A10",
    ("8087", "0A2A"): "Intel Wireless 7265",
    ("8087", "0A2B"): "Intel Wireless 8265/8275",
    ("8087", "0AAA"): "Intel Wireless 9260/9560",
    ("8087", "0025"): "Intel AX201",
    ("8087", "0026"): "Intel AX201",
    ("8087", "0029"): "Intel AX200",
    ("8087", "0032"): "Intel AX210",
    ("8087", "0033"): "Intel AX211",
    ("0CF3", "3004"): "Qualcomm Atheros AR3012",
    ("0CF3", "E300"): "Qualcomm Atheros QCA61x4",
    ("0489", "E0A2"): "Broadcom BCM20702A0",
    ("0A5C", "21E8"): "Broadcom BCM20702A0",
    ("0BDA", "B00A"): "Realtek RTL8821C",
    ("0BDA", "8771"): "Realtek RTL8761B",
    ("0BDA", "C123"): "Realtek RTL8723DE",
    ("2357", "0604"): "TP-Link UB500 (RTL8761B)",
}


def _lookup_usb_chipset(vid: str, pid: str) -> str:
    """Look up USB vendor:product to get chipset name."""
    key = (vid.upper(), pid.upper())
    return _USB_CHIPSETS.get(key, f"USB {vid}:{pid}")


def recommend_adapter_roles(adapters: list[dict] | None = None) -> dict:
    """Recommend which adapter to use for scanning vs spoofing.

    Returns {"scan": "<hciX>", "spoof": "hci1", "notes": [...]}
    When only one adapter is available, returns it for both roles with warnings.
    """
    if adapters is None:
        adapters = list_adapters()
    if not adapters:
        return {"scan": None, "spoof": None, "notes": ["No adapters found"]}

    recommendation = {"scan": None, "spoof": None, "notes": []}

    # Categorize adapters by capability
    spoofable = []
    all_up = [a for a in adapters if a.get("status") == "UP"]

    for a in all_up:
        can_spoof = a.get("capabilities", {}).get("address_change")
        if can_spoof is True:
            spoofable.append(a)

    if len(all_up) == 1:
        adapter = all_up[0]
        recommendation["scan"] = adapter["name"]
        recommendation["spoof"] = adapter["name"]
        can_spoof = adapter.get("capabilities", {}).get("address_change")
        if can_spoof is False:
            recommendation["notes"].append(
                f"{adapter['name']} ({adapter.get('chipset', 'Unknown')}) likely does not support "
                f"MAC spoofing (Intel chipsets typically don't). Consider an external CSR8510 USB adapter. "
                f"'blue-tap spoof mac' will verify by testing each method."
            )
        elif can_spoof is None:
            recommendation["notes"].append(
                f"{adapter['name']}: Run 'blue-tap spoof mac' to test which spoofing methods work."
            )
    elif len(all_up) >= 2:
        if spoofable:
            recommendation["spoof"] = spoofable[0]["name"]
            # Use a different adapter for scanning
            for a in all_up:
                if a["name"] != spoofable[0]["name"]:
                    recommendation["scan"] = a["name"]
                    break
            recommendation["notes"].append(
                f"Recommended: {recommendation['scan']} for scanning, "
                f"{recommendation['spoof']} ({spoofable[0].get('chipset', '')}) for spoofing"
            )
        else:
            recommendation["scan"] = all_up[0]["name"]
            recommendation["spoof"] = all_up[1]["name"]
            recommendation["notes"].append(
                "No confirmed spoofable adapter. Test each with 'blue-tap spoof mac'."
            )

    return recommendation


def _hci_cmd(hci: str, *args: str) -> bool:
    """Run hciconfig command with error handling."""
    result = run_cmd(["sudo", "hciconfig", hci, *args])
    if result.returncode != 0:
        error(f"hciconfig {hci} {' '.join(args)} failed: {result.stderr.strip()}")
        return False
    return True


def adapter_up(hci: str | None = None) -> dict:
    """Bring an adapter up.

    Returns:
        {"success": bool, "hci": str, "operation": str, "error": str|None}
    """
    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "operation": "up", "error": f"Adapter {hci} not found"}
    if _hci_cmd(hci, "up"):
        success(f"{hci} is UP")
        logger.info("Adapter brought up", extra={"hci": hci})
        return {"success": True, "hci": hci, "operation": "up", "error": None}
    return {"success": False, "hci": hci, "operation": "up", "error": f"hciconfig {hci} up failed"}


def adapter_down(hci: str | None = None) -> dict:
    """Bring an adapter down.

    Returns:
        {"success": bool, "hci": str, "operation": str, "error": str|None}
    """
    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "operation": "down", "error": f"Adapter {hci} not found"}
    if _hci_cmd(hci, "down"):
        info(f"{hci} is DOWN")
        logger.info("Adapter brought down", extra={"hci": hci})
        return {"success": True, "hci": hci, "operation": "down", "error": None}
    return {"success": False, "hci": hci, "operation": "down", "error": f"hciconfig {hci} down failed"}


def adapter_reset(hci: str | None = None) -> dict:
    """Reset an adapter.

    Returns:
        {"success": bool, "hci": str, "operation": str, "error": str|None}
    """
    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "operation": "reset", "error": f"Adapter {hci} not found"}
    if _hci_cmd(hci, "reset"):
        info(f"{hci} reset complete")
        logger.info("Adapter reset", extra={"hci": hci})
        return {"success": True, "hci": hci, "operation": "reset", "error": None}
    return {"success": False, "hci": hci, "operation": "reset", "error": f"hciconfig {hci} reset failed"}


def set_device_class(hci: str, device_class: str = "0x5a020c") -> dict:
    """Set the Bluetooth device class.

    Common classes for IVI impersonation:
      0x200404 - Audio/Video: Car Audio
      0x200408 - Audio/Video: Portable Audio
      0x5a020c - Phone (smartphone)
      0x7a020c - Smart Phone

    Args:
        hci: HCI adapter name (e.g., "<hciX>")
        device_class: Hex string with or without 0x prefix, range 0x000000-0xFFFFFF

    Raises:
        ValueError: If device_class is not a valid hex string in range 0x000000-0xFFFFFF

    Returns:
        {"success": bool, "hci": str, "device_class": str}
    """
    # Normalise: accept with or without 0x prefix
    normalised = device_class if device_class.lower().startswith("0x") else f"0x{device_class}"
    # Validate hex characters
    hex_body = normalised[2:]
    if not hex_body or not all(c in "0123456789abcdefABCDEF" for c in hex_body):
        raise ValueError(
            f"device_class must be a valid hex string (e.g. 0x5a020c), got: {device_class!r}"
        )
    val = int(normalised, 16)
    if not 0 <= val <= 0xFFFFFF:
        raise ValueError(
            f"device_class must be in range 0x000000-0xFFFFFF, got: {device_class!r} ({val:#x})"
        )

    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "device_class": normalised}
    if _hci_cmd(hci, "class", normalised):
        success(f"{hci} device class set to {normalised}")
        logger.info("Device class set", extra={"hci": hci, "device_class": normalised})
        return {"success": True, "hci": hci, "device_class": normalised}
    return {"success": False, "hci": hci, "device_class": normalised}


def set_device_name(hci: str, name: str) -> dict:
    """Set the Bluetooth device name (useful for impersonation).

    Args:
        hci: HCI adapter name (e.g., "<hciX>")
        name: Device name; must be at most 248 bytes when UTF-8 encoded (Bluetooth spec limit)

    Raises:
        ValueError: If name exceeds 248 bytes when UTF-8 encoded

    Returns:
        {"success": bool, "hci": str, "name": str, "previous_name": str|None}
    """
    name_bytes = name.encode("utf-8", errors="replace")
    if len(name_bytes) > 248:
        raise ValueError(
            f"Device name too long: {len(name_bytes)} bytes (max 248 bytes UTF-8 encoded). "
            f"Received: {name!r}"
        )

    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "name": name, "previous_name": None}

    # Capture previous name before changing
    previous_name: str | None = None
    prev_result = run_cmd(["hciconfig", hci, "name"])
    if prev_result.returncode == 0:
        m = re.search(r"Name:\s*'(.+?)'", prev_result.stdout)
        if m:
            previous_name = m.group(1)

    if _hci_cmd(hci, "name", name):
        success(f"{hci} name set to '{name}'")
        logger.info("Device name set", extra={"hci": hci, "name": name, "previous_name": previous_name})
        return {"success": True, "hci": hci, "name": name, "previous_name": previous_name}
    return {"success": False, "hci": hci, "name": name, "previous_name": previous_name}


def enable_page_scan(hci: str) -> bool:
    """Make device discoverable (page scan) and connectable."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "piscan"):
        success(f"{hci} set to discoverable + connectable")
        return True
    return False


def disable_page_scan(hci: str) -> bool:
    """Make device non-discoverable."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "noscan"):
        info(f"{hci} set to non-discoverable")
        return True
    return False


def enable_ssp(hci: str) -> dict:
    """Enable Secure Simple Pairing on the adapter.

    Returns:
        {"success": bool, "hci": str, "ssp_enabled": bool, "error": str|None}
    """
    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "ssp_enabled": False, "error": f"Adapter {hci} not found"}
    idx = hci.replace("hci", "")
    # Need to power off first to change SSP on some adapters
    power_off = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
    if power_off.returncode != 0:
        warning(f"Failed to power off {hci} before SSP change")
        logger.warning("Power off before SSP enable failed", extra={"hci": hci, "stderr": power_off.stderr.strip()})

    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "on"])

    power_on = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])
    if power_on.returncode != 0:
        error(f"Failed to power on {hci} after SSP change — adapter may be DOWN")
        logger.error("Power on after SSP enable failed — attempting hciconfig up fallback", extra={"hci": hci})
        run_cmd(["sudo", "hciconfig", hci, "up"])

    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 and "not supported" not in combined:
        success(f"SSP enabled on {hci}")
        logger.info("SSP enabled", extra={"hci": hci})
        return {"success": True, "hci": hci, "ssp_enabled": True, "error": None}
    else:
        err_msg = result.stderr.strip() or result.stdout.strip()
        error(f"Failed to enable SSP: {err_msg}")
        logger.error("SSP enable failed", extra={"hci": hci, "detail": err_msg})
        return {"success": False, "hci": hci, "ssp_enabled": False, "error": err_msg}


def disable_ssp(hci: str) -> dict:
    """Disable SSP (force legacy PIN pairing).

    Returns:
        {"success": bool, "hci": str, "ssp_enabled": bool, "error": str|None}
    """
    if not _adapter_exists(hci):
        return {"success": False, "hci": hci, "ssp_enabled": True, "error": f"Adapter {hci} not found"}
    idx = hci.replace("hci", "")
    power_off = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
    if power_off.returncode != 0:
        warning(f"Failed to power off {hci} before SSP change")
        logger.warning("Power off before SSP disable failed", extra={"hci": hci, "stderr": power_off.stderr.strip()})

    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "off"])

    power_on = run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])
    if power_on.returncode != 0:
        error(f"Failed to power on {hci} after SSP change — adapter may be DOWN")
        logger.error("Power on after SSP disable failed — attempting hciconfig up fallback", extra={"hci": hci})
        run_cmd(["sudo", "hciconfig", hci, "up"])

    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 and "not supported" not in combined:
        warning(f"SSP disabled on {hci} - legacy PIN pairing mode")
        logger.info("SSP disabled", extra={"hci": hci})
        return {"success": True, "hci": hci, "ssp_enabled": False, "error": None}
    else:
        err_msg = result.stderr.strip() or result.stdout.strip()
        error(f"Failed to disable SSP: {err_msg}")
        logger.error("SSP disable failed", extra={"hci": hci, "detail": err_msg})
        # SSP state is unknown after failure — report True (unchanged) as
        # the disable command did not succeed.
        return {"success": False, "hci": hci, "ssp_enabled": True, "error": err_msg}  # unchanged: SSP still enabled
