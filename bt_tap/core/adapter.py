"""HCI Bluetooth adapter management and capability detection."""

import os
import re

from bt_tap.utils.bt_helpers import run_cmd, get_hci_adapters
from bt_tap.utils.output import info, success, error, warning


def _adapter_exists(hci: str) -> bool:
    """Check if an HCI adapter exists on the system."""
    result = run_cmd(["hciconfig", hci])
    if result.returncode != 0 or "No such device" in result.stderr:
        error(f"Adapter {hci} not found. Run 'bt-tap adapter list' to see available adapters.")
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
        hci: HCI adapter name (e.g., "hci0")
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

    Returns {"scan": "hci0", "spoof": "hci1", "notes": [...]}
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
                f"'bt-tap spoof mac' will verify by testing each method."
            )
        elif can_spoof is None:
            recommendation["notes"].append(
                f"{adapter['name']}: Run 'bt-tap spoof mac' to test which spoofing methods work."
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
                "No confirmed spoofable adapter. Test each with 'bt-tap spoof mac'."
            )

    return recommendation


def _hci_cmd(hci: str, *args: str) -> bool:
    """Run hciconfig command with error handling."""
    result = run_cmd(["sudo", "hciconfig", hci, *args])
    if result.returncode != 0:
        error(f"hciconfig {hci} {' '.join(args)} failed: {result.stderr.strip()}")
        return False
    return True


def adapter_up(hci: str = "hci0") -> bool:
    """Bring an adapter up."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "up"):
        success(f"{hci} is UP")
        return True
    return False


def adapter_down(hci: str = "hci0") -> bool:
    """Bring an adapter down."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "down"):
        info(f"{hci} is DOWN")
        return True
    return False


def adapter_reset(hci: str = "hci0") -> bool:
    """Reset an adapter."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "reset"):
        info(f"{hci} reset complete")
        return True
    return False


def set_device_class(hci: str, device_class: str = "0x5a020c") -> bool:
    """Set the Bluetooth device class.

    Common classes for IVI impersonation:
      0x200404 - Audio/Video: Car Audio
      0x200408 - Audio/Video: Portable Audio
      0x5a020c - Phone (smartphone)
      0x7a020c - Smart Phone
    """
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "class", device_class):
        success(f"{hci} device class set to {device_class}")
        return True
    return False


def set_device_name(hci: str, name: str) -> bool:
    """Set the Bluetooth device name (useful for impersonation)."""
    if not _adapter_exists(hci):
        return False
    if _hci_cmd(hci, "name", name):
        success(f"{hci} name set to '{name}'")
        return True
    return False


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


def enable_ssp(hci: str) -> bool:
    """Enable Secure Simple Pairing on the adapter."""
    if not _adapter_exists(hci):
        return False
    idx = hci.replace("hci", "")
    # Need to power off first to change SSP on some adapters
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "on"])
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])

    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 and "not supported" not in combined:
        success(f"SSP enabled on {hci}")
        return True
    else:
        error(f"Failed to enable SSP: {result.stderr.strip() or result.stdout.strip()}")
        return False


def disable_ssp(hci: str) -> bool:
    """Disable SSP (force legacy PIN pairing)."""
    if not _adapter_exists(hci):
        return False
    idx = hci.replace("hci", "")
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
    result = run_cmd(["sudo", "btmgmt", "--index", idx, "ssp", "off"])
    run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])

    combined = (result.stdout + result.stderr).lower()
    if result.returncode == 0 and "not supported" not in combined:
        warning(f"SSP disabled on {hci} - legacy PIN pairing mode")
        return True
    else:
        error(f"Failed to disable SSP: {result.stderr.strip() or result.stdout.strip()}")
        return False
