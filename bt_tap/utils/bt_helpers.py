"""Common Bluetooth utility functions."""

import re
import subprocess
import shutil


MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Well-known Bluetooth profile UUIDs
PROFILE_UUIDS = {
    "0x1101": "SPP (Serial Port)",
    "0x1103": "DUN (Dialup Networking)",
    "0x1105": "OPP (Object Push)",
    "0x1106": "FTP (File Transfer)",
    "0x1108": "HSP (Headset)",
    "0x110a": "A2DP Source",
    "0x110b": "A2DP Sink",
    "0x110c": "AVRCP Target",
    "0x110e": "AVRCP Controller",
    "0x110f": "AVRCP",
    "0x1112": "HSP AG",
    "0x111e": "HFP (Hands-Free)",
    "0x111f": "HFP AG (Audio Gateway)",
    "0x1124": "HID",
    "0x112d": "SIM Access",
    "0x112e": "PBAP PCE (Client)",
    "0x112f": "PBAP PSE (Server)",
    "0x1130": "PBAP",
    "0x1132": "MAP MAS (Server)",
    "0x1133": "MAP MNS (Notification)",
    "0x1134": "MAP",
    "0x1116": "NAP (Network Access Point)",
    "0x1117": "GN (Group Ad-hoc Network)",
    "0x1200": "PnP Information",
    "0x1400": "HDP (Health Device Profile)",
    "0x131e": "CTN (Calendar, Task, Notes)",
}

# PBAP repositories
PBAP_REPOS = {
    "telecom/pb.vcf": "Main Phonebook",
    "telecom/ich.vcf": "Incoming Call History",
    "telecom/och.vcf": "Outgoing Call History",
    "telecom/mch.vcf": "Missed Call History",
    "telecom/cch.vcf": "Combined Call History",
    "telecom/spd.vcf": "Speed Dial",
    "telecom/fav.vcf": "Favorites",
    "SIM1/telecom/pb.vcf": "SIM Phonebook",
    "SIM1/telecom/ich.vcf": "SIM Incoming Calls",
    "SIM1/telecom/och.vcf": "SIM Outgoing Calls",
    "SIM1/telecom/mch.vcf": "SIM Missed Calls",
}


def validate_mac(address: str) -> bool:
    return bool(MAC_RE.match(address))


def normalize_mac(address: str) -> str:
    """Normalize MAC address to uppercase colon-separated format."""
    clean = address.replace("-", ":").upper()
    if validate_mac(clean):
        return clean
    raise ValueError(f"Invalid MAC address: {address}")


def check_tool(name: str) -> bool:
    """Check if a system tool is available."""
    return shutil.which(name) is not None


def check_root() -> bool:
    """Check if running as root."""
    import os
    return os.geteuid() == 0


def run_cmd(cmd: list[str], timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess command with error handling.

    Returns a CompletedProcess even on timeout (with returncode=-1
    and stderr containing the timeout message).
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            check=check,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1,
            stdout="", stderr=f"Command timed out after {timeout}s",
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            cmd, returncode=-1,
            stdout="", stderr=f"Command not found: {cmd[0]}",
        )


def lookup_oui(mac: str) -> str:
    """Look up manufacturer from MAC address OUI (first 3 octets).

    Common automotive and phone OUIs for quick identification.
    """
    prefix = mac.upper().replace("-", ":")[:8]
    return _OUI_DATABASE.get(prefix, "")


# Common OUI prefixes for automotive and mobile devices
_OUI_DATABASE = {
    # Automotive IVI / Infotainment
    "00:17:53": "Harman International",
    "00:26:7E": "Parrot",
    "00:1E:DC": "Harman/Becker",
    "00:1A:7D": "Cyber-Q (Continental)",
    "FC:F1:36": "Samsung Harman",
    "A4:77:33": "Google (Android Auto)",
    "00:07:04": "Alpine Electronics",
    "00:1D:BA": "Sony",
    "00:13:7B": "Movon (Hyundai Mobis)",
    "00:25:56": "Hon Hai (Foxconn/IVI supplier)",
    # Phone manufacturers
    "DC:A6:32": "Apple",
    "F0:DB:E2": "Apple",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "8C:85:90": "Samsung",
    "78:BD:BC": "Samsung",
    "50:55:27": "Samsung",
    "94:65:2D": "OnePlus",
    "DC:6D:CD": "Huawei",
    "30:07:4D": "Xiaomi",
    "58:CB:52": "Google (Pixel)",
    "44:07:0B": "Google (Pixel)",
    # Bluetooth chipset vendors
    "00:02:72": "CSR (Cambridge Silicon Radio)",
    "00:15:83": "Intel Corporate",
    "00:1B:DC": "Broadcom",
    "00:25:00": "Qualcomm",
    "34:C9:F0": "Realtek",
}


def get_hci_adapters() -> list[dict]:
    """List available HCI Bluetooth adapters."""
    result = run_cmd(["hciconfig"])
    if result.returncode != 0:
        return []
    adapters = []
    current = None
    for line in result.stdout.splitlines():
        m = re.match(r"^(hci\d+):\s+Type:\s+(\S+)\s+Bus:\s+(\S+)", line)
        if m:
            current = {
                "name": m.group(1),
                "type": m.group(2),
                "bus": m.group(3),
                "address": "",
                "status": "",
            }
            adapters.append(current)
        elif current:
            addr_m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", line)
            if addr_m:
                current["address"] = addr_m.group(1)
            if "UP RUNNING" in line:
                current["status"] = "UP"
            elif "DOWN" in line:
                current["status"] = "DOWN"
    return adapters


def get_adapter_address(hci: str = "hci0") -> str | None:
    """Get the BD address of an adapter."""
    result = run_cmd(["hciconfig", hci])
    if result.returncode != 0:
        return None
    m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", result.stdout)
    return m.group(1) if m else None


# ============================================================================
# Adapter State Guard
# ============================================================================

class AdapterNotReady(Exception):
    """Raised when the adapter cannot be brought to a ready state."""
    pass


def get_adapter_state(hci: str = "hci0") -> dict:
    """Get current adapter state: exists, up/down, scanning, connected devices.

    Returns:
        {"exists": bool, "up": bool, "scanning": bool,
         "address": str, "raw_status": str}
    """
    state = {
        "exists": False,
        "up": False,
        "scanning": False,
        "address": "",
        "raw_status": "",
    }

    result = run_cmd(["hciconfig", hci])
    if result.returncode != 0 or "No such device" in result.stderr:
        return state

    state["exists"] = True
    output = result.stdout

    addr_m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", output)
    if addr_m:
        state["address"] = addr_m.group(1)

    if "UP RUNNING" in output:
        state["up"] = True
        state["raw_status"] = "UP RUNNING"
    elif "DOWN" in output:
        state["raw_status"] = "DOWN"
    else:
        # Parse whatever flags are present
        flags_m = re.search(r"<(.+?)>", output)
        state["raw_status"] = flags_m.group(1) if flags_m else "UNKNOWN"

    # Check if adapter is currently scanning (hcitool processes running)
    scan_check = run_cmd(["pgrep", "-af", f"hcitool.*{hci}.*(scan|inq)"], timeout=3)
    if scan_check.returncode == 0 and scan_check.stdout.strip():
        state["scanning"] = True

    return state


def ensure_adapter_ready(hci: str = "hci0", timeout: int = 15,
                          auto_up: bool = True) -> bool:
    """Ensure the BT adapter is present and UP before proceeding.

    This should be called at the start of any operation that needs
    the adapter. It handles common transient states:
      - Adapter DOWN after a reset/spoof → brings it back up
      - Adapter busy scanning → waits for scan to complete
      - Adapter missing → fails immediately with clear error

    Args:
        hci: Adapter name (e.g., "hci0")
        timeout: Max seconds to wait for adapter to become ready
        auto_up: If True, attempt to bring adapter up if it's down

    Returns:
        True if adapter is ready, False if it couldn't be made ready.

    Raises:
        AdapterNotReady: If adapter doesn't exist at all.
    """
    import time
    from bt_tap.utils.output import info, warning, error

    deadline = time.time() + timeout

    while time.time() < deadline:
        state = get_adapter_state(hci)

        if not state["exists"]:
            error(f"Adapter {hci} not found. Check hardware connection.")
            return False

        if state["up"] and not state["scanning"]:
            return True  # Ready to go

        if state["up"] and state["scanning"]:
            remaining = int(deadline - time.time())
            if remaining > 0:
                info(f"Waiting for {hci} scan to complete ({remaining}s remaining)...")
                time.sleep(2)
                continue
            else:
                warning(f"{hci} still scanning after {timeout}s timeout")
                return False

        if not state["up"]:
            if auto_up:
                info(f"{hci} is DOWN, bringing up...")
                up_result = run_cmd(["sudo", "hciconfig", hci, "up"])
                if up_result.returncode == 0:
                    # Give it a moment to initialize
                    time.sleep(1)
                    continue
                else:
                    warning(f"Failed to bring up {hci}: {up_result.stderr.strip()}")
                    # May need a reset first
                    run_cmd(["sudo", "hciconfig", hci, "reset"])
                    time.sleep(2)
                    run_cmd(["sudo", "hciconfig", hci, "up"])
                    time.sleep(1)
                    continue
            else:
                error(f"{hci} is DOWN. Run: bt-tap adapter up {hci}")
                return False

    error(f"Adapter {hci} not ready after {timeout}s")
    return False


def wait_for_adapter(hci: str = "hci0", timeout: int = 30) -> bool:
    """Wait for an adapter to appear (e.g., after USB replug).

    Polls hciconfig until the adapter shows up or timeout expires.
    Useful after MAC spoofing operations that require physical replug.
    """
    import time
    from bt_tap.utils.output import info

    info(f"Waiting for {hci} to appear ({timeout}s)...")
    deadline = time.time() + timeout

    while time.time() < deadline:
        result = run_cmd(["hciconfig", hci])
        if result.returncode == 0 and "No such device" not in result.stderr:
            if "UP RUNNING" in result.stdout:
                return True
            # Exists but not up — try bringing up
            run_cmd(["sudo", "hciconfig", hci, "up"])
            time.sleep(1)
            continue
        time.sleep(2)

    return False
