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
    "0x1200": "PnP Information",
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
    """Run a subprocess command with error handling."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
        check=check,
    )


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
