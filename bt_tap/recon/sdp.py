"""SDP (Service Discovery Protocol) enumeration."""

import re

from bt_tap.utils.bt_helpers import run_cmd, PROFILE_UUIDS
from bt_tap.utils.output import info, success, error, warning


def browse_services(address: str) -> list[dict]:
    """Browse all SDP services on a remote device.

    This reveals which Bluetooth profiles the IVI/phone supports:
    PBAP, MAP, HFP, A2DP, AVRCP, OPP, SPP, etc.
    """
    info(f"Browsing SDP services on {address}...")
    result = run_cmd(["sdptool", "browse", address], timeout=30)

    if result.returncode != 0:
        error(f"SDP browse failed: {result.stderr.strip()}")
        return []

    return parse_sdp_output(result.stdout)


def parse_sdp_output(output: str) -> list[dict]:
    """Parse sdptool browse output into structured service records.

    sdptool outputs protocol info across multiple lines, e.g.:
        Protocol Descriptor List:
          "L2CAP" (0x0100)
          "RFCOMM" (0x0003)
            Channel: 3
    We track which protocol was last seen to associate Channel/PSM lines.
    """
    services = []
    current = None
    last_protocol = None  # Track last seen protocol for multi-line parsing

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Service Name:"):
            if current:
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
            last_protocol = None

        elif line.startswith("Service RecHandle:"):
            if current is None:
                current = {"name": "Unknown"}
            current["handle"] = line.split(":", 1)[1].strip()
            last_protocol = None

        elif line.startswith("Service Class ID List:"):
            last_protocol = None

        elif line.startswith('"') and current:
            # UUID line like: "Headset Audio Gateway" (0x1112)
            m = re.match(r'"(.+?)"\s*\((0x[0-9A-Fa-f]+)\)', line)
            if m:
                uuid_name = m.group(1)
                uuid_hex = m.group(2).lower()
                current.setdefault("class_ids", []).append(uuid_name)
                current["profile"] = PROFILE_UUIDS.get(uuid_hex, uuid_name)

                # Track protocol context for channel/PSM on following lines
                if "RFCOMM" in uuid_name:
                    last_protocol = "RFCOMM"
                elif "L2CAP" in uuid_name:
                    last_protocol = "L2CAP"

        elif "Protocol Descriptor List:" in line:
            last_protocol = None

        elif "RFCOMM" in line and current:
            last_protocol = "RFCOMM"
            # Channel may be on the same line (some sdptool versions)
            m = re.search(r"Channel:\s*(\d+)", line)
            if m:
                current["protocol"] = "RFCOMM"
                current["channel"] = int(m.group(1))

        elif "L2CAP" in line and current:
            last_protocol = "L2CAP"
            # PSM may be on the same line
            m = re.search(r"PSM:\s*(\S+)", line)
            if m:
                current["protocol"] = "L2CAP"
                current["channel"] = m.group(1)

        elif line.startswith("Channel:") and current and last_protocol == "RFCOMM":
            # Channel on its own line after "RFCOMM" line
            m = re.search(r"Channel:\s*(\d+)", line)
            if m:
                current["protocol"] = "RFCOMM"
                current["channel"] = int(m.group(1))

        elif line.startswith("PSM:") and current and last_protocol == "L2CAP":
            # PSM on its own line after "L2CAP" line
            m = re.search(r"PSM:\s*(\S+)", line)
            if m:
                current["protocol"] = "L2CAP"
                current["channel"] = m.group(1)

        elif "OBEX" in line and current:
            current.setdefault("protocols", []).append("OBEX")

        elif "GOEP" in line and current:
            current.setdefault("protocols", []).append("GOEP")

        elif "Profile Descriptor List:" in line:
            last_protocol = None

        elif current and re.match(r'".*?"\s*\(0x[0-9A-Fa-f]+\)', line):
            m = re.match(r'"(.+?)"\s*\((0x[0-9A-Fa-f]+)\)', line)
            if m:
                uuid_hex = m.group(2).lower()
                profile_name = PROFILE_UUIDS.get(uuid_hex, m.group(1))
                current["profile"] = profile_name

    if current:
        services.append(current)

    success(f"Found {len(services)} SDP service(s)")
    return services


def find_service_channel(address: str, profile_keyword: str) -> int | None:
    """Find the RFCOMM channel for a specific service by keyword.

    Examples: find_service_channel(addr, "PBAP")
              find_service_channel(addr, "Hands-Free")
              find_service_channel(addr, "MAP")
    """
    services = browse_services(address)
    for svc in services:
        name = svc.get("name", "").lower()
        profile = svc.get("profile", "").lower()
        if (profile_keyword.lower() in name or
                profile_keyword.lower() in profile):
            channel = svc.get("channel")
            if channel and svc.get("protocol") == "RFCOMM":
                info(f"Found {profile_keyword}: channel {channel} ({svc.get('name')})")
                return int(channel)
    warning(f"No RFCOMM channel found for '{profile_keyword}'")
    return None


def check_ssp(address: str) -> bool | None:
    """Check if a device supports Secure Simple Pairing via SDP records."""
    result = run_cmd(["sdptool", "browse", address], timeout=30)
    if result.returncode != 0:
        return None
    output = result.stdout
    if "Simple Pairing" in output or "Secure Simple Pairing" in output:
        return True
    return False


def get_raw_sdp(address: str) -> str:
    """Get raw SDP output for analysis."""
    result = run_cmd(["sdptool", "browse", address], timeout=30)
    return result.stdout if result.returncode == 0 else ""
