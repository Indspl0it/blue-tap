"""SDP (Service Discovery Protocol) enumeration."""

import re

from blue_tap.utils.bt_helpers import run_cmd, PROFILE_UUIDS
from blue_tap.utils.output import info, success, error, warning


def browse_services(address: str, hci: str = "hci0",
                    retries: int = 2) -> list[dict]:
    """Browse all SDP services on a remote device.

    This reveals which Bluetooth profiles the IVI/phone supports:
    PBAP, MAP, HFP, A2DP, AVRCP, OPP, SPP, etc.

    Retries on transient failures (connection reset, timeout).
    """
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return []

    info(f"Browsing SDP services on {address}...")

    for attempt in range(retries + 1):
        result = run_cmd(["sdptool", "browse", address], timeout=30)

        if result.returncode == 0:
            return parse_sdp_output(result.stdout)

        stderr = result.stderr.strip().lower()
        # Transient failures worth retrying
        if any(hint in stderr for hint in ("reset", "timeout", "resource temporarily")):
            if attempt < retries:
                import time
                warning(f"SDP browse attempt {attempt + 1} failed, retrying...")
                time.sleep(2)
                continue

        error(f"SDP browse failed: {result.stderr.strip()}")
        return []

    error(f"SDP browse failed after {retries + 1} attempts")
    return []


def parse_sdp_output(output: str) -> list[dict]:
    """Parse sdptool browse output into structured service records.

    Captures: service name, class IDs, protocol (RFCOMM/L2CAP), channel/PSM,
    profile version, provider name, and additional protocol layers (OBEX, GOEP).
    """
    services = []
    current = None
    last_protocol = None

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

        elif line.startswith("Service Description:"):
            if current:
                current["description"] = line.split(":", 1)[1].strip()

        elif line.startswith("Provider Name:"):
            if current:
                current["provider"] = line.split(":", 1)[1].strip()

        elif line.startswith("Service Class ID List:"):
            last_protocol = None

        elif line.startswith("Profile Descriptor List:"):
            last_protocol = None

        elif line.startswith("Protocol Descriptor List:"):
            last_protocol = None

        elif line.startswith('"') and current:
            m = re.match(r'"(.+?)"\s*\((0x[0-9A-Fa-f]+)\)', line)
            if m:
                uuid_name = m.group(1)
                uuid_hex = m.group(2).lower()
                current.setdefault("class_ids", []).append(uuid_name)
                current["profile"] = PROFILE_UUIDS.get(uuid_hex, uuid_name)

                # Track protocol context
                if "RFCOMM" in uuid_name:
                    last_protocol = "RFCOMM"
                elif "L2CAP" in uuid_name:
                    last_protocol = "L2CAP"

        elif line.startswith("Version:") and current:
            version_str = line.split(":", 1)[1].strip()
            # Parse version like 0x0108 -> "1.8", 0x0102 -> "1.2"
            try:
                ver_int = int(version_str, 16)
                major = (ver_int >> 8) & 0xFF
                minor = ver_int & 0xFF
                current["profile_version"] = f"{major}.{minor}"
            except (ValueError, TypeError):
                current["profile_version"] = version_str

        elif "RFCOMM" in line and current:
            last_protocol = "RFCOMM"
            m = re.search(r"Channel:\s*(\d+)", line)
            if m:
                current["protocol"] = "RFCOMM"
                current["channel"] = int(m.group(1))

        elif "L2CAP" in line and current:
            last_protocol = "L2CAP"
            m = re.search(r"PSM:\s*(\S+)", line)
            if m:
                current["protocol"] = "L2CAP"
                try:
                    current["channel"] = int(m.group(1), 0)
                except (ValueError, TypeError):
                    current["channel"] = 0

        elif line.startswith("Channel:") and current and last_protocol == "RFCOMM":
            m = re.search(r"Channel:\s*(\d+)", line)
            if m:
                current["protocol"] = "RFCOMM"
                current["channel"] = int(m.group(1))

        elif line.startswith("PSM:") and current and last_protocol == "L2CAP":
            m = re.search(r"PSM:\s*(\S+)", line)
            if m:
                current["protocol"] = "L2CAP"
                try:
                    current["channel"] = int(m.group(1), 0)
                except (ValueError, TypeError):
                    current["channel"] = 0

        elif "OBEX" in line and current:
            current.setdefault("protocols", []).append("OBEX")

        elif "GOEP" in line and current:
            current.setdefault("protocols", []).append("GOEP")

        # Handle bare attribute lines with hex values (sdptool format variance)
        elif line.startswith("Attribute") and current:
            # e.g., "Attribute (0x0311) - uint16: 0x0001"
            pass  # preserve current service, don't break state

    if current:
        services.append(current)

    success(f"Found {len(services)} SDP service(s)")
    return services


def find_service_channel(address: str, profile_keyword: str,
                         services: list[dict] | None = None) -> int | None:
    """Find the RFCOMM channel for a specific service by keyword.

    Args:
        address: Target device address
        profile_keyword: Keyword to match (e.g., "PBAP", "Hands-Free", "MAP")
        services: Pre-fetched service list to avoid redundant SDP browses.
                  If None, will browse fresh.

    Examples:
        services = browse_services(addr)
        pbap_ch = find_service_channel(addr, "PBAP", services)
        map_ch = find_service_channel(addr, "MAP", services)
        hfp_ch = find_service_channel(addr, "Hands-Free", services)
    """
    if services is None:
        services = browse_services(address)

    keyword_lower = profile_keyword.lower()
    for svc in services:
        name = svc.get("name", "").lower()
        profile = svc.get("profile", "").lower()
        class_ids = " ".join(svc.get("class_ids", [])).lower()
        description = svc.get("description", "").lower()
        if keyword_lower in name or keyword_lower in profile or keyword_lower in class_ids or keyword_lower in description:
            channel = svc.get("channel")
            if channel and svc.get("protocol") == "RFCOMM":
                info(f"Found {profile_keyword}: channel {channel} ({svc.get('name')})")
                return int(channel)

    warning(f"No RFCOMM channel found for '{profile_keyword}'")
    return None


def search_service(address: str, uuid: str) -> list[dict]:
    """Search for a specific service by UUID using sdptool search.

    Faster than browse+filter when you know the UUID.
    Common UUIDs: 0x1130 (PBAP), 0x1134 (MAP), 0x111f (HFP AG),
                  0x110b (A2DP Sink), 0x110e (AVRCP CT)
    """
    info(f"Searching for UUID {uuid} on {address}...")
    result = run_cmd(["sdptool", "search", "--bdaddr", address, uuid], timeout=15)
    if result.returncode != 0:
        return []
    return parse_sdp_output(result.stdout)


def search_services_batch(address: str, uuids: list[str]) -> dict[str, list[dict]]:
    """Search for multiple service UUIDs in a single pass.

    More efficient than calling search_service() repeatedly when you need
    to check several profiles.

    Returns:
        Dict mapping UUID to list of matching service records.
    """
    results = {}
    # First try a full browse (1 connection, all services)
    all_services = browse_services(address)
    if all_services:
        for uuid in uuids:
            uuid_lower = uuid.lower()
            matched = [
                s for s in all_services
                if uuid_lower in " ".join(s.get("class_ids", [])).lower()
                or uuid_lower in s.get("profile", "").lower()
            ]
            results[uuid] = matched
    else:
        # Fallback: individual searches
        for uuid in uuids:
            results[uuid] = search_service(address, uuid)
    return results


def check_ssp(address: str, hci: str = "hci0") -> bool | None:
    """Check if a device supports Secure Simple Pairing via LMP features.

    SSP is a link-layer feature advertised in LMP feature pages,
    NOT in SDP records. We use hcitool info to read the LMP features.
    """
    result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=10)
    if result.returncode != 0:
        # hcitool info requires an active connection on some systems.
        # Fall back to checking via btmgmt.
        warning("hcitool info failed — device may not be in range or connectable")
        return None

    output = result.stdout
    # hcitool info shows LMP features which include SSP
    if "Secure Simple Pairing" in output or "SSP" in output:
        return True

    # Check features bitmask — SSP is bit 51 (byte 6, bit 3) in LMP features
    features_m = re.search(r"Features:\s*(0x[0-9a-f\s]+)", output, re.IGNORECASE)
    if features_m:
        features_hex = features_m.group(1).replace(" ", "").replace("0x", "")
        try:
            # Byte 6, bit 3 = SSP Host Support
            if len(features_hex) >= 14:
                byte6 = int(features_hex[12:14], 16)
                if byte6 & 0x08:
                    return True
        except (ValueError, IndexError):
            pass

    return False


def get_raw_sdp(address: str) -> str:
    """Get raw SDP output for analysis."""
    result = run_cmd(["sdptool", "browse", address], timeout=30)
    return result.stdout if result.returncode == 0 else ""


def get_device_bt_version(address: str, hci: str = "hci0") -> dict:
    """Get remote device's Bluetooth/LMP version and features.

    Returns:
        {"lmp_version": "5.2", "lmp_subversion": "0x1234",
         "manufacturer": "Broadcom", "features": [...]}
    """
    result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=10)
    version_info = {
        "lmp_version": None,
        "lmp_subversion": None,
        "manufacturer": None,
        "features_raw": None,
    }

    if result.returncode != 0:
        return version_info

    for line in result.stdout.splitlines():
        if "LMP Version:" in line:
            m = re.search(r"LMP Version:\s*(.+)", line)
            if m:
                version_info["lmp_version"] = m.group(1).strip()
        elif "LMP Subversion:" in line:
            m = re.search(r"LMP Subversion:\s*(\S+)", line)
            if m:
                version_info["lmp_subversion"] = m.group(1).strip()
        elif "Manufacturer:" in line:
            version_info["manufacturer"] = line.split(":", 1)[1].strip()
        elif "Features:" in line:
            version_info["features_raw"] = line.split(":", 1)[1].strip()

    return version_info
