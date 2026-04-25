"""SDP (Service Discovery Protocol) enumeration.

This file owns two things:

1. **Module-level helpers** (``browse_services``, ``browse_services_detailed``,
   ``find_service_channel``, ``check_ssp``, ``get_raw_sdp``,
   ``get_device_bt_version``) used by exploitation/assessment/fuzzing/
   post_exploitation code paths throughout the project. These MUST NOT be
   removed — they have many external callers.
2. **The native ``SdpScannerModule``** — the registered Module subclass for
   ``reconnaissance.sdp``. It calls the helpers above directly (no wrapper
   layer, no cross-file imports).
"""

import logging
import re
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptInt, OptString
from blue_tap.framework.registry import ModuleFamily
from blue_tap.utils.bt_helpers import run_cmd, PROFILE_UUIDS
from blue_tap.utils.output import info, success, error, warning

logger = logging.getLogger(__name__)


def browse_services(address: str, hci: str | None = None,
                    retries: int = 2, timeout: float = 30.0) -> list[dict]:
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    detailed = browse_services_detailed(address, hci=hci, retries=retries, timeout=timeout)
    return detailed.get("services", [])


def browse_services_detailed(address: str, hci: str | None = None,
                             retries: int = 2,
                             timeout: float = 30.0) -> dict[str, Any]:
    """Browse all SDP services on a remote device.

    This reveals which Bluetooth profiles the IVI/phone supports:
    PBAP, MAP, HFP, A2DP, AVRCP, OPP, SPP, etc.

    Retries on transient failures (connection reset, timeout). ``timeout`` is
    the per-attempt ceiling (seconds) for the underlying ``sdptool browse``
    call — callers that need to bound a single attempt use this rather than
    the retry budget.
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return {
            "services": [],
            "service_count": 0,
            "rfcomm_channels": [],
            "l2cap_psms": [],
            "raw_output": "",
            "status": "adapter_not_ready",
            "partially_parsed": False,
            "vendor_specific_present": False,
        }

    info(f"Browsing SDP services on {address}...")

    for attempt in range(retries + 1):
        cmd = ["sdptool"]
        if hci:
            cmd += ["-i", hci]
        cmd += ["browse", address]
        result = run_cmd(cmd, timeout=timeout)

        if result.returncode == 0:
            services = parse_sdp_output(result.stdout)
            return _build_sdp_summary(result.stdout, services, status="completed")

        stderr = result.stderr.strip().lower()
        # Transient failures worth retrying
        if any(hint in stderr for hint in ("reset", "timeout", "resource temporarily")):
            if attempt < retries:
                import time
                warning(f"SDP browse attempt {attempt + 1} failed, retrying...")
                time.sleep(2)
                continue

        error(f"SDP browse failed: {result.stderr.strip()}")
        return {
            "services": [],
            "service_count": 0,
            "rfcomm_channels": [],
            "l2cap_psms": [],
            "raw_output": "",
            "status": "error",
            "error": result.stderr.strip(),
            "partially_parsed": False,
            "vendor_specific_present": False,
        }

    error(f"SDP browse failed after {retries + 1} attempts")
    return {
        "services": [],
        "service_count": 0,
        "rfcomm_channels": [],
        "l2cap_psms": [],
        "raw_output": "",
        "status": "error",
        "error": f"failed after {retries + 1} attempts",
        "partially_parsed": False,
        "vendor_specific_present": False,
    }


def parse_sdp_output(output: str) -> list[dict]:
    """Parse sdptool browse output into structured service records.

    Captures: service name, class IDs, protocol (RFCOMM/L2CAP), channel/PSM,
    profile version, provider name, and additional protocol layers (OBEX, GOEP).
    """
    services = []
    current = None
    last_protocol = None
    section = ""

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Service Name:"):
            if current:
                _finalize_service(current)
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "protocols": [], "raw_attributes": [], "profile_descriptors": []}
            last_protocol = None
            section = ""

        elif line.startswith("Service RecHandle:"):
            if current is None:
                current = {"name": "Unknown", "protocols": [], "raw_attributes": [], "profile_descriptors": []}
            current["handle"] = line.split(":", 1)[1].strip()
            last_protocol = None
            section = ""

        elif line.startswith("Service Description:"):
            if current:
                current["description"] = line.split(":", 1)[1].strip()

        elif line.startswith("Provider Name:"):
            if current:
                current["provider"] = line.split(":", 1)[1].strip()

        elif line.startswith("Service Class ID List:"):
            last_protocol = None
            section = "class_ids"

        elif line.startswith("Profile Descriptor List:"):
            last_protocol = None
            section = "profiles"

        elif line.startswith("Protocol Descriptor List:"):
            last_protocol = None
            section = "protocols"

        elif line.startswith('"') and current:
            m = re.match(r'"(.+?)"\s*\((0x[0-9A-Fa-f]+)\)', line)
            if m:
                uuid_name = m.group(1)
                uuid_hex = m.group(2).lower()
                if section == "profiles":
                    current.setdefault("profile_descriptors", []).append(
                        {"name": uuid_name, "uuid": uuid_hex, "profile": PROFILE_UUIDS.get(uuid_hex, uuid_name)}
                    )
                    current["profile"] = PROFILE_UUIDS.get(uuid_hex, uuid_name)
                else:
                    current.setdefault("class_ids", []).append(uuid_name)
                    current.setdefault("class_id_uuids", []).append(uuid_hex)
                    if section != "protocols":
                        current["profile"] = PROFILE_UUIDS.get(uuid_hex, uuid_name)
                if section == "protocols":
                    current.setdefault("protocol_stack", []).append({"name": uuid_name, "uuid": uuid_hex})
                    current.setdefault("protocols", []).append(uuid_name)
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
            if current.get("profile_descriptors"):
                current["profile_descriptors"][-1]["version"] = current["profile_version"]

        elif "RFCOMM" in line and current:
            last_protocol = "RFCOMM"
            current.setdefault("protocols", []).append("RFCOMM")
            m = re.search(r"Channel:\s*(\d+)", line)
            if m:
                current["protocol"] = "RFCOMM"
                current["channel"] = int(m.group(1))

        elif "L2CAP" in line and current:
            last_protocol = "L2CAP"
            current.setdefault("protocols", []).append("L2CAP")
            m = re.search(r"PSM:\s*(\S+)", line)
            if m:
                current["protocol"] = "L2CAP"
                try:
                    psm = int(m.group(1), 0)
                    current["channel"] = psm
                    current["psm"] = psm
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
                    psm = int(m.group(1), 0)
                    current["channel"] = psm
                    current["psm"] = psm
                except (ValueError, TypeError):
                    current["channel"] = 0

        elif "OBEX" in line and current:
            current.setdefault("protocols", []).append("OBEX")

        elif "GOEP" in line and current:
            current.setdefault("protocols", []).append("GOEP")

        # Handle bare attribute lines with hex values (sdptool format variance)
        elif line.startswith("Attribute") and current:
            current.setdefault("raw_attributes", []).append(line)
            attr_match = re.match(r"Attribute\s+\((0x[0-9A-Fa-f]+)\)\s*-\s*(.+)", line)
            if attr_match:
                current.setdefault("attributes", []).append(
                    {"attribute_id": attr_match.group(1).lower(), "raw": attr_match.group(2).strip()}
                )

    if current:
        _finalize_service(current)
        services.append(current)

    success(f"Found {len(services)} SDP service(s)")
    return services


def _build_sdp_summary(raw_output: str, services: list[dict], status: str) -> dict[str, Any]:
    rfcomm_channels = sorted(
        {
            int(service["channel"])
            for service in services
            if service.get("protocol") == "RFCOMM" and service.get("channel") is not None
        }
    )
    l2cap_psms = sorted(
        {
            int(service["psm"])
            for service in services
            if service.get("psm") is not None
        }
    )
    return {
        "services": services,
        "service_count": len(services),
        "rfcomm_channels": rfcomm_channels,
        "l2cap_psms": l2cap_psms,
        "raw_output": raw_output,
        "status": status,
        "partially_parsed": any(service.get("raw_attributes") for service in services),
        "vendor_specific_present": any(service.get("vendor_specific") for service in services),
    }


def _finalize_service(service: dict[str, Any]) -> None:
    service["protocols"] = sorted(set(service.get("protocols", [])))
    class_ids = service.get("class_ids", [])
    service["vendor_specific"] = any("vendor" in class_id.lower() for class_id in class_ids)


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
            uuid_norm = uuid_lower.replace("0x", "").lstrip("0") or uuid_lower
            matched = []
            for s in all_services:
                class_ids_text = " ".join(s.get("class_ids", [])).lower()
                class_uuids = [c.lower() for c in s.get("class_id_uuids", [])]
                profile_text = s.get("profile", "").lower()
                if (
                    uuid_lower in class_ids_text
                    or uuid_lower in profile_text
                    or any(uuid_lower in c or uuid_norm in c.replace("0x", "").lstrip("0") for c in class_uuids)
                ):
                    matched.append(s)
            results[uuid] = matched
    else:
        # Fallback: individual searches
        for uuid in uuids:
            results[uuid] = search_service(address, uuid)
    return results


def check_ssp(address: str, hci: str | None = None) -> bool | None:
    """Check if a device supports Secure Simple Pairing via LMP features.

    SSP is a link-layer feature advertised in LMP feature pages,
    NOT in SDP records. We use hcitool info to read the LMP features.
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
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


def get_raw_sdp(address: str, hci: str | None = None, timeout: float = 30.0) -> str:
    """Get raw SDP output for analysis."""
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    cmd = ["sdptool"]
    if hci:
        cmd += ["-i", hci]
    cmd += ["browse", address]
    result = run_cmd(cmd, timeout=timeout)
    return result.stdout if result.returncode == 0 else ""


def get_device_bt_version(address: str, hci: str | None = None) -> dict:
    """Get remote device's Bluetooth/LMP version and features.

    Returns:
        {"lmp_version": "5.2", "lmp_subversion": "0x1234",
         "manufacturer": "Broadcom", "features": [...]}
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
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


# ── Native Module class ─────────────────────────────────────────────────────

class SdpScannerModule(Module):
    """SDP Service Discovery.

    Enumerate SDP service records and decode attributes on a Classic
    Bluetooth target. Calls ``browse_services_detailed`` from this same
    file — no cross-file forwarding.
    """

    module_id = "reconnaissance.sdp"
    family = ModuleFamily.RECONNAISSANCE
    name = "SDP Service Discovery"
    description = "Enumerate SDP service records and decode attributes"
    protocols = ("Classic", "SDP", "L2CAP")
    requires = ("classic_target",)
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = True
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target BR/EDR address"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptInt("RETRIES", default=2, description="Retry count on transient failures"),
    )

    def run(self, ctx: RunContext) -> dict:
        target = str(ctx.options.get("RHOST", ""))
        hci = str(ctx.options.get("HCI", ""))
        retries = int(ctx.options.get("RETRIES", 2))
        started_at = ctx.started_at

        error_msg: str | None = None
        result: dict
        try:
            result = browse_services_detailed(target, hci=hci, retries=retries)
        except Exception as exc:
            logger.exception("SDP browse failed for %s", target)
            error_msg = str(exc)
            result = {
                "services": [],
                "service_count": 0,
                "rfcomm_channels": [],
                "l2cap_psms": [],
                "raw_output": "",
                "status": "error",
                "error": error_msg,
            }

        status = str(result.get("status", "error"))
        services = result.get("services", []) or []
        service_count = len(services)

        if error_msg or status not in ("completed", "adapter_not_ready"):
            execution_status = "failed"
        elif status == "adapter_not_ready":
            execution_status = "skipped"
        else:
            execution_status = "completed"

        # Map to recon family outcomes: observed / merged / correlated / partial / not_applicable
        if execution_status == "skipped":
            outcome = "not_applicable"
        elif execution_status == "completed" and service_count > 0:
            outcome = "observed"
        elif execution_status == "completed":
            # Browse completed but returned no services — a clean negative
            outcome = "not_applicable"
        else:
            # Probe was attempted but failed (timeout, connection error, etc.)
            outcome = "partial"

        summary_text = (
            f"SDP browse error: {error_msg or result.get('error', 'unknown error')}"
            if execution_status == "failed"
            else (
                f"Found {service_count} SDP services"
                if service_count
                else "No SDP services found"
            )
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            module_id=self.module_id,
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="sdp_browse",
                    kind="collector",
                    id="sdp_browse",
                    title="SDP Browse",
                    module=self.module_id,
                    module_id=self.module_id,
                    protocol="SDP",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "service_count": service_count,
                            "rfcomm_channels": result.get("rfcomm_channels", []),
                            "l2cap_psms": result.get("l2cap_psms", []),
                            "error": error_msg or result.get("error"),
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "service_count": service_count,
                "error": error_msg or result.get("error"),
            },
            module_data=result,
            run_id=ctx.run_id,
        )
