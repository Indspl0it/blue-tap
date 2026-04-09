"""Confirmed OTA HID/HOGP vulnerability checks."""

from __future__ import annotations

import socket

from blue_tap.attack.cve_framework import make_cve_finding as _finding
from blue_tap.recon.gatt import enumerate_services_sync


def _has_hid_service(services: list[dict]) -> bool:
    for svc in services:
        uuid = str(svc.get("uuid", "")).lower().replace("-", "")
        if "1124" in uuid:
            return True
    return False


def _connect_l2cap_psm(address: str, psm: int, timeout: float = 4.0) -> tuple[bool, str]:
    AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
    BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
    sock = None
    try:
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        sock.settimeout(timeout)
        sock.connect((address, psm))
        return True, "accepted"
    except OSError as exc:
        return False, str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _check_hid_unbonded_connection(address: str, services: list[dict]) -> list[dict]:
    """CVE-2020-0556 / CVE-2023-45866 via unbonded HID control+interrupt acceptance."""
    if not _has_hid_service(services):
        return [_finding(
            "INFO", "CVE-2020-0556/CVE-2023-45866: Not Applicable",
            "HID unbonded-acceptance check skipped — target does not advertise HID Host "
            "service UUID 0x1124 over Classic Bluetooth.",
            cve="CVE-2020-0556,CVE-2023-45866", status="not_applicable", confidence="high",
            evidence="No HID Host SDP UUID 0x1124 present",
        )]

    ctrl_ok, ctrl_reason = _connect_l2cap_psm(address, 0x0011)
    if not ctrl_ok:
        if any(token in ctrl_reason.lower() for token in ("permission", "auth", "security", "denied")):
            return []
        return [_finding(
            "MEDIUM", "CVE-2020-0556/CVE-2023-45866: Inconclusive",
            "Target advertises HID Host, but the unbonded HID Control channel probe did not "
            "cleanly reach an accept-or-reject differential.",
            cve="CVE-2020-0556,CVE-2023-45866", status="inconclusive", confidence="medium",
            evidence=f"PSM 0x0011 connect failed: {ctrl_reason}",
        )]

    intr_ok, intr_reason = _connect_l2cap_psm(address, 0x0013)
    if intr_ok:
        return [_finding(
            "CRITICAL",
            "Unbonded HID Host Acceptance (CVE-2020-0556, CVE-2023-45866)",
            "Target accepted both HID Control and Interrupt channels from an unbonded device. "
            "This confirms the classic unauthenticated HID acceptance path.",
            cve="CVE-2020-0556,CVE-2023-45866",
            impact="Unauthenticated HID device impersonation and keystroke injection",
            remediation="Require bonding before accepting HID/HOGP device connections.",
            status="confirmed",
            confidence="high",
            evidence="L2CAP PSM 0x0011 and 0x0013 accepted without bonding",
        )]

    if any(token in intr_reason.lower() for token in ("permission", "auth", "security", "denied")):
        return [_finding(
            "MEDIUM", "CVE-2020-0556/CVE-2023-45866: Inconclusive",
            "Target accepted HID Control unbonded but denied or blocked the Interrupt channel. "
            "This is not a full vulnerable pattern, but it is not a clean secure rejection either.",
            cve="CVE-2020-0556,CVE-2023-45866", status="inconclusive", confidence="medium",
            evidence=f"PSM 0x0011 accepted, PSM 0x0013 failed: {intr_reason}",
        )]

    return [_finding(
        "MEDIUM", "CVE-2020-0556/CVE-2023-45866: Inconclusive",
        "Target accepted HID Control unbonded, but the Interrupt-channel result was not definitive.",
        cve="CVE-2020-0556,CVE-2023-45866", status="inconclusive", confidence="medium",
        evidence=f"PSM 0x0011 accepted; PSM 0x0013 failed: {intr_reason}",
    )]


def _check_hogp_unbonded_write(address: str) -> list[dict]:
    """Secondary BLE HOGP differential for targets exposing HID over GATT."""
    try:
        services = enumerate_services_sync(address)
    except Exception:
        return []

    hid_service = None
    report_char = None
    for svc in services:
        if str(svc.get("uuid", "")).lower().startswith("00001812"):
            hid_service = svc
            for char in svc.get("characteristics", []):
                if str(char.get("uuid", "")).lower().startswith("00002a4d"):
                    report_char = char
                    break
            break

    if hid_service is None or report_char is None:
        return [_finding(
            "INFO", "CVE-2020-0556/CVE-2023-45866 HOGP: Not Applicable",
            "BLE HOGP probe skipped — no HID Service (0x1812) with Report characteristic "
            "(0x2A4D) was enumerated pre-auth.",
            cve="CVE-2020-0556,CVE-2023-45866", status="not_applicable", confidence="high",
            evidence="No pre-auth HOGP HID Report characteristic found",
        )]

    props = {p.lower() for p in report_char.get("properties", [])}
    if "write" in props or "write-without-response" in props:
        return [_finding(
            "CRITICAL",
            "Unauthenticated HOGP Report Write (CVE-2020-0556, CVE-2023-45866)",
            "Target exposes a pre-auth writable HID Report characteristic over BLE HOGP.",
            cve="CVE-2020-0556,CVE-2023-45866",
            impact="Unauthenticated BLE HID report injection",
            remediation="Require bonding/authentication before accepting HOGP report writes.",
            status="confirmed",
            confidence="high",
            evidence=f"HID Report characteristic {report_char.get('uuid')} writable pre-auth",
        )]

    return []
