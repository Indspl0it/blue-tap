"""Non-CVE BLE and pairing-surface checks used by vulnscan."""

from __future__ import annotations

import errno
import socket

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding


_SENSITIVE_SERVICE_KEYWORDS = (
    "firmware",
    "dfu",
    "update",
    "debug",
    "diagnostic",
    "control",
    "config",
    "vehicle",
    "transport discovery",
    "bond management",
    "hid",
)

_SENSITIVE_CHAR_KEYWORDS = (
    "firmware",
    "dfu",
    "ota",
    "update",
    "debug",
    "diagnostic",
    "control",
    "command",
    "config",
    "reset",
    "unlock",
    "key",
    "passkey",
    "pair",
    "bond",
    "report",
)

_SENSITIVE_UUID_SUFFIXES = {
    "00002a4d-0000-1000-8000-00805f9b34fb",  # Report
    "00002a4e-0000-1000-8000-00805f9b34fb",  # Report Map
    "00002a4c-0000-1000-8000-00805f9b34fb",  # HID Control Point
}


def _classify_writable_surface(service_name: str, char_name: str, uuid: str) -> str:
    combined = f"{service_name} {char_name} {uuid}".lower()
    if uuid.lower() in _SENSITIVE_UUID_SUFFIXES:
        return "sensitive"
    if any(keyword in combined for keyword in _SENSITIVE_SERVICE_KEYWORDS):
        return "sensitive"
    if any(keyword in combined for keyword in _SENSITIVE_CHAR_KEYWORDS):
        return "sensitive"
    return "generic"


def check_pairing_method(address: str, hci: str) -> list[dict]:
    findings: list[dict] = []
    try:
        from blue_tap.modules.reconnaissance.hci_capture import detect_pairing_mode

        mode = detect_pairing_mode(address, hci)
    except Exception as exc:
        return [
            _finding(
                "INFO",
                "Pairing Method Not Determined",
                "Pairing-mode probe did not produce a usable result.",
                status="inconclusive",
                confidence="low",
                evidence=str(exc),
                category="posture",
            )
        ]

    method = mode.get("pairing_method", "Unknown")
    io_cap = mode.get("io_capability", "Unknown")
    ssp_supported = mode.get("ssp_supported", "Unknown")
    evidence = f"pairing_method={method}; io_capability={io_cap}; ssp_supported={ssp_supported}"

    if method == "Unknown":
        return [
            _finding(
                "INFO",
                "Pairing Method Not Determined",
                "Blue-Tap could not classify the negotiated pairing method from the observed exchange.",
                status="inconclusive",
                confidence="low",
                evidence=evidence,
                category="posture",
            )
        ]

    if method == "Just Works":
        findings.append(
            _finding(
                "MEDIUM",
                "Pairing Posture: Just Works",
                "The observed pairing flow resolved to Just Works. This removes MITM confirmation and should be treated as a weaker pairing posture, not a standalone vulnerability.",
                impact="An attacker who can interpose during pairing may exploit the lack of user confirmation.",
                remediation="Prefer Numeric Comparison or Passkey Entry where the target hardware permits it.",
                status="confirmed",
                confidence="medium",
                evidence=evidence,
                category="posture",
            )
        )
    else:
        findings.append(
            _finding(
                "INFO",
                f"Pairing Posture: {method}",
                f"Observed pairing method: {method}.",
                status="confirmed",
                confidence="medium",
                evidence=evidence,
                category="posture",
            )
        )
    return findings


def check_writable_gatt(address: str) -> list[dict]:
    findings: list[dict] = []
    try:
        from blue_tap.modules.reconnaissance.gatt import enumerate_services_sync

        services = enumerate_services_sync(address)
    except Exception as exc:
        return [
            _finding(
                "INFO",
                "Writable GATT Surface Not Evaluated",
                "GATT enumeration was unavailable for writable-surface analysis.",
                status="inconclusive",
                confidence="low",
                evidence=str(exc),
                category="exposure",
            )
        ]

    generic_count = 0
    sensitive_open = []
    sensitive_protected = []

    for svc in services:
        service_name = svc.get("description", "Unknown Service")
        for char in svc.get("characteristics", []):
            props = {p.lower() for p in char.get("properties", [])}
            if "write" not in props and "write-without-response" not in props:
                continue
            generic_count += 1
            char_name = char.get("description", "Unknown")
            uuid = char.get("uuid", "")
            security_hint = char.get("security_hint", "unknown")
            surface_class = _classify_writable_surface(service_name, char_name, uuid)
            entry = {
                "service": service_name,
                "characteristic": char_name,
                "uuid": uuid,
                "security_hint": security_hint,
                "properties": sorted(props),
            }
            if surface_class != "sensitive":
                continue
            if security_hint in {"open", "unknown"} or "write-without-response" in props:
                sensitive_open.append(entry)
            else:
                sensitive_protected.append(entry)

    if sensitive_open:
        sample = "; ".join(
            f"{item['characteristic']} ({item['uuid']}, {item['security_hint']})"
            for item in sensitive_open[:5]
        )
        findings.append(
            _finding(
                "HIGH",
                "Sensitive Writable GATT Surface",
                "Sensitive writable GATT characteristics are exposed without a strong indication that pairing or encryption is required.",
                impact="Firmware, control, pairing, or diagnostic functions may be reachable over BLE writes.",
                remediation="Require authenticated or encrypted writes for sensitive characteristics and reduce vendor-specific writable surface in production builds.",
                status="confirmed",
                confidence="medium",
                evidence=sample,
                category="exposure",
            )
        )

    if sensitive_protected:
        sample = "; ".join(
            f"{item['characteristic']} ({item['uuid']}, {item['security_hint']})"
            for item in sensitive_protected[:5]
        )
        findings.append(
            _finding(
                "INFO",
                "Sensitive GATT Writes Present but Security-Gated",
                "Sensitive writable GATT characteristics were enumerated, but the current security hints indicate that pairing or encryption is likely required.",
                status="confirmed",
                confidence="medium",
                evidence=sample,
                category="posture",
            )
        )

    if generic_count:
        findings.append(
            _finding(
                "INFO",
                "Writable GATT Characteristics Present",
                f"Found {generic_count} writable GATT characteristic(s). Generic writable attributes are common and only become security-relevant when paired with sensitive function or weak access control.",
                status="confirmed",
                confidence="medium",
                evidence=f"enumerated_writable_characteristics={generic_count}",
                category="exposure",
            )
        )
    return findings


def check_eatt_support(address: str, l2cap_timeout: float) -> list[dict]:
    findings: list[dict] = []
    try:
        sock = socket.socket(
            getattr(socket, "AF_BLUETOOTH", 31),
            socket.SOCK_SEQPACKET,
            getattr(socket, "BTPROTO_L2CAP", 0),
        )
        sock.settimeout(l2cap_timeout)
        try:
            sock.connect((address, 0x0027))
            findings.append(
                _finding(
                    "INFO",
                    "EATT Capability Detected",
                    "Target accepted a connection to PSM 0x0027, indicating Enhanced ATT capability.",
                    status="confirmed",
                    confidence="high",
                    evidence="L2CAP PSM 0x0027 connection succeeded",
                    category="posture",
                )
            )
        except OSError as exc:
            if exc.errno == errno.EACCES:
                findings.append(
                    _finding(
                        "INFO",
                        "EATT Capability Detected (Security-Gated)",
                        "Target exposes EATT but requires authentication or encryption before the channel can be used.",
                        status="confirmed",
                        confidence="high",
                        evidence="L2CAP PSM 0x0027 returned EACCES",
                        category="posture",
                    )
                )
        finally:
            sock.close()
    except OSError:
        return findings
    return findings
