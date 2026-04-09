"""Non-CVE RFCOMM, OBEX, and diagnostics checks used by vulnscan."""

from __future__ import annotations

import errno
import socket
import struct

from blue_tap.attack.cve_framework import make_cve_finding as _finding
from blue_tap.recon.rfcomm_scan import RFCOMMScanner


_PBAP_UUID_HINTS = ("112f", "1130")
_MAP_UUID_HINTS = ("1132", "1133", "1134")
_OPP_UUID_HINTS = ("1105",)
_SENSITIVE_NAME_KEYWORDS = (
    "pbap",
    "phonebook",
    "map",
    "message",
    "object push",
    "file transfer",
)


def _match_profile(service: dict) -> str | None:
    uuid = str(service.get("uuid", "")).lower()
    name = str(service.get("name", "")).lower()
    if any(token in uuid for token in _PBAP_UUID_HINTS) or any(token in name for token in ("pbap", "phonebook")):
        return "pbap"
    if any(token in uuid for token in _MAP_UUID_HINTS) or any(token in name for token in ("map", "message")):
        return "map"
    if any(token in uuid for token in _OPP_UUID_HINTS) or "object push" in name:
        return "opp"
    if any(keyword in name for keyword in _SENSITIVE_NAME_KEYWORDS):
        return "sensitive"
    return None


def check_service_exposure(address: str, services: list[dict], rfcomm_timeout: float) -> list[dict]:
    findings: list[dict] = []
    scanner = RFCOMMScanner(address)
    reachable = []
    for svc in services:
        if svc.get("protocol") != "RFCOMM":
            continue
        ch = svc.get("channel")
        if not isinstance(ch, int):
            continue
        profile = _match_profile(svc)
        if not profile:
            continue
        probe = scanner.probe_channel(ch, timeout=rfcomm_timeout)
        if probe.get("status") != "open":
            continue
        reachable.append({
            "name": svc.get("name", "Unknown"),
            "channel": ch,
            "profile": profile,
            "response_type": probe.get("response_type", "unknown"),
        })

    if not reachable:
        return findings

    profile_list = ", ".join(f"{item['name']} (ch {item['channel']})" for item in reachable[:6])
    evidence = "; ".join(
        f"{item['profile']}/ch{item['channel']}={item['response_type']}" for item in reachable
    )
    findings.append(
        _finding(
            "INFO",
            "Sensitive RFCOMM Profiles Reachable",
            f"RFCOMM transport was reachable for sensitive profiles: {profile_list}. This confirms transport exposure, not unauthenticated data access.",
            impact="Profile transport is reachable and should be correlated with authorization and encryption checks before treating it as data exposure.",
            remediation="Keep sensitive profiles gated by authentication, authorization, and encryption.",
            status="confirmed",
            confidence="high",
            evidence=evidence,
            category="exposure",
        )
    )
    return findings


def check_hidden_rfcomm(address: str, services: list[dict], rfcomm_timeout: float) -> list[dict]:
    findings: list[dict] = []
    sdp_channels = sorted({
        svc.get("channel") for svc in services
        if svc.get("protocol") == "RFCOMM" and isinstance(svc.get("channel"), int)
    })
    if not sdp_channels:
        return findings

    scanner = RFCOMMScanner(address)
    try:
        hidden = scanner.find_hidden_services(sdp_channels)
    except Exception:
        return findings

    severity_map = {
        "at_modem": "HIGH",
        "obex": "HIGH",
        "silent_open": "MEDIUM",
        "raw_data": "MEDIUM",
    }

    for result in hidden:
        ch = result["channel"]
        confirm = scanner.probe_channel(ch, timeout=rfcomm_timeout)
        if confirm.get("status") != "open":
            continue
        response_type = confirm.get("response_type", result.get("response_type", "unknown"))
        raw_hex = confirm.get("raw_response_hex") or result.get("raw_response_hex", "")
        findings.append(
            _finding(
                severity_map.get(response_type, "MEDIUM"),
                f"Unadvertised RFCOMM Channel (ch {ch})",
                f"Channel {ch} was open across repeated probes but was not advertised in SDP.",
                impact="Unadvertised RFCOMM services are often debug, factory, or undocumented interfaces with weaker access control.",
                remediation="Disable undocumented RFCOMM listeners or gate them behind authentication and authorization.",
                status="confirmed",
                confidence="high",
                evidence=f"channel={ch}; response_type={response_type}; raw_response_hex={raw_hex[:80] or 'none'}; sdp_channels={sdp_channels}",
                category="exposure",
            )
        )
    return findings


def check_encryption_enforcement(address: str, services: list[dict], connect_timeout: float, obex_timeout: float) -> list[dict]:
    findings: list[dict] = []
    sensitive_keywords = ("pbap", "phonebook", "map", "message", "hfp", "hands-free", "handsfree")
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_rfcomm = getattr(socket, "BTPROTO_RFCOMM", 3)
    sol_bluetooth = 274
    bt_security = 4
    pbap_uuid = bytes.fromhex("796135f0f0c511d809660800200c9a66")
    map_uuid = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")

    for svc in services:
        name = str(svc.get("name", ""))
        lname = name.lower()
        ch = svc.get("channel")
        if svc.get("protocol") != "RFCOMM" or not isinstance(ch, int):
            continue
        if not any(keyword in lname for keyword in sensitive_keywords):
            continue

        sock = None
        try:
            sock = socket.socket(af_bluetooth, socket.SOCK_STREAM, btproto_rfcomm)
            sock.settimeout(connect_timeout)
            sock.setsockopt(sol_bluetooth, bt_security, struct.pack("BBH", 1, 0, 0))
            sock.connect((address, ch))
        except OSError as exc:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            if exc.errno == errno.EACCES:
                findings.append(
                    _finding(
                        "INFO",
                        f"Encryption Enforced ({name})",
                        f"{name} rejected a low-security RFCOMM connection.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"channel={ch}; connect_errno=EACCES",
                        category="posture",
                    )
                )
            continue

        evidence = [f"channel={ch}", "bt_security=LOW"]
        severity = "MEDIUM"
        description = f"{name} accepted a low-security RFCOMM connection."

        try:
            if any(token in lname for token in ("pbap", "phonebook", "map", "message")):
                target_uuid = map_uuid if any(token in lname for token in ("map", "message")) else pbap_uuid
                target_header = b"\x46" + struct.pack(">H", 3 + len(target_uuid)) + target_uuid
                obex_body = b"\x10\x00" + struct.pack(">H", 0xFFFF) + target_header
                obex_connect = b"\x80" + struct.pack(">H", 3 + len(obex_body)) + obex_body
                sock.settimeout(obex_timeout)
                sock.sendall(obex_connect)
                resp = sock.recv(1024)
                if resp:
                    evidence.append(f"obex_status=0x{resp[0]:02X}")
                    if resp[0] == 0xA0:
                        severity = "HIGH"
                        description = f"{name} accepted a low-security RFCOMM connection and returned OBEX Success without requiring stronger link security."
                    elif resp[0] in (0xC1, 0xC3):
                        severity = "INFO"
                        description = f"{name} accepted the transport connection but enforced authorization at the OBEX layer."
            elif any(token in lname for token in ("hfp", "hands-free", "handsfree")):
                sock.sendall(b"AT\r\n")
                sock.settimeout(obex_timeout)
                resp = sock.recv(256)
                if resp:
                    text = resp.decode("ascii", errors="replace")
                    evidence.append(f"rfcomm_response={text[:80]}")
                    if "OK" in text or "ERROR" in text or "AT" in text.upper():
                        severity = "HIGH"
                        description = f"{name} accepted a low-security RFCOMM connection and responded to AT traffic."
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

        findings.append(
            _finding(
                severity,
                f"Low-Security RFCOMM Accepted ({name})",
                description,
                impact="Sensitive profile traffic may be exposed before the target enforces stronger security controls.",
                remediation="Require medium or high Bluetooth security before allowing sensitive profile traffic.",
                status="confirmed",
                confidence="high" if severity in {"HIGH", "INFO"} else "medium",
                evidence="; ".join(evidence),
                category="exposure" if severity != "INFO" else "posture",
            )
        )
    return findings


def check_authorization_model(address: str, services: list[dict], timeout: float) -> list[dict]:
    findings: list[dict] = []
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_rfcomm = getattr(socket, "BTPROTO_RFCOMM", 3)
    pbap_uuid = bytes.fromhex("796135f0f0c511d809660800200c9a66")
    map_uuid = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")

    for svc in services:
        name = str(svc.get("name", ""))
        lname = name.lower()
        ch = svc.get("channel")
        if svc.get("protocol") != "RFCOMM" or not isinstance(ch, int):
            continue
        if not any(token in lname for token in ("pbap", "phonebook", "map", "message")):
            continue

        target_uuid = map_uuid if any(token in lname for token in ("map", "message")) else pbap_uuid
        sock = None
        try:
            sock = socket.socket(af_bluetooth, socket.SOCK_STREAM, btproto_rfcomm)
            sock.settimeout(timeout)
            sock.connect((address, ch))
            target_header = b"\x46" + struct.pack(">H", 3 + len(target_uuid)) + target_uuid
            obex_body = b"\x10\x00" + struct.pack(">H", 0xFFFF) + target_header
            obex_connect = b"\x80" + struct.pack(">H", 3 + len(obex_body)) + obex_body
            sock.sendall(obex_connect)
            resp = sock.recv(1024)
        except OSError as exc:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            if exc.errno == errno.EACCES:
                findings.append(
                    _finding(
                        "INFO",
                        f"Transport Authentication Enforced ({name})",
                        f"{name} required authentication before RFCOMM transport was established.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"channel={ch}; connect_errno=EACCES",
                        category="posture",
                    )
                )
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if not resp:
            continue
        status_code = resp[0]
        if status_code == 0xA0:
            findings.append(
                _finding(
                    "CRITICAL",
                    f"Unauthenticated OBEX Access ({name})",
                    f"{name} returned OBEX Success to an unauthenticated connect request.",
                    impact="Phonebook or message data may be retrievable without pairing or authorization.",
                    remediation="Require transport authentication and explicit profile authorization before OBEX operations.",
                    status="confirmed",
                    confidence="high",
                    evidence=f"channel={ch}; obex_status=0x{status_code:02X}",
                    category="exposure",
                )
            )
        elif status_code in (0xC1, 0xC3):
            findings.append(
                _finding(
                    "INFO",
                    f"OBEX Authorization Enforced ({name})",
                    f"{name} rejected unauthenticated OBEX access with an authorization error.",
                    status="confirmed",
                    confidence="high",
                    evidence=f"channel={ch}; obex_status=0x{status_code:02X}",
                    category="posture",
                )
            )
    return findings


def check_automotive_diagnostics(address: str, services: list[dict], connect_timeout: float, at_timeout: float) -> list[dict]:
    findings: list[dict] = []
    af_bluetooth = getattr(socket, "AF_BLUETOOTH", 31)
    btproto_rfcomm = getattr(socket, "BTPROTO_RFCOMM", 3)
    diag_keywords = ("diagnostic", "obd", "can", "ecu", "debug", "factory", "gateway")
    probes = [b"ATI\r\n", b"AT@1\r\n", b"0100\r\n"]

    diag_channels = []
    for svc in services:
        uuid = str(svc.get("uuid", "")).lower()
        name = str(svc.get("name", ""))
        lname = name.lower()
        ch = svc.get("channel")
        if svc.get("protocol") != "RFCOMM" or not isinstance(ch, int):
            continue
        is_serial_diag = "1101" in uuid or "1103" in uuid
        keyword_match = any(token in lname for token in diag_keywords)
        if is_serial_diag or keyword_match:
            diag_channels.append((name, ch, is_serial_diag, keyword_match))

    for name, ch, is_serial_diag, keyword_match in diag_channels:
        if keyword_match:
            findings.append(
                _finding(
                    "INFO",
                    f"Diagnostic-Looking Service ({name})",
                    f"Service name '{name}' suggests diagnostic or factory functionality. This is naming evidence only until the protocol is confirmed.",
                    status="confirmed",
                    confidence="medium",
                    evidence=f"channel={ch}; name={name}",
                    category="exposure",
                )
            )
        if not is_serial_diag:
            continue

        sock = None
        try:
            sock = socket.socket(af_bluetooth, socket.SOCK_STREAM, btproto_rfcomm)
            sock.settimeout(connect_timeout)
            sock.connect((address, ch))
            responses = []
            for probe in probes:
                try:
                    sock.sendall(probe)
                    sock.settimeout(at_timeout)
                    data = sock.recv(1024)
                    if data:
                        responses.append((probe.decode("ascii", errors="replace").strip(), data))
                except OSError:
                    continue
        except OSError:
            responses = []
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        for probe_name, resp in responses:
            resp_text = resp.decode("ascii", errors="replace")
            if "ELM" in resp_text or "OBD" in resp_text or any(token in resp_text for token in ("41 00", "41 0C", "7E8")):
                findings.append(
                    _finding(
                        "CRITICAL",
                        f"Bluetooth Diagnostic Responder ({name})",
                        f"Channel {ch} responded to an OBD/diagnostic probe with recognizable diagnostic data.",
                        impact="Bluetooth transport may provide direct access to vehicle diagnostics or CAN-adjacent interfaces.",
                        remediation="Remove diagnostic bridges from production Bluetooth surface or require strong authentication and authorization.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"channel={ch}; probe={probe_name}; response={resp_text[:100]}",
                        category="exposure",
                    )
                )
                break
            if "OK" in resp_text or "ERROR" in resp_text or "AT" in resp_text.upper():
                findings.append(
                    _finding(
                        "HIGH",
                        f"Serial Command Interface over Bluetooth ({name})",
                        f"Channel {ch} responded to modem-style probes, indicating an interactive serial command surface.",
                        impact="Serial command interfaces are frequently diagnostic or control paths and should be treated as high-risk if exposed to unauthenticated peers.",
                        remediation="Restrict serial control channels to authenticated maintenance workflows.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"channel={ch}; probe={probe_name}; response={resp_text[:100]}",
                        category="exposure",
                    )
                )
                break
    return findings
