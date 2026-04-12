"""Non-CVE security-posture checks used by vulnscan."""

from __future__ import annotations

import re

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding


def check_pin_lockout(address: str, hci: str, ssp: bool | None) -> list[dict]:
    if ssp is not False:
        return [
            _finding(
                "INFO",
                "PIN Lockout Not Applicable",
                "PIN lockout testing only applies to legacy PIN pairing targets.",
                status="not_applicable",
                confidence="high",
                evidence=f"ssp={ssp}",
                category="posture",
            )
        ]
    try:
        from blue_tap.modules.exploitation.pin_brute import PINBruteForce

        brute = PINBruteForce(address, hci=hci)
        result = brute.detect_lockout(attempts=3)
    except Exception as exc:
        return [
            _finding(
                "INFO",
                "PIN Lockout Not Evaluated",
                "Legacy PIN lockout behavior could not be measured.",
                status="inconclusive",
                confidence="low",
                evidence=str(exc),
                category="posture",
            )
        ]

    locked_out = result.get("locked_out", False)
    timings = result.get("timings", [])
    timing_str = ", ".join(f"{t:.3f}s" for t in timings)
    increasing = len(timings) >= 2 and all(b >= a for a, b in zip(timings, timings[1:]))
    avg_time = sum(timings) / len(timings) if timings else 0.0

    if locked_out:
        return [
            _finding(
                "INFO",
                "PIN Lockout or Backoff Detected",
                "The target slowed down or locked out repeated incorrect PIN attempts.",
                status="confirmed",
                confidence="high",
                evidence=f"timings=[{timing_str}]",
                category="posture",
            )
        ]

    severity = "HIGH" if avg_time < 2.0 and not increasing else "MEDIUM"
    description = (
        "Repeated incorrect PIN attempts were rejected without a visible lockout or growing delay."
        if severity == "HIGH" else
        "Repeated incorrect PIN attempts did not trigger a hard lockout, but response timing suggests some throttling."
    )
    return [
        _finding(
            severity,
            "Legacy PIN Pairing Lacks Strong Lockout",
            description,
            impact="Legacy PIN brute force becomes more feasible when retries are not strongly rate-limited.",
            remediation="Add lockout or strong exponential backoff for repeated incorrect PIN attempts.",
            status="confirmed",
            confidence="high" if severity == "HIGH" else "medium",
            evidence=f"timings=[{timing_str}]",
            category="posture",
        )
    ]


def check_device_class(address: str, hci: str, services: list[dict], hcitool_info_result) -> list[dict]:
    findings: list[dict] = []
    result = hcitool_info_result
    if result is None or getattr(result, "returncode", 1) != 0:
        return findings

    match = re.search(r"Class:\s*(0x[0-9a-fA-F]+)", result.stdout)
    if not match:
        return findings

    from blue_tap.hardware.scanner import parse_device_class

    cod = parse_device_class(match.group(1))
    services_bits = cod.get("services", [])
    corroborated = []
    service_names = " ".join(str(svc.get("name", "")) for svc in services).lower()

    if "Object Transfer" in services_bits and any(token in service_names for token in ("pbap", "map", "opp", "obex")):
        corroborated.append("Object Transfer")
    if "Networking" in services_bits and any(token in service_names for token in ("pan", "network", "dun")):
        corroborated.append("Networking")

    findings.append(
        _finding(
            "INFO",
            "Bluetooth Device Class Profile Posture",
            f"Device class reports major={cod.get('major', 'Unknown')} minor={cod.get('minor', 'Unknown')}.",
            status="confirmed",
            confidence="high",
            evidence=f"class={cod.get('raw', match.group(1))}; services={services_bits}",
            category="posture",
        )
    )

    if corroborated:
        findings.append(
            _finding(
                "INFO",
                "Device Class Corroborates Exposed Profiles",
                f"Device class service bits align with observed service exposure: {', '.join(corroborated)}.",
                status="confirmed",
                confidence="medium",
                evidence=f"corroborated_service_bits={corroborated}",
                category="posture",
            )
        )
    return findings


def check_lmp_features(address: str, hci: str, hcitool_info_result) -> list[dict]:
    findings: list[dict] = []
    result = hcitool_info_result
    if result is None or getattr(result, "returncode", 1) != 0:
        return findings

    match = re.search(r"Features:\s*(0x[0-9a-fA-F]+(?:\s+0x[0-9a-fA-F]+)*)", result.stdout)
    if not match:
        return findings

    raw_features = match.group(1)
    feature_bytes = []
    for bs in raw_features.split():
        try:
            feature_bytes.append(int(bs, 16))
        except ValueError:
            feature_bytes.append(0)
    while len(feature_bytes) < 8:
        feature_bytes.append(0)

    def has_bit(byte_idx: int, bit_idx: int) -> bool:
        return byte_idx < len(feature_bytes) and bool(feature_bytes[byte_idx] & (1 << bit_idx))

    findings.append(
        _finding(
            "INFO",
            "LMP Feature Summary",
            "Collected the target LMP feature bitmap for posture and prerequisite analysis.",
            status="confirmed",
            confidence="high",
            evidence=f"features={raw_features}",
            category="posture",
        )
    )

    if not has_bit(0, 2):
        findings.append(
            _finding(
                "CRITICAL",
                "LMP Posture: Encryption Not Supported",
                "Target feature bits indicate BR/EDR encryption support is absent.",
                impact="Traffic to the device may be fundamentally incapable of link-layer encryption.",
                remediation="Use hardware and firmware that support Bluetooth encryption.",
                status="confirmed",
                confidence="high",
                evidence=f"features={raw_features}; byte0.bit2=0",
                category="posture",
            )
        )

    if not has_bit(6, 3):
        findings.append(
            _finding(
                "HIGH",
                "LMP Posture: Secure Simple Pairing Absent",
                "Target feature bits do not advertise Secure Simple Pairing support.",
                impact="The target may rely on legacy pairing flows with weaker security properties.",
                remediation="Enable SSP-capable hardware and firmware where supported.",
                status="confirmed",
                confidence="high",
                evidence=f"features={raw_features}; byte6.bit3=0",
                category="posture",
            )
        )

    if not has_bit(7, 3):
        findings.append(
            _finding(
                "INFO",
                "LMP Posture: Secure Connections Absent",
                "Target does not advertise Secure Connections support.",
                status="confirmed",
                confidence="high",
                evidence=f"features={raw_features}; byte7.bit3=0",
                category="posture",
            )
        )

    if has_bit(0, 5):
        findings.append(
            _finding(
                "INFO",
                "LMP Capability: Role Switch Supported",
                "Role switch support is present. This is useful context for authentication-bypass research and BIAS applicability.",
                status="confirmed",
                confidence="medium",
                evidence=f"features={raw_features}; byte0.bit5=1",
                category="posture",
            )
        )

    if has_bit(5, 3):
        findings.append(
            _finding(
                "INFO",
                "LMP Capability: Pause Encryption Supported",
                "Pause encryption support is present. This is a prerequisite and posture signal for some downgrade attacks, but not a vulnerability by itself.",
                status="confirmed",
                confidence="medium",
                evidence=f"features={raw_features}; byte5.bit3=1",
                category="posture",
            )
        )

    return findings
