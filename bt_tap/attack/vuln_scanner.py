"""Bluetooth vulnerability and attack-surface scanner.

This scanner emphasizes evidence-based classification:
- confirmed: directly observed behavior
- potential: heuristic/version-based susceptibility
- unverified: requires active exploit testing

It avoids declaring definitive CVE exploitation unless direct evidence exists.
"""

import re

from bt_tap.recon.sdp import browse_services, check_ssp, get_raw_sdp
from bt_tap.recon.rfcomm_scan import RFCOMMScanner
from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.utils.output import (
    console,
    info,
    section,
    success,
    summary_panel,
    verbose,
    vuln_table,
    warning,
)


def _finding(
    severity: str,
    name: str,
    description: str,
    *,
    cve: str = "N/A",
    impact: str = "",
    remediation: str = "",
    status: str = "potential",
    confidence: str = "medium",
    evidence: str = "",
) -> dict:
    return {
        "severity": severity,
        "name": name,
        "description": description,
        "impact": impact,
        "cve": cve,
        "remediation": remediation,
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
    }


def _parse_bt_version(raw_version: str | None) -> float | None:
    if not raw_version:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)", raw_version)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _extract_lmp_version(address: str, hci: str) -> tuple[str | None, str]:
    """Return (raw_lmp_version, evidence)."""
    if not check_tool("hcitool"):
        return None, "hcitool not available"

    result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=12)
    if result.returncode != 0:
        return None, f"hcitool info failed: {result.stderr.strip()}"

    m = re.search(r"LMP Version:\s*(.+)", result.stdout)
    if not m:
        return None, "LMP Version not present in hcitool info output"

    raw = m.group(1).strip()
    return raw, f"LMP Version reported: {raw}"


def _check_service_exposure(address: str, services: list[dict]) -> list[dict]:
    """Actively probe sensitive RFCOMM services to determine reachability."""
    findings: list[dict] = []

    keywords = (
        "pbap",
        "phonebook",
        "map",
        "message",
        "object push",
        "file transfer",
    )

    targets = []
    for svc in services:
        name = svc.get("name", "")
        lname = name.lower()
        if not any(k in lname for k in keywords):
            continue
        if svc.get("protocol") != "RFCOMM":
            continue
        ch = svc.get("channel")
        if isinstance(ch, int):
            targets.append((name, ch))

    if not targets:
        return findings

    scanner = RFCOMMScanner(address)
    confirmed = []
    blocked = []

    for svc_name, ch in targets:
        probe = scanner.probe_channel(ch, timeout=2.0)
        if probe.get("status") == "open":
            confirmed.append((svc_name, ch, probe.get("response_type", "unknown")))
        else:
            blocked.append((svc_name, ch, probe.get("status", "closed")))

    if confirmed:
        desc = ", ".join(f"{n} (ch {c})" for n, c, _ in confirmed)
        evidence = "; ".join(
            f"{n}/ch{c}=open({r})" for n, c, r in confirmed
        )
        findings.append(
            _finding(
                "MEDIUM",
                "Sensitive RFCOMM Services Reachable",
                f"Sensitive services are actively reachable over RFCOMM: {desc}",
                impact="Data-access profiles may be reachable depending on target-side auth policy.",
                remediation="Require authentication/authorization before allowing profile operations.",
                status="confirmed",
                confidence="high",
                evidence=evidence,
            )
        )

    if blocked and not confirmed:
        evidence = "; ".join(f"{n}/ch{c}={s}" for n, c, s in blocked)
        findings.append(
            _finding(
                "INFO",
                "Sensitive Services Not Directly Reachable",
                "Sensitive services were advertised but RFCOMM probe did not confirm direct access.",
                status="confirmed",
                confidence="medium",
                evidence=evidence,
            )
        )

    return findings


def _check_knob(bt_version: float | None, raw_version: str | None) -> list[dict]:
    findings: list[dict] = []
    if bt_version is None:
        return findings

    if bt_version < 5.1:
        findings.append(
            _finding(
                "MEDIUM",
                "KNOB Susceptibility (CVE-2019-9506)",
                "Bluetooth version is in the potentially affected range (<5.1).",
                cve="CVE-2019-9506",
                impact="Potential key-length downgrade if target/host stack lacks patch-level mitigations.",
                remediation="Validate vendor patch level and enforce minimum encryption key length.",
                status="potential",
                confidence="low",
                evidence=f"Version heuristic from LMP Version: {raw_version}",
            )
        )
    return findings


def _check_blurtooth(bt_version: float | None, raw_version: str | None) -> list[dict]:
    findings: list[dict] = []
    if bt_version is None:
        return findings

    if 4.2 <= bt_version <= 5.0:
        findings.append(
            _finding(
                "MEDIUM",
                "BLURtooth Susceptibility (CVE-2020-15802)",
                "Bluetooth version is in the commonly affected CTKD range (4.2 to 5.0).",
                cve="CVE-2020-15802",
                impact="Potential cross-transport key overwrite depending on stack behavior and patch level.",
                remediation="Confirm CTKD hardening in vendor stack updates.",
                status="potential",
                confidence="low",
                evidence=f"Version heuristic from LMP Version: {raw_version}",
            )
        )
    return findings


def _check_bias(ssp: bool | None) -> list[dict]:
    findings: list[dict] = []
    if ssp is False:
        return findings

    findings.append(
        _finding(
            "INFO",
            "BIAS Requires Active Validation (CVE-2020-10135)",
            "BIAS cannot be confirmed from passive metadata. Active role-switch/auth testing is required.",
            cve="CVE-2020-10135",
            remediation="Run active BIAS test tooling and verify vendor patch level.",
            status="unverified",
            confidence="low",
            evidence=f"SSP probe result: {ssp}",
        )
    )
    return findings


def _check_blueborne(address: str) -> list[dict]:
    findings: list[dict] = []
    raw_sdp = get_raw_sdp(address)
    if "BlueZ" not in raw_sdp:
        return findings

    m = re.search(r"BlueZ\s+(\d+\.\d+)", raw_sdp)
    if not m:
        return findings

    try:
        bluez_ver = float(m.group(1))
    except ValueError:
        return findings

    if bluez_ver < 5.47:
        findings.append(
            _finding(
                "HIGH",
                "BlueBorne Susceptibility Indicator (CVE-2017-1000251)",
                "Observed BlueZ version string appears older than 5.47.",
                cve="CVE-2017-1000251",
                impact="Potential legacy BlueBorne exposure if this BlueZ version is authoritative for the target stack.",
                remediation="Verify actual stack version and backported patches; update vendor firmware.",
                status="potential",
                confidence="medium",
                evidence=f"SDP contains BlueZ {m.group(1)}",
            )
        )
    return findings


def _check_pairing_method(address: str, hci: str) -> list[dict]:
    findings: list[dict] = []
    try:
        from bt_tap.recon.hci_capture import detect_pairing_mode

        mode = detect_pairing_mode(address, hci)
        method = mode.get("pairing_method", "Unknown")
        if method == "Just Works":
            findings.append(
                _finding(
                    "MEDIUM",
                    "Just Works Pairing Observed",
                    "Pairing method resolved to Just Works (no MITM confirmation).",
                    impact="Susceptible to machine-in-the-middle during pairing under appropriate conditions.",
                    remediation="Prefer Numeric Comparison / Passkey with user confirmation.",
                    status="confirmed",
                    confidence="medium",
                    evidence=f"Pairing probe result: {method}",
                )
            )
        elif method != "Unknown":
            findings.append(
                _finding(
                    "INFO",
                    "Pairing Method Identified",
                    f"Pairing method observed: {method}",
                    status="confirmed",
                    confidence="medium",
                    evidence=f"Pairing probe result: {method}",
                )
            )
    except Exception as exc:
        verbose(f"Pairing mode probe unavailable: {exc}")

    return findings


def _check_writable_gatt(address: str) -> list[dict]:
    findings: list[dict] = []
    try:
        from bt_tap.recon.gatt import enumerate_services_sync

        services = enumerate_services_sync(address)
    except Exception as exc:
        verbose(f"GATT enumeration unavailable: {exc}")
        return findings

    writable = []
    for svc in services:
        for char in svc.get("characteristics", []):
            props = {p.lower() for p in char.get("properties", [])}
            if "write" in props or "write-without-response" in props:
                writable.append(
                    {
                        "service": svc.get("description", "Unknown"),
                        "char": char.get("description", "Unknown"),
                        "uuid": char.get("uuid", ""),
                        "props": sorted(props),
                    }
                )

    if writable:
        sample = ", ".join(f"{w['char']} ({w['uuid']})" for w in writable[:5])
        findings.append(
            _finding(
                "INFO",
                "Writable GATT Characteristics Present",
                f"Found {len(writable)} writable characteristic(s). Sample: {sample}",
                impact="Writable characteristics increase attack surface; exploitability depends on authz and value validation.",
                remediation="Require authentication and strict value validation for sensitive writes.",
                status="confirmed",
                confidence="medium",
                evidence=f"Enumerated writable GATT chars: {len(writable)}",
            )
        )

    return findings


def scan_vulnerabilities(address: str, hci: str = "hci0") -> list[dict]:
    """Run vulnerability and attack-surface checks against a target.

    Output is evidence-based and intentionally avoids definitive CVE claims
    without active exploit verification.
    """
    info(f"Scanning {address} for vulnerabilities and attack-surface indicators...")
    findings: list[dict] = []

    section("Check 1: Secure Simple Pairing", style="bt.cyan")
    ssp = check_ssp(address)
    if ssp is False:
        findings.append(
            _finding(
                "MEDIUM",
                "Legacy Pairing Indicator (No SSP Advertised)",
                "Target did not advertise Secure Simple Pairing in SDP output.",
                impact="May rely on legacy pairing workflows, depending on target implementation.",
                remediation="Verify pairing policy and require SSP-capable pairing modes.",
                status="potential",
                confidence="medium",
                evidence="SDP browse output did not include SSP markers",
            )
        )
        warning("SSP not advertised; possible legacy pairing behavior")
    elif ssp is True:
        success("SSP support advertised")
    else:
        warning("Could not determine SSP support")

    section("Check 2: Service Exposure", style="bt.cyan")
    services = browse_services(address)
    findings.extend(_check_service_exposure(address, services))

    section("Check 3: Reachability", style="bt.cyan")
    if check_tool("l2ping"):
        l2ping = run_cmd(["l2ping", "-c", "3", "-t", "5", address], timeout=20)
        if l2ping.returncode == 0:
            lines = l2ping.stdout.strip().splitlines()
            info(f"Device is L2CAP reachable: {lines[-1] if lines else '(no output)'}")
        else:
            warning("L2CAP ping failed - out of range, blocked, or unavailable")
    else:
        warning("l2ping not available; skipping reachability probe")

    section("Check 4: Version-Derived CVE Heuristics", style="bt.cyan")
    raw_version, ver_evidence = _extract_lmp_version(address, hci)
    bt_version = _parse_bt_version(raw_version)
    if raw_version:
        info(f"LMP Version: {raw_version}")
    else:
        warning(f"Bluetooth version unavailable ({ver_evidence})")

    findings.extend(_check_knob(bt_version, raw_version))
    findings.extend(_check_blurtooth(bt_version, raw_version))
    findings.extend(_check_bias(ssp))
    findings.extend(_check_blueborne(address))

    section("Check 5: Pairing Method Probe", style="bt.cyan")
    findings.extend(_check_pairing_method(address, hci))

    section("Check 6: BLE Writable Surface", style="bt.cyan")
    findings.extend(_check_writable_gatt(address))

    _print_findings(address, findings)
    return findings


def _print_findings(address: str, findings: list[dict]):
    """Print vulnerability findings summary with evidence quality context."""
    console.print()
    if not findings:
        success(f"No indicators found on {address} from available checks")
        return

    console.print(vuln_table(findings))

    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    potential = sum(1 for f in findings if f.get("status") == "potential")
    unverified = sum(1 for f in findings if f.get("status") == "unverified")
    high = sum(1 for f in findings if f.get("severity", "").lower() in ("high", "critical"))

    summary_panel(
        "Vulnerability Scan Summary",
        {
            "Target": address,
            "Total Findings": str(len(findings)),
            "Confirmed": str(confirmed),
            "Potential": str(potential),
            "Unverified": str(unverified),
            "Critical/High Severity": str(high),
        },
        style="red" if high > 0 else "yellow" if potential > 0 else "green",
    )
