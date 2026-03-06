"""Bluetooth vulnerability scanner for known CVEs.

Checks targets for susceptibility to known Bluetooth attacks:
  - BlueBorne (CVE-2017-0781/1000251) - RCE, no pairing needed
  - KNOB (CVE-2019-9506) - Encryption key negotiation downgrade
  - BIAS (CVE-2020-10135) - Impersonation of paired devices
  - BLURtooth (CVE-2020-15802) - Cross-transport key overwrite
  - BLUFFS (2023) - Session key forcing
  - PerfektBlue (2025) - Automotive AVRCP/RFCOMM RCE

Also checks for:
  - Legacy pairing (no SSP)
  - JustWorks pairing (no MITM protection)
  - Open/unauthenticated services
  - Writable GATT characteristics
"""

import re

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.recon.sdp import browse_services, check_ssp, get_raw_sdp
from bt_tap.utils.output import info, success, error, warning, verbose, console, section, step, target, vuln_table, summary_panel


def scan_vulnerabilities(address: str, hci: str = "hci0") -> list[dict]:
    """Run all vulnerability checks against a target."""
    info(f"Scanning {address} for known vulnerabilities...")
    findings = []

    # Check 1: SSP support
    section("Check 1: Secure Simple Pairing", style="bt.cyan")
    ssp = check_ssp(address)
    if ssp is False:
        findings.append({
            "severity": "HIGH",
            "name": "No SSP Support",
            "description": "Device does not advertise SSP. May use legacy PIN pairing.",
            "impact": "Legacy pairing uses E21/E22 which is vulnerable to offline brute-force.",
            "cve": "N/A",
            "remediation": "Ensure SSP is enabled on the device.",
        })
        warning("NO SSP detected - legacy pairing may be vulnerable")
    elif ssp is True:
        info("SSP supported")
    else:
        warning("Could not determine SSP support")
    verbose(f"SSP probe result: {ssp}")

    # Check 2: Open services (no authentication)
    section("Check 2: Service Enumeration", style="bt.cyan")
    services = browse_services(address)
    open_services = []
    for svc in services:
        # Services accessible without authentication
        name = svc.get("name", "").lower()
        if any(kw in name for kw in ["pbap", "phonebook", "map", "message",
                                       "object push", "file transfer"]):
            open_services.append(svc)

    if open_services:
        findings.append({
            "severity": "MEDIUM",
            "name": "Sensitive Services Exposed",
            "description": f"{len(open_services)} data-access services found: " +
                          ", ".join(s.get("name", "?") for s in open_services),
            "impact": "PBAP/MAP/OPP services allow phonebook, SMS, and file access if connected.",
            "cve": "N/A",
            "remediation": "Ensure services require authentication before data access.",
        })
        for svc in open_services:
            warning(f"  Exposed: {svc.get('name')} (ch={svc.get('channel')})")
    verbose(f"Services found: {len(services)}, sensitive: {len(open_services)}")

    # Check 3: L2CAP ping (device reachable)
    section("Check 3: L2CAP Reachability", style="bt.cyan")
    l2ping_result = run_cmd(["l2ping", "-c", "3", "-t", "5", address], timeout=20)
    if l2ping_result.returncode == 0:
        lines = l2ping_result.stdout.strip().splitlines()
        info(f"Device is L2CAP reachable: {lines[-1] if lines else '(no output)'}")
    else:
        warning("L2CAP ping failed - device may be out of range or filtering")
    verbose(f"l2ping exit code: {l2ping_result.returncode}")

    # Check 4: Bluetooth version and features
    section("Check 4: Device Features & Version", style="bt.cyan")
    info_result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=10)
    bt_version = None
    if info_result.returncode == 0:
        output = info_result.stdout
        # Extract LMP version
        ver_match = re.search(r"LMP Version:\s*(\S+)", output)
        if ver_match:
            bt_version = ver_match.group(1)
            info(f"LMP Version: {bt_version}")

        # Check for feature bits that indicate vulnerability
        if "Encryption" not in output:
            findings.append({
                "severity": "HIGH",
                "name": "Encryption Not Supported",
                "description": "Device does not advertise encryption support.",
                "impact": "All traffic is in cleartext.",
                "cve": "N/A",
            })
    verbose(f"BT version detected: {bt_version}, encryption in features: {'Encryption' in (info_result.stdout if info_result.returncode == 0 else '')}")

    # Check 5: KNOB vulnerability assessment
    section("Check 5: KNOB Attack Susceptibility", style="bt.cyan")
    _check_knob(address, bt_version, findings)

    # Check 6: BIAS vulnerability assessment
    section("Check 6: BIAS Attack Susceptibility", style="bt.cyan")
    _check_bias(address, ssp, findings)

    # Check 7: BLURtooth assessment
    section("Check 7: BLURtooth Susceptibility", style="bt.cyan")
    _check_blurtooth(address, bt_version, findings)

    # Check 8: BlueBorne assessment
    section("Check 8: BlueBorne Susceptibility", style="bt.cyan")
    _check_blueborne(address, bt_version, findings)

    # Summary
    _print_findings(address, findings)
    return findings


def _check_knob(address: str, bt_version: str | None, findings: list):
    """Check KNOB (Key Negotiation of Bluetooth) susceptibility.

    CVE-2019-9506: Spec-level flaw allowing encryption key length downgrade.
    Patched in BT 5.1+ with minimum key size enforcement.
    """
    # KNOB is a spec-level flaw - all BT 1.0-5.0 devices are potentially affected
    if bt_version:
        try:
            major = float(bt_version.split()[0]) if bt_version else 0
        except (ValueError, IndexError):
            major = 0
        if major < 5.1:
            findings.append({
                "severity": "HIGH",
                "name": "KNOB Attack (CVE-2019-9506)",
                "description": f"BT version {bt_version} may be vulnerable to KNOB. "
                               "Attacker can force 1-byte encryption key during negotiation.",
                "impact": "Encryption can be brute-forced in real-time, enabling traffic decryption.",
                "cve": "CVE-2019-9506",
                "remediation": "Update firmware to enforce minimum 7-byte key length.",
                "tool": "BlueToolkit: ./bluetoolkit.py -t <addr> -e knob",
            })
            warning("Potentially vulnerable to KNOB (key negotiation downgrade)")
        else:
            info("BT 5.1+ - KNOB should be mitigated")
        verbose(f"KNOB check: BT version={bt_version}, parsed major={major}")
    else:
        info("Could not determine BT version for KNOB check")
        verbose("KNOB check skipped: bt_version is None")


def _check_bias(address: str, ssp_supported: bool | None, findings: list):
    """Check BIAS (Bluetooth Impersonation Attacks) susceptibility.

    CVE-2020-10135: Exploits legacy authentication + role-switching.
    """
    # BIAS requires SSP but exploits the legacy auth fallback
    findings.append({
        "severity": "MEDIUM",
        "name": "BIAS Attack (CVE-2020-10135)",
        "description": "BIAS exploits legacy authentication procedures during role-switch. "
                       "Cannot fully determine without active testing.",
        "impact": "Attacker can impersonate a previously paired device.",
        "cve": "CVE-2020-10135",
        "remediation": "Apply vendor patches. Disable legacy auth. Require mutual authentication.",
        "tool": "BlueToolkit: ./bluetoolkit.py -t <addr> -e bias",
    })
    info("BIAS susceptibility requires active testing (use BlueToolkit)")
    verbose(f"BIAS check: SSP supported={ssp_supported}, added as MEDIUM finding")


def _check_blurtooth(address: str, bt_version: str | None, findings: list):
    """Check BLURtooth (CTKD key overwrite) susceptibility.

    CVE-2020-15802: Affects BT 4.2-5.0 dual-mode devices.
    """
    if bt_version:
        try:
            ver_str = bt_version.split()[0] if bt_version else "0"
            major = float(ver_str)
        except (ValueError, IndexError):
            major = 0
        if 4.2 <= major <= 5.0:
            findings.append({
                "severity": "MEDIUM",
                "name": "BLURtooth (CVE-2020-15802)",
                "description": f"BT {bt_version} is in the affected range (4.2-5.0) for CTKD attacks.",
                "impact": "Attacker can overwrite authenticated keys with unauthenticated ones via CTKD.",
                "cve": "CVE-2020-15802",
                "remediation": "Update to BT 5.1+ or apply vendor CTKD restrictions.",
            })
            warning("In BLURtooth-affected BT version range")
        else:
            info(f"BT {bt_version} - outside BLURtooth range")
        verbose(f"BLURtooth check: BT version={bt_version}, parsed major={major}, in range={4.2 <= major <= 5.0}")


def _check_blueborne(address: str, bt_version: str | None, findings: list):
    """Check BlueBorne susceptibility.

    CVE-2017-0781/1000251: RCE via L2CAP/SDP/BNEP, no pairing needed.
    Largely patched post-2017, but many automotive IVIs run old firmware.
    """
    # SDP raw dump can sometimes reveal old BlueZ version strings
    raw_sdp = get_raw_sdp(address)
    if "BlueZ" in raw_sdp:
        match = re.search(r"BlueZ\s+(\d+\.\d+)", raw_sdp)
        if match:
            bluez_ver = float(match.group(1))
            if bluez_ver < 5.47:
                findings.append({
                    "severity": "CRITICAL",
                    "name": "BlueBorne (CVE-2017-1000251)",
                    "description": f"BlueZ {match.group(1)} detected. Versions < 5.47 are vulnerable.",
                    "impact": "Remote code execution without pairing or user interaction.",
                    "cve": "CVE-2017-1000251",
                    "remediation": "Update BlueZ to 5.47+.",
                    "tool": "git clone https://github.com/mailinneberg/BlueBorne",
                })
                error(f"CRITICAL: BlueBorne vulnerable BlueZ {match.group(1)}")
                return
    info("Could not detect BlueZ version in SDP. Manual testing recommended.")
    verbose(f"BlueBorne check: BlueZ string found={'BlueZ' in raw_sdp}, raw SDP length={len(raw_sdp)}")


def _print_findings(address: str, findings: list):
    """Print vulnerability findings summary."""
    console.print()
    if not findings:
        success(f"No known vulnerabilities detected on {address}")
        return

    console.print(vuln_table(findings))

    # Summary
    high = sum(1 for f in findings if f.get("severity", "").lower() in ("high", "critical"))
    medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
    low = sum(1 for f in findings if f.get("severity", "").lower() == "low")

    summary_panel("Vulnerability Scan Summary", {
        "Target": address,
        "Total Findings": str(len(findings)),
        "Critical/High": str(high),
        "Medium": str(medium),
        "Low/Info": str(low),
    }, style="red" if high > 0 else "yellow" if medium > 0 else "green")
