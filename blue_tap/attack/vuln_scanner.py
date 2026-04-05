"""Bluetooth vulnerability and attack-surface scanner.

This scanner emphasizes evidence-based classification:
- confirmed: directly observed behavior
- potential: heuristic/version-based susceptibility
- unverified: requires active exploit testing

It avoids declaring definitive CVE exploitation unless direct evidence exists.
"""

import errno
import re
import socket
import struct

from blue_tap.recon.sdp import browse_services, check_ssp, get_raw_sdp
from blue_tap.recon.rfcomm_scan import RFCOMMScanner
from blue_tap.utils.bt_helpers import run_cmd, check_tool
from blue_tap.utils.output import (
    console,
    error,
    info,
    section,
    success,
    summary_panel,
    verbose,
    vuln_table,
    warning,
)

# Timeout constants (seconds) — tune these for your environment
HCITOOL_TIMEOUT = 12       # hcitool info/name commands
SDP_BROWSE_TIMEOUT = 30    # sdptool browse
RFCOMM_PROBE_TIMEOUT = 2.0 # RFCOMM channel connect probes
L2CAP_PROBE_TIMEOUT = 3.0  # L2CAP PSM connect probes
OBEX_PROBE_TIMEOUT = 4.0   # OBEX authorization probes
ENCRYPTION_TIMEOUT = 4.0   # Encryption enforcement checks
AT_PROBE_TIMEOUT = 2.0     # Automotive AT command probes


def _run_hcitool_info(address: str, hci: str = "hci0"):
    """Run hcitool info with retry on transient failure."""
    result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=HCITOOL_TIMEOUT)
    if result.returncode != 0:
        # Retry once on transient failures
        stderr = result.stderr.lower()
        if any(hint in stderr for hint in ("timeout", "resource temporarily", "reset")):
            verbose("hcitool info failed transiently, retrying...")
            import time
            time.sleep(1)
            result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=HCITOOL_TIMEOUT)
    return result


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

    result = _run_hcitool_info(address, hci)
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
        probe = scanner.probe_channel(ch, timeout=RFCOMM_PROBE_TIMEOUT)
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


def _check_darkfirmware_available(hci: str = "hci0") -> bool:
    """Check if DarkFirmware is available for enhanced vulnerability probing."""
    try:
        from blue_tap.core.firmware import DarkFirmwareManager
        return DarkFirmwareManager().is_darkfirmware_loaded(hci)
    except Exception:
        return False


def _check_knob(bt_version: float | None, raw_version: str | None,
                lmp_features: dict | None = None) -> list[dict]:
    """KNOB (CVE-2019-9506): LMP key size negotiation downgrade.

    Detection approach:
      1. Version heuristic: LMP < 5.1 means spec didn't mandate min key size
      2. LMP feature check: if pause_encryption is supported, KNOB is easier
         (attacker can pause/resume encryption to re-negotiate key size)
      3. Spec fix (BT 5.3): HCI_Set_Min_Encryption_Key_Size command added

    What we CANNOT detect: whether the vendor firmware independently enforces
    min key size (many did post-2019 via firmware patches, regardless of BT ver).
    """
    findings: list[dict] = []
    if bt_version is None:
        return findings

    evidence_parts = [f"LMP Version: {raw_version}"]

    if bt_version < 5.1:
        severity = "MEDIUM"
        # Upgrade severity if pause_encryption is supported (easier to exploit)
        if lmp_features and lmp_features.get("pause_encryption"):
            severity = "HIGH"
            evidence_parts.append("pause_encryption feature enabled (KNOB prerequisite)")

        findings.append(
            _finding(
                severity,
                "KNOB Susceptibility (CVE-2019-9506)",
                f"BT {bt_version} < 5.1: spec permitted 1-byte encryption key size. "
                f"MitM at baseband can rewrite LMP_encryption_key_size_req to force "
                f"key entropy to 8 bits (brute-forcible in real-time). "
                f"{'Pause_encryption enabled increases exploitability.' if severity == 'HIGH' else ''}"
                f"Many vendors patched independently — verify firmware patch level.",
                cve="CVE-2019-9506",
                impact="Complete traffic decryption and injection on BR/EDR connections. "
                       "CVSS 8.1. Requires baseband MitM (USRP/HackRF).",
                remediation="Update firmware to enforce min 7-byte key size. "
                            "BT 5.3+ adds HCI_Set_Min_Encryption_Key_Size. "
                            "Verify with vendor if pre-5.3 firmware has backported fix.",
                status="potential",
                confidence="low",
                evidence="; ".join(evidence_parts),
            )
        )
    return findings


def _check_blurtooth(bt_version: float | None, raw_version: str | None,
                      lmp_features: dict | None = None) -> list[dict]:
    """BLURtooth (CVE-2020-15802): Cross-Transport Key Derivation overwrite.

    Detection approach:
      1. Version heuristic: BT 4.2-5.0 supports CTKD without key strength check
      2. LMP feature check: le_and_bredr (dual-mode) is required for CTKD
      3. Protocol indicator: SMP BR/EDR fixed channel (L2CAP CID 0x0007) presence
         means the device accepts cross-transport SMP — CTKD attack surface exists

    What we CANNOT detect: whether the stack compares key strength before
    overwrite (the actual fix introduced in BT 5.1).
    """
    findings: list[dict] = []
    if bt_version is None:
        return findings

    if 4.2 <= bt_version <= 5.0:
        evidence_parts = [f"LMP Version: {raw_version}"]
        confidence = "low"

        # If dual-mode is confirmed, CTKD is architecturally possible
        if lmp_features and lmp_features.get("le_and_bredr"):
            evidence_parts.append("Dual-mode (LE+BR/EDR) confirmed — CTKD architecturally possible")
            confidence = "medium"

        findings.append(
            _finding(
                "MEDIUM",
                "BLURtooth / CTKD Susceptibility (CVE-2020-15802)",
                f"BT {bt_version} in range 4.2-5.0: CTKD can overwrite stronger BR/EDR link key "
                f"with weaker BLE-derived key. Attacker pairs via BLE Just Works, derived key "
                f"overwrites existing BR/EDR key without strength comparison.",
                cve="CVE-2020-15802",
                impact="Attacker gains BR/EDR service access (PBAP/MAP/HFP) by pairing "
                       "via weak BLE Just Works. CVSS 5.9.",
                remediation="Update to BT 5.1+ which mandates key strength comparison "
                            "before CTKD overwrite. Disable CTKD if not needed.",
                status="potential",
                confidence=confidence,
                evidence="; ".join(evidence_parts),
            )
        )
    return findings


def _check_perfektblue(address: str, services: list[dict],
                        device_name: str = "", manufacturer: str = "",
                        sdp_raw: str = "") -> list[dict]:
    """PerfektBlue (CVE-2024-45431/32/33/34): OpenSynergy BlueSDK vulns.

    Detection approach:
      1. Manufacturer/name matching: VW, Audi, Skoda, Seat, Mercedes, Daimler
      2. SDP provider string: "OpenSynergy" or "BlueSDK" in SDP output
      3. Active probe: L2CAP channel with CID=0 — OpenSynergy BlueSDK accepts
         invalid CID (CVE-2024-45431) while spec-compliant stacks reject it.
         This is a non-destructive detection method.
      4. AVRCP service presence: CVE-2024-45434 (UAF) requires AVRCP

    What we CANNOT detect without crash risk: CVE-2024-45434 (AVRCP UAF),
    CVE-2024-45433 (RFCOMM termination). These require triggering the bug.
    """
    findings: list[dict] = []

    # Build context for matching
    combined = f"{device_name} {manufacturer} {sdp_raw}".lower()
    bluesdk_manufacturers = ["volkswagen", "vw", "audi", "skoda", "seat", "cupra",
                             "mercedes", "daimler", "stellantis"]

    is_suspect = any(m in combined for m in bluesdk_manufacturers)
    is_confirmed_stack = any(s in combined for s in ["opensynergy", "bluesdk", "blue sdk"])

    if not is_suspect and not is_confirmed_stack:
        return findings

    evidence_parts = []
    if is_confirmed_stack:
        evidence_parts.append("OpenSynergy/BlueSDK string found in SDP")
    if is_suspect:
        matched = [m for m in bluesdk_manufacturers if m in combined]
        evidence_parts.append(f"Manufacturer matches known BlueSDK users: {matched}")

    has_avrcp = any("avrcp" in str(s).lower() or "a/v remote" in str(s).lower()
                     for s in services)
    if has_avrcp:
        evidence_parts.append("AVRCP service present (CVE-2024-45434 target)")

    # Flag the chain
    severity = "HIGH" if is_confirmed_stack else "MEDIUM"
    confidence = "medium" if is_confirmed_stack else "low"

    findings.append(
        _finding(
            severity,
            "PerfektBlue: OpenSynergy BlueSDK Vulnerability Chain",
            "Target matches OpenSynergy BlueSDK indicators. PerfektBlue is a chain of "
            "4 CVEs (CVSS 3.5-8.0) enabling 1-click RCE on IVI after pairing. "
            "Affects 350M+ vehicles. CVE-2024-45434 (AVRCP UAF, CVSS 8.0) is the "
            "most critical. Patches released Sept 2024 but supply chain delays apply.",
            cve="CVE-2024-45434",
            impact="Remote code execution on IVI. Access GPS, microphone, contacts. "
                   "Lateral movement to other vehicle systems possible.",
            remediation="Verify IVI firmware updated after Sept 2024. Contact vehicle "
                        "manufacturer for BlueSDK patch status.",
            status="potential",
            confidence=confidence,
            evidence="; ".join(evidence_parts),
        )
    )

    return findings


def _check_bluffs(bt_version: float | None, raw_version: str | None) -> list[dict]:
    """BLUFFS (CVE-2023-24023): Session key derivation attacks.

    Detection approach:
      1. Version heuristic: BT < 5.4 lacks the spec fixes for session key
         derivation introduced in BT Core Spec Addendum 6 (CSA6)
      2. BLUFFS enables an attacker within Bluetooth range to force the
         establishment of weak session keys, breaking both forward and
         future secrecy guarantees

    What we CANNOT detect: whether the vendor has independently backported
    the CSA6 mitigations (session key diversification) to older firmware.
    """
    findings: list[dict] = []
    if bt_version is None:
        return findings

    if bt_version < 5.4:
        findings.append(
            _finding(
                "MEDIUM",
                "BLUFFS Session Key Derivation (CVE-2023-24023)",
                f"Bluetooth version {bt_version} < 5.4 is susceptible to BLUFFS "
                f"session key derivation attacks (CVE-2023-24023). An attacker "
                f"within Bluetooth range could force the establishment of weak "
                f"session keys, breaking forward and future secrecy.",
                cve="CVE-2023-24023",
                impact="Session key compromise allows decryption of past and "
                       "future traffic if the attacker captures encrypted frames.",
                remediation="Update to BT 5.4+ firmware or apply vendor patches "
                            "addressing CVE-2023-24023.",
                status="potential",
                confidence="low",
                evidence=f"LMP Version: {raw_version}",
            )
        )
    return findings


def _check_pin_pairing_bypass(bt_version: float | None, raw_version: str | None,
                               ssp: bool | None) -> list[dict]:
    """CVE-2020-26555: BR/EDR PIN code pairing authentication bypass.

    Detection: If SSP is NOT in LMP features AND BT version <= 5.2,
    the device uses legacy PIN pairing which is vulnerable to BD_ADDR
    spoofing-based auth bypass (complete pairing without knowing PIN).

    This is a spec-level flaw: the entire PIN-based pairing mechanism is
    fundamentally broken if the attacker can spoof the BD_ADDR.
    """
    findings: list[dict] = []

    if ssp is False and bt_version is not None and bt_version <= 5.2:
        findings.append(
            _finding(
                "HIGH",
                "Legacy PIN Pairing Auth Bypass (CVE-2020-26555)",
                "Device lacks SSP and uses legacy PIN-based pairing (BT Core 1.0B-5.2). "
                "An attacker can spoof the BD_ADDR of a peer device and complete pairing "
                "without knowledge of the PIN code. This is a specification-level flaw.",
                cve="CVE-2020-26555",
                impact="Complete pairing bypass. Attacker can pair with IVI as any device.",
                remediation="Enable SSP (Secure Simple Pairing). Legacy PIN pairing is "
                            "fundamentally broken and should not be used.",
                status="confirmed" if ssp is False else "potential",
                confidence="high" if ssp is False else "medium",
                evidence=f"SSP={ssp}, LMP Version: {raw_version}",
            )
        )
    return findings


def _check_invalid_curve(bt_version: float | None, raw_version: str | None,
                          lmp_features: dict | None = None) -> list[dict]:
    """CVE-2018-5383: Invalid ECDH public key validation during SSP.

    Detection: BT < 5.1 with SSP present. The spec didn't mandate validating
    that the peer's ECDH public key lies on the P-256 curve. An attacker
    performing MitM during pairing can inject an invalid public key to
    recover the shared secret.

    We CANNOT actively test this without performing a full pairing with
    a crafted invalid key — which would be destructive. Version heuristic only.
    """
    findings: list[dict] = []
    if bt_version is None:
        return findings

    ssp_present = lmp_features.get("ssp", False) if lmp_features else None

    if bt_version < 5.1 and ssp_present:
        findings.append(
            _finding(
                "MEDIUM",
                "Invalid Curve Attack Susceptibility (CVE-2018-5383)",
                "BT < 5.1 with SSP: spec did not mandate ECDH public key point validation. "
                "Attacker performing MitM during SSP pairing can inject invalid P-256 "
                "coordinates to recover the Diffie-Hellman shared secret.",
                cve="CVE-2018-5383",
                impact="MitM during pairing. Recover link key from intercepted SSP exchange. "
                       "CVSS 7.1.",
                remediation="Update firmware to validate ECDH public key coordinates on curve. "
                            "Fixed in BT 5.1+ spec.",
                status="potential",
                confidence="low",
                evidence=f"LMP Version: {raw_version}, SSP={ssp_present}",
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


def _check_bias_active(address: str, hci: str, ssp: bool | None,
                       phone_address: str | None = None) -> list[dict]:
    """Actively probe for BIAS vulnerability (CVE-2020-10135).

    This is invasive: temporarily spoofs adapter MAC and identity,
    then tests if the target auto-reconnects.

    Args:
        phone_address: MAC of the phone paired with the target. Required for
            the auto-reconnect test — without it, we can still check SSP/version
            but cannot test whether the IVI reconnects to a spoofed identity.
    """
    findings = []

    if ssp is False:
        findings.append(_finding(
            "info", "BIAS probe skipped (no SSP)",
            "Device does not support SSP — BIAS attack targets SSP authentication. "
            "Legacy pairing has its own weaknesses (see PIN bypass check).",
            cve="CVE-2020-10135",
            status="unverified",
            confidence="high",
        ))
        return findings

    if not phone_address:
        findings.append(_finding(
            "info", "BIAS auto-reconnect test skipped (no phone address)",
            "Active BIAS probe requires the paired phone's MAC address to test "
            "auto-reconnection. Use --phone <MAC> or select interactively. "
            "SSP and version checks were still performed in the passive scan.",
            cve="CVE-2020-10135",
            status="unverified",
            confidence="low",
        ))
        return findings

    try:
        from blue_tap.attack.bias import BIASAttack

        info(f"Running active BIAS probe (spoofing as phone {phone_address})...")
        attack = BIASAttack(address, phone_address, "Phone", hci)
        result = attack.probe_vulnerability()

        if result.get("auto_reconnects"):
            findings.append(_finding(
                "critical",
                "BIAS: Auto-reconnection to spoofed identity (CVE-2020-10135)",
                f"Target auto-reconnected to a spoofed identity within 15 seconds. "
                f"This confirms the BIAS vulnerability — an attacker can impersonate "
                f"the paired phone and gain full access without re-pairing.",
                cve="CVE-2020-10135",
                impact="Complete authentication bypass. Attacker can connect as the "
                       "paired phone and access all profiles (PBAP, MAP, HFP, A2DP).",
                remediation="Update IVI firmware to enforce mutual authentication. "
                           "Disable auto-reconnect for paired devices if possible.",
                status="confirmed",
                confidence="high",
                evidence=f"Auto-reconnect detected. SSP: {result.get('ssp_supported')}, "
                         f"BT version: {result.get('bt_version')}",
            ))
        elif result.get("ssp_supported") is False:
            findings.append(_finding(
                "high",
                "BIAS: SSP not enforced (CVE-2020-10135)",
                "Target does not enforce SSP — legacy pairing can be exploited "
                "for authentication bypass via role-switch.",
                cve="CVE-2020-10135",
                impact="Authentication bypass possible via role-switch attack.",
                remediation="Enable and enforce SSP on the target device.",
                status="potential",
                confidence="medium",
                evidence=f"SSP supported: {result.get('ssp_supported')}, "
                         f"BT version: {result.get('bt_version')}",
            ))
        else:
            findings.append(_finding(
                "medium",
                "BIAS: Active probe inconclusive (CVE-2020-10135)",
                "Active BIAS probe completed but target did not auto-reconnect "
                "within the test window. May still be vulnerable with different timing.",
                cve="CVE-2020-10135",
                status="potential",
                confidence="low",
                evidence=f"No auto-reconnect in 15s. SSP: {result.get('ssp_supported')}, "
                         f"BT version: {result.get('bt_version')}",
            ))
    except ImportError:
        findings.append(_finding(
            "info", "BIAS active probe unavailable",
            "Could not import BIAS attack module.",
            cve="CVE-2020-10135",
            status="unverified",
            confidence="low",
        ))
    except Exception as e:
        warning(f"BIAS active probe failed: {e}")
        findings.append(_finding(
            "info", "BIAS active probe failed",
            f"Active probe encountered an error: {e}. "
            "The device may still be vulnerable — try manual testing.",
            cve="CVE-2020-10135",
            status="unverified",
            confidence="low",
        ))

    return findings


def _check_blueborne(address: str) -> list[dict]:
    findings: list[dict] = []

    # Primary: try bluetoothd --version (more reliable than SDP strings)
    btd_result = run_cmd(["bluetoothd", "--version"], timeout=5)
    bluez_version = None
    version_source = ""
    if btd_result.returncode == 0:
        ver_match = re.search(r"(\d+\.\d+)", btd_result.stdout)
        if ver_match:
            bluez_version = ver_match.group(1)
            version_source = f"bluetoothd --version reported {bluez_version}"

    # Fallback: parse SDP output for BlueZ version string
    if bluez_version is None:
        raw_sdp = get_raw_sdp(address)
        if "BlueZ" in raw_sdp:
            m = re.search(r"BlueZ\s+(\d+\.\d+)", raw_sdp)
            if m:
                bluez_version = m.group(1)
                version_source = f"SDP contains BlueZ {bluez_version}"

    if bluez_version:
        try:
            bluez_ver = float(bluez_version)
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
                    evidence=version_source,
                )
            )
    return findings


def _check_pairing_method(address: str, hci: str) -> list[dict]:
    findings: list[dict] = []
    try:
        from blue_tap.recon.hci_capture import detect_pairing_mode

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
        from blue_tap.recon.gatt import enumerate_services_sync

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


# Known BrakTooth-vulnerable chipset manufacturers/keywords
_BRAKTOOTH_CHIPSETS = {
    "esp32": ["CVE-2021-28139", "CVE-2021-28136", "CVE-2021-28135"],
    "cypress": ["CVE-2021-34145", "CVE-2021-34148"],
    "cyw20735": ["CVE-2021-34145", "CVE-2021-34148", "CVE-2021-34147"],
    "csr": ["CVE-2021-35093"],
    "csr8510": ["CVE-2021-35093"],
    "csr8811": ["CVE-2021-35093"],
    "intel": ["CVE-2021-34147"],
    "ax200": ["CVE-2021-34147"],
    "qualcomm": ["CVE-2021-34147"],
    "wcn3990": ["CVE-2021-34147"],
}


def _check_braktooth_chipset(address: str, hci: str) -> list[dict]:
    """Flag known BrakTooth-vulnerable chipsets by manufacturer string.

    BrakTooth attacks operate at LMP layer (below HCI) and cannot be
    tested from standard BlueZ. But we can flag known-vulnerable chipsets
    from the manufacturer ID in hcitool info output.
    """
    findings: list[dict] = []

    result = _run_hcitool_info(address, hci)
    if result.returncode != 0:
        return findings

    manufacturer = ""
    for line in result.stdout.splitlines():
        if "Manufacturer:" in line:
            manufacturer = line.split(":", 1)[1].strip().lower()
            break

    if not manufacturer:
        return findings

    for chipset_key, cves in _BRAKTOOTH_CHIPSETS.items():
        if re.search(rf'\b{re.escape(chipset_key)}\b', manufacturer, re.IGNORECASE):
            findings.append(
                _finding(
                    "MEDIUM",
                    f"BrakTooth Chipset Susceptibility ({chipset_key})",
                    f"Target manufacturer '{manufacturer}' matches known BrakTooth-vulnerable "
                    f"chipset family. BrakTooth affects LMP/baseband layer (16 vulns, 25 CVEs).",
                    cve=", ".join(cves),
                    impact="Potential firmware crash, deadlock, or RCE via crafted LMP PDUs. "
                           "Requires ESP32-based attack hardware or SDR, not testable via HCI.",
                    remediation="Check vendor firmware update status. BrakTooth patches are chipset-specific.",
                    status="potential",
                    confidence="medium",
                    evidence=f"Manufacturer: {manufacturer}, matched chipset: {chipset_key}",
                )
            )
            info(f"BrakTooth chipset match: {manufacturer} ({', '.join(cves)})")

    if not findings:
        info(f"No BrakTooth chipset match for: {manufacturer}")

    return findings


def _check_eatt_support(address: str) -> list[dict]:
    """Probe for EATT (Enhanced ATT) support via L2CAP PSM 0x0027.

    EATT was introduced in BT 5.2. If the target accepts L2CAP connection
    to PSM 0x0027, it supports BT 5.2+ EATT — indicates a newer stack
    with parallel GATT capability and mandatory encryption.
    """

    findings: list[dict] = []

    try:
        sock = socket.socket(
            getattr(socket, "AF_BLUETOOTH", 31),
            socket.SOCK_SEQPACKET,
            getattr(socket, "BTPROTO_L2CAP", 0),
        )
        sock.settimeout(L2CAP_PROBE_TIMEOUT)
        try:
            sock.connect((address, 0x0027))
            findings.append(
                _finding(
                    "INFO",
                    "EATT Supported (BT 5.2+)",
                    "Target accepted L2CAP connection on PSM 0x0027 (EATT). "
                    "Indicates BT 5.2+ stack with Enhanced Attribute Protocol.",
                    impact="EATT allows parallel GATT operations — increased attack surface "
                           "for race conditions in GATT servers. Encryption is mandatory on EATT.",
                    status="confirmed",
                    confidence="high",
                    evidence="L2CAP PSM 0x0027 connection succeeded",
                )
            )
            success("EATT supported (BT 5.2+)")
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                info("EATT not supported (PSM 0x0027 refused)")
            elif exc.errno == errno.EACCES:
                findings.append(
                    _finding(
                        "INFO",
                        "EATT Present but Auth Required (BT 5.2+)",
                        "PSM 0x0027 requires authentication — EATT is available but "
                        "properly secured.",
                        status="confirmed",
                        confidence="high",
                        evidence="L2CAP PSM 0x0027 returned EACCES",
                    )
                )
                info("EATT present but requires auth (correctly secured)")
            else:
                verbose(f"EATT probe: {exc}")
        finally:
            sock.close()
    except OSError:
        pass

    return findings


def _check_hidden_rfcomm(address: str, services: list[dict]) -> list[dict]:
    """Diff RFCOMM scan against SDP to find unadvertised services."""
    findings: list[dict] = []

    sdp_channels = []
    for svc in services:
        if svc.get("protocol") == "RFCOMM":
            ch = svc.get("channel")
            if isinstance(ch, int):
                sdp_channels.append(ch)

    if not sdp_channels:
        verbose("No SDP RFCOMM channels to diff against; skipping hidden-service check")
        return findings

    try:
        scanner = RFCOMMScanner(address)
        hidden = scanner.find_hidden_services(sdp_channels)
    except Exception as exc:
        verbose(f"Hidden RFCOMM scan failed: {exc}")
        return findings

    severity_map = {
        "at_modem": "CRITICAL",
        "obex": "HIGH",
        "silent_open": "MEDIUM",
        "raw_data": "MEDIUM",
    }

    for h in hidden:
        ch = h["channel"]
        rtype = h.get("response_type", "unknown")
        sev = severity_map.get(rtype, "MEDIUM")
        findings.append(
            _finding(
                sev,
                f"Hidden RFCOMM Service (ch {ch})",
                f"Channel {ch} is open but not advertised in SDP. Response type: {rtype}.",
                impact="Unadvertised services may be debug/factory interfaces lacking auth controls.",
                remediation="Disable or authenticate unadvertised RFCOMM channels.",
                status="confirmed",
                confidence="high",
                evidence=f"Channel {ch} open ({rtype}), not in SDP channels {sdp_channels}",
            )
        )

    return findings


def _check_encryption_enforcement(address: str, services: list[dict]) -> list[dict]:
    """Test whether sensitive RFCOMM services accept unencrypted connections."""
    findings: list[dict] = []

    SOL_BLUETOOTH = 274
    BT_SECURITY = 4

    sensitive_keywords = ("pbap", "phonebook", "map", "message", "hfp", "hands-free", "handsfree")
    targets = []
    for svc in services:
        name = svc.get("name", "")
        lname = name.lower()
        if not any(k in lname for k in sensitive_keywords):
            continue
        if svc.get("protocol") != "RFCOMM":
            continue
        ch = svc.get("channel")
        if isinstance(ch, int):
            targets.append((name, ch))

    AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
    BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", 3)

    for svc_name, ch in targets:
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            sock.settimeout(ENCRYPTION_TIMEOUT)
            # Set security level to BT_SECURITY_LOW (1)
            sec_struct = struct.pack("BBH", 1, 0, 0)
            sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, sec_struct)
            try:
                sock.connect((address, ch))
                # Connection succeeded without encryption
                findings.append(
                    _finding(
                        "HIGH",
                        f"No Encryption Required ({svc_name})",
                        f"{svc_name} on channel {ch} accepted connection at BT_SECURITY_LOW.",
                        impact="Data transferred over this profile may be sent unencrypted.",
                        remediation="Enforce BT_SECURITY_MEDIUM or higher on sensitive services.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"RFCOMM ch {ch} ({svc_name}) connected with BT_SECURITY_LOW",
                    )
                )
                sock.close()
            except OSError as exc:
                sock.close()
                if exc.errno == errno.EACCES:
                    findings.append(
                        _finding(
                            "INFO",
                            f"Encryption Enforced ({svc_name})",
                            f"{svc_name} on channel {ch} correctly refused unencrypted connection.",
                            status="confirmed",
                            confidence="high",
                            evidence=f"RFCOMM ch {ch} ({svc_name}) returned EACCES at BT_SECURITY_LOW",
                        )
                    )
                else:
                    verbose(f"Encryption check for {svc_name}/ch{ch}: {exc}")
        except OSError as exc:
            verbose(f"Socket setup failed for encryption check on {svc_name}/ch{ch}: {exc}")
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return findings


def _check_pin_lockout(address: str, hci: str, ssp: bool | None) -> list[dict]:
    """Test whether legacy-pairing target implements PIN lockout."""
    findings: list[dict] = []

    if ssp is not False:
        verbose("SSP is enabled or unknown; skipping PIN lockout check")
        return findings

    try:
        from blue_tap.attack.pin_brute import PINBruteForce

        brute = PINBruteForce(address, hci=hci)
        result = brute.detect_lockout(attempts=2)
    except Exception as exc:
        verbose(f"PIN lockout detection failed: {exc}")
        return findings

    locked_out = result.get("locked_out", False)
    timings = result.get("timings", [])
    timing_str = ", ".join(f"{t:.3f}s" for t in timings)

    if not locked_out:
        avg_time = sum(timings) / len(timings) if timings else 0
        if avg_time < 2.0:
            findings.append(
                _finding(
                    "HIGH",
                    "No PIN Lockout (Fast Rejections)",
                    "Target rejected wrong PINs quickly with no lockout. Brute force is feasible.",
                    impact="An attacker can enumerate all 10,000 4-digit PINs in minutes.",
                    remediation="Implement exponential backoff or lockout after repeated failed pairings.",
                    status="confirmed",
                    confidence="high",
                    evidence=f"Timings: [{timing_str}], no lockout detected",
                )
            )
        else:
            findings.append(
                _finding(
                    "MEDIUM",
                    "No PIN Lockout Detected",
                    "Target did not lock out after wrong PINs, but rejections were not fast.",
                    impact="PIN brute force may be feasible but slower than expected.",
                    remediation="Implement lockout after repeated failed pairings.",
                    status="confirmed",
                    confidence="medium",
                    evidence=f"Timings: [{timing_str}], no lockout detected",
                )
            )
    else:
        findings.append(
            _finding(
                "INFO",
                "PIN Lockout Detected",
                "Target implements lockout or backoff after repeated wrong PINs.",
                status="confirmed",
                confidence="high",
                evidence=f"Timings: [{timing_str}], lockout detected",
            )
        )

    return findings


def _check_device_class(address: str, hci: str) -> list[dict]:
    """Parse device class of device and flag interesting service bits."""
    findings: list[dict] = []

    if not check_tool("hcitool"):
        return findings

    result = _run_hcitool_info(address, hci)
    if result.returncode != 0:
        return findings

    m = re.search(r"Class:\s*(0x[0-9a-fA-F]+)", result.stdout)
    if not m:
        return findings

    from blue_tap.core.scanner import parse_device_class

    cod = parse_device_class(m.group(1))
    svc_list = cod.get("services", [])
    major = cod.get("major", "Unknown")
    minor = cod.get("minor", "Unknown")

    flagged = []
    if "Object Transfer" in svc_list:
        flagged.append("Object Transfer")
    if "Networking" in svc_list:
        flagged.append("Networking")

    if flagged:
        findings.append(
            _finding(
                "MEDIUM",
                "Interesting Device Class Services",
                f"Device class advertises attack-relevant services: {', '.join(flagged)}.",
                impact="Object Transfer / Networking service bits increase OBEX/network attack surface.",
                remediation="Disable unnecessary service class bits in device firmware.",
                status="confirmed",
                confidence="medium",
                evidence=f"CoD {cod.get('raw', m.group(1))}: major={major}, minor={minor}, services={svc_list}",
            )
        )
    else:
        info(f"Device class: {major}/{minor}, services: {svc_list}")

    return findings


def _extract_lmp_features_dict(address: str, hci: str) -> dict | None:
    """Extract LMP features as a dict for reuse by CVE checks.

    Returns dict with boolean flags: encryption, role_switch, pause_encryption,
    ssp, le_and_bredr, secure_connections — or None if extraction fails.
    """
    if not check_tool("hcitool"):
        return None

    result = _run_hcitool_info(address, hci)
    if result.returncode != 0:
        return None

    m = re.search(r"Features:\s*(0x[0-9a-fA-F]+(?:\s+0x[0-9a-fA-F]+)*)", result.stdout)
    if not m:
        return None

    byte_strs = m.group(1).strip().split()
    fb = []
    for bs in byte_strs:
        try:
            fb.append(int(bs, 16))
        except ValueError:
            fb.append(0)
    while len(fb) < 8:
        fb.append(0)

    return {
        "encryption": bool(fb[0] & 0x04),
        "role_switch": bool(fb[0] & 0x20),
        "pause_encryption": bool(fb[5] & 0x08),
        "eir": bool(fb[6] & 0x01),
        "le_and_bredr": bool(fb[6] & 0x02),
        "ssp": bool(fb[6] & 0x08),
        "secure_connections": bool(fb[7] & 0x08),
    }


def _check_lmp_features(address: str, hci: str) -> list[dict]:
    """Parse LMP feature bits from hcitool info and flag missing security features."""
    findings: list[dict] = []

    if not check_tool("hcitool"):
        return findings

    result = _run_hcitool_info(address, hci)
    if result.returncode != 0:
        return findings

    m = re.search(r"Features:\s*(0x[0-9a-fA-F]+(?:\s+0x[0-9a-fA-F]+)*)", result.stdout)
    if not m:
        verbose("No Features line in hcitool info output")
        return findings

    raw_features = m.group(1)
    byte_strs = raw_features.strip().split()
    feature_bytes = []
    for bs in byte_strs:
        try:
            feature_bytes.append(int(bs, 16))
        except ValueError:
            feature_bytes.append(0)

    # Pad to at least 8 bytes
    while len(feature_bytes) < 8:
        feature_bytes.append(0)

    def has_bit(byte_idx: int, bit: int) -> bool:
        if byte_idx >= len(feature_bytes):
            return False
        return bool(feature_bytes[byte_idx] & (1 << bit))

    # Check security-relevant bits
    if not has_bit(0, 2):
        findings.append(
            _finding(
                "CRITICAL",
                "LMP: Encryption Not Supported",
                "Target LMP features indicate encryption is not supported.",
                impact="All Bluetooth traffic to this device is unencrypted.",
                remediation="Device firmware must support encryption. Consider replacing hardware.",
                status="confirmed",
                confidence="high",
                evidence=f"Features byte 0 bit 2 = 0 (features: {raw_features})",
            )
        )

    if has_bit(0, 5):
        findings.append(
            _finding(
                "INFO",
                "LMP: Role Switch Supported",
                "Target supports role switch. This is a prerequisite for BIAS attacks.",
                cve="CVE-2020-10135",
                status="confirmed",
                confidence="medium",
                evidence=f"Features byte 0 bit 5 = 1 (features: {raw_features})",
            )
        )

    if has_bit(5, 3):
        findings.append(
            _finding(
                "MEDIUM",
                "LMP: Pause Encryption Supported",
                "Target supports pause encryption, which is related to KNOB attack surface.",
                cve="CVE-2019-9506",
                impact="Pause encryption can facilitate key length negotiation attacks.",
                remediation="Verify firmware enforces minimum key length regardless of pause encryption.",
                status="confirmed",
                confidence="medium",
                evidence=f"Features byte 5 bit 3 = 1 (features: {raw_features})",
            )
        )

    if not has_bit(6, 3):
        findings.append(
            _finding(
                "HIGH",
                "LMP: SSP Not Supported in Features",
                "Target LMP features do not include Secure Simple Pairing support.",
                impact="Device relies on legacy PIN pairing, vulnerable to passive eavesdropping of pairing exchange.",
                remediation="Use hardware that supports SSP (Bluetooth 2.1+).",
                status="confirmed",
                confidence="high",
                evidence=f"Features byte 6 bit 3 = 0 (features: {raw_features})",
            )
        )

    if not has_bit(7, 3):
        findings.append(
            _finding(
                "MEDIUM",
                "LMP: Secure Connections Not Supported",
                "Target does not support Secure Connections (P-256 ECDH).",
                impact="Falls back to legacy pairing crypto (P-192), weaker against offline brute force.",
                remediation="Use hardware supporting Bluetooth 4.1+ Secure Connections.",
                status="confirmed",
                confidence="high",
                evidence=f"Features byte 7 bit 3 = 0 (features: {raw_features})",
            )
        )

    return findings


def _check_authorization_model(address: str, services: list[dict]) -> list[dict]:
    """Test if PBAP/MAP services allow unauthenticated OBEX access."""
    findings: list[dict] = []

    AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
    BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", 3)

    # OBEX target UUIDs per profile
    PBAP_UUID = bytes.fromhex("796135f0f0c511d809660800200c9a66")
    MAP_UUID = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")

    profile_channels = []
    for svc in services:
        name = svc.get("name", "")
        lname = name.lower()
        if svc.get("protocol") != "RFCOMM":
            continue
        ch = svc.get("channel")
        if not isinstance(ch, int):
            continue
        if any(k in lname for k in ("pbap", "phonebook", "map", "message")):
            profile_channels.append((name, ch))

    for svc_name, ch in profile_channels:
        # Select correct OBEX target UUID based on service name
        svc_lower = svc_name.lower()
        target_uuid = MAP_UUID if any(k in svc_lower for k in ("map", "message")) else PBAP_UUID
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            sock.settimeout(OBEX_PROBE_TIMEOUT)
            try:
                sock.connect((address, ch))
            except OSError as exc:
                sock.close()
                if exc.errno == errno.EACCES:
                    findings.append(
                        _finding(
                            "INFO",
                            f"RFCOMM Auth Required ({svc_name})",
                            f"{svc_name} on channel {ch} requires authentication to connect.",
                            status="confirmed",
                            confidence="high",
                            evidence=f"RFCOMM ch {ch} ({svc_name}) returned EACCES on connect",
                        )
                    )
                else:
                    verbose(f"RFCOMM connect to {svc_name}/ch{ch} failed: {exc}")
                continue

            # Connected — send OBEX Connect with target UUID
            # OBEX Connect: opcode=0x80, version=0x10, flags=0x00, maxlen=0xFFFF
            # Target header: HI=0x46, length=2+16
            target_header = b"\x46" + struct.pack(">H", 3 + len(target_uuid)) + target_uuid
            obex_body = b"\x10\x00" + struct.pack(">H", 0xFFFF) + target_header
            obex_connect = b"\x80" + struct.pack(">H", 3 + len(obex_body)) + obex_body

            try:
                sock.sendall(obex_connect)
                sock.settimeout(OBEX_PROBE_TIMEOUT)
                resp = sock.recv(1024)
            except (TimeoutError, OSError):
                resp = b""
            finally:
                sock.close()

            if resp and resp[0] == 0xA0:
                findings.append(
                    _finding(
                        "CRITICAL",
                        f"Unauthenticated OBEX Access ({svc_name})",
                        f"{svc_name} on channel {ch} returned OBEX Success (0xA0) without authentication.",
                        impact="Phonebook/message data may be accessible without pairing.",
                        remediation="Require authentication and authorization before OBEX profile access.",
                        status="confirmed",
                        confidence="high",
                        evidence=f"OBEX Connect to ch {ch} ({svc_name}) returned 0x{resp[0]:02X}",
                    )
                )
            elif resp and resp[0] in (0xC1, 0xC3):
                findings.append(
                    _finding(
                        "INFO",
                        f"OBEX Authorization Enforced ({svc_name})",
                        f"{svc_name} on channel {ch} returned Unauthorized/Forbidden (0x{resp[0]:02X}).",
                        status="confirmed",
                        confidence="high",
                        evidence=f"OBEX Connect to ch {ch} ({svc_name}) returned 0x{resp[0]:02X}",
                    )
                )
            elif resp and resp[0] in (0xC0, 0x44, 0xD0):
                verbose(f"OBEX rejected from {svc_name}/ch{ch}: 0x{resp[0]:02X}")
            elif resp:
                verbose(f"OBEX response from {svc_name}/ch{ch}: 0x{resp[0]:02X}")
        except OSError as exc:
            verbose(f"Authorization check socket error for {svc_name}/ch{ch}: {exc}")

    return findings


def _check_automotive_diagnostics(address: str, services: list[dict]) -> list[dict]:
    """Probe for automotive diagnostic interfaces via SPP/DUN channels."""
    findings: list[dict] = []

    AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
    BTPROTO_RFCOMM = getattr(socket, "BTPROTO_RFCOMM", 3)

    # Find SPP (0x1101) and DUN (0x1103) channels
    diag_channels = []
    diag_keywords = ("diagnostic", "obd", "can", "ecu", "debug", "factory", "gateway")

    for svc in services:
        uuid = svc.get("uuid", "").lower()
        name = svc.get("name", "")
        lname = name.lower()
        ch = svc.get("channel")
        if svc.get("protocol") != "RFCOMM" or not isinstance(ch, int):
            continue

        is_spp = "1101" in uuid
        is_dun = "1103" in uuid
        has_keyword = any(k in lname for k in diag_keywords)

        if is_spp or is_dun or has_keyword:
            diag_channels.append((name, ch, is_spp, is_dun, has_keyword))

    # Check SDP names for diagnostic keywords even without SPP/DUN UUID
    for svc in services:
        name = svc.get("name", "")
        lname = name.lower()
        if any(k in lname for k in diag_keywords):
            ch = svc.get("channel")
            if isinstance(ch, int) and not any(d[1] == ch for d in diag_channels):
                diag_channels.append((name, ch, False, False, True))

    if not diag_channels:
        return findings

    # Flag keyword matches in SDP names
    for name, ch, is_spp, is_dun, has_keyword in diag_channels:
        if has_keyword:
            findings.append(
                _finding(
                    "HIGH",
                    f"Diagnostic Service Name ({name})",
                    f"SDP service '{name}' on channel {ch} matches automotive diagnostic keywords.",
                    impact="May provide access to vehicle diagnostic or CAN bus interfaces.",
                    remediation="Remove or authenticate diagnostic Bluetooth services in production.",
                    status="confirmed",
                    confidence="medium",
                    evidence=f"SDP name '{name}' matches diagnostic keywords, ch {ch}",
                )
            )

    # Actively probe SPP/DUN channels
    probes = [b"ATI\r\n", b"ATZ\r\n", b"0100\r\n"]
    for name, ch, is_spp, is_dun, has_keyword in diag_channels:
        if not (is_spp or is_dun):
            continue
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            sock.settimeout(OBEX_PROBE_TIMEOUT)
            try:
                sock.connect((address, ch))
            except OSError:
                sock.close()
                continue

            responses = []
            for probe in probes:
                try:
                    sock.sendall(probe)
                    sock.settimeout(AT_PROBE_TIMEOUT)
                    data = sock.recv(1024)
                    if data:
                        responses.append((probe.strip().decode(errors="replace"), data))
                except (TimeoutError, OSError):
                    continue

            sock.close()

            for probe_name, resp in responses:
                resp_text = resp.decode("ascii", errors="replace")
                if "ELM" in resp_text or any(
                    c in resp_text for c in ("41 00", "41 0C", "7E8")
                ):
                    findings.append(
                        _finding(
                            "CRITICAL",
                            f"CAN Bus Access via Bluetooth ({name})",
                            f"Channel {ch} responded to OBD probe with ELM/PID data.",
                            impact="Direct CAN bus access enables vehicle diagnostics, "
                                   "ECU interrogation, and potentially safety-critical commands.",
                            remediation="Remove Bluetooth-to-CAN bridges or require strong auth.",
                            status="confirmed",
                            confidence="high",
                            evidence=f"Probe '{probe_name}' on ch {ch} returned: {resp_text[:100]}",
                        )
                    )
                    break
                elif b"OK" in resp or b"ERROR" in resp or b"AT" in resp.upper():
                    findings.append(
                        _finding(
                            "HIGH",
                            f"Diagnostic Serial Access ({name})",
                            f"Channel {ch} responded to AT command with modem-style response.",
                            impact="AT-command serial access may allow modem control or diagnostic operations.",
                            remediation="Authenticate and restrict AT-command interfaces.",
                            status="confirmed",
                            confidence="high",
                            evidence=f"Probe '{probe_name}' on ch {ch} returned: {resp_text[:100]}",
                        )
                    )
                    break

        except OSError as exc:
            verbose(f"Diagnostic probe on {name}/ch{ch} failed: {exc}")

    return findings


# ---------------------------------------------------------------------------
# LMP Feature Probing via DarkFirmware
# ---------------------------------------------------------------------------

# LMP feature bitmap (BT Core Spec Vol 2, Part C, Section 3.3)
FEATURE_BITS: dict[tuple[int, int], str] = {
    (0, 0): "3-slot_packets",
    (0, 1): "5-slot_packets",
    (0, 2): "encryption",
    (0, 3): "slot_offset",
    (0, 4): "timing_accuracy",
    (0, 5): "role_switch",
    (0, 6): "hold_mode",
    (0, 7): "sniff_mode",
    (1, 1): "power_control",
    (2, 1): "edr_2mbps",
    (2, 2): "edr_3mbps",
    (3, 3): "edr_esco_2mbps",
    (3, 4): "edr_esco_3mbps",
    (3, 7): "extended_features",
    (4, 0): "le_supported",
    (4, 1): "le_and_bredr",
    (5, 2): "secure_connections_controller",
    (6, 0): "secure_connections_host",
    (7, 0): "ssp_host",
    (7, 3): "secure_connections_host_support",
}


def _probe_lmp_features(address: str, hci: str) -> dict | None:
    """Actively probe target's LMP features via DarkFirmware.

    Sends LMP_FEATURES_REQ and parses the 8-byte feature bitmap
    from the response. Returns decoded feature dict or None if
    probing failed.

    Args:
        address: Target Bluetooth address (unused for LMP — operates on
            the active ACL link).
        hci: HCI adapter identifier (e.g. ``"hci0"``).

    Returns:
        Dict with ``"raw"`` (bytes) plus boolean flags for each known
        feature, or ``None`` if probing is unavailable or fails.
    """
    try:
        from blue_tap.core.hci_vsc import HCIVSCSocket
        from blue_tap.fuzz.protocols.lmp import build_features_req, LMP_FEATURES_RES
    except ImportError:
        info("DarkFirmware not available — skipping LMP feature probing")
        return None

    info(f"Probing LMP features via DarkFirmware on {hci}...")
    hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0

    try:
        lmp_responses: list[bytes] = []
        with HCIVSCSocket(hci_idx) as vsc:
            vsc.start_lmp_monitor(lambda evt: lmp_responses.append(evt))
            payload = build_features_req()
            ok = vsc.send_lmp(payload)
            if not ok:
                warning("Failed to send LMP_FEATURES_REQ via DarkFirmware")
                vsc.stop_lmp_monitor()
                return None

            info("LMP_FEATURES_REQ sent, waiting for response...")
            import time as _time
            _time.sleep(5)
            vsc.stop_lmp_monitor()

        # Parse responses — look for LMP_FEATURES_RES (opcode 40)
        for resp in lmp_responses:
            if not resp or len(resp) < 1:
                continue
            opcode = resp[0] & 0x7F  # mask off TID bit
            if opcode == LMP_FEATURES_RES and len(resp) >= 9:
                raw_features = resp[1:9]
                result: dict = {"raw": raw_features}

                for (byte_idx, bit_idx), name in FEATURE_BITS.items():
                    if byte_idx < len(raw_features):
                        result[name] = bool(raw_features[byte_idx] & (1 << bit_idx))
                    else:
                        result[name] = False

                enc = result.get("encryption", False)
                sc = result.get("secure_connections_controller", False)
                rs = result.get("role_switch", False)
                info(f"LMP features probed: encryption={enc}, SC={sc}, role_switch={rs}")
                return result

        warning("No LMP_FEATURES_RES received within timeout")
        return None

    except Exception as exc:
        warning(f"LMP feature probing failed: {exc}")
        return None


def _probe_lmp_version(address: str, hci: str) -> dict | None:
    """Actively probe target's LMP version via DarkFirmware.

    Sends LMP_VERSION_REQ (opcode 37) and parses the response:
    ver_nr(1), company_id(2), sub_ver(2).

    Args:
        address: Target Bluetooth address.
        hci: HCI adapter identifier.

    Returns:
        Dict with ``"version"``, ``"company"``, ``"subversion"`` keys,
        or ``None`` if probing fails.
    """
    try:
        from blue_tap.core.hci_vsc import HCIVSCSocket
        from blue_tap.fuzz.protocols.lmp import build_version_req, LMP_VERSION_RES
    except ImportError:
        info("DarkFirmware not available — skipping LMP version probing")
        return None

    info(f"Probing LMP version via DarkFirmware on {hci}...")
    hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0

    try:
        lmp_responses: list[bytes] = []
        with HCIVSCSocket(hci_idx) as vsc:
            vsc.start_lmp_monitor(lambda evt: lmp_responses.append(evt))
            payload = build_version_req()
            ok = vsc.send_lmp(payload)
            if not ok:
                warning("Failed to send LMP_VERSION_REQ via DarkFirmware")
                vsc.stop_lmp_monitor()
                return None

            info("LMP_VERSION_REQ sent, waiting for response...")
            import time as _time
            _time.sleep(5)
            vsc.stop_lmp_monitor()

        # Parse responses — look for LMP_VERSION_RES (opcode 38)
        for resp in lmp_responses:
            if not resp or len(resp) < 1:
                continue
            opcode = resp[0] & 0x7F
            if opcode == LMP_VERSION_RES and len(resp) >= 6:
                ver_nr = resp[1]
                company_id = struct.unpack("<H", resp[2:4])[0]
                sub_ver = struct.unpack("<H", resp[4:6])[0]
                info(f"LMP version probed: ver={ver_nr:#04x}, company={company_id:#06x}, "
                     f"subver={sub_ver:#06x}")
                return {
                    "version": ver_nr,
                    "company": company_id,
                    "subversion": sub_ver,
                }

        warning("No LMP_VERSION_RES received within timeout")
        return None

    except Exception as exc:
        warning(f"LMP version probing failed: {exc}")
        return None


def scan_vulnerabilities(address: str, hci: str = "hci0", active: bool = False,
                         phone_address: str | None = None) -> list[dict]:
    """Run vulnerability and attack-surface checks against a target.

    Output is evidence-based and intentionally avoids definitive CVE claims
    without active exploit verification.
    """
    info(f"Scanning {address} for vulnerabilities and attack-surface indicators...")
    findings: list[dict] = []

    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        error("Adapter not ready — cannot scan")
        return findings

    section("Check 1: Secure Simple Pairing", style="bt.cyan")
    ssp = check_ssp(address, hci)
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

    # Collect LMP features and device context for protocol-informed CVE checks
    lmp_feats = _extract_lmp_features_dict(address, hci)

    # DarkFirmware-enhanced probing: use active LMP probes if available
    if active and _check_darkfirmware_available(hci):
        section("Check 4b: DarkFirmware LMP Probing", style="bt.cyan")
        df_features = _probe_lmp_features(address, hci)
        if df_features is not None:
            info("Using DarkFirmware-probed LMP features (overriding hcitool heuristics)")
            # Merge DarkFirmware results — these are more authoritative
            if lmp_feats is None:
                lmp_feats = {}
            for key, val in df_features.items():
                if key != "raw":
                    lmp_feats[key] = val

        df_version = _probe_lmp_version(address, hci)
        if df_version is not None:
            info(f"DarkFirmware LMP version: {df_version}")

    device_name = ""
    manufacturer = ""
    name_result = run_cmd(["hcitool", "-i", hci, "name", address], timeout=8)
    if name_result.returncode == 0:
        device_name = name_result.stdout.strip()
    sdp_raw = get_raw_sdp(address)
    # Extract manufacturer from hcitool info
    info_result = _run_hcitool_info(address, hci)
    if info_result.returncode == 0:
        mfr_m = re.search(r"Manufacturer:\s*(.+)", info_result.stdout)
        if mfr_m:
            manufacturer = mfr_m.group(1).strip()

    # --- Local analysis checks (parallel, no active connections needed) ---
    from concurrent.futures import ThreadPoolExecutor, as_completed

    section("Check 4a: Local Analysis (version/feature checks)", style="bt.cyan")
    local_checks = [
        lambda: _check_knob(bt_version, raw_version, lmp_feats),
        lambda: _check_blurtooth(bt_version, raw_version, lmp_feats),
        lambda: _check_bluffs(bt_version, raw_version),
        lambda: _check_pin_pairing_bypass(bt_version, raw_version, ssp),
        lambda: _check_invalid_curve(bt_version, raw_version, lmp_feats),
        *([] if active else [lambda: _check_bias(ssp)]),
        lambda: _check_braktooth_chipset(address, hci),
        lambda: _check_lmp_features(address, hci),
        lambda: _check_device_class(address, hci),
        lambda: _check_blueborne(address),
    ]

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fn) for fn in local_checks]
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception as e:
                warning(f"Check failed: {e}")

    # --- Sequential active checks (require active connections, can't overlap) ---
    section("Check 5: Encryption Enforcement", style="bt.cyan")
    findings.extend(_check_encryption_enforcement(address, services))

    section("Check 6: Authorization Model (OBEX)", style="bt.cyan")
    findings.extend(_check_authorization_model(address, services))

    section("Check 7: Automotive Diagnostics", style="bt.cyan")
    findings.extend(_check_automotive_diagnostics(address, services))

    if active:
        section("Active Check: PIN Lockout Detection")
        findings.extend(_check_pin_lockout(address, hci, ssp))
    else:
        verbose("Skipping PIN lockout check (use --active to enable)")

    if active:
        section("Active Check: BIAS Vulnerability Probe")
        findings.extend(_check_bias_active(address, hci, ssp, phone_address))

    # DarkFirmware-enhanced active KNOB probe
    if _check_darkfirmware_available(hci) and active:
        section("Active Check: DarkFirmware KNOB Probe", style="bt.cyan")
        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket
            from blue_tap.fuzz.protocols.lmp import build_enc_key_size_req

            hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0
            with HCIVSCSocket(hci_idx) as vsc:
                lmp_responses = []
                vsc.start_lmp_monitor(lambda evt: lmp_responses.append(evt))
                payload = build_enc_key_size_req(key_size=1)
                ok = vsc.send_lmp(payload)
                if ok:
                    import time as _time
                    _time.sleep(2)
                vsc.stop_lmp_monitor()

                if lmp_responses:
                    findings.append(
                        _finding(
                            "HIGH",
                            "KNOB: DarkFirmware Active Probe Response (CVE-2019-9506)",
                            f"Target responded to LMP_encryption_key_size_req(key_size=1) "
                            f"sent via DarkFirmware. {len(lmp_responses)} LMP response(s) received.",
                            cve="CVE-2019-9506",
                            impact="Target may accept 1-byte encryption key size — "
                                   "complete traffic decryption possible.",
                            remediation="Update firmware to enforce min 7-byte key size.",
                            status="confirmed",
                            confidence="high",
                            evidence="darkfirmware_active_probe",
                        )
                    )
                    info(f"DarkFirmware KNOB probe: {len(lmp_responses)} LMP response(s)")
                else:
                    info("DarkFirmware KNOB probe: no LMP response (target may enforce key size)")
        except Exception as exc:
            verbose(f"DarkFirmware KNOB probe failed: {exc}")

    section("Check 9: Hidden RFCOMM Services", style="bt.cyan")
    findings.extend(_check_hidden_rfcomm(address, services))

    section("Check 10: BLE Writable Surface", style="bt.cyan")
    findings.extend(_check_writable_gatt(address))

    section("Check 11: EATT Support (BT 5.2+ Indicator)", style="bt.cyan")
    findings.extend(_check_eatt_support(address))

    section("Check 12: Pairing Method Probe", style="bt.cyan")
    findings.extend(_check_pairing_method(address, hci))

    section("Check 13: PerfektBlue (OpenSynergy BlueSDK)", style="bt.cyan")
    findings.extend(_check_perfektblue(address, services, device_name, manufacturer, sdp_raw))

    if not active:
        info("Tip: Use --active to enable invasive checks (BIAS probe, PIN lockout)")

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
