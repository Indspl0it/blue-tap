"""Bluetooth vulnerability and attack-surface scanner.

This scanner emphasizes evidence-based classification:
- confirmed: directly observed vulnerable behavior
- inconclusive: check reached the target but the response was not definitive
- pairing_required: the target must enter pairing/bonding mode to validate
- not_applicable: wrong target role, transport, or prerequisites absent
(All check outcomes use the canonical assessment taxonomy.)

It avoids declaring definitive CVE exploitation unless direct evidence exists.
"""

import errno
import re
import socket
import struct
from datetime import datetime, timezone

from blue_tap.modules.assessment.cve_framework import (
    CveCheck,
    CveSection,
    ScanCheck,
    ScanSection,
    build_vulnscan_result,
    make_cve_finding,
    summarize_check,
    summarize_findings,
)
from blue_tap.framework.runtime.cli_events import emit_cli_event
from blue_tap.framework.contracts.result_schema import make_run_id
from blue_tap.modules.reconnaissance.rfcomm_scan import RFCOMMScanner
from blue_tap.modules.reconnaissance.sdp import browse_services, check_ssp, get_raw_sdp
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


def _run_hcitool_info(address: str, hci: str | None = None):
    """Run hcitool info with retry on transient failure."""
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
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
    status: str = "inconclusive",
    confidence: str = "medium",
    evidence: str = "",
) -> dict:
    return make_cve_finding(
        severity,
        name,
        description,
        cve=cve,
        impact=impact,
        remediation=remediation,
        status=status,
        confidence=confidence,
        evidence=evidence,
        category="heuristic" if cve == "N/A" else "cve",
    )


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
    from blue_tap.modules.assessment.checks.non_cve_rfcomm import check_service_exposure
    return check_service_exposure(address, services, RFCOMM_PROBE_TIMEOUT)


def _check_darkfirmware_available(_scan_hci: str | None = None) -> bool:
    """Check if DarkFirmware is available for enhanced vulnerability probing.

    Identifies the RTL8761B dongle by USB VID:PID (never by position) and probes
    that adapter for DarkFirmware — the scan adapter is irrelevant here.

    The startup flow caches the dongle HCI in ``BT_TAP_DARKFIRMWARE_HCI`` so
    most calls are a single env-var lookup + one HCI probe. If the env var is
    absent (e.g. unit tests, non-standard startup) ``find_rtl8761b_hci()`` is
    called to discover the adapter dynamically.
    """
    try:
        import os as _os
        from blue_tap.hardware.firmware import DarkFirmwareManager
        mgr = DarkFirmwareManager()
        df_hci = _os.environ.get("BT_TAP_DARKFIRMWARE_HCI") or mgr.find_rtl8761b_hci()
        if df_hci is None:
            return False
        return mgr.is_darkfirmware_loaded(df_hci)
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
                status="inconclusive",
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
                status="inconclusive",
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
        findings.append(_finding(
            "INFO", "CVE-2024-45431/32/33/34: Not Applicable",
            "PerfektBlue check skipped — target does not match known OpenSynergy BlueSDK "
            "indicators (manufacturer, SDP strings). Check only applies to automotive IVI "
            "systems using OpenSynergy BlueSDK (VW, Audi, Mercedes, Stellantis, etc.).",
            cve="CVE-2024-45431,CVE-2024-45432,CVE-2024-45433,CVE-2024-45434",
            status="not_applicable", confidence="high",
            evidence="No OpenSynergy/BlueSDK manufacturer or SDP string found",
        ))
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
            status="inconclusive",
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
                status="inconclusive",
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
                status="confirmed" if ssp is False else "inconclusive",
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
                status="inconclusive",
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
            status="inconclusive",
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
            status="inconclusive",
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
            status="inconclusive",
            confidence="low",
        ))
        return findings

    try:
        from blue_tap.modules.exploitation.bias import BIASAttack

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
                status="inconclusive",
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
                status="inconclusive",
                confidence="low",
                evidence=f"No auto-reconnect in 15s. SSP: {result.get('ssp_supported')}, "
                         f"BT version: {result.get('bt_version')}",
            ))
    except ImportError:
        findings.append(_finding(
            "info", "BIAS active probe unavailable",
            "Could not import BIAS attack module.",
            cve="CVE-2020-10135",
            status="inconclusive",
            confidence="low",
        ))
    except Exception as e:
        warning(f"BIAS active probe failed: {e}")
        findings.append(_finding(
            "info", "BIAS active probe failed",
            f"Active probe encountered an error: {e}. "
            "The device may still be vulnerable — try manual testing.",
            cve="CVE-2020-10135",
            status="inconclusive",
            confidence="low",
        ))

    return findings


def _check_blueborne(address: str) -> list[dict]:
    findings: list[dict] = []

    bluez_version = None
    version_source = ""
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
                    status="inconclusive",
                    confidence="medium",
                    evidence=version_source,
                )
            )
    return findings


def _check_pairing_method(address: str, hci: str) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_ble import check_pairing_method
    return check_pairing_method(address, hci)


def _check_writable_gatt(address: str) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_ble import check_writable_gatt
    return check_writable_gatt(address)


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
                    status="inconclusive",
                    confidence="medium",
                    evidence=f"Manufacturer: {manufacturer}, matched chipset: {chipset_key}",
                )
            )
            info(f"BrakTooth chipset match: {manufacturer} ({', '.join(cves)})")

    if not findings:
        info(f"No BrakTooth chipset match for: {manufacturer}")

    return findings


def _check_eatt_support(address: str) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_ble import check_eatt_support
    return check_eatt_support(address, L2CAP_PROBE_TIMEOUT)


def _check_hidden_rfcomm(address: str, services: list[dict]) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_rfcomm import check_hidden_rfcomm
    return check_hidden_rfcomm(address, services, RFCOMM_PROBE_TIMEOUT)


def _check_encryption_enforcement(address: str, services: list[dict]) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_rfcomm import check_encryption_enforcement
    return check_encryption_enforcement(address, services, ENCRYPTION_TIMEOUT, OBEX_PROBE_TIMEOUT)


def _check_pin_lockout(address: str, hci: str, ssp: bool | None) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_posture import check_pin_lockout
    return check_pin_lockout(address, hci, ssp)


def _check_device_class(address: str, hci: str, services: list[dict], hcitool_info_result=None) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_posture import check_device_class
    if hcitool_info_result is None:
        hcitool_info_result = _run_hcitool_info(address, hci) if check_tool("hcitool") else None
    return check_device_class(address, hci, services, hcitool_info_result)


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
    from blue_tap.modules.assessment.checks.non_cve_posture import check_lmp_features
    result = _run_hcitool_info(address, hci) if check_tool("hcitool") else None
    return check_lmp_features(address, hci, result)


def _check_authorization_model(address: str, services: list[dict]) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_rfcomm import check_authorization_model
    return check_authorization_model(address, services, OBEX_PROBE_TIMEOUT)


def _check_automotive_diagnostics(address: str, services: list[dict]) -> list[dict]:
    from blue_tap.modules.assessment.checks.non_cve_rfcomm import check_automotive_diagnostics
    return check_automotive_diagnostics(address, services, OBEX_PROBE_TIMEOUT, AT_PROBE_TIMEOUT)


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
        hci: HCI adapter identifier (e.g. ``<hciX>``).

    Returns:
        Dict with ``"raw"`` (bytes) plus boolean flags for each known
        feature, or ``None`` if probing is unavailable or fails.
    """
    try:
        from blue_tap.hardware.hci_vsc import HCIVSCSocket
        from blue_tap.modules.fuzzing.protocols.lmp import build_features_req, LMP_FEATURES_RES
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
        from blue_tap.hardware.hci_vsc import HCIVSCSocket
        from blue_tap.modules.fuzzing.protocols.lmp import build_version_req, LMP_VERSION_RES
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


def run_vulnerability_scan(address: str, hci: str | None = None, active: bool = False,
                           phone_address: str | None = None) -> dict:
    """Run vulnerability and attack-surface checks against a target.

    Output is evidence-based and intentionally avoids definitive CVE claims
    without active exploit verification.
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    started_at = datetime.now(timezone.utc).isoformat()
    run_id = make_run_id("vulnscan")
    emit_cli_event(
        event_type="run_started",
        module="assessment.vuln_scanner",
        run_id=run_id,
        target=address,
        adapter=hci,
        message=f"Vulnerability scan started against {address}",
        details={"active": active, "phone_address": phone_address or ""},
    )
    info(f"Scanning {address} for vulnerabilities and attack-surface indicators...")
    findings: list[dict] = []
    cve_check_log: list[dict] = []
    non_cve_check_log: list[dict] = []

    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        error("Adapter not ready — cannot scan")
        result = build_vulnscan_result(
            target=address,
            adapter=hci,
            active=active,
            findings=findings,
            cve_checks=cve_check_log,
            non_cve_checks=non_cve_check_log,
            started_at=started_at,
            run_id=run_id,
        )
        emit_cli_event(
            event_type="run_error",
            module="assessment.vuln_scanner",
            run_id=run_id,
            target=address,
            adapter=hci,
            message=f"Vulnerability scan aborted: adapter {hci} not ready",
        )
        return result

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
                status="inconclusive",
                confidence="medium",
                evidence="SDP browse output did not include SSP markers",
            )
        )
        warning("SSP not advertised; possible legacy pairing behavior")
    elif ssp is True:
        success("SSP support advertised")
    else:
        warning("Could not determine SSP support")

    services = browse_services(address, hci=hci)

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
    sdp_raw = get_raw_sdp(address, hci=hci)
    # Extract manufacturer from hcitool info
    info_result = _run_hcitool_info(address, hci)
    if info_result.returncode == 0:
        mfr_m = re.search(r"Manufacturer:\s*(.+)", info_result.stdout)
        if mfr_m:
            manufacturer = mfr_m.group(1).strip()

    def _run_non_cve_check(spec: ScanCheck, section_title: str):
        results = []
        verbose(f"[NON-CVE] {spec.check_id} — {spec.title}")
        emit_cli_event(
            event_type="execution_started",
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id=spec.check_id,
            target=address,
            adapter=hci,
            message=f"Non-CVE check started: {spec.check_id}",
            details={"section": section_title},
        )
        try:
            results = spec.runner(*spec.args)
        except Exception as exc:
            warning(f"{spec.check_id}: check failed ({exc})")
            non_cve_check_log.append({
                "check_id": spec.check_id,
                "title": spec.title,
                "section": section_title,
                "error": str(exc),
                "finding_count": 0,
                "primary_status": "error",
                "status_counts": {"error": 1},
                "evidence_samples": [],
            })
            emit_cli_event(
                event_type="run_error",
                module="assessment.vuln_scanner",
                run_id=run_id,
                execution_id=spec.check_id,
                target=address,
                adapter=hci,
                message=f"Non-CVE check failed: {spec.check_id} ({exc})",
            )
            return
        for result in results:
            result.setdefault("check_title", spec.title)
            result.setdefault("category", result.get("category", "exposure"))
            result.setdefault("section", section_title)
            status = result.get("status")
            if status == "not_applicable":
                verbose(f"SKIP {spec.check_id}: {result.get('evidence', 'not applicable')}")
            elif status == "inconclusive":
                warning(f"INCONCLUSIVE {spec.check_id}: {result.get('evidence', 'probe did not produce a definitive answer')}")
            elif status == "confirmed":
                info(f"{spec.check_id}: {result.get('name', spec.title)}")
        non_cve_check_log.append({
            "check_id": spec.check_id,
            "title": spec.title,
            "section": section_title,
            **summarize_check(results),
        })
        primary_status = non_cve_check_log[-1]["primary_status"]
        emit_cli_event(
            event_type="execution_result" if primary_status != "not_applicable" else "execution_skipped",
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id=spec.check_id,
            target=address,
            adapter=hci,
            message=f"Non-CVE check finished: {spec.check_id} -> {primary_status}",
            details={"status": primary_status},
        )
        findings.extend(results)

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
        lambda: _check_blueborne(address),
    ]

    local_analysis_findings = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fn) for fn in local_checks]
        for future in as_completed(futures):
            try:
                local_analysis_findings.extend(future.result())
            except Exception as e:
                warning(f"Check failed: {e}")
    findings.extend(local_analysis_findings)
    non_cve_check_log.append({
        "check_id": "local_analysis",
        "title": "Local Analysis",
        "section": "Check 4a: Local Analysis (version/feature checks)",
        **summarize_check(local_analysis_findings),
    })
    emit_cli_event(
        event_type="execution_result",
        module="assessment.vuln_scanner",
        run_id=run_id,
        execution_id="local_analysis",
        target=address,
        adapter=hci,
        message=f"Non-CVE check finished: local_analysis -> {non_cve_check_log[-1]['primary_status']}",
        details={"status": non_cve_check_log[-1]["primary_status"]},
    )

    non_cve_sections = [
        ScanSection(
            "Check 5: Non-CVE RFCOMM and Exposure Checks",
            (
                ScanCheck("service_exposure", "Sensitive RFCOMM Profile Reachability", _check_service_exposure, (address, services)),
                ScanCheck("encryption_enforcement", "Low-Security RFCOMM Acceptance", _check_encryption_enforcement, (address, services)),
                ScanCheck("authorization_model", "OBEX Authorization Model", _check_authorization_model, (address, services)),
                ScanCheck("automotive_diagnostics", "Automotive Diagnostic Surface", _check_automotive_diagnostics, (address, services)),
                ScanCheck("hidden_rfcomm", "Unadvertised RFCOMM Channels", _check_hidden_rfcomm, (address, services)),
            ),
        ),
        ScanSection(
            "Check 6: Non-CVE BLE and Pairing Checks",
            (
                ScanCheck("writable_gatt", "Writable GATT Surface", _check_writable_gatt, (address,)),
                ScanCheck("eatt_support", "EATT Capability", _check_eatt_support, (address,)),
                ScanCheck("pairing_method", "Pairing Method Posture", _check_pairing_method, (address, hci)),
            ),
        ),
        ScanSection(
            "Check 7: Non-CVE Security Posture Checks",
            (
                ScanCheck("pin_lockout", "Legacy PIN Lockout", _check_pin_lockout, (address, hci, ssp)),
                ScanCheck("device_class", "Bluetooth Device Class Posture", _check_device_class, (address, hci, services, info_result)),
                ScanCheck("lmp_features", "LMP Feature Posture", _check_lmp_features, (address, hci)),
            ),
        ),
    ]

    for non_cve_section in non_cve_sections:
        section(non_cve_section.title, style="bt.cyan")
        for non_cve_check in non_cve_section.checks:
            _run_non_cve_check(non_cve_check, non_cve_section.title)

    if active:
        section("Active Check: BIAS Vulnerability Probe")
        bias_active_results = _check_bias_active(address, hci, ssp, phone_address)
        findings.extend(bias_active_results)
        non_cve_check_log.append({
            "check_id": "bias_active",
            "title": "Active BIAS Probe",
            "section": "Active Check: BIAS Vulnerability Probe",
            **summarize_check(bias_active_results),
        })
        emit_cli_event(
            event_type="execution_result",
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id="bias_active",
            target=address,
            adapter=hci,
            message=f"Non-CVE check finished: bias_active -> {non_cve_check_log[-1]['primary_status']}",
            details={"status": non_cve_check_log[-1]["primary_status"]},
        )

    # DarkFirmware-enhanced active KNOB probe
    if _check_darkfirmware_available(hci) and active:
        section("Active Check: DarkFirmware KNOB Probe", style="bt.cyan")
        darkfirmware_knob_results = []
        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket
            from blue_tap.modules.fuzzing.protocols.lmp import build_enc_key_size_req

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
                    darkfirmware_knob_results.append(
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
        findings.extend(darkfirmware_knob_results)
        non_cve_check_log.append({
            "check_id": "darkfirmware_knob_probe",
            "title": "DarkFirmware KNOB Probe",
            "section": "Active Check: DarkFirmware KNOB Probe",
            **summarize_check(darkfirmware_knob_results),
        })
        emit_cli_event(
            event_type="execution_result",
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id="darkfirmware_knob_probe",
            target=address,
            adapter=hci,
            message=f"Non-CVE check finished: darkfirmware_knob_probe -> {non_cve_check_log[-1]['primary_status']}",
            details={"status": non_cve_check_log[-1]["primary_status"]},
        )

    section("Check 8: PerfektBlue (OpenSynergy BlueSDK)", style="bt.cyan")
    perfektblue_results = _check_perfektblue(address, services, device_name, manufacturer, sdp_raw)
    findings.extend(perfektblue_results)
    non_cve_check_log.append({
        "check_id": "perfektblue",
        "title": "PerfektBlue OpenSynergy BlueSDK Probe",
        "section": "Check 8: PerfektBlue (OpenSynergy BlueSDK)",
        **summarize_check(perfektblue_results),
    })
    emit_cli_event(
        event_type="execution_result",
        module="assessment.vuln_scanner",
        run_id=run_id,
        execution_id="perfektblue",
        target=address,
        adapter=hci,
        message=f"Non-CVE check finished: perfektblue -> {non_cve_check_log[-1]['primary_status']}",
        details={"status": non_cve_check_log[-1]["primary_status"]},
    )

    # -----------------------------------------------------------------------
    # CVE Behavioral Differential Probes
    # These checks should only emit confirmed / inconclusive /
    # pairing_required / not_applicable. Surface-only detections are omitted.
    # -----------------------------------------------------------------------
    from blue_tap.modules.assessment.checks.cve_bnep import (
        _check_bnep_role_swap,
        _check_bnep_heap_oracle,
    )
    from blue_tap.modules.assessment.checks.cve_avrcp import (
        _check_avrcp_metamsg_oob,
        _check_avrcp_getcap_leak,
    )
    from blue_tap.modules.assessment.checks.cve_sdp import (
        _check_sdp_continuation_info_leak,
    )
    from blue_tap.modules.assessment.checks.cve_airoha import (
        _check_airoha_race_gatt,
        _check_airoha_race_bredr,
        _check_airoha_race_link_key,
    )
    from blue_tap.modules.assessment.checks.cve_pairing import (
        _check_bredr_method_confusion,
        _check_justworks_silent_pair,
        _check_reflected_public_key,
    )
    from blue_tap.modules.assessment.checks.cve_raw_acl import (
        _check_bluefrag_boundary_probe,
    )
    from blue_tap.modules.assessment.checks.cve_hid import (
        _check_hid_unbonded_connection,
        _check_hogp_unbonded_write,
    )
    from blue_tap.modules.assessment.checks.cve_gatt import (
        _check_android_eatt_integer_overflow,
        _check_bluez_gatt_prep_write_overflow,
    )
    from blue_tap.modules.assessment.checks.cve_l2cap import (
        _check_android_l2cap_heap_jitter,
        _check_a2mp_heap_jitter,
        _check_ecred_6cid_overflow,
        _check_ecred_duplicate_id,
        _check_l2cap_conf_mtu_info_leak,
        _check_l2cap_efs_info_leak,
        _check_l2cap_psm_zero_uaf,
    )
    from blue_tap.modules.assessment.checks.cve_ble_smp import (
        _check_ble_legacy_pairing_bypass,
        _check_smp_bredr_oob,
    )

    def _run_cve_check(spec: CveCheck, section_title: str):
        """Run a CVE check, emit structured logs, and record a reportable result."""
        results = []
        verbose(f"[CVE] {spec.cve} — {spec.title}")
        emit_cli_event(
            event_type="execution_started",
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id=spec.cve,
            target=address,
            adapter=hci,
            message=f"CVE check started: {spec.cve}",
            details={"section": section_title, "title": spec.title},
        )
        try:
            results = spec.runner(*spec.args)
        except Exception as exc:
            warning(f"{spec.cve}: check failed ({exc})")
            cve_check_log.append({
                "cve": spec.cve,
                "title": spec.title,
                "section": section_title,
                "error": str(exc),
                "finding_count": 0,
                "primary_status": "error",
                "status_counts": {"error": 1},
                "evidence_samples": [],
            })
            emit_cli_event(
                event_type="run_error",
                module="assessment.vuln_scanner",
                run_id=run_id,
                execution_id=spec.cve,
                target=address,
                adapter=hci,
                message=f"CVE check failed: {spec.cve} ({exc})",
            )
            return
        for r in results:
            r.setdefault("check_title", spec.title)
            r.setdefault("category", "cve")
            r.setdefault("section", section_title)
            status = r.get("status")
            if status == "not_applicable":
                verbose(f"SKIP {r.get('cve','?')}: {r.get('evidence','not applicable for this target')}")
            elif status == "pairing_required":
                info(f"{r.get('cve','?')}: pairing required to validate ({r.get('evidence','target not pairable')})")
            elif status == "inconclusive":
                warning(f"INCONCLUSIVE {r.get('cve','?')}: {r.get('evidence','probe reached target but response was not definitive')}")
            elif status == "confirmed":
                warning(f"FOUND {r.get('cve','?')}: {r.get('name','')}")
        check_summary = summarize_check(results)
        cve_check_log.append({
            "cve": spec.cve,
            "title": spec.title,
            "section": section_title,
            **check_summary,
        })
        primary_status = check_summary["primary_status"]
        emit_cli_event(
            event_type=(
                "pairing_required" if primary_status == "pairing_required"
                else "execution_skipped" if primary_status == "not_applicable"
                else "execution_result"
            ),
            module="assessment.vuln_scanner",
            run_id=run_id,
            execution_id=spec.cve,
            target=address,
            adapter=hci,
            message=f"CVE check finished: {spec.cve} -> {primary_status}",
            details={"status": primary_status},
        )
        findings.extend(results)

    cve_sections = [
        CveSection(
            "Check 9: SDP CVE Probes (CVE-2017-0785)",
            (CveCheck("CVE-2017-0785", "SDP Continuation State Replay", _check_sdp_continuation_info_leak, (address,)),),
        ),
        CveSection(
            "Check 10: HID CVE Probes (CVE-2020-0556, CVE-2023-45866)",
            (
                CveCheck("CVE-2020-0556/CVE-2023-45866", "HID Unbonded L2CAP Connection", _check_hid_unbonded_connection, (address, services)),
                CveCheck("CVE-2023-45866", "HOGP Unbonded Report Write", _check_hogp_unbonded_write, (address,)),
            ),
        ),
        CveSection(
            "Check 11: BNEP CVE Probes (CVE-2017-0783, CVE-2017-13258 family)",
            (
                CveCheck("CVE-2017-0783", "BNEP Role Swap", _check_bnep_role_swap, (address, services)),
                CveCheck("CVE-2017-13258", "BNEP Heap Oracle", _check_bnep_heap_oracle, (address, services)),
            ),
        ),
        CveSection(
            "Check 12: AVRCP CVE Probes (CVE-2021-0507, CVE-2022-39176)",
            (
                CveCheck("CVE-2021-0507", "AVRCP Metadata OOB", _check_avrcp_metamsg_oob, (address, services)),
                CveCheck("CVE-2022-39176", "AVRCP GetCapabilities Leak", _check_avrcp_getcap_leak, (address, services)),
            ),
        ),
        CveSection(
            "Check 13: GATT/ATT CVE Probes (CVE-2022-0204, CVE-2023-35681)",
            (
                CveCheck("CVE-2022-0204", "BlueZ Prepare Write Overflow", _check_bluez_gatt_prep_write_overflow, (address,)),
                CveCheck("CVE-2023-35681", "Android EATT Integer Overflow", _check_android_eatt_integer_overflow, (address,)),
            ),
        ),
        CveSection(
            "Check 14: Airoha RACE Protocol Probes (CVE-2025-20700/01/02)",
            (
                CveCheck("CVE-2025-20700", "Airoha RACE GATT Auth Bypass", _check_airoha_race_gatt, (address,)),
                CveCheck("CVE-2025-20701", "Airoha RACE BR/EDR Auth Bypass", _check_airoha_race_bredr, (address, services)),
                CveCheck("CVE-2025-20702", "Airoha RACE Link Key Disclosure", _check_airoha_race_link_key, (address,)),
            ),
        ),
        CveSection(
            "Check 15: L2CAP CVE Probes (CVE-2019-3459, CVE-2018-9359/60/61, CVE-2020-12352, CVE-2022-42896, CVE-2022-20345, CVE-2022-42895, CVE-2026-23395)",
            (
                CveCheck("CVE-2019-3459", "L2CAP CONF MTU Leak", _check_l2cap_conf_mtu_info_leak, (address,)),
                CveCheck("CVE-2018-9359", "Android L2CAP Heap Jitter", _check_android_l2cap_heap_jitter, (address,)),
                CveCheck("CVE-2020-12352", "BlueZ A2MP Heap Jitter", _check_a2mp_heap_jitter, (address,)),
                CveCheck("CVE-2022-42896", "LE Credit-Based PSM Zero", _check_l2cap_psm_zero_uaf, (address,)),
                CveCheck("CVE-2022-20345", "eCred 6-CID Overflow", _check_ecred_6cid_overflow, (address,)),
                CveCheck("CVE-2026-23395", "eCred Duplicate Identifier", _check_ecred_duplicate_id, (address,)),
                CveCheck("CVE-2022-42895", "L2CAP EFS Leak", _check_l2cap_efs_info_leak, (address,)),
            ),
        ),
        CveSection(
            "Check 16: BLE/SMP CVE Probes (CVE-2024-34722, CVE-2018-9365, CVE-2020-26558)",
            (
                CveCheck("CVE-2020-26558", "Reflected Public Key", _check_reflected_public_key, (address,)),
                CveCheck("CVE-2024-34722", "BLE Legacy Pairing Bypass", _check_ble_legacy_pairing_bypass, (address,)),
                CveCheck("CVE-2018-9365", "SMP BR/EDR Fixed CID OOB", _check_smp_bredr_oob, (address, ssp)),
            ),
        ),
        CveSection(
            "Check 17: BR/EDR Pairing CVE Probes (CVE-2022-25837, CVE-2019-2225)",
            (
                CveCheck("CVE-2022-25837", "BR/EDR Method Confusion", _check_bredr_method_confusion, (address, hci)),
                CveCheck("CVE-2019-2225", "JustWorks Silent Pair", _check_justworks_silent_pair, (address, hci)),
            ),
        ),
    ]
    if active:
        cve_sections.append(
            CveSection(
                "Check 18: Raw ACL CVE Probes (CVE-2020-0022)",
                (CveCheck("CVE-2020-0022", "BlueFrag Boundary Probe", _check_bluefrag_boundary_probe, (address, hci)),),
            )
        )
    else:
        verbose("Skipping raw ACL BlueFrag probe (use --active to enable)")

    for cve_section in cve_sections:
        section(cve_section.title, style="bt.cyan")
        for cve_check in cve_section.checks:
            _run_cve_check(cve_check, cve_section.title)

    if not active:
        info("Tip: Use --active to enable additional invasive checks (BIAS probe, PIN lockout)")

    _print_findings(address, findings)
    result = build_vulnscan_result(
        target=address,
        adapter=hci,
        active=active,
        findings=findings,
        cve_checks=cve_check_log,
        non_cve_checks=non_cve_check_log,
        started_at=started_at,
        run_id=run_id,
    )
    emit_cli_event(
        event_type="run_completed",
        module="assessment.vuln_scanner",
        run_id=run_id,
        target=address,
        adapter=hci,
        message=(
            f"Vulnerability scan completed: {len(findings)} findings, "
            f"{sum(1 for f in findings if f.get('status') == 'confirmed')} confirmed"
        ),
    )
    return result


def scan_vulnerabilities(address: str, hci: str | None = None, active: bool = False,
                         phone_address: str | None = None) -> list[dict]:
    """Compatibility wrapper returning only the vulnerability findings list."""
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    return run_vulnerability_scan(address, hci=hci, active=active, phone_address=phone_address).get("module_data", {}).get("findings", [])


def _print_findings(address: str, findings: list[dict]):
    """Print vulnerability findings summary with evidence quality context."""
    console.print()
    if not findings:
        success(f"No indicators found on {address} from available checks")
        return

    # Exclude not_applicable (skipped) from the display table — they're counted in the summary
    displayable = [f for f in findings if f.get("status") != "not_applicable"]
    if displayable:
        vuln_table(displayable)

    summary = summarize_findings(findings)

    summary_panel(
        "Vulnerability Scan Summary",
        {
            "Target": address,
            "Total Findings": str(summary["displayed"]),
            "Confirmed": str(summary["confirmed"]),
            "Not Detected": str(summary["not_detected"]),
            "Inconclusive": str(summary["inconclusive"]),
            "Pairing Required": str(summary["pairing_required"]),
            "Skipped (Not Applicable)": str(summary["not_applicable"]),
            "Critical/High Severity": str(summary["high_or_critical"]),
        },
        style="red" if summary["high_or_critical"] > 0 else "yellow" if summary["inconclusive"] > 0 else "green",
    )


# ── Native Module wrapper ─────────────────────────────────────────────────────

from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptBool, OptString
from blue_tap.framework.registry import ModuleFamily


class VulnScannerModule(Module):
    """Vulnerability Scanner.

    Runs CVE and posture checks against a Bluetooth target and produces a
    structured assessment report. Combines SDP enumeration, GATT fingerprinting,
    and protocol-level probes to assess the attack surface.
    """

    module_id = "assessment.vuln_scanner"
    family = ModuleFamily.ASSESSMENT
    name = "Vulnerability Scanner"
    description = "Run CVE and attack-surface checks against a Bluetooth target"
    protocols = ("Classic", "BLE")
    requires = ("adapter", "classic_target")
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.vulnscan.result"
    has_report_adapter = True
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target Bluetooth address"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptBool("ACTIVE", default=False,
                description="Enable active probing (connects to target)"),
        OptString("PHONE", default="",
                  description="Phone/attacker address for pair-based checks"),
    )

    def run(self, ctx: RunContext) -> dict:
        """Execute the vulnerability scan and return a RunEnvelope."""
        address = ctx.options.get("RHOST", "")
        hci = ctx.options.get("HCI", "")
        active = bool(ctx.options.get("ACTIVE", False))
        phone = ctx.options.get("PHONE", "") or None

        try:
            return run_vulnerability_scan(
                address=address,
                hci=hci,
                active=active,
                phone_address=phone,
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception(
                "Vulnerability scan failed (target=%s, hci=%s)", address, hci
            )
            from blue_tap.framework.contracts.result_schema import (
                build_run_envelope, make_execution, make_evidence,
            )
            return build_run_envelope(
                schema=self.schema_prefix,
                module="assessment.vuln_scanner",
                module_id="assessment.vuln_scanner",
                target=address,
                adapter=hci,
                started_at=ctx.started_at,
                executions=[
                    make_execution(
                        execution_id="vuln_scan",
                        kind="check",
                        id="vuln_scan",
                        title="Vulnerability Scan",
                        module_id="assessment.vuln_scanner",
                        execution_status="error",
                        module_outcome="not_applicable",
                        evidence=make_evidence(summary=str(exc)),
                        destructive=False,
                        requires_pairing=False,
                    )
                ],
                summary={"outcome": "not_applicable", "error": str(exc)},
                module_data={},
                run_id=ctx.run_id,
            )
