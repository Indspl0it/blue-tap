"""Assessment CLI — vulnerability scanning and fleet-wide assessment."""

from __future__ import annotations

import rich_click as click
from rich.table import Table

from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup, _save_json
from blue_tap.utils.output import info, success, error, warning, console
from blue_tap.utils.interactive import resolve_address


# ============================================================================
# VULNSCAN - Vulnerability Scanner
# ============================================================================

@click.command("vulnscan", cls=LoggedCommand)
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
@click.option("--phone", default=None, help="Paired phone MAC for the BIAS auto-reconnect probe")
def vulnscan(address, hci, output, phone):
    """Scan target for vulnerabilities and attack-surface indicators.

    \b
    Evidence-based checks: SSP/legacy pairing, service exposure (active
    RFCOMM probe), KNOB, BLURtooth, BIAS, BlueBorne, pairing method,
    writable GATT characteristics, and modular CVE differential probes.
    Findings are classified as confirmed, inconclusive, pairing_required,
    not_applicable, or legacy heuristic statuses where applicable.

    \b
    This command runs the full vulnscan pass, including active checks such as
    PIN lockout, raw ACL BlueFrag, and the BIAS auto-reconnect probe.
    Provide --phone if you want the BIAS probe to test reconnect behavior
    against the target's normally paired phone identity.
    """
    address = resolve_address(address)
    if not address:
        return

    phone_address = None
    if phone:
        phone_address = resolve_address(phone, prompt="Verify phone address")

    from blue_tap.modules.assessment.vuln_scanner import run_vulnerability_scan
    from blue_tap.modules.assessment.cve_framework import summarize_findings
    info(f"Starting vulnerability assessment on [bold]{address}[/bold]...")
    info("  Running 20+ checks: SSP, KNOB, BIAS, BlueBorne, BLURtooth, BLUFFS, PerfektBlue, BrakTooth...")
    result = run_vulnerability_scan(address, hci, active=True, phone_address=phone_address)
    findings = result.get("module_data", {}).get("findings", [])
    summary = summarize_findings(findings)
    critical = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
    success(
        f"Assessment complete: {summary['displayed']} finding(s) — "
        f"{summary['confirmed']} confirmed, {summary['inconclusive']} inconclusive, "
        f"{summary['pairing_required']} pairing-required "
        f"({critical} CRITICAL, {high} HIGH)"
    )

    # Recommended next steps based on findings
    if findings:
        shown = set()
        recommendations = []
        for f in findings:
            name = f.get("name", "").lower()
            if "knob" in name and "knob" not in shown:
                recommendations.append(f"  KNOB: blue-tap knob probe {address} -i {hci}")
                shown.add("knob")
            elif "bias" in name and "bias" not in shown:
                _phone = phone or "PHONE_MAC"
                recommendations.append(f"  BIAS: blue-tap bias probe {address} {_phone} -i {hci}")
                shown.add("bias")
            elif "bluffs" in name and "bluffs" not in shown:
                recommendations.append(f"  BLUFFS: blue-tap bluffs {address} --variant probe -i {hci}")
                shown.add("bluffs")
            elif ("blurtooth" in name or "ctkd" in name) and "blurtooth" not in shown:
                recommendations.append(f"  BLURtooth: blue-tap vulnscan {address} -i {hci}")
                shown.add("blurtooth")
            elif "service" in name and "expos" in name and "service" not in shown:
                _phone = phone or "PHONE_MAC"
                recommendations.append(f"  Data extraction: blue-tap hijack {address} {_phone} -i {hci}")
                shown.add("service")
        if recommendations:
            info("")
            info("Recommended next steps:")
            for rec in recommendations:
                info(rec)

    from blue_tap.framework.sessions.store import log_command
    log_command("vulnscan", result, category="vuln", target=address)

    if output:
        _save_json(result, output)


# ============================================================================
# FLEET - Fleet-Wide Assessment
# ============================================================================

@click.group(cls=LoggedGroup)
def fleet():
    """Fleet-wide Bluetooth assessment — scan, classify, and vulnscan multiple devices."""


@fleet.command("scan")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0")
def fleet_scan(duration, hci):
    """Scan and classify all nearby Bluetooth devices.

    \b
    Discovers Classic and BLE devices, classifies each as:
    IVI, phone, headset, computer, wearable, or unknown.
    """
    from blue_tap.modules.assessment.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    table = Table(title=f"Discovered Devices ({len(devices)})")
    table.add_column("Address", style="bold")
    table.add_column("Name")
    table.add_column("RSSI")
    table.add_column("Type")
    table.add_column("Classification", style="bold")

    class_colors = {"ivi": "red", "phone": "cyan", "headset": "yellow",
                    "computer": "blue", "wearable": "magenta", "unknown": "dim"}

    for dev in devices:
        cls = dev.get("classification", "unknown")
        color = class_colors.get(cls, "white")
        table.add_row(
            dev.get("address", "?"),
            dev.get("name", "Unknown"),
            str(dev.get("rssi", "")),
            dev.get("type", "Classic"),
            f"[{color}]{cls.upper()}[/{color}]",
        )
    console.print(table)

    ivi_count = sum(1 for d in devices if d.get("classification") == "ivi")
    phone_count = sum(1 for d in devices if d.get("classification") == "phone")
    info(f"Found: {ivi_count} IVI(s), {phone_count} phone(s), {len(devices) - ivi_count - phone_count} other(s)")

    from blue_tap.framework.sessions.store import log_command
    # Log the underlying scan RunEnvelope (produced by FleetAssessment.scan())
    log_command("fleet_scan", assessment._scan_envelope, category="scan")


@fleet.command("vulnscan")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("--all-devices", is_flag=True, help="Assess all devices, not just IVIs")
def fleet_assess(duration, hci, all_devices):
    """Scan, classify, and run vulnerability scans on all IVIs.

    \b
    By default, only scans devices classified as IVI.
    Use --all-devices to scan everything discovered.
    """
    from blue_tap.modules.assessment.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    device_class = None if all_devices else "ivi"
    class_label = "all devices" if all_devices else "IVIs"
    targets_to_assess = [d["address"] for d in devices
                         if device_class is None or d.get("classification") == device_class]

    if not targets_to_assess:
        warning(f"No {class_label} found to scan")
        return

    info(f"Running vulnscan on {len(targets_to_assess)} {class_label}...")
    results = assessment.assess(targets=targets_to_assess)

    console.print()
    risk_color = "dim"
    for dev_result in results:
        addr = dev_result.get("address", "?")
        risk = dev_result.get("risk_rating", "UNKNOWN")
        findings = dev_result.get("findings", [])
        risk_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green"}.get(risk, "dim")

        console.print(f"[bold]{addr}[/bold] — [{risk_color}]{risk}[/{risk_color}] ({len(findings)} findings)")
        for f in findings[:3]:
            sev = f.get("severity", "?")
            console.print(f"  [{sev.lower() if sev in ('HIGH','CRITICAL') else 'dim'}]{sev}[/] {f.get('name', '?')}")
        if len(findings) > 3:
            console.print(f"  [dim]... and {len(findings) - 3} more[/dim]")

    report = assessment.report()
    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    # Log the underlying scan envelope produced during fleet.scan()
    log_command("fleet_scan", assessment._scan_envelope, category="scan")
    # Wrap fleet assessment results in a RunEnvelope before logging
    assess_envelope = build_run_envelope(
        schema="blue_tap.vuln.result",
        module="vuln",
        target="fleet",
        adapter=hci,
        operator_context={"operation": "fleet_assess", "all_devices": all_devices},
        summary={
            "assessed": report.get("assessed", 0),
            "overall_risk": report.get("overall_risk", "UNKNOWN"),
            "total_devices": report.get("total_devices", 0),
        },
        executions=[],
        module_data=report,
        run_id=make_run_id("vuln"),
    )
    log_command("fleet_assess", assess_envelope, category="vuln")

    console.print()
    success(f"Fleet vulnscan complete: {report.get('assessed', 0)} devices scanned, "
            f"overall risk: [{risk_color}]{report.get('overall_risk', '?')}[/{risk_color}]")


@fleet.command("report")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("-f", "--format", "fmt", default="html", type=click.Choice(["html", "json"]))
@click.option("--all-devices", is_flag=True, help="Assess all devices, not just IVIs")
def fleet_report(duration, hci, output, fmt, all_devices):
    """Generate a consolidated fleet vulnerability report."""
    from blue_tap.modules.assessment.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info("Running full fleet vulnerability workflow (scan + classify + vulnscan)...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    if all_devices:
        targets = [d["address"] for d in devices]
    else:
        targets = [d["address"] for d in devices if d.get("classification") == "ivi"]

    if targets:
        assessment.assess(targets=targets)
    else:
        warning("No devices to scan")

    report_data = assessment.report()

    out_path = output or f"fleet_report.{fmt}"
    if fmt == "json":
        _save_json(report_data, out_path)
    else:
        from blue_tap.interfaces.reporting.generator import ReportGenerator
        rpt = ReportGenerator()
        scan_run = report_data.get("scan_run", {})
        rpt.add_run_envelope(scan_run)
        for dev in report_data.get("devices", []):
            vulnscan_data = dev.get("vulnscan", {})
            rpt.add_run_envelope(vulnscan_data)
        rpt.generate_html(out_path)

    from blue_tap.framework.contracts.result_schema import build_run_envelope, make_run_id, now_iso
    from blue_tap.framework.sessions.store import log_command
    # Log the underlying scan envelope produced during fleet.scan()
    log_command("fleet_scan", assessment._scan_envelope, category="scan")
    # Wrap fleet report data in a RunEnvelope before logging
    report_envelope = build_run_envelope(
        schema="blue_tap.vuln.result",
        module="vuln",
        target="fleet",
        adapter=hci,
        operator_context={"operation": "fleet_report", "all_devices": all_devices, "fmt": fmt},
        summary={
            "assessed": report_data.get("assessed", 0),
            "overall_risk": report_data.get("overall_risk", "UNKNOWN"),
            "total_devices": report_data.get("total_devices", 0),
        },
        executions=[],
        module_data=report_data,
        run_id=make_run_id("vuln"),
    )
    log_command("fleet_report", report_envelope, category="vuln")


__all__ = ["vulnscan", "fleet"]
