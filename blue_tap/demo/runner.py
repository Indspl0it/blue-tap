"""Demo runner — simulates a full 9-phase automated pentest with mock data.

Uses the real Blue-Tap Rich UI but with hardcoded realistic data so no
Bluetooth hardware is required. Generates a real HTML+JSON report at the end.
"""

import os
import time

from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from blue_tap.utils.output import (
    banner, info, success, warning, console, section, phase, step, substep,
    device_table, service_table, vuln_table, get_progress,
    CYAN, GREEN, YELLOW, RED, PURPLE, DIM, BLUE, ORANGE,
)
from blue_tap.demo import mock_data as M


def _delay(base: float = 0.3, variance: float = 0.2):
    """Simulate work with a realistic delay."""
    import random
    time.sleep(base + random.uniform(0, variance))


def _channel_table(channels: list[dict]) -> Table:
    """Build RFCOMM channel scan table."""
    table = Table(
        title=f"[bold {CYAN}]RFCOMM Channel Scan[/bold {CYAN}]",
        show_lines=False, border_style=DIM,
    )
    table.add_column("Ch", style=DIM, width=4, justify="right")
    table.add_column("Status", width=10)
    table.add_column("Service", style="bold white")

    for ch in channels:
        status = ch["status"]
        if status == "open":
            status_str = f"[bold {GREEN}]OPEN[/bold {GREEN}]"
        else:
            status_str = f"[{DIM}]closed[/{DIM}]"
        svc = ch.get("service", "")
        table.add_row(str(ch["channel"]), status_str, svc)
    return table


def _l2cap_table(results: list[dict]) -> Table:
    """Build L2CAP PSM scan table."""
    table = Table(
        title=f"[bold {CYAN}]L2CAP PSM Scan[/bold {CYAN}]",
        show_lines=False, border_style=DIM,
    )
    table.add_column("PSM", style=DIM, width=8, justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Status", width=14)

    for r in results:
        psm_str = f"0x{r['psm']:04x}" if r["psm"] > 255 else str(r["psm"])
        status = r["status"]
        if status == "open":
            status_str = f"[bold {GREEN}]OPEN[/bold {GREEN}]"
        elif status == "auth_required":
            status_str = f"[bold {YELLOW}]AUTH REQ[/bold {YELLOW}]"
        else:
            status_str = f"[{DIM}]closed[/{DIM}]"
        table.add_row(psm_str, r["name"], status_str)
    return table


def _dos_result_table(results: list[dict]) -> Table:
    """Build DoS test results table."""
    table = Table(
        title=f"[bold {CYAN}]DoS Resilience Test Results[/bold {CYAN}]",
        show_lines=True, border_style=DIM,
    )
    table.add_column("#", style=DIM, width=3, justify="right")
    table.add_column("Test", style="bold white")
    table.add_column("Result", width=16)
    table.add_column("Packets", style=CYAN, justify="right")
    table.add_column("Response", style=DIM, justify="right")

    for i, r in enumerate(results, 1):
        result = r["result"]
        if result == "target_responsive":
            result_str = f"[bold {GREEN}]RESPONSIVE[/bold {GREEN}]"
        elif result == "target_degraded":
            result_str = f"[bold {YELLOW}]DEGRADED[/bold {YELLOW}]"
        else:
            result_str = f"[bold {RED}]UNRESPONSIVE[/bold {RED}]"

        resp = r["response_time_ms"]
        resp_str = f"{resp}ms" if resp > 0 else "N/A"
        table.add_row(str(i), r["test"], result_str, str(r["packets_sent"]), resp_str)
    return table


def _fuzz_table(stats: dict) -> Table:
    """Build fuzzing protocol statistics table."""
    table = Table(
        title=f"[bold {CYAN}]Fuzzing Campaign Statistics[/bold {CYAN}]",
        show_lines=True, border_style=DIM,
    )
    table.add_column("Protocol", style="bold white")
    table.add_column("Packets", style=CYAN, justify="right")
    table.add_column("Crashes", justify="right")
    table.add_column("Coverage Paths", style=DIM, justify="right")

    for proto, data in stats.items():
        crashes = data["crashes"]
        crash_str = f"[bold {RED}]{crashes}[/bold {RED}]" if crashes > 0 else f"[{GREEN}]0[/{GREEN}]"
        table.add_row(proto.upper(), f"{data['packets']:,}", crash_str, str(data["coverage"]))
    return table


def _crash_detail_panel(crash: dict) -> Panel:
    """Build a crash detail panel."""
    text = Text()
    text.append(f"  ID: ", style="bold")
    text.append(f"{crash['id']}\n")
    text.append(f"  Protocol: ", style="bold")
    text.append(f"{crash['protocol'].upper()}\n")
    text.append(f"  Severity: ", style="bold")
    sev = crash["severity"]
    sev_color = RED if sev in ("CRITICAL", "HIGH") else YELLOW
    text.append(f"{sev}\n", style=sev_color)
    text.append(f"  Description: ", style="bold")
    text.append(f"{crash['description']}\n")
    text.append(f"  Reproduction: ", style="bold")
    text.append(f"{crash['reproduction']}\n")
    text.append(f"  Input: ", style="bold")
    text.append(f"{crash['input_hex'][:64]}...\n", style=DIM)

    return Panel(text, title=f"[bold {RED}]Crash: {crash['id']}[/bold {RED}]",
                 border_style=RED, padding=(0, 2))


def _lmp_table(captures: list[dict]) -> Table:
    """Build LMP capture table."""
    table = Table(
        title=f"[bold {CYAN}]LMP Capture (DarkFirmware)[/bold {CYAN}]",
        show_lines=False, border_style=DIM,
    )
    table.add_column("Time", style=DIM, width=14)
    table.add_column("Dir", width=4)
    table.add_column("Opcode", style="bold white")
    table.add_column("Data", style=DIM)

    for cap in captures:
        ts = cap["timestamp"].split("T")[1][:12]
        direction = f"[{CYAN}]TX[/{CYAN}]" if cap["direction"] == "tx" else f"[{YELLOW}]RX[/{YELLOW}]"
        decoded = cap.get("decoded", {})
        data_str = ", ".join(f"{k}={v}" for k, v in decoded.items())
        table.add_row(ts, direction, cap["opcode"], data_str)
    return table


def run_demo(output_dir: str = "demo_output"):
    """Execute the full demo — 9 phases of automated IVI pentest with mock data."""

    os.makedirs(output_dir, exist_ok=True)
    results = {"target": M.IVI_ADDRESS, "status": "started", "phases": {}}
    start_time = time.time()

    console.print()
    console.rule("[bold red]Blue-Tap Automated Pentest[/bold red]", style="red")
    console.print()
    info(f"Target IVI: [bold]{M.IVI_NAME}[/bold] ({M.IVI_ADDRESS})")
    info(f"Adapter: {M.IVI_HCI}")
    info(f"Output: {output_dir}/")
    info(f"Mode: [bold yellow]DEMO[/bold yellow] — simulated data, no hardware required")
    console.print()

    # ── Phase 1: Discovery ──────────────────────────────────────────
    with phase("Device Discovery", 1, 9):
        with step("Scanning for nearby Bluetooth devices"):
            with get_progress() as progress:
                task = progress.add_task("Scanning Classic BT...", total=100)
                for i in range(100):
                    _delay(0.02, 0.01)
                    progress.update(task, advance=1)

        info(f"Found [bold]{len(M.SCAN_DEVICES)}[/bold] device(s)")
        console.print(device_table(M.SCAN_DEVICES))

        with step("Identifying paired phone"):
            _delay(0.5, 0.3)

        phone = M.SCAN_DEVICES[1]
        success(f"Identified phone: [bold]{M.PHONE_NAME}[/bold] ({M.PHONE_ADDRESS})")

        results["phases"]["discovery"] = {
            "status": "success",
            "devices_found": len(M.SCAN_DEVICES),
            "phone_address": M.PHONE_ADDRESS,
            "phone_name": M.PHONE_NAME,
        }

    # ── Phase 2: Fingerprinting ─────────────────────────────────────
    with phase("Device Fingerprinting", 2, 9):
        with step("Querying device information"):
            _delay(0.8, 0.4)

        fp = M.FINGERPRINT

        fp_table = Table(title=f"[bold {CYAN}]Target Fingerprint[/bold {CYAN}]",
                         show_lines=False, border_style=DIM)
        fp_table.add_column("Property", style="bold white", width=24)
        fp_table.add_column("Value", style=CYAN)

        fp_table.add_row("Name", fp["name"])
        fp_table.add_row("Address", fp["address"])
        fp_table.add_row("BT Version", fp["bt_version"])
        fp_table.add_row("LMP Version", fp["lmp_version"])
        fp_table.add_row("Manufacturer", fp["manufacturer"])
        fp_table.add_row("Chipset", fp["chipset"])
        fp_table.add_row("Profiles", str(len(fp["profiles"])))
        fp_table.add_row("Secure Connections", f"[bold {RED}]No[/bold {RED}]")
        fp_table.add_row("IO Capability", fp["security_posture"]["io_capability"])
        fp_table.add_row("Min Key Size", str(fp["security_posture"]["min_encryption_key_size"]))
        console.print(fp_table)

        with step("Analyzing attack surface"):
            _delay(0.3, 0.2)

        for hint in fp["vuln_hints"]:
            warning(f"Indicator: {hint}")

        info(f"Attack surface: {', '.join(fp['attack_surface'])}")
        results["phases"]["fingerprint"] = {"status": "success", "fingerprint": fp}

    # ── Phase 3: Reconnaissance ─────────────────────────────────────
    with phase("Service Reconnaissance", 3, 9):
        with step("Browsing SDP services"):
            _delay(1.0, 0.5)

        console.print(service_table(M.SDP_SERVICES, title="SDP Services"))
        info(f"Found [bold]{len(M.SDP_SERVICES)}[/bold] SDP service(s)")

        with step("Scanning RFCOMM channels 1-30"):
            with get_progress() as progress:
                task = progress.add_task("RFCOMM scan...", total=30)
                for i in range(30):
                    _delay(0.04, 0.02)
                    progress.update(task, advance=1)

        open_rfcomm = [ch for ch in M.RFCOMM_CHANNELS if ch["status"] == "open"]
        console.print(_channel_table(M.RFCOMM_CHANNELS))
        info(f"RFCOMM: [bold]{len(open_rfcomm)}[/bold] open channel(s)")

        with step("Scanning L2CAP PSMs"):
            _delay(0.6, 0.3)

        open_l2cap = [r for r in M.L2CAP_RESULTS if r["status"] in ("open", "auth_required")]
        console.print(_l2cap_table(M.L2CAP_RESULTS))
        info(f"L2CAP: [bold]{len(open_l2cap)}[/bold] open/auth-required PSM(s)")

        results["phases"]["recon"] = {
            "status": "success",
            "sdp_services": len(M.SDP_SERVICES),
            "rfcomm_open": len(open_rfcomm),
            "l2cap_open": len(open_l2cap),
            "services": M.SDP_SERVICES,
        }

    # ── Phase 4: Vulnerability Assessment ───────────────────────────
    with phase("Vulnerability Assessment", 4, 9):
        with step(f"Running CVE checks against {M.IVI_ADDRESS}"):
            with get_progress() as progress:
                task = progress.add_task("CVE checks...", total=len(M.VULN_FINDINGS))
                for finding in M.VULN_FINDINGS:
                    _delay(0.15, 0.1)
                    substep(f"Checking: {finding['name']}")
                    progress.update(task, advance=1)

        console.print(vuln_table(M.VULN_FINDINGS, title="Vulnerability Findings"))

        sev_counts = {}
        for f in M.VULN_FINDINGS:
            sev = f["severity"]
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_summary = ", ".join(f"[bold]{c} {s}[/bold]" for s, c in
                                sorted(sev_counts.items(),
                                       key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x[0])))
        warning(f"[bold]{len(M.VULN_FINDINGS)}[/bold] findings: {sev_summary}")

        results["phases"]["vuln_assessment"] = {
            "status": "success",
            "findings": M.VULN_FINDINGS,
            "count": len(M.VULN_FINDINGS),
        }

    # ── Phase 5: Pairing & Encryption Attacks ───────────────────────
    with phase("Pairing & Encryption Attacks", 5, 9):
        with step("Probing SSP downgrade vulnerability"):
            _delay(1.2, 0.5)

        ssp = M.SSP_PROBE_RESULT
        for ev in ssp["evidence"]:
            substep(ev)
        warning("SSP downgrade: [bold red]VULNERABLE[/bold red] - legacy PIN fallback possible")

        with step("Probing KNOB vulnerability (CVE-2019-9506)"):
            _delay(1.0, 0.4)

        knob = M.KNOB_PROBE_RESULT
        for ev in knob["evidence"]:
            substep(ev)
        warning("KNOB: [bold red]VULNERABLE[/bold red] - key size negotiated to 1 byte")

        with step("LMP security negotiation capture"):
            _delay(0.8, 0.3)

        console.print(_lmp_table(M.LMP_CAPTURES))

        results["phases"]["pairing_attacks"] = {
            "status": "success",
            "attacks": {
                "ssp_probe": ssp,
                "knob_probe": knob,
            },
        }

    # ── Phase 6: Exploitation (Hijack + Data Extraction) ────────────
    with phase("Exploitation (Hijack + Data Extraction)", 6, 9):
        with step(f"Spoofing MAC to impersonate {M.PHONE_NAME}"):
            _delay(1.5, 0.5)
        success(f"MAC spoofed to {M.PHONE_ADDRESS}")

        with step("Connecting to IVI as paired phone"):
            _delay(2.0, 0.8)
        success("Connected without user interaction (cached link key)")

        with step("Extracting phonebook via PBAP (ch19)"):
            with get_progress() as progress:
                task = progress.add_task("Downloading contacts...", total=M.PBAP_CONTACTS["count"])
                for i in range(M.PBAP_CONTACTS["count"]):
                    _delay(0.005, 0.002)
                    progress.update(task, advance=1)

        pbap = M.PBAP_CONTACTS
        info(f"Extracted [bold]{pbap['count']}[/bold] contacts, "
             f"{pbap['call_history']['incoming']}+{pbap['call_history']['outgoing']}+{pbap['call_history']['missed']} "
             f"call history entries")

        # Show sample contacts
        contact_table = Table(title=f"[bold {RED}]Extracted Contacts (sample)[/bold {RED}]",
                              show_lines=False, border_style=DIM)
        contact_table.add_column("Name", style="bold white")
        contact_table.add_column("Phone", style=CYAN)
        contact_table.add_column("Email", style=DIM)
        for c in pbap["sample_entries"]:
            contact_table.add_row(c["fn"], c["tel"], c.get("email", ""))
        console.print(contact_table)

        with step("Extracting messages via MAP (ch20)"):
            with get_progress() as progress:
                task = progress.add_task("Downloading messages...",
                                         total=M.MAP_MESSAGES["inbox_count"] + M.MAP_MESSAGES["sent_count"])
                total = M.MAP_MESSAGES["inbox_count"] + M.MAP_MESSAGES["sent_count"]
                for i in range(total):
                    _delay(0.003, 0.001)
                    progress.update(task, advance=1)

        msg = M.MAP_MESSAGES
        info(f"Extracted [bold]{msg['inbox_count']}[/bold] inbox + "
             f"[bold]{msg['sent_count']}[/bold] sent messages")

        # Show sample messages
        msg_table = Table(title=f"[bold {RED}]Extracted Messages (sample)[/bold {RED}]",
                          show_lines=False, border_style=DIM)
        msg_table.add_column("From", style=CYAN)
        msg_table.add_column("Subject", style="bold white")
        msg_table.add_column("Preview", style=DIM, max_width=50)
        for m in msg["sample_messages"]:
            msg_table.add_row(m["from"], m["subject"], m["snippet"])
        console.print(msg_table)

        with step("Cleaning up — restoring original MAC"):
            _delay(0.5, 0.2)

        results["phases"]["exploitation"] = M.HIJACK_RESULT

    # ── Phase 7: Protocol Fuzzing ───────────────────────────────────
    with phase("Protocol Fuzzing", 7, 9):
        fz = M.FUZZ_RESULTS
        info(f"Strategy: [bold]coverage-guided[/bold] (response-diversity feedback)")
        info(f"Protocols: {', '.join(p.upper() for p in fz['protocols_fuzzed'])}")
        info(f"Duration: {fz['duration_seconds']}s (demo accelerated)")

        with step("Running coverage-guided fuzzing campaign"):
            with get_progress() as progress:
                task = progress.add_task("Fuzzing...", total=fz["packets_sent"])
                batch = fz["packets_sent"] // 50
                for i in range(50):
                    _delay(0.06, 0.03)
                    progress.update(task, advance=batch)
                    if i == 28:
                        warning(f"[bold]CRASH[/bold] detected in SDP — continuing campaign")
                    if i == 37:
                        warning(f"[bold]CRASH[/bold] detected in L2CAP — continuing campaign")
                progress.update(task, completed=fz["packets_sent"])

        console.print(_fuzz_table(fz["protocol_stats"]))

        info(f"Sent [bold]{fz['packets_sent']:,}[/bold] test cases across 4 protocols")
        info(f"Coverage paths discovered: [bold]{fz['coverage_paths']}[/bold]")
        info(f"State transitions observed: [bold]{fz['state_transitions']}[/bold]")
        warning(f"[bold]{fz['crashes']}[/bold] unique crash(es), "
                f"[bold]{fz['hangs']}[/bold] hang(s), "
                f"[bold]{fz['anomalies_detected']}[/bold] anomalies")

        for crash in fz["crash_details"]:
            console.print(_crash_detail_panel(crash))

        results["phases"]["fuzzing"] = fz

    # ── Phase 8: DoS Testing ────────────────────────────────────────
    with phase("Denial of Service Testing", 8, 9):
        dos = M.DOS_RESULTS

        with step("Running resilience test battery"):
            for r in dos:
                substep(f"Testing: {r['test']}...")
                _delay(0.8, 0.4)
                result = r["result"]
                if result == "target_responsive":
                    info(f"    {r['test']}: [bold green]RESPONSIVE[/bold green]")
                elif result == "target_degraded":
                    warning(f"    {r['test']}: [bold yellow]DEGRADED[/bold yellow]")
                else:
                    warning(f"    {r['test']}: [bold red]UNRESPONSIVE[/bold red]")

        console.print(_dos_result_table(dos))

        unresponsive = sum(1 for r in dos if r["result"] == "target_unresponsive")
        degraded = sum(1 for r in dos if r["result"] == "target_degraded")
        info(f"{len(dos)} tests run: {unresponsive} unresponsive, {degraded} degraded")

        results["phases"]["dos_testing"] = {
            "status": "success",
            "tests_run": len(dos),
            "unresponsive_count": unresponsive,
            "results": dos,
        }

    # ── Phase 9: Report Generation ──────────────────────────────────
    with phase("Report Generation", 9, 9):
        with step("Compiling assessment data"):
            _delay(0.5, 0.2)

        from blue_tap.report.generator import ReportGenerator
        from blue_tap.demo.report_data import (
            build_demo_dos_result,
            build_demo_fingerprint_result,
            build_demo_fuzz_result,
            build_demo_recon_result,
            build_demo_scan_result,
            build_demo_vuln_result,
        )

        report = ReportGenerator()

        # Feed standardized demo envelopes into the report generator
        report.add_run_envelope(
            build_demo_scan_result(
                devices=M.SCAN_DEVICES,
                adapter=M.IVI_HCI,
                duration_requested=15,
            )
        )
        report.add_run_envelope(
            build_demo_fingerprint_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                fingerprint=M.FINGERPRINT,
            )
        )
        report.add_run_envelope(
            build_demo_vuln_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                findings=M.VULN_FINDINGS,
            )
        )
        report.add_run_envelope(
            build_demo_recon_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                entries=M.SDP_SERVICES,
            )
        )

        from blue_tap.core.attack_framework import build_attack_result
        from blue_tap.core.data_framework import build_data_result

        report.add_run_envelope(
            build_attack_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                operation="demo_attack_phases",
                title="Demo Attack Phases",
                protocol="multi",
                module_data={
                    "results": {
                        "pairing_attacks": results["phases"].get("pairing_attacks", {}),
                        "exploitation": M.HIJACK_RESULT,
                    }
                },
                summary_data={"demo": True},
                observations=["source=demo"],
            )
        )

        report.add_run_envelope(
            build_data_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                family="pbap",
                operation="demo_pbap_dump",
                title="Demo PBAP Dump",
                module_data={
                    "results": {"contacts": M.PBAP_CONTACTS, "source": f"PBAP dump from {M.IVI_NAME}"},
                    "output_dir": "demo_pbap",
                },
                summary_data={"demo": True},
                observations=["source=demo"],
            )
        )

        report.add_run_envelope(
            build_data_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                family="map",
                operation="demo_map_dump",
                title="Demo MAP Dump",
                module_data={
                    "results": {"messages": M.MAP_MESSAGES, "source": f"MAP dump from {M.IVI_NAME}"},
                    "output_dir": "demo_map",
                },
                summary_data={"demo": True},
                observations=["source=demo"],
            )
        )

        report.add_run_envelope(
            build_demo_fuzz_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                fuzz_results=M.FUZZ_RESULTS,
            )
        )

        report.add_run_envelope(
            build_demo_dos_result(
                target=M.IVI_ADDRESS,
                adapter=M.IVI_HCI,
                checks=M.DOS_RESULTS,
            )
        )

        report.add_lmp_captures(M.LMP_CAPTURES)

        report.add_session_metadata({
            "name": f"demo-{M.IVI_ADDRESS.replace(':', '')}",
            "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "targets": [M.IVI_ADDRESS],
            "commands": [
                {"command": phase_name, "category": "auto", "target": M.IVI_ADDRESS,
                 "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}
                for phase_name in results["phases"]
            ],
        })

        with step("Generating HTML report"):
            _delay(0.3, 0.1)

        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(output_dir, f"report_{ts}.html")
        json_path = os.path.join(output_dir, f"report_{ts}.json")

        report.generate_html(html_path)

        with step("Generating JSON report"):
            _delay(0.2, 0.1)

        report.generate_json(json_path)

        # Create "latest" symlinks
        import shutil
        latest_html = os.path.join(output_dir, "report.html")
        latest_json = os.path.join(output_dir, "report.json")
        try:
            shutil.copy2(html_path, latest_html)
            shutil.copy2(json_path, latest_json)
        except OSError:
            pass

        success(f"HTML report: [bold]{html_path}[/bold]")
        success(f"JSON report: [bold]{json_path}[/bold]")

        results["phases"]["report"] = {"status": "success", "html": html_path, "json": json_path}

    # ── Final Summary ───────────────────────────────────────────────
    total_time = time.time() - start_time
    results["total_time_seconds"] = round(total_time, 1)
    results["status"] = "complete"

    console.print()
    console.rule(f"[bold green]Pentest Complete "
                 f"(9/9 phases, {total_time:.1f}s)[/bold green]", style="green")
    console.print()

    # Executive summary panel
    crit = sum(1 for f in M.VULN_FINDINGS if f["severity"] == "CRITICAL")
    high = sum(1 for f in M.VULN_FINDINGS if f["severity"] == "HIGH")
    med = sum(1 for f in M.VULN_FINDINGS if f["severity"] == "MEDIUM")
    low = sum(1 for f in M.VULN_FINDINGS if f["severity"] == "LOW")

    summary_items = Text()
    summary_items.append("  Target: ", style="bold")
    summary_items.append(f"{M.IVI_NAME} ({M.IVI_ADDRESS})\n")
    summary_items.append("  Paired Phone: ", style="bold")
    summary_items.append(f"{M.PHONE_NAME} ({M.PHONE_ADDRESS})\n")
    summary_items.append("  Risk Rating: ", style="bold")
    summary_items.append("CRITICAL\n", style=f"bold {RED}")
    summary_items.append("  Vulnerabilities: ", style="bold")
    summary_items.append(f"{crit} CRITICAL", style=f"bold {RED}")
    summary_items.append(", ")
    summary_items.append(f"{high} HIGH", style=f"bold {ORANGE}")
    summary_items.append(", ")
    summary_items.append(f"{med} MEDIUM", style=f"bold {YELLOW}")
    summary_items.append(", ")
    summary_items.append(f"{low} LOW\n", style=f"bold {GREEN}")
    summary_items.append("  Data Extracted: ", style="bold")
    summary_items.append("156 contacts, 122 call logs, 436 messages\n")
    summary_items.append("  Fuzzing: ", style="bold")
    summary_items.append(f"{M.FUZZ_RESULTS['packets_sent']:,} packets, "
                         f"{M.FUZZ_RESULTS['crashes']} crashes\n")
    summary_items.append("  DoS: ", style="bold")
    summary_items.append("1 unresponsive, 2 degraded out of 5 tests\n")
    summary_items.append("  Total Time: ", style="bold")
    summary_items.append(f"{total_time:.1f} seconds\n")
    summary_items.append("  Reports: ", style="bold")
    summary_items.append(f"{output_dir}/report.html\n")

    console.print(Panel(summary_items, title="[bold]Assessment Summary[/bold]",
                         border_style="red", padding=(1, 2)))

    console.print()
    info("[bold yellow]DEMO MODE[/bold yellow] — All data above is simulated. "
         "No Bluetooth hardware was used.")
    info(f"Open [bold]{output_dir}/report.html[/bold] in a browser for the full report.")
    console.print()

    return results
