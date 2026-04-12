"""Reconnaissance CLI — recon group for service enumeration and device fingerprinting."""

from __future__ import annotations

import rich_click as click
from rich.panel import Panel

from blue_tap.framework.runtime.cli_events import emit_cli_event
from blue_tap.interfaces.cli.shared import (
    LoggedCommand,
    LoggedGroup,
    _recon_artifact,
    _recon_cli_context,
    _recon_error,
    _recon_module_data,
    _recon_persist,
    _recon_result,
    _recon_skip,
    _recon_start,
    _save_json,
)
from blue_tap.utils.interactive import resolve_address
from blue_tap.utils.output import info, success, warning, error, service_table, channel_table, console


@click.group(cls=LoggedGroup)
def recon():
    """Service enumeration and device fingerprinting."""


@recon.command("auto")
@click.argument("address", required=False, default=None)
@click.option("--hci", default="hci0", help="HCI adapter for classic probes")
@click.option("--below-hci-hci", default="hci1", help="HCI adapter for DarkFirmware below-HCI collectors")
@click.option("--with-captures", is_flag=True, help="Include prerequisite-aware capture collectors")
@click.option("--with-below-hci", is_flag=True, help="Include prerequisite-aware below-HCI collectors")
@click.option("-d", "--duration", default=20, type=int, help="Capture duration for optional recon collectors")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_auto(address, hci, below_hci_hci, with_captures, with_below_hci, duration, output):
    """Run capability-driven classic/BLE reconnaissance automatically."""
    address = resolve_address(address)
    if not address:
        return

    from blue_tap.modules.reconnaissance.campaign import run_auto_recon
    from blue_tap.framework.sessions.store import log_command

    info(f"Running automatic reconnaissance on [bold]{address}[/bold]...")
    result = run_auto_recon(
        address=address,
        hci=hci,
        below_hci_hci=below_hci_hci,
        with_captures=with_captures,
        with_below_hci=with_below_hci,
        duration=duration,
    )

    classification = result.get("summary", {}).get("classification", "undetermined")
    success(f"Recon capability classification: {classification}")
    for execution in result.get("executions", []):
        title = execution.get("title", execution.get("id", ""))
        state = execution.get("execution_status", "")
        outcome = execution.get("module_outcome", "")
        summary = execution.get("evidence", {}).get("summary", "")
        if state == "skipped":
            warning(f"{title}: skipped ({outcome})")
            if summary:
                info(f"  {summary}")
        else:
            info(f"{title}: {state}/{outcome}")
            if summary:
                info(f"  {summary}")

    log_command("recon_auto", result, category="recon", target=address)
    if output:
        _save_json(result, output)


@recon.command("sdp")
@click.argument("address", required=False, default=None)
@click.option("--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_sdp(address, hci, output):
    """Browse SDP services on a target device."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sdp import browse_services_detailed

    info(f"Browsing SDP services on [bold]{address}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("sdp_browse", target=address, adapter=hci)
    _recon_start(ctx, execution_id="sdp_browse", message=f"SDP browse started on {address}")
    try:
        sdp_result = browse_services_detailed(address, hci=hci)
    except TypeError:
        sdp_result = browse_services_detailed(address)
    services = sdp_result.get("services", [])
    if services:
        success(f"Found {len(services)} SDP service(s)")
        console.print(service_table(services, f"SDP Services: {address}"))

        # Highlight interesting services
        for svc in services:
            profile = svc.get("profile", "")
            if any(kw in profile for kw in ["PBAP", "MAP", "HFP", "A2DP", "SPP"]):
                info(f"  Attack surface: {svc.get('name')} -> {profile} "
                     f"(ch={svc.get('channel')})")
    else:
        warning(f"No SDP services found on {address}")

    result = build_recon_result(
        target=address,
        adapter=hci,
        run_id=ctx["run_id"],
        operation="sdp_browse",
        title="SDP Service Browse",
        protocol="SDP",
        entries=services,
        module_data_extra=_recon_module_data(sdp_result, ctx),
        observations=[
            f"service_count={len(services)}",
            f"rfcomm_channels={len(sdp_result.get('rfcomm_channels', []))}",
            f"l2cap_psms={len(sdp_result.get('l2cap_psms', []))}",
        ],
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="sdp_browse", message=f"SDP browse completed with {len(services)} service(s)")
    _recon_persist("sdp_browse", result, ctx, target=address, output=output)


@recon.command("gatt")
@click.argument("address", required=False, default=None)
@click.option("--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_gatt(address, hci, output):
    """Enumerate BLE GATT services and characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.gatt import enumerate_services_detailed_sync, flatten_gatt_entries

    info(f"Enumerating GATT services on [bold]{address}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("gatt_enum", target=address, adapter=hci)
    _recon_start(ctx, execution_id="gatt_enum", message=f"GATT enumeration started on {address}")
    try:
        gatt_result = enumerate_services_detailed_sync(address, adapter=hci)
    except TypeError:
        gatt_result = enumerate_services_detailed_sync(address)
    services = gatt_result.get("services", [])
    total_chars = sum(len(s.get("characteristics", [])) for s in services)
    if services:
        success(f"Found {len(services)} service(s) with {total_chars} characteristic(s)")
        for svc in services:
            console.print(f"\n[bold cyan]Service: {svc['description']}[/bold cyan]")
            console.print(f"  UUID: {svc['uuid']}  Handle: {svc['handle']}")
            for char in svc["characteristics"]:
                props = ", ".join(char["properties"])
                console.print(f"  [green]{char['description']}[/green] [{props}]")
                console.print(f"    UUID: {char['uuid']}")
                if char.get("value_hex"):
                    console.print(f"    Value: {char['value_hex']} | {char.get('value_str', '')}")
    else:
        warning(f"No GATT services found (status={gatt_result.get('status', 'unknown')})")
        if gatt_result.get("error"):
            info(f"  {gatt_result.get('error')}")

    flat_entries = flatten_gatt_entries(services)
    result = build_recon_result(
        target=address,
        adapter=hci,
        run_id=ctx["run_id"],
        operation="gatt_enum",
        title="GATT Enumeration",
        protocol="GATT",
        entries=flat_entries,
        operator_context={"service_count": len(services)},
        module_outcome=(
            "observed"
            if services
            else ("auth_required" if gatt_result.get("status") == "auth_required" else "no_results")
        ),
        evidence_summary=(
            f"Enumerated {len(services)} GATT service(s) and {total_chars} characteristic(s)"
            if services
            else f"GATT enumeration completed with status={gatt_result.get('status', 'unknown')}"
        ),
        observations=gatt_result.get("observations", []),
        module_data_extra=_recon_module_data({
            "gatt_result": gatt_result,
            "service_count": len(services),
            "characteristic_count": total_chars,
        }, ctx),
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="gatt_enum", message=f"GATT enumeration completed with {len(services)} service(s)")
    _recon_persist("gatt_enum", result, ctx, target=address, output=output)


@recon.command("fingerprint")
@click.argument("address", required=False, default=None)
@click.option("--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_fingerprint(address, hci, output):
    """Fingerprint a device and identify IVI characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.fingerprint import fingerprint_device

    started_at = now_iso()
    ctx = _recon_cli_context("fingerprint", target=address, adapter=hci)
    _recon_start(ctx, execution_id="fingerprint", message=f"Fingerprinting started on {address}")
    info(f"Fingerprinting device [bold]{address}[/bold]...")
    fp = fingerprint_device(address, hci=hci)
    success(f"Fingerprint complete: {fp.get('manufacturer', '?')}, BT {fp.get('bt_version', '?')}, "
            f"{len(fp.get('profiles', []))} profile(s)")

    class_info = fp.get("device_class_info", {})
    class_str = ""
    if class_info:
        class_str = f"{class_info.get('major', '?')}/{class_info.get('minor', '?')}"
        if class_info.get("services"):
            class_str += f" [{', '.join(class_info['services'])}]"

    ivi_str = "[green]LIKELY[/green]" if fp.get("ivi_likely") else "[dim]Unknown[/dim]"
    panel_text = f"""[cyan]Address:[/cyan] {fp['address']}
[cyan]Name:[/cyan] {fp['name']}
[cyan]Chipset:[/cyan] {fp['manufacturer']}
[cyan]IVI Likely:[/cyan] {ivi_str}
[cyan]Device Class:[/cyan] {fp.get('device_class', 'N/A')} {class_str}
[cyan]BT Version:[/cyan] {fp.get('lmp_version') or fp.get('bt_version') or 'N/A'}
[cyan]Profiles:[/cyan] {len(fp['profiles'])}"""

    console.print(Panel(panel_text, title="Device Fingerprint", border_style="cyan"))

    if fp.get("ivi_signals"):
        console.print("\n[bold cyan]IVI Signals (heuristic):[/bold cyan]")
        for sig in fp["ivi_signals"]:
            console.print(f"  [cyan]~[/cyan] {sig}")

    if fp["attack_surface"]:
        console.print("\n[bold red]Attack Surface:[/bold red]")
        for surface in fp["attack_surface"]:
            console.print(f"  [red]>[/red] {surface}")

    if fp.get("vuln_hints"):
        console.print("\n[bold yellow]Vulnerability Indicators:[/bold yellow]")
        for hint in fp["vuln_hints"]:
            console.print(f"  [yellow]![/yellow] {hint}")

    result = build_recon_result(
        target=address,
        adapter=hci,
        run_id=ctx["run_id"],
        operation="fingerprint",
        title="Device Fingerprint",
        protocol="Fingerprint",
        entries=[],
        fingerprint=fp,
        module_data_extra=_recon_module_data({
            "device_class": fp.get("device_class"),
            "profiles": fp.get("profiles", []),
            "attack_surface": fp.get("attack_surface", []),
            "vuln_hints": fp.get("vuln_hints", []),
            "evidence_classes": fp.get("evidence_classes", {}),
            "manufacturer_sources": fp.get("manufacturer_sources", []),
        }, ctx),
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="fingerprint", message=f"Fingerprinting completed for {address}")
    _recon_persist("fingerprint", result, ctx, target=address, output=output)


@recon.command("ssp")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_ssp(address, output):
    """Check if device supports Secure Simple Pairing."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sdp import check_ssp

    info(f"Checking SSP support on [bold]{address}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("ssp_check", target=address, adapter="hci0")
    _recon_start(ctx, execution_id="ssp_check", message=f"SSP probe started on {address}")
    ssp_supported = check_ssp(address)
    if ssp_supported is True:
        success(f"{address} supports SSP (more secure pairing)")
    elif ssp_supported is False:
        warning(f"{address} may NOT support SSP (legacy pairing - easier to attack)")
    else:
        error(f"Could not determine SSP support for {address}")

    result = build_recon_result(
        target=address,
        adapter="hci0",
        run_id=ctx["run_id"],
        operation="ssp_check",
        title="Secure Simple Pairing Capability Check",
        protocol="SSP",
        entries=[],
        module_data_extra=_recon_module_data({"ssp_supported": ssp_supported}, ctx),
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="ssp_check", message=f"SSP probe completed for {address}")
    _recon_persist("ssp_check", result, ctx, target=address, output=output)


@recon.command("rfcomm-scan")
@click.argument("address", required=False, default=None)
@click.option("-t", "--timeout", default=2.0, help="Timeout per channel")
@click.option("--retries", default=1, help="Retries per channel on timeout")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_rfcomm_scan(address, timeout, retries, output):
    """Scan all RFCOMM channels (1-30) for hidden services."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.rfcomm_scan import RFCOMMScanner

    info(f"Scanning RFCOMM channels 1-30 on [bold]{address}[/bold] (timeout={timeout}s)...")
    started_at = now_iso()
    ctx = _recon_cli_context("rfcomm_scan", target=address, adapter="hci0")
    _recon_start(ctx, execution_id="rfcomm_scan", message=f"RFCOMM scan started on {address}")
    scanner = RFCOMMScanner(address)
    results = scanner.scan_all_channels(timeout_per_ch=timeout, max_retries=retries)

    # Show open/interesting channels only
    interesting = [r for r in results if r["status"] != "closed"]
    if interesting:
        console.print(channel_table(interesting, title="RFCOMM Scan Results"))
    else:
        warning("No open RFCOMM channels found")

    open_channels = [r for r in results if r["status"] == "open"]
    info(f"Scanned {len(results)} channels: {len(open_channels)} open")

    result = build_recon_result(
        target=address,
        adapter="hci0",
        run_id=ctx["run_id"],
        operation="rfcomm_scan",
        title="RFCOMM Channel Scan",
        protocol="RFCOMM",
        entries=results,
        operator_context={"timeout_per_channel": timeout, "retries": retries},
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="rfcomm_scan", message=f"RFCOMM scan completed on {address}")
    if output:
        # Serialize (strip raw_response bytes for JSON)
        for r in results:
            r.pop("raw_response", None)
    _recon_persist("rfcomm_scan", result, ctx, target=address, output=output)


@recon.command("l2cap-scan")
@click.argument("address", required=False, default=None)
@click.option("--dynamic", is_flag=True, help="Also scan dynamic PSM range")
@click.option("-t", "--timeout", default=1.0, help="Timeout per PSM")
@click.option("--workers", default=10, help="Parallel workers for dynamic scan")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_l2cap_scan(address, dynamic, timeout, workers, output):
    """Scan L2CAP PSM values for open services."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.l2cap_scan import L2CAPScanner

    range_desc = "standard + dynamic" if dynamic else "standard"
    info(f"Scanning L2CAP PSMs on [bold]{address}[/bold] ({range_desc}, timeout={timeout}s)...")
    started_at = now_iso()
    ctx = _recon_cli_context("l2cap_scan", target=address, adapter="hci0")
    _recon_start(ctx, execution_id="l2cap_scan", message=f"L2CAP scan started on {address}")
    scanner = L2CAPScanner(address)
    results = scanner.scan_standard_psms(timeout=timeout)

    if dynamic:
        info("  Scanning dynamic PSM range...")
        results.extend(scanner.scan_dynamic_psms(timeout=timeout, workers=workers))

    if results:
        console.print(channel_table(results, title="L2CAP Scan Results"))

    open_psms = [r for r in results if r["status"] in ("open", "auth_required")]
    if not open_psms:
        warning("No open L2CAP PSMs found")

    result = build_recon_result(
        target=address,
        adapter="hci0",
        run_id=ctx["run_id"],
        operation="l2cap_scan",
        title="L2CAP PSM Scan",
        protocol="L2CAP",
        entries=results,
        operator_context={"dynamic": dynamic, "timeout": timeout, "workers": workers},
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="l2cap_scan", message=f"L2CAP scan completed on {address}")
    _recon_persist("l2cap_scan", result, ctx, target=address, output=output)


@recon.command("capture-start")
@click.option("-o", "--output", default="bt_capture.log", help="Output file")
@click.option("-i", "--hci", default=None, help="HCI adapter (default: all)")
@click.option("--pcap", is_flag=True, help="Write btsnoop/pcap format for Wireshark")
def recon_capture_start(output, hci, pcap):
    """Start HCI traffic capture via btmon."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.hci_capture import HCICapture

    # Auto-adjust extension for pcap mode
    if pcap and not output.endswith((".pcap", ".btsnoop")):
        output = output.rsplit(".", 1)[0] + ".btsnoop"

    cap = HCICapture()
    started_at = now_iso()
    ctx = _recon_cli_context("capture_start", target="", adapter=hci or "all", details={"pcap": pcap, "output": output})
    _recon_start(ctx, execution_id="capture_start", message=f"HCI capture start requested on {hci or 'all'}")
    started = cap.start(output, hci=hci, pcap=pcap)
    if started:
        success(f"btmon capture started -> {output}")
    else:
        error(f"Failed to start capture")

    result = build_recon_result(
        target="",
        adapter=hci or "all",
        run_id=ctx["run_id"],
        operation="capture_start",
        title="HCI Capture Start",
        protocol="HCI",
        entries=[],
        module_outcome="observed" if started else "collector_unavailable",
        execution_status="completed" if started else "failed",
        module_data_extra=_recon_module_data({"capture_started": started, "output": output, "pcap": pcap}, ctx),
        operator_context={"pcap": pcap},
        started_at=started_at,
    )
    if started:
        _recon_result(
            ctx,
            execution_id="capture_start",
            message="HCI capture started",
        )
    else:
        _recon_error(ctx, execution_id="capture_start", message="HCI capture failed to start")
    _recon_persist("capture_start", result, ctx)


@recon.command("capture-stop")
def recon_capture_stop():
    """Stop HCI traffic capture."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.hci_capture import HCICapture

    cap = HCICapture()
    started_at = now_iso()
    ctx = _recon_cli_context("capture_stop", target="", adapter="all")
    _recon_start(ctx, execution_id="capture_stop", message="HCI capture stop requested")
    result = cap.stop()
    if result:
        success(f"Capture stopped: {result}")
    else:
        warning("No capture appears to be running")

    artifacts = []
    if result:
        from blue_tap.framework.contracts.result_schema import make_artifact
        artifacts.append(make_artifact(kind="pcap", label="HCI capture output", path=result))
    envelope = build_recon_result(
        target="",
        adapter="all",
        run_id=ctx["run_id"],
        operation="capture_stop",
        title="HCI Capture Stop",
        protocol="HCI",
        entries=[],
        module_outcome="observed" if result else "prerequisite_missing",
        execution_status="completed" if result else "skipped",
        module_data_extra=_recon_module_data({"capture_stopped": bool(result), "output": result}, ctx),
        artifacts=artifacts,
        started_at=started_at,
    )
    if result:
        _recon_artifact(
            ctx,
            execution_id="capture_stop",
            message=f"HCI capture saved to {result}",
            details={"path": result},
        )
        _recon_result(ctx, execution_id="capture_stop", message="HCI capture stop completed")
    else:
        _recon_skip(ctx, execution_id="capture_stop", message="No capture appears to be running")
    _recon_persist("capture_stop", envelope, ctx)


@recon.command("pairing-mode")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_pairing_mode(address, hci, output):
    """Detect target's pairing mode and IO capabilities."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.hci_capture import detect_pairing_mode

    info(f"Detecting pairing mode on [bold]{address}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("pairing_mode_probe", target=address, adapter=hci)
    _recon_start(ctx, execution_id="pairing_mode_probe", message=f"Pairing mode probe started on {address}")
    result = detect_pairing_mode(address, hci)
    panel_text = (
        f"[cyan]SSP Supported:[/cyan] {result.get('ssp_supported') if result.get('ssp_supported') is not None else 'Inconclusive (probe failed)'}\n"
        f"[cyan]IO Capability:[/cyan] {result.get('io_capability', 'Unknown')}\n"
        f"[cyan]Pairing Method:[/cyan] {result.get('pairing_method', 'Unknown')}"
    )
    console.print(Panel(panel_text, title="Pairing Mode Detection", border_style="cyan"))

    envelope = build_recon_result(
        target=address,
        adapter=hci,
        run_id=ctx["run_id"],
        operation="pairing_mode_probe",
        title="Pairing Mode Detection",
        protocol="Pairing",
        entries=[],
        module_data_extra=_recon_module_data({"pairing_probe": result}, ctx),
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="pairing_mode_probe", message=f"Pairing mode probe completed for {address}")
    _recon_persist("pairing_mode", envelope, ctx, target=address, output=output)


@recon.command("nrf-scan")
@click.option("-d", "--duration", default=30, help="Scan duration (seconds)")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_nrf_scan(duration, output):
    """Scan BLE advertisers using nRF52840 dongle."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sniffer import NRFBLESniffer

    info(f"Starting BLE advertisement scan via nRF52840 ({duration}s)...")
    started_at = now_iso()
    ctx = _recon_cli_context("nrf_ble_scan", target="", adapter="nrf52840", details={"duration": duration})
    _recon_start(ctx, execution_id="nrf_ble_scan", message=f"nRF BLE scan started for {duration}s")
    sniffer = NRFBLESniffer()
    advertisers = sniffer.scan_advertisers(duration)

    result = build_recon_result(
        target="",
        adapter="nrf52840",
        run_id=ctx["run_id"],
        operation="nrf_ble_scan",
        title="nRF BLE Advertisement Scan",
        protocol="BLE",
        entries=advertisers,
        operator_context={"duration": duration},
        module_data_extra=_recon_module_data({"advertisers": advertisers, "duration": duration}, ctx),
        started_at=started_at,
    )
    _recon_result(ctx, execution_id="nrf_ble_scan", message=f"nRF BLE scan completed with {len(advertisers)} advertiser(s)")
    _recon_persist("nrf_scan", result, ctx, output=output)


@recon.command("lmp-sniff")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=120, type=int, help="Capture duration in seconds")
@click.option("-o", "--output", default="lmp_capture.json", help="Output file path")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
@click.option("-f", "--format", "output_format", default="json",
              type=click.Choice(["json", "pcap"]), help="Output format (json=BTIDES v2, pcap=Wireshark)")
@click.option("--filter", "lmp_filter", default=None,
              type=click.Choice(["auth", "encryption", "features", "security"]),
              help="Filter LMP packets by category")
def recon_lmp_sniff(address, duration, output, hci, output_format, lmp_filter):
    """Capture LMP traffic using DarkFirmware RTL8761B.

    Monitors incoming LMP packets via the firmware's RX hook.
    Captures pre-encryption negotiation (features, auth, key size).
    Exports to BTIDES v2 JSON or Wireshark pcap format.
    """
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sniffer import DarkFirmwareSniffer, LMPFilter

    started_at = now_iso()
    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    sniffer = DarkFirmwareSniffer(hci_dev=hci_dev)
    if not sniffer.is_available():
        error("DarkFirmware not available. Check adapter with: blue-tap adapter firmware-status")
        ctx = _recon_cli_context("lmp_sniff", target=address or "", adapter=hci, details={"duration": duration, "output_format": output_format, "filter": lmp_filter or ""})
        _recon_skip(ctx, execution_id="lmp_sniff", message="LMP capture skipped because DarkFirmware is unavailable")
        envelope = build_recon_result(
            target=address or "",
            adapter=hci,
            run_id=ctx["run_id"],
            operation="lmp_sniff",
            title="LMP Capture",
            protocol="LMP",
            entries=[],
            module_outcome="prerequisite_missing",
            execution_status="skipped",
            module_data_extra=_recon_module_data({"capture_result": {"success": False, "error": "DarkFirmware unavailable"}, "output": output}, ctx),
            started_at=started_at,
        )
        _recon_persist("lmp_sniff", envelope, ctx, target=address or "")
        return

    pkt_filter = LMPFilter(category=lmp_filter) if lmp_filter else None
    info(f"Starting LMP capture (duration={duration}s, output={output}, format={output_format})")
    ctx = _recon_cli_context("lmp_sniff", target=address or "", adapter=hci, details={"duration": duration, "output_format": output_format, "filter": lmp_filter or ""})
    _recon_start(ctx, execution_id="lmp_sniff", message=f"LMP capture started on {hci}")
    result = sniffer.start_capture(
        target=address,
        output=output,
        duration=duration,
        lmp_filter=pkt_filter,
        output_format=output_format,
    )

    artifacts = []
    if result.get("success"):
        from blue_tap.framework.contracts.result_schema import make_artifact
        artifacts.append(make_artifact(kind=output_format, label="LMP capture", path=output))

    envelope = build_recon_result(
        target=address or "",
        adapter=hci,
        run_id=ctx["run_id"],
        operation="lmp_sniff",
        title="LMP Capture",
        protocol="LMP",
        entries=[],
        operator_context={"duration": duration, "output_format": output_format, "filter": lmp_filter or ""},
        module_outcome="artifact_collected" if result.get("success") else "collector_unavailable",
        execution_status="completed" if result.get("success") else "failed",
        module_data_extra=_recon_module_data({"capture_result": result, "output": output}, ctx),
        artifacts=artifacts,
        started_at=started_at,
    )
    if result.get("success"):
        _recon_artifact(ctx, execution_id="lmp_sniff", message=f"LMP capture saved to {output}", details={"path": output})
        _recon_result(ctx, execution_id="lmp_sniff", message=f"LMP capture completed with success={result.get('success', False)}")
    else:
        _recon_error(ctx, execution_id="lmp_sniff", message=f"LMP capture failed: {result.get('error', 'unknown error')}")
    _recon_persist("lmp_sniff", envelope, ctx, target=address or "")

    if result["success"]:
        success(f"Captured {result['packets']} LMP packets in {result['duration']}s")
        success(f"Output: {result['output']}")
    else:
        error("LMP capture failed")


@recon.command("lmp-monitor")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=0, type=int, help="Monitor duration (0=until Ctrl-C)")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
@click.option("--dashboard", is_flag=True, help="Rich live dashboard display")
@click.option("--filter", "lmp_filter", default=None,
              type=click.Choice(["auth", "encryption", "features", "security"]),
              help="Filter LMP packets by category")
def recon_lmp_monitor(address, duration, hci, dashboard, lmp_filter):
    """Real-time LMP packet monitor using DarkFirmware.

    Shows incoming LMP packets in real-time on the console.
    Use --dashboard for a Rich live UI with packet stream table.
    Use Ctrl-C to stop monitoring.
    """
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import make_artifact, now_iso
    from blue_tap.modules.reconnaissance.sniffer import DarkFirmwareSniffer, LMPFilter

    started_at = now_iso()
    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    sniffer = DarkFirmwareSniffer(hci_dev=hci_dev)
    if not sniffer.is_available():
        error("DarkFirmware not available. Check adapter with: blue-tap adapter firmware-status")
        ctx = _recon_cli_context("lmp_monitor", target=address or "", adapter=hci, details={"duration": duration, "dashboard": dashboard, "filter": lmp_filter or ""})
        _recon_skip(ctx, execution_id="lmp_monitor", message="LMP monitor skipped because DarkFirmware is unavailable")
        envelope = build_recon_result(
            target=address or "",
            adapter=hci,
            run_id=ctx["run_id"],
            operation="lmp_monitor",
            title="LMP Live Monitor",
            protocol="LMP",
            entries=[],
            module_outcome="prerequisite_missing",
            execution_status="skipped",
            module_data_extra=_recon_module_data({"capture_result": {"success": False, "error": "DarkFirmware unavailable"}}, ctx),
            started_at=started_at,
        )
        _recon_persist("lmp_monitor", envelope, ctx, target=address or "")
        return

    pkt_filter = LMPFilter(category=lmp_filter) if lmp_filter else None
    ctx = _recon_cli_context("lmp_monitor", target=address or "", adapter=hci, details={"duration": duration, "dashboard": dashboard, "filter": lmp_filter or ""})
    _recon_start(ctx, execution_id="lmp_monitor", message=f"LMP monitor started on {hci}")
    result = sniffer.monitor(
        target=address,
        duration=duration,
        lmp_filter=pkt_filter,
        dashboard=dashboard,
    )
    artifacts = []
    if result.get("packets"):
        artifacts.append(
            make_artifact(
                kind="monitor_summary",
                label="LMP monitor session",
                path="console",
                description="Interactive DarkFirmware LMP monitor session",
            )
        )
    envelope = build_recon_result(
        target=address or "",
        adapter=hci,
        run_id=ctx["run_id"],
        operation="lmp_monitor",
        title="LMP Live Monitor",
        protocol="LMP",
        entries=[],
        module_outcome="artifact_collected" if result.get("success") else "collector_unavailable",
        execution_status="completed" if result.get("success") else "failed",
        operator_context={
            "duration": duration,
            "dashboard": dashboard,
            "filter": lmp_filter or "",
        },
        module_data_extra=_recon_module_data({"capture_result": result}, ctx),
        evidence_summary=(
            f"LMP live monitor captured {result.get('packets', 0)} packet(s) "
            f"in {result.get('duration', 0)}s"
        ),
        observations=[
            f"dashboard={dashboard}",
            f"duration={duration}",
            f"filter={lmp_filter or 'none'}",
            f"packets={result.get('packets', 0)}",
            f"interrupted={result.get('interrupted', False)}",
        ],
        artifacts=artifacts,
        started_at=started_at,
    )
    if artifacts:
        _recon_artifact(ctx, execution_id="lmp_monitor", message="LMP monitor session artifact recorded", details={"count": len(artifacts)})
    if result.get("success"):
        _recon_result(ctx, execution_id="lmp_monitor", message=f"LMP monitor completed with {result.get('packets', 0)} packet(s)")
    else:
        _recon_error(ctx, execution_id="lmp_monitor", message=f"LMP monitor failed: {result.get('error', 'unknown error')}")
    _recon_persist("lmp_monitor", envelope, ctx, target=address or "")


@recon.command("nrf-sniff")
@click.option("-t", "--target", default=None, help="BLE address to follow")
@click.option("-o", "--output", default="ble_pairing.pcap", help="Output pcap file")
@click.option("-d", "--duration", default=120, help="Capture duration (seconds)")
def recon_nrf_sniff(target, output, duration):
    """Sniff BLE pairing exchanges using nRF52840 dongle."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sniffer import NRFBLESniffer

    target_str = f" following {target}" if target else ""
    info(f"Starting BLE pairing sniff via nRF52840{target_str} ({duration}s)...")
    started_at = now_iso()
    ctx = _recon_cli_context("nrf_pairing_sniff", target=target or "", adapter="nrf52840", details={"duration": duration, "output": output})
    _recon_start(ctx, execution_id="nrf_pairing_sniff", message="nRF BLE pairing sniff started")
    sniffer = NRFBLESniffer()
    result = sniffer.sniff_pairing(output, duration, target=target)

    artifacts = []
    if result.get("success"):
        from blue_tap.framework.contracts.result_schema import make_artifact
        artifacts.append(make_artifact(kind="pcap", label="BLE pairing capture", path=output))

    envelope = build_recon_result(
        target=target or "",
        adapter="nrf52840",
        run_id=ctx["run_id"],
        operation="nrf_pairing_sniff",
        title="nRF BLE Pairing Sniff",
        protocol="BLE",
        entries=[],
        operator_context={"duration": duration},
        module_outcome="artifact_collected" if result.get("success") else "collector_unavailable",
        execution_status="completed" if result.get("success") else "failed",
        module_data_extra=_recon_module_data({"capture_result": result, "output": output}, ctx),
        artifacts=artifacts,
        started_at=started_at,
    )
    if result.get("success"):
        _recon_artifact(ctx, execution_id="nrf_pairing_sniff", message=f"BLE pairing pcap saved to {output}", details={"path": output})
        _recon_result(ctx, execution_id="nrf_pairing_sniff", message=f"nRF pairing sniff completed with success={result.get('success', False)}")
    else:
        _recon_error(ctx, execution_id="nrf_pairing_sniff", message=f"nRF pairing sniff failed: {result.get('error', 'unknown error')}")
    _recon_persist("nrf_sniff", envelope, ctx, target=target or "")


@recon.command("combined-sniff")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=60, type=int, help="Capture duration in seconds")
@click.option("-o", "--output", default="combined_capture.json", help="Output file path")
@click.option("--hci", default="hci1", help="HCI device for DarkFirmware adapter (e.g. hci1 or 1)")
def recon_combined_sniff(address, duration, output, hci):
    """Simultaneous BLE + LMP monitoring.

    Runs nRF52840 BLE sniffer and DarkFirmware LMP monitor concurrently
    with a unified timeline. Covers the full attack surface from
    advertisements through link-layer negotiation.
    """
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sniffer import (
        CombinedSniffer, NRFBLESniffer, DarkFirmwareSniffer,
    )

    started_at = now_iso()
    hci_dev = int(hci.replace("hci", "")) if isinstance(hci, str) and hci.startswith("hci") else int(hci)
    nrf_ok = NRFBLESniffer.is_available()
    df_ok = DarkFirmwareSniffer(hci_dev=hci_dev).is_available()
    ctx = _recon_cli_context("combined_sniff", target=address or "", adapter=hci, details={"duration": duration, "output": output})
    _recon_start(ctx, execution_id="combined_sniff", message="Combined BLE and LMP capture started")

    if not nrf_ok and not df_ok:
        error("Neither nRF52840 nor DarkFirmware adapter available")
        _recon_skip(ctx, execution_id="combined_sniff", message="Combined capture skipped because no collectors are available")
        envelope = build_recon_result(
            target=address or "",
            adapter=hci,
            run_id=ctx["run_id"],
            operation="combined_sniff",
            title="Combined BLE and LMP Capture",
            protocol="Dual-Mode",
            entries=[],
            module_outcome="prerequisite_missing",
            execution_status="skipped",
            module_data_extra=_recon_module_data({"capture_result": {"success": False, "error": "no collectors available"}, "output": output}, ctx),
            started_at=started_at,
        )
        _recon_persist("combined_sniff", envelope, ctx, target=address or "")
        return

    if not nrf_ok:
        warning("nRF52840 not available, LMP-only capture")
    if not df_ok:
        warning("DarkFirmware not available, BLE-only capture")

    info(f"Starting combined BLE+LMP capture (duration={duration}s)")
    combined = CombinedSniffer(
        nrf_available=nrf_ok,
        darkfirmware_available=df_ok,
        hci_dev=hci_dev,
    )
    result = combined.monitor(target=address, duration=duration)
    if result.get("success"):
        try:
            combined.export(output)
        except Exception as exc:
            result = dict(result)
            result["success"] = False
            result["error"] = f"export failed: {exc}"

    artifacts = []
    if result.get("success"):
        from blue_tap.framework.contracts.result_schema import make_artifact
        artifacts.append(make_artifact(kind="json", label="Combined BLE and LMP capture", path=output))
    envelope = build_recon_result(
        target=address or "",
        adapter=hci,
        run_id=ctx["run_id"],
        operation="combined_sniff",
        title="Combined BLE and LMP Capture",
        protocol="Dual-Mode",
        entries=[],
        operator_context={"duration": duration, "output": output},
        module_outcome="artifact_collected" if result.get("success") else "collector_unavailable",
        execution_status="completed" if result.get("success") else "failed",
        module_data_extra=_recon_module_data({"capture_result": result, "output": output}, ctx),
        artifacts=artifacts,
        started_at=started_at,
    )
    if result.get("success"):
        _recon_artifact(ctx, execution_id="combined_sniff", message=f"Combined capture saved to {output}", details={"path": output})
        _recon_result(ctx, execution_id="combined_sniff", message=f"Combined capture completed with success={result.get('success', False)}")
    else:
        _recon_error(ctx, execution_id="combined_sniff", message=f"Combined capture failed: {result.get('error', 'unknown error')}")
    _recon_persist("combined_sniff", envelope, ctx, target=address or "")

    if result.get("success"):
        success(f"Combined capture: {result['lmp_count']} LMP + {result['ble_count']} BLE events")
        success(f"Output: {output}")
    else:
        error("Combined capture failed")


@recon.command("crack-key")
@click.argument("pcap_file")
@click.option("-o", "--output", default=None, help="Output decrypted pcap")
def recon_crack_key(pcap_file, output):
    """Crack BLE pairing key from captured pcap using Crackle."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import make_artifact, now_iso
    from blue_tap.modules.reconnaissance.sniffer import CrackleRunner

    info(f"Cracking BLE pairing key from [bold]{pcap_file}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("crack_ble_key", target="", adapter="offline", details={"input_file": pcap_file, "output_file": output or ""})
    _recon_start(ctx, execution_id="crack_ble_key", message=f"BLE key cracking started for {pcap_file}")
    runner = CrackleRunner()
    result = runner.crack_ble(pcap_file, output)
    artifacts = [
        make_artifact(
            kind="pcap",
            label="Input capture",
            path=pcap_file,
            description="Captured BLE pairing trace analyzed with Crackle",
        )
    ]
    if output and result.get("success"):
        artifacts.append(
            make_artifact(
                kind="pcap",
                label="Decrypted BLE capture",
                path=output,
                description="Crackle decrypted output pcap",
            )
        )
        _recon_artifact(ctx, execution_id="crack_ble_key", message=f"Decrypted BLE capture saved to {output}", details={"path": output})
    envelope = build_recon_result(
        target="",
        adapter="offline",
        run_id=ctx["run_id"],
        operation="crack_ble_key",
        title="BLE Pairing Key Recovery",
        protocol="BLE",
        entries=[],
        module_outcome="observed" if result.get("success") else "failed",
        execution_status="completed" if result.get("success") else "failed",
        module_data_extra=_recon_module_data({
            "analysis_result": result,
            "input_file": pcap_file,
            "output_file": output or "",
            "key_material": {
                "tk": result.get("tk"),
                "ltk": result.get("ltk"),
            },
        }, ctx),
        evidence_summary=(
            "Recovered BLE key material from captured pairing exchange"
            if result.get("success")
            else "BLE key recovery did not yield reusable key material"
        ),
        observations=[
            f"input_file={pcap_file}",
            f"output_file={output or ''}",
            f"success={result.get('success', False)}",
            f"tk_present={bool(result.get('tk'))}",
            f"ltk_present={bool(result.get('ltk'))}",
        ],
        artifacts=artifacts,
        started_at=started_at,
    )
    if result.get("success"):
        _recon_result(ctx, execution_id="crack_ble_key", message=f"BLE key cracking completed with success={result.get('success', False)}")
    else:
        _recon_error(ctx, execution_id="crack_ble_key", message="BLE key cracking failed")
    _recon_persist("crack_key", envelope, ctx)
    if result.get("success"):
        if result.get("ltk"):
            success(f"LTK recovered: {result['ltk']}")
        if result.get("tk"):
            info(f"TK recovered: {result['tk']}")
    else:
        warning("Key crack failed — pcap may not contain a complete pairing exchange")


@recon.command("extract-link-key")
@click.argument("pcap_file")
def recon_extract_link_key(pcap_file):
    """Extract BR/EDR link key from captured pairing pcap (via tshark)."""
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import make_artifact, now_iso
    from blue_tap.modules.reconnaissance.sniffer import LinkKeyExtractor

    info(f"Extracting link keys from [bold]{pcap_file}[/bold]...")
    started_at = now_iso()
    ctx = _recon_cli_context("extract_link_key", target="", adapter="offline", details={"input_file": pcap_file})
    _recon_start(ctx, execution_id="extract_link_key", message=f"BR/EDR link-key extraction started for {pcap_file}")
    extractor = LinkKeyExtractor()
    result = extractor.extract_from_pcap(pcap_file)
    envelope = build_recon_result(
        target="",
        adapter="offline",
        run_id=ctx["run_id"],
        operation="extract_link_key",
        title="BR/EDR Link Key Extraction",
        protocol="BR/EDR",
        entries=[],
        module_outcome="observed" if result.get("success") else "failed",
        execution_status="completed" if result.get("success") else "failed",
        module_data_extra=_recon_module_data({
            "analysis_result": result,
            "input_file": pcap_file,
            "key_material": {"link_keys": result.get("keys", [])},
        }, ctx),
        evidence_summary=(
            f"Extracted {len(result.get('keys', []))} potential BR/EDR link key(s)"
            if result.get("success")
            else "No reusable BR/EDR link key was extracted from the capture"
        ),
        observations=[
            f"input_file={pcap_file}",
            f"success={result.get('success', False)}",
            f"key_count={len(result.get('keys', []))}",
        ],
        artifacts=[
            make_artifact(
                kind="pcap",
                label="Input capture",
                path=pcap_file,
                description="Captured BR/EDR pairing trace analyzed for link keys",
            )
        ],
        started_at=started_at,
    )
    _recon_artifact(ctx, execution_id="extract_link_key", message=f"BR/EDR link-key analysis recorded for {pcap_file}", details={"path": pcap_file})
    if result.get("success"):
        _recon_result(ctx, execution_id="extract_link_key", message=f"BR/EDR link-key extraction completed with success={result.get('success', False)}")
    else:
        _recon_error(ctx, execution_id="extract_link_key", message="BR/EDR link-key extraction failed")
    _recon_persist("extract_link_key", envelope, ctx)
    if result.get("success"):
        for key in result.get("keys", []):
            success(f"Link key: {key}")


@recon.command("inject-link-key")
@click.argument("remote_mac")
@click.argument("link_key")
@click.option("-i", "--hci", default="hci0")
@click.option("--key-type", default=4, help="BlueZ key type (4=auth, 5=unauth)")
def recon_inject_link_key(remote_mac, link_key, hci, key_type):
    """Inject a recovered link key into BlueZ for impersonation.

    \b
    After recovering a link key (via nRF/DarkFirmware capture + crack, or other means),
    inject it so bluetoothctl can connect using the stolen key.
    """
    from blue_tap.framework.envelopes.recon import build_recon_result
    from blue_tap.framework.contracts.result_schema import now_iso
    from blue_tap.modules.reconnaissance.sniffer import LinkKeyExtractor

    info(f"Injecting link key for [bold]{remote_mac}[/bold] into BlueZ ({hci})...")
    started_at = now_iso()
    ctx = _recon_cli_context("inject_link_key", target=remote_mac, adapter=hci, details={"key_type": key_type})
    _recon_start(ctx, execution_id="inject_link_key", message=f"Link-key injection started for {remote_mac}")
    extractor = LinkKeyExtractor()
    adapter_mac = extractor.get_adapter_mac(hci)
    ok = False
    error_text = ""
    action_result = {}
    if not adapter_mac:
        error(f"Cannot determine adapter MAC for {hci}")
        error_text = f"Cannot determine adapter MAC for {hci}"
    else:
        action_result = extractor.inject_link_key(adapter_mac, remote_mac, link_key, key_type)
        ok = bool(action_result.get("success"))
        if ok:
            success(f"Link key injected — try: bluetoothctl connect {remote_mac}")
        else:
            error_text = action_result.get("error", "Link key injection failed")
    envelope = build_recon_result(
        target=remote_mac,
        adapter=hci,
        run_id=ctx["run_id"],
        operation="inject_link_key",
        title="BlueZ Link Key Injection",
        protocol="BR/EDR",
        entries=[],
        module_outcome="observed" if ok else "failed",
        execution_status="completed" if ok else "failed",
        module_data_extra=_recon_module_data({
            "action_result": {
                **action_result,
                "success": ok,
                "adapter_mac": action_result.get("adapter_mac", adapter_mac or ""),
                "remote_mac": action_result.get("remote_mac", remote_mac),
                "key_type": key_type,
                **({"error": error_text} if error_text else {}),
            }
        }, ctx),
        evidence_summary=(
            f"Injected recovered link key for {remote_mac} into BlueZ"
            if ok
            else f"Link key injection for {remote_mac} failed"
        ),
        observations=[
            f"remote_mac={remote_mac}",
            f"adapter={hci}",
            f"adapter_mac={adapter_mac or ''}",
            f"key_type={key_type}",
            f"success={ok}",
        ],
        started_at=started_at,
    )
    if ok:
        _recon_result(ctx, execution_id="inject_link_key", message=f"Link-key injection completed with success={ok}")
    else:
        _recon_error(ctx, execution_id="inject_link_key", message=f"Link-key injection failed: {error_text or 'unknown error'}")
    _recon_persist("inject_link_key", envelope, ctx, target=remote_mac)


__all__ = ["recon"]
