"""Recon campaign orchestration."""

from __future__ import annotations

import os
import tempfile
import time
from typing import Any

from blue_tap.core.cli_events import emit_cli_event
from blue_tap.core.recon_framework import build_recon_execution, summarize_recon_entries
from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_FAILED,
    EXECUTION_SKIPPED,
    build_run_envelope,
    make_artifact,
    make_evidence,
    make_execution,
    make_run_id,
    now_iso,
)
from blue_tap.recon.capability_detector import detect_target_capabilities
from blue_tap.recon.capture_analysis import analyze_capture_results
from blue_tap.recon.correlation import build_recon_correlation, correlate_l2cap_with_sdp, correlate_rfcomm_with_sdp
from blue_tap.recon.fingerprint import fingerprint_device
from blue_tap.recon.gatt import enumerate_services_detailed_sync, flatten_gatt_entries
from blue_tap.recon.hci_capture import HCICapture, detect_pairing_mode
from blue_tap.recon.l2cap_scan import L2CAPScanner
from blue_tap.recon.prerequisites import evaluate_recon_prerequisites, prerequisite_skip_reason
from blue_tap.recon.rfcomm_scan import RFCOMMScanner
from blue_tap.recon.sdp import browse_services_detailed
from blue_tap.recon.sniffer import CombinedSniffer, DarkFirmwareSniffer, NRFBLESniffer


def run_auto_recon(
    *,
    address: str,
    hci: str = "hci0",
    below_hci_hci: str = "hci1",
    with_captures: bool = False,
    with_below_hci: bool = False,
    duration: int = 20,
) -> dict[str, Any]:
    """Run a capability-driven recon campaign and return one run envelope."""
    started_at = now_iso()
    run_id = make_run_id("recon")
    cli_events: list[dict[str, Any]] = []
    _emit(
        cli_events,
        event_type="run_started",
        run_id=run_id,
        target=address,
        adapter=hci,
        message=f"Recon run started for {address}",
        details={"with_captures": with_captures, "with_below_hci": with_below_hci, "duration": duration},
    )

    capability = detect_target_capabilities(address, hci=hci)
    _emit(
        cli_events,
        event_type="execution_result",
        run_id=run_id,
        execution_id="recon_capability_detection",
        target=address,
        adapter=hci,
        message=f"Target classified as {capability.get('classification', 'undetermined')}",
    )
    executions = [
        make_execution(
            kind="collector",
            id="recon_capability_detection",
            title="Transport Capability Detection",
            module="recon",
            protocol="Bluetooth",
            execution_status=EXECUTION_COMPLETED,
            module_outcome=capability.get("classification", "undetermined"),
            evidence=make_evidence(
                summary=(
                    f"Target classified as {capability.get('classification', 'undetermined')}"
                ),
                confidence="medium",
                observations=capability.get("observations", []),
                module_evidence={
                    "classic": capability.get("classic", {}),
                    "ble": capability.get("ble", {}),
                },
            ),
            started_at=started_at,
            completed_at=now_iso(),
            tags=["recon", "capability_detection"],
            module_data=capability,
        )
    ]

    module_data: dict[str, Any] = {"capability_detection": capability, "cli_events": cli_events}
    artifacts: list[dict[str, Any]] = []

    classification = capability.get("classification")
    classic_supported = classification in {"classic_only", "dual_mode"}
    ble_supported = classification in {"ble_only", "dual_mode"}
    prerequisites = evaluate_recon_prerequisites(
        target_capability=classification,
        classic_adapter=hci,
        below_hci_adapter=below_hci_hci,
    )
    module_data["prerequisites"] = prerequisites

    if classic_supported:
        _emit(cli_events, event_type="phase_started", run_id=run_id, target=address, adapter=hci, message="Classic recon phase started")
        fingerprint = fingerprint_device(address, hci=hci)
        module_data["fingerprint"] = fingerprint
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="fingerprint", target=address, adapter=hci, message="Fingerprint collection completed")
        executions.append(
            build_recon_execution(
                operation="fingerprint",
                title="Device Fingerprint",
                protocol="Fingerprint",
                entries=[],
                fingerprint=fingerprint,
                started_at=started_at,
                module_data_extra={
                    "profiles": fingerprint.get("profiles", []),
                    "attack_surface": fingerprint.get("attack_surface", []),
                    "vuln_hints": fingerprint.get("vuln_hints", []),
                },
                evidence_summary=f"Fingerprint collected for {address}",
                observations=[
                    f"name={fingerprint.get('name', '')}",
                    f"manufacturer={fingerprint.get('manufacturer', '')}",
                    f"profile_count={len(fingerprint.get('profiles', []))}",
                ],
            )
        )

        sdp_result = browse_services_detailed(address, hci=hci)
        sdp_entries = sdp_result.get("services", [])
        module_data["sdp"] = sdp_result
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="sdp_browse", target=address, adapter=hci, message=f"SDP browse collected {len(sdp_entries)} service(s)")
        executions.append(
            build_recon_execution(
                operation="sdp_browse",
                title="SDP Service Browse",
                protocol="SDP",
                entries=sdp_entries,
                started_at=started_at,
                module_data_extra=sdp_result,
                evidence_summary=f"{len(sdp_entries)} SDP service(s) observed",
                observations=[
                    f"service_count={len(sdp_entries)}",
                    f"rfcomm_channels={len(sdp_result.get('rfcomm_channels', []))}",
                    f"l2cap_psms={len(sdp_result.get('l2cap_psms', []))}",
                ],
            )
        )

        rfcomm_results = RFCOMMScanner(address).scan_all_channels(hci=hci)
        rfcomm_correlation = correlate_rfcomm_with_sdp(sdp_entries, rfcomm_results)
        hidden_channels = rfcomm_correlation.get("hidden_channels", [])
        module_data["rfcomm"] = {
            "entries": rfcomm_results,
            "hidden_channels": hidden_channels,
            "correlation": rfcomm_correlation,
        }
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="rfcomm_scan", target=address, adapter=hci, message=f"RFCOMM scan completed with {len(hidden_channels)} hidden channel(s)")
        executions.append(
            build_recon_execution(
                operation="rfcomm_scan",
                title="RFCOMM Channel Scan",
                protocol="RFCOMM",
                entries=rfcomm_results,
                started_at=started_at,
                module_outcome="hidden_surface_detected" if hidden_channels else "observed",
                module_data_extra={"hidden_channels": hidden_channels, "correlation": rfcomm_correlation},
                evidence_summary=(
                    f"{len(hidden_channels)} hidden RFCOMM channel(s) detected"
                    if hidden_channels
                    else f"{len(rfcomm_results)} RFCOMM channel probe(s) completed"
                ),
                observations=[
                    f"open_channels={sum(1 for item in rfcomm_results if item.get('status') == 'open')}",
                    f"hidden_channels={len(hidden_channels)}",
                ],
            )
        )

        l2cap_scanner = L2CAPScanner(address)
        l2cap_results = l2cap_scanner.scan_standard_psms(hci=hci)
        dynamic_l2cap_results = []
        if _should_probe_dynamic_l2cap(sdp_result, l2cap_results):
            _emit(
                cli_events,
                event_type="execution_started",
                run_id=run_id,
                execution_id="l2cap_dynamic_followup",
                target=address,
                adapter=hci,
                message="Bounded dynamic L2CAP follow-up started",
            )
            dynamic_l2cap_results = l2cap_scanner.scan_dynamic_psms(start=4097, end=4127, timeout=0.75, workers=4)
            _emit(
                cli_events,
                event_type="execution_result",
                run_id=run_id,
                execution_id="l2cap_dynamic_followup",
                target=address,
                adapter=hci,
                message=f"Bounded dynamic L2CAP follow-up completed with {sum(1 for item in dynamic_l2cap_results if item.get('status') in {'open', 'auth_required'})} responsive PSM(s)",
            )
            l2cap_results.extend(dynamic_l2cap_results)
        l2cap_correlation = correlate_l2cap_with_sdp(sdp_entries, l2cap_results)
        module_data["l2cap"] = {
            "entries": l2cap_results,
            "dynamic_entries": dynamic_l2cap_results,
            "correlation": l2cap_correlation,
        }
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="l2cap_scan", target=address, adapter=hci, message=f"L2CAP scan completed with {len(l2cap_correlation.get('unexpected_psms', []))} unexpected PSM(s)")
        executions.append(
            build_recon_execution(
                operation="l2cap_scan",
                title="L2CAP PSM Scan",
                protocol="L2CAP",
                entries=l2cap_results,
                started_at=started_at,
                module_data_extra={
                    "open_psms": [item["psm"] for item in l2cap_results if item.get("status") in {"open", "auth_required"}],
                    "dynamic_psms_scanned": [item["psm"] for item in dynamic_l2cap_results],
                    "correlation": l2cap_correlation,
                },
                evidence_summary=f"{len(l2cap_results)} L2CAP PSM probe(s) completed",
                observations=[
                    f"open_psms={sum(1 for item in l2cap_results if item.get('status') == 'open')}",
                    f"auth_required_psms={sum(1 for item in l2cap_results if item.get('status') == 'auth_required')}",
                    f"unexpected_psms={len(l2cap_correlation.get('unexpected_psms', []))}",
                    f"dynamic_followup_psms={len(dynamic_l2cap_results)}",
                ],
            )
        )
        pairing_probe = detect_pairing_mode(address, hci)
        module_data["pairing_mode"] = pairing_probe
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="pairing_mode_probe", target=address, adapter=hci, message=f"Pairing mode probe completed: {pairing_probe.get('pairing_method', 'Unknown')}")
        executions.append(
            build_recon_execution(
                operation="pairing_mode_probe",
                title="Pairing Mode Detection",
                protocol="Pairing",
                entries=[],
                started_at=started_at,
                module_outcome="observed" if pairing_probe.get("ssp_supported") is not None else "partial_observation",
                module_data_extra={"pairing_probe": pairing_probe},
                evidence_summary="Pairing mode probe completed",
                observations=[
                    f"ssp_supported={pairing_probe.get('ssp_supported')}",
                    f"io_capability={pairing_probe.get('io_capability', '')}",
                    f"pairing_method={pairing_probe.get('pairing_method', '')}",
                ],
            )
        )
    else:
        skipped = _classic_skip_executions(started_at)
        executions.extend(skipped)
        for execution in skipped:
            _emit(
                cli_events,
                event_type="execution_skipped",
                run_id=run_id,
                execution_id=execution.get("id", ""),
                target=address,
                adapter=hci,
                message=execution.get("evidence", {}).get("summary", ""),
            )

    if ble_supported:
        _emit(cli_events, event_type="phase_started", run_id=run_id, target=address, adapter=hci, message="BLE recon phase started")
        try:
            gatt_result = enumerate_services_detailed_sync(address, adapter=hci)
        except TypeError:
            gatt_result = enumerate_services_detailed_sync(address)
        module_data["gatt"] = gatt_result
        _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="gatt_enum", target=address, adapter=hci, message=_gatt_summary(gatt_result))
        executions.append(
            build_recon_execution(
                operation="gatt_enum",
                title="GATT Enumeration",
                protocol="GATT",
                entries=flatten_gatt_entries(gatt_result.get("services", [])),
                started_at=started_at,
                module_outcome=_gatt_outcome(gatt_result),
                execution_status=EXECUTION_COMPLETED,
                module_data_extra={
                    "gatt_result": gatt_result,
                    "service_count": gatt_result.get("service_count", 0),
                    "characteristic_count": gatt_result.get("characteristic_count", 0),
                },
                evidence_summary=_gatt_summary(gatt_result),
                observations=gatt_result.get("observations", []),
                confidence="medium" if gatt_result.get("services") else "low",
            )
        )
    else:
        executions.append(_skip_execution("recon_gatt", "GATT Enumeration", "GATT", started_at, "unsupported_transport", "GATT enumeration skipped because BLE support was not detected"))
        _emit(
            cli_events,
            event_type="execution_skipped",
            run_id=run_id,
            execution_id="recon_gatt",
            target=address,
            adapter=hci,
            message="GATT enumeration skipped because BLE support was not detected",
        )

    if with_captures:
        capture_exec, capture_data, capture_artifacts = _run_hci_capture_step(address, hci, duration, prerequisites, started_at, run_id, cli_events)
        executions.append(capture_exec)
        module_data["hci_capture"] = capture_data
        artifacts.extend(capture_artifacts)
        nrf_exec, nrf_data, nrf_artifacts = _run_nrf_capture_step(address, duration, prerequisites, started_at, run_id, cli_events)
        executions.append(nrf_exec)
        module_data["nrf_capture"] = nrf_data
        artifacts.extend(nrf_artifacts)
    if with_below_hci:
        lmp_exec, lmp_data, lmp_artifacts = _run_lmp_capture_step(address, below_hci_hci, duration, prerequisites, started_at, run_id, cli_events)
        executions.append(lmp_exec)
        module_data["lmp_capture"] = lmp_data
        artifacts.extend(lmp_artifacts)
        combined_exec, combined_data, combined_artifacts = _run_combined_capture_step(address, below_hci_hci, duration, prerequisites, started_at, run_id, cli_events)
        executions.append(combined_exec)
        module_data["combined_capture"] = combined_data
        artifacts.extend(combined_artifacts)

    module_data["capture_summary"] = _build_capture_summary(module_data)
    module_data["capture_analysis"] = analyze_capture_results(module_data)
    module_data["correlation"] = build_recon_correlation(
        capability=capability,
        fingerprint=module_data.get("fingerprint"),
        sdp_result=module_data.get("sdp"),
        rfcomm_results=(module_data.get("rfcomm") or {}).get("entries"),
        l2cap_results=(module_data.get("l2cap") or {}).get("entries"),
        gatt_result=module_data.get("gatt"),
        pairing_mode=module_data.get("pairing_mode"),
        capture_analyses=(module_data.get("capture_analysis", {}).get("details", {}) or {}).get("artifact_analyses", []),
    )
    module_data["correlation"]["capture_findings"] = module_data["capture_analysis"]["findings"]

    summary = {
        **summarize_recon_entries([], "recon_auto"),
        "classification": classification,
        "classic_supported": classic_supported,
        "ble_supported": ble_supported,
        "executed_steps": sum(1 for execution in executions if execution.get("execution_status") != EXECUTION_SKIPPED),
        "skipped_steps": sum(1 for execution in executions if execution.get("execution_status") == EXECUTION_SKIPPED),
        "artifact_count": len(artifacts),
    }
    _emit(cli_events, event_type="run_completed", run_id=run_id, target=address, adapter=hci, message="Recon run completed", details={"artifact_count": len(artifacts)})
    module_data["cli_events"] = cli_events
    return build_run_envelope(
        schema="blue_tap.recon.result",
        module="recon",
        run_id=run_id,
        target=address,
        adapter=hci,
        operator_context={"operation": "recon_auto", "duration": duration},
        summary=summary,
        executions=executions,
        artifacts=artifacts,
        module_data=module_data,
        started_at=started_at,
        completed_at=now_iso(),
    )


def _classic_skip_executions(started_at: str) -> list[dict[str, Any]]:
    message = "Classic recon skipped because BR/EDR support was not detected"
    return [
        _skip_execution("recon_fingerprint", "Device Fingerprint", "Fingerprint", started_at, "unsupported_transport", message),
        _skip_execution("recon_sdp", "SDP Service Browse", "SDP", started_at, "unsupported_transport", message),
        _skip_execution("recon_rfcomm_scan", "RFCOMM Channel Scan", "RFCOMM", started_at, "unsupported_transport", message),
        _skip_execution("recon_l2cap_scan", "L2CAP PSM Scan", "L2CAP", started_at, "unsupported_transport", message),
    ]


def _skip_execution(
    execution_id: str,
    title: str,
    protocol: str,
    started_at: str,
    outcome: str,
    summary: str,
) -> dict[str, Any]:
    return make_execution(
        kind="collector",
        id=execution_id,
        title=title,
        module="recon",
        protocol=protocol,
        execution_status=EXECUTION_SKIPPED,
        module_outcome=outcome,
        evidence=make_evidence(summary=summary, confidence="high", observations=[f"outcome={outcome}"]),
        started_at=started_at,
        completed_at=now_iso(),
        tags=["recon", "skipped"],
        module_data={"reason": outcome},
    )


def _emit(events: list[dict[str, Any]], **kwargs: Any) -> None:
    event = emit_cli_event(module="recon", **kwargs)
    events.append(event)


def _run_hci_capture_step(address: str, hci: str, duration: int, prerequisites: dict[str, Any], started_at: str, run_id: str, cli_events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if not prerequisites["hci_capture"]["available"]:
        execution = _skip_execution("recon_hci_capture", "HCI Capture", "HCI", started_at, "prerequisite_missing", prerequisite_skip_reason(prerequisites, "hci_capture", "HCI capture"))
        _emit(cli_events, event_type="execution_skipped", run_id=run_id, execution_id="recon_hci_capture", target=address, adapter=hci, message=execution["evidence"]["summary"])
        return execution, {"status": "skipped"}, []
    _emit(cli_events, event_type="execution_started", run_id=run_id, execution_id="recon_hci_capture", target=address, adapter=hci, message="HCI capture started")
    output = _tmp_artifact_path("recon_hci_", ".btsnoop")
    capture = HCICapture()
    started = capture.start(output, hci=hci, pcap=True)
    if started:
        time.sleep(max(1, min(duration, 5)))
        stopped_output = capture.stop()
        artifact = make_artifact(kind="capture", label="HCI capture", path=stopped_output or output, description="Bounded btmon capture from recon auto")
        _emit(cli_events, event_type="artifact_saved", run_id=run_id, execution_id="recon_hci_capture", target=address, adapter=hci, message=f"HCI capture saved to {artifact['path']}")
        metadata = _artifact_metadata(artifact["path"])
        execution = build_recon_execution(
            operation="recon_hci_capture",
            title="HCI Capture",
            protocol="HCI",
            entries=[],
            started_at=started_at,
            module_outcome="artifact_collected",
            module_data_extra={"capture_result": {"success": True, "output": artifact["path"], "duration": min(duration, 5), **metadata}},
            evidence_summary="HCI capture completed",
            observations=[f"output={artifact['path']}", "pcap=true", f"size_bytes={metadata.get('size_bytes', 0)}"],
            artifacts=[artifact],
        )
        return execution, {"status": "completed", "output": artifact["path"], **metadata}, [artifact]
    execution = make_execution(
        kind="collector",
        id="recon_hci_capture",
        title="HCI Capture",
        module="recon",
        protocol="HCI",
        execution_status=EXECUTION_FAILED,
        module_outcome="collector_unavailable",
        evidence=make_evidence(summary="HCI capture failed to start", confidence="medium"),
        started_at=started_at,
        completed_at=now_iso(),
        module_data={"capture_result": {"success": False}},
    )
    _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="recon_hci_capture", target=address, adapter=hci, message="HCI capture failed to start", details={"execution_status": EXECUTION_FAILED, "module_outcome": "collector_unavailable"})
    return execution, {"status": "failed"}, []


def _run_nrf_capture_step(address: str, duration: int, prerequisites: dict[str, Any], started_at: str, run_id: str, cli_events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if not prerequisites["nrf_ble_sniffer"]["available"]:
        execution = _skip_execution("recon_nrf_capture", "nRF BLE Capture", "BLE", started_at, "prerequisite_missing", prerequisite_skip_reason(prerequisites, "nrf_ble_sniffer", "nRF BLE capture"))
        _emit(cli_events, event_type="execution_skipped", run_id=run_id, execution_id="recon_nrf_capture", target=address, adapter="nrf52840", message=execution["evidence"]["summary"])
        return execution, {"status": "skipped"}, []
    _emit(cli_events, event_type="execution_started", run_id=run_id, execution_id="recon_nrf_capture", target=address, adapter="nrf52840", message="nRF BLE capture started")
    output = _tmp_artifact_path("recon_ble_", ".pcap")
    result = NRFBLESniffer().sniff_pairing(output, duration=min(duration, 10), target=address)
    if result.get("success"):
        artifact = make_artifact(kind="pcap", label="BLE pairing capture", path=result.get("output", output), description="nRF52840 BLE pairing capture")
        _emit(cli_events, event_type="artifact_saved", run_id=run_id, execution_id="recon_nrf_capture", target=address, adapter="nrf52840", message=f"BLE capture saved to {artifact['path']}")
        metadata = _artifact_metadata(artifact["path"])
        execution = build_recon_execution(
            operation="recon_nrf_capture",
            title="nRF BLE Capture",
            protocol="BLE",
            entries=[],
            started_at=started_at,
            module_outcome="artifact_collected",
            module_data_extra={"capture_result": {**result, **metadata}, "output": artifact["path"]},
            evidence_summary="nRF BLE capture completed",
            observations=[f"output={artifact['path']}", f"duration={min(duration, 10)}", f"size_bytes={metadata.get('size_bytes', 0)}"],
            artifacts=[artifact],
        )
        return execution, {"status": "completed", "result": result, **metadata}, [artifact]
    execution = make_execution(
        kind="collector",
        id="recon_nrf_capture",
        title="nRF BLE Capture",
        module="recon",
        protocol="BLE",
        execution_status=EXECUTION_FAILED,
        module_outcome="no_relevant_traffic" if "error" not in result else "collector_unavailable",
        evidence=make_evidence(summary=f"nRF BLE capture unsuccessful: {result.get('error', 'no traffic captured')}", confidence="medium"),
        started_at=started_at,
        completed_at=now_iso(),
        module_data={"capture_result": result},
    )
    _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="recon_nrf_capture", target=address, adapter="nrf52840", message=execution["evidence"]["summary"], details={"execution_status": EXECUTION_FAILED, "module_outcome": execution.get("module_outcome", "")})
    return execution, {"status": "failed", "result": result}, []


def _run_lmp_capture_step(address: str, below_hci_hci: str, duration: int, prerequisites: dict[str, Any], started_at: str, run_id: str, cli_events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if not prerequisites["darkfirmware_lmp"]["available"]:
        execution = _skip_execution("recon_below_hci", "Below-HCI Recon", "LMP", started_at, "prerequisite_missing", prerequisite_skip_reason(prerequisites, "darkfirmware_lmp", "Below-HCI recon"))
        _emit(cli_events, event_type="execution_skipped", run_id=run_id, execution_id="recon_below_hci", target=address, adapter=below_hci_hci, message=execution["evidence"]["summary"])
        return execution, {"status": "skipped"}, []
    _emit(cli_events, event_type="execution_started", run_id=run_id, execution_id="recon_below_hci", target=address, adapter=below_hci_hci, message="Below-HCI LMP capture started")
    output = _tmp_artifact_path("recon_lmp_", ".json")
    hci_dev = _parse_hci_dev(below_hci_hci)
    result = DarkFirmwareSniffer(hci_dev=hci_dev).start_capture(target=address, output=output, duration=min(duration, 10))
    if result.get("success"):
        artifact = make_artifact(kind="btides", label="LMP capture", path=result.get("output", output), description="DarkFirmware LMP capture")
        _emit(cli_events, event_type="artifact_saved", run_id=run_id, execution_id="recon_below_hci", target=address, adapter=below_hci_hci, message=f"LMP capture saved to {artifact['path']}")
        metadata = _artifact_metadata(artifact["path"])
        execution = build_recon_execution(
            operation="recon_below_hci",
            title="Below-HCI Recon",
            protocol="LMP",
            entries=[],
            started_at=started_at,
            module_outcome="artifact_collected",
            module_data_extra={"capture_result": {**result, **metadata}, "output": artifact["path"]},
            evidence_summary=f"LMP capture completed with {result.get('packets', 0)} packet(s)",
            observations=[f"packets={result.get('packets', 0)}", f"output={artifact['path']}", f"size_bytes={metadata.get('size_bytes', 0)}"],
            artifacts=[artifact],
        )
        return execution, {"status": "completed", "result": result, **metadata}, [artifact]
    execution = make_execution(
        kind="collector",
        id="recon_below_hci",
        title="Below-HCI Recon",
        module="recon",
        protocol="LMP",
        execution_status=EXECUTION_FAILED,
        module_outcome="collector_unavailable",
        evidence=make_evidence(summary=f"LMP capture unsuccessful: {result.get('error', 'no packets captured')}", confidence="medium"),
        started_at=started_at,
        completed_at=now_iso(),
        module_data={"capture_result": result},
    )
    _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="recon_below_hci", target=address, adapter=below_hci_hci, message=execution["evidence"]["summary"], details={"execution_status": EXECUTION_FAILED, "module_outcome": "collector_unavailable"})
    return execution, {"status": "failed", "result": result}, []


def _run_combined_capture_step(address: str, below_hci_hci: str, duration: int, prerequisites: dict[str, Any], started_at: str, run_id: str, cli_events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    if not prerequisites["combined_capture"]["available"]:
        execution = _skip_execution("recon_combined_capture", "Combined BLE and LMP Capture", "BLE/LMP", started_at, "prerequisite_missing", prerequisite_skip_reason(prerequisites, "combined_capture", "Combined capture"))
        _emit(cli_events, event_type="execution_skipped", run_id=run_id, execution_id="recon_combined_capture", target=address, adapter=below_hci_hci, message=execution["evidence"]["summary"])
        return execution, {"status": "skipped"}, []
    _emit(cli_events, event_type="execution_started", run_id=run_id, execution_id="recon_combined_capture", target=address, adapter=below_hci_hci, message="Combined BLE and LMP capture started")
    output = _tmp_artifact_path("recon_combined_", ".json")
    combined = CombinedSniffer(nrf_available=True, darkfirmware_available=True, hci_dev=_parse_hci_dev(below_hci_hci))
    result = combined.monitor(target=address, duration=min(duration, 10))
    exported = combined.export(output)
    if result.get("success") and exported:
        artifact = make_artifact(kind="timeline", label="Combined BLE and LMP capture", path=output, description="Correlated combined capture timeline")
        _emit(cli_events, event_type="artifact_saved", run_id=run_id, execution_id="recon_combined_capture", target=address, adapter=below_hci_hci, message=f"Combined capture saved to {artifact['path']}")
        metadata = _artifact_metadata(output)
        execution = build_recon_execution(
            operation="recon_combined_capture",
            title="Combined BLE and LMP Capture",
            protocol="BLE/LMP",
            entries=[],
            started_at=started_at,
            module_outcome="artifact_collected",
            module_data_extra={"capture_result": {**result, **metadata}, "output": output},
            evidence_summary=f"Combined capture completed with {result.get('lmp_count', 0)} LMP and {result.get('ble_count', 0)} BLE event(s)",
            observations=[f"lmp_count={result.get('lmp_count', 0)}", f"ble_count={result.get('ble_count', 0)}", f"output={output}", f"size_bytes={metadata.get('size_bytes', 0)}"],
            artifacts=[artifact],
        )
        return execution, {"status": "completed", "result": result, **metadata}, [artifact]
    execution = make_execution(
        kind="collector",
        id="recon_combined_capture",
        title="Combined BLE and LMP Capture",
        module="recon",
        protocol="BLE/LMP",
        execution_status=EXECUTION_FAILED,
        module_outcome="collector_unavailable",
        evidence=make_evidence(summary="Combined capture unsuccessful", confidence="medium"),
        started_at=started_at,
        completed_at=now_iso(),
        module_data={"capture_result": result, "exported": exported},
    )
    _emit(cli_events, event_type="execution_result", run_id=run_id, execution_id="recon_combined_capture", target=address, adapter=below_hci_hci, message="Combined capture unsuccessful", details={"execution_status": EXECUTION_FAILED, "module_outcome": "collector_unavailable"})
    return execution, {"status": "failed", "result": result}, []


def _tmp_artifact_path(prefix: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(fd)
    return path


def _parse_hci_dev(hci: str) -> int:
    if hci.startswith("hci"):
        hci = hci[3:]
    return int(hci)


def _artifact_metadata(path: str) -> dict[str, Any]:
    try:
        stat = os.stat(path)
        return {"exists": True, "size_bytes": stat.st_size, "modified_at": stat.st_mtime}
    except OSError:
        return {"exists": False, "size_bytes": 0, "modified_at": 0}


def _build_capture_summary(module_data: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "hci_capture_collected": False,
        "ble_capture_collected": False,
        "lmp_capture_collected": False,
        "combined_capture_collected": False,
        "artifacts_present": 0,
    }
    mapping = {
        "hci_capture": "hci_capture_collected",
        "nrf_capture": "ble_capture_collected",
        "lmp_capture": "lmp_capture_collected",
        "combined_capture": "combined_capture_collected",
    }
    for key, summary_key in mapping.items():
        item = module_data.get(key, {})
        if isinstance(item, dict) and item.get("status") == "completed":
            summary[summary_key] = True
            summary["artifacts_present"] += 1
    return summary


def _should_probe_dynamic_l2cap(sdp_result: dict[str, Any], l2cap_results: list[dict[str, Any]]) -> bool:
    if any(item.get("status") in {"open", "auth_required"} for item in l2cap_results):
        return True
    sdp_psms = (sdp_result or {}).get("l2cap_psms", [])
    return bool(sdp_psms)


def _gatt_outcome(gatt_result: dict[str, Any]) -> str:
    if gatt_result.get("service_count", 0) > 0:
        return "observed"
    status = str(gatt_result.get("status", "unknown"))
    if status in {"auth_required", "access_denied"}:
        return "auth_required"
    if status in {"not_found", "not_connectable", "timeout"}:
        return status
    return "no_results"


def _gatt_summary(gatt_result: dict[str, Any]) -> str:
    service_count = gatt_result.get("service_count", 0)
    characteristic_count = gatt_result.get("characteristic_count", 0)
    status = gatt_result.get("status", "unknown")
    if service_count:
        return f"Enumerated {service_count} GATT service(s) and {characteristic_count} characteristic(s)"
    if gatt_result.get("error"):
        return f"GATT enumeration ended with status={status}: {gatt_result.get('error')}"
    return f"GATT enumeration completed with status={status}"
