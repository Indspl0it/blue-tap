"""Reconnaissance report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions


class ReconReportAdapter(ReportAdapter):
    module = "recon"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.recon.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("recon_runs", []).append(envelope)
        report_state.setdefault("recon_executions", []).extend(envelope_executions(envelope))
        module_data = envelope.get("module_data", {})
        artifacts = envelope.get("artifacts", [])
        if isinstance(artifacts, list) and artifacts:
            report_state.setdefault("recon_artifacts", []).extend(
                artifact for artifact in artifacts if isinstance(artifact, dict)
            )
        entries = module_data.get("entries", [])
        if isinstance(entries, list):
            report_state.setdefault("recon_results", []).extend(entries)
        for nested_key in ("sdp", "rfcomm", "l2cap"):
            nested = module_data.get(nested_key)
            if isinstance(nested, dict):
                nested_entries = nested.get("services" if nested_key == "sdp" else "entries", [])
                if isinstance(nested_entries, list):
                    report_state.setdefault("recon_results", []).extend(
                        item for item in nested_entries if isinstance(item, dict)
                    )
        fingerprint = module_data.get("fingerprint")
        if isinstance(fingerprint, dict):
            report_state.setdefault("fingerprints", []).append(fingerprint)
        capability = module_data.get("capability_detection")
        if isinstance(capability, dict):
            report_state.setdefault("capability_detections", []).append(capability)
        prerequisites = module_data.get("prerequisites")
        if isinstance(prerequisites, dict):
            report_state.setdefault("recon_prerequisites", []).append(prerequisites)
        correlation = module_data.get("correlation")
        if isinstance(correlation, dict):
            report_state.setdefault("recon_correlations", []).append(correlation)
        cli_events = module_data.get("cli_events")
        if isinstance(cli_events, list):
            report_state.setdefault("recon_cli_events", []).extend(
                event for event in cli_events if isinstance(event, dict)
            )
        gatt_result = module_data.get("gatt_result") or module_data.get("gatt")
        if isinstance(gatt_result, dict):
            report_state.setdefault("gatt_results", []).append(gatt_result)
            services = gatt_result.get("services", [])
            if isinstance(services, list):
                report_state.setdefault("gatt_service_trees", []).extend(services)
        capture_summaries = _extract_capture_summaries(module_data)
        if capture_summaries:
            report_state.setdefault("recon_capture_summaries", []).extend(capture_summaries)
        capture_analysis = module_data.get("capture_analysis")
        if isinstance(capture_analysis, dict):
            report_state.setdefault("recon_capture_analyses", []).append(capture_analysis)
        capture_result = module_data.get("capture_result")
        if isinstance(capture_result, dict):
            executions = envelope.get("executions", [])
            first_execution = executions[0] if executions else {}
            report_state.setdefault("capture_results", []).append(
                {
                    "operation": module_data.get("operation", envelope.get("operator_context", {}).get("operation", "")),
                    "protocol": first_execution.get("protocol", ""),
                    "output": module_data.get("output", ""),
                    "result": capture_result,
                }
            )

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        recon_results = report_state.get("recon_results", [])
        runs = report_state.get("recon_runs", [])
        fingerprints = report_state.get("fingerprints", [])
        capability_detections = report_state.get("capability_detections", [])
        gatt_results = report_state.get("gatt_results", [])
        correlations = report_state.get("recon_correlations", [])
        prerequisites = report_state.get("recon_prerequisites", [])
        cli_events = report_state.get("recon_cli_events", [])
        capture_summaries = report_state.get("recon_capture_summaries", [])
        capture_analyses = report_state.get("recon_capture_analyses", [])
        if not recon_results and not runs and not fingerprints and not capability_detections and not gatt_results and not correlations and not cli_events and not capture_summaries and not capture_analyses:
            return []

        sdp_services = []
        gatt_services = []
        channel_scans = []
        other_recon = []

        for entry in recon_results:
            if isinstance(entry, dict):
                if entry.get("uuid") or entry.get("service_name") or entry.get("service_id"):
                    sdp_services.append(entry)
                elif entry.get("handle") or entry.get("characteristic"):
                    gatt_services.append(entry)
                elif entry.get("channel") or entry.get("psm"):
                    channel_scans.append(entry)
                else:
                    other_recon.append(entry)
            else:
                other_recon.append(entry)

        blocks = []
        capability_rows = []
        for capability in capability_detections:
            capability_rows.append(
                [
                    str(capability.get("classification", "")),
                    str(capability.get("classic", {}).get("supported", "")),
                    str(capability.get("ble", {}).get("supported", "")),
                    ", ".join(capability.get("classic", {}).get("signals", [])),
                    ", ".join(capability.get("ble", {}).get("signals", [])),
                ]
            )
        if capability_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Classification", "Classic", "BLE", "Classic Signals", "BLE Signals"],
                        "rows": capability_rows,
                    },
                )
            )
        prereq_rows = []
        for prereq in prerequisites:
            for key, value in prereq.items():
                prereq_rows.append(
                    [
                        str(key),
                        str(value.get("available", "")),
                        str(value.get("reason", "")),
                    ]
                )
        if prereq_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Prerequisite", "Available", "Reason"],
                        "rows": prereq_rows,
                    },
                )
            )
        execution_rows = []
        for run in runs:
            for execution in run.get("executions", []):
                evidence = execution.get("evidence", {}) or {}
                execution_rows.append([
                    str(execution.get("id", "")),
                    str(execution.get("title", "")),
                    str(execution.get("protocol", "")),
                    str(execution.get("module_outcome", "")),
                    str(execution.get("execution_status", "")),
                    str(evidence.get("summary", "")),
                ])
        if execution_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["ID", "Title", "Protocol", "Outcome", "Execution", "Evidence Summary"],
                        "rows": execution_rows,
                    },
                )
            )

        fingerprint_rows = []
        for fingerprint in fingerprints:
            attack_surface = ", ".join(str(item) for item in fingerprint.get("attack_surface", []) or [])
            vuln_hints = ", ".join(str(item) for item in fingerprint.get("vuln_hints", []) or [])
            fingerprint_rows.append(
                [
                    str(fingerprint.get("address", "")),
                    str(fingerprint.get("name", "")),
                    str(fingerprint.get("manufacturer", "")),
                    str(fingerprint.get("bt_version", fingerprint.get("lmp_version", ""))),
                    attack_surface,
                    vuln_hints,
                ]
            )
        if fingerprint_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Address", "Name", "Manufacturer", "Version", "Attack Surface", "Indicators"],
                        "rows": fingerprint_rows,
                    },
                )
            )

        if sdp_services:
            rows = []
            for svc in sdp_services:
                rows.append([
                    str(svc.get("uuid", svc.get("service_id", ""))),
                    str(svc.get("service_name", svc.get("name", ""))),
                    str(svc.get("description", "")),
                    str(svc.get("channel", svc.get("port", ""))),
                ])
            blocks.append(SectionBlock("table", {"headers": ["UUID", "Service Name", "Description", "Channel"], "rows": rows}))

        if gatt_services:
            rows = []
            for svc in gatt_services:
                rows.append([
                    str(svc.get("handle", "")),
                    str(svc.get("uuid", "")),
                    str(svc.get("name", svc.get("characteristic", ""))),
                    str(svc.get("properties", "")),
                ])
            blocks.append(SectionBlock("table", {"headers": ["Handle", "UUID", "Name", "Properties"], "rows": rows}))
        elif gatt_results:
            rows = []
            for result in gatt_results:
                rows.append(
                    [
                        str(result.get("status", "")),
                        str(result.get("service_count", "")),
                        str(result.get("characteristic_count", "")),
                        str((result.get("security_summary") or {}).get("writable_characteristics", "")),
                        str((result.get("security_summary") or {}).get("protected_characteristics", "")),
                    ]
                )
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Status", "Services", "Characteristics", "Writable", "Protected"],
                        "rows": rows,
                    },
                )
            )

        if channel_scans:
            rows = []
            for ch in channel_scans:
                rows.append([
                    str(ch.get("channel", ch.get("psm", ""))),
                    str(ch.get("status", ch.get("state", ""))),
                    str(ch.get("service", ch.get("description", ""))),
                ])
            blocks.append(SectionBlock("table", {"headers": ["Channel/PSM", "Status", "Service"], "rows": rows}))
        correlation_rows = []
        for correlation in correlations:
            for finding in correlation.get("findings", []):
                correlation_rows.append([str(correlation.get("classification", "")), str(finding)])
            for finding in correlation.get("spec_interpretation", {}).get("classic", {}).get("findings", []):
                correlation_rows.append([str(correlation.get("classification", "")), f"classic:{finding}"])
            for finding in correlation.get("spec_interpretation", {}).get("ble", {}).get("findings", []):
                correlation_rows.append([str(correlation.get("classification", "")), f"ble:{finding}"])
            for hidden in correlation.get("rfcomm", {}).get("hidden_channels", []):
                correlation_rows.append(
                    [str(correlation.get("classification", "")), f"hidden_rfcomm_channel={hidden.get('channel')}"]
                )
            for unexpected in correlation.get("l2cap", {}).get("unexpected_psms", []):
                correlation_rows.append(
                    [str(correlation.get("classification", "")), f"unexpected_l2cap_psm={unexpected.get('psm')}"]
                )
        if correlation_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Classification", "Correlation Finding"],
                        "rows": correlation_rows,
                    },
                )
            )

        cli_event_rows = []
        for event in cli_events:
            details = event.get("details", {}) if isinstance(event.get("details", {}), dict) else {}
            cli_event_rows.append(
                [
                    str(event.get("timestamp", "")),
                    str(event.get("event_type", "")),
                    str(event.get("execution_id", "")),
                    str(event.get("message", "")),
                    str(event.get("adapter", "")),
                    _compact_details(details),
                ]
            )
        if cli_event_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Timestamp", "Event", "Execution", "Message", "Adapter", "Details"],
                        "rows": cli_event_rows,
                    },
                )
            )

        capture_summary_rows = []
        for capture in capture_summaries or report_state.get("capture_results", []):
            result = capture.get("result", {}) or {}
            capture_summary_rows.append(
                [
                    str(capture.get("operation", "")),
                    str(capture.get("protocol", "")),
                    str(capture.get("status", result.get("success", ""))),
                    _capture_metric_text(result),
                    str(capture.get("output", result.get("output", result.get("pcap", "")))),
                ]
            )
        if capture_summary_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Operation", "Protocol", "Status", "Metric", "Output"],
                        "rows": capture_summary_rows,
                    },
                )
            )

        capture_analysis_rows = []
        artifact_analysis_rows = []
        for analysis in capture_analyses:
            for finding in analysis.get("findings", []):
                capture_analysis_rows.append(["capture_analysis", str(finding)])
            details = analysis.get("details", {}) or {}
            for artifact in details.get("artifact_analyses", []) or []:
                artifact_analysis_rows.append(
                    [
                        str(artifact.get("kind", "")),
                        str(artifact.get("packet_count", "")),
                        str(artifact.get("summary", "")),
                        ", ".join(str(finding) for finding in artifact.get("findings", [])[:6]),
                    ]
                )
        if capture_analysis_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Source", "Finding"],
                        "rows": capture_analysis_rows,
                    },
                )
            )
        if artifact_analysis_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Artifact Kind", "Packets", "Summary", "Findings"],
                        "rows": artifact_analysis_rows,
                    },
                )
            )

        if other_recon:
            blocks.append(SectionBlock("text", {"text": str(other_recon[:20])}))

        operation_rows = []
        artifact_rows = []
        seen_artifacts: set[tuple[str, str, str]] = set()
        for artifact in report_state.get("recon_artifacts", []):
            if not isinstance(artifact, dict):
                continue
            key = (str(artifact.get("kind", "")), str(artifact.get("label", "")), str(artifact.get("path", "")))
            if key in seen_artifacts:
                continue
            seen_artifacts.add(key)
            artifact_rows.append([
                "campaign",
                str(artifact.get("kind", "")),
                str(artifact.get("label", "")),
                str(artifact.get("path", "")),
            ])

        for run in runs:
            executions = run.get("executions", []) or []
            for execution in executions:
                module_data = execution.get("module_data", {}) or {}
                artifacts = execution.get("artifacts", []) or []
                if not artifacts:
                    artifacts = execution.get("evidence", {}).get("artifacts", []) or []
                highlights = []
                analysis_result = module_data.get("analysis_result", {})
                if isinstance(analysis_result, dict):
                    if analysis_result.get("ltk"):
                        highlights.append("ltk_recovered=yes")
                    if analysis_result.get("tk"):
                        highlights.append("tk_recovered=yes")
                    if analysis_result.get("keys"):
                        highlights.append(f"keys={len(analysis_result.get('keys', []))}")
                    if analysis_result.get("error"):
                        highlights.append(f"error={analysis_result.get('error')}")
                    if analysis_result.get("note"):
                        highlights.append(f"note={analysis_result.get('note')}")
                action_result = module_data.get("action_result", {})
                if isinstance(action_result, dict):
                    if action_result.get("adapter_mac"):
                        highlights.append(f"adapter_mac={action_result.get('adapter_mac')}")
                    if action_result.get("remote_mac"):
                        highlights.append(f"remote_mac={action_result.get('remote_mac')}")
                    if action_result.get("error"):
                        highlights.append(f"error={action_result.get('error')}")
                key_material = module_data.get("key_material", {})
                if isinstance(key_material, dict):
                    if key_material.get("ltk"):
                        highlights.append("key_material=ltk")
                    if key_material.get("tk"):
                        highlights.append("key_material=tk")
                    if key_material.get("link_keys"):
                        highlights.append(f"link_keys={len(key_material.get('link_keys', []))}")

                if highlights or artifacts:
                    operation_rows.append([
                        str(execution.get("title", "")),
                        str(execution.get("protocol", "")),
                        str(execution.get("module_outcome", "")),
                        "; ".join(highlights),
                        ", ".join(str(a.get("label", a.get("path", ""))) for a in artifacts),
                    ])
                for artifact in artifacts:
                    artifact_rows.append([
                        str(execution.get("title", "")),
                        str(artifact.get("kind", "")),
                        str(artifact.get("label", "")),
                        str(artifact.get("path", "")),
                    ])
        if operation_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Operation", "Protocol", "Outcome", "Highlights", "Artifacts"],
                        "rows": operation_rows,
                    },
                )
            )
        if artifact_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Operation", "Artifact Type", "Label", "Path"],
                        "rows": artifact_rows,
                    },
                )
            )

        return [
            SectionModel(
                section_id="sec-recon",
                title="Reconnaissance Results",
                summary=(
                    f"Reconnaissance collected {len(recon_results)} structured record(s), "
                    f"{len(fingerprints)} fingerprint profile(s), across {len(runs)} run(s)."
                ),
                blocks=tuple(blocks),
            )
        ]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("recon_runs", []),
            "entries": report_state.get("recon_results", []),
            "fingerprints": report_state.get("fingerprints", []),
            "capabilities": report_state.get("capability_detections", []),
            "prerequisites": report_state.get("recon_prerequisites", []),
            "correlations": report_state.get("recon_correlations", []),
            "cli_events": report_state.get("recon_cli_events", []),
            "capture_summaries": report_state.get("recon_capture_summaries", []),
            "capture_analysis": report_state.get("recon_capture_analyses", []),
            "artifacts": report_state.get("recon_artifacts", []),
            "gatt_results": report_state.get("gatt_results", []),
            "capture_results": report_state.get("capture_results", []),
            "executions": report_state.get("recon_executions", []),
        }


def _capture_metric_text(result: dict[str, Any]) -> str:
    if not isinstance(result, dict):
        return ""
    if result.get("packets") is not None:
        return f"packets={result.get('packets')}"
    if result.get("lmp_count") is not None or result.get("ble_count") is not None:
        return f"lmp={result.get('lmp_count', 0)} ble={result.get('ble_count', 0)}"
    if result.get("size_bytes") is not None:
        return f"size_bytes={result.get('size_bytes')}"
    if result.get("duration") is not None:
        return f"duration={result.get('duration')}"
    return ""


def _compact_details(details: dict[str, Any]) -> str:
    if not details:
        return ""
    pairs = []
    for key, value in details.items():
        if isinstance(value, (dict, list)):
            continue
        pairs.append(f"{key}={value}")
    return "; ".join(pairs[:4])


def _extract_capture_summaries(module_data: dict[str, Any]) -> list[dict[str, Any]]:
    captures: list[dict[str, Any]] = []
    capture_map = [
        ("hci_capture", "HCI Capture", "HCI"),
        ("nrf_capture", "nRF BLE Capture", "BLE"),
        ("lmp_capture", "Below-HCI Recon", "LMP"),
        ("combined_capture", "Combined BLE and LMP Capture", "BLE/LMP"),
    ]
    for key, label, protocol in capture_map:
        entry = module_data.get(key)
        if not isinstance(entry, dict):
            continue
        result = entry.get("result", {}) if isinstance(entry.get("result"), dict) else {}
        captures.append(
            {
                "operation": key,
                "label": label,
                "protocol": protocol,
                "status": entry.get("status", "unknown"),
                "output": entry.get("output", result.get("output", "")),
                "result": result,
                "details": entry,
            }
        )
    legacy = module_data.get("capture_result")
    if isinstance(legacy, dict):
        captures.append(
            {
                "operation": module_data.get("operation", "capture"),
                "label": "Legacy Capture",
                "protocol": module_data.get("protocol", ""),
                "status": legacy.get("success", "unknown"),
                "output": module_data.get("output", legacy.get("output", legacy.get("pcap", ""))),
                "result": legacy,
                "details": legacy,
            }
        )
    return captures
