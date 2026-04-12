"""Post-processing helpers for recon capture collectors."""

from __future__ import annotations

from typing import Any

from blue_tap.modules.reconnaissance.correlation import analyze_capture_artifact, summarize_capture_analyses


def analyze_capture_results(module_data: dict[str, Any]) -> dict[str, Any]:
    findings: list[str] = []
    details: dict[str, Any] = {}
    artifact_analyses: list[dict[str, Any]] = []

    hci_capture = _capture_entry(module_data.get("hci_capture"))
    if hci_capture.get("completed"):
        findings.append("hci_capture_collected")
        if hci_capture.get("size_bytes", 0) > 0:
            findings.append("hci_capture_nonempty")
        artifact = _capture_artifact(module_data.get("hci_capture"))
        if artifact:
            artifact_analysis = analyze_capture_artifact(artifact)
            artifact_analyses.append(artifact_analysis)
            findings.extend(artifact_analysis.get("findings", []))
            hci_capture["artifact_analysis"] = artifact_analysis
        details["hci_capture"] = hci_capture

    nrf_capture = _capture_entry(module_data.get("nrf_capture"))
    if nrf_capture.get("completed"):
        findings.append("ble_capture_collected")
        result = (module_data.get("nrf_capture") or {}).get("result", {})
        if isinstance(result, dict) and result.get("success"):
            findings.append("ble_pairing_capture_success")
        artifact = _capture_artifact(module_data.get("nrf_capture"))
        if artifact:
            artifact_analysis = analyze_capture_artifact(artifact)
            artifact_analyses.append(artifact_analysis)
            findings.extend(artifact_analysis.get("findings", []))
            nrf_capture["artifact_analysis"] = artifact_analysis
        details["nrf_capture"] = nrf_capture

    lmp_capture = _capture_entry(module_data.get("lmp_capture"))
    if lmp_capture.get("completed"):
        findings.append("lmp_capture_collected")
        result = (module_data.get("lmp_capture") or {}).get("result", {})
        if isinstance(result, dict) and result.get("packets", 0) > 0:
            findings.append("lmp_packets_observed")
        artifact = _capture_artifact(module_data.get("lmp_capture"))
        if artifact:
            artifact_analysis = analyze_capture_artifact(artifact)
            artifact_analyses.append(artifact_analysis)
            findings.extend(artifact_analysis.get("findings", []))
            if artifact_analysis.get("packet_count", 0) > 0:
                findings.append("lmp_packets_observed")
            lmp_capture["artifact_analysis"] = artifact_analysis
        details["lmp_capture"] = lmp_capture

    combined_capture = _capture_entry(module_data.get("combined_capture"))
    if combined_capture.get("completed"):
        findings.append("combined_capture_collected")
        result = (module_data.get("combined_capture") or {}).get("result", {})
        if isinstance(result, dict):
            if result.get("lmp_count", 0) > 0:
                findings.append("combined_lmp_events_observed")
            if result.get("ble_count", 0) > 0:
                findings.append("combined_ble_events_observed")
        artifact = _capture_artifact(module_data.get("combined_capture"))
        if artifact:
            artifact_analysis = analyze_capture_artifact(artifact)
            artifact_analyses.append(artifact_analysis)
            findings.extend(artifact_analysis.get("findings", []))
            source_counts = artifact_analysis.get("source_counts", {}) or {}
            if source_counts.get("ble", 0) > 0:
                findings.append("combined_ble_events_observed")
            if source_counts.get("lmp", 0) > 0:
                findings.append("combined_lmp_events_observed")
            combined_capture["artifact_analysis"] = artifact_analysis
        details["combined_capture"] = combined_capture

    pairing_mode = module_data.get("pairing_mode", {})
    if isinstance(pairing_mode, dict):
        method = pairing_mode.get("pairing_method", "")
        if method and method != "Unknown":
            findings.append(f"pairing_method={method}")
        if pairing_mode.get("ssp_supported") is True:
            findings.append("ssp_supported")
        elif pairing_mode.get("ssp_supported") is False:
            findings.append("ssp_not_supported")
        details["pairing_mode"] = {
            "ssp_supported": pairing_mode.get("ssp_supported"),
            "io_capability": pairing_mode.get("io_capability", ""),
            "pairing_method": method,
        }

    artifact_summary = summarize_capture_analyses(artifact_analyses)
    findings.extend(artifact_summary.get("findings", []))
    unique_findings = list(dict.fromkeys(findings))
    details["artifact_analyses"] = artifact_analyses
    details["artifact_summary"] = artifact_summary
    return {"findings": unique_findings, "details": details}


def _capture_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"completed": False}
    completed = value.get("status") == "completed"
    return {
        "completed": completed,
        "size_bytes": int(value.get("size_bytes", 0) or 0),
        "output": value.get("output", ""),
    }


def _capture_artifact(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    return str(value.get("output", "") or value.get("path", "") or "")
