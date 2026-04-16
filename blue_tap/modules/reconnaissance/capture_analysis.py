"""Post-processing helpers for recon capture collectors.

Owns ``analyze_capture_results`` (used by recon campaign orchestration)
plus the native internal ``CaptureAnalysisModule``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptPath
from blue_tap.framework.registry import ModuleFamily
from blue_tap.modules.reconnaissance.correlation import analyze_capture_artifact, summarize_capture_analyses

logger = logging.getLogger(__name__)


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


# ── Native Module class ─────────────────────────────────────────────────────

class CaptureAnalysisModule(Module):
    """Capture Analysis (internal).

    Analyze a single pcap/btsnoop/LMP capture file and surface findings.
    This is a thin front-door on ``analyze_capture_artifact`` — the operator
    supplies a file path and gets back the artifact analysis dict that recon
    campaign orchestration normally builds up internally.
    """

    module_id = "reconnaissance.capture_analysis"
    family = ModuleFamily.RECONNAISSANCE
    name = "Capture Analysis"
    description = "Analyze a captured pcap/btsnoop/LMP artifact for findings"
    protocols = ("Classic", "BLE")
    requires = ()
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = False
    internal = True
    references = ()
    options = (
        OptPath("PCAP", required=True, description="Path to the capture artifact to analyze"),
    )

    def run(self, ctx: RunContext) -> dict:
        pcap_path = str(ctx.options.get("PCAP", ""))
        started_at = ctx.started_at

        error_msg: str | None = None
        analysis: dict = {}
        try:
            if not pcap_path:
                error_msg = "PCAP option is empty"
            elif not os.path.exists(pcap_path):
                error_msg = f"file not found: {pcap_path}"
            else:
                analysis = analyze_capture_artifact(pcap_path)
                if not isinstance(analysis, dict):
                    analysis = {"raw": analysis}
        except Exception as exc:
            logger.exception("Capture analysis failed for %s", pcap_path)
            error_msg = str(exc)

        findings = analysis.get("findings", []) or []
        packet_count = int(analysis.get("packet_count", 0) or 0)

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        elif findings or packet_count:
            execution_status = "completed"
            outcome = "observed"
        else:
            execution_status = "completed"
            outcome = "not_applicable"

        summary_text = (
            f"Capture analysis error: {error_msg}"
            if error_msg
            else f"Found {len(findings)} finding(s), {packet_count} packet(s)"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module="capture_analysis",
            target="",
            adapter="",
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="capture_analysis",
                    kind="collector",
                    id="capture_analysis",
                    title="PCAP Analysis",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "pcap": pcap_path,
                            "finding_count": len(findings),
                            "packet_count": packet_count,
                            "error": error_msg,
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "finding_count": len(findings),
                "packet_count": packet_count,
                "pcap": pcap_path,
                "error": error_msg,
            },
            module_data=analysis,
            run_id=ctx.run_id,
        )
