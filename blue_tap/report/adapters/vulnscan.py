"""Vulnerability scan report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


class VulnscanReportAdapter(ReportAdapter):
    module = "vulnscan"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.vulnscan.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("vuln_scan_runs", []).append(envelope)
        module_data = envelope_module_data(envelope)
        report_state.setdefault("vuln_findings", []).extend(module_data.get("findings", []))
        report_state.setdefault("vuln_executions", []).extend(envelope_executions(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        findings = [f for f in report_state.get("vuln_findings", []) if f.get("status") != "not_applicable"]
        runs = report_state.get("vuln_scan_runs", [])
        if not findings and not runs:
            return []
        latest = runs[-1] if runs else {}
        all_findings = report_state.get("vuln_findings", [])
        summary = {
            "confirmed": sum(1 for finding in all_findings if finding.get("status") == "confirmed"),
            "not_detected": sum(1 for finding in all_findings if finding.get("status") == "not_detected"),
            "inconclusive": sum(1 for finding in all_findings if finding.get("status") == "inconclusive"),
            "pairing_required": sum(1 for finding in all_findings if finding.get("status") == "pairing_required"),
            "not_applicable": sum(1 for finding in all_findings if finding.get("status") == "not_applicable"),
        }

        blocks: list[SectionBlock] = []

        # Status summary bar with outcome counts
        status_items = []
        for label in ("confirmed", "not_detected", "inconclusive", "pairing_required", "not_applicable"):
            count = summary.get(label, 0)
            if count or label == "confirmed":
                status_items.append({"label": label.replace("_", " ").title(), "count": count, "status": label})
        blocks.append(SectionBlock("status_summary", {"items": status_items}))

        # Finding cards grouped by severity
        if findings:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))
            cards = []
            for f in sorted_findings:
                cards.append({
                    "title": f.get("name", f.get("cve", "Unknown")),
                    "status": f.get("status", ""),
                    "details": {
                        "CVE": f.get("cve", "N/A"),
                        "Severity": f.get("severity", ""),
                        "Confidence": f.get("confidence", ""),
                    },
                    "body": f.get("evidence", ""),
                })
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        # Execution detail table
        execution_rows = []
        for execution in latest.get("executions", []):
            if execution.get("kind") != "check":
                continue
            evidence = execution.get("evidence", {})
            execution_rows.append([
                execution.get("id", ""),
                execution.get("title", ""),
                execution.get("module_outcome", ""),
                execution.get("execution_status", ""),
                evidence.get("summary", ""),
            ])
        if execution_rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["ID", "Title", "Outcome", "Execution", "Evidence Summary"],
                        "rows": execution_rows,
                    },
                )
            )

        total = len(findings)
        confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
        return [SectionModel(
            section_id="sec-vulnerabilities",
            title="Vulnerability Findings",
            summary=f"{total} finding(s) reported, {confirmed} confirmed.",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("vuln_scan_runs", []),
            "findings": report_state.get("vuln_findings", []),
            "executions": report_state.get("vuln_executions", []),
        }
