"""Data-exfiltration report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


class DataReportAdapter(ReportAdapter):
    module = "data"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.data.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("data_runs", []).append(envelope)
        report_state.setdefault("data_executions", []).extend(envelope_executions(envelope))
        report_state.setdefault("data_operations", []).append(envelope_module_data(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("data_runs", [])
        if not runs:
            return []
        executions = report_state.get("data_executions", [])
        families = {str(execution.get("protocol", "")).lower() for execution in executions if execution.get("protocol")}
        if families == {"pbap"}:
            title = "Data Exfiltration: PBAP"
        elif families == {"map"}:
            title = "Data Exfiltration: MAP"
        else:
            title = "Data Extraction Operations"

        blocks: list[SectionBlock] = []

        # Cards for each extraction operation
        cards = []
        for execution in executions:
            evidence = execution.get("evidence", {}) or {}
            details = {
                "Protocol": execution.get("protocol", ""),
                "Outcome": execution.get("module_outcome", ""),
            }
            artifacts = execution.get("artifacts", []) or []
            if artifacts:
                details["Artifacts"] = ", ".join(str(a.get("label", a.get("path", ""))) for a in artifacts)
            cards.append({
                "title": execution.get("title", execution.get("id", "")),
                "status": execution.get("module_outcome", ""),
                "details": details,
                "body": evidence.get("summary", ""),
            })
        if cards:
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        return [SectionModel(
            section_id="sec-data-ops",
            title=title,
            summary=f"{len(runs)} data-extraction run(s) with {len(executions)} operation(s).",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("data_runs", []),
            "results": report_state.get("data_operations", []),
            "executions": report_state.get("data_executions", []),
        }
