"""DoS report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


class DosReportAdapter(ReportAdapter):
    module = "dos"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.dos.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("dos_runs", []).append(envelope)
        module_data = envelope_module_data(envelope)
        report_state.setdefault("dos_results", []).extend(module_data.get("checks", []))
        report_state.setdefault("dos_executions", []).extend(envelope_executions(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("dos_runs", [])
        results = report_state.get("dos_results", [])
        if not runs and not results:
            return []
        latest = runs[-1] if runs else {}
        summary = latest.get("summary", {})
        latest_module_data = envelope_module_data(latest) if latest else {}

        blocks: list[SectionBlock] = []

        # Status summary bar
        status_items = []
        for label in ("success", "recovered", "unresponsive", "failed"):
            count = summary.get(label, 0)
            if count or label in ("success", "unresponsive"):
                status_items.append({"label": label.title(), "count": count, "status": label})
        blocks.append(SectionBlock("status_summary", {"items": status_items}))

        if latest_module_data.get("abort_reason"):
            blocks.append(SectionBlock("paragraph", {"text": f"Abort reason: {latest_module_data.get('abort_reason')}"}))

        # DoS check cards with recovery details
        executions = latest.get("executions", [])
        cards = []
        for execution in executions:
            evidence = execution.get("evidence", {})
            module_data = execution.get("module_data", {})
            recovery = module_data.get("recovery", {})
            details = {
                "Protocol": execution.get("protocol", ""),
                "Outcome": execution.get("module_outcome", ""),
                "Status": execution.get("execution_status", ""),
            }
            waited = recovery.get("waited_seconds", 0)
            if waited:
                details["Recovery Wait"] = f"{waited}s"
            cards.append({
                "title": execution.get("title", execution.get("id", "")),
                "status": execution.get("module_outcome", ""),
                "details": details,
                "body": evidence.get("summary", ""),
            })
        if cards:
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        total = len(executions)
        unresponsive = summary.get("unresponsive", 0)
        return [SectionModel(
            section_id="sec-dos",
            title="Denial of Service Tests",
            summary=f"{total} test(s) executed, {unresponsive} left target unresponsive.",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("dos_runs", []),
            "results": report_state.get("dos_results", []),
            "executions": report_state.get("dos_executions", []),
        }
