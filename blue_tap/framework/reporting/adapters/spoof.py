"""Spoof report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions, envelope_module_data


class SpoofReportAdapter(ReportAdapter):
    module = "spoof"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.spoof.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("spoof_operations", []).append(envelope)
        report_state.setdefault("spoof_executions", []).extend(envelope_executions(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        ops = report_state.get("spoof_operations", [])
        if not ops:
            return []

        blocks: list[SectionBlock] = []
        rows = []
        for op in ops:
            summary = op.get("summary", {})
            md = envelope_module_data(op)
            rows.append([
                summary.get("operation", ""),
                md.get("original_mac", ""),
                md.get("target_mac", op.get("target", "")),
                summary.get("method", ""),
                "Yes" if summary.get("success") else "No",
                "Verified" if md.get("verified") else "",
            ])

        if rows:
            blocks.append(SectionBlock("table", {
                "headers": ["Operation", "Original MAC", "Target MAC", "Method", "Success", "Verified"],
                "rows": rows,
            }))

        success_count = sum(1 for op in ops if op.get("summary", {}).get("success"))
        return [SectionModel(
            section_id="sec-spoof-ops",
            title="MAC Spoofing Operations",
            summary=f"{len(ops)} operation(s), {success_count} successful.",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "operations": report_state.get("spoof_operations", []),
            "executions": report_state.get("spoof_executions", []),
        }
