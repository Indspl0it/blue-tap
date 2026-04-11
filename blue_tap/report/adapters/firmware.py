"""Firmware report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


class FirmwareReportAdapter(ReportAdapter):
    module = "firmware"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.firmware.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("firmware_operations", []).append(envelope)
        report_state.setdefault("firmware_executions", []).extend(envelope_executions(envelope))
        # Extract connection inspection data
        for execution in envelope_executions(envelope):
            if execution.get("id") == "connection_inspect":
                report_state.setdefault("connection_inspections", []).append(execution)

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        ops = report_state.get("firmware_operations", [])
        if not ops:
            return []

        blocks: list[SectionBlock] = []

        # Operations table
        rows = []
        for op in ops:
            summary = op.get("summary", {})
            rows.append([
                summary.get("operation", ""),
                op.get("target", ""),
                "Yes" if summary.get("success", summary.get("loaded")) else "No",
            ])
        if rows:
            blocks.append(SectionBlock("table", {
                "headers": ["Operation", "Adapter", "Success"],
                "rows": rows,
            }))

        # Connection inspection cards
        inspections = report_state.get("connection_inspections", [])
        if inspections:
            cards = []
            for insp in inspections:
                evidence = insp.get("evidence", {})
                me = evidence.get("module_evidence", {})
                knob_count = me.get("knob_vulnerable", 0)
                cards.append({
                    "title": f"Connection Inspection ({me.get('active_connections', 0)} active)",
                    "status": "critical" if knob_count > 0 else "info",
                    "details": {
                        "Active": str(me.get("active_connections", 0)),
                        "KNOB Vulnerable": str(knob_count),
                        "Total Slots": str(me.get("total_slots", 0)),
                    },
                    "body": evidence.get("summary", ""),
                })
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        return [SectionModel(
            section_id="sec-firmware-ops",
            title="DarkFirmware Operations",
            summary=f"{len(ops)} firmware operation(s).",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "operations": report_state.get("firmware_operations", []),
            "executions": report_state.get("firmware_executions", []),
            "connection_inspections": report_state.get("connection_inspections", []),
        }
