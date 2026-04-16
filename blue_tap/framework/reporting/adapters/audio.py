"""Audio operation report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions, envelope_module_data


class AudioReportAdapter(ReportAdapter):
    module = "audio"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        """Accept legacy audio envelopes plus A2DP/AVRCP/HFP modules."""
        module = str(envelope.get("module", ""))
        schema = str(envelope.get("schema", ""))
        if module == self.module:
            return True
        if module in (
            "post_exploitation.a2dp",
            "post_exploitation.avrcp",
            "post_exploitation.hfp",
        ) or module.startswith("post_exploitation.media."):
            return True
        return schema == "blue_tap.audio.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("audio_runs", []).append(envelope)
        report_state.setdefault("audio_executions", []).extend(envelope_executions(envelope))
        report_state.setdefault("audio_operations", []).append(envelope_module_data(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("audio_runs", [])
        if not runs:
            return []

        blocks: list[SectionBlock] = []
        executions = report_state.get("audio_executions", [])

        # Cards for each audio operation
        cards = []
        for execution in executions:
            evidence = execution.get("evidence", {}) or {}
            artifacts = execution.get("artifacts", []) or []
            details = {
                "Protocol": execution.get("protocol", ""),
                "Outcome": execution.get("module_outcome", ""),
            }
            if artifacts:
                details["Artifacts"] = str(len(artifacts))
                for a in artifacts[:3]:
                    details[a.get("kind", "file")] = a.get("label", a.get("path", ""))
            cards.append({
                "title": execution.get("title", execution.get("id", "")),
                "status": execution.get("module_outcome", ""),
                "details": details,
                "body": evidence.get("summary", ""),
            })
        if cards:
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        return [SectionModel(
            section_id="sec-audio-ops",
            title="Audio Operations",
            summary=f"{len(runs)} audio run(s) with {len(executions)} operation(s).",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("audio_runs", []),
            "results": report_state.get("audio_operations", []),
            "executions": report_state.get("audio_executions", []),
        }
