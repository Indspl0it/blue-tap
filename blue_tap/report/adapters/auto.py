"""Auto mode report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


_PHASE_ORDER = [
    "auto_discovery",
    "auto_fingerprint",
    "auto_recon",
    "auto_vuln_assessment",
    "auto_pairing_attacks",
    "auto_exploitation",
    "auto_fuzzing",
    "auto_dos_testing",
    "auto_report",
]

_STATUS_STYLE = {
    "completed": "success",
    "skipped": "info",
    "failed": "critical",
    "error": "critical",
    "timeout": "warning",
}


class AutoReportAdapter(ReportAdapter):
    module = "auto"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return (
            envelope.get("module") == self.module
            or envelope.get("schema") == "blue_tap.auto.result"
        )

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("auto_runs", []).append(envelope)
        report_state.setdefault("auto_executions", []).extend(envelope_executions(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("auto_runs", [])
        if not runs:
            return []

        blocks: list[SectionBlock] = []

        # Phase summary table — one row per phase execution
        executions = report_state.get("auto_executions", [])
        # Sort by canonical phase order; unknown phases fall to the end
        def _phase_sort_key(ex: dict) -> int:
            return _PHASE_ORDER.index(ex.get("id", "")) if ex.get("id", "") in _PHASE_ORDER else 999

        sorted_execs = sorted(executions, key=_phase_sort_key)

        rows = []
        for ex in sorted_execs:
            status = ex.get("execution_status", "")
            outcome = ex.get("module_outcome", "")
            obs = ex.get("evidence", {}).get("observations", [])
            elapsed = next((o for o in obs if "Elapsed" in o), "")
            rows.append([
                ex.get("title", ex.get("id", "")),
                status,
                outcome,
                elapsed,
            ])

        if rows:
            blocks.append(SectionBlock("table", {
                "headers": ["Phase", "Status", "Outcome", "Elapsed"],
                "rows": rows,
            }))

        # Summary card per run
        cards = []
        for run in runs:
            summary = run.get("summary", {})
            cards.append({
                "title": f"Auto Pentest: {run.get('target', '')}",
                "status": "success" if summary.get("phases_passed", 0) > 0 else "info",
                "details": {
                    "Phases Passed": str(summary.get("phases_passed", 0)),
                    "Phases Failed": str(summary.get("phases_failed", 0)),
                    "Phases Skipped": str(summary.get("phases_skipped", 0)),
                    "Total Phases": str(summary.get("total_phases", 0)),
                },
                "body": f"Completed in {summary.get('total_time_seconds', 0):.1f}s",
            })
        if cards:
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        total_passed = sum(r.get("summary", {}).get("phases_passed", 0) for r in runs)
        total_failed = sum(r.get("summary", {}).get("phases_failed", 0) for r in runs)
        return [SectionModel(
            section_id="sec-auto-pentest",
            title="Automated Pentest Workflow",
            summary=f"{len(runs)} run(s), {total_passed} phases passed, {total_failed} phases failed.",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("auto_runs", []),
            "executions": report_state.get("auto_executions", []),
        }
