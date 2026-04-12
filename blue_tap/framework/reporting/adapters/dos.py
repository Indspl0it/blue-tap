"""DoS report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions, envelope_module_data
from blue_tap.utils.output import warning


def _extract_cves(execution: dict[str, Any]) -> str:
    """Extract CVE tags from an execution record's tags list."""
    tags = execution.get("tags", [])
    if not isinstance(tags, list):
        return ""
    cves = [t[len("cve:"):] if t.lower().startswith("cve:") else t
            for t in tags if isinstance(t, str) and "cve" in t.lower()]
    return ", ".join(cves)


class DosReportAdapter(ReportAdapter):
    module = "dos"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.dos.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("dos_runs", []).append(envelope)
        module_data = envelope_module_data(envelope)
        checks = module_data.get("checks")
        if checks is None:
            warning(
                f"DoS envelope missing 'checks' key in module_data "
                f"(run_id={envelope.get('run_id', '?')}); dos_results will be empty for this run"
            )
            checks = []
        report_state.setdefault("dos_results", []).extend(checks)
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

        # Run metadata (selected_checks, recovery_timeout, interrupted_on, abort_reason)
        meta_pairs: list[dict[str, str]] = []
        if latest.get("selected_checks"):
            meta_pairs.append({
                "key": "Selected Checks",
                "value": ", ".join(str(x) for x in latest.get("selected_checks", [])),
            })
        if latest.get("recovery_timeout") is not None:
            meta_pairs.append({"key": "Recovery Timeout", "value": f"{latest.get('recovery_timeout')}s"})
        if latest.get("interrupted_on"):
            meta_pairs.append({"key": "Interrupted On", "value": str(latest.get("interrupted_on"))})
        if latest_module_data.get("abort_reason"):
            meta_pairs.append({"key": "Abort Reason", "value": str(latest_module_data.get("abort_reason"))})
        if meta_pairs:
            blocks.append(SectionBlock("key_value", {"pairs": meta_pairs}))

        # Per-check execution table (standardized ExecutionRecord path)
        executions = latest.get("executions", [])
        if executions:
            table_rows: list[list[str]] = []
            for execution in executions:
                mod_data = execution.get("module_data", {})
                recovery = mod_data.get("recovery", {})
                recovery_parts = []
                if recovery.get("recovered") is not None:
                    recovery_parts.append(f"recovered={recovery.get('recovered')}")
                waited = recovery.get("waited_seconds", 0)
                if waited:
                    recovery_parts.append(f"waited={waited}s")
                probe_strategy = recovery.get("probe_strategy", [])
                if probe_strategy:
                    recovery_parts.append(f"via {','.join(str(x) for x in probe_strategy)}")
                recovery_text = " ".join(recovery_parts)

                table_rows.append([
                    execution.get("id", ""),
                    execution.get("title", execution.get("id", "")),
                    _extract_cves(execution),
                    execution.get("protocol", ""),
                    "yes" if execution.get("requires_pairing") else "no",
                    execution.get("execution_status", ""),
                    execution.get("module_outcome", ""),
                    recovery_text,
                    execution.get("evidence", {}).get("summary", ""),
                ])
            blocks.append(SectionBlock("table", {
                "headers": [
                    "Check ID", "Title", "CVE", "Protocol", "Pairing",
                    "Status", "Outcome", "Recovery", "Evidence",
                ],
                "rows": table_rows,
            }))

        # DoS check cards with recovery details (compact summary view)
        cards = []
        for execution in executions:
            evidence = execution.get("evidence", {})
            mod_data = execution.get("module_data", {})
            recovery = mod_data.get("recovery", {})
            details = {
                "Protocol": execution.get("protocol", ""),
                "Outcome": execution.get("module_outcome", ""),
                "Status": execution.get("execution_status", ""),
            }
            cves = _extract_cves(execution)
            if cves:
                details["CVE"] = cves
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
