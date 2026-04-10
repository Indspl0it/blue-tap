"""Fuzz report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


class FuzzReportAdapter(ReportAdapter):
    module = "fuzz"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.fuzz.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("fuzz_runs", []).append(envelope)
        report_state.setdefault("fuzz_executions", []).extend(envelope_executions(envelope))
        module_data = envelope_module_data(envelope)
        run_type = module_data.get("run_type", "")
        if run_type == "campaign":
            report_state.setdefault("campaigns", []).append(module_data)
            report_state.setdefault("crashes", []).extend(module_data.get("crashes", []))
            # Extract per-protocol execution data
            for execution in envelope_executions(envelope):
                if execution.get("kind") == "probe" and execution.get("id", "").startswith("fuzz_"):
                    report_state.setdefault("fuzz_protocol_runs", []).append(execution)
                    # Extract state coverage from module_evidence
                    me = execution.get("evidence", {}).get("module_evidence", {})
                    if me.get("state_coverage"):
                        report_state.setdefault("fuzz_state_coverage", []).append({
                            "protocol": execution.get("protocol", ""),
                            **me["state_coverage"],
                        })
                    if me.get("field_weights"):
                        report_state.setdefault("fuzz_field_weights", []).append({
                            "protocol": execution.get("protocol", ""),
                            "weights": me["field_weights"],
                        })
        elif run_type == "single_protocol_run":
            report_state.setdefault("protocol_runs", []).append(module_data)
            result = module_data.get("result")
            if isinstance(result, dict):
                report_state.setdefault("fuzz_results", []).append(
                    {
                        "command": module_data.get("command", ""),
                        "protocol": module_data.get("protocol", ""),
                        **result,
                    }
                )
        else:
            report_state.setdefault("operations", []).append(module_data)

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("fuzz_runs", [])
        if not runs:
            return []

        blocks: list[SectionBlock] = []
        total_sent = 0
        total_crashes = 0
        total_errors = 0
        rows = []
        for run in runs:
            summary = run.get("summary", {})
            sent_count = int(summary.get("packets_sent", summary.get("sent", 0)) or 0)
            crash_count = int(summary.get("crashes", 0) or 0)
            error_count = int(summary.get("errors", 0) or 0)
            total_sent += sent_count
            total_crashes += crash_count
            total_errors += error_count
            command_label = (
                summary.get("command")
                or summary.get("operation")
                or summary.get("run_type", "")
            )
            protocol_label = (
                summary.get("protocol")
                or ", ".join(summary.get("protocols", []) or [])
                or run.get("operator_context", {}).get("protocol", "")
            )
            rows.append(
                [
                    command_label,
                    protocol_label,
                    run.get("target", ""),
                    str(sent_count),
                    str(crash_count),
                    str(error_count),
                    f"{float(summary.get('runtime_seconds', summary.get('elapsed_seconds', 0.0)) or 0.0):.1f}s",
                ]
            )

        # Badge summary for key metrics
        badges = [
            {"label": "Runs", "value": len(runs), "status": "info"},
            {"label": "Cases Sent", "value": total_sent, "status": "info"},
            {"label": "Crashes", "value": total_crashes, "status": "critical" if total_crashes else "info"},
            {"label": "Errors", "value": total_errors, "status": "warning" if total_errors else "info"},
        ]
        blocks.append(SectionBlock("badge_group", {"badges": badges}))

        if rows:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Command", "Protocol", "Target", "Cases Sent", "Crashes", "Errors", "Duration"],
                        "rows": rows,
                    },
                )
            )

        # Per-protocol breakdown
        proto_runs = report_state.get("fuzz_protocol_runs", [])
        if proto_runs:
            proto_rows = []
            for pr in proto_runs:
                md = pr.get("module_data", {})
                proto_rows.append([
                    pr.get("protocol", ""),
                    str(md.get("packets_sent", 0)),
                    str(md.get("crashes", 0)),
                    str(md.get("anomalies", 0)),
                    str(md.get("states_discovered", 0)),
                    pr.get("module_outcome", ""),
                ])
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Protocol", "Packets", "Crashes", "Anomalies", "States", "Outcome"],
                        "rows": proto_rows,
                    },
                )
            )

        # Crash cards if available
        crashes = report_state.get("crashes", [])
        if crashes:
            cards = []
            for crash in crashes[:20]:
                payload_hex = crash.get("payload_hex", "")
                details = {
                    "Protocol": crash.get("protocol", ""),
                    "Severity": crash.get("severity", ""),
                    "Reproduced": "Yes" if crash.get("reproduced") else "No",
                }
                if payload_hex:
                    details["Payload (first 32B)"] = payload_hex[:64]
                cards.append({
                    "title": crash.get("crash_type", "Unknown Crash"),
                    "status": crash.get("severity", "MEDIUM").lower(),
                    "details": details,
                    "body": crash.get("description", crash.get("error", "")),
                })
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        return [
            SectionModel(
                section_id="sec-fuzz-runs",
                title="Fuzz Testing Results",
                summary=(
                    f"{len(runs)} fuzz run(s), "
                    f"{total_sent} case(s) sent, {total_crashes} crash(es) detected."
                ),
                blocks=tuple(blocks),
            )
        ]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("fuzz_runs", []),
            "campaigns": report_state.get("campaigns", []),
            "protocol_runs": report_state.get("protocol_runs", []),
            "operations": report_state.get("operations", []),
            "crashes": report_state.get("crashes", []),
            "results": report_state.get("fuzz_results", []),
            "executions": report_state.get("fuzz_executions", []),
            "per_protocol_runs": report_state.get("fuzz_protocol_runs", []),
            "state_coverage": report_state.get("fuzz_state_coverage", []),
            "field_weights": report_state.get("fuzz_field_weights", []),
        }
