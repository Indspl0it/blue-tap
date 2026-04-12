"""Attack report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions, envelope_module_data


class AttackReportAdapter(ReportAdapter):
    module = "attack"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return envelope.get("module") == self.module or envelope.get("schema") == "blue_tap.attack.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("attack_runs", []).append(envelope)
        report_state.setdefault("attack_executions", []).extend(envelope_executions(envelope))
        report_state.setdefault("attack_operations", []).append(envelope_module_data(envelope))
        report_state.setdefault("attack_artifacts", []).extend(_collect_artifacts(envelope))
        report_state.setdefault("attack_limitations", []).extend(_collect_limitations(envelope))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("attack_runs", [])
        if not runs:
            return []

        blocks: list[SectionBlock] = []
        executions = report_state.get("attack_executions", [])
        limitations = report_state.get("attack_limitations", [])
        artifacts = report_state.get("attack_artifacts", [])

        # Cards for each attack operation
        cards = []
        for execution in executions:
            evidence = execution.get("evidence", {}) or {}
            details = {
                "Protocol": execution.get("protocol", ""),
                "Outcome": execution.get("module_outcome", ""),
                "Status": execution.get("execution_status", ""),
            }
            if execution.get("severity"):
                details["Severity"] = execution["severity"]
            if execution.get("destructive"):
                details["Destructive"] = "Yes"
            cards.append({
                "title": execution.get("title", execution.get("id", "")),
                "status": execution.get("module_outcome", ""),
                "details": details,
                "body": evidence.get("summary", ""),
            })
        if cards:
            blocks.append(SectionBlock("card_list", {"cards": cards}))

        if limitations:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Scope", "Limitation"],
                        "rows": [[item.get("scope", ""), item.get("text", "")] for item in limitations],
                    },
                )
            )

        if artifacts:
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Label", "Kind", "Path", "Execution"],
                        "rows": [
                            [
                                str(artifact.get("label", "")),
                                str(artifact.get("kind", "")),
                                str(artifact.get("path", "")),
                                str(artifact.get("execution_id", "")),
                            ]
                            for artifact in artifacts
                        ],
                    },
                )
            )

        return [SectionModel(
            section_id="sec-attack-ops",
            title="Attack Operation Runs",
            summary=f"{len(runs)} attack run(s) with {len(executions)} operation(s).",
            blocks=tuple(blocks),
        )]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("attack_runs", []),
            "results": report_state.get("attack_operations", []),
            "executions": report_state.get("attack_executions", []),
            "artifacts": report_state.get("attack_artifacts", []),
            "capability_limitations": report_state.get("attack_limitations", []),
        }


def _collect_artifacts(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []

    for artifact in envelope.get("artifacts", []) or []:
        if isinstance(artifact, dict):
            artifacts.append(artifact)

    for execution in envelope.get("executions", []) or []:
        if not isinstance(execution, dict):
            continue
        for artifact in execution.get("artifacts", []) or []:
            if isinstance(artifact, dict):
                artifacts.append(artifact)
        evidence = execution.get("evidence", {}) or {}
        if isinstance(evidence, dict):
            for artifact in evidence.get("artifacts", []) or []:
                if isinstance(artifact, dict):
                    artifacts.append(artifact)

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for artifact in artifacts:
        key = (
            str(artifact.get("label", "")),
            str(artifact.get("kind", "")),
            str(artifact.get("path", "")),
            str(artifact.get("execution_id", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(artifact)
    return deduped


def _collect_limitations(envelope: dict[str, Any]) -> list[dict[str, str]]:
    limitations: list[dict[str, str]] = []

    def add(scope: str, values: Any) -> None:
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            return
        for value in values:
            if not value:
                continue
            limitations.append({"scope": scope, "text": str(value)})

    summary = envelope.get("summary", {}) or {}
    module_data = envelope.get("module_data", {}) or {}
    add("run", summary.get("capability_limitations"))
    add("run", module_data.get("capability_limitations"))

    for execution in envelope.get("executions", []) or []:
        if not isinstance(execution, dict):
            continue
        scope = execution.get("title", execution.get("id", "execution"))
        evidence = execution.get("evidence", {}) or {}
        if isinstance(evidence, dict):
            add(str(scope), evidence.get("capability_limitations"))

    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in limitations:
        key = (item["scope"], item["text"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
