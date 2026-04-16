"""Discovery report adapter."""

from __future__ import annotations

from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.framework.contracts.result_schema import envelope_executions, envelope_module_data


class DiscoveryReportAdapter(ReportAdapter):
    module = "discovery"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        """Accept legacy ``module="scan"`` and modern ``discovery.*`` envelopes.

        Modules now record their full ``module_id`` (e.g. ``discovery.scanner``)
        in the envelope ``module`` field. The previous strict equality check
        against ``"scan"`` made the discovery scanner invisible to the report
        once the module name was corrected.
        """
        module = str(envelope.get("module", ""))
        schema = str(envelope.get("schema", ""))
        if module == self.module or module.startswith("discovery."):
            return True
        return schema == "blue_tap.scan.result"

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        report_state.setdefault("scan_runs", []).append(envelope)
        report_state.setdefault("scan_executions", []).extend(envelope_executions(envelope))
        module_data = envelope_module_data(envelope)
        report_state.setdefault("scan_results", []).extend(module_data.get("devices", []))

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("scan_runs", [])
        devices = report_state.get("scan_results", [])
        if not runs:
            return []
        latest = runs[-1] if runs else {}
        summary = latest.get("summary", {})

        blocks: list[SectionBlock] = []

        # Summary badges
        classic_count = sum(1 for d in devices if d.get("type", "").lower() in ("classic", "br/edr"))
        ble_count = sum(1 for d in devices if d.get("type", "").lower() in ("ble", "le"))
        dual_count = summary.get("exact_dual_mode_matches", 0)
        badges = [
            {"label": "Total Devices", "value": len(devices), "status": "info"},
            {"label": "Classic", "value": classic_count, "status": "info"},
            {"label": "BLE", "value": ble_count, "status": "info"},
        ]
        if dual_count:
            badges.append({"label": "Dual-Mode Matches", "value": dual_count, "status": "success"})
        blocks.append(SectionBlock("badge_group", {"badges": badges}))

        if devices:
            rows = []
            for d in devices:
                class_info = d.get("class_info", {}) or {}
                services = d.get("service_uuids", []) or []
                if len(services) > 2:
                    service_preview = ", ".join(services[:2]) + f" (+{len(services) - 2})"
                else:
                    service_preview = ", ".join(services)
                notes = []
                if d.get("merge_reason"):
                    notes.append(str(d.get("merge_reason")))
                if d.get("possible_dual_mode_with"):
                    notes.append(f"correlation_hints={len(d.get('possible_dual_mode_with', []))}")
                rows.append([
                    d.get("address", ""),
                    d.get("name", "Unknown"),
                    str(d.get("rssi", "")),
                    d.get("type", "Unknown"),
                    class_info.get("minor") or class_info.get("major") or "",
                    d.get("manufacturer_name") or d.get("oui_vendor") or "",
                    service_preview,
                    "; ".join(notes),
                ])
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": ["Address", "Name", "RSSI", "Type", "Class", "Manufacturer", "Services", "Notes"],
                        "rows": rows,
                    },
                )
            )
        else:
            blocks.append(
                SectionBlock(
                    "text",
                    {"text": "Discovery completed successfully, but no Bluetooth devices were observed during this scan window."},
                )
            )

        return [
            SectionModel(
                section_id="sec-devices",
                title="Discovered Devices",
                summary=f"{len(devices)} device(s) discovered." if devices else "Scan completed with no devices discovered.",
                blocks=tuple(blocks),
            )
        ]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {
            "runs": report_state.get("scan_runs", []),
            "devices": report_state.get("scan_results", []),
            "executions": report_state.get("scan_executions", []),
        }
