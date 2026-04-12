"""Pentest report generation for Blue-Tap.

Generates professional HTML or JSON reports from attack session data including
scan results, vulnerability findings, PBAP/MAP dumps, fuzzing campaigns, and
analysis notes.  All charts use inline SVG (no JS dependencies).
"""

import html as _html_mod
import json
import math
import os
from datetime import datetime

from blue_tap.framework.reporting.adapters import get_report_adapters
from blue_tap.framework.reporting.renderers import render_sections
from blue_tap.utils.output import info, success, error, warning

try:
    from blue_tap import __version__
except ImportError:
    __version__ = "unknown"


# Resolved once at module load time: built-in adapters + any registered by plugins.
REPORT_ADAPTERS = get_report_adapters()
_REPORT_ADAPTER_MAP = {adapter.module: adapter for adapter in REPORT_ADAPTERS}


# ---------------------------------------------------------------------------
# SVG chart helpers (pure SVG, no JS)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
    "INFO": "#2563eb",
    "UNKNOWN": "#6b7280",
}


def _svg_donut_chart(data: dict[str, int], colors: dict[str, str],
                     size: int = 180, hole: float = 0.6) -> str:
    """Render an SVG donut chart.  *data* maps label -> count."""
    total = sum(data.values())
    if total == 0:
        return ""

    cx = cy = size / 2
    r = (size / 2) * 0.85
    circumference = 2 * math.pi * r
    segments: list[str] = []
    offset = 0.0

    for label, count in data.items():
        if count == 0:
            continue
        pct = count / total
        dash = pct * circumference
        gap = circumference - dash
        color = colors.get(label, "#666")
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{color}" stroke-width="{r * (1 - hole)}" '
            f'stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" />'
        )
        offset += dash

    # center label
    segments.append(
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" '
        f'fill="#333" font-size="22" font-weight="bold">{total}</text>'
    )
    segments.append(
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" '
        f'fill="#666" font-size="11">TOTAL</text>'
    )

    # legend
    legend_y = size + 8
    legend_items: list[str] = []
    lx = 4
    for label, count in data.items():
        if count == 0:
            continue
        color = colors.get(label, "#666")
        legend_items.append(
            f'<rect x="{lx}" y="{legend_y}" width="10" height="10" '
            f'rx="2" fill="{color}"/>'
            f'<text x="{lx + 14}" y="{legend_y + 9}" fill="#474F51" '
            f'font-size="10">{_esc(label)} ({count})</text>'
        )
        lx += len(label) * 7 + 46

    svg_h = size + 28
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{max(size, lx + 10)}" height="{svg_h}" '
        f'viewBox="0 0 {max(size, lx + 10)} {svg_h}">',
        *segments,
        *legend_items,
        "</svg>",
    ]
    return "\n".join(lines)


def _svg_bar_chart(data: dict[str, int], color: str = "#2B579A",
                   width: int = 420, bar_height: int = 26) -> str:
    """Render an SVG horizontal bar chart."""
    if not data:
        return ""

    max_val = max(data.values()) or 1
    label_width = max(len(k) for k in data) * 8 + 10
    chart_w = width - label_width - 50
    total_h = len(data) * (bar_height + 6) + 4

    bars: list[str] = []
    y = 4
    for label, val in data.items():
        bw = max(2, (val / max_val) * chart_w)
        bars.append(
            f'<text x="{label_width - 4}" y="{y + bar_height * 0.7}" '
            f'text-anchor="end" fill="#474F51" font-size="11">{_esc(label)}</text>'
        )
        bars.append(
            f'<rect x="{label_width}" y="{y}" width="{bw:.1f}" '
            f'height="{bar_height}" rx="3" fill="{color}" opacity="0.85"/>'
        )
        bars.append(
            f'<text x="{label_width + bw + 6}" y="{y + bar_height * 0.7}" '
            f'fill="#333" font-size="11" font-weight="bold">{val}</text>'
        )
        y += bar_height + 6

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{total_h}" '
        f'viewBox="0 0 {width} {total_h}">\n'
        + "\n".join(bars)
        + "\n</svg>"
    )


def _esc(text: str) -> str:
    """Escape HTML special characters including single quotes."""
    return _html_mod.escape(str(text), quote=True)


def _risk_rating(vuln_findings: list[dict], fuzz_crashes: list[dict]) -> str:
    """Compute overall risk rating from findings and crashes."""
    all_sevs = [f.get("severity", "").upper() for f in vuln_findings]
    all_sevs += [c.get("severity", "").upper() for c in fuzz_crashes]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if level in all_sevs:
            return level
    return "INFO"


def _display_vuln_findings(vuln_findings: list[dict]) -> list[dict]:
    """Findings worth rendering as actual report findings."""
    return [f for f in vuln_findings if f.get("status") != "not_applicable"]



# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

_CSS = """
*, *::before, *::after { box-sizing: border-box; }
body { font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif;
       margin: 0; padding: 0; background: #f8fafc; color: #1e293b; font-size: 14px; line-height: 1.65; }
.page-container { max-width: 1080px; margin: 32px auto; background: #fff; border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.04); overflow: hidden; }
.report-header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #fff; padding: 28px 36px; }
.report-header h1 { margin: 0; font-size: 1.75em; font-weight: 700; color: #fff; border: none; letter-spacing: -0.02em; }
.report-header .version { color: #94a3b8; font-size: 0.85em; margin-top: 6px; }
.classification-banner { background: #dc2626; color: #fff; text-align: center; padding: 6px 12px;
    font-size: 0.75em; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; }
.report-body { padding: 32px 36px; }
h1 { color: #0f172a; font-size: 1.5em; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-top: 0; font-weight: 700; }
h2 { color: #0f172a; margin-top: 36px; font-size: 1.25em; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; font-weight: 700; }
h3 { color: #334155; font-size: 1.05em; font-weight: 600; }
h4 { color: #475569; font-size: 0.95em; margin-top: 14px; font-weight: 600; }
h5 { color: #64748b; font-size: 0.9em; margin-bottom: 4px; font-weight: 600; }
a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; color: #1d4ed8; }
p { margin: 8px 0; color: #334155; }
pre { background: #f8fafc; padding: 14px 16px; border-radius: 8px; overflow-x: auto; font-size: 12px;
    line-height: 1.5; border: 1px solid #e2e8f0; font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; color: #334155; }
code { background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 0.88em; color: #475569;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }
table { border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 0.875em; }
th, td { padding: 10px 14px; text-align: left; vertical-align: middle; }
th { background: #f8fafc; color: #475569; font-weight: 600; font-size: 0.8em; text-transform: uppercase;
    letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }
td { border-bottom: 1px solid #f1f5f9; }
tr:hover td { background: #f8fafc; }
.header { display: none; }
.meta { color: #64748b; font-size: 0.85em; margin: 4px 0; }
.section { margin: 24px 0; padding: 20px 24px; border: 1px solid #e2e8f0; border-radius: 10px; background: #fff; }
.summary { background: #f8fafc; padding: 18px 20px; border-radius: 10px; margin: 16px 0; border: 1px solid #e2e8f0; }
.toc { background: #f8fafc; border: 1px solid #e2e8f0; padding: 18px 24px; border-radius: 10px; margin: 20px 0; }
.toc ol { padding-left: 20px; }
.toc li { margin: 5px 0; }
.toc a { color: #2563eb; font-weight: 500; }
.risk-badge { display: inline-block; padding: 10px 28px; border-radius: 8px; font-size: 1.2em;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
.risk-CRITICAL { background: #fef2f2; color: #dc2626; border: 2px solid #fecaca; }
.risk-HIGH { background: #fff7ed; color: #ea580c; border: 2px solid #fed7aa; }
.risk-MEDIUM { background: #fffbeb; color: #d97706; border: 2px solid #fde68a; }
.risk-LOW { background: #f0fdf4; color: #16a34a; border: 2px solid #bbf7d0; }
.risk-INFO { background: #eff6ff; color: #2563eb; border: 2px solid #bfdbfe; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 16px; margin: 20px 0; }
.metric-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; text-align: center;
    transition: box-shadow 0.15s; }
.metric-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.metric-card .value { font-size: 2em; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; }
.metric-card .label { font-size: 0.78em; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
.chart-row { display: flex; gap: 28px; flex-wrap: wrap; align-items: flex-start; margin: 20px 0; }
.finding-card { border-left: 4px solid #e2e8f0; padding: 18px 20px; margin: 14px 0; background: #fff;
    border: 1px solid #e2e8f0; border-radius: 10px; }
.finding-card.sev-CRITICAL { border-left: 4px solid #dc2626; background: #fefefe; }
.finding-card.sev-HIGH { border-left: 4px solid #ea580c; }
.finding-card.sev-MEDIUM { border-left: 4px solid #d97706; }
.finding-card.sev-LOW { border-left: 4px solid #16a34a; }
.finding-card.sev-INFO { border-left: 4px solid #2563eb; }
.evidence-block { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 16px; margin: 10px 0; }
.evidence-block .ev-label { color: #475569; font-size: 0.8em; font-weight: 700; margin-bottom: 6px;
    text-transform: uppercase; letter-spacing: 0.05em; }
.crash-card { border-left: 4px solid #dc2626; padding: 16px 20px; margin: 14px 0; background: #fff;
    border: 1px solid #e2e8f0; border-radius: 10px; }
.crash-card.high { border-left-color: #ea580c; }
.crash-card.medium { border-left-color: #d97706; }
.hexdump { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 11px; line-height: 1.5; }
.severity-badge { display: inline-block; padding: 3px 10px; border-radius: 6px; font-weight: 600;
    font-size: 0.75em; text-align: center; letter-spacing: 0.03em; }
.severity-CRITICAL { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.severity-HIGH { background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }
.severity-MEDIUM { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
.severity-LOW { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
.severity-INFO { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }
.status-confirmed { color: #dc2626; font-weight: 600; }
.status-potential { color: #ea580c; font-weight: 600; }
.status-unverified { color: #2563eb; }
.status-inconclusive { color: #d97706; font-weight: 600; }
.status-pairing_required { color: #2563eb; font-weight: 600; }
.status-not_applicable { color: #64748b; }
.status-success { color: #16a34a; font-weight: 600; }
.status-recovered { color: #2563eb; font-weight: 600; }
.status-unresponsive { color: #dc2626; font-weight: 700; }
.status-error { color: #dc2626; font-weight: 600; }
.status-failed { color: #d97706; font-weight: 600; }
.status-skipped { color: #64748b; }
.reproduced-yes { color: #16a34a; font-weight: 600; }
.reproduced-no { color: #dc2626; }
.tag { display: inline-block; background: #f1f5f9; border: 1px solid #e2e8f0; padding: 2px 10px;
    border-radius: 9999px; font-size: 0.75em; color: #475569; margin: 2px; font-weight: 500; }
.timeline-table td:first-child { white-space: nowrap; color: #64748b; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; }
.fuzz-stat { display: inline-block; margin: 5px 18px 5px 0; }
.fuzz-stat .value { font-size: 1.5em; font-weight: 800; color: #0f172a; }
.fuzz-stat .label { font-size: 0.8em; color: #64748b; }
.mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
.evidence-list { list-style: none; padding: 0; }
.evidence-list li { padding: 4px 0; color: #475569; }
.footer { text-align: center; color: #94a3b8; font-size: 0.8em; padding: 20px 36px;
    border-top: 1px solid #e2e8f0; background: #f8fafc; }
.card-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; margin: 14px 0; }
.card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 20px; background: #fff; }
.card-header { margin-bottom: 8px; font-size: 0.95em; }
.card-details { display: grid; grid-template-columns: auto 1fr; gap: 2px 12px; margin: 8px 0; font-size: 0.85em; }
.card-details dt { color: #64748b; font-weight: 600; }
.card-details dd { margin: 0; color: #334155; }
.card-body { color: #475569; font-size: 0.85em; margin: 6px 0 0; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 0.75em; font-weight: 600;
    letter-spacing: 0.03em; margin: 2px; }
.badge-danger { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.badge-warning { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
.badge-info { background: #eff6ff; color: #2563eb; border: 1px solid #bfdbfe; }
.badge-critical { background: #fef2f2; color: #991b1b; border: 1px solid #fca5a5; }
.badge-pairing { background: #faf5ff; color: #7c3aed; border: 1px solid #ddd6fe; }
.badge-default { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
.badge-group { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
.status-summary { display: flex; flex-wrap: wrap; gap: 18px; margin: 14px 0; padding: 14px 18px;
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; }
.status-item { text-align: center; }
.status-count { display: block; font-size: 1.5em; font-weight: 800; }
.status-label { display: block; font-size: 0.75em; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
.timeline { border-left: 3px solid #e2e8f0; margin: 14px 0; padding-left: 18px; }
.timeline-event { margin: 10px 0; display: flex; gap: 10px; align-items: baseline; }
.timeline-ts { color: #64748b; font-family: 'JetBrains Mono', monospace; font-size: 0.8em; white-space: nowrap; }
.timeline-label { font-weight: 600; font-size: 0.85em; }
.timeline-msg { color: #475569; font-size: 0.85em; }
.kv-list { display: grid; grid-template-columns: auto 1fr; gap: 4px 14px; margin: 10px 0; }
.kv-list dt { color: #64748b; font-weight: 600; font-size: 0.85em; }
.kv-list dd { margin: 0; color: #334155; font-size: 0.85em; }
@media print {
    body { background: #fff; }
    .page-container { box-shadow: none; max-width: 100%; border-radius: 0; margin: 0; }
    .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .classification-banner { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .severity-badge, .risk-badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .section { break-inside: avoid; }
}
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blue-Tap Pentest Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
{css}
</style>
</head>
<body>
<div class="page-container">
{content}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates pentest reports from Blue-Tap session data."""

    def __init__(self):
        self.scan_results: list[dict] = []
        self.scan_runs: list[dict] = []
        self.vuln_findings: list[dict] = []
        self.vuln_scan_runs: list[dict] = []
        self.recon_results: list[dict] = []
        self.fuzz_runs: list[dict] = []
        self.notes: list[str] = []
        # Session metadata for timeline/scope
        self._session_metadata: dict = {}
        self._module_report_state: dict[str, dict] = {
            "scan": {"scan_runs": [], "scan_results": [], "scan_executions": []},
            "vulnscan": {"vuln_scan_runs": [], "vuln_findings": [], "vuln_executions": []},
            "attack": {"attack_runs": [], "attack_executions": [], "attack_operations": []},
            "data": {"data_runs": [], "data_executions": [], "data_operations": []},
            "audio": {"audio_runs": [], "audio_executions": [], "audio_operations": []},
            "dos": {"dos_runs": [], "dos_results": [], "dos_executions": []},
            "fuzz": {"fuzz_runs": [], "campaigns": [], "protocol_runs": [], "operations": [], "crashes": []},
            "lmp_capture": {"lmp_captures": []},
            "recon": {"recon_runs": [], "recon_results": [], "fingerprints": [], "capture_results": [], "recon_executions": []},
        }

    def _all_module_executions(self) -> list[dict]:
        executions: list[dict] = []
        seen_execution_ids: set[str] = set()
        for adapter in REPORT_ADAPTERS:
            section = adapter.build_json_section(self._module_report_state.get(adapter.module, {}))
            for execution in section.get("executions", []):
                execution_id = str(execution.get("execution_id", ""))
                if execution_id and execution_id in seen_execution_ids:
                    continue
                if execution_id:
                    seen_execution_ids.add(execution_id)
                executions.append(execution)
        return executions

    def _module_json_section(self, module: str) -> dict:
        return _REPORT_ADAPTER_MAP[module].build_json_section(self._module_report_state.get(module, {}))

    def _render_module_html(self, module: str, *, state_keys: tuple[str, ...]) -> str:
        adapter_state = self._module_report_state.get(module, {})
        if not any(adapter_state.get(key) for key in state_keys):
            return ""
        return render_sections(_REPORT_ADAPTER_MAP[module].build_sections(adapter_state))

    def _data_operations(self, family: str | None = None) -> list[dict]:
        operations = list(self._module_report_state.get("data", {}).get("data_operations", []))
        if family is None:
            return operations
        return [operation for operation in operations if operation.get("family") == family]

    def _fuzz_adapter_state(self) -> dict:
        """Return the fuzz adapter report state (single source of truth for fuzz data)."""
        return self._module_report_state.get("fuzz", {})

    @property
    def _fuzz_crashes(self) -> list[dict]:
        return self._fuzz_adapter_state().get("crashes", [])

    @property
    def _fuzz_campaign_stats(self) -> dict:
        stats_list = self._fuzz_adapter_state().get("campaign_stats_list", [])
        if stats_list:
            return stats_list[-1]
        return {}

    @property
    def _fuzz_state_coverage(self) -> dict:
        return self._fuzz_adapter_state().get("campaign_state_coverage", {})

    @property
    def _fuzz_field_weights(self) -> dict:
        return self._fuzz_adapter_state().get("campaign_field_weights", {})

    @property
    def _fuzz_health_events(self) -> list[dict]:
        return self._fuzz_adapter_state().get("campaign_health_events", [])

    @property
    def _fuzz_baselines(self) -> dict:
        return self._fuzz_adapter_state().get("campaign_baselines", {})

    @property
    def _fuzz_evidence_dir(self) -> str:
        return self._fuzz_adapter_state().get("evidence_dir", "")

    @property
    def _fuzz_corpus_stats(self) -> dict:
        return self._fuzz_adapter_state().get("corpus_stats", {})

    @property
    def _fuzz_evidence_files(self) -> list:
        return self._fuzz_adapter_state().get("evidence_files", [])

    def _ingest_standardized_envelope(self, envelope: dict) -> bool:
        for adapter in REPORT_ADAPTERS:
            if adapter.accepts(envelope):
                adapter.ingest(envelope, self._module_report_state.setdefault(adapter.module, {}))
                return True
        return False

    def add_run_envelope(self, envelope: dict) -> bool:
        """Ingest a standardized module run envelope."""
        if not isinstance(envelope, dict):
            return False
        schema = str(envelope.get("schema", ""))
        if not schema.startswith("blue_tap.") or not schema.endswith(".result"):
            return False

        module = envelope.get("module")
        if module == "scan":
            self.scan_runs.append(envelope)
            self.scan_results.extend(envelope.get("module_data", {}).get("devices", []))
        elif module == "vulnscan":
            self.vuln_scan_runs.append(envelope)
            self.vuln_findings.extend(envelope.get("module_data", {}).get("findings", []))
        elif module in {"attack", "data", "audio", "dos", "spoof", "firmware", "auto", "playbook", "lmp_capture"}:
            # Fully adapter-managed modules do not need legacy instance vars.
            ...
        elif module == "fuzz":
            self.fuzz_runs.append(envelope)
            # All fuzz data is handled by FuzzReportAdapter via _ingest_standardized_envelope below.
        elif module == "recon":
            module_data = envelope.get("module_data", {})
            entries = module_data.get("entries", [])
            if isinstance(entries, list):
                self.recon_results.extend(entries)
        else:
            return False

        self._ingest_standardized_envelope(envelope)
        return True

    # ------------------------------------------------------------------
    # Data intake
    # ------------------------------------------------------------------

    def add_note(self, note: str):
        self.notes.append(note)

    def add_session_metadata(self, metadata: dict) -> None:
        """Store session metadata for timeline, scope, and methodology sections."""
        self._session_metadata = metadata if isinstance(metadata, dict) else {}

    # ------------------------------------------------------------------
    # Load from directory (generic)
    # ------------------------------------------------------------------

    def load_from_directory(self, dump_dir: str):
        """Load standardized report data from a Blue-Tap directory."""
        if not os.path.isdir(dump_dir):
            error(f"Directory not found: {dump_dir}")
            return
        processed_json_paths: set[str] = set()

        session_meta_path = os.path.join(dump_dir, "session.json")
        if os.path.exists(session_meta_path):
            try:
                with open(session_meta_path) as f:
                    metadata = json.load(f)
                if isinstance(metadata, dict):
                    self.add_session_metadata(metadata)
                    for cmd_entry in metadata.get("commands", []):
                        if not isinstance(cmd_entry, dict):
                            continue
                        entry_file = cmd_entry.get("file")
                        if not entry_file:
                            continue
                        entry_path = os.path.join(dump_dir, str(entry_file))
                        if not os.path.exists(entry_path):
                            continue
                        processed_json_paths.add(os.path.abspath(entry_path))
                        try:
                            with open(entry_path) as f:
                                entry = json.load(f)
                        except (json.JSONDecodeError, OSError):
                            continue
                        if isinstance(entry, dict):
                            self.add_run_envelope(entry.get("data", {}))
                info(f"Loaded standardized session data from {dump_dir}")
            except (json.JSONDecodeError, OSError) as exc:
                warning(f"Could not load session.json from {dump_dir}: {exc}")

        for root, _dirs, files in os.walk(dump_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, dump_dir)
                if not fname.endswith(".json") or fname == "session.json":
                    continue
                if rel.startswith("fuzz/") or rel.startswith("fuzz\\"):
                    continue
                if os.path.abspath(fpath) in processed_json_paths:
                    continue
                try:
                    with open(fpath) as f:
                        data = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue
                if isinstance(data, dict) and self.add_run_envelope(data):
                    continue
                if isinstance(data, dict):
                    self.add_run_envelope(data.get("data", {}))

    # ===================================================================
    # HTML Section Builders
    # ===================================================================

    def _build_header_html(self) -> str:
        meta = self._session_metadata or {}
        created = meta.get("created", "")
        updated = meta.get("last_updated", "")
        period = ""
        if created:
            period = f"Assessment Period: {created[:10]}"
            if updated and updated[:10] != created[:10]:
                period += f" to {updated[:10]}"

        return (
            '<div class="report-header">'
            f'<h1>Blue-Tap Pentest Report</h1>'
            f'<p class="version">Blue-Tap v{_esc(__version__)} '
            f'| Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
            f'{" | " + _esc(period) if period else ""}'
            f'</p>'
            '</div>'
            '<div class="classification-banner">CONFIDENTIAL - Authorized Personnel Only</div>'
            '<div class="report-body">'
        )

    def _build_toc_html(self, sections_present: list[tuple[str, str]]) -> str:
        """Build table of contents from list of (anchor, title) tuples."""
        items = []
        for i, (anchor, title) in enumerate(sections_present, 1):
            items.append(f'<li><a href="#{anchor}">{i}. {_esc(title)}</a></li>')
        return (
            '<div class="toc">'
            '<h2 style="margin-top:0">Table of Contents</h2>'
            f'<ol>{"".join(items)}</ol>'
            '</div>'
        )

    def _build_executive_summary_html(self) -> str:
        s = []
        s.append('<div class="section" id="sec-executive-summary">')
        s.append('<h2>Executive Summary</h2>')

        # Risk rating
        from blue_tap.modules.assessment.cve_framework import summarize_findings  # CVE-specific; imported here, not at module level
        rating = _risk_rating(self.vuln_findings, self._fuzz_crashes)
        vuln_summary = summarize_findings(self.vuln_findings)
        display_findings = _display_vuln_findings(self.vuln_findings)
        s.append(f'<div style="text-align:center;margin:16px 0">'
                 f'<span class="risk-badge risk-{rating}">Overall Risk: {rating}</span></div>')

        # Narrative summary paragraph
        confirmed = vuln_summary["confirmed"]
        inconclusive = vuln_summary["inconclusive"]
        pairing_required = vuln_summary["pairing_required"]
        crash_count = len(self._fuzz_crashes)
        num_devices = len(self.scan_results) or 1

        narrative = (
            f'<p>This assessment evaluated the Bluetooth security posture of '
            f'{num_devices} device(s). '
            f'{confirmed} confirmed vulnerabilit{"y" if confirmed == 1 else "ies"} '
            f'were identified, with {inconclusive} inconclusive probe result(s) '
            f'and {pairing_required} pairing-gated check(s), '
            f'with an overall risk rating of <strong>{rating}</strong>.'
        )
        if crash_count:
            crash_protos = sorted(set(
                c.get("protocol", "unknown") for c in self._fuzz_crashes))
            critical_crashes = sum(
                1 for c in self._fuzz_crashes
                if c.get("severity", "").upper() == "CRITICAL")
            narrative += (
                f' Protocol fuzzing generated {crash_count} crash'
                f'{"es" if crash_count != 1 else ""} across '
                f'{len(crash_protos)} protocol(s), '
            )
            if critical_crashes:
                narrative += (
                    f'including {critical_crashes} critical crash'
                    f'{"es" if critical_crashes != 1 else ""} '
                    f'that caused device reboots — indicating memory safety '
                    f'issues in the target\'s Bluetooth stack.'
                )
            else:
                narrative += (
                    'indicating input validation weaknesses in the '
                    'target\'s Bluetooth stack.'
                )
        pbap_operations = self._data_operations("pbap")
        map_operations = self._data_operations("map")
        if pbap_operations or map_operations:
            data_types = []
            if pbap_operations:
                data_types.append("contacts")
            if map_operations:
                data_types.append("messages")
            narrative += (
                f' Sensitive data including {"/".join(data_types)} was '
                f'successfully extracted without user awareness.'
            )
        narrative += '</p>'
        s.append(narrative)

        # Metric cards
        data_exfil = len(pbap_operations) + len(map_operations)
        packets = self._fuzz_campaign_stats.get("packets_sent", 0)

        s.append('<div class="metric-grid">')
        for val, label in [
            (len(self.scan_results), "Devices Scanned"),
            (f"{confirmed}C / {inconclusive}I", "Vulnerabilities"),
            (f"{crash_count}", "Fuzz Crashes"),
            (f"{packets:,}", "Fuzz Test Cases"),
            (f"{data_exfil}", "Data Sets Exfiltrated"),
            (f"{len(self._module_report_state.get('dos', {}).get('dos_executions', []))}", "DoS Tests"),
        ]:
            s.append(f'<div class="metric-card">'
                     f'<div class="value">{val}</div>'
                     f'<div class="label">{label}</div></div>')
        s.append('</div>')

        # Findings breakdown table
        if display_findings:
            sev_counts: dict[str, int] = {}
            for f in display_findings:
                sv = f.get("severity", "INFO").upper()
                sev_counts[sv] = sev_counts.get(sv, 0) + 1
            s.append('<p><strong>Vulnerability Breakdown:</strong> ')
            parts = []
            for sv in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                c = sev_counts.get(sv, 0)
                if c:
                    parts.append(f'<span class="severity-badge severity-{sv}">{c} {sv}</span>')
            s.append(" ".join(parts) + '</p>')

        # Charts row
        charts = []

        # Vuln severity donut
        if display_findings:
            vuln_by_sev = {}
            for f in display_findings:
                sv = f.get("severity", "INFO").upper()
                vuln_by_sev[sv] = vuln_by_sev.get(sv, 0) + 1
            chart = _svg_donut_chart(vuln_by_sev, _SEVERITY_COLORS)
            if chart:
                charts.append(f'<div><h4>Vulnerability Severity</h4>{chart}</div>')

        # Crash severity donut
        if self._fuzz_crashes:
            crash_by_sev = {}
            for c in self._fuzz_crashes:
                sv = c.get("severity", "UNKNOWN").upper()
                crash_by_sev[sv] = crash_by_sev.get(sv, 0) + 1
            chart = _svg_donut_chart(crash_by_sev, _SEVERITY_COLORS)
            if chart:
                charts.append(f'<div><h4>Crash Severity</h4>{chart}</div>')

        # Protocol crash bar chart
        if self._fuzz_crashes:
            crash_by_proto: dict[str, int] = {}
            for c in self._fuzz_crashes:
                p = c.get("protocol", "unknown")
                crash_by_proto[p] = crash_by_proto.get(p, 0) + 1
            chart = _svg_bar_chart(crash_by_proto, "#EE9336")
            if chart:
                charts.append(f'<div><h4>Crashes by Protocol</h4>{chart}</div>')

        if charts:
            s.append('<div class="chart-row">' + "".join(charts) + '</div>')

        s.append('</div>')
        return "\n".join(s)

    def _build_scope_html(self) -> str:
        meta = self._session_metadata
        if not meta:
            return ""

        s = []
        s.append('<div class="section" id="sec-scope">')
        s.append('<h2>Scope and Methodology</h2>')

        s.append(f'<p><strong>Tool:</strong> Blue-Tap v{_esc(__version__)}</p>')

        targets = meta.get("targets", [])
        if targets:
            s.append('<h3>Target Devices</h3><table><tr><th>MAC Address</th></tr>')
            for t in targets:
                s.append(f'<tr><td class="mono">{_esc(t)}</td></tr>')
            s.append('</table>')

        # Methodology from commands executed
        commands = meta.get("commands", [])
        if commands:
            categories = sorted(set(c.get("category", "general") for c in commands))
            category_labels = {
                "scan": "Device Discovery", "recon": "Reconnaissance",
                "vuln": "Vulnerability Assessment", "attack": "Exploitation",
                "fuzz": "Fuzz Testing", "dos": "Denial of Service Testing",
                "data": "Data Extraction", "audio": "Audio Capture",
            }
            s.append('<h3>Assessment Modules Executed</h3><table>'
                     '<tr><th>Phase</th><th>Module</th><th>Commands Run</th></tr>')
            for cat in categories:
                label = category_labels.get(cat, cat.title())
                count = sum(1 for c in commands if c.get("category") == cat)
                s.append(f'<tr><td>{_esc(label)}</td><td>{_esc(cat)}</td><td>{count}</td></tr>')
            s.append('</table>')

        s.append('</div>')
        return "\n".join(s)

    def _build_timeline_html(self) -> str:
        meta = self._session_metadata
        commands = meta.get("commands", []) if meta else []
        if not commands:
            return ""

        s = []
        s.append('<div class="section" id="sec-timeline">')
        s.append('<h2>Assessment Timeline</h2>')
        s.append('<table class="timeline-table"><tr><th>Time</th><th>Command</th>'
                 '<th>Category</th><th>Target</th></tr>')
        for cmd in commands:
            ts = cmd.get("timestamp", "")
            if ts:
                ts = ts[11:19] if len(ts) >= 19 else ts  # HH:MM:SS
            s.append(
                f'<tr><td>{_esc(ts)}</td>'
                f'<td><code>{_esc(cmd.get("command", ""))}</code></td>'
                f'<td><span class="tag">{_esc(cmd.get("category", ""))}</span></td>'
                f'<td class="mono">{_esc(cmd.get("target", ""))}</td></tr>'
            )
        s.append('</table></div>')
        return "\n".join(s)

    def _build_scan_html(self) -> str:
        adapter_state = self._module_report_state.get("scan", {})
        if adapter_state.get("scan_runs"):
            sections = _REPORT_ADAPTER_MAP["scan"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

    def _build_vuln_html(self) -> str:
        adapter_state = self._module_report_state.get("vulnscan", {})
        if adapter_state.get("vuln_scan_runs"):
            sections = _REPORT_ADAPTER_MAP["vulnscan"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

    def _build_attack_html(self) -> str:
        return self._render_module_html("attack", state_keys=("runs", "attack_runs"))

    def _build_recon_html(self) -> str:
        adapter_state = self._module_report_state.get("recon", {})
        if adapter_state.get("recon_runs"):
            sections = _REPORT_ADAPTER_MAP["recon"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

    def _build_dos_html(self) -> str:
        return self._render_module_html("dos", state_keys=("dos_runs",))

    def _build_pbap_html(self) -> str:
        return ""

    def _build_map_html(self) -> str:
        return ""

    def _build_data_ops_html(self) -> str:
        return self._render_module_html("data", state_keys=("runs", "data_runs"))

    def _build_audio_html(self) -> str:
        return self._render_module_html("audio", state_keys=("runs", "audio_runs"))

    def _build_appendix_html(self) -> str:
        if not self.notes:
            return ""
        parts = ['<div class="section" id="sec-appendix">', '<h2>Appendix</h2>', '<h3>Analyst Notes</h3>']
        for note in self.notes:
            parts.append(f'<p>{_esc(note)}</p>')
        parts.append('</div>')
        return "\n".join(parts)

    # ===================================================================
    # Public output generators
    # ===================================================================

    def generate_html(self, output: str = "report.html") -> str:
        """Generate a professional styled HTML pentest report."""
        # Determine which sections exist
        toc_entries: list[tuple[str, str]] = []
        toc_entries.append(("sec-executive-summary", "Executive Summary"))

        if self._session_metadata:
            toc_entries.append(("sec-scope", "Scope and Methodology"))
            if self._session_metadata.get("commands"):
                toc_entries.append(("sec-timeline", "Assessment Timeline"))

        if self.scan_results:
            toc_entries.append(("sec-devices", "Discovered Devices"))
        if self.vuln_findings:
            toc_entries.append(("sec-vulnerabilities", "Vulnerability Findings"))
        if self._module_report_state.get("attack", {}).get("runs") or self._module_report_state.get("attack", {}).get("attack_runs"):
            toc_entries.append(("sec-attack-ops", "Attack Operation Runs"))
        if self._module_report_state.get("auto", {}).get("auto_runs"):
            toc_entries.append(("sec-auto-pentest", "Automated Pentest Workflow"))
        fuzz_state = self._module_report_state.get("fuzz", {})
        if fuzz_state.get("fuzz_runs"):
            toc_entries.append(("sec-fuzzing", "Fuzzing Campaign Results"))
        has_fuzz_intel = any([
            fuzz_state.get("campaign_state_coverage"),
            fuzz_state.get("campaign_field_weights"),
            fuzz_state.get("campaign_health_events"),
            fuzz_state.get("campaign_baselines"),
        ])
        if has_fuzz_intel:
            toc_entries.append(("sec-fuzz-intel", "Fuzzing Intelligence Analysis"))
        if self._module_report_state.get("lmp_capture", {}).get("lmp_captures"):
            toc_entries.append(("sec-lmp", "LMP Capture Analysis"))
        if self.recon_results or self._module_report_state.get("recon", {}).get("recon_runs"):
            toc_entries.append(("sec-recon", "Reconnaissance Results"))
        if self._module_report_state.get("dos", {}).get("dos_runs"):
            toc_entries.append(("sec-dos", "Denial of Service Tests"))
        if self._module_report_state.get("data", {}).get("runs") or self._module_report_state.get("data", {}).get("data_runs"):
            toc_entries.append(("sec-data-ops", "Data Extraction Operations"))
        if self._module_report_state.get("audio", {}).get("runs") or self._module_report_state.get("audio", {}).get("audio_runs"):
            toc_entries.append(("sec-audio-ops", "Audio Operations"))
        if self.notes:
            toc_entries.append(("sec-appendix", "Appendix"))

        # Build all sections
        body_parts = [
            self._build_header_html(),
            self._build_toc_html(toc_entries),
            self._build_executive_summary_html(),
            self._build_scope_html(),
            self._build_timeline_html(),
            self._build_scan_html(),
            self._build_vuln_html(),
            self._build_attack_html(),
            self._render_module_html("auto", state_keys=("auto_runs",)),
        ]
        body_parts.append(self._render_module_html("fuzz", state_keys=("fuzz_runs",)))
        body_parts.append(self._render_module_html("lmp_capture", state_keys=("lmp_captures",)))
        body_parts.extend([
            self._build_recon_html(),
            self._build_dos_html(),
            self._build_data_ops_html(),
            self._build_pbap_html(),
            self._build_map_html(),
            self._build_audio_html(),
            self._build_appendix_html(),
            '</div>',  # close .report-body
            f'<div class="footer">Blue-Tap v{_esc(__version__)} | '
            f'Report generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | '
            f'CONFIDENTIAL</div>',
        ])

        content = "\n".join(p for p in body_parts if p)
        html = _HTML_TEMPLATE.replace("{css}", _CSS).replace("{content}", content)

        outdir = os.path.dirname(output)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        with open(output, "w") as f:
            f.write(html)
        success(f"HTML report generated: {output}")
        return output

    def generate_json(self, output: str = "report.json") -> str:
        """Generate a machine-readable JSON report."""
        from blue_tap.modules.assessment.cve_framework import summarize_findings  # CVE-specific; imported here, not at module level
        vuln_summary = summarize_findings(self.vuln_findings)
        # Fuzz section
        fuzz_data = {}
        if self._fuzz_campaign_stats or self._fuzz_crashes:
            fuzz_data = {
                "campaign_stats": self._fuzz_campaign_stats,
                "crashes": self._fuzz_crashes,
                "corpus_stats": self._fuzz_corpus_stats,
                "evidence_dir": self._fuzz_evidence_dir,
                "crash_summary": {
                    "total": len(self._fuzz_crashes),
                    "by_severity": {},
                    "by_protocol": {},
                    "by_type": {},
                    "reproduced": sum(1 for c in self._fuzz_crashes if c.get("reproduced")),
                },
            }
            for crash in self._fuzz_crashes:
                sev = crash.get("severity", "UNKNOWN")
                proto = crash.get("protocol", "unknown")
                ctype = crash.get("crash_type", "unknown")
                fuzz_data["crash_summary"]["by_severity"][sev] = (
                    fuzz_data["crash_summary"]["by_severity"].get(sev, 0) + 1)
                fuzz_data["crash_summary"]["by_protocol"][proto] = (
                    fuzz_data["crash_summary"]["by_protocol"].get(proto, 0) + 1)
                fuzz_data["crash_summary"]["by_type"][ctype] = (
                    fuzz_data["crash_summary"]["by_type"].get(ctype, 0) + 1)

        # Scope
        scope = {}
        if self._session_metadata:
            scope = {
                "targets": self._session_metadata.get("targets", []),
                "session_name": self._session_metadata.get("name", ""),
                "created": self._session_metadata.get("created", ""),
                "last_updated": self._session_metadata.get("last_updated", ""),
                "commands_executed": len(self._session_metadata.get("commands", [])),
                "categories": list(set(
                    c.get("category", "") for c in self._session_metadata.get("commands", [])
                )),
            }

        # Timeline
        timeline = []
        for cmd in (self._session_metadata or {}).get("commands", []):
            timeline.append({
                "timestamp": cmd.get("timestamp", ""),
                "command": cmd.get("command", ""),
                "category": cmd.get("category", ""),
                "target": cmd.get("target", ""),
            })

        report = {
            "generated": datetime.now().isoformat(),
            "tool": "Blue-Tap",
            "tool_version": __version__,
            "risk_rating": _risk_rating(self.vuln_findings, self._fuzz_crashes),
            "scope": scope,
            "summary": {
                "devices_scanned": len(self.scan_results),
                "total_findings": vuln_summary["displayed"],
                "status_counts": vuln_summary["status_counts"],
                "confirmed": vuln_summary["confirmed"],
                "potential": vuln_summary["potential"],
                "unverified": vuln_summary["unverified"],
                "inconclusive": vuln_summary["inconclusive"],
                "pairing_required": vuln_summary["pairing_required"],
                "not_applicable": vuln_summary["not_applicable"],
                "high_severity": vuln_summary["high_or_critical"],
                "fuzz_test_cases": self._fuzz_campaign_stats.get("packets_sent", 0),
                "fuzz_crashes": len(self._fuzz_crashes),
                "data_exfiltration": len(self._data_operations("pbap")) + len(self._data_operations("map")),
            },
            "timeline": timeline,
            "modules": {
                "scan": self._module_json_section("scan"),
                "vulnscan": self._module_json_section("vulnscan"),
                "attack": self._module_json_section("attack"),
                "auto": self._module_json_section("auto"),
                "data": self._module_json_section("data"),
                "audio": self._module_json_section("audio"),
                "dos": self._module_json_section("dos"),
                "fuzz": self._module_json_section("fuzz"),
                "lmp_capture": self._module_json_section("lmp_capture"),
                "recon": self._module_json_section("recon"),
            },
            "executions": self._all_module_executions(),
            "scan_results": self.scan_results,
            "scan_runs": self.scan_runs,
            "vulnerabilities": self.vuln_findings,
            "vulnerability_scans": self.vuln_scan_runs,
            "recon_results": self.recon_results,
            "fuzzing": (
                fuzz_data
                if fuzz_data
                else self._module_json_section("fuzz").get("results", [])
            ),
            "fuzz_runs": self.fuzz_runs,
            "fuzzing_intelligence": {
                "state_coverage": self._fuzz_state_coverage,
                "field_weights": self._fuzz_field_weights,
                "baselines": self._fuzz_baselines,
                "health_events": self._fuzz_health_events,
            } if any([self._fuzz_state_coverage, self._fuzz_field_weights,
                      self._fuzz_health_events, self._fuzz_baselines]) else {},
            "notes": self.notes,
        }

        outdir = os.path.dirname(output)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"JSON report generated: {output}")
        return output
