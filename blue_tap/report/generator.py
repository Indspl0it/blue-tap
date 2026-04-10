"""Pentest report generation for Blue-Tap.

Generates professional HTML or JSON reports from attack session data including
scan results, vulnerability findings, PBAP/MAP dumps, fuzzing campaigns, and
analysis notes.  All charts use inline SVG (no JS dependencies).
"""

import html as _html_mod
import json
import math
import os
import shutil
from datetime import datetime

from blue_tap.attack.cve_framework import summarize_findings
from blue_tap.report.adapters import REPORT_ADAPTERS
from blue_tap.report.renderers import render_sections
from blue_tap.utils.output import info, success, error

try:
    from blue_tap import __version__
except ImportError:
    __version__ = "unknown"


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


# ---------------------------------------------------------------------------
# Hex dump formatter
# ---------------------------------------------------------------------------

def _format_hexdump(data_hex: str, bytes_per_line: int = 16) -> str:
    """Format a hex string as a traditional hexdump with offset, hex, and ASCII."""
    try:
        raw = bytes.fromhex(data_hex)
    except (ValueError, TypeError):
        if not data_hex:
            return "(no data)"
        preview = data_hex[:60]
        return f"(invalid hex data: {preview}{'...' if len(data_hex) > 60 else ''})"

    lines = ["Offset  Hex                                              ASCII"]
    for offset in range(0, len(raw), bytes_per_line):
        chunk = raw[offset:offset + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}    {hex_part}  {ascii_part}")
    return "\n".join(lines)


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
        self.fuzz_results: list = []
        self.dos_results: list = []
        self.dos_runs: list[dict] = []
        self.notes: list[str] = []
        # Structured fuzz campaign data
        self._fuzz_campaign_stats: dict = {}
        self._fuzz_crashes: list[dict] = []
        self._fuzz_evidence_dir: str = ""
        self._fuzz_corpus_stats: dict = {}
        self._fuzz_evidence_files: list[tuple] = []
        # Session metadata for timeline/scope
        self._session_metadata: dict = {}
        # Fuzzing intelligence data (Phase 1-6)
        self._fuzz_state_coverage: dict = {}
        self._fuzz_field_weights: dict = {}
        self._fuzz_health_events: list[dict] = []
        self._fuzz_anomalies: list[dict] = []
        self._fuzz_baselines: dict = {}
        # LMP capture data (Phase 4 sniffer)
        self._lmp_captures: list[dict] = []
        self._module_report_state: dict[str, dict] = {
            "scan": {"scan_runs": [], "scan_results": [], "scan_executions": []},
            "vulnscan": {"vuln_scan_runs": [], "vuln_findings": [], "vuln_executions": []},
            "attack": {"attack_runs": [], "attack_executions": [], "attack_operations": []},
            "data": {"data_runs": [], "data_executions": [], "data_operations": []},
            "audio": {"audio_runs": [], "audio_executions": [], "audio_operations": []},
            "dos": {"dos_runs": [], "dos_results": [], "dos_executions": []},
            "fuzz": {"fuzz_runs": [], "campaigns": [], "protocol_runs": [], "operations": [], "crashes": []},
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

    def _data_operations(self, family: str | None = None) -> list[dict]:
        operations = list(self._module_report_state.get("data", {}).get("data_operations", []))
        if family is None:
            return operations
        return [operation for operation in operations if operation.get("family") == family]

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
        elif module == "attack":
            pass
        elif module == "data":
            pass
        elif module == "audio":
            pass
        elif module == "dos":
            self.dos_runs.append(envelope)
            self.dos_results.extend(envelope.get("module_data", {}).get("checks", []))
        elif module == "fuzz":
            self.fuzz_runs.append(envelope)
            module_data = envelope.get("module_data", {})
            run_type = module_data.get("run_type")
            if run_type == "campaign":
                campaign_stats = module_data.get("campaign_stats", {})
                if isinstance(campaign_stats, dict):
                    self._fuzz_campaign_stats = campaign_stats
                    self._fuzz_state_coverage = campaign_stats.get("state_coverage", {}) or {}
                    self._fuzz_field_weights = campaign_stats.get("field_weights", {}) or {}
                    self._fuzz_health_events = (campaign_stats.get("health_monitor", {}) or {}).get("events", []) or []
                crashes = module_data.get("crashes", [])
                if isinstance(crashes, list):
                    self._fuzz_crashes = crashes
                fuzz_dir = module_data.get("session_fuzz_dir")
                if isinstance(fuzz_dir, str) and fuzz_dir:
                    self._fuzz_evidence_dir = fuzz_dir
            elif run_type == "single_protocol_run":
                result = module_data.get("result", {})
                if isinstance(result, dict):
                    self.fuzz_results.append(
                        {
                            "command": module_data.get("command", ""),
                            "protocol": module_data.get("protocol", ""),
                            **result,
                        }
                    )
            else:
                self.fuzz_results.append(module_data or envelope)
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

    def add_fuzz_results(self, data: dict):
        if isinstance(data, dict) and self.add_run_envelope(data):
            return
        # TODO(standardization): Remove this legacy fuzz dict intake after
        # fuzz CLI commands log standardized run envelopes consistently.
        self.fuzz_results.append(data)

    def add_dos_results(self, data: dict):
        if isinstance(data, dict) and self.add_run_envelope(data):
            return
        # TODO(standardization): Remove this legacy DoS intake once demo/auto and
        # any remaining direct callers stop passing ad hoc DoS result dicts.
        self.dos_results.append(data)

    def add_note(self, note: str):
        self.notes.append(note)

    def add_lmp_captures(self, captures: list[dict]) -> None:
        """Add LMP capture data from DarkFirmwareSniffer BTIDES export.

        Args:
            captures: List of LMP capture dicts, each containing an ``LMPArray``
                      of packet entries with opcode, timestamp, direction, and
                      optional decoded parameters.
        """
        self._lmp_captures.extend(captures)

    def add_session_metadata(self, metadata: dict) -> None:
        """Store session metadata for timeline, scope, and methodology sections."""
        self._session_metadata = metadata

    def add_fuzz_campaign_results(self, campaign_stats: dict, crashes: list[dict],
                                   evidence_dir: str = "") -> None:
        """Add detailed fuzzing campaign results with evidence."""
        self._fuzz_campaign_stats = campaign_stats
        self._fuzz_crashes = crashes
        self._fuzz_evidence_dir = evidence_dir
        # Extract intelligence data from campaign stats if present
        if "state_coverage" in campaign_stats:
            self._fuzz_state_coverage = campaign_stats["state_coverage"]
        if "field_weights" in campaign_stats:
            self._fuzz_field_weights = campaign_stats["field_weights"]
        if "health_monitor" in campaign_stats:
            self._fuzz_health_events = campaign_stats["health_monitor"].get("events", [])

    # ------------------------------------------------------------------
    # Session / fuzz data loaders
    # ------------------------------------------------------------------

    def load_fuzz_from_session(self, session_dir: str) -> None:
        """Auto-load fuzzing data from a session's fuzz/ subdirectory."""
        # TODO(standardization): Keep this as artifact hydration for standardized
        # fuzz envelopes, not as the primary fuzz report model. Once campaign and
        # crash-management commands emit complete fuzz envelopes, this loader
        # should enrich those envelopes rather than acting as a parallel intake path.
        fuzz_dir = os.path.join(session_dir, "fuzz")
        if not os.path.isdir(fuzz_dir):
            return

        info(f"Loading fuzzing data from {fuzz_dir}")

        # Load campaign stats (prefer final stats over state)
        for stats_file in ("campaign_stats.json", "campaign_state.json"):
            stats_path = os.path.join(fuzz_dir, stats_file)
            if os.path.exists(stats_path):
                try:
                    with open(stats_path) as f:
                        self._fuzz_campaign_stats = json.load(f)
                    info(f"Loaded campaign stats from {stats_file}")
                    break
                except (json.JSONDecodeError, OSError) as exc:
                    info(f"Could not load {stats_file}: {exc}")

        # Load crashes from SQLite DB
        crashes_db_path = os.path.join(fuzz_dir, "crashes.db")
        if os.path.exists(crashes_db_path):
            try:
                from blue_tap.fuzz.crash_db import CrashDB
                with CrashDB(crashes_db_path) as db:
                    self._fuzz_crashes = db.get_crashes()
                info(f"Loaded {len(self._fuzz_crashes)} crashes from crashes.db")
            except ImportError:
                error("blue_tap.fuzz.crash_db not available")
            except (OSError, ValueError) as exc:
                warning(f"Could not load crashes.db: {exc}")

        # Also check per-protocol crash DBs
        for fname in os.listdir(fuzz_dir):
            if fname.endswith("_crashes.db") and fname != "crashes.db":
                proto_db_path = os.path.join(fuzz_dir, fname)
                try:
                    from blue_tap.fuzz.crash_db import CrashDB
                    with CrashDB(proto_db_path) as db:
                        proto_crashes = db.get_crashes()
                        existing_hashes = {c.get("payload_hash") for c in self._fuzz_crashes
                                           if c.get("payload_hash") is not None}
                        for crash in proto_crashes:
                            h = crash.get("payload_hash")
                            if h is None or h not in existing_hashes:
                                self._fuzz_crashes.append(crash)
                                if h is not None:
                                    existing_hashes.add(h)
                    info(f"Loaded additional crashes from {fname}")
                except (ImportError, OSError, ValueError) as exc:
                    info(f"Could not load {fname}: {exc}")

        # Count corpus seeds per protocol
        corpus_dir = os.path.join(fuzz_dir, "corpus")
        if os.path.isdir(corpus_dir):
            for entry in os.listdir(corpus_dir):
                proto_corpus = os.path.join(corpus_dir, entry)
                if os.path.isdir(proto_corpus):
                    count = len([f for f in os.listdir(proto_corpus)
                                 if os.path.isfile(os.path.join(proto_corpus, f))])
                    self._fuzz_corpus_stats[entry] = count
                elif os.path.isfile(proto_corpus):
                    self._fuzz_corpus_stats.setdefault("_root", 0)
                    self._fuzz_corpus_stats["_root"] += 1

        # Note evidence files
        self._fuzz_evidence_dir = fuzz_dir
        evidence_files = []
        capture_path = os.path.join(fuzz_dir, "capture.btsnoop")
        if os.path.exists(capture_path):
            evidence_files.append(("btsnoop capture", capture_path))

        evidence_subdir = os.path.join(fuzz_dir, "evidence")
        if os.path.isdir(evidence_subdir):
            for fname in sorted(os.listdir(evidence_subdir)):
                fpath = os.path.join(evidence_subdir, fname)
                if os.path.isfile(fpath):
                    evidence_files.append((fname, fpath))

        self._fuzz_evidence_files = evidence_files

        # Load fuzzing intelligence files (Phase 1-6)
        for fname, attr in [
            ("state_graph.json", "_fuzz_state_coverage"),
            ("field_weights.json", "_fuzz_field_weights"),
            ("baselines.json", "_fuzz_baselines"),
        ]:
            fpath = os.path.join(fuzz_dir, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath) as f:
                        setattr(self, attr, json.load(f))
                    info(f"Loaded {fname}")
                except (json.JSONDecodeError, OSError):
                    pass

        # Extract intelligence from campaign stats
        if self._fuzz_campaign_stats:
            if "state_coverage" in self._fuzz_campaign_stats:
                self._fuzz_state_coverage = self._fuzz_campaign_stats["state_coverage"]
            if "field_weights" in self._fuzz_campaign_stats:
                self._fuzz_field_weights = self._fuzz_campaign_stats["field_weights"]
            if "health_monitor" in self._fuzz_campaign_stats:
                hm = self._fuzz_campaign_stats["health_monitor"]
                if isinstance(hm, dict):
                    self._fuzz_health_events = hm.get("events", [])

    # ------------------------------------------------------------------
    # Evidence package
    # ------------------------------------------------------------------

    def generate_evidence_package(self, session_dir: str, output_dir: str) -> str:
        """Generate an evidence package directory with all fuzz artifacts."""
        os.makedirs(output_dir, exist_ok=True)
        crashes_dir = os.path.join(output_dir, "crashes")
        pcaps_dir = os.path.join(output_dir, "pcaps")
        corpus_dir = os.path.join(output_dir, "corpus")
        stats_dir = os.path.join(output_dir, "stats")
        for d in (crashes_dir, pcaps_dir, corpus_dir, stats_dir):
            os.makedirs(d, exist_ok=True)

        fuzz_dir = os.path.join(session_dir, "fuzz")
        manifest_crashes = []

        if not self._fuzz_crashes and not self._fuzz_campaign_stats:
            self.load_fuzz_from_session(session_dir)

        # Export crash payloads
        for i, crash in enumerate(self._fuzz_crashes, 1):
            protocol = crash.get("protocol", "unknown").replace("/", "-").replace(" ", "_")
            bin_name = f"crash_{i:03d}_{protocol}.bin"
            txt_name = f"crash_{i:03d}_{protocol}.txt"

            payload_hex = crash.get("payload_hex", "")
            if payload_hex:
                try:
                    with open(os.path.join(crashes_dir, bin_name), "wb") as f:
                        f.write(bytes.fromhex(payload_hex))
                except (ValueError, OSError) as exc:
                    error(f"Crash #{i}: could not write {bin_name}: {exc}")

            desc_lines = [
                f"Crash #{i}",
                f"Severity: {crash.get('severity', 'UNKNOWN')}",
                f"Protocol: {crash.get('protocol', 'unknown')}",
                f"Crash Type: {crash.get('crash_type', 'unknown')}",
                f"Timestamp: {crash.get('timestamp', 'N/A')}",
                f"Payload Size: {crash.get('payload_len', len(payload_hex) // 2)} bytes",
                f"Reproduced: {'Yes' if crash.get('reproduced') else 'No'}",
                f"Target: {crash.get('target_addr', 'N/A')}",
                "", "Mutation Log:",
                crash.get("mutation_log", "(none)") or "(none)",
                "", "Payload Hexdump:", _format_hexdump(payload_hex),
            ]
            response_hex = crash.get("response_hex", "")
            if response_hex:
                desc_lines.extend(["", "Response Hexdump:", _format_hexdump(response_hex)])
            notes = crash.get("notes", "")
            if notes:
                desc_lines.extend(["", "Notes:", notes])
            try:
                with open(os.path.join(crashes_dir, txt_name), "w") as f:
                    f.write("\n".join(desc_lines))
            except OSError:
                pass

            manifest_crashes.append({
                "id": i, "severity": crash.get("severity", "UNKNOWN"),
                "protocol": crash.get("protocol", "unknown"),
                "crash_type": crash.get("crash_type", "unknown"),
                "payload_file": f"crashes/{bin_name}",
                "description_file": f"crashes/{txt_name}",
                "reproduced": bool(crash.get("reproduced")),
                "timestamp": crash.get("timestamp", ""),
            })

        # Copy pcap files
        pcap_files = []
        capture_src = os.path.join(fuzz_dir, "capture.btsnoop")
        if os.path.exists(capture_src):
            dst = os.path.join(pcaps_dir, "campaign_capture.btsnoop")
            try:
                shutil.copy2(capture_src, dst)
                pcap_files.append("pcaps/campaign_capture.btsnoop")
            except OSError:
                pass

        evidence_subdir = os.path.join(fuzz_dir, "evidence")
        if os.path.isdir(evidence_subdir):
            for fname in sorted(os.listdir(evidence_subdir)):
                if fname.endswith(".btsnoop"):
                    try:
                        shutil.copy2(os.path.join(evidence_subdir, fname),
                                     os.path.join(pcaps_dir, fname))
                        pcap_files.append(f"pcaps/{fname}")
                    except OSError:
                        pass

        # Corpus stats
        corpus_stats = self._fuzz_corpus_stats or self._fuzz_campaign_stats.get("protocol_breakdown", {})
        try:
            with open(os.path.join(corpus_dir, "protocol_seed_counts.json"), "w") as f:
                json.dump(corpus_stats, f, indent=2)
        except OSError:
            pass

        if self._fuzz_campaign_stats:
            try:
                with open(os.path.join(stats_dir, "campaign_stats.json"), "w") as f:
                    json.dump(self._fuzz_campaign_stats, f, indent=2, default=str)
            except OSError:
                pass

        manifest = {
            "generated": datetime.now().isoformat(),
            "tool": f"Blue-Tap v{__version__}",
            "target": self._fuzz_campaign_stats.get("target", ""),
            "campaign": {
                "duration_seconds": self._fuzz_campaign_stats.get("runtime_seconds", 0),
                "test_cases": self._fuzz_campaign_stats.get("packets_sent", 0),
                "strategy": self._fuzz_campaign_stats.get("strategy", "unknown"),
                "protocols": self._fuzz_campaign_stats.get("protocols", []),
            },
            "crashes": manifest_crashes, "pcaps": pcap_files, "corpus_stats": corpus_stats,
        }

        manifest_path = os.path.join(output_dir, "evidence_manifest.json")
        try:
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2, default=str)
            success(f"Evidence package generated: {output_dir}")
        except OSError as exc:
            error(f"Could not write evidence manifest: {exc}")
        return manifest_path

    # ------------------------------------------------------------------
    # Load from directory (generic)
    # ------------------------------------------------------------------

    def load_from_directory(self, dump_dir: str):
        """Load standardized report data from a Blue-Tap directory."""
        if not os.path.isdir(dump_dir):
            error(f"Directory not found: {dump_dir}")
            return
        processed_json_paths: set[str] = set()

        fuzz_dir = os.path.join(dump_dir, "fuzz")
        if os.path.isdir(fuzz_dir):
            self.load_fuzz_from_session(dump_dir)

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
        meta = self._session_metadata
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
            (f"{len(self.dos_results)}", "DoS Tests"),
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
        adapter_state = self._module_report_state.get("attack", {})
        if adapter_state.get("runs") or adapter_state.get("attack_runs"):
            sections = _REPORT_ADAPTER_MAP["attack"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

    def _build_fuzz_html(self) -> list[str]:
        """Build the detailed fuzzing campaign HTML section.

        TODO(standardization): Move the ~270 lines of campaign narrative,
        severity breakdown, crash cards, and protocol coverage logic below
        into FuzzReportAdapter.build_sections().  The adapter already handles
        badge/table blocks; this method should delegate to it fully, matching
        the pattern used by _build_vuln_html / _build_dos_html / _build_scan_html.
        """
        sections: list[str] = []
        adapter_sections = _REPORT_ADAPTER_MAP["fuzz"].build_sections(self._module_report_state.get("fuzz", {}))
        has_campaign = bool(self._fuzz_campaign_stats)
        has_crashes = bool(self._fuzz_crashes)
        has_standardized_runs = bool(adapter_sections)

        if not has_campaign and not has_crashes and not self.fuzz_results and not has_standardized_runs:
            return sections

        if has_standardized_runs:
            sections.append(render_sections(adapter_sections))

        sections.append('<div class="section" id="sec-fuzzing">')
        sections.append("<h2>Fuzzing Campaign Results</h2>")

        # Campaign overview
        if has_campaign:
            stats = self._fuzz_campaign_stats
            runtime = stats.get("runtime_seconds", 0)
            packets = stats.get("packets_sent", 0)
            pps = stats.get("packets_per_second", 0)
            strategy = stats.get("strategy", "unknown")
            protocols = stats.get("protocols", [])
            total_crashes = stats.get("crashes", len(self._fuzz_crashes))
            result_status = stats.get("result", "unknown")

            hours = int(runtime // 3600)
            minutes = int((runtime % 3600) // 60)
            secs = int(runtime % 60)
            runtime_str = f"{hours}h {minutes}m {secs}s" if hours else f"{minutes}m {secs}s"

            sections.append('<h3>Campaign Overview</h3>')
            sections.append('<div class="summary">')
            for val, label in [
                (runtime_str, "Duration"), (f"{packets:,}", "Test Cases"),
                (f"{pps:.1f}/s", "Send Rate"), (str(total_crashes), "Crashes"),
            ]:
                sections.append(
                    f'<div class="fuzz-stat"><span class="value">{val}</span>'
                    f'<br><span class="label">{label}</span></div>'
                )
            sections.append("</div>")

            sections.append(f"<p><strong>Strategy:</strong> {_esc(strategy)}</p>")
            sections.append(
                f"<p><strong>Protocols Tested:</strong> "
                f"{_esc(', '.join(protocols) if protocols else 'N/A')}</p>"
            )
            sections.append(f"<p><strong>Campaign Result:</strong> {_esc(result_status)}</p>")

            # Narrative interpretation
            fuzz_narrative = (
                f'<p>Protocol fuzzing sent {packets:,} test cases across '
                f'{len(protocols)} protocol(s) over {runtime_str}. '
            )
            if total_crashes:
                critical_count = sum(
                    1 for c in self._fuzz_crashes
                    if c.get("severity", "").upper() == "CRITICAL")
                fuzz_narrative += (
                    f'{total_crashes} crash{"es" if total_crashes != 1 else ""} '
                    f'{"were" if total_crashes != 1 else "was"} detected'
                )
                if critical_count:
                    fuzz_narrative += (
                        f', including {critical_count} critical crash'
                        f'{"es" if critical_count != 1 else ""} that caused the '
                        f'target device to reboot — indicating exploitable memory '
                        f'corruption vulnerabilities in the Bluetooth stack.'
                    )
                else:
                    fuzz_narrative += (
                        ', indicating input handling weaknesses in the target\'s '
                        'Bluetooth stack implementation.'
                    )
            else:
                fuzz_narrative += (
                    'No crashes were detected during the fuzzing campaign, '
                    'suggesting the target\'s Bluetooth stack handles malformed '
                    'input gracefully for the tested protocols.'
                )
            fuzz_narrative += '</p>'
            sections.append(fuzz_narrative)

            # Severity breakdown with chart
            if has_crashes:
                sev_counts: dict[str, int] = {}
                reproduced_count = 0
                for crash in self._fuzz_crashes:
                    sev = crash.get("severity", "UNKNOWN")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    if crash.get("reproduced"):
                        reproduced_count += 1

                parts = []
                for sl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    c = sev_counts.get(sl, 0)
                    if c:
                        parts.append(f'<span class="severity-badge severity-{sl}">{c} {sl}</span>')
                if parts:
                    sections.append(f"<p><strong>Crash Breakdown:</strong> {' '.join(parts)}</p>")

                total = len(self._fuzz_crashes)
                repro_rate = (reproduced_count / total * 100) if total > 0 else 0
                sections.append(
                    f"<p><strong>Reproduction Rate:</strong> "
                    f"{reproduced_count}/{total} ({repro_rate:.0f}%)</p>"
                )

        # Crash findings table
        if has_crashes:
            sections.append("<h3>Crash Findings</h3>")
            sections.append(
                "<table><tr><th>#</th><th>Severity</th><th>Protocol</th>"
                "<th>Crash Type</th><th>Payload Size</th>"
                "<th>Payload Preview</th><th>Mutation</th>"
                "<th>Reproduced</th><th>Timestamp</th></tr>"
            )
            for i, crash in enumerate(self._fuzz_crashes, 1):
                sev = crash.get("severity", "UNKNOWN")
                protocol = crash.get("protocol", "unknown")
                crash_type = crash.get("crash_type", "unknown")
                payload_len = crash.get("payload_len", 0)
                payload_hex = crash.get("payload_hex", "")
                preview = payload_hex[:48] + ("..." if len(payload_hex) > 48 else "")
                mutation = crash.get("mutation_log", "") or ""
                if len(mutation) > 40:
                    mutation = mutation[:37] + "..."
                reproduced = crash.get("reproduced", 0)
                repro = ('<span class="reproduced-yes">Yes</span>' if reproduced
                         else '<span class="reproduced-no">No</span>')
                timestamp = crash.get("timestamp", "")

                sections.append(
                    f"<tr><td>{i}</td>"
                    f'<td><span class="severity-badge severity-{sev}">{_esc(sev)}</span></td>'
                    f"<td>{_esc(protocol)}</td><td>{_esc(crash_type)}</td>"
                    f"<td>{payload_len} bytes</td>"
                    f'<td class="mono">{_esc(preview)}</td>'
                    f"<td>{_esc(mutation)}</td><td>{repro}</td>"
                    f"<td>{_esc(timestamp)}</td></tr>"
                )
            sections.append("</table>")

            # Crash detail cards (CRITICAL and HIGH)
            critical_high = [
                (i, c) for i, c in enumerate(self._fuzz_crashes, 1)
                if c.get("severity", "").upper() in ("CRITICAL", "HIGH")
            ]
            if critical_high:
                sections.append("<h3>Crash Details (Critical/High)</h3>")
                for idx, crash in critical_high:
                    sev = crash.get("severity", "UNKNOWN").upper()
                    protocol = crash.get("protocol", "unknown")
                    crash_type = crash.get("crash_type", "unknown")
                    timestamp = crash.get("timestamp", "N/A")
                    payload_hex = crash.get("payload_hex", "")
                    payload_len = crash.get("payload_len", len(payload_hex) // 2)
                    mutation = crash.get("mutation_log", "") or "(none)"
                    response_hex = crash.get("response_hex", "")
                    reproduced = crash.get("reproduced", 0)
                    target_addr = crash.get("target_addr", "N/A")

                    card_css = "crash-card" + (" high" if sev == "HIGH" else "")

                    repro_str = ('<span class="reproduced-yes">Yes</span>' if reproduced
                                 else '<span class="reproduced-no">No</span>')

                    sections.append(f'<div class="{card_css}">')
                    sections.append(
                        f'<h4>Crash #{idx} '
                        f'<span class="severity-badge severity-{sev}">{_esc(sev)}</span> '
                        f'{_esc(protocol)} / {_esc(crash_type)}</h4>'
                    )
                    sections.append(f'<p><strong>Timestamp:</strong> {_esc(timestamp)} '
                                    f'| <strong>Target:</strong> <code>{_esc(target_addr)}</code> '
                                    f'| <strong>Reproduced:</strong> {repro_str}</p>')

                    # Reproduction steps
                    sections.append('<div class="evidence-block">'
                                    '<div class="ev-label">Reproduction Steps</div>'
                                    '<pre>'
                                    f'1. Connect to target: {_esc(target_addr)}\n'
                                    f'2. Select protocol: {_esc(protocol)}\n'
                                    f'3. Send payload ({payload_len} bytes):\n'
                                    f'   blue-tap fuzz replay --payload-hex {_esc(payload_hex[:80])}'
                                    f'{"..." if len(payload_hex) > 80 else ""}\n'
                                    f'4. Observe: {_esc(crash_type)}'
                                    '</pre></div>')

                    sections.append(f'<h5>Payload ({payload_len} bytes)</h5>')
                    sections.append(f'<pre class="hexdump">{_esc(_format_hexdump(payload_hex))}</pre>')

                    sections.append("<h5>Mutation Log</h5>")
                    sections.append(f"<pre>{_esc(mutation)}</pre>")

                    sections.append("<h5>Device Response</h5>")
                    if response_hex:
                        sections.append(f'<pre class="hexdump">{_esc(_format_hexdump(response_hex))}</pre>')
                    else:
                        sections.append("<pre>No response (connection dropped immediately)</pre>")

                    # Evidence file references
                    if self._fuzz_evidence_dir:
                        proto_safe = protocol.replace("/", "-").replace(" ", "_")
                        sections.append('<div class="evidence-block">'
                                        '<div class="ev-label">Evidence Files</div>'
                                        f'<p>Crash payload: <code>crashes/crash_{idx:03d}_{_esc(proto_safe)}.bin</code></p>')
                        capture_path = os.path.join(self._fuzz_evidence_dir, "capture.btsnoop")
                        if os.path.exists(capture_path):
                            sections.append(f'<p>Pcap capture: <code>fuzz/capture.btsnoop</code> '
                                            f'(frame at {_esc(timestamp)})</p>')
                        sections.append('</div>')

                    notes = crash.get("notes", "")
                    if notes:
                        sections.append(f"<p><strong>Notes:</strong> {_esc(notes)}</p>")

                    sections.append("</div>")

        # Protocol coverage table
        if has_campaign and has_crashes:
            breakdown = self._fuzz_campaign_stats.get("protocol_breakdown", {})
            if breakdown:
                crash_by_proto: dict[str, int] = {}
                for crash in self._fuzz_crashes:
                    p = crash.get("protocol", "unknown")
                    crash_by_proto[p] = crash_by_proto.get(p, 0) + 1

                sections.append("<h3>Protocol Coverage</h3>")
                sections.append(
                    "<table><tr><th>Protocol</th><th>Test Cases Sent</th>"
                    "<th>Crashes</th><th>Crash Rate</th></tr>"
                )
                for proto, sent in sorted(breakdown.items()):
                    crashes_for = crash_by_proto.get(proto, 0)
                    rate = (crashes_for / sent * 100) if sent > 0 else 0
                    sections.append(
                        f"<tr><td>{_esc(proto)}</td><td>{sent:,}</td>"
                        f"<td>{crashes_for}</td><td>{rate:.2f}%</td></tr>"
                    )
                sections.append("</table>")

        # Evidence package
        if self._fuzz_evidence_files:
            sections.append("<h3>Evidence Package</h3>")
            sections.append('<ul class="evidence-list">')
            for desc, path in self._fuzz_evidence_files:
                rel = os.path.relpath(path, self._fuzz_evidence_dir) if self._fuzz_evidence_dir else desc
                sections.append(f"<li>{_esc(desc)} -- <code>{_esc(rel)}</code></li>")
            sections.append("</ul>")

        if self._fuzz_corpus_stats:
            sections.append("<h4>Corpus Statistics</h4>")
            sections.append("<table><tr><th>Protocol</th><th>Seeds</th></tr>")
            for proto, count in sorted(self._fuzz_corpus_stats.items()):
                sections.append(f"<tr><td>{_esc(proto)}</td><td>{count}</td></tr>")
            sections.append("</table>")

        # Fallback: raw fuzz_results
        if self.fuzz_results and not has_campaign and not has_crashes:
            for entry in self.fuzz_results:
                src = entry.get("source", "fuzz")
                sections.append(f"<h3>{_esc(src)}</h3>")
                sections.append(f"<pre>{_esc(json.dumps(entry.get('data', entry), indent=2, default=str)[:2000])}</pre>")

        sections.append("</div>")
        return sections

    def _build_fuzz_intelligence_html(self) -> str:
        """Build the fuzzing intelligence section (state coverage, field weights, health).

        TODO(standardization): Move this intelligence rendering into
        FuzzReportAdapter or a dedicated FuzzIntelligenceAdapter.
        """
        has_data = any([self._fuzz_state_coverage, self._fuzz_field_weights,
                        self._fuzz_health_events, self._fuzz_baselines])
        if not has_data:
            return ""

        s = []
        s.append('<div class="section" id="sec-fuzz-intel">')
        s.append('<h2>Fuzzing Intelligence Analysis</h2>')
        s.append('<p>Behavioral analysis data collected during the fuzzing campaign.</p>')

        # State coverage
        if self._fuzz_state_coverage:
            sc = self._fuzz_state_coverage
            s.append('<h3>Protocol State Coverage</h3>')
            total_states = sc.get("total_states", 0)
            total_trans = sc.get("total_transitions", 0)
            protos_tracked = sc.get("protocols_tracked") or sc.get("protocols", {})
            num_protos = len(protos_tracked) if isinstance(protos_tracked, (dict, list)) else 0
            s.append(f'<p>The fuzzer explored {total_states} unique protocol state(s) '
                     f'across {total_trans} transition(s)'
                     f'{" in " + str(num_protos) + " protocol(s)" if num_protos else ""}. '
                     f'Higher coverage indicates more thorough testing of the target\'s '
                     f'protocol implementation.</p>')
            s.append(f'<p>Total states discovered: <strong>{sc.get("total_states", 0)}</strong> | '
                     f'Total transitions: <strong>{sc.get("total_transitions", 0)}</strong></p>')
            protos = sc.get("protocols_tracked") or sc.get("protocols", {})
            if isinstance(protos, dict):
                s.append('<table><tr><th>Protocol</th><th>States</th><th>Transitions</th></tr>')
                for proto, pdata in sorted(protos.items()) if isinstance(protos, dict) else []:
                    states = pdata.get("states", 0) if isinstance(pdata, dict) else 0
                    trans = pdata.get("transitions", 0) if isinstance(pdata, dict) else 0
                    s.append(f'<tr><td>{_esc(proto)}</td><td>{states}</td><td>{trans}</td></tr>')
                s.append('</table>')
            elif isinstance(protos, list):
                s.append(f'<p>Protocols tracked: {_esc(", ".join(protos))}</p>')

        # Field mutation weights
        if self._fuzz_field_weights:
            s.append('<h3>Field Mutation Weight Analysis</h3>')
            s.append('<p>The fuzzer learned which protocol fields are most likely to '
                     'trigger anomalies. Fields with high mutation weights produced more '
                     'interesting target behavior when mutated.</p>')
            s.append('<p>Fields ranked by anomaly/crash production. Higher weight = '
                     'more productive for finding bugs.</p>')
            for proto, weights in sorted(self._fuzz_field_weights.items()):
                if not isinstance(weights, dict) or not weights:
                    continue
                s.append(f'<h4>{_esc(proto)}</h4>')
                s.append('<table><tr><th>Field</th><th>Weight</th><th>Bar</th></tr>')
                sorted_fields = sorted(weights.items(), key=lambda x: x[1], reverse=True)
                for fname, w in sorted_fields:
                    bar_width = int(w * 200)
                    bar_color = "#D43F3A" if w > 0.3 else "#EE9336" if w > 0.15 else "#4CAE4C"
                    s.append(
                        f'<tr><td><code>{_esc(fname)}</code></td>'
                        f'<td>{w:.1%}</td>'
                        f'<td><div style="background:{bar_color};width:{bar_width}px;'
                        f'height:14px;border-radius:3px;display:inline-block"></div></td></tr>'
                    )
                s.append('</table>')

        # Baseline profiles
        if self._fuzz_baselines:
            s.append('<h3>Target Response Baselines</h3>')
            s.append('<p>Normal response behavior learned before fuzzing began.</p>')
            s.append('<table><tr><th>Protocol</th><th>Samples</th><th>Avg Size</th>'
                     '<th>Avg Latency</th><th>Response Opcodes</th></tr>')
            for proto, bl in sorted(self._fuzz_baselines.items()):
                if not isinstance(bl, dict):
                    continue
                s.append(
                    f'<tr><td>{_esc(proto)}</td>'
                    f'<td>{bl.get("samples", 0)}</td>'
                    f'<td>{bl.get("mean_len", 0):.0f}B</td>'
                    f'<td>{bl.get("mean_latency_ms", 0):.0f}ms</td>'
                    f'<td>{_esc(str(bl.get("seen_opcodes", [])))}</td></tr>'
                )
            s.append('</table>')

        # Health events (reboots, degradation)
        if self._fuzz_health_events:
            num_events = len(self._fuzz_health_events)
            reboot_events = sum(
                1 for e in self._fuzz_health_events
                if isinstance(e, dict) and e.get("status", "") in ("rebooted", "unreachable"))
            s.append('<h3>Target Health Events</h3>')
            s.append(f'<p>Target health monitoring detected {num_events} event(s) during '
                     f'the campaign.'
                     f'{" Reboot events are the highest-confidence indicator of exploitable crashes." if reboot_events else ""}'
                     f'{" " + str(reboot_events) + " reboot/unreachable event(s) were observed." if reboot_events else ""}'
                     f'</p>')
            s.append('<table><tr><th>Time</th><th>Status</th><th>Details</th>'
                     '<th>Iteration</th></tr>')
            for evt in self._fuzz_health_events:
                if not isinstance(evt, dict):
                    continue
                status = evt.get("status", "unknown")
                status_color = "#D43F3A" if status in ("rebooted", "zombie", "unreachable") else (
                    "#EE9336" if status == "degraded" else "#4CAE4C")
                s.append(
                    f'<tr><td>{_esc(str(evt.get("timestamp", "")))}</td>'
                    f'<td style="color:{status_color};font-weight:bold">'
                    f'{_esc(status.upper())}</td>'
                    f'<td>{_esc(evt.get("details", ""))}</td>'
                    f'<td>{evt.get("iteration", "")}</td></tr>'
                )
            s.append('</table>')

        s.append('</div>')
        return "\n".join(s)

    def _build_lmp_html(self) -> str:
        """Render LMP capture findings as HTML section.

        TODO(standardization): Move this into a dedicated LmpCaptureAdapter
        or integrate into the ReconReportAdapter, matching the adapter-based
        rendering pattern used by other modules.

        Produces a table of captured LMP packets color-coded by category
        (auth=red, encryption=orange, features=blue), a feature bitmap
        visualization, and an encryption negotiation summary.
        """
        if not self._lmp_captures:
            return ""

        from datetime import datetime as _dt

        s = []
        s.append('<div class="section" id="sec-lmp">')
        s.append('<h2>LMP Capture Analysis</h2>')
        s.append('<p>Link Manager Protocol packets captured via DarkFirmware '
                 'RTL8761B reveal the below-HCI negotiation between link '
                 'managers, including authentication, encryption setup, and '
                 'feature exchange.</p>')

        # Category colour map
        _auth = {8, 9, 10, 11, 12, 13, 14, 59, 60, 61}
        _enc = {15, 16, 17, 18}
        _feat = {37, 38, 39, 40}

        features_hex = None
        key_sizes: list[int] = []

        for capture in self._lmp_captures:
            bdaddr = capture.get("bdaddr", "unknown")
            lmp_array = capture.get("LMPArray", [])
            if not lmp_array:
                continue

            s.append(f'<h3>Capture: {_esc(bdaddr)}</h3>')
            s.append('<table><tr><th>Timestamp</th><th>Direction</th>'
                     '<th>Opcode</th><th>Decoded</th></tr>')

            for pkt in lmp_array:
                opcode = pkt.get("opcode", 0)
                ts_val = pkt.get("timestamp", 0)
                try:
                    ts_str = _dt.fromtimestamp(ts_val).strftime("%H:%M:%S.%f")[:-3] if ts_val else ""
                except (OSError, ValueError):
                    ts_str = str(ts_val)

                direction = _esc(pkt.get("direction", "rx"))
                decoded = pkt.get("decoded", {})
                opcode_name = _esc(decoded.get("opcode_name", f"0x{opcode:04x}"))

                # Build decoded params string
                params = []
                for k, v in decoded.items():
                    if k == "opcode_name":
                        continue
                    params.append(f"{k}={_esc(str(v))}")
                params_str = ", ".join(params) if params else ""

                # Colour by category
                if opcode in _auth:
                    color = "#dc2626"  # red
                elif opcode in _enc:
                    color = "#ea580c"  # orange
                elif opcode in _feat:
                    color = "#2563eb"  # blue
                else:
                    color = "#6b7280"  # grey

                s.append(
                    f'<tr style="color:{color}">'
                    f'<td>{_esc(ts_str)}</td>'
                    f'<td>{direction}</td>'
                    f'<td class="mono">{opcode_name}</td>'
                    f'<td>{params_str}</td></tr>'
                )

                # Track for summaries
                if decoded.get("features_hex"):
                    features_hex = decoded["features_hex"]
                if decoded.get("key_size"):
                    key_sizes.append(decoded["key_size"])

            s.append('</table>')

        # Feature bitmap visualization
        if features_hex:
            s.append('<h3>Feature Bitmap</h3>')
            s.append('<p>8-byte LMP features bitmap from '
                     'LMP_FEATURES_RES:</p>')
            try:
                feat_bytes = bytes.fromhex(features_hex)
                s.append('<table class="feature-grid"><tr>')
                _feature_names = [
                    "3-slot", "5-slot", "Encryption", "SlotOffset",
                    "TimingAccuracy", "RoleSwitch", "HoldMode", "SniffMode",
                    "ParkState", "PowerCtrlReq", "CQDDR", "SCOLink",
                    "HV2", "HV3", "uLaw", "aLaw",
                ]
                for byte_idx, b in enumerate(feat_bytes):
                    for bit in range(8):
                        bit_num = byte_idx * 8 + bit
                        is_set = bool(b & (1 << bit))
                        bg = "#22c55e" if is_set else "#374151"
                        name = _feature_names[bit_num] if bit_num < len(_feature_names) else f"bit{bit_num}"
                        s.append(
                            f'<td style="background:{bg};color:white;'
                            f'padding:2px 4px;font-size:10px;" '
                            f'title="Bit {bit_num}: {_esc(name)}">'
                            f'{"1" if is_set else "0"}</td>'
                        )
                    if byte_idx % 2 == 1:
                        s.append('</tr><tr>')
                s.append('</tr></table>')
            except (ValueError, IndexError):
                s.append(f'<pre>{_esc(features_hex)}</pre>')

        # Encryption negotiation summary
        if key_sizes:
            min_ks = min(key_sizes)
            max_ks = max(key_sizes)
            s.append('<h3>Encryption Negotiation Summary</h3>')
            s.append(f'<p>Key size requests observed: min={min_ks}, '
                     f'max={max_ks}, count={len(key_sizes)}</p>')
            if min_ks < 7:
                s.append(
                    '<p style="color:#dc2626;font-weight:bold">'
                    'WARNING: Key size below 7 bytes detected '
                    '(potential KNOB attack surface - CVE-2019-9506)</p>'
                )

        s.append('</div>')
        return "\n".join(s)

    def _build_recon_html(self) -> str:
        adapter_state = self._module_report_state.get("recon", {})
        if adapter_state.get("recon_runs"):
            sections = _REPORT_ADAPTER_MAP["recon"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

    def _build_dos_html(self) -> str:
        adapter_state = self._module_report_state.get("dos", {})
        if adapter_state.get("dos_runs"):
            sections = _REPORT_ADAPTER_MAP["dos"].build_sections(adapter_state)
            return render_sections(sections)
        # TODO(standardization): Delete the legacy DoS HTML branch below once all
        # DoS report producers emit standardized envelopes only.
        if not self.dos_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-dos">')
        s.append('<h2>Denial of Service Test Results</h2>')
        s.append('<p>Denial of Service tests evaluate the target\'s resilience to '
                 'protocol-level resource exhaustion and state machine confusion attacks. '
                 'The following tests were conducted across multiple Bluetooth protocol '
                 'layers.</p>')

        if self.dos_runs:
            latest = self.dos_runs[-1]
            summary = latest.get("summary", {})
            s.append('<p><strong>Structured DoS Run Summary:</strong> '
                     f'total={_esc(str(summary.get("total", 0)))}, '
                     f'success={_esc(str(summary.get("success", 0)))}, '
                     f'recovered={_esc(str(summary.get("recovered", 0)))}, '
                     f'unresponsive={_esc(str(summary.get("unresponsive", 0)))}, '
                     f'error={_esc(str(summary.get("error", 0)))}</p>')
            run_meta = []
            if latest.get("selected_checks"):
                run_meta.append(f"selected={', '.join(str(x) for x in latest.get('selected_checks', []))}")
            if latest.get("recovery_timeout") is not None:
                run_meta.append(f"recovery_timeout={latest.get('recovery_timeout')}s")
            if latest.get("interrupted_on"):
                run_meta.append(f"interrupted_on={latest.get('interrupted_on')}")
            if latest.get("abort_reason"):
                run_meta.append(f"abort_reason={latest.get('abort_reason')}")
            if run_meta:
                s.append(f"<p><strong>Run Metadata:</strong> {_esc(' | '.join(run_meta))}</p>")
            checks = latest.get("checks", [])
            if checks:
                s.append('<h3>DoS Check Execution</h3>')
                s.append('<table><tr><th>Check ID</th><th>Check</th><th>CVE</th><th>Protocol</th><th>Pairing</th><th>Status</th><th>Recovery</th><th>Evidence</th></tr>')
                for check in checks:
                    recovery = check.get("recovery", {})
                    recovery_text = ""
                    if recovery:
                        recovery_text = (
                            f"recovered={recovery.get('recovered')} "
                            f"waited={recovery.get('waited_seconds', 0)}s"
                        )
                        if recovery.get("probe_strategy"):
                            recovery_text += f" via {','.join(str(x) for x in recovery.get('probe_strategy', []))}"
                    s.append(
                        f'<tr><td>{_esc(check.get("check_id", ""))}</td>'
                        f'<td>{_esc(check.get("title", ""))}</td>'
                        f'<td>{_esc(", ".join(str(x) for x in check.get("cves", [])))}</td>'
                        f'<td>{_esc(check.get("protocol", ""))}</td>'
                        f'<td>{_esc("yes" if check.get("requires_pairing") else "no")}</td>'
                        f'<td class="status-{_esc(check.get("status", "unknown"))}">{_esc(check.get("status", "unknown"))}</td>'
                        f'<td>{_esc(recovery_text)}</td>'
                        f'<td>{_esc(check.get("evidence", ""))}</td></tr>'
                    )
                s.append('</table>')

        # Group results by protocol layer
        layer_keywords = {
            "L2CAP": ["l2cap", "l2ping", "cid_exhaust", "connection_storm", "data_flood", "echo"],
            "SDP": ["sdp", "continuation", "des_bomb", "service_search"],
            "RFCOMM": ["rfcomm", "sabm", "mux_command", "credit_exhaust", "dlci"],
            "OBEX": ["obex", "setpath", "connect_flood"],
            "HFP": ["hfp", "at_command", "slc_", "handsfree", "hands-free"],
            "AVDTP": ["avdtp", "a2dp", "setconf"],
            "AVRCP": ["avrcp", "avctp", "register_notification"],
            "BLE": ["ble", "att", "smp", "eatt", "sweyntooth"],
            "Raw ACL": ["raw_acl", "bluefrag"],
            "Pairing": ["pair", "ssp", "pin", "auth", "name_flood", "rate_test"],
        }
        grouped: dict[str, list[dict]] = {}
        for entry in self.dos_results:
            data = entry.get("data", entry) if isinstance(entry, dict) else entry
            if not isinstance(data, dict):
                grouped.setdefault("Other", []).append(data)
                continue
            if "check_id" in data and "raw_result" in data:
                raw = data.get("raw_result", {})
                test_name = " ".join(
                    str(part) for part in (
                        data.get("protocol", ""),
                        data.get("check_id", ""),
                        data.get("title", ""),
                        raw.get("attack", ""),
                        raw.get("attack_name", ""),
                    ) if part
                ).lower()
            else:
                test_name = str(data.get("attack", data.get("test", data.get("command",
                               data.get("attack_name",
                               entry.get("source", "") if isinstance(entry, dict) else ""))))).lower()
            placed = False
            for layer, keywords in layer_keywords.items():
                if any(kw in test_name for kw in keywords):
                    grouped.setdefault(layer, []).append(data)
                    placed = True
                    break
            if not placed:
                grouped.setdefault("Other", []).append(data)

        total_tests = len(self.dos_results)
        unresponsive_count = 0

        for layer, tests in grouped.items():
            s.append(f'<h3>{_esc(layer)} Layer Tests</h3>')
            s.append('<table><tr><th>Test</th><th>Target</th><th>Duration</th>'
                     '<th>Packets Sent</th><th>Result</th><th>Impact</th></tr>')
            for data in tests:
                if not isinstance(data, dict):
                    s.append(f'<tr><td colspan="6"><pre>'
                             f'{_esc(json.dumps(data, indent=2, default=str)[:500])}'
                             f'</pre></td></tr>')
                    continue
                if "check_id" in data and "raw_result" in data:
                    raw = data.get("raw_result", {})
                    result_str = str(data.get("status", "unknown"))
                    impact_str = str(raw.get("notes", raw.get("error", data.get("evidence", ""))))
                    packets_sent = raw.get("packets_sent", raw.get("packets", "N/A"))
                    duration = raw.get("duration", raw.get("duration_seconds", "N/A"))
                    test_name = data.get("title", data.get("check_id", "dos"))
                else:
                    result_str = str(data.get("result", data.get("status", "unknown")))
                    impact_str = str(data.get("impact", data.get("effect", "")))
                    packets_sent = data.get("packets_sent", data.get("packets", "N/A"))
                    duration = data.get("duration", data.get("duration_seconds", "N/A"))
                    test_name = str(data.get("attack", data.get("test", data.get("command", data.get("attack_name", "dos")))))
                is_unresponsive = any(
                    kw in (result_str + impact_str).lower()
                    for kw in ("unresponsive", "crash", "timeout", "reboot",
                               "disconnected", "frozen", "hung"))
                if is_unresponsive:
                    unresponsive_count += 1
                s.append(
                    f'<tr><td>{_esc(test_name)}</td>'
                    f'<td class="mono">{_esc(str(data.get("target", raw.get("target", "")) if "check_id" in data and "raw_result" in data else data.get("target", "")))}</td>'
                    f'<td>{_esc(str(duration))}</td>'
                    f'<td>{_esc(str(packets_sent))}</td>'
                    f'<td>{_esc(result_str)}</td>'
                    f'<td>{_esc(impact_str)}</td></tr>'
                )
                if is_unresponsive:
                    s.append(f'<tr><td colspan="6" style="color:#D43F3A;font-style:italic">'
                             f'Impact: Target became unresponsive following this test, '
                             f'indicating insufficient resource management for {_esc(layer)} '
                             f'protocol operations.</td></tr>')
            s.append('</table>')

        # Summary
        s.append(f'<p><strong>Summary:</strong> Of {total_tests} DoS test(s) conducted, '
                 f'{unresponsive_count} caused the target to become unresponsive, '
                 f'{"indicating insufficient rate limiting and resource management in " if unresponsive_count else "suggesting adequate resilience in "}'
                 f'the Bluetooth stack.</p>')

        s.append('</div>')
        return "\n".join(s)

    def _build_pbap_html(self) -> str:
        return ""

    def _build_map_html(self) -> str:
        return ""

    def _build_data_ops_html(self) -> str:
        adapter_state = self._module_report_state.get("data", {})
        if not (adapter_state.get("runs") or adapter_state.get("data_runs")):
            return ""
        return render_sections(_REPORT_ADAPTER_MAP["data"].build_sections(adapter_state))

    def _build_audio_html(self) -> str:
        adapter_state = self._module_report_state.get("audio", {})
        if adapter_state.get("runs") or adapter_state.get("audio_runs"):
            sections = _REPORT_ADAPTER_MAP["audio"].build_sections(adapter_state)
            return render_sections(sections)
        return ""

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
        if self._module_report_state.get("fuzz", {}).get("fuzz_runs"):
            toc_entries.append(("sec-fuzz-runs", "Ad Hoc Fuzz Command Runs"))
        if self._fuzz_campaign_stats or self._fuzz_crashes or self.fuzz_results:
            toc_entries.append(("sec-fuzzing", "Fuzzing Campaign Results"))
        has_fuzz_intel = any([self._fuzz_state_coverage, self._fuzz_field_weights,
                             self._fuzz_health_events, self._fuzz_baselines])
        if has_fuzz_intel:
            toc_entries.append(("sec-fuzz-intel", "Fuzzing Intelligence Analysis"))
        if self._lmp_captures:
            toc_entries.append(("sec-lmp", "LMP Capture Analysis"))
        if self.recon_results or self._module_report_state.get("recon", {}).get("recon_runs"):
            toc_entries.append(("sec-recon", "Reconnaissance Results"))
        if self.dos_results:
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
        ]
        body_parts.extend(self._build_fuzz_html())
        body_parts.append(self._build_fuzz_intelligence_html())
        body_parts.append(self._build_lmp_html())
        body_parts.extend([
            self._build_recon_html(),
            self._build_dos_html(),
            self._build_data_ops_html(),
            self._build_pbap_html(),
            self._build_map_html(),
            self._build_audio_html(),
            self._build_appendix_html(),
            '</div>'  # close .report-body
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
        for cmd in self._session_metadata.get("commands", []):
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
                "data": self._module_json_section("data"),
                "audio": self._module_json_section("audio"),
                "dos": self._module_json_section("dos"),
                "fuzz": self._module_json_section("fuzz"),
                "recon": self._module_json_section("recon"),
            },
            "executions": self._all_module_executions(),
            "scan_results": self.scan_results,
            "scan_runs": self.scan_runs,
            "vulnerabilities": self.vuln_findings,
            "vulnerability_scans": self.vuln_scan_runs,
            "recon_results": self.recon_results,
            "fuzzing": fuzz_data if fuzz_data else self.fuzz_results,
            "fuzz_runs": self.fuzz_runs,
            "dos_runs": self.dos_runs,
            "fuzzing_intelligence": {
                "state_coverage": self._fuzz_state_coverage,
                "field_weights": self._fuzz_field_weights,
                "baselines": self._fuzz_baselines,
                "health_events": self._fuzz_health_events,
            } if any([self._fuzz_state_coverage, self._fuzz_field_weights,
                      self._fuzz_health_events, self._fuzz_baselines]) else {},
            "dos_results": self.dos_results,
            "notes": self.notes,
        }

        outdir = os.path.dirname(output)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"JSON report generated: {output}")
        return output
