"""Pentest report generation for Blue-Tap.

Generates professional HTML or JSON reports from attack session data including
scan results, vulnerability findings, PBAP/MAP dumps, fuzzing campaigns, and
analysis notes.  All charts use inline SVG (no JS dependencies).
"""

import hashlib
import html as _html_mod
import json
import math
import os
import shutil
from datetime import datetime

from blue_tap.utils.output import info, success, error

try:
    from blue_tap import __version__
except ImportError:
    __version__ = "unknown"


# ---------------------------------------------------------------------------
# SVG chart helpers (pure SVG, no JS)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffaa00",
    "LOW": "#88cc00",
    "INFO": "#4488ff",
    "UNKNOWN": "#666",
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
        f'fill="#e0e0e0" font-size="22" font-weight="bold">{total}</text>'
    )
    segments.append(
        f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" '
        f'fill="#888" font-size="11">TOTAL</text>'
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
            f'<text x="{lx + 14}" y="{legend_y + 9}" fill="#ccc" '
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


def _svg_bar_chart(data: dict[str, int], color: str = "#00d4ff",
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
            f'text-anchor="end" fill="#ccc" font-size="11">{_esc(label)}</text>'
        )
        bars.append(
            f'<rect x="{label_width}" y="{y}" width="{bw:.1f}" '
            f'height="{bar_height}" rx="3" fill="{color}" opacity="0.85"/>'
        )
        bars.append(
            f'<text x="{label_width + bw + 6}" y="{y + bar_height * 0.7}" '
            f'fill="#e0e0e0" font-size="11" font-weight="bold">{val}</text>'
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


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 960px; margin: 0 auto; padding: 24px; background: #0f0f1a; color: #d8d8e8; line-height: 1.6; }
h1 { color: #00d4ff; font-size: 1.8em; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; margin-top: 0; }
h2 { color: #ff6b6b; margin-top: 36px; font-size: 1.35em; border-bottom: 1px solid #333; padding-bottom: 6px; }
h3 { color: #ffd93d; font-size: 1.1em; }
h4 { color: #ccc; font-size: 1em; margin-top: 14px; }
h5 { color: #aaa; font-size: 0.95em; margin-bottom: 4px; }
a { color: #00d4ff; text-decoration: none; }
a:hover { text-decoration: underline; }
p { margin: 6px 0; }
pre { background: #16213e; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; line-height: 1.5; }
code { background: #16213e; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 0.9em; }
th, td { border: 1px solid #2a2a40; padding: 8px 10px; text-align: left; }
th { background: #16213e; color: #00d4ff; font-weight: 600; }
tr:nth-child(even) { background: #12122a; }
tr:hover { background: #1a1a3a; }
.header { text-align: center; margin-bottom: 30px; }
.header .version { color: #888; font-size: 0.85em; }
.header .classification { color: #ff6b6b; font-weight: bold; font-size: 0.85em;
    border: 1px solid #ff6b6b; padding: 3px 12px; display: inline-block; margin-top: 8px; border-radius: 4px; }
.meta { color: #888; font-size: 0.85em; margin: 4px 0; }
.section { margin: 24px 0; padding: 18px; border: 1px solid #2a2a40; border-radius: 10px; background: #111122; }
.summary { background: #16213e; padding: 18px; border-radius: 10px; margin: 20px 0; }
.toc { background: #111122; border: 1px solid #2a2a40; padding: 16px 24px; border-radius: 10px; margin: 20px 0; }
.toc ol { padding-left: 20px; }
.toc li { margin: 4px 0; }
.toc a { color: #00d4ff; }
.risk-badge { display: inline-block; padding: 8px 24px; border-radius: 6px; font-size: 1.3em;
    font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }
.risk-CRITICAL { background: #ff4444; color: #fff; }
.risk-HIGH { background: #ff6b35; color: #fff; }
.risk-MEDIUM { background: #ffaa00; color: #000; }
.risk-LOW { background: #88cc00; color: #000; }
.risk-INFO { background: #4488ff; color: #fff; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 14px; margin: 16px 0; }
.metric-card { background: #111122; border: 1px solid #2a2a40; border-radius: 8px; padding: 14px; text-align: center; }
.metric-card .value { font-size: 1.8em; font-weight: bold; color: #00d4ff; }
.metric-card .label { font-size: 0.8em; color: #888; margin-top: 4px; }
.chart-row { display: flex; gap: 24px; flex-wrap: wrap; align-items: flex-start; margin: 16px 0; }
.finding-card { border-left: 4px solid #2a2a40; padding: 14px; margin: 14px 0; background: #111128; border-radius: 0 8px 8px 0; }
.finding-card.sev-CRITICAL { border-left-color: #ff4444; }
.finding-card.sev-HIGH { border-left-color: #ff6b35; }
.finding-card.sev-MEDIUM { border-left-color: #ffaa00; }
.finding-card.sev-LOW { border-left-color: #88cc00; }
.finding-card.sev-INFO { border-left-color: #4488ff; }
.evidence-block { background: #0d0d1a; border: 1px solid #333; border-radius: 6px; padding: 10px 14px; margin: 8px 0; }
.evidence-block .ev-label { color: #ffd93d; font-size: 0.85em; font-weight: 600; margin-bottom: 4px; }
.crash-card { border-left: 4px solid #ff4444; padding: 12px; margin: 14px 0; background: #1a1a30; border-radius: 0 8px 8px 0; }
.crash-card.high { border-left-color: #ff6b35; }
.crash-card.medium { border-left-color: #ffaa00; }
.hexdump { font-family: 'Courier New', monospace; font-size: 11px; line-height: 1.4; }
.severity-badge { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; display: inline-block; }
.severity-CRITICAL { background: #ff4444; color: #fff; }
.severity-HIGH { background: #ff6b35; color: #fff; }
.severity-MEDIUM { background: #ffaa00; color: #000; }
.severity-LOW { background: #88cc00; color: #000; }
.severity-INFO { background: #4488ff; color: #fff; }
.status-confirmed { color: #ff4444; }
.status-potential { color: #ffaa00; }
.status-unverified { color: #4488ff; }
.reproduced-yes { color: #00ff9f; font-weight: bold; }
.reproduced-no { color: #ff4444; }
.tag { display: inline-block; background: #1a1a3a; border: 1px solid #333; padding: 1px 8px;
    border-radius: 12px; font-size: 0.8em; color: #aaa; margin: 2px; }
.timeline-table td:first-child { white-space: nowrap; color: #888; font-family: monospace; font-size: 0.85em; }
.fuzz-stat { display: inline-block; margin: 5px 15px 5px 0; }
.fuzz-stat .value { font-size: 1.4em; font-weight: bold; color: #00d4ff; }
.fuzz-stat .label { font-size: 0.85em; color: #888; }
.mono { font-family: 'Courier New', monospace; }
.evidence-list { list-style: none; padding: 0; }
.evidence-list li { padding: 3px 0; }
.evidence-list li::before { content: "\\1F4CE "; }
.footer { text-align: center; color: #555; font-size: 0.8em; margin-top: 40px; padding-top: 16px; border-top: 1px solid #222; }
@media print {
    body { background: #fff; color: #222; max-width: 100%; }
    .section, .summary, .toc { border-color: #ccc; background: #fafafa; }
    h1 { color: #003366; border-bottom-color: #003366; }
    h2 { color: #cc0000; }
    th { background: #eee; color: #003366; }
    tr:nth-child(even) { background: #f5f5f5; }
    .metric-card { border-color: #ccc; background: #f9f9f9; }
    .metric-card .value { color: #003366; }
    .header .classification { color: #cc0000; border-color: #cc0000; }
    pre { background: #f5f5f5; border: 1px solid #ccc; }
}
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Blue-Tap Pentest Report</title>
<style>
{css}
</style>
</head>
<body>
{content}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates pentest reports from Blue-Tap session data."""

    def __init__(self):
        self.scan_results: list[dict] = []
        self.vuln_findings: list[dict] = []
        self.pbap_results: dict = {}
        self.map_results: dict = {}
        self.attack_results: dict = {}
        self.recon_results: list[dict] = []
        self.fuzz_results: list = []
        self.dos_results: list = []
        self.fingerprint_results: dict = {}
        self.audio_captures: list[dict] = []
        self.other_data: dict = {}
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

    # ------------------------------------------------------------------
    # Data intake (public API — signatures must not change)
    # ------------------------------------------------------------------

    def add_scan_results(self, devices: list[dict]):
        self.scan_results.extend(devices)

    def add_vuln_findings(self, findings: list[dict]):
        self.vuln_findings.extend(findings)

    def add_pbap_results(self, data: dict):
        self.pbap_results.update(data)

    def add_map_results(self, messages: dict):
        self.map_results.update(messages)

    def add_attack_results(self, results: dict):
        self.attack_results.update(results)

    def add_recon_results(self, data: list[dict]):
        self.recon_results.extend(data)

    def add_fuzz_results(self, data: dict):
        self.fuzz_results.append(data)

    def add_dos_results(self, data: dict):
        self.dos_results.append(data)

    def add_fingerprint(self, data: dict):
        self.fingerprint_results.update(data)

    def add_audio_capture(self, filepath: str, duration: float = 0, description: str = ""):
        self.audio_captures.append({
            "file": filepath, "duration": duration, "description": description,
        })

    def add_note(self, note: str):
        self.notes.append(note)

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
                info(f"Could not load crashes.db: {exc}")

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
        """Load all available data from a Blue-Tap output directory."""
        if not os.path.isdir(dump_dir):
            error(f"Directory not found: {dump_dir}")
            return

        results_file = os.path.join(dump_dir, "attack_results.json")
        if os.path.exists(results_file):
            try:
                with open(results_file) as f:
                    self.attack_results = json.load(f)
                info(f"Loaded attack results from {results_file}")
            except (json.JSONDecodeError, OSError) as exc:
                error(f"Could not load attack_results.json: {exc}")

        fuzz_dir = os.path.join(dump_dir, "fuzz")
        if os.path.isdir(fuzz_dir):
            self.load_fuzz_from_session(dump_dir)

        for root, dirs, files in os.walk(dump_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, dump_dir)
                rel_lower = rel.lower()

                if fname.endswith(".json") and fname != "attack_results.json":
                    if rel_lower.startswith("fuzz/") or rel_lower.startswith("fuzz\\"):
                        continue
                    try:
                        with open(fpath) as f:
                            data = json.load(f)
                        if "pbap" in rel_lower:
                            self.pbap_results[rel] = data
                        elif "map" in rel_lower:
                            self.map_results[rel] = data
                        elif "vuln" in rel_lower:
                            if isinstance(data, list):
                                self.vuln_findings.extend(data)
                            else:
                                self.vuln_findings.append(data)
                        elif "fuzz" in rel_lower:
                            self.fuzz_results.append({"source": rel, "data": data})
                        elif "dos" in rel_lower or "flood" in rel_lower or "brute" in rel_lower:
                            self.dos_results.append({"source": rel, "data": data})
                        elif "rfcomm" in rel_lower or "l2cap" in rel_lower or "scan" in rel_lower:
                            if isinstance(data, list):
                                self.recon_results.extend(data)
                            else:
                                self.recon_results.append(data)
                        else:
                            self.other_data[rel] = data
                    except (json.JSONDecodeError, OSError):
                        pass

                elif fname.endswith(".vcf"):
                    try:
                        with open(fpath) as f:
                            content = f.read()
                        count = content.count("BEGIN:VCARD")
                        self.pbap_results[rel] = {
                            "file": rel, "entries": count, "size": os.path.getsize(fpath),
                        }
                    except OSError:
                        pass

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
            '<div class="header">'
            f'<h1>Blue-Tap Pentest Report</h1>'
            f'<p class="version">Blue-Tap v{_esc(__version__)} '
            f'| Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>'
            f'{"<p class=meta>" + _esc(period) + "</p>" if period else ""}'
            '<p class="classification">CONFIDENTIAL - Authorized Personnel Only</p>'
            '</div>'
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
        s.append(f'<div style="text-align:center;margin:16px 0">'
                 f'<span class="risk-badge risk-{rating}">Overall Risk: {rating}</span></div>')

        # Metric cards
        confirmed = sum(1 for f in self.vuln_findings if f.get("status") == "confirmed")
        potential = sum(1 for f in self.vuln_findings if f.get("status") == "potential")
        crash_count = len(self._fuzz_crashes)
        data_exfil = len(self.pbap_results) + len(self.map_results)
        packets = self._fuzz_campaign_stats.get("packets_sent", 0)

        s.append('<div class="metric-grid">')
        for val, label in [
            (len(self.scan_results), "Devices Scanned"),
            (f"{confirmed}C / {potential}P", "Vulnerabilities"),
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
        if self.vuln_findings:
            sev_counts: dict[str, int] = {}
            for f in self.vuln_findings:
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
        if self.vuln_findings:
            vuln_by_sev = {}
            for f in self.vuln_findings:
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
            chart = _svg_bar_chart(crash_by_proto, "#ff6b35")
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

    def _build_fingerprint_html(self) -> str:
        fp = self.fingerprint_results
        if not fp:
            return ""

        s = []
        s.append('<div class="section" id="sec-fingerprint">')
        s.append('<h2>Device Fingerprint</h2>')

        # Identity table
        s.append('<h3>Identity</h3>')
        s.append('<table><tr><th>Property</th><th>Value</th></tr>')
        for key in ("address", "name", "manufacturer", "device_class", "ivi_likely"):
            val = fp.get(key)
            if val is not None:
                s.append(f'<tr><td>{_esc(key.replace("_", " ").title())}</td><td>{_esc(str(val))}</td></tr>')
        s.append('</table>')

        # Protocol support
        proto_keys = ("bt_version", "lmp_version", "lmp_subversion")
        has_proto = any(fp.get(k) is not None for k in proto_keys)
        if has_proto:
            s.append('<h3>Protocol Support</h3>')
            s.append('<table><tr><th>Property</th><th>Value</th></tr>')
            for key in proto_keys:
                val = fp.get(key)
                if val is not None:
                    s.append(f'<tr><td>{_esc(key.replace("_", " ").title())}</td><td>{_esc(str(val))}</td></tr>')
            s.append('</table>')

        # Attack surface
        surface = fp.get("attack_surface", [])
        if surface:
            s.append('<h3>Attack Surface</h3>')
            for item in surface:
                s.append(f'<span class="tag">{_esc(item)}</span> ')

        # Vuln hints
        hints = fp.get("vuln_hints", [])
        if hints:
            s.append('<h3>Vulnerability Indicators</h3><ul>')
            for hint in hints:
                s.append(f'<li><span class="severity-badge severity-MEDIUM">INDICATOR</span> {_esc(hint)}</li>')
            s.append('</ul>')

        s.append('</div>')
        return "\n".join(s)

    def _build_scan_html(self) -> str:
        if not self.scan_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-devices">')
        s.append('<h2>Discovered Devices</h2>')
        s.append(f'<p>{len(self.scan_results)} device(s) discovered during scanning.</p>')
        s.append('<table><tr><th>Address</th><th>Name</th><th>RSSI</th><th>Type</th></tr>')
        for d in self.scan_results:
            s.append(
                f'<tr><td class="mono">{_esc(d.get("address", ""))}</td>'
                f'<td>{_esc(d.get("name", "Unknown"))}</td>'
                f'<td>{_esc(str(d.get("rssi", "")))}</td>'
                f'<td>{_esc(d.get("type", "Classic"))}</td></tr>'
            )
        s.append('</table></div>')
        return "\n".join(s)

    def _build_vuln_html(self) -> str:
        if not self.vuln_findings:
            return ""
        s = []
        s.append('<div class="section" id="sec-vulnerabilities">')
        s.append('<h2>Vulnerability Findings</h2>')

        # Summary table
        s.append('<table><tr><th>ID</th><th>Severity</th><th>Status</th>'
                 '<th>Finding</th><th>CVE</th></tr>')
        for i, v in enumerate(self.vuln_findings, 1):
            sev = v.get("severity", "INFO").upper()
            status = v.get("status", "potential")
            confidence = v.get("confidence", "")
            status_display = f'{status} ({confidence})' if confidence else status
            cve = v.get("cve", "N/A")
            s.append(
                f'<tr><td>VULN-{i:03d}</td>'
                f'<td><span class="severity-badge severity-{sev}">{_esc(sev)}</span></td>'
                f'<td class="status-{_esc(status)}">{_esc(status_display)}</td>'
                f'<td>{_esc(v.get("name", ""))}</td>'
                f'<td>{_esc(cve)}</td></tr>'
            )
        s.append('</table>')

        # Individual finding cards
        s.append('<h3>Finding Details</h3>')
        for i, v in enumerate(self.vuln_findings, 1):
            sev = v.get("severity", "INFO").upper()
            status = v.get("status", "potential")
            confidence = v.get("confidence", "")
            cve = v.get("cve", "N/A")
            desc = v.get("description", "")
            impact = v.get("impact", "")
            evidence = v.get("evidence", "")
            remediation = v.get("remediation", "")
            category = v.get("category", "")

            s.append(f'<div class="finding-card sev-{sev}">')
            s.append(f'<h4>VULN-{i:03d}: {_esc(v.get("name", "Unknown Finding"))}</h4>')
            s.append(f'<p><span class="severity-badge severity-{sev}">{_esc(sev)}</span> '
                     f'<span class="status-{_esc(status)}">{_esc(status)}</span>'
                     f'{" / " + _esc(confidence) + " confidence" if confidence else ""}'
                     f'{" | CVE: " + _esc(cve) if cve and cve != "N/A" else ""}'
                     f'{" | " if category else ""}'
                     f'{"<span class=tag>" + _esc(category) + "</span>" if category else ""}'
                     f'</p>')

            if desc:
                s.append(f'<p><strong>Description:</strong> {_esc(desc)}</p>')
            if impact:
                s.append(f'<p><strong>Impact:</strong> {_esc(impact)}</p>')

            if evidence:
                s.append('<div class="evidence-block">'
                         '<div class="ev-label">Evidence</div>'
                         f'<pre>{_esc(evidence)}</pre></div>')

            if remediation:
                s.append(f'<p><strong>Remediation:</strong> {_esc(remediation)}</p>')

            s.append('</div>')

        s.append('</div>')
        return "\n".join(s)

    def _build_attack_html(self) -> str:
        if not self.attack_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-attack">')
        s.append('<h2>Attack Chain Results</h2>')

        phases = self.attack_results.get("phases", {})
        if phases:
            s.append('<table><tr><th>Phase</th><th>Status</th><th>Details</th></tr>')
            for phase, result in phases.items():
                status = result.get("status", "unknown")
                details = result.get("error", result.get("details", ""))
                if status == "success":
                    css = "severity-badge severity-LOW"
                elif status == "failed":
                    css = "severity-badge severity-HIGH"
                else:
                    css = "severity-badge severity-MEDIUM"
                s.append(f'<tr><td>{_esc(phase)}</td>'
                         f'<td><span class="{css}">{_esc(status.upper())}</span></td>'
                         f'<td>{_esc(str(details))}</td></tr>')
            s.append('</table>')
        else:
            s.append(f'<pre>{_esc(json.dumps(self.attack_results, indent=2, default=str)[:3000])}</pre>')
        s.append('</div>')
        return "\n".join(s)

    def _build_fuzz_html(self) -> list[str]:
        """Build the detailed fuzzing campaign HTML section."""
        sections: list[str] = []
        has_campaign = bool(self._fuzz_campaign_stats)
        has_crashes = bool(self._fuzz_crashes)

        if not has_campaign and not has_crashes and not self.fuzz_results:
            return sections

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
        """Build the fuzzing intelligence section (state coverage, field weights, health)."""
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
                    bar_color = "#ff4444" if w > 0.3 else "#ffaa00" if w > 0.15 else "#88cc00"
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
            s.append('<h3>Target Health Events</h3>')
            s.append('<table><tr><th>Time</th><th>Status</th><th>Details</th>'
                     '<th>Iteration</th></tr>')
            for evt in self._fuzz_health_events:
                if not isinstance(evt, dict):
                    continue
                status = evt.get("status", "unknown")
                status_color = "#ff4444" if status in ("rebooted", "zombie", "unreachable") else (
                    "#ffaa00" if status == "degraded" else "#88cc00")
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

    def _build_recon_html(self) -> str:
        if not self.recon_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-recon">')
        s.append('<h2>Reconnaissance Results</h2>')

        # Try to categorize recon data
        sdp_services = []
        gatt_services = []
        channel_scans = []
        other_recon = []

        for entry in self.recon_results:
            if isinstance(entry, dict):
                if entry.get("uuid") or entry.get("service_name") or entry.get("service_id"):
                    sdp_services.append(entry)
                elif entry.get("handle") or entry.get("characteristic"):
                    gatt_services.append(entry)
                elif entry.get("channel") or entry.get("psm"):
                    channel_scans.append(entry)
                else:
                    other_recon.append(entry)
            else:
                other_recon.append(entry)

        if sdp_services:
            s.append('<h3>SDP Services</h3>')
            s.append('<table><tr><th>UUID</th><th>Service Name</th><th>Description</th><th>Channel</th></tr>')
            for svc in sdp_services:
                s.append(
                    f'<tr><td class="mono">{_esc(str(svc.get("uuid", svc.get("service_id", ""))))}</td>'
                    f'<td>{_esc(str(svc.get("service_name", svc.get("name", ""))))}</td>'
                    f'<td>{_esc(str(svc.get("description", "")))}</td>'
                    f'<td>{_esc(str(svc.get("channel", svc.get("port", ""))))}</td></tr>'
                )
            s.append('</table>')

        if gatt_services:
            s.append('<h3>GATT Services</h3>')
            s.append('<table><tr><th>Handle</th><th>UUID</th><th>Name</th><th>Properties</th></tr>')
            for svc in gatt_services:
                s.append(
                    f'<tr><td>{_esc(str(svc.get("handle", "")))}</td>'
                    f'<td class="mono">{_esc(str(svc.get("uuid", "")))}</td>'
                    f'<td>{_esc(str(svc.get("name", svc.get("characteristic", ""))))}</td>'
                    f'<td>{_esc(str(svc.get("properties", "")))}</td></tr>'
                )
            s.append('</table>')

        if channel_scans:
            s.append('<h3>Channel Scan Results</h3>')
            s.append('<table><tr><th>Channel/PSM</th><th>Status</th><th>Service</th></tr>')
            for ch in channel_scans:
                chan = ch.get("channel", ch.get("psm", ""))
                s.append(
                    f'<tr><td>{_esc(str(chan))}</td>'
                    f'<td>{_esc(str(ch.get("status", ch.get("state", ""))))}</td>'
                    f'<td>{_esc(str(ch.get("service", ch.get("description", ""))))}</td></tr>'
                )
            s.append('</table>')

        if other_recon:
            s.append('<h3>Additional Recon Data</h3>')
            s.append(f'<pre>{_esc(json.dumps(other_recon, indent=2, default=str)[:3000])}</pre>')

        s.append('</div>')
        return "\n".join(s)

    def _build_dos_html(self) -> str:
        if not self.dos_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-dos">')
        s.append('<h2>Denial of Service Test Results</h2>')
        s.append('<table><tr><th>Test</th><th>Target</th><th>Duration</th>'
                 '<th>Packets Sent</th><th>Result</th><th>Impact</th></tr>')
        for entry in self.dos_results:
            data = entry.get("data", entry) if isinstance(entry, dict) else entry
            if isinstance(data, dict):
                s.append(
                    f'<tr><td>{_esc(str(data.get("test", data.get("command", entry.get("source", "dos")))))}</td>'
                    f'<td class="mono">{_esc(str(data.get("target", "")))}</td>'
                    f'<td>{_esc(str(data.get("duration", data.get("duration_seconds", "N/A"))))}</td>'
                    f'<td>{_esc(str(data.get("packets_sent", data.get("packets", "N/A"))))}</td>'
                    f'<td>{_esc(str(data.get("result", data.get("status", "unknown"))))}</td>'
                    f'<td>{_esc(str(data.get("impact", data.get("effect", ""))))}</td></tr>'
                )
            else:
                s.append(f'<tr><td colspan="6"><pre>{_esc(json.dumps(data, indent=2, default=str)[:500])}</pre></td></tr>')
        s.append('</table></div>')
        return "\n".join(s)

    def _build_pbap_html(self) -> str:
        if not self.pbap_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-data-exfil">')
        s.append('<h2>Data Exfiltration: PBAP (Phonebook)</h2>')
        s.append('<p>The following phonebook data was successfully extracted from the target device.</p>')
        s.append('<table><tr><th>Source</th><th>Entries</th><th>Size</th><th>Category</th></tr>')
        for path, data in self.pbap_results.items():
            entries = data.get("entries", "N/A") if isinstance(data, dict) else "N/A"
            size = data.get("size", "N/A") if isinstance(data, dict) else "N/A"
            # Derive category from filename
            cat = "Contacts"
            path_lower = path.lower()
            if "ch" in path_lower:
                cat = "Call History"
            elif "fav" in path_lower:
                cat = "Favorites"
            elif "ich" in path_lower:
                cat = "Incoming Calls"
            elif "och" in path_lower:
                cat = "Outgoing Calls"
            elif "mch" in path_lower:
                cat = "Missed Calls"
            s.append(f'<tr><td><code>{_esc(path)}</code></td>'
                     f'<td>{entries}</td><td>{size}</td><td>{_esc(cat)}</td></tr>')
        s.append('</table></div>')
        return "\n".join(s)

    def _build_map_html(self) -> str:
        if not self.map_results:
            return ""
        s = []
        s.append('<div class="section" id="sec-map">')
        s.append('<h2>Data Exfiltration: MAP (Messages)</h2>')
        s.append(f'<p>{len(self.map_results)} message data set(s) collected.</p>')
        for path, data in self.map_results.items():
            s.append(f'<h3>{_esc(path)}</h3>')
            if isinstance(data, dict):
                listing = data.get("listing_file", "")
                messages = data.get("messages", [])
                if listing:
                    s.append(f'<p>Listing file: <code>{_esc(listing)}</code></p>')
                if messages:
                    s.append(f'<p>Messages fetched: {len(messages)}</p>')
                    s.append('<table><tr><th>Handle</th><th>File</th></tr>')
                    for msg in messages[:50]:
                        s.append(f'<tr><td>{_esc(msg.get("handle", ""))}</td>'
                                 f'<td><code>{_esc(msg.get("file", ""))}</code></td></tr>')
                    s.append('</table>')
                    if len(messages) > 50:
                        s.append(f'<p>... and {len(messages) - 50} more</p>')
                elif not listing:
                    s.append(f'<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>')
            else:
                s.append(f'<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>')
        s.append('</div>')
        return "\n".join(s)

    def _build_audio_html(self) -> str:
        if not self.audio_captures:
            return ""
        s = []
        s.append('<div class="section" id="sec-audio">')
        s.append('<h2>Audio Captures</h2>')
        s.append('<table><tr><th>File</th><th>Duration</th><th>Description</th></tr>')
        for cap in self.audio_captures:
            dur = f"{cap.get('duration', 0):.1f}s" if cap.get("duration") else "N/A"
            s.append(f'<tr><td><code>{_esc(cap.get("file", ""))}</code></td>'
                     f'<td>{dur}</td><td>{_esc(cap.get("description", ""))}</td></tr>')
        s.append('</table></div>')
        return "\n".join(s)

    def _build_appendix_html(self) -> str:
        parts = []

        if self.other_data:
            parts.append('<div class="section" id="sec-appendix">')
            parts.append('<h2>Appendix: Additional Data</h2>')
            for path, data in self.other_data.items():
                parts.append(f'<h3>{_esc(path)}</h3>')
                parts.append(f'<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>')
            parts.append('</div>')

        if self.notes:
            if not parts:
                parts.append('<div class="section" id="sec-appendix">')
                parts.append('<h2>Appendix</h2>')
            else:
                # Already in an appendix section
                pass
            parts.append('<h3>Analyst Notes</h3>')
            for note in self.notes:
                parts.append(f'<p>{_esc(note)}</p>')
            if not self.other_data:
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

        if self.fingerprint_results:
            toc_entries.append(("sec-fingerprint", "Device Fingerprint"))
        if self.scan_results:
            toc_entries.append(("sec-devices", "Discovered Devices"))
        if self.vuln_findings:
            toc_entries.append(("sec-vulnerabilities", "Vulnerability Findings"))
        if self.attack_results:
            toc_entries.append(("sec-attack", "Attack Chain Results"))
        if self._fuzz_campaign_stats or self._fuzz_crashes or self.fuzz_results:
            toc_entries.append(("sec-fuzzing", "Fuzzing Campaign Results"))
        has_fuzz_intel = any([self._fuzz_state_coverage, self._fuzz_field_weights,
                             self._fuzz_health_events, self._fuzz_baselines])
        if has_fuzz_intel:
            toc_entries.append(("sec-fuzz-intel", "Fuzzing Intelligence Analysis"))
        if self.recon_results:
            toc_entries.append(("sec-recon", "Reconnaissance Results"))
        if self.dos_results:
            toc_entries.append(("sec-dos", "Denial of Service Tests"))
        if self.pbap_results:
            toc_entries.append(("sec-data-exfil", "Data Exfiltration: PBAP"))
        if self.map_results:
            toc_entries.append(("sec-map", "Data Exfiltration: MAP"))
        if self.audio_captures:
            toc_entries.append(("sec-audio", "Audio Captures"))
        if self.other_data or self.notes:
            toc_entries.append(("sec-appendix", "Appendix"))

        # Build all sections
        body_parts = [
            self._build_header_html(),
            self._build_toc_html(toc_entries),
            self._build_executive_summary_html(),
            self._build_scope_html(),
            self._build_timeline_html(),
            self._build_fingerprint_html(),
            self._build_scan_html(),
            self._build_vuln_html(),
            self._build_attack_html(),
        ]
        body_parts.extend(self._build_fuzz_html())
        body_parts.append(self._build_fuzz_intelligence_html())
        body_parts.extend([
            self._build_recon_html(),
            self._build_dos_html(),
            self._build_pbap_html(),
            self._build_map_html(),
            self._build_audio_html(),
            self._build_appendix_html(),
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
                "total_findings": len(self.vuln_findings),
                "confirmed": sum(1 for f in self.vuln_findings if f.get("status") == "confirmed"),
                "potential": sum(1 for f in self.vuln_findings if f.get("status") == "potential"),
                "unverified": sum(1 for f in self.vuln_findings if f.get("status") == "unverified"),
                "high_severity": sum(1 for f in self.vuln_findings
                                     if f.get("severity", "").lower() in ("high", "critical")),
                "fuzz_test_cases": self._fuzz_campaign_stats.get("packets_sent", 0),
                "fuzz_crashes": len(self._fuzz_crashes),
                "data_exfiltration": len(self.pbap_results) + len(self.map_results),
            },
            "timeline": timeline,
            "fingerprint": self.fingerprint_results,
            "scan_results": self.scan_results,
            "vulnerabilities": self.vuln_findings,
            "pbap_data": self.pbap_results,
            "map_data": self.map_results,
            "attack_results": self.attack_results,
            "recon_results": self.recon_results,
            "fuzzing": fuzz_data if fuzz_data else self.fuzz_results,
            "fuzzing_intelligence": {
                "state_coverage": self._fuzz_state_coverage,
                "field_weights": self._fuzz_field_weights,
                "baselines": self._fuzz_baselines,
                "health_events": self._fuzz_health_events,
            } if any([self._fuzz_state_coverage, self._fuzz_field_weights,
                      self._fuzz_health_events, self._fuzz_baselines]) else {},
            "dos_results": self.dos_results,
            "audio_captures": self.audio_captures,
            "other_data": self.other_data,
            "notes": self.notes,
        }

        outdir = os.path.dirname(output)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"JSON report generated: {output}")
        return output
