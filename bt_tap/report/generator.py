"""Pentest report generation for BT-Tap.

Generates HTML or JSON reports from attack session data including scan results,
vulnerability findings, PBAP/MAP dumps, and analysis notes.
"""

import json
import os
from datetime import datetime

from bt_tap.utils.output import info, success, error


# Inline HTML template (avoids Jinja2 dependency)
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BT-Tap Pentest Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         max-width: 900px; margin: 0 auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
  h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
  h2 {{ color: #ff6b6b; margin-top: 30px; }}
  h3 {{ color: #ffd93d; }}
  .meta {{ color: #888; font-size: 0.9em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
  th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
  th {{ background: #16213e; color: #00d4ff; }}
  tr:nth-child(even) {{ background: #16213e; }}
  .vuln-high {{ color: #ff4444; font-weight: bold; }}
  .vuln-medium {{ color: #ffaa00; }}
  .vuln-low {{ color: #88cc00; }}
  .vuln-info {{ color: #4488ff; }}
  h4 {{ color: #ccc; margin-top: 15px; }}
  pre {{ background: #16213e; padding: 10px; border-radius: 4px; overflow-x: auto; }}
  .section {{ margin: 20px 0; padding: 15px; border: 1px solid #333; border-radius: 8px; }}
  .summary {{ background: #16213e; padding: 15px; border-radius: 8px; margin: 20px 0; }}
</style>
</head>
<body>
<h1>BT-Tap Pentest Report</h1>
<p class="meta">Generated: {generated} | Tool: BT-Tap v1.5.0</p>

{content}

</body>
</html>"""


class ReportGenerator:
    """Generates pentest reports from BT-Tap session data."""

    def __init__(self):
        self.scan_results = []
        self.vuln_findings = []
        self.pbap_results = {}
        self.map_results = {}
        self.attack_results = {}
        self.recon_results = []
        self.fuzz_results = []
        self.dos_results = []
        self.fingerprint_results = {}
        self.audio_captures = []
        self.other_data = {}
        self.notes = []

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

    def load_from_directory(self, dump_dir: str):
        """Load all available data from a BT-Tap output directory."""
        if not os.path.isdir(dump_dir):
            error(f"Directory not found: {dump_dir}")
            return

        # Load attack_results.json
        results_file = os.path.join(dump_dir, "attack_results.json")
        if os.path.exists(results_file):
            with open(results_file) as f:
                self.attack_results = json.load(f)
            info(f"Loaded attack results from {results_file}")

        # Load any JSON files in subdirectories
        for root, dirs, files in os.walk(dump_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, dump_dir)

                if fname.endswith(".json") and fname != "attack_results.json":
                    try:
                        with open(fpath) as f:
                            data = json.load(f)
                        rel_lower = rel.lower()
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
                            # AT dumps, device info, etc.
                            self.other_data[rel] = data
                    except (json.JSONDecodeError, OSError):
                        pass

                elif fname.endswith(".vcf"):
                    # Count vCard entries
                    try:
                        with open(fpath) as f:
                            content = f.read()
                        count = content.count("BEGIN:VCARD")
                        self.pbap_results[rel] = {
                            "file": rel, "entries": count,
                            "size": os.path.getsize(fpath),
                        }
                    except OSError:
                        pass

    def generate_html(self, output: str = "report.html") -> str:
        """Generate a styled HTML pentest report."""
        sections = []

        # Summary
        sections.append('<div class="summary">')
        sections.append("<h2>Executive Summary</h2>")
        sections.append(f"<p>Devices scanned: {len(self.scan_results)}</p>")

        # Break down vuln findings by evidence quality
        confirmed = sum(1 for f in self.vuln_findings if f.get("status") == "confirmed")
        potential = sum(1 for f in self.vuln_findings if f.get("status") == "potential")
        unverified = sum(1 for f in self.vuln_findings if f.get("status") == "unverified")
        high_sev = sum(1 for f in self.vuln_findings
                       if f.get("severity", "").lower() in ("high", "critical"))
        sections.append(f"<p>Findings: {len(self.vuln_findings)} total "
                        f"(<span class='vuln-high'>{confirmed} confirmed</span>, "
                        f"<span class='vuln-medium'>{potential} potential</span>, "
                        f"<span class='vuln-info'>{unverified} unverified</span>)</p>")
        if high_sev:
            sections.append(f"<p class='vuln-high'>Critical/High severity: {high_sev}</p>")

        sections.append(f"<p>PBAP data sets: {len(self.pbap_results)}</p>")
        sections.append(f"<p>MAP data sets: {len(self.map_results)}</p>")
        if self.fuzz_results:
            sections.append(f"<p>Fuzzing runs: {len(self.fuzz_results)}</p>")
        if self.dos_results:
            sections.append(f"<p>DoS/pairing tests: {len(self.dos_results)}</p>")
        if self.recon_results:
            sections.append(f"<p>Channel scan results: {len(self.recon_results)}</p>")
        sections.append("</div>")

        # Attack Results
        if self.attack_results:
            sections.append('<div class="section">')
            sections.append("<h2>Attack Chain Results</h2>")
            phases = self.attack_results.get("phases", {})
            if phases:
                sections.append("<table><tr><th>Phase</th><th>Status</th><th>Details</th></tr>")
                for phase, result in phases.items():
                    status = result.get("status", "unknown")
                    details = result.get("error", "")
                    css = "vuln-high" if status == "failed" else "vuln-low" if status == "success" else "vuln-medium"
                    sections.append(f'<tr><td>{_esc(phase)}</td>'
                                    f'<td class="{css}">{_esc(status)}</td>'
                                    f'<td>{_esc(details)}</td></tr>')
                sections.append("</table>")
            else:
                sections.append(f"<pre>{_esc(json.dumps(self.attack_results, indent=2))}</pre>")
            sections.append("</div>")

        # Vulnerability Findings
        if self.vuln_findings:
            sections.append('<div class="section">')
            sections.append("<h2>Vulnerability &amp; Attack-Surface Findings</h2>")
            sections.append("<table><tr><th>#</th><th>Severity</th><th>Status</th>"
                            "<th>Name</th><th>CVE</th><th>Description</th></tr>")
            for i, v in enumerate(self.vuln_findings, 1):
                sev = v.get("severity", "info").lower()
                css = {"high": "vuln-high", "critical": "vuln-high",
                       "medium": "vuln-medium", "low": "vuln-low"}.get(sev, "vuln-info")
                status = v.get("status", "potential")
                confidence = v.get("confidence", "")
                status_display = f"{status} ({confidence})" if confidence else status
                sections.append(
                    f'<tr><td>{i}</td>'
                    f'<td class="{css}">{_esc(sev.upper())}</td>'
                    f'<td>{_esc(status_display)}</td>'
                    f'<td>{_esc(v.get("name", ""))}</td>'
                    f'<td>{_esc(v.get("cve", "N/A"))}</td>'
                    f'<td>{_esc(v.get("description", ""))}</td></tr>'
                )
            sections.append("</table>")

            # Detailed findings with impact/remediation/evidence
            sections.append("<h3>Finding Details</h3>")
            for i, v in enumerate(self.vuln_findings, 1):
                impact = v.get("impact", "")
                remediation = v.get("remediation", "")
                evidence = v.get("evidence", "")
                if impact or remediation or evidence:
                    sections.append(f"<h4>#{i}: {_esc(v.get('name', ''))}</h4>")
                    if impact:
                        sections.append(f"<p><strong>Impact:</strong> {_esc(impact)}</p>")
                    if evidence:
                        sections.append(f"<p><strong>Evidence:</strong> {_esc(evidence)}</p>")
                    if remediation:
                        sections.append(f"<p><strong>Remediation:</strong> {_esc(remediation)}</p>")

            sections.append("</div>")

        # Fingerprint Results
        if self.fingerprint_results:
            sections.append('<div class="section">')
            sections.append("<h2>Device Fingerprint</h2>")
            sections.append("<table><tr><th>Property</th><th>Value</th></tr>")
            display_keys = ["address", "name", "manufacturer", "ivi_likely",
                           "device_class", "bt_version", "lmp_version"]
            for key in display_keys:
                val = self.fingerprint_results.get(key)
                if val is not None:
                    sections.append(f"<tr><td>{_esc(key)}</td><td>{_esc(str(val))}</td></tr>")
            sections.append("</table>")
            # Attack surface
            surface = self.fingerprint_results.get("attack_surface", [])
            if surface:
                sections.append("<h3>Attack Surface</h3><ul>")
                for item in surface:
                    sections.append(f"<li>{_esc(item)}</li>")
                sections.append("</ul>")
            # Vuln hints
            hints = self.fingerprint_results.get("vuln_hints", [])
            if hints:
                sections.append("<h3>Vulnerability Indicators</h3><ul>")
                for hint in hints:
                    sections.append(f'<li class="vuln-medium">{_esc(hint)}</li>')
                sections.append("</ul>")
            sections.append("</div>")

        # Scan Results
        if self.scan_results:
            sections.append('<div class="section">')
            sections.append("<h2>Discovered Devices</h2>")
            sections.append("<table><tr><th>Address</th><th>Name</th>"
                            "<th>RSSI</th><th>Type</th></tr>")
            for d in self.scan_results:
                sections.append(
                    f'<tr><td>{_esc(d.get("address", ""))}</td>'
                    f'<td>{_esc(d.get("name", "Unknown"))}</td>'
                    f'<td>{_esc(str(d.get("rssi", "")))}</td>'
                    f'<td>{_esc(d.get("type", "Classic"))}</td></tr>'
                )
            sections.append("</table>")
            sections.append("</div>")

        # PBAP Results
        if self.pbap_results:
            sections.append('<div class="section">')
            sections.append("<h2>PBAP Data (Phonebook)</h2>")
            sections.append("<table><tr><th>Source</th><th>Entries</th><th>Size</th></tr>")
            for path, data in self.pbap_results.items():
                entries = data.get("entries", "N/A") if isinstance(data, dict) else "N/A"
                size = data.get("size", "N/A") if isinstance(data, dict) else "N/A"
                sections.append(f"<tr><td>{_esc(path)}</td>"
                                f"<td>{entries}</td><td>{size}</td></tr>")
            sections.append("</table>")
            sections.append("</div>")

        # MAP Results
        if self.map_results:
            sections.append('<div class="section">')
            sections.append("<h2>MAP Data (Messages)</h2>")
            sections.append(f"<p>Message data sets collected: {len(self.map_results)}</p>")
            for path, data in self.map_results.items():
                sections.append(f"<h3>{_esc(path)}</h3>")
                if isinstance(data, dict):
                    listing = data.get("listing_file", "")
                    messages = data.get("messages", [])
                    if listing:
                        sections.append(f"<p>Listing file: {_esc(listing)}</p>")
                    if messages:
                        sections.append(f"<p>Messages fetched: {len(messages)}</p>")
                        sections.append("<table><tr><th>Handle</th><th>File</th></tr>")
                        for msg in messages[:50]:  # Cap at 50 in report
                            sections.append(
                                f'<tr><td>{_esc(msg.get("handle", ""))}</td>'
                                f'<td>{_esc(msg.get("file", ""))}</td></tr>')
                        sections.append("</table>")
                        if len(messages) > 50:
                            sections.append(f"<p>... and {len(messages) - 50} more</p>")
                    elif not listing:
                        sections.append(f"<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>")
                else:
                    sections.append(f"<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>")
            sections.append("</div>")

        # Recon Results (RFCOMM/L2CAP scans)
        if self.recon_results:
            sections.append('<div class="section">')
            sections.append("<h2>Recon / Channel Scan Results</h2>")
            sections.append(f"<pre>{_esc(json.dumps(self.recon_results, indent=2, default=str)[:3000])}</pre>")
            sections.append("</div>")

        # Fuzz Results
        if self.fuzz_results:
            sections.append('<div class="section">')
            sections.append("<h2>Fuzzing Results</h2>")
            for entry in self.fuzz_results:
                src = entry.get("source", "fuzz")
                sections.append(f"<h3>{_esc(src)}</h3>")
                sections.append(f"<pre>{_esc(json.dumps(entry.get('data', entry), indent=2, default=str)[:2000])}</pre>")
            sections.append("</div>")

        # DoS Results
        if self.dos_results:
            sections.append('<div class="section">')
            sections.append("<h2>DoS / Pairing Attack Results</h2>")
            for entry in self.dos_results:
                src = entry.get("source", "dos")
                sections.append(f"<h3>{_esc(src)}</h3>")
                sections.append(f"<pre>{_esc(json.dumps(entry.get('data', entry), indent=2, default=str)[:2000])}</pre>")
            sections.append("</div>")

        # Other Data (AT dumps, etc.)
        if self.other_data:
            sections.append('<div class="section">')
            sections.append("<h2>Additional Data</h2>")
            for path, data in self.other_data.items():
                sections.append(f"<h3>{_esc(path)}</h3>")
                sections.append(f"<pre>{_esc(json.dumps(data, indent=2, default=str)[:2000])}</pre>")
            sections.append("</div>")

        # Audio Captures
        if self.audio_captures:
            sections.append('<div class="section">')
            sections.append("<h2>Audio Captures</h2>")
            sections.append("<table><tr><th>File</th><th>Duration</th><th>Description</th></tr>")
            for cap in self.audio_captures:
                dur = f"{cap.get('duration', 0):.1f}s" if cap.get("duration") else "N/A"
                sections.append(
                    f"<tr><td>{_esc(cap.get('file', ''))}</td>"
                    f"<td>{dur}</td>"
                    f"<td>{_esc(cap.get('description', ''))}</td></tr>"
                )
            sections.append("</table>")
            sections.append("</div>")

        # Notes
        if self.notes:
            sections.append('<div class="section">')
            sections.append("<h2>Analyst Notes</h2>")
            for note in self.notes:
                sections.append(f"<p>{_esc(note)}</p>")
            sections.append("</div>")

        content = "\n".join(sections)
        html = _HTML_TEMPLATE.format(
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            content=content,
        )

        outdir = os.path.dirname(output)
        if outdir:
            os.makedirs(outdir, exist_ok=True)
        with open(output, "w") as f:
            f.write(html)
        success(f"HTML report generated: {output}")
        return output

    def generate_json(self, output: str = "report.json") -> str:
        """Generate a machine-readable JSON report."""
        report = {
            "generated": datetime.now().isoformat(),
            "tool": "BT-Tap",
            "summary": {
                "devices_scanned": len(self.scan_results),
                "total_findings": len(self.vuln_findings),
                "confirmed": sum(1 for f in self.vuln_findings if f.get("status") == "confirmed"),
                "potential": sum(1 for f in self.vuln_findings if f.get("status") == "potential"),
                "unverified": sum(1 for f in self.vuln_findings if f.get("status") == "unverified"),
                "high_severity": sum(1 for f in self.vuln_findings
                                     if f.get("severity", "").lower() in ("high", "critical")),
            },
            "fingerprint": self.fingerprint_results,
            "scan_results": self.scan_results,
            "vulnerabilities": self.vuln_findings,
            "pbap_data": self.pbap_results,
            "map_data": self.map_results,
            "attack_results": self.attack_results,
            "recon_results": self.recon_results,
            "fuzz_results": self.fuzz_results,
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


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
