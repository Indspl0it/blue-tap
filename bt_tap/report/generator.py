"""Pentest report generation for BT-Tap.

Generates HTML or JSON reports from attack session data including scan results,
vulnerability findings, PBAP/MAP dumps, fuzzing campaigns, and analysis notes.
"""

import json
import os
import shutil
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
  .crash-card {{ border-left: 4px solid #ff4444; padding: 10px; margin: 15px 0; background: #1a1a30; }}
  .crash-card.high {{ border-left-color: #ff6b35; }}
  .crash-card.medium {{ border-left-color: #ffaa00; }}
  .hexdump {{ font-family: 'Courier New', monospace; font-size: 12px; line-height: 1.4; }}
  .evidence-list {{ list-style: none; padding: 0; }}
  .evidence-list li::before {{ content: "\\01F4CE "; }}
  .reproduced-yes {{ color: #00ff9f; }}
  .reproduced-no {{ color: #ff4444; }}
  .crash-rate {{ font-size: 0.85em; color: #888; }}
  .severity-critical {{ background: #ff4444; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold; }}
  .severity-high {{ background: #ff6b35; color: #fff; padding: 2px 6px; border-radius: 3px; font-weight: bold; }}
  .severity-medium {{ background: #ffaa00; color: #000; padding: 2px 6px; border-radius: 3px; }}
  .severity-low {{ background: #88cc00; color: #000; padding: 2px 6px; border-radius: 3px; }}
  .severity-info {{ background: #4488ff; color: #fff; padding: 2px 6px; border-radius: 3px; }}
  .fuzz-stat {{ display: inline-block; margin: 5px 15px 5px 0; }}
  .fuzz-stat .value {{ font-size: 1.4em; font-weight: bold; color: #00d4ff; }}
  .fuzz-stat .label {{ font-size: 0.85em; color: #888; }}
  .mono {{ font-family: 'Courier New', monospace; }}
</style>
</head>
<body>
<h1>BT-Tap Pentest Report</h1>
<p class="meta">Generated: {generated} | Tool: BT-Tap v1.5.0</p>

{content}

</body>
</html>"""


def _format_hexdump(data_hex: str, bytes_per_line: int = 16) -> str:
    """Format a hex string as a traditional hexdump with offset, hex, and ASCII columns.

    Args:
        data_hex: Hex-encoded data string (e.g. "80001a10...").
        bytes_per_line: Number of bytes per line (default 16).

    Returns:
        Formatted hexdump string.
    """
    try:
        raw = bytes.fromhex(data_hex)
    except (ValueError, TypeError):
        return f"(invalid hex data: {data_hex[:60]}...)" if data_hex else "(no data)"

    lines = ["Offset  Hex                                              ASCII"]
    for offset in range(0, len(raw), bytes_per_line):
        chunk = raw[offset:offset + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to fixed width
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}    {hex_part}  {ascii_part}")
    return "\n".join(lines)


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
        # Structured fuzz campaign data
        self._fuzz_campaign_stats = {}
        self._fuzz_crashes = []
        self._fuzz_evidence_dir = ""
        self._fuzz_corpus_stats = {}
        self._fuzz_evidence_files = []

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

    def add_fuzz_campaign_results(self, campaign_stats: dict, crashes: list[dict],
                                   evidence_dir: str = "") -> None:
        """Add detailed fuzzing campaign results with evidence.

        Args:
            campaign_stats: Dict with runtime, packets_sent, crashes, protocols, strategy, etc.
            crashes: List of crash dicts from CrashDB (each has payload_hex, protocol,
                     crash_type, severity, mutation_log, response_hex, timestamp, reproduced)
            evidence_dir: Path to evidence directory (pcaps, crash payloads)
        """
        self._fuzz_campaign_stats = campaign_stats
        self._fuzz_crashes = crashes
        self._fuzz_evidence_dir = evidence_dir

    def load_fuzz_from_session(self, session_dir: str) -> None:
        """Auto-load fuzzing data from a session's fuzz/ subdirectory.

        Looks for:
        - fuzz/crashes.db -- loads all crashes
        - fuzz/campaign_state.json -- loads campaign stats
        - fuzz/campaign_stats.json -- loads final stats
        - fuzz/corpus/ -- counts seeds per protocol
        - fuzz/capture.btsnoop -- notes pcap location
        - fuzz/<protocol>_crashes.db -- per-protocol crash DBs from targeted commands
        """
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
                from bt_tap.fuzz.crash_db import CrashDB
                with CrashDB(crashes_db_path) as db:
                    self._fuzz_crashes = db.get_crashes()
                info(f"Loaded {len(self._fuzz_crashes)} crashes from crashes.db")
            except Exception as exc:
                info(f"Could not load crashes.db: {exc}")

        # Also check per-protocol crash DBs
        for fname in os.listdir(fuzz_dir):
            if fname.endswith("_crashes.db") and fname != "crashes.db":
                proto_db_path = os.path.join(fuzz_dir, fname)
                try:
                    from bt_tap.fuzz.crash_db import CrashDB
                    with CrashDB(proto_db_path) as db:
                        proto_crashes = db.get_crashes()
                        # Deduplicate by payload_hash
                        existing_hashes = {c.get("payload_hash") for c in self._fuzz_crashes}
                        for crash in proto_crashes:
                            if crash.get("payload_hash") not in existing_hashes:
                                self._fuzz_crashes.append(crash)
                                existing_hashes.add(crash.get("payload_hash"))
                    info(f"Loaded additional crashes from {fname}")
                except Exception as exc:
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
                    # Seeds directly in corpus dir
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

    def generate_evidence_package(self, session_dir: str, output_dir: str) -> str:
        """Generate an evidence package directory with all fuzz artifacts.

        Creates:
        output_dir/
          evidence_manifest.json      -- index of all evidence files
          crashes/
            crash_001_<protocol>.bin  -- raw crash payload bytes
            crash_001_<protocol>.txt  -- human-readable description
          pcaps/
            campaign_capture.btsnoop  -- full campaign pcap (copied)
            replay_001.btsnoop        -- individual crash replay pcaps
          corpus/
            protocol_seed_counts.json -- corpus statistics
          stats/
            campaign_stats.json       -- campaign statistics

        Returns path to evidence_manifest.json
        """
        os.makedirs(output_dir, exist_ok=True)
        crashes_dir = os.path.join(output_dir, "crashes")
        pcaps_dir = os.path.join(output_dir, "pcaps")
        corpus_dir = os.path.join(output_dir, "corpus")
        stats_dir = os.path.join(output_dir, "stats")
        for d in (crashes_dir, pcaps_dir, corpus_dir, stats_dir):
            os.makedirs(d, exist_ok=True)

        fuzz_dir = os.path.join(session_dir, "fuzz")
        manifest_crashes = []

        # If we haven't loaded yet, do so now
        if not self._fuzz_crashes and not self._fuzz_campaign_stats:
            self.load_fuzz_from_session(session_dir)

        # Export crash payloads
        for i, crash in enumerate(self._fuzz_crashes, 1):
            protocol = crash.get("protocol", "unknown").replace("/", "-").replace(" ", "_")
            bin_name = f"crash_{i:03d}_{protocol}.bin"
            txt_name = f"crash_{i:03d}_{protocol}.txt"

            # Write binary payload
            payload_hex = crash.get("payload_hex", "")
            try:
                payload_bytes = bytes.fromhex(payload_hex)
                with open(os.path.join(crashes_dir, bin_name), "wb") as f:
                    f.write(payload_bytes)
            except (ValueError, OSError):
                pass

            # Write human-readable description
            desc_lines = [
                f"Crash #{i}",
                f"Severity: {crash.get('severity', 'UNKNOWN')}",
                f"Protocol: {crash.get('protocol', 'unknown')}",
                f"Crash Type: {crash.get('crash_type', 'unknown')}",
                f"Timestamp: {crash.get('timestamp', 'N/A')}",
                f"Payload Size: {crash.get('payload_len', len(payload_hex) // 2)} bytes",
                f"Reproduced: {'Yes' if crash.get('reproduced') else 'No'}",
                f"Target: {crash.get('target_addr', 'N/A')}",
                "",
                "Mutation Log:",
                crash.get("mutation_log", "(none)") or "(none)",
                "",
                "Payload Hexdump:",
                _format_hexdump(payload_hex),
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
                "id": i,
                "severity": crash.get("severity", "UNKNOWN"),
                "protocol": crash.get("protocol", "unknown"),
                "crash_type": crash.get("crash_type", "unknown"),
                "payload_file": f"crashes/{bin_name}",
                "description_file": f"crashes/{txt_name}",
                "payload_hex": payload_hex[:64] + ("..." if len(payload_hex) > 64 else ""),
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

        # Copy replay pcaps if they exist
        evidence_subdir = os.path.join(fuzz_dir, "evidence")
        if os.path.isdir(evidence_subdir):
            for fname in sorted(os.listdir(evidence_subdir)):
                if fname.endswith(".btsnoop"):
                    src = os.path.join(evidence_subdir, fname)
                    dst = os.path.join(pcaps_dir, fname)
                    try:
                        shutil.copy2(src, dst)
                        pcap_files.append(f"pcaps/{fname}")
                    except OSError:
                        pass

        # Write corpus statistics
        corpus_stats = self._fuzz_corpus_stats or {}
        if not corpus_stats:
            # Derive from campaign stats protocol_breakdown
            breakdown = self._fuzz_campaign_stats.get("protocol_breakdown", {})
            corpus_stats = breakdown
        try:
            with open(os.path.join(corpus_dir, "protocol_seed_counts.json"), "w") as f:
                json.dump(corpus_stats, f, indent=2)
        except OSError:
            pass

        # Write campaign stats
        if self._fuzz_campaign_stats:
            try:
                with open(os.path.join(stats_dir, "campaign_stats.json"), "w") as f:
                    json.dump(self._fuzz_campaign_stats, f, indent=2, default=str)
            except OSError:
                pass

        # Build manifest
        manifest = {
            "generated": datetime.now().isoformat(),
            "tool": "BT-Tap Fuzzer",
            "target": self._fuzz_campaign_stats.get("target", ""),
            "campaign": {
                "duration_seconds": self._fuzz_campaign_stats.get("runtime_seconds", 0),
                "test_cases": self._fuzz_campaign_stats.get("packets_sent", 0),
                "strategy": self._fuzz_campaign_stats.get("strategy", "unknown"),
                "protocols": self._fuzz_campaign_stats.get("protocols", []),
            },
            "crashes": manifest_crashes,
            "pcaps": pcap_files,
            "corpus_stats": corpus_stats,
        }

        manifest_path = os.path.join(output_dir, "evidence_manifest.json")
        try:
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2, default=str)
            success(f"Evidence package generated: {output_dir}")
        except OSError as exc:
            error(f"Could not write evidence manifest: {exc}")

        return manifest_path

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

        # Auto-detect fuzz/ subdirectory and load structured fuzz data
        fuzz_dir = os.path.join(dump_dir, "fuzz")
        if os.path.isdir(fuzz_dir):
            self.load_fuzz_from_session(dump_dir)

        # Load any JSON files in subdirectories
        for root, dirs, files in os.walk(dump_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, dump_dir)

                if fname.endswith(".json") and fname != "attack_results.json":
                    # Skip fuzz files already loaded via load_fuzz_from_session
                    rel_lower = rel.lower()
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

    def _build_fuzz_html(self) -> list[str]:
        """Build the detailed fuzzing campaign HTML section.

        Returns a list of HTML strings to be joined into the report.
        """
        sections = []

        has_campaign = bool(self._fuzz_campaign_stats)
        has_crashes = bool(self._fuzz_crashes)

        if not has_campaign and not has_crashes and not self.fuzz_results:
            return sections

        sections.append('<div class="section">')
        sections.append("<h2>Fuzzing Campaign Results</h2>")

        # ---- Executive Summary ----
        if has_campaign:
            stats = self._fuzz_campaign_stats
            runtime = stats.get("runtime_seconds", 0)
            packets = stats.get("packets_sent", 0)
            pps = stats.get("packets_per_second", 0)
            strategy = stats.get("strategy", "unknown")
            protocols = stats.get("protocols", [])
            total_crashes = stats.get("crashes", len(self._fuzz_crashes))
            result_status = stats.get("result", "unknown")

            # Format runtime
            hours = int(runtime // 3600)
            minutes = int((runtime % 3600) // 60)
            secs = int(runtime % 60)
            runtime_str = f"{hours}h {minutes}m {secs}s" if hours else f"{minutes}m {secs}s"

            sections.append("<h3>Executive Summary</h3>")
            sections.append('<div class="summary">')
            sections.append(
                f'<div class="fuzz-stat"><span class="value">{runtime_str}</span>'
                f'<br><span class="label">Duration</span></div>'
            )
            sections.append(
                f'<div class="fuzz-stat"><span class="value">{packets:,}</span>'
                f'<br><span class="label">Test Cases Sent</span></div>'
            )
            sections.append(
                f'<div class="fuzz-stat"><span class="value">{pps:.1f}/s</span>'
                f'<br><span class="label">Send Rate</span></div>'
            )
            sections.append(
                f'<div class="fuzz-stat"><span class="value">{total_crashes}</span>'
                f'<br><span class="label">Crashes Found</span></div>'
            )
            sections.append("</div>")

            sections.append(f"<p><strong>Strategy:</strong> {_esc(strategy)}</p>")
            sections.append(
                f"<p><strong>Protocols Tested:</strong> "
                f"{_esc(', '.join(protocols) if protocols else 'N/A')}</p>"
            )
            sections.append(f"<p><strong>Campaign Result:</strong> {_esc(result_status)}</p>")

            # Crash severity breakdown
            if has_crashes:
                sev_counts = {}
                reproduced_count = 0
                for crash in self._fuzz_crashes:
                    sev = crash.get("severity", "UNKNOWN")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    if crash.get("reproduced"):
                        reproduced_count += 1

                breakdown_parts = []
                for sev_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    count = sev_counts.get(sev_level, 0)
                    if count > 0:
                        css = f"severity-{sev_level.lower()}"
                        breakdown_parts.append(
                            f'<span class="{css}">{count} {sev_level}</span>'
                        )
                if breakdown_parts:
                    sections.append(
                        f"<p><strong>Crash Breakdown:</strong> {' &nbsp; '.join(breakdown_parts)}</p>"
                    )

                total = len(self._fuzz_crashes)
                repro_rate = (reproduced_count / total * 100) if total > 0 else 0
                sections.append(
                    f"<p><strong>Reproduction Rate:</strong> "
                    f"{reproduced_count}/{total} ({repro_rate:.0f}%)</p>"
                )

        # ---- Crash Findings Table ----
        if has_crashes:
            sections.append("<h3>Crash Findings</h3>")
            sections.append(
                "<table>"
                "<tr><th>#</th><th>Severity</th><th>Protocol</th>"
                "<th>Crash Type</th><th>Payload Size</th>"
                "<th>Payload Preview</th><th>Mutation</th>"
                "<th>Reproduced?</th><th>Timestamp</th></tr>"
            )
            for i, crash in enumerate(self._fuzz_crashes, 1):
                sev = crash.get("severity", "UNKNOWN")
                css = f"severity-{sev.lower()}"
                protocol = crash.get("protocol", "unknown")
                crash_type = crash.get("crash_type", "unknown")
                payload_len = crash.get("payload_len", 0)
                payload_hex = crash.get("payload_hex", "")
                # Show first 24 bytes (48 hex chars)
                preview = payload_hex[:48]
                if len(payload_hex) > 48:
                    preview += "..."
                mutation = crash.get("mutation_log", "") or ""
                # Truncate mutation for table display
                if len(mutation) > 40:
                    mutation = mutation[:37] + "..."
                reproduced = crash.get("reproduced", 0)
                repro_display = (
                    '<span class="reproduced-yes">Yes</span>'
                    if reproduced
                    else '<span class="reproduced-no">No</span>'
                )
                timestamp = crash.get("timestamp", "")

                sections.append(
                    f"<tr>"
                    f"<td>{i}</td>"
                    f'<td><span class="{css}">{_esc(sev)}</span></td>'
                    f"<td>{_esc(protocol)}</td>"
                    f"<td>{_esc(crash_type)}</td>"
                    f"<td>{payload_len} bytes</td>"
                    f'<td class="mono">{_esc(preview)}</td>'
                    f"<td>{_esc(mutation)}</td>"
                    f"<td>{repro_display}</td>"
                    f"<td>{_esc(timestamp)}</td>"
                    f"</tr>"
                )
            sections.append("</table>")

            # ---- Crash Detail Cards (CRITICAL and HIGH only) ----
            critical_high = [
                (i, c) for i, c in enumerate(self._fuzz_crashes, 1)
                if c.get("severity", "").upper() in ("CRITICAL", "HIGH")
            ]
            if critical_high:
                sections.append("<h3>Crash Details</h3>")
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

                    card_class = "crash-card"
                    if sev == "HIGH":
                        card_class += " high"

                    repro_str = (
                        '<span class="reproduced-yes">Yes</span>'
                        if reproduced
                        else '<span class="reproduced-no">No</span>'
                    )

                    sections.append(f'<div class="{card_class}">')
                    sections.append(
                        f"<h4>Crash #{idx} &mdash; {_esc(sev)} &mdash; "
                        f"{_esc(protocol)} &mdash; {_esc(crash_type)}</h4>"
                    )
                    sections.append(f"<p><strong>Timestamp:</strong> {_esc(timestamp)}</p>")
                    sections.append(f"<p><strong>Protocol:</strong> {_esc(protocol)}</p>")
                    sections.append(
                        f"<p><strong>Crash Type:</strong> {_esc(crash_type)}</p>"
                    )
                    sections.append(f"<p><strong>Reproduced:</strong> {repro_str}</p>")

                    sections.append(f"<h5>Payload ({payload_len} bytes)</h5>")
                    sections.append(
                        f'<pre class="hexdump">{_esc(_format_hexdump(payload_hex))}</pre>'
                    )

                    sections.append("<h5>Mutation Log</h5>")
                    sections.append(f"<pre>{_esc(mutation)}</pre>")

                    sections.append("<h5>Response</h5>")
                    if response_hex:
                        sections.append(
                            f'<pre class="hexdump">{_esc(_format_hexdump(response_hex))}</pre>'
                        )
                    else:
                        sections.append("<pre>No response (connection dropped immediately)</pre>")

                    # Evidence references
                    if self._fuzz_evidence_dir:
                        sections.append("<h5>Evidence</h5>")
                        proto_safe = protocol.replace("/", "-").replace(" ", "_")
                        sections.append(
                            f"<p>Crash payload saved: fuzz/evidence/crash_{idx:03d}.bin</p>"
                        )
                        capture_path = os.path.join(self._fuzz_evidence_dir, "capture.btsnoop")
                        if os.path.exists(capture_path):
                            sections.append(
                                f"<p>Pcap capture: fuzz/capture.btsnoop (frame at {_esc(timestamp)})</p>"
                            )

                    notes = crash.get("notes", "")
                    if notes:
                        sections.append(f"<p><strong>Notes:</strong> {_esc(notes)}</p>")

                    sections.append("</div>")

        # ---- Protocol Coverage Table ----
        if has_campaign and has_crashes:
            stats = self._fuzz_campaign_stats
            breakdown = stats.get("protocol_breakdown", {})
            if breakdown:
                # Count crashes per protocol
                crash_by_proto = {}
                for crash in self._fuzz_crashes:
                    proto = crash.get("protocol", "unknown")
                    crash_by_proto[proto] = crash_by_proto.get(proto, 0) + 1

                sections.append("<h3>Protocol Coverage</h3>")
                sections.append(
                    "<table><tr><th>Protocol</th><th>Test Cases Sent</th>"
                    "<th>Crashes</th><th>Crash Rate</th></tr>"
                )
                for proto, sent in sorted(breakdown.items()):
                    crashes_for_proto = crash_by_proto.get(proto, 0)
                    rate = (crashes_for_proto / sent * 100) if sent > 0 else 0
                    sections.append(
                        f"<tr><td>{_esc(proto)}</td>"
                        f"<td>{sent:,}</td>"
                        f"<td>{crashes_for_proto}</td>"
                        f'<td class="crash-rate">{rate:.2f}%</td></tr>'
                    )
                sections.append("</table>")

        # ---- Evidence Package Summary ----
        if self._fuzz_evidence_files:
            sections.append("<h3>Evidence Package</h3>")
            sections.append('<ul class="evidence-list">')
            for desc, path in self._fuzz_evidence_files:
                rel_path = os.path.relpath(path, self._fuzz_evidence_dir) if self._fuzz_evidence_dir else desc
                sections.append(f"<li>{_esc(desc)} &mdash; <code>{_esc(rel_path)}</code></li>")
            sections.append("</ul>")

        if self._fuzz_corpus_stats:
            sections.append("<h4>Corpus Statistics</h4>")
            sections.append("<table><tr><th>Protocol</th><th>Seeds</th></tr>")
            for proto, count in sorted(self._fuzz_corpus_stats.items()):
                sections.append(f"<tr><td>{_esc(proto)}</td><td>{count}</td></tr>")
            sections.append("</table>")

        if self._fuzz_evidence_dir:
            sections.append(
                f"<p>Full evidence directory: <code>{_esc(self._fuzz_evidence_dir)}</code></p>"
            )

        # ---- Fallback: raw fuzz_results (from non-campaign JSON files) ----
        if self.fuzz_results and not has_campaign and not has_crashes:
            for entry in self.fuzz_results:
                src = entry.get("source", "fuzz")
                sections.append(f"<h3>{_esc(src)}</h3>")
                sections.append(
                    f"<pre>{_esc(json.dumps(entry.get('data', entry), indent=2, default=str)[:2000])}</pre>"
                )

        sections.append("</div>")
        return sections

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

        # Fuzz summary in executive section
        has_fuzz_campaign = bool(self._fuzz_campaign_stats)
        has_fuzz_crashes = bool(self._fuzz_crashes)
        if has_fuzz_campaign or has_fuzz_crashes or self.fuzz_results:
            crash_count = len(self._fuzz_crashes) if has_fuzz_crashes else len(self.fuzz_results)
            packets = self._fuzz_campaign_stats.get("packets_sent", 0) if has_fuzz_campaign else 0
            sections.append(
                f"<p>Fuzzing: {packets:,} test cases, {crash_count} crashes</p>"
            )
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

        # Fuzz Results (detailed campaign section)
        sections.extend(self._build_fuzz_html())

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
        # Build detailed fuzz section for JSON
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
            # Aggregate crash stats
            for crash in self._fuzz_crashes:
                sev = crash.get("severity", "UNKNOWN")
                proto = crash.get("protocol", "unknown")
                ctype = crash.get("crash_type", "unknown")
                fuzz_data["crash_summary"]["by_severity"][sev] = (
                    fuzz_data["crash_summary"]["by_severity"].get(sev, 0) + 1
                )
                fuzz_data["crash_summary"]["by_protocol"][proto] = (
                    fuzz_data["crash_summary"]["by_protocol"].get(proto, 0) + 1
                )
                fuzz_data["crash_summary"]["by_type"][ctype] = (
                    fuzz_data["crash_summary"]["by_type"].get(ctype, 0) + 1
                )

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
                "fuzz_test_cases": self._fuzz_campaign_stats.get("packets_sent", 0),
                "fuzz_crashes": len(self._fuzz_crashes),
            },
            "fingerprint": self.fingerprint_results,
            "scan_results": self.scan_results,
            "vulnerabilities": self.vuln_findings,
            "pbap_data": self.pbap_results,
            "map_data": self.map_results,
            "attack_results": self.attack_results,
            "recon_results": self.recon_results,
            "fuzzing": fuzz_data if fuzz_data else self.fuzz_results,
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
