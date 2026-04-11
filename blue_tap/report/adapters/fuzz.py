"""Fuzz report adapter."""

from __future__ import annotations

import html as _html_mod
import math
from typing import Any

from blue_tap.core.report_contract import ReportAdapter, SectionBlock, SectionModel
from blue_tap.core.result_schema import envelope_executions, envelope_module_data


def _esc(text: str) -> str:
    return _html_mod.escape(str(text), quote=True)


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


def _runtime_str(seconds: float) -> str:
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours}h {minutes}m {secs}s" if hours else f"{minutes}m {secs}s"


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

            # Extract campaign-level intelligence
            campaign_stats = module_data.get("campaign_stats", {})
            if isinstance(campaign_stats, dict):
                report_state.setdefault("campaign_stats_list", []).append(campaign_stats)

                sc = campaign_stats.get("state_coverage", {})
                if sc:
                    # Merge into a flat state dict (last writer wins; campaigns usually single)
                    report_state["campaign_state_coverage"] = sc

                fw = campaign_stats.get("field_weights", {})
                if fw:
                    existing = report_state.get("campaign_field_weights", {})
                    existing.update(fw)
                    report_state["campaign_field_weights"] = existing

                hm = campaign_stats.get("health_monitor", {})
                if isinstance(hm, dict):
                    events = hm.get("events", [])
                    if events:
                        report_state.setdefault("campaign_health_events", []).extend(events)

            # Baselines from module_data directly (some producers store them there)
            baselines = module_data.get("baselines", {})
            if isinstance(baselines, dict) and baselines:
                existing_bl = report_state.get("campaign_baselines", {})
                existing_bl.update(baselines)
                report_state["campaign_baselines"] = existing_bl

            # Evidence dir for file references in crash cards
            fuzz_dir = module_data.get("session_fuzz_dir", "")
            if fuzz_dir:
                report_state["evidence_dir"] = fuzz_dir

            # Corpus stats
            cs = module_data.get("corpus_stats", {})
            if isinstance(cs, dict) and cs:
                existing_cs = report_state.get("corpus_stats", {})
                existing_cs.update(cs)
                report_state["corpus_stats"] = existing_cs

            # Evidence files list
            ev_files = module_data.get("evidence_files", [])
            if ev_files:
                report_state.setdefault("evidence_files", []).extend(ev_files)

            # Per-protocol execution data
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

    # ------------------------------------------------------------------
    # Section building helpers
    # ------------------------------------------------------------------

    def _build_campaign_overview_block(self, stats: dict, crashes: list) -> SectionBlock:
        """Badge group + narrative for campaign overview."""
        runtime = stats.get("runtime_seconds", 0)
        packets = stats.get("packets_sent", 0)
        pps = stats.get("packets_per_second", 0)
        strategy = stats.get("strategy", "unknown")
        protocols = stats.get("protocols", [])
        total_crashes = stats.get("crashes", len(crashes))
        result_status = stats.get("result", "unknown")

        runtime_s = _runtime_str(float(runtime))

        # Build narrative HTML
        critical_count = sum(
            1 for c in crashes if c.get("severity", "").upper() == "CRITICAL"
        )
        if total_crashes:
            crash_text = (
                f'{total_crashes} crash{"es" if total_crashes != 1 else ""} '
                f'{"were" if total_crashes != 1 else "was"} detected'
            )
            if critical_count:
                crash_text += (
                    f', including {critical_count} critical crash'
                    f'{"es" if critical_count != 1 else ""} that caused the '
                    f'target device to reboot — indicating exploitable memory '
                    f'corruption vulnerabilities in the Bluetooth stack.'
                )
            else:
                crash_text += (
                    ", indicating input handling weaknesses in the target's "
                    "Bluetooth stack implementation."
                )
        else:
            crash_text = (
                "No crashes were detected during the fuzzing campaign, "
                "suggesting the target's Bluetooth stack handles malformed "
                "input gracefully for the tested protocols."
            )

        narrative = (
            f"<h3>Campaign Overview</h3>"
            f'<div class="summary">'
            f'<div class="fuzz-stat"><span class="value">{_esc(runtime_s)}</span><br>'
            f'<span class="label">Duration</span></div>'
            f'<div class="fuzz-stat"><span class="value">{packets:,}</span><br>'
            f'<span class="label">Test Cases</span></div>'
            f'<div class="fuzz-stat"><span class="value">{pps:.1f}/s</span><br>'
            f'<span class="label">Send Rate</span></div>'
            f'<div class="fuzz-stat"><span class="value">{total_crashes}</span><br>'
            f'<span class="label">Crashes</span></div>'
            f"</div>"
            f"<p><strong>Strategy:</strong> {_esc(strategy)}</p>"
            f"<p><strong>Protocols Tested:</strong> "
            f"{_esc(', '.join(protocols) if protocols else 'N/A')}</p>"
            f"<p><strong>Campaign Result:</strong> {_esc(result_status)}</p>"
            f"<p>Protocol fuzzing sent {packets:,} test cases across "
            f"{len(protocols)} protocol(s) over {_esc(runtime_s)}. "
            f"{_esc(crash_text)}</p>"
        )
        return SectionBlock("html_raw", {"html": narrative})

    def _build_severity_breakdown_block(self, crashes: list) -> SectionBlock | None:
        if not crashes:
            return None
        sev_counts: dict[str, int] = {}
        reproduced_count = 0
        for crash in crashes:
            sev = crash.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if crash.get("reproduced"):
                reproduced_count += 1

        parts = []
        for sl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = sev_counts.get(sl, 0)
            if c:
                parts.append(f'<span class="severity-badge severity-{sl}">{c} {sl}</span>')

        total = len(crashes)
        repro_rate = (reproduced_count / total * 100) if total > 0 else 0
        html = (
            f"<p><strong>Crash Breakdown:</strong> {' '.join(parts)}</p>"
            f"<p><strong>Reproduction Rate:</strong> "
            f"{reproduced_count}/{total} ({repro_rate:.0f}%)</p>"
        )
        return SectionBlock("html_raw", {"html": html})

    def _build_crash_detail_cards_block(
        self, crashes: list, evidence_dir: str
    ) -> SectionBlock | None:
        """Crash detail cards for CRITICAL and HIGH crashes (html_raw for hex dumps)."""
        critical_high = [
            (i, c) for i, c in enumerate(crashes, 1)
            if c.get("severity", "").upper() in ("CRITICAL", "HIGH")
        ]
        if not critical_high:
            return None

        parts = ["<h3>Crash Details (Critical/High)</h3>"]
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
            repro_str = (
                '<span class="reproduced-yes">Yes</span>'
                if reproduced
                else '<span class="reproduced-no">No</span>'
            )

            parts.append(f'<div class="{card_css}">')
            parts.append(
                f'<h4>Crash #{idx} '
                f'<span class="severity-badge severity-{sev}">{_esc(sev)}</span> '
                f'{_esc(protocol)} / {_esc(crash_type)}</h4>'
            )
            parts.append(
                f'<p><strong>Timestamp:</strong> {_esc(timestamp)} '
                f'| <strong>Target:</strong> <code>{_esc(target_addr)}</code> '
                f'| <strong>Reproduced:</strong> {repro_str}</p>'
            )

            # Reproduction steps
            parts.append(
                '<div class="evidence-block">'
                '<div class="ev-label">Reproduction Steps</div>'
                '<pre>'
                f'1. Connect to target: {_esc(target_addr)}\n'
                f'2. Select protocol: {_esc(protocol)}\n'
                f'3. Send payload ({payload_len} bytes):\n'
                f'   blue-tap fuzz replay --payload-hex {_esc(payload_hex[:80])}'
                f'{"..." if len(payload_hex) > 80 else ""}\n'
                f'4. Observe: {_esc(crash_type)}'
                '</pre></div>'
            )

            parts.append(f'<h5>Payload ({payload_len} bytes)</h5>')
            parts.append(f'<pre class="hexdump">{_esc(_format_hexdump(payload_hex))}</pre>')

            parts.append("<h5>Mutation Log</h5>")
            parts.append(f"<pre>{_esc(mutation)}</pre>")

            parts.append("<h5>Device Response</h5>")
            if response_hex:
                parts.append(f'<pre class="hexdump">{_esc(_format_hexdump(response_hex))}</pre>')
            else:
                parts.append("<pre>No response (connection dropped immediately)</pre>")

            if evidence_dir:
                proto_safe = protocol.replace("/", "-").replace(" ", "_")
                parts.append(
                    '<div class="evidence-block">'
                    '<div class="ev-label">Evidence Files</div>'
                    f'<p>Crash payload: '
                    f'<code>crashes/crash_{idx:03d}_{_esc(proto_safe)}.bin</code></p>'
                    '</div>'
                )

            notes = crash.get("notes", "")
            if notes:
                parts.append(f"<p><strong>Notes:</strong> {_esc(notes)}</p>")

            parts.append("</div>")

        return SectionBlock("html_raw", {"html": "\n".join(parts)})

    def _build_protocol_coverage_block(
        self, stats: dict, crashes: list
    ) -> SectionBlock | None:
        breakdown = stats.get("protocol_breakdown", {})
        if not breakdown:
            return None
        crash_by_proto: dict[str, int] = {}
        for crash in crashes:
            p = crash.get("protocol", "unknown")
            crash_by_proto[p] = crash_by_proto.get(p, 0) + 1

        rows = []
        for proto, sent in sorted(breakdown.items()):
            crashes_for = crash_by_proto.get(proto, 0)
            rate = (crashes_for / sent * 100) if sent > 0 else 0
            rows.append([proto, f"{sent:,}", str(crashes_for), f"{rate:.2f}%"])

        return SectionBlock(
            "table",
            {
                "headers": ["Protocol", "Test Cases Sent", "Crashes", "Crash Rate"],
                "rows": rows,
            },
        )

    def _build_state_coverage_block(self, sc: dict) -> SectionBlock | None:
        if not sc:
            return None
        total_states = sc.get("total_states", 0)
        total_trans = sc.get("total_transitions", 0)
        protos = sc.get("protocols_tracked") or sc.get("protocols", {})
        num_protos = len(protos) if isinstance(protos, (dict, list)) else 0

        intro = (
            f"<h3>Protocol State Coverage</h3>"
            f"<p>The fuzzer explored {total_states} unique protocol state(s) "
            f"across {total_trans} transition(s)"
            f'{" in " + str(num_protos) + " protocol(s)" if num_protos else ""}. '
            f"Higher coverage indicates more thorough testing of the target's "
            f"protocol implementation.</p>"
            f"<p>Total states discovered: <strong>{total_states}</strong> | "
            f"Total transitions: <strong>{total_trans}</strong></p>"
        )

        if isinstance(protos, dict) and protos:
            rows = []
            for proto, pdata in sorted(protos.items()):
                states = pdata.get("states", 0) if isinstance(pdata, dict) else 0
                trans = pdata.get("transitions", 0) if isinstance(pdata, dict) else 0
                rows.append([proto, str(states), str(trans)])
            table_html = (
                "<table><tr><th>Protocol</th><th>States</th><th>Transitions</th></tr>"
                + "".join(
                    f"<tr><td>{_esc(r[0])}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
                    for r in rows
                )
                + "</table>"
            )
            html = intro + table_html
        elif isinstance(protos, list) and protos:
            html = intro + f"<p>Protocols tracked: {_esc(', '.join(protos))}</p>"
        else:
            html = intro

        return SectionBlock("html_raw", {"html": html})

    def _build_field_weights_block(self, field_weights: dict) -> SectionBlock | None:
        if not field_weights:
            return None
        parts = [
            "<h3>Field Mutation Weight Analysis</h3>",
            "<p>The fuzzer learned which protocol fields are most likely to "
            "trigger anomalies. Fields with high mutation weights produced more "
            "interesting target behavior when mutated.</p>",
            "<p>Fields ranked by anomaly/crash production. Higher weight = "
            "more productive for finding bugs.</p>",
        ]
        for proto, weights in sorted(field_weights.items()):
            if not isinstance(weights, dict) or not weights:
                continue
            parts.append(f"<h4>{_esc(proto)}</h4>")
            parts.append("<table><tr><th>Field</th><th>Weight</th><th>Bar</th></tr>")
            sorted_fields = sorted(weights.items(), key=lambda x: float(x[1]) if isinstance(x[1], (int, float)) else 0, reverse=True)
            for fname, w in sorted_fields:
                try:
                    w_float = float(w)
                except (TypeError, ValueError):
                    w_float = 0.0
                bar_width = int(w_float * 200)
                bar_color = (
                    "#D43F3A" if w_float > 0.3
                    else "#EE9336" if w_float > 0.15
                    else "#4CAE4C"
                )
                parts.append(
                    f"<tr><td><code>{_esc(fname)}</code></td>"
                    f"<td>{w_float:.1%}</td>"
                    f'<td><div style="background:{bar_color};width:{bar_width}px;'
                    f'height:14px;border-radius:3px;display:inline-block"></div></td></tr>'
                )
            parts.append("</table>")
        return SectionBlock("html_raw", {"html": "\n".join(parts)})

    def _build_baselines_block(self, baselines: dict) -> SectionBlock | None:
        if not baselines:
            return None
        rows = []
        for proto, bl in sorted(baselines.items()):
            if not isinstance(bl, dict):
                continue
            rows.append([
                proto,
                str(bl.get("samples", 0)),
                f"{bl.get('mean_len', 0):.0f}B",
                f"{bl.get('mean_latency_ms', 0):.0f}ms",
                str(bl.get("seen_opcodes", [])),
            ])
        if not rows:
            return None
        html = (
            "<h3>Target Response Baselines</h3>"
            "<p>Normal response behavior learned before fuzzing began.</p>"
            "<table><tr><th>Protocol</th><th>Samples</th><th>Avg Size</th>"
            "<th>Avg Latency</th><th>Response Opcodes</th></tr>"
            + "".join(
                f"<tr><td>{_esc(r[0])}</td><td>{r[1]}</td><td>{r[2]}</td>"
                f"<td>{r[3]}</td><td>{_esc(r[4])}</td></tr>"
                for r in rows
            )
            + "</table>"
        )
        return SectionBlock("html_raw", {"html": html})

    def _build_health_events_block(self, health_events: list) -> SectionBlock | None:
        if not health_events:
            return None
        num_events = len(health_events)
        reboot_events = sum(
            1 for e in health_events
            if isinstance(e, dict) and e.get("status", "") in ("rebooted", "unreachable")
        )
        events = []
        for evt in health_events:
            if not isinstance(evt, dict):
                continue
            status = evt.get("status", "unknown")
            events.append({
                "timestamp": str(evt.get("timestamp", "")),
                "label": status.upper(),
                "message": evt.get("details", ""),
                "status": (
                    "critical" if status in ("rebooted", "zombie", "unreachable")
                    else "warning" if status == "degraded"
                    else "info"
                ),
            })

        # Build as html_raw to preserve the intro paragraph with reboot count
        intro = (
            "<h3>Target Health Events</h3>"
            f"<p>Target health monitoring detected {num_events} event(s) during the campaign."
            + (
                f" Reboot events are the highest-confidence indicator of exploitable crashes."
                f" {reboot_events} reboot/unreachable event(s) were observed."
                if reboot_events
                else ""
            )
            + "</p>"
        )
        rows_html = "".join(
            f"<tr><td>{_esc(e['timestamp'])}</td>"
            f'<td style="color:{"#D43F3A" if e["status"] == "critical" else "#EE9336" if e["status"] == "warning" else "#4CAE4C"};font-weight:bold">'
            f'{_esc(e["label"])}</td>'
            f"<td>{_esc(e['message'])}</td></tr>"
            for e in events
        )
        html = (
            intro
            + "<table><tr><th>Time</th><th>Status</th><th>Details</th></tr>"
            + rows_html
            + "</table>"
        )
        return SectionBlock("html_raw", {"html": html})

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        runs = report_state.get("fuzz_runs", [])
        if not runs:
            return []

        sections: list[SectionModel] = []

        # ---- Section 1: Fuzz Testing Results ----
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

        # Campaign overview (if we have campaign stats)
        campaigns = report_state.get("campaigns", [])
        crashes = report_state.get("crashes", [])
        if campaigns:
            # Use the last/most recent campaign stats
            latest_stats = campaigns[-1].get("campaign_stats", {})
            if isinstance(latest_stats, dict) and latest_stats:
                overview_block = self._build_campaign_overview_block(latest_stats, crashes)
                blocks.append(overview_block)

                sev_block = self._build_severity_breakdown_block(crashes)
                if sev_block:
                    blocks.append(sev_block)

        # Crash summary table
        if crashes:
            crash_rows = []
            for i, crash in enumerate(crashes, 1):
                sev = crash.get("severity", "UNKNOWN")
                protocol = crash.get("protocol", "unknown")
                crash_type = crash.get("crash_type", "unknown")
                payload_len = crash.get("payload_len", 0)
                payload_hex = crash.get("payload_hex", "")
                preview = payload_hex[:48] + ("..." if len(payload_hex) > 48 else "")
                mutation = crash.get("mutation_log", "") or ""
                if len(mutation) > 40:
                    mutation = mutation[:37] + "..."
                reproduced = "Yes" if crash.get("reproduced") else "No"
                timestamp = crash.get("timestamp", "")
                crash_rows.append([
                    str(i), sev, protocol, crash_type,
                    f"{payload_len} bytes", preview, mutation, reproduced, timestamp,
                ])
            blocks.append(
                SectionBlock(
                    "table",
                    {
                        "headers": [
                            "#", "Severity", "Protocol", "Crash Type",
                            "Payload Size", "Payload Preview", "Mutation",
                            "Reproduced", "Timestamp",
                        ],
                        "rows": crash_rows,
                    },
                )
            )

        # Crash detail cards (CRITICAL/HIGH) - html_raw for hex dumps
        evidence_dir = report_state.get("evidence_dir", "")
        detail_block = self._build_crash_detail_cards_block(crashes, evidence_dir)
        if detail_block:
            blocks.append(detail_block)

        # Protocol coverage table
        if campaigns and crashes:
            latest_stats = campaigns[-1].get("campaign_stats", {})
            if isinstance(latest_stats, dict):
                cov_block = self._build_protocol_coverage_block(latest_stats, crashes)
                if cov_block:
                    blocks.append(SectionBlock("html_raw", {"html": "<h3>Protocol Coverage</h3>"}))
                    blocks.append(cov_block)

        # Evidence files and corpus stats (from campaign module_data)
        evidence_files = report_state.get("evidence_files", [])
        corpus_stats = report_state.get("corpus_stats", {})
        if evidence_files or corpus_stats:
            parts = []
            if evidence_files:
                parts.append("<h3>Evidence Package</h3><ul>")
                for item in evidence_files:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        desc, path = item
                        parts.append(f"<li>{_esc(desc)} -- <code>{_esc(path)}</code></li>")
                    else:
                        parts.append(f"<li>{_esc(str(item))}</li>")
                parts.append("</ul>")
            if corpus_stats:
                parts.append("<h4>Corpus Statistics</h4>")
                parts.append("<table><tr><th>Protocol</th><th>Seeds</th></tr>")
                for proto, count in sorted(corpus_stats.items()):
                    parts.append(f"<tr><td>{_esc(proto)}</td><td>{count}</td></tr>")
                parts.append("</table>")
            if parts:
                blocks.append(SectionBlock("html_raw", {"html": "\n".join(parts)}))

        # Fallback: raw fuzz_results when no campaign
        fuzz_results = report_state.get("fuzz_results", [])
        if fuzz_results and not campaigns:
            raw_cards = []
            for entry in fuzz_results:
                raw_cards.append({
                    "title": entry.get("command", entry.get("protocol", "fuzz run")),
                    "status": "info",
                    "details": {
                        "Protocol": entry.get("protocol", ""),
                        "Crashes": str(entry.get("crashes", entry.get("crash_count", 0))),
                    },
                    "body": "",
                })
            blocks.append(SectionBlock("card_list", {"cards": raw_cards}))

        sections.append(
            SectionModel(
                section_id="sec-fuzzing",
                title="Fuzzing Campaign Results",
                summary=(
                    f"{len(runs)} fuzz run(s), "
                    f"{total_sent} case(s) sent, {total_crashes} crash(es) detected."
                ),
                blocks=tuple(blocks),
            )
        )

        # ---- Section 2: Fuzzing Intelligence Analysis ----
        intel_blocks: list[SectionBlock] = []

        state_coverage = report_state.get("campaign_state_coverage", {})
        sc_block = self._build_state_coverage_block(state_coverage)
        if sc_block:
            intel_blocks.append(sc_block)

        field_weights = report_state.get("campaign_field_weights", {})
        fw_block = self._build_field_weights_block(field_weights)
        if fw_block:
            intel_blocks.append(fw_block)

        baselines = report_state.get("campaign_baselines", {})
        bl_block = self._build_baselines_block(baselines)
        if bl_block:
            intel_blocks.append(bl_block)

        health_events = report_state.get("campaign_health_events", [])
        he_block = self._build_health_events_block(health_events)
        if he_block:
            intel_blocks.append(he_block)

        if intel_blocks:
            sections.append(
                SectionModel(
                    section_id="sec-fuzz-intel",
                    title="Fuzzing Intelligence Analysis",
                    summary="Behavioral analysis data collected during the fuzzing campaign.",
                    blocks=tuple(intel_blocks),
                )
            )

        return sections

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
