"""LMP Capture report adapter.

Handles LMP capture data from DarkFirmware RTL8761B sniffer (BTIDES export).
Renders: color-coded packet table, feature bitmap visualization, encryption
negotiation summary.
"""

from __future__ import annotations

import html as _html
import logging
from datetime import datetime as _dt
from typing import Any

from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionBlock, SectionModel

logger = logging.getLogger(__name__)

# LMP opcode category sets for colour coding
_AUTH_OPCODES: frozenset[int] = frozenset({8, 9, 10, 11, 12, 13, 14, 59, 60, 61})
_ENC_OPCODES: frozenset[int] = frozenset({15, 16, 17, 18})
_FEAT_OPCODES: frozenset[int] = frozenset({37, 38, 39, 40})

_FEATURE_NAMES: list[str] = [
    "3-slot", "5-slot", "Encryption", "SlotOffset",
    "TimingAccuracy", "RoleSwitch", "HoldMode", "SniffMode",
    "ParkState", "PowerCtrlReq", "CQDDR", "SCOLink",
    "HV2", "HV3", "uLaw", "aLaw",
]


def _esc(value: Any) -> str:
    return _html.escape(str(value), quote=True)


class LmpCaptureReportAdapter(ReportAdapter):
    module = "lmp_capture"

    def accepts(self, envelope: dict[str, Any]) -> bool:
        return (
            envelope.get("module") == self.module
            or str(envelope.get("schema", "")).startswith("blue_tap.lmp_capture.")
        )

    def ingest(self, envelope: dict[str, Any], report_state: dict[str, Any]) -> None:
        module_data = envelope.get("module_data", {}) or {}
        captures = module_data.get("captures", [])
        if not isinstance(captures, list):
            logger.warning(
                "LmpCaptureAdapter.ingest: module_data.captures is not a list, got %s",
                type(captures).__name__,
            )
            captures = []
        report_state.setdefault("lmp_captures", []).extend(captures)
        logger.debug(
            "LmpCaptureAdapter.ingest: added %d capture(s), total now %d",
            len(captures),
            len(report_state["lmp_captures"]),
        )

    def build_sections(self, report_state: dict[str, Any]) -> list[SectionModel]:
        captures = report_state.get("lmp_captures", [])
        if not captures:
            return []

        html_parts = self._render_lmp_html(captures)
        if not html_parts:
            return []

        blocks: list[SectionBlock] = []
        blocks.append(SectionBlock("html_raw", {"html": html_parts}))

        return [
            SectionModel(
                section_id="sec-lmp",
                title="LMP Capture Analysis",
                summary=(
                    "Link Manager Protocol packets captured via DarkFirmware "
                    "RTL8761B reveal the below-HCI negotiation between link "
                    "managers, including authentication, encryption setup, and "
                    "feature exchange."
                ),
                blocks=tuple(blocks),
            )
        ]

    def build_json_section(self, report_state: dict[str, Any]) -> dict[str, Any]:
        return {"captures": report_state.get("lmp_captures", [])}

    # ------------------------------------------------------------------
    # Internal rendering helpers
    # ------------------------------------------------------------------

    def _render_lmp_html(self, captures: list[dict]) -> str:
        """Render the full LMP content HTML (packet tables + bitmap + enc summary)."""
        s: list[str] = []
        features_hex: str | None = None
        key_sizes: list[int] = []

        for capture in captures:
            bdaddr = capture.get("bdaddr", "unknown")
            lmp_array = capture.get("LMPArray", [])
            if not lmp_array:
                continue

            s.append(f'<h3>Capture: {_esc(bdaddr)}</h3>')
            s.append(
                '<table><tr><th>Timestamp</th><th>Direction</th>'
                '<th>Opcode</th><th>Decoded</th></tr>'
            )

            for pkt in lmp_array:
                opcode = pkt.get("opcode", 0)
                ts_val = pkt.get("timestamp", 0)
                try:
                    ts_str = (
                        _dt.fromtimestamp(ts_val).strftime("%H:%M:%S.%f")[:-3]
                        if ts_val
                        else ""
                    )
                except (OSError, ValueError):
                    ts_str = str(ts_val)

                direction = _esc(pkt.get("direction", "rx"))
                decoded = pkt.get("decoded", {})
                opcode_name = _esc(decoded.get("opcode_name", f"0x{opcode:04x}"))

                params = []
                for k, v in decoded.items():
                    if k == "opcode_name":
                        continue
                    params.append(f"{k}={_esc(str(v))}")
                params_str = ", ".join(params) if params else ""

                if opcode in _AUTH_OPCODES:
                    color = "#dc2626"  # red
                elif opcode in _ENC_OPCODES:
                    color = "#ea580c"  # orange
                elif opcode in _FEAT_OPCODES:
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

                if decoded.get("features_hex"):
                    features_hex = decoded["features_hex"]
                if decoded.get("key_size"):
                    key_sizes.append(decoded["key_size"])

            s.append('</table>')

        if not s:
            return ""

        # Feature bitmap visualization
        if features_hex:
            s.append('<h3>Feature Bitmap</h3>')
            s.append('<p>8-byte LMP features bitmap from LMP_FEATURES_RES:</p>')
            try:
                feat_bytes = bytes.fromhex(features_hex)
                s.append('<table class="feature-grid"><tr>')
                for byte_idx, b in enumerate(feat_bytes):
                    for bit in range(8):
                        bit_num = byte_idx * 8 + bit
                        is_set = bool(b & (1 << bit))
                        bg = "#22c55e" if is_set else "#374151"
                        name = (
                            _FEATURE_NAMES[bit_num]
                            if bit_num < len(_FEATURE_NAMES)
                            else f"bit{bit_num}"
                        )
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
            s.append(
                f'<p>Key size requests observed: min={min_ks}, '
                f'max={max_ks}, count={len(key_sizes)}</p>'
            )
            if min_ks < 7:
                s.append(
                    '<p style="color:#dc2626;font-weight:bold">'
                    'WARNING: Key size below 7 bytes detected '
                    '(potential KNOB attack surface - CVE-2019-9506)</p>'
                )

        return "\n".join(s)
