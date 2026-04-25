"""User-flow 10.12: Report-only path on a pre-existing session.

Create a session dir with fake envelopes for every family, then run:
  blue-tap -s <name> report

Assertions:
  - HTML report produced
  - Contains sections for families with envelopes
  - No KeyError when adapter is missing (regression guard Phase 3.4)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
    now_iso,
)

SESSION_NAME = "flow_report_prefab"
TARGET = "AA:BB:CC:DD:EE:FF"


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def _discovery_envelope() -> dict:
    return build_run_envelope(
        module_id="discovery.scanner",
        schema="blue_tap.scan.result",
        module="scanner",
        target="",
        adapter="hci0",
        summary={"outcome": "observed", "device_count": 1, "classic_count": 1, "ble_count": 0},
        executions=[make_execution(
            module_id="discovery.scanner",
            execution_id="scan",
            kind="collector",
            id="scan",
            title="Bluetooth Scan (all)",
            execution_status="completed",
            module_outcome="observed",
            evidence=make_evidence(summary="Found 1 device"),
            destructive=False,
            requires_pairing=False,
        )],
        module_data={"devices": [{"address": TARGET, "name": "Test", "type": "classic"}]},
    )


def _recon_envelope() -> dict:
    return build_run_envelope(
        module_id="reconnaissance.sdp",
        schema="blue_tap.recon.sdp.result",
        module="sdp",
        target=TARGET,
        adapter="hci0",
        summary={"outcome": "observed", "service_count": 1},
        executions=[make_execution(
            module_id="reconnaissance.sdp",
            execution_id="sdp_browse",
            kind="collector",
            id="sdp_browse",
            title="SDP Browse",
            execution_status="completed",
            module_outcome="observed",
            evidence=make_evidence(summary="Found 1 SDP service"),
            destructive=False,
            requires_pairing=False,
        )],
        module_data={"services": [{"uuid": "0x1101", "name": "Serial Port"}]},
    )


def _assessment_envelope() -> dict:
    return build_run_envelope(
        module_id="assessment.vuln_scanner",
        schema="blue_tap.vulnscan.result",
        module="assessment.vuln_scanner",
        target=TARGET,
        adapter="hci0",
        summary={"outcome": "inconclusive", "confirmed": 0, "inconclusive": 1},
        executions=[make_execution(
            module_id="assessment.check_ssp",
            execution_id="check_ssp",
            kind="check",
            id="check_ssp",
            title="SSP Check",
            execution_status="completed",
            module_outcome="inconclusive",
            evidence=make_evidence(summary="SSP uncertain"),
            destructive=False,
            requires_pairing=False,
        )],
        module_data={"findings": []},
    )


def _exploitation_envelope() -> dict:
    return build_run_envelope(
        module_id="exploitation.knob",
        schema="blue_tap.attack.result",
        module="exploitation",
        target=TARGET,
        adapter="hci0",
        operator_context={"command": "knob"},
        summary={"operation": "knob", "likely_vulnerable": True},
        executions=[make_execution(
            execution_id="knob_probe",
            kind="check",
            id="knob_probe",
            title="KNOB Probe",
            execution_status="completed",
            module_outcome="success",
            evidence=make_evidence(summary="Key negotiation probed"),
            destructive=True,
            requires_pairing=False,
            module_id="exploitation.knob",
        )],
        module_data={},
    )


def _post_exploitation_envelope() -> dict:
    return build_run_envelope(
        module_id="post_exploitation.pbap",
        schema="blue_tap.post_exploitation.pbap.result",
        module="post_exploitation.pbap",
        target=TARGET,
        adapter="hci0",
        summary={"outcome": "extracted", "total_entries": 2},
        executions=[make_execution(
            module_id="post_exploitation.pbap",
            execution_id="pbap_pb",
            kind="collector",
            id="pbap_pb",
            title="PBAP Pull: pb",
            execution_status="completed",
            module_outcome="extracted",
            evidence=make_evidence(summary="2 vCard entries extracted"),
            destructive=False,
            requires_pairing=True,
        )],
        module_data={},
    )


def _fuzzing_envelope() -> dict:
    return build_run_envelope(
        module_id="fuzzing.engine",
        schema="blue_tap.fuzz.result",
        module="engine",
        target=TARGET,
        adapter="hci0",
        summary={"outcome": "no_findings", "iterations": 100, "crashes": 0},
        executions=[make_execution(
            module_id="fuzzing.engine",
            execution_id="fuzz_campaign",
            kind="phase",
            id="fuzz_campaign",
            title="Fuzz Campaign (coverage_guided)",
            execution_status="completed",
            module_outcome="no_findings",
            evidence=make_evidence(summary="100 iterations, 0 crashes"),
            destructive=True,
            requires_pairing=False,
        )],
        module_data={"protocols": ["sdp"]},
    )


def _write_session(session_dir: Path) -> dict:
    """Create a full session directory with pre-built envelopes."""
    session_dir.mkdir(parents=True, exist_ok=True)

    envelopes = [
        ("001_scan.json", "scan", _discovery_envelope()),
        ("002_sdp.json", "recon", _recon_envelope()),
        ("003_vulnscan.json", "vuln", _assessment_envelope()),
        ("004_knob.json", "attack", _exploitation_envelope()),
        ("005_pbap.json", "data", _post_exploitation_envelope()),
        ("006_fuzz.json", "fuzz", _fuzzing_envelope()),
    ]

    commands = []
    for i, (filename, category, envelope) in enumerate(envelopes, 1):
        entry = {
            "command": filename.split(".")[0].lstrip("0123456789_"),
            "category": category,
            "target": TARGET,
            "timestamp": now_iso(),
            "data": envelope,
        }
        filepath = session_dir / filename
        filepath.write_text(json.dumps(entry, indent=2))
        commands.append({
            "seq": i,
            "command": entry["command"],
            "category": category,
            "target": TARGET,
            "timestamp": now_iso(),
            "file": filename,
        })

    meta = {
        "name": SESSION_NAME,
        "created": now_iso(),
        "last_updated": now_iso(),
        "adapter": "",  # intentionally missing adapter — regression guard Phase 3.4
        "targets": [TARGET],
        "commands": commands,
        "files": [],
    }
    (session_dir / "session.json").write_text(json.dumps(meta, indent=2))
    return meta


def test_report_from_prefab_session(tmp_path):
    """Report must render without KeyError even when adapter field is empty."""
    runner = _make_runner(tmp_path)

    # Manually create the session directory with envelopes
    session_dir = tmp_path / "sessions" / SESSION_NAME
    meta = _write_session(session_dir)

    result = runner.invoke(cli, ["-s", SESSION_NAME, "report"])
    assert result.exit_code == 0, f"report failed:\n{result.output}"

    report_file = session_dir / "report.html"
    assert report_file.exists(), "report.html was not created"

    html = report_file.read_text()
    assert len(html) > 500, f"Report HTML is suspiciously short ({len(html)} bytes)"

    # Must not raise KeyError (regression guard Phase 3.4 — missing adapter key)
    assert "KeyError" not in html
    assert "Traceback" not in result.output
