import json
from pathlib import Path

from blue_tap.demo import mock_data as M
from blue_tap.framework.envelopes.auto import build_auto_result
from blue_tap.framework.contracts.result_schema import build_run_envelope, make_evidence, make_execution
from blue_tap.demo.report_data import (
    build_demo_dos_result,
    build_demo_fingerprint_result,
    build_demo_fuzz_result,
    build_demo_recon_result,
    build_demo_scan_result,
    build_demo_vuln_result,
)
from blue_tap.interfaces.reporting.generator import ReportGenerator
from blue_tap.framework.sessions.store import Session


def test_generate_json_includes_module_and_global_executions(tmp_path):
    report = ReportGenerator()
    report.add_run_envelope(build_demo_scan_result(devices=M.SCAN_DEVICES, adapter=M.IVI_HCI, duration_requested=15))
    report.add_run_envelope(
        build_demo_fingerprint_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, fingerprint=M.FINGERPRINT)
    )
    report.add_run_envelope(build_demo_recon_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, entries=M.SDP_SERVICES))
    report.add_run_envelope(build_demo_vuln_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, findings=M.VULN_FINDINGS))
    report.add_run_envelope(build_demo_dos_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, checks=M.DOS_RESULTS))
    report.add_run_envelope(build_demo_fuzz_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, fuzz_results=M.FUZZ_RESULTS))

    output = tmp_path / "report.json"
    report.generate_json(str(output))
    payload = json.loads(output.read_text())

    assert payload["modules"]["scan"]["executions"]
    assert payload["modules"]["recon"]["executions"]
    assert payload["modules"]["recon"]["fingerprints"]
    assert payload["modules"]["vulnscan"]["executions"]
    assert payload["modules"]["dos"]["executions"]
    assert payload["modules"]["fuzz"]["executions"]
    assert payload["executions"]
    assert "fingerprint" not in payload

    execution_modules = {execution["module"] for execution in payload["executions"]}
    assert {"scan", "recon", "vulnscan", "dos", "fuzz"}.issubset(execution_modules)


def test_recon_html_renders_fingerprint_data():
    report = ReportGenerator()
    report.add_run_envelope(
        build_demo_fingerprint_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, fingerprint=M.FINGERPRINT)
    )
    report.add_run_envelope(build_demo_recon_result(target=M.IVI_ADDRESS, adapter=M.IVI_HCI, entries=M.SDP_SERVICES))

    html = report._build_recon_html()

    assert "Reconnaissance Results" in html
    assert M.FINGERPRINT["manufacturer"] in html
    assert M.FINGERPRINT["name"] in html


def test_load_from_directory_prefers_standardized_session_entries(tmp_path):
    session = Session("report_loader_test", base_dir=str(tmp_path))
    session.log(
        "demo_scan",
        build_demo_scan_result(devices=M.SCAN_DEVICES, adapter=M.IVI_HCI, duration_requested=15),
        category="scan",
    )
    session.log(
        "demo_audio",
        {
            "schema": "blue_tap.audio.result",
            "module": "audio",
            "module_data": {
                "operation": "demo_audio_capture",
                "output_file": "audio/demo.wav",
                "duration": 4.2,
                "description": "demo audio artifact",
            },
            "executions": [
                {
                    "execution_id": "exec-audio-1",
                    "id": "demo_audio_capture",
                    "title": "Demo Audio Capture",
                    "module": "audio",
                    "protocol": "HFP",
                    "execution_status": "completed",
                    "module_outcome": "completed",
                    "evidence": {"summary": "Demo audio capture complete"},
                    "artifacts": [],
                    "module_data": {},
                }
            ],
            "summary": {},
        },
        category="audio",
    )

    session_dir = Path(session.dir)
    (session_dir / "attack_results.json").write_text(json.dumps({"legacy": True}))
    (session_dir / "pbap_dump.json").write_text(json.dumps({"legacy": "pbap"}))
    (session_dir / "audio_capture.json").write_text(json.dumps({"legacy": "audio"}))

    report = ReportGenerator()
    report.load_from_directory(str(session_dir))

    payload_path = tmp_path / "loader-report.json"
    report.generate_json(str(payload_path))
    payload = json.loads(payload_path.read_text())

    assert payload["modules"]["scan"]["runs"]
    assert payload["modules"]["audio"]["runs"]
    assert len(payload["modules"]["scan"]["runs"]) == 1
    assert len(payload["modules"]["audio"]["runs"]) == 1
    assert "attack_results" not in payload
    assert "pbap_data" not in payload
    assert "audio_captures" not in payload


def test_session_log_validates_standardized_envelope_at_write_time(tmp_path):
    session = Session("validation_test", base_dir=str(tmp_path))
    envelope = build_run_envelope(
        schema="blue_tap.attack.result",
        module="attack",
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        operator_context={"command": "knob"},
        summary={"operation": "knob"},
        executions=[
            make_execution(
                kind="check",
                id="knob_probe",
                title="KNOB Probe",
                module="attack",
                protocol="BR/EDR",
                execution_status="completed",
                module_outcome="confirmed",
                evidence=make_evidence(summary="probe complete"),
            )
        ],
        module_data={"cli_events": []},
    )

    path = Path(session.log("knob_probe", envelope, category="attack", target="AA:BB:CC:DD:EE:FF"))
    payload = json.loads(path.read_text())

    assert payload["validation"]["checked_at_write_time"] is True
    assert payload["validation"]["valid"] is True
    assert payload["validation"]["errors"] == []


def test_generate_json_includes_auto_and_lmp_capture_modules(tmp_path):
    report = ReportGenerator()
    report.add_run_envelope(
        build_auto_result(
            target="AA:BB:CC:DD:EE:FF",
            adapter="hci0",
            results={
                "target": "AA:BB:CC:DD:EE:FF",
                "status": "complete",
                "phases": {"discovery": {"status": "success", "_elapsed_seconds": 1.0}},
                "total_time_seconds": 1.0,
            },
        )
    )
    report.add_run_envelope(
        {
            "schema": "blue_tap.lmp_capture.result",
            "module": "lmp_capture",
            "module_data": {
                "captures": [
                    {
                        "bdaddr": "AA:BB:CC:DD:EE:FF",
                        "LMPArray": [{"opcode": 8, "timestamp": 0, "direction": "tx", "decoded": {"opcode_name": "LMP_AU_RAND"}}],
                    }
                ]
            },
        }
    )

    output = tmp_path / "report-modules.json"
    report.generate_json(str(output))
    payload = json.loads(output.read_text())

    assert "auto" in payload["modules"]
    assert payload["modules"]["auto"]["runs"]
    assert "lmp_capture" in payload["modules"]
    assert payload["modules"]["lmp_capture"]["captures"]


def test_generate_html_renders_auto_section(tmp_path):
    report = ReportGenerator()
    report.add_run_envelope(
        build_auto_result(
            target="AA:BB:CC:DD:EE:FF",
            adapter="hci0",
            results={
                "target": "AA:BB:CC:DD:EE:FF",
                "status": "complete",
                "phases": {
                    "discovery": {"status": "success", "_elapsed_seconds": 1.0},
                    "report": {"status": "success", "_elapsed_seconds": 1.0},
                },
                "total_time_seconds": 2.0,
            },
        )
    )

    output = tmp_path / "report.html"
    report.generate_html(str(output))
    html = output.read_text()

    assert 'id="sec-auto-pentest"' in html
    assert "Automated Pentest Workflow" in html


def test_generate_json_keeps_top_level_fuzzing_for_single_protocol_runs(tmp_path):
    report = ReportGenerator()
    envelope = build_run_envelope(
        schema="blue_tap.fuzz.result",
        module="fuzz",
        target="AA:BB:CC:DD:EE:FF",
        adapter="hci0",
        operator_context={"command": "fuzz sdp"},
        summary={"command": "fuzz sdp", "protocol": "sdp", "packets_sent": 10, "crashes": 0, "errors": 0},
        executions=[],
        module_data={
            "run_type": "single_protocol_run",
            "command": "fuzz sdp",
            "protocol": "sdp",
            "result": {"packets_sent": 10, "crashes": 0, "errors": 0},
        },
    )
    report.add_run_envelope(envelope)

    output = tmp_path / "fuzz-single.json"
    report.generate_json(str(output))
    payload = json.loads(output.read_text())

    assert payload["fuzzing"]
    assert payload["fuzzing"][0]["protocol"] == "sdp"
