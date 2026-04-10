import json

from click.testing import CliRunner

from blue_tap.cli import main
from blue_tap.recon.capability_detector import detect_target_capabilities
from blue_tap.recon.capture_analysis import analyze_capture_results
from blue_tap.recon.campaign import run_auto_recon
from blue_tap.recon.correlation import build_recon_correlation
from blue_tap.recon.correlation import analyze_capture_artifact
from blue_tap.recon.l2cap_scan import _classify_l2cap_behavior
from blue_tap.recon.rfcomm_scan import classify_rfcomm_response
from blue_tap.recon.spec_interpretation import evaluate_smp_transcript, interpret_ble_capture, interpret_lmp_capture
from blue_tap.report.generator import ReportGenerator
from blue_tap.recon.sdp import parse_sdp_output


def test_capability_detector_classifies_dual_mode(monkeypatch):
    monkeypatch.setattr("blue_tap.recon.capability_detector.ensure_adapter_ready", lambda hci: True)

    def fake_run_cmd(cmd, timeout=0):
        class Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if cmd[:4] == ["hcitool", "-i", "hci0", "name"]:
            return Result(0, stdout="DemoCar\n")
        if cmd[:4] == ["hcitool", "-i", "hci0", "info"]:
            return Result(0, stdout="hci0: Type: Primary\n")
        return Result(1, stderr="unsupported")

    monkeypatch.setattr("blue_tap.recon.capability_detector.run_cmd", fake_run_cmd)
    monkeypatch.setattr(
        "blue_tap.recon.capability_detector.browse_services",
        lambda address, hci="hci0": [{"name": "Hands-Free", "profile": "HFP AG"}],
    )
    monkeypatch.setattr(
        "blue_tap.recon.capability_detector.enumerate_services_detailed_sync",
        lambda address: {"connected": True, "service_count": 2, "characteristic_count": 5, "status": "completed", "error": ""},
    )

    result = detect_target_capabilities("AA:BB:CC:DD:EE:FF")

    assert result["classification"] == "dual_mode"
    assert result["classic"]["supported"] is True
    assert result["ble"]["supported"] is True


def test_standalone_recon_command_persists_final_cli_events(monkeypatch):
    recorded = {}

    def fake_log_command(command, data, category="general", target=""):
        recorded["command"] = command
        recorded["data"] = data
        recorded["category"] = category
        recorded["target"] = target
        return "session-file.json"

    monkeypatch.setattr("blue_tap.utils.session.log_command", fake_log_command)
    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr(
        "blue_tap.recon.sdp.browse_services_detailed",
        lambda address: {
            "services": [{"name": "Serial Port", "profile": "SPP", "protocol": "RFCOMM", "channel": 5}],
            "rfcomm_channels": [5],
            "l2cap_psms": [],
        },
    )

    result = CliRunner().invoke(main, ["recon", "sdp", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    cli_events = recorded["data"]["module_data"]["cli_events"]
    assert any(event["event_type"] == "run_completed" for event in cli_events)
    assert any(event["event_type"] == "execution_result" for event in cli_events)


def test_run_auto_recon_logs_skips_for_unsupported_transport(monkeypatch):
    monkeypatch.setattr(
        "blue_tap.recon.campaign.detect_target_capabilities",
        lambda address, hci="hci0": {
            "classification": "ble_only",
            "classic": {"supported": False, "signals": []},
            "ble": {"supported": True, "signals": ["gatt_connect"]},
            "observations": ["classification=ble_only"],
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.enumerate_services_detailed_sync",
        lambda address: {
            "connected": True,
            "status": "completed",
            "services": [
                {
                    "uuid": "0000180a-0000-1000-8000-00805f9b34fb",
                    "handle": 1,
                    "description": "Device Information",
                    "characteristics": [
                        {
                            "uuid": "00002a29-0000-1000-8000-00805f9b34fb",
                            "handle": 2,
                            "description": "Manufacturer Name String",
                            "properties": ["read"],
                            "value_str": "Demo",
                            "security_hint": "read_only",
                        }
                    ],
                }
            ],
            "service_count": 1,
            "characteristic_count": 1,
            "observations": ["connected=true"],
            "security_summary": {"writable_characteristics": 0, "protected_characteristics": 0},
        },
    )

    envelope = run_auto_recon(address="AA:BB:CC:DD:EE:FF")

    skipped = [execution for execution in envelope["executions"] if execution["execution_status"] == "skipped"]
    assert skipped
    assert any(execution["id"] == "recon_sdp" for execution in skipped)
    assert envelope["module_data"]["gatt"]["service_count"] == 1


def test_parse_sdp_output_preserves_protocol_details():
    services = parse_sdp_output(
        """
Service Name: Hands-Free unit
Service RecHandle: 0x10000
Service Class ID List:
  "Handsfree Audio Gateway" (0x111f)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 7
Profile Descriptor List:
  "Hands-Free Profile" (0x111e)
    Version: 0x0107
Attribute (0x0311) - uint16: 0x0001
"""
    )

    assert services[0]["protocol"] == "RFCOMM"
    assert services[0]["channel"] == 7
    assert services[0]["profile_descriptors"]
    assert services[0]["raw_attributes"]


def test_rfcomm_and_l2cap_classifiers_add_protocol_hints():
    rfcomm = classify_rfcomm_response(b"OK\r\nAT+GMM\r\n")
    assert rfcomm["response_type"] == "at_modem"
    assert "at_command_surface" in rfcomm["protocol_hints"]
    assert rfcomm["ascii_ratio"] > 0

    assert _classify_l2cap_behavior(31, "open") == "att_or_ble_att"
    assert _classify_l2cap_behavior(15, "auth_required") == "protected_surface"


def test_spec_interpretation_summarizes_lmp_and_ble_posture():
    lmp = interpret_lmp_capture(
        {
            "feature_packets": 2,
            "auth_packets": 1,
            "encryption_packets": 1,
            "observed_key_sizes": [6, 16],
            "bt_versions": ["6"],
        },
        pairing_mode={"ssp_supported": False, "pairing_method": "Just Works"},
    )
    ble = interpret_ble_capture(
        {
            "source_counts": {"ble": 2},
            "signal_counts": {"pairing_or_auth_activity": 1, "encryption_activity": 1},
        },
        pairing_mode={"ssp_supported": True, "pairing_method": "Just Works"},
    )

    assert lmp["posture"] == "weak_key_negotiation_observed"
    assert "classic_legacy_pairing_possible" in lmp["findings"]
    assert "min_observed_key_size=6" in lmp["findings"]
    assert ble["posture"] == "ble_pairing_observed"
    assert "ble_unauthenticated_association_model_possible" in ble["findings"]


def test_evaluate_smp_transcript_classifies_legacy_justworks():
    transcript = evaluate_smp_transcript(
        [
            {
                "opcode": 0x01,
                "io_capability": 0x03,
                "oob_data_flags": 0x00,
                "authreq": 0x01,
                "max_enc_key_size": 16,
                "initiator_key_distribution": 0x07,
                "responder_key_distribution": 0x07,
            },
            {
                "opcode": 0x02,
                "io_capability": 0x03,
                "oob_data_flags": 0x00,
                "authreq": 0x01,
                "max_enc_key_size": 16,
                "initiator_key_distribution": 0x07,
                "responder_key_distribution": 0x07,
            },
        ]
    )

    assert transcript["association_model"] == "just_works"
    assert transcript["secure_connections"] is False
    assert transcript["crackability"] == "legacy_justworks_trivially_crackable"
    assert "ble_secure_connections=no" in transcript["findings"]


def test_run_auto_recon_includes_prerequisites_and_correlation(monkeypatch):
    monkeypatch.setattr(
        "blue_tap.recon.campaign.detect_target_capabilities",
        lambda address, hci="hci0": {
            "classification": "classic_only",
            "classic": {"supported": True, "signals": ["sdp_services"]},
            "ble": {"supported": False, "signals": []},
            "observations": ["classification=classic_only"],
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.evaluate_recon_prerequisites",
        lambda **kwargs: {
            "classic_adapter_ready": {"available": True, "reason": ""},
            "hci_capture": {"available": False, "reason": "btmon not installed"},
            "nrf_ble_sniffer": {"available": False, "reason": "target does not expose BLE support"},
            "darkfirmware_lmp": {"available": False, "reason": "DarkFirmware adapter hci1 is unavailable"},
            "combined_capture": {"available": False, "reason": "target does not expose BLE support"},
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.fingerprint_device",
        lambda address, hci="hci0": {"address": address, "name": "Demo", "manufacturer": "DemoCorp", "profiles": [], "attack_surface": []},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.detect_pairing_mode",
        lambda address, hci="hci0": {"ssp_supported": True, "io_capability": "NoInputNoOutput", "pairing_method": "Just Works"},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.browse_services_detailed",
        lambda address, hci="hci0": {
            "services": [{"name": "Serial Port", "protocol": "RFCOMM", "channel": 5}],
            "rfcomm_channels": [5],
            "l2cap_psms": [],
            "service_count": 1,
            "status": "completed",
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.RFCOMMScanner",
        lambda address: type(
            "StubScanner",
            (),
            {"scan_all_channels": lambda self, hci="hci0": [{"channel": 7, "status": "open", "response_type": "at_modem"}]},
        )(),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.L2CAPScanner",
        lambda address: type(
            "StubL2",
            (),
            {
                "scan_standard_psms": lambda self, hci="hci0": [{"psm": 25, "status": "open", "name": "AVDTP"}],
                "scan_dynamic_psms": lambda self, start=4097, end=4127, timeout=0.75, workers=4: [
                    {"psm": 4097, "status": "open", "name": "Dynamic/Vendor (0x1001)", "behavior_hint": "vendor_dynamic_surface", "protocol_family": "dynamic_vendor"}
                ],
            },
        )(),
    )

    envelope = run_auto_recon(address="AA:BB:CC:DD:EE:FF", with_captures=True, with_below_hci=True)

    assert envelope["module_data"]["prerequisites"]["hci_capture"]["available"] is False
    assert envelope["module_data"]["correlation"]["rfcomm"]["hidden_channels"]
    assert envelope["module_data"]["correlation"]["l2cap"]["dynamic_open_psms"]
    assert envelope["module_data"]["correlation"]["spec_interpretation"]["classic"]["findings"]
    assert any(execution["module_outcome"] == "prerequisite_missing" for execution in envelope["executions"])
    assert envelope["module_data"]["cli_events"]
    assert "pairing_method=Just Works" in envelope["module_data"]["capture_analysis"]["findings"]


def test_run_auto_recon_executes_capture_collectors_when_available(monkeypatch):
    monkeypatch.setattr(
        "blue_tap.recon.campaign.detect_target_capabilities",
        lambda address, hci="hci0": {
            "classification": "dual_mode",
            "classic": {"supported": True, "signals": ["sdp_services"]},
            "ble": {"supported": True, "signals": ["gatt_connect"]},
            "observations": ["classification=dual_mode"],
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.evaluate_recon_prerequisites",
        lambda **kwargs: {
            "classic_adapter_ready": {"available": True, "reason": ""},
            "hci_capture": {"available": True, "reason": ""},
            "nrf_ble_sniffer": {"available": True, "reason": ""},
            "darkfirmware_lmp": {"available": True, "reason": ""},
            "combined_capture": {"available": True, "reason": ""},
        },
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.fingerprint_device",
        lambda address, hci="hci0": {"address": address, "name": "Demo", "manufacturer": "DemoCorp", "profiles": [], "attack_surface": []},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.detect_pairing_mode",
        lambda address, hci="hci0": {"ssp_supported": True, "io_capability": "DisplayYesNo", "pairing_method": "Numeric Comparison"},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.browse_services_detailed",
        lambda address, hci="hci0": {"services": [], "rfcomm_channels": [], "l2cap_psms": [], "service_count": 0, "status": "completed"},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.RFCOMMScanner",
        lambda address: type("StubScanner", (), {"scan_all_channels": lambda self, hci="hci0": []})(),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.L2CAPScanner",
        lambda address: type("StubL2", (), {"scan_standard_psms": lambda self, hci="hci0": []})(),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign.enumerate_services_detailed_sync",
        lambda address: {"connected": True, "status": "completed", "services": [], "service_count": 0, "characteristic_count": 0, "observations": [], "security_summary": {}},
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign._run_hci_capture_step",
        lambda *args, **kwargs: (
            {
                "id": "recon_hci_capture",
                "title": "HCI Capture",
                "module": "recon",
                "protocol": "HCI",
                "execution_status": "completed",
                "module_outcome": "artifact_collected",
                "evidence": {"summary": "HCI capture completed"},
            },
            {"status": "completed"},
            [{"kind": "capture", "label": "HCI capture", "path": "/tmp/hci.btsnoop"}],
        ),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign._run_nrf_capture_step",
        lambda *args, **kwargs: (
            {
                "id": "recon_nrf_capture",
                "title": "nRF BLE Capture",
                "module": "recon",
                "protocol": "BLE",
                "execution_status": "completed",
                "module_outcome": "artifact_collected",
                "evidence": {"summary": "BLE capture completed"},
            },
            {"status": "completed"},
            [{"kind": "pcap", "label": "BLE capture", "path": "/tmp/ble.pcap"}],
        ),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign._run_lmp_capture_step",
        lambda *args, **kwargs: (
            {
                "id": "recon_below_hci",
                "title": "Below-HCI Recon",
                "module": "recon",
                "protocol": "LMP",
                "execution_status": "completed",
                "module_outcome": "artifact_collected",
                "evidence": {"summary": "LMP capture completed"},
            },
            {"status": "completed"},
            [{"kind": "btides", "label": "LMP capture", "path": "/tmp/lmp.json"}],
        ),
    )
    monkeypatch.setattr(
        "blue_tap.recon.campaign._run_combined_capture_step",
        lambda *args, **kwargs: (
            {
                "id": "recon_combined_capture",
                "title": "Combined BLE and LMP Capture",
                "module": "recon",
                "protocol": "BLE/LMP",
                "execution_status": "completed",
                "module_outcome": "artifact_collected",
                "evidence": {"summary": "Combined capture completed"},
            },
            {"status": "completed"},
            [{"kind": "timeline", "label": "Combined capture", "path": "/tmp/combined.json"}],
        ),
    )

    envelope = run_auto_recon(
        address="AA:BB:CC:DD:EE:FF",
        with_captures=True,
        with_below_hci=True,
        duration=3,
    )

    execution_ids = {execution["id"] for execution in envelope["executions"]}
    assert {"recon_hci_capture", "recon_nrf_capture", "recon_below_hci", "recon_combined_capture", "pairing_mode_probe"}.issubset(execution_ids)
    assert len(envelope["artifacts"]) == 4
    assert "combined_capture_collected" in envelope["module_data"]["capture_analysis"]["findings"]


def test_recon_json_includes_capabilities_and_gatt_results(tmp_path):
    report = ReportGenerator()
    report.add_run_envelope(
        {
            "schema": "blue_tap.recon.result",
            "schema_version": 2,
            "module": "recon",
            "run_id": "recon-demo-1",
            "target": "AA:BB:CC:DD:EE:FF",
            "adapter": "hci0",
            "started_at": "2026-04-10T00:00:00+00:00",
            "completed_at": "2026-04-10T00:00:01+00:00",
            "operator_context": {"operation": "recon_auto"},
            "summary": {"classification": "dual_mode"},
            "executions": [
                {
                    "execution_id": "exec-hci-1",
                    "id": "recon_hci_capture",
                    "title": "HCI Capture",
                    "module": "recon",
                    "protocol": "HCI",
                    "execution_status": "completed",
                    "module_outcome": "artifact_collected",
                    "evidence": {"summary": "HCI capture completed"},
                    "artifacts": [
                        {"artifact_id": "artifact-1", "kind": "capture", "label": "HCI capture", "path": "/tmp/hci.btsnoop"}
                    ],
                    "module_data": {},
                }
            ],
            "artifacts": [
                {"artifact_id": "artifact-1", "kind": "capture", "label": "HCI capture", "path": "/tmp/hci.btsnoop"}
            ],
            "module_data": {
                "capability_detection": {
                    "classification": "dual_mode",
                    "classic": {"supported": True, "signals": ["sdp_services"]},
                    "ble": {"supported": True, "signals": ["gatt_services"]},
                },
                "prerequisites": {
                    "hci_capture": {"available": False, "reason": "btmon not installed"},
                },
                "correlation": {
                    "classification": "dual_mode",
                    "findings": ["hidden_rfcomm_channels=1"],
                    "rfcomm": {"hidden_channels": [{"channel": 9}]},
                    "l2cap": {"unexpected_psms": []},
                    "spec_interpretation": {
                        "classic": {"posture": "classic_surface_characterized", "findings": ["classic_telephony_control_surface_visible"]},
                        "ble": {"posture": "ble_pairing_observed", "findings": ["ble_pairing_or_auth_activity_visible"]},
                    },
                },
                "cli_events": [
                    {
                        "timestamp": "2026-04-10T00:00:00+00:00",
                        "event_type": "run_started",
                        "execution_id": "",
                        "message": "Recon run started",
                        "target": "AA:BB:CC:DD:EE:FF",
                        "adapter": "hci0",
                        "details": {"duration": 3},
                    },
                    {
                        "timestamp": "2026-04-10T00:00:01+00:00",
                        "event_type": "artifact_saved",
                        "execution_id": "recon_hci_capture",
                        "message": "HCI capture saved to /tmp/hci.btsnoop",
                        "target": "AA:BB:CC:DD:EE:FF",
                        "adapter": "hci0",
                        "details": {"path": "/tmp/hci.btsnoop"},
                    },
                ],
                "hci_capture": {
                    "status": "completed",
                    "output": "/tmp/hci.btsnoop",
                    "result": {"success": True, "packets": 42, "output": "/tmp/hci.btsnoop", "duration": 3},
                },
                "capture_analysis": {
                    "findings": ["lmp_feature_exchange_observed=yes", "pairing_method=Numeric Comparison"],
                    "details": {
                        "artifact_analyses": [
                            {
                                "kind": "btides",
                                "packet_count": 3,
                                "summary": "BTIDES capture with 3 LMP packet(s)",
                                "findings": ["lmp_feature_exchange_observed=yes"],
                            }
                        ]
                    },
                },
                "gatt": {
                    "status": "completed",
                    "service_count": 1,
                    "characteristic_count": 2,
                    "services": [],
                    "security_summary": {
                        "writable_characteristics": 1,
                        "protected_characteristics": 1,
                    },
                },
            },
        }
    )

    output = tmp_path / "recon-report.json"
    report.generate_json(str(output))
    payload = json.loads(output.read_text())

    assert payload["modules"]["recon"]["capabilities"]
    assert payload["modules"]["recon"]["prerequisites"]
    assert payload["modules"]["recon"]["correlations"]
    assert payload["modules"]["recon"]["cli_events"]
    assert payload["modules"]["recon"]["capture_summaries"]
    assert payload["modules"]["recon"]["capture_analysis"]
    assert payload["modules"]["recon"]["artifacts"]
    assert payload["modules"]["recon"]["gatt_results"]
    assert payload["modules"]["recon"]["correlations"][0]["spec_interpretation"]["classic"]["findings"]


def test_recon_html_renders_cli_events_and_capture_details():
    report = ReportGenerator()
    report.add_run_envelope(
        {
            "schema": "blue_tap.recon.result",
            "schema_version": 2,
            "module": "recon",
            "run_id": "recon-demo-2",
            "target": "AA:BB:CC:DD:EE:FF",
            "adapter": "hci0",
            "started_at": "2026-04-10T00:00:00+00:00",
            "completed_at": "2026-04-10T00:00:05+00:00",
            "operator_context": {"operation": "recon_auto"},
            "summary": {"classification": "dual_mode"},
            "executions": [
                {
                    "execution_id": "exec-hci-1",
                    "id": "recon_hci_capture",
                    "title": "HCI Capture",
                    "module": "recon",
                    "protocol": "HCI",
                    "execution_status": "completed",
                    "module_outcome": "artifact_collected",
                    "evidence": {"summary": "HCI capture completed"},
                    "artifacts": [
                        {"artifact_id": "artifact-2", "kind": "capture", "label": "HCI capture", "path": "/tmp/hci.btsnoop"}
                    ],
                    "module_data": {},
                }
            ],
            "artifacts": [
                {"artifact_id": "artifact-2", "kind": "capture", "label": "HCI capture", "path": "/tmp/hci.btsnoop"}
            ],
            "module_data": {
                "cli_events": [
                    {
                        "timestamp": "2026-04-10T00:00:00+00:00",
                        "event_type": "run_started",
                        "execution_id": "",
                        "message": "Recon run started",
                        "target": "AA:BB:CC:DD:EE:FF",
                        "adapter": "hci0",
                        "details": {"duration": 3},
                    },
                    {
                        "timestamp": "2026-04-10T00:00:01+00:00",
                        "event_type": "artifact_saved",
                        "execution_id": "recon_hci_capture",
                        "message": "HCI capture saved to /tmp/hci.btsnoop",
                        "target": "AA:BB:CC:DD:EE:FF",
                        "adapter": "hci0",
                        "details": {"path": "/tmp/hci.btsnoop"},
                    },
                ],
                "hci_capture": {
                    "status": "completed",
                    "output": "/tmp/hci.btsnoop",
                    "result": {"success": True, "packets": 42, "output": "/tmp/hci.btsnoop", "duration": 3},
                },
            },
        }
    )

    html = report._build_recon_html()

    assert "artifact_saved" in html
    assert "/tmp/hci.btsnoop" in html
    assert "Timestamp" in html


def test_capture_analysis_parses_btides_and_combined_artifacts(tmp_path):
    btides_path = tmp_path / "lmp.json"
    btides_path.write_text(
        json.dumps(
            {
                "format": "btides",
                "version": 2,
                "captures": [
                    {
                        "bdaddr": "AA:BB:CC:DD:EE:FF",
                        "bdaddr_local": "11:22:33:44:55:66",
                        "LMPArray": [
                            {"opcode": 40, "decoded": {"opcode_name": "LMP_features_res", "features_hex": "abcd"}},
                            {"opcode": 38, "decoded": {"opcode_name": "LMP_version_res", "bt_version": 6, "company_id": 123, "subversion": 1}},
                            {"opcode": 16, "decoded": {"opcode_name": "LMP_encryption_key_size_req", "key_size": 16}},
                            {"opcode": 59, "decoded": {"opcode_name": "LMP_dhkey_check"}},
                        ],
                    }
                ],
            }
        )
    )

    combined_path = tmp_path / "combined.json"
    combined_path.write_text(
        json.dumps(
            {
                "format": "combined_capture",
                "version": 1,
                "total_events": 3,
                "events": [
                    {"source": "lmp", "timestamp": 1.0},
                    {"source": "ble", "timestamp": 2.0},
                    {"source": "ble", "timestamp": 3.0},
                ],
            }
        )
    )

    module_data = {
        "lmp_capture": {"status": "completed", "output": str(btides_path), "size_bytes": btides_path.stat().st_size},
        "combined_capture": {"status": "completed", "output": str(combined_path), "size_bytes": combined_path.stat().st_size},
        "pairing_mode": {"ssp_supported": True, "io_capability": "KeyboardOnly", "pairing_method": "Numeric Comparison"},
    }

    analysis = analyze_capture_results(module_data)

    assert "lmp_capture_collected" in analysis["findings"]
    assert "decoded_lmp_packets=yes" in analysis["findings"]
    assert "lmp_features_observed=yes" in analysis["findings"]
    assert "lmp_auth_exchange_observed=yes" in analysis["findings"]
    assert "lmp_encryption_negotiation_observed=yes" in analysis["findings"]
    assert "min_lmp_key_size=16" in analysis["findings"]
    assert "combined_capture_collected" in analysis["findings"]
    assert "combined_ble_events_observed" in analysis["findings"]
    assert "ble_capture_activity=yes" in analysis["findings"]
    assert "lmp_capture_activity=yes" in analysis["findings"]
    assert analysis["details"]["lmp_capture"]["artifact_analysis"]["packet_count"] == 4
    assert analysis["details"]["lmp_capture"]["artifact_analysis"]["auth_packets"] == 1
    assert analysis["details"]["combined_capture"]["artifact_analysis"]["packet_count"] == 3


def test_pcap_analysis_extracts_smp_and_crackle_signals(tmp_path, monkeypatch):
    pcap_path = tmp_path / "ble5_pairing.pcap"
    pcap_path.write_bytes(b"pcap")

    def fake_check_tool(tool):
        return tool in {"tshark", "crackle"}

    def fake_run_cmd(cmd, timeout=0):
        class Result:
            def __init__(self, returncode=0, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if cmd[:4] == ["tshark", "-r", str(pcap_path), "-T"] or cmd[:3] == ["tshark", "-r", str(pcap_path)] and "frame.number" in cmd:
            return Result(stdout="1\n2\n3\n4\n")
        if cmd[:3] == ["tshark", "-r", str(pcap_path)] and "btsmp" in cmd:
            return Result(stdout="0x01\t0x03\t0x00\t0x01\t16\t0x07\t0x07\t\n0x02\t0x03\t0x00\t0x01\t16\t0x07\t0x07\t\n")
        if cmd[:3] == ["tshark", "-r", str(pcap_path)] and "btl2cap" in cmd:
            return Result(stdout="0x0006\t\n0x0004\t\n")
        if cmd[:3] == ["tshark", "-r", str(pcap_path)] and "btrfcomm" in cmd:
            return Result(stdout="")
        if cmd[:2] == ["crackle", "-i"]:
            return Result(stdout="TK found: 000000\nLTK found: 81b06facd90fe7a6e9bbd9cee59736a7\nSuccessfully cracked\n")
        return Result(returncode=1, stderr="unsupported")

    monkeypatch.setattr("blue_tap.recon.correlation.check_tool", fake_check_tool)
    monkeypatch.setattr("blue_tap.recon.correlation.run_cmd", fake_run_cmd)

    analysis = analyze_capture_artifact(str(pcap_path))

    assert analysis["kind"] == "pcap"
    assert "ble_smp_messages=2" in analysis["findings"]
    assert "ble_crackability=legacy_justworks_trivially_crackable" in analysis["findings"]
    assert "crackle_success" in analysis["findings"]
    assert "ble_ltk_recovered" in analysis["findings"]


def test_recon_correlation_promotes_ble_pcap_interpretation():
    correlation = build_recon_correlation(
        capability={"classification": "dual_mode"},
        fingerprint=None,
        sdp_result={"services": []},
        rfcomm_results=[],
        l2cap_results=[],
        gatt_result=None,
        pairing_mode={"ssp_supported": True, "pairing_method": "Just Works"},
        capture_analyses=[
            {
                "kind": "pcap",
                "smp_analysis": {
                    "evaluation": {
                        "posture": "ble_pairing_observed",
                        "crackability": "legacy_justworks_trivially_crackable",
                        "findings": ["ble_association_model=just_works", "ble_secure_connections=no"],
                    }
                },
                "crackle_summary": {"result": {"success": True, "ltk": "abcd"}},
                "source_counts": {"ble": 2},
                "signal_counts": {"pairing_or_auth_activity": 1},
                "findings": [],
            }
        ],
    )

    assert "ble_capture_crackability=legacy_justworks_trivially_crackable" in correlation["spec_interpretation"]["ble"]["findings"]
    assert "ble_capture_keys_recovered" in correlation["spec_interpretation"]["ble"]["findings"]
