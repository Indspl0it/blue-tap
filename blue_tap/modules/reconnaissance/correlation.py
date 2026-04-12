"""Recon protocol correlation helpers."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from blue_tap.modules.reconnaissance.spec_interpretation import (
    evaluate_smp_transcript,
    interpret_ble_capture,
    interpret_l2cap_probe,
    interpret_lmp_capture,
    interpret_rfcomm_probe,
    normalize_smp_message,
)
from blue_tap.utils.bt_helpers import check_tool, run_cmd

LMP_AUTH_OPCODES = {8, 9, 10, 11, 12, 13, 14, 59, 60, 61}
LMP_ENCRYPTION_OPCODES = {15, 16, 17, 18}
LMP_FEATURE_OPCODES = {37, 38, 39, 40}


def correlate_rfcomm_with_sdp(sdp_entries: list[dict], rfcomm_results: list[dict]) -> dict[str, Any]:
    advertised_channels = {
        int(entry["channel"]): _service_label(entry)
        for entry in sdp_entries
        if isinstance(entry, dict) and entry.get("protocol") == "RFCOMM" and entry.get("channel") is not None
    }
    hidden = []
    advertised_open = []
    advertised_unreachable = []
    protocol_hint_counts: Counter[str] = Counter()
    response_type_counts: Counter[str] = Counter()
    interesting_channels = []
    posture_counts: Counter[str] = Counter()

    for result in rfcomm_results:
        for hint in result.get("protocol_hints", []) or []:
            protocol_hint_counts[str(hint)] += 1
        response_type_counts[str(result.get("response_type", "unknown"))] += 1
        channel = result.get("channel")
        interpretation = interpret_rfcomm_probe(result, advertised=channel in advertised_channels)
        result["spec_interpretation"] = interpretation
        posture_counts[interpretation.get("posture", "indeterminate")] += 1
        if channel in advertised_channels:
            result["advertised_service"] = advertised_channels[channel]
            if result.get("status") == "open":
                advertised_open.append(result)
            elif result.get("status") in {"closed", "timeout", "host_unreachable"}:
                advertised_unreachable.append(
                    {"channel": channel, "service": advertised_channels[channel], "status": result.get("status", "")}
                )
        elif result.get("status") == "open":
            hidden.append(
                {
                    "channel": channel,
                    "response_type": result.get("response_type", ""),
                    "status": result.get("status", ""),
                    "banner_preview": result.get("banner_preview", ""),
                    "protocol_hints": result.get("protocol_hints", []),
                }
            )
        if result.get("status") == "open" and (
            channel not in advertised_channels
            or result.get("response_type") in {"at_modem", "obex", "raw_binary"}
        ):
            interesting_channels.append(
                {
                    "channel": channel,
                    "response_type": result.get("response_type", ""),
                    "protocol_hints": result.get("protocol_hints", []),
                    "banner_preview": result.get("banner_preview", ""),
                }
            )

    return {
        "advertised_channels": sorted(advertised_channels),
        "advertised_services": advertised_channels,
        "open_channels": [result.get("channel") for result in rfcomm_results if result.get("status") == "open"],
        "advertised_open": advertised_open,
        "hidden_channels": hidden,
        "advertised_unreachable": advertised_unreachable,
        "response_type_counts": dict(response_type_counts),
        "protocol_hint_counts": dict(protocol_hint_counts),
        "posture_counts": dict(posture_counts),
        "interesting_channels": interesting_channels,
    }


def correlate_l2cap_with_sdp(sdp_entries: list[dict], l2cap_results: list[dict]) -> dict[str, Any]:
    advertised_psms = {
        int(entry["psm"]): _service_label(entry)
        for entry in sdp_entries
        if isinstance(entry, dict) and entry.get("psm") is not None
    }
    observed = []
    unexpected = []
    advertised_closed = []
    dynamic_open_psms = []
    protected_psms = []
    posture_counts: Counter[str] = Counter()

    for result in l2cap_results:
        psm = result.get("psm")
        interpretation = interpret_l2cap_probe(result, advertised=psm in advertised_psms)
        result["spec_interpretation"] = interpretation
        posture_counts[interpretation.get("posture", "indeterminate")] += 1
        if psm in advertised_psms:
            result["advertised_service"] = advertised_psms[psm]
            if result.get("status") in {"open", "auth_required"}:
                observed.append(result)
            else:
                advertised_closed.append(
                    {"psm": psm, "service": advertised_psms[psm], "status": result.get("status", "")}
                )
        elif result.get("status") in {"open", "auth_required"}:
            unexpected.append(
                {
                    "psm": psm,
                    "status": result.get("status", ""),
                    "name": result.get("name", ""),
                    "behavior_hint": result.get("behavior_hint", ""),
                    "protocol_family": result.get("protocol_family", ""),
                }
            )
        if result.get("status") == "open" and int(psm or 0) >= 4097:
            dynamic_open_psms.append(
                {
                    "psm": psm,
                    "name": result.get("name", ""),
                    "behavior_hint": result.get("behavior_hint", ""),
                }
            )
        if result.get("status") == "auth_required":
            protected_psms.append(
                {
                    "psm": psm,
                    "name": result.get("name", ""),
                    "behavior_hint": result.get("behavior_hint", ""),
                }
            )

    return {
        "advertised_psms": sorted(advertised_psms),
        "advertised_services": advertised_psms,
        "observed_advertised_psms": observed,
        "unexpected_psms": unexpected,
        "advertised_closed": advertised_closed,
        "dynamic_open_psms": dynamic_open_psms,
        "protected_psms": protected_psms,
        "posture_counts": dict(posture_counts),
    }


def build_recon_correlation(
    *,
    capability: dict[str, Any],
    fingerprint: dict[str, Any] | None,
    sdp_result: dict[str, Any] | None,
    rfcomm_results: list[dict] | None,
    l2cap_results: list[dict] | None,
    gatt_result: dict[str, Any] | None,
    pairing_mode: dict[str, Any] | None = None,
    capture_analyses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sdp_entries = (sdp_result or {}).get("services", [])
    rfcomm = correlate_rfcomm_with_sdp(sdp_entries, rfcomm_results or []) if rfcomm_results is not None else {}
    l2cap = correlate_l2cap_with_sdp(sdp_entries, l2cap_results or []) if l2cap_results is not None else {}
    gatt_security = (gatt_result or {}).get("security_summary", {})

    findings = []
    if rfcomm.get("hidden_channels"):
        findings.append(f"hidden_rfcomm_channels={len(rfcomm['hidden_channels'])}")
    if rfcomm.get("protocol_hint_counts", {}).get("at_command_surface"):
        findings.append(f"rfcomm_at_surfaces={rfcomm['protocol_hint_counts']['at_command_surface']}")
    if rfcomm.get("protocol_hint_counts", {}).get("object_transfer"):
        findings.append(f"rfcomm_obex_surfaces={rfcomm['protocol_hint_counts']['object_transfer']}")
    if l2cap.get("unexpected_psms"):
        findings.append(f"unexpected_l2cap_psms={len(l2cap['unexpected_psms'])}")
    if l2cap.get("dynamic_open_psms"):
        findings.append(f"dynamic_l2cap_psms={len(l2cap['dynamic_open_psms'])}")
    if l2cap.get("protected_psms"):
        findings.append(f"protected_l2cap_psms={len(l2cap['protected_psms'])}")
    if gatt_security.get("protected_characteristics"):
        findings.append(f"protected_gatt_characteristics={gatt_security['protected_characteristics']}")
    if fingerprint and fingerprint.get("attack_surface"):
        findings.append(f"attack_surface_items={len(fingerprint.get('attack_surface', []))}")
    if isinstance(pairing_mode, dict):
        if pairing_mode.get("ssp_supported") is False:
            findings.append("ssp_not_supported")
        method = str(pairing_mode.get("pairing_method", "") or "")
        if method:
            findings.append(f"pairing_method={method}")
    capture_summary = summarize_capture_analyses(capture_analyses or [])
    findings.extend(capture_summary.get("findings", []))
    spec_interpretation = _build_spec_interpretation(
        rfcomm=rfcomm,
        l2cap=l2cap,
        capture_analyses=capture_analyses or [],
        pairing_mode=pairing_mode,
    )
    findings.extend(spec_interpretation.get("findings", []))

    return {
        "classification": capability.get("classification", "undetermined"),
        "rfcomm": rfcomm,
        "l2cap": l2cap,
        "gatt_security": gatt_security,
        "capture": capture_summary,
        "spec_interpretation": spec_interpretation,
        "findings": findings,
    }


def analyze_capture_artifact(path: str) -> dict[str, Any]:
    if not path:
        return {
            "path": "",
            "exists": False,
            "kind": "unknown",
            "summary": "no artifact path provided",
            "findings": [],
        }

    exists = os.path.exists(path)
    suffix = os.path.splitext(path)[1].lower()
    if not exists:
        return {
            "path": path,
            "exists": False,
            "kind": suffix.lstrip(".") or "unknown",
            "summary": "artifact missing",
            "findings": [f"missing_artifact={path}"],
        }

    if suffix == ".json":
        try:
            with open(path) as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "path": path,
                "exists": True,
                "kind": "json",
                "summary": f"unreadable JSON artifact: {exc}",
                "findings": [f"artifact_error={exc}"],
            }
        return _analyze_json_capture(path, payload)

    if suffix in {".pcap", ".btsnoop"}:
        return _analyze_pcap_capture(path)

    size_bytes = os.path.getsize(path)
    return {
        "path": path,
        "exists": True,
        "kind": suffix.lstrip(".") or "artifact",
        "size_bytes": size_bytes,
        "summary": f"artifact size={size_bytes} bytes",
        "findings": [f"artifact_size={size_bytes}"],
    }


def summarize_capture_analyses(analyses: list[dict[str, Any]]) -> dict[str, Any]:
    findings = []
    packet_total = 0
    for analysis in analyses:
        packet_total += int(analysis.get("packet_count", 0) or 0)
        findings.extend(analysis.get("findings", []))
    unique_findings = list(dict.fromkeys(findings))
    summary = {
        "artifact_count": len(analyses),
        "packet_count": packet_total,
        "findings": unique_findings,
    }
    if analyses:
        summary["summary"] = ", ".join(
            str(item.get("summary", "")) for item in analyses if item.get("summary")
        )
    return summary


def _service_label(entry: dict[str, Any]) -> str:
    return str(entry.get("name") or entry.get("profile") or entry.get("description") or "Unknown")


def _analyze_json_capture(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("format") == "combined_capture" or "events" in payload:
        events = payload.get("events", [])
        source_counts = Counter(str(evt.get("source", "unknown")) for evt in events if isinstance(evt, dict))
        findings = [f"{source}_events={count}" for source, count in sorted(source_counts.items())]
        signal_counts: Counter[str] = Counter()
        nested_artifacts = []
        for event in events:
            if not isinstance(event, dict):
                continue
            for signal in _extract_event_security_signals(event):
                signal_counts[signal] += 1
            result = event.get("result", {})
            if isinstance(result, dict):
                nested_output = str(result.get("output", "") or result.get("pcap", "") or "")
                if nested_output:
                    nested_artifacts.append(nested_output)
        findings.extend(f"{signal}=yes" for signal in sorted(signal_counts))
        if nested_artifacts:
            findings.append(f"nested_artifacts={len(nested_artifacts)}")
        return {
            "path": path,
            "exists": True,
            "kind": "combined_capture",
            "packet_count": len(events),
            "source_counts": dict(source_counts),
            "signal_counts": dict(signal_counts),
            "nested_artifacts": nested_artifacts,
            "summary": f"combined capture with {len(events)} event(s)",
            "findings": findings,
            "signals": sorted(signal_counts),
        }

    if payload.get("format") == "btides" or payload.get("captures"):
        captures = payload.get("captures", [])
        packets = []
        for capture in captures:
            packets.extend(capture.get("LMPArray", []) or [])
        opcode_counts = Counter(int(pkt.get("opcode", 0)) for pkt in packets if isinstance(pkt, dict))
        decoded = Counter()
        auth_packets = 0
        encryption_packets = 0
        feature_packets = 0
        key_sizes: list[int] = []
        company_ids = set()
        bt_versions = set()
        for pkt in packets:
            if not isinstance(pkt, dict):
                continue
            opcode = int(pkt.get("opcode", 0) or 0)
            if opcode in LMP_AUTH_OPCODES:
                auth_packets += 1
            if opcode in LMP_ENCRYPTION_OPCODES:
                encryption_packets += 1
            if opcode in LMP_FEATURE_OPCODES:
                feature_packets += 1
            decoded_fields = pkt.get("decoded", {}) or {}
            for key in ("opcode_name", "bt_version", "company_id", "subversion", "features_hex", "key_size"):
                if key in decoded_fields:
                    decoded[key] += 1
            if "key_size" in decoded_fields:
                try:
                    key_sizes.append(int(decoded_fields["key_size"]))
                except (TypeError, ValueError):
                    pass
            if "company_id" in decoded_fields:
                company_ids.add(str(decoded_fields["company_id"]))
            if "bt_version" in decoded_fields:
                bt_versions.add(str(decoded_fields["bt_version"]))
        findings = []
        if decoded.get("opcode_name"):
            findings.append("decoded_lmp_packets=yes")
        if decoded.get("features_hex"):
            findings.append("lmp_features_observed=yes")
        if decoded.get("bt_version"):
            findings.append("lmp_version_observed=yes")
        if decoded.get("key_size"):
            findings.append("encryption_key_size_observed=yes")
        if auth_packets:
            findings.append("lmp_auth_exchange_observed=yes")
        if encryption_packets:
            findings.append("lmp_encryption_negotiation_observed=yes")
        if feature_packets:
            findings.append("lmp_feature_exchange_observed=yes")
        if key_sizes:
            findings.append(f"min_lmp_key_size={min(key_sizes)}")
            if min(key_sizes) < 7:
                findings.append("weak_lmp_key_size_observed=yes")
        return {
            "path": path,
            "exists": True,
            "kind": "btides",
            "packet_count": len(packets),
            "opcode_counts": dict(opcode_counts),
            "decoded_fields": dict(decoded),
            "auth_packets": auth_packets,
            "encryption_packets": encryption_packets,
            "feature_packets": feature_packets,
            "observed_key_sizes": sorted(set(key_sizes)),
            "company_ids": sorted(company_ids),
            "bt_versions": sorted(bt_versions),
            "summary": f"BTIDES capture with {len(packets)} LMP packet(s)",
            "findings": findings,
            "signals": findings,
        }

    return {
        "path": path,
        "exists": True,
        "kind": "json",
        "packet_count": 0,
        "summary": "unclassified JSON capture artifact",
        "findings": ["unclassified_json_capture"],
    }


def _analyze_pcap_capture(path: str) -> dict[str, Any]:
    size_bytes = os.path.getsize(path)
    findings = [f"artifact_size={size_bytes}"]
    packet_count = None
    if check_tool("tshark"):
        result = run_cmd(["tshark", "-r", path, "-T", "fields", "-e", "frame.number"], timeout=20)
        if result.returncode == 0:
            packet_count = len([line for line in result.stdout.splitlines() if line.strip()])
            findings.append(f"tshark_packets={packet_count}")
    smp_analysis = _analyze_pcap_smp(path) if check_tool("tshark") else {}
    l2cap_summary = _analyze_pcap_l2cap(path) if check_tool("tshark") else {}
    rfcomm_summary = _analyze_pcap_rfcomm(path) if check_tool("tshark") else {}
    crackle_summary = _analyze_pcap_crackle(path, smp_analysis) if smp_analysis.get("messages") else {}
    findings.extend(smp_analysis.get("findings", []))
    findings.extend(l2cap_summary.get("findings", []))
    findings.extend(rfcomm_summary.get("findings", []))
    findings.extend(crackle_summary.get("findings", []))
    return {
        "path": path,
        "exists": True,
        "kind": "pcap",
        "size_bytes": size_bytes,
        "packet_count": packet_count or 0,
        "summary": f"pcap artifact ({size_bytes} bytes)",
        "findings": list(dict.fromkeys(findings)),
        "smp_analysis": smp_analysis,
        "l2cap_summary": l2cap_summary,
        "rfcomm_summary": rfcomm_summary,
        "crackle_summary": crackle_summary,
    }


def _extract_event_security_signals(event: dict[str, Any]) -> list[str]:
    signals: set[str] = set()
    event_type = str(event.get("type", "")).lower()
    text_parts = [event_type]
    for key, value in event.items():
        if key in {"result", "source", "timestamp"}:
            continue
        if isinstance(value, (str, int, float, bool)):
            text_parts.append(f"{key}={value}")
    result = event.get("result", {})
    if isinstance(result, dict):
        for key in ("success", "output", "pcap", "error", "target"):
            if key in result:
                text_parts.append(f"{key}={result.get(key)}")
    haystack = " ".join(text_parts).lower()

    if "pair" in haystack or "confirm" in haystack or "dhkey" in haystack or "auth" in haystack:
        signals.add("pairing_or_auth_activity")
    if "encrypt" in haystack or "key_size" in haystack or "ltk" in haystack or "link_key" in haystack:
        signals.add("encryption_activity")
    if "feature" in haystack or "version" in haystack or "company_id" in haystack or "subversion" in haystack:
        signals.add("feature_exchange_activity")
    if event.get("source") == "ble":
        signals.add("ble_capture_activity")
    if event.get("source") == "lmp":
        signals.add("lmp_capture_activity")
    return sorted(signals)


def _build_spec_interpretation(
    *,
    rfcomm: dict[str, Any],
    l2cap: dict[str, Any],
    capture_analyses: list[dict[str, Any]],
    pairing_mode: dict[str, Any] | None,
) -> dict[str, Any]:
    findings: list[str] = []
    classic = {"posture": "limited_visibility", "findings": []}
    ble = {"posture": "limited_visibility", "findings": []}

    if rfcomm.get("protocol_hint_counts", {}).get("at_command_surface"):
        classic["findings"].append("classic_telephony_control_surface_visible")
    if rfcomm.get("protocol_hint_counts", {}).get("object_transfer"):
        classic["findings"].append("classic_object_transfer_surface_visible")
    if l2cap.get("protected_psms"):
        classic["findings"].append("classic_l2cap_access_control_visible")
    if l2cap.get("dynamic_open_psms"):
        classic["findings"].append("classic_dynamic_l2cap_surface_visible")
    if classic["findings"]:
        classic["posture"] = "classic_surface_characterized"

    for analysis in capture_analyses:
        kind = str(analysis.get("kind", ""))
        if kind == "btides":
            lmp = interpret_lmp_capture(analysis, pairing_mode=pairing_mode)
            classic["findings"].extend(lmp.get("findings", []))
            if lmp.get("posture") != "limited_visibility":
                classic["posture"] = lmp["posture"]
        elif kind in {"combined_capture", "pcap"}:
            ble_capture = interpret_ble_capture(analysis, pairing_mode=pairing_mode)
            ble["findings"].extend(ble_capture.get("findings", []))
            if ble_capture.get("posture") != "limited_visibility":
                ble["posture"] = ble_capture["posture"]
            smp_evaluation = (analysis.get("smp_analysis", {}) or {}).get("evaluation", {}) or {}
            if smp_evaluation:
                ble["findings"].extend(smp_evaluation.get("findings", []))
                crackability = str(smp_evaluation.get("crackability", "unknown"))
                if crackability != "unknown":
                    ble["findings"].append(f"ble_capture_crackability={crackability}")
                posture = str(smp_evaluation.get("posture", ""))
                if posture and posture != "limited_visibility":
                    ble["posture"] = posture
            crackle_summary = analysis.get("crackle_summary", {}) or {}
            crackle_result = crackle_summary.get("result", {}) or {}
            if crackle_result.get("success"):
                ble["findings"].append("ble_capture_keys_recovered")
                ble["posture"] = "ble_keys_recovered"

    findings.extend(classic["findings"])
    findings.extend(ble["findings"])
    return {
        "classic": {"posture": classic["posture"], "findings": list(dict.fromkeys(classic["findings"]))},
        "ble": {"posture": ble["posture"], "findings": list(dict.fromkeys(ble["findings"]))},
        "findings": list(dict.fromkeys(findings)),
    }


def _analyze_pcap_smp(path: str) -> dict[str, Any]:
    fields = [
        "btsmp.opcode",
        "btsmp.io_capability",
        "btsmp.oob_data_flags",
        "btsmp.authreq",
        "btsmp.max_enc_key_size",
        "btsmp.initiator_key_distribution",
        "btsmp.responder_key_distribution",
        "btsmp.reason",
    ]
    records = _tshark_rows(path, "btsmp", fields)
    messages = []
    opcode_counts: Counter[str] = Counter()
    for record in records:
        message = {
            "opcode": _int_or_none(record.get("btsmp.opcode")),
            "io_capability": _int_or_none(record.get("btsmp.io_capability")),
            "oob_data_flags": _int_or_none(record.get("btsmp.oob_data_flags")),
            "authreq": _int_or_none(record.get("btsmp.authreq")),
            "max_enc_key_size": _int_or_none(record.get("btsmp.max_enc_key_size")),
            "initiator_key_distribution": _int_or_none(record.get("btsmp.initiator_key_distribution")),
            "responder_key_distribution": _int_or_none(record.get("btsmp.responder_key_distribution")),
            "reason": _int_or_none(record.get("btsmp.reason")),
        }
        if message["opcode"] is None:
            continue
        messages.append(normalize_smp_message({k: v for k, v in message.items() if v is not None}))
        opcode_counts[str(message["opcode"])] += 1
    if not messages:
        return {}
    evaluation = evaluate_smp_transcript(messages)
    findings = list(evaluation.get("findings", []))
    findings.append(f"ble_smp_messages={len(messages)}")
    return {
        "messages": messages,
        "opcode_counts": dict(opcode_counts),
        "evaluation": evaluation,
        "findings": findings,
    }


def _analyze_pcap_l2cap(path: str) -> dict[str, Any]:
    records = _tshark_rows(path, "btl2cap", ["btl2cap.cid", "btl2cap.psm"])
    psms = sorted({value for row in records if (value := _int_or_none(row.get("btl2cap.psm"))) is not None})
    cids = sorted({value for row in records if (value := _int_or_none(row.get("btl2cap.cid"))) is not None})
    findings = []
    if psms:
        findings.append(f"pcap_l2cap_psms={len(psms)}")
    if 6 in cids:
        findings.append("pcap_ble_smp_cid_seen")
    if 7 in cids:
        findings.append("pcap_bredr_smp_cid_seen")
    return {"psms": psms, "cids": cids, "findings": findings}


def _analyze_pcap_rfcomm(path: str) -> dict[str, Any]:
    records = _tshark_rows(path, "btrfcomm", ["btrfcomm.channel", "btrfcomm.frame_type"])
    channels = sorted({value for row in records if (value := _int_or_none(row.get("btrfcomm.channel"))) is not None})
    frame_types = Counter(str(row.get("btrfcomm.frame_type", "")) for row in records if row.get("btrfcomm.frame_type"))
    findings = []
    if channels:
        findings.append(f"pcap_rfcomm_channels={len(channels)}")
    return {"channels": channels, "frame_types": dict(frame_types), "findings": findings}


def _analyze_pcap_crackle(path: str, smp_analysis: dict[str, Any]) -> dict[str, Any]:
    evaluation = smp_analysis.get("evaluation", {}) or {}
    crackability = str(evaluation.get("crackability", "unknown"))
    if not crackability.startswith("legacy_"):
        return {}
    if not check_tool("crackle"):
        return {"findings": [f"crackle_recommended={crackability}"]}
    result = run_cmd(["crackle", "-i", path], timeout=60)
    output = (result.stdout or "") + (result.stderr or "")
    parsed = _parse_crackle_output(output)
    findings = [f"crackle_recommended={crackability}"]
    if parsed.get("success"):
        findings.append("crackle_success")
    if parsed.get("tk"):
        findings.append("ble_tk_recovered")
    if parsed.get("ltk"):
        findings.append("ble_ltk_recovered")
    if "secure connections" in output.lower():
        findings.append("crackle_secure_connections_detected")
    elif "no pairing" in output.lower():
        findings.append("crackle_no_pairing_exchange")
    return {"result": parsed, "findings": findings}


def _tshark_rows(path: str, display_filter: str, fields: list[str]) -> list[dict[str, str]]:
    cmd = ["tshark", "-r", path, "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    result = run_cmd(cmd, timeout=30)
    if result.returncode != 0:
        return []
    rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        row = {}
        for index, field in enumerate(fields):
            row[field] = parts[index].strip() if index < len(parts) else ""
        rows.append(row)
    return rows


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        return None


def _parse_crackle_output(output: str) -> dict[str, Any]:
    import re

    result = {"success": False, "tk": None, "ltk": None}
    tk_match = re.search(r"TK\s*(?:found|=)[:\s]+([0-9A-Fa-f]+)", output)
    if tk_match:
        result["tk"] = tk_match.group(1)
    ltk_match = re.search(r"LTK\s*(?:found|=)[:\s]+([0-9A-Fa-f]+)", output)
    if ltk_match:
        result["ltk"] = ltk_match.group(1)
    if result["tk"] or result["ltk"] or "successfully" in output.lower():
        result["success"] = True
    return result
