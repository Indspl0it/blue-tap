"""Standardized demo report envelope builders."""

from __future__ import annotations

from blue_tap.modules.assessment.cve_framework import summarize_check, summarize_findings, build_vulnscan_result
from blue_tap.modules.exploitation.dos.framework import build_dos_run_result, summarize_dos_checks
from blue_tap.framework.envelopes.fuzz import build_fuzz_campaign_result
from blue_tap.framework.envelopes.recon import build_recon_result
from blue_tap.framework.contracts.result_schema import now_iso
from blue_tap.framework.envelopes.scan import build_scan_result


def build_demo_scan_result(*, devices: list[dict], adapter: str, duration_requested: int) -> dict:
    started_at = now_iso()
    collectors = [
        {
            "collector_id": "demo_discovery",
            "title": "Demo Discovery Dataset",
            "device_count": len(devices),
            "metadata": {"adapter": adapter, "passive": False, "source": "demo"},
        }
    ]
    return build_scan_result(
        module_id="discovery.scanner",
        scan_mode="all",
        adapter=adapter,
        duration_requested=duration_requested,
        passive=False,
        devices=devices,
        collectors=collectors,
        started_at=started_at,
    )


def build_demo_vuln_result(*, target: str, adapter: str, findings: list[dict]) -> dict:
    started_at = now_iso()
    cve_checks = []
    non_cve_checks = []
    for finding in findings:
        check = {
            "cve": finding.get("cve") or "N/A",
            "title": finding.get("name", "Demo Vulnerability Finding"),
            "section": "Demo Vuln Findings",
            **summarize_check([finding]),
        }
        if finding.get("cve"):
            cve_checks.append(check)
        else:
            non_cve_checks.append({
                "check_id": finding.get("name", "demo_non_cve").lower().replace(" ", "_"),
                "title": finding.get("name", "Demo Non-CVE Finding"),
                "section": "Demo Exposure Findings",
                **summarize_check([finding]),
            })
    return build_vulnscan_result(
        target=target,
        adapter=adapter,
        active=True,
        findings=findings,
        cve_checks=cve_checks,
        non_cve_checks=non_cve_checks,
        started_at=started_at,
    )


def build_demo_recon_result(*, target: str, adapter: str, entries: list[dict]) -> dict:
    return build_recon_result(
        module_id="reconnaissance.demo_recon",
        target=target,
        adapter=adapter,
        operation="demo_recon_dataset",
        title="Demo Reconnaissance Dataset",
        protocol="Recon",
        entries=entries,
        module_data_extra={"source": "demo"},
        evidence_summary=f"{len(entries)} demo recon entry(s) loaded",
        observations=["source=demo", f"entry_count={len(entries)}"],
        started_at=now_iso(),
    )


def build_demo_fingerprint_result(*, target: str, adapter: str, fingerprint: dict) -> dict:
    return build_recon_result(
        module_id="reconnaissance.demo_fingerprint",
        target=target,
        adapter=adapter,
        operation="demo_fingerprint",
        title="Demo Fingerprint Dataset",
        protocol="Fingerprint",
        entries=[],
        fingerprint=fingerprint,
        module_data_extra={"source": "demo"},
        evidence_summary="Demo fingerprint dataset loaded",
        observations=["source=demo", f"name={fingerprint.get('name', '')}"],
        started_at=now_iso(),
    )


def build_demo_dos_result(*, target: str, adapter: str, checks: list[dict]) -> dict:
    normalized_checks = []
    for check in checks:
        result = str(check.get("result", ""))
        if result == "target_unresponsive":
            status = "unresponsive"
            recovered = False
            waited_seconds = 180
        elif result == "target_degraded":
            status = "recovered"
            recovered = True
            waited_seconds = 8
        else:
            status = "success"
            recovered = True
            waited_seconds = 0
        normalized_checks.append({
            "check_id": check.get("method", "demo_dos"),
            "title": check.get("test", "Demo DoS Check"),
            "protocol": "Demo",
            "status": status,
            "destructive": True,
            "requires_pairing": False,
            "evidence": check.get("details", ""),
            "raw_result": dict(check),
            "recovery": {
                "recovered": recovered,
                "waited_seconds": waited_seconds,
                "probe_strategy": ["demo"],
                "probe_details": [],
            },
            "started_at": now_iso(),
            "completed_at": now_iso(),
        })
    return build_dos_run_result(
        target=target,
        adapter=adapter,
        mode="all",
        checks=normalized_checks,
        started_at=now_iso(),
    )


def build_demo_fuzz_result(*, target: str, adapter: str, fuzz_results: dict) -> dict:
    protocol_stats = fuzz_results.get("protocol_stats", {}) or {}
    crash_details = fuzz_results.get("crash_details", []) or []
    campaign_summary = {
        "target": target,
        "strategy": fuzz_results.get("strategy", "demo"),
        "runtime_seconds": fuzz_results.get("duration_seconds", 0),
        "packets_sent": fuzz_results.get("packets_sent", 0),
        "crashes": fuzz_results.get("crashes", len(crash_details)),
        "errors": fuzz_results.get("anomalies_detected", 0),
        "protocols": list(fuzz_results.get("protocols_fuzzed", [])),
        "protocol_breakdown": {
            proto: int((stats or {}).get("packets", 0))
            for proto, stats in protocol_stats.items()
        },
        "result": fuzz_results.get("status", "complete"),
    }
    crashes = []
    for crash in crash_details:
        crashes.append(
            {
                "protocol": crash.get("protocol", "unknown"),
                "severity": crash.get("severity", "UNKNOWN"),
                "timestamp": crash.get("timestamp", ""),
                "crash_type": crash.get("description", "demo_crash"),
                "payload_hex": crash.get("input_hex", ""),
                "payload_len": len(str(crash.get("input_hex", ""))) // 2,
                "response_hex": "",
                "notes": crash.get("response", ""),
                "mutation_log": crash.get("reproduction", ""),
                "target_addr": target,
                "reproduced": 1 if "3/3" in str(crash.get("reproduction", "")) or "2/2" in str(crash.get("reproduction", "")) else 0,
            }
        )
    return build_fuzz_campaign_result(
        module_id="fuzzing.engine",
        target=target,
        adapter=adapter,
        campaign_summary=campaign_summary,
        crashes=crashes,
        session_fuzz_dir="",
        started_at=now_iso(),
    )
