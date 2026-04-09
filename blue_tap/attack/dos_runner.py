"""High-level DoS runner with modular check execution and recovery handling."""

from __future__ import annotations

from blue_tap.attack.dos_framework import (
    DOS_STATUS_NOT_APPLICABLE,
    DOS_STATUS_RECOVERED,
    DOS_STATUS_SUCCESS,
    DOS_STATUS_UNRESPONSIVE,
    build_dos_run_result,
    default_recovery_probes,
    infer_dos_status,
    now_iso,
    probe_target_responsive,
    wait_for_target_recovery,
)
from blue_tap.attack.dos_registry import DOS_CHECK_INDEX, DOS_CHECKS
from blue_tap.utils.bt_helpers import ensure_adapter_ready
from blue_tap.utils.output import info, section, success, warning


def list_dos_checks() -> list[dict]:
    return [
        {
            "check_id": check.check_id,
            "title": check.title,
            "protocol": check.protocol,
            "description": check.description,
            "default_params": check.default_params,
            "requires_darkfirmware": check.requires_darkfirmware,
            "requires_pairing": check.requires_pairing,
            "cves": list(check.cves),
            "category": check.category,
            "recovery_probes": list(check.recovery_probes or default_recovery_probes(check.protocol)),
        }
        for check in DOS_CHECKS
    ]


def _normalize_params(defaults: dict, overrides: dict | None) -> dict:
    params = dict(defaults)
    if overrides:
        params.update(overrides)
    return params


def _run_one_check(address: str, hci: str, check_id: str, params: dict | None = None,
                   recovery_timeout: int = 180) -> dict:
    check = DOS_CHECK_INDEX[check_id]
    merged_params = _normalize_params(check.default_params, params)
    effective_hci = str(merged_params.pop("hci", hci))
    started_at = now_iso()
    recovery_probes = tuple(check.recovery_probes or default_recovery_probes(check.protocol))

    info(f"[DoS] {check.check_id} — {check.title}")
    info(f"[DoS] protocol={check.protocol} destructive={check.destructive} params={merged_params if merged_params else '{}'}")
    info(f"[DoS] recovery probes={','.join(recovery_probes)}")
    if check.requires_pairing:
        warning(f"[DoS] {check.check_id}: this check requires an existing bond or active pairing context")

    if check.requires_darkfirmware:
        try:
            from blue_tap.core.firmware import DarkFirmwareManager

            if not DarkFirmwareManager().is_darkfirmware_loaded(effective_hci):
                return {
                    "check_id": check.check_id,
                    "title": check.title,
                "protocol": check.protocol,
                "status": DOS_STATUS_NOT_APPLICABLE,
                "params": merged_params,
                "requires_darkfirmware": True,
                "requires_pairing": check.requires_pairing,
                "evidence": f"DarkFirmware not loaded on {effective_hci}",
                "raw_result": {},
                "recovery": {"probe_strategy": list(recovery_probes)},
                "started_at": started_at,
                "completed_at": now_iso(),
            }
        except Exception as exc:
            return {
                "check_id": check.check_id,
                "title": check.title,
                "protocol": check.protocol,
                "status": DOS_STATUS_NOT_APPLICABLE,
                "params": merged_params,
                "requires_darkfirmware": True,
                "requires_pairing": check.requires_pairing,
                "evidence": f"Could not verify DarkFirmware on {effective_hci}: {exc}",
                "raw_result": {},
                "recovery": {"probe_strategy": list(recovery_probes)},
                "started_at": started_at,
                "completed_at": now_iso(),
            }

    try:
        raw_result = check.runner(address, hci=effective_hci, **merged_params)
    except Exception as exc:
        return {
            "check_id": check.check_id,
            "title": check.title,
            "protocol": check.protocol,
            "status": "error",
            "params": merged_params,
            "requires_pairing": check.requires_pairing,
            "evidence": str(exc),
            "raw_result": {},
            "recovery": {"probe_strategy": list(recovery_probes)},
            "started_at": started_at,
            "completed_at": now_iso(),
        }

    status = infer_dos_status(raw_result)
    recovery = {}

    if check.requires_pairing and status == DOS_STATUS_NOT_APPLICABLE:
        warning(f"[DoS] {check.check_id}: pairing/bonding precondition was not met in this session")

    if status == DOS_STATUS_UNRESPONSIVE:
        warning(f"[DoS] {check.check_id}: target appears unresponsive; waiting for recovery")
        recovery = wait_for_target_recovery(
            address,
            effective_hci,
            timeout_seconds=recovery_timeout,
            recovery_probes=recovery_probes,
        )
        if recovery.get("recovered"):
            status = DOS_STATUS_RECOVERED
            success(f"[DoS] {check.check_id}: target recovered after {recovery.get('waited_seconds')}s")
        else:
            warning(f"[DoS] {check.check_id}: target did not recover within {recovery_timeout}s")
    else:
        responsive, probe, probe_details = probe_target_responsive(address, effective_hci, recovery_probes)
        recovery = {
            "recovered": responsive,
            "waited_seconds": 0,
            "last_probe": probe,
            "probe_details": probe_details,
            "probe_strategy": list(recovery_probes),
        }
        if not responsive and status == DOS_STATUS_SUCCESS:
            warning(f"[DoS] {check.check_id}: post-check reachability probe failed; waiting for recovery")
            recovery = wait_for_target_recovery(
                address,
                effective_hci,
                timeout_seconds=recovery_timeout,
                recovery_probes=recovery_probes,
            )
            if recovery.get("recovered"):
                status = DOS_STATUS_RECOVERED
            else:
                status = DOS_STATUS_UNRESPONSIVE

    evidence_bits = []
    for key in ("result", "target_status", "notes", "error"):
        value = raw_result.get(key)
        if value:
            evidence_bits.append(f"{key}={value}")
    if recovery.get("last_probe"):
        evidence_bits.append(f"recovery_probe={recovery['last_probe']}")

    return {
        "check_id": check.check_id,
        "title": check.title,
        "protocol": check.protocol,
        "category": check.category,
        "cves": list(check.cves),
        "destructive": check.destructive,
        "requires_darkfirmware": check.requires_darkfirmware,
        "requires_pairing": check.requires_pairing,
        "params": merged_params,
        "status": status,
        "evidence": "; ".join(evidence_bits),
        "raw_result": raw_result,
        "recovery": recovery,
        "started_at": started_at,
        "completed_at": now_iso(),
    }


def run_dos_checks(address: str, hci: str = "hci0", check_ids: list[str] | None = None,
                   param_overrides: dict[str, dict] | None = None,
                   recovery_timeout: int = 180) -> dict:
    started_at = now_iso()
    selected = check_ids or [check.check_id for check in DOS_CHECKS]
    checks: list[dict] = []
    interrupted_on: str | None = None
    abort_reason: str | None = None

    if not ensure_adapter_ready(hci):
        return build_dos_run_result(
            target=address,
            adapter=hci,
            mode="all" if len(selected) > 1 else "single",
            checks=[{
                "check_id": "adapter_prereq",
                "title": "Adapter Readiness",
                "protocol": "local",
                "status": "error",
                "params": {},
                "evidence": f"Adapter {hci} not ready",
                "raw_result": {},
            }],
            selected_checks=selected,
            started_at=started_at,
            recovery_timeout=recovery_timeout,
            abort_reason=f"Adapter {hci} not ready",
        )

    for check_id in selected:
        check = DOS_CHECK_INDEX.get(check_id)
        if check is None:
            checks.append({
                "check_id": check_id,
                "title": "Unknown DoS Check",
                "protocol": "unknown",
                "status": "error",
                "params": {},
                "evidence": f"Unknown DoS check id: {check_id}",
                "raw_result": {},
            })
            continue
        section_title = f"DoS Check: {check.title}"
        section(section_title, style="bt.cyan")
        result = _run_one_check(
            address,
            hci,
            check_id,
            params=(param_overrides or {}).get(check_id),
            recovery_timeout=recovery_timeout,
        )
        checks.append(result)
        if result["status"] == DOS_STATUS_UNRESPONSIVE:
            warning(f"[DoS] Aborting remaining checks because {check_id} left the target unresponsive")
            interrupted_on = check_id
            abort_reason = f"{check_id} left target unresponsive after recovery wait"
            break

    return build_dos_run_result(
        target=address,
        adapter=hci,
        mode="all" if len(selected) > 1 else "single",
        checks=checks,
        selected_checks=selected,
        started_at=started_at,
        recovery_timeout=recovery_timeout,
        interrupted_on=interrupted_on,
        abort_reason=abort_reason,
    )
