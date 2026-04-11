"""Shared CVE finding schema, summaries, and orchestration helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_ERROR,
    build_run_envelope,
    make_evidence,
    make_execution,
    now_iso,
)


STATUS_CONFIRMED = "confirmed"
STATUS_NOT_DETECTED = "not_detected"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_PAIRING_REQUIRED = "pairing_required"
STATUS_NOT_APPLICABLE = "not_applicable"

LEGACY_STATUS_POTENTIAL = "potential"
LEGACY_STATUS_UNVERIFIED = "unverified"

ACTIVE_CVE_STATUSES = (
    STATUS_CONFIRMED,
    STATUS_NOT_DETECTED,
    STATUS_INCONCLUSIVE,
    STATUS_PAIRING_REQUIRED,
    STATUS_NOT_APPLICABLE,
)

ALL_STATUSES = ACTIVE_CVE_STATUSES + (
    LEGACY_STATUS_POTENTIAL,
    LEGACY_STATUS_UNVERIFIED,
)

STATUS_ORDER = {
    STATUS_CONFIRMED: 0,
    STATUS_NOT_DETECTED: 1,
    LEGACY_STATUS_POTENTIAL: 2,
    LEGACY_STATUS_UNVERIFIED: 3,
    STATUS_INCONCLUSIVE: 4,
    STATUS_PAIRING_REQUIRED: 5,
    STATUS_NOT_APPLICABLE: 6,
}


@dataclass(frozen=True)
class CveCheck:
    """Structured metadata for one CVE probe."""

    cve: str
    title: str
    runner: Callable[..., list[dict]]
    args: tuple[Any, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CveSection:
    """Logical grouping of related CVE checks."""

    title: str
    checks: tuple[CveCheck, ...]


@dataclass(frozen=True)
class ScanCheck:
    """Structured metadata for one non-CVE scanner check."""

    check_id: str
    title: str
    runner: Callable[..., list[dict]]
    args: tuple[Any, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScanSection:
    """Logical grouping of related non-CVE scanner checks."""

    title: str
    checks: tuple[ScanCheck, ...]


def make_cve_finding(
    severity: str,
    name: str,
    description: str,
    *,
    cve: str = "N/A",
    impact: str = "",
    remediation: str = "",
    status: str = STATUS_CONFIRMED,
    confidence: str = "high",
    evidence: str = "",
    category: str = "cve",
    transport: str = "",
    destructive: bool = False,
    requires_pairing: bool = False,
    preconditions: list[str] | None = None,
    check_title: str = "",
) -> dict:
    """Create a normalized finding dict used by CVE check modules and reports."""

    return {
        "severity": severity,
        "name": name,
        "description": description,
        "impact": impact,
        "cve": cve,
        "remediation": remediation,
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "category": category,
        "transport": transport,
        "destructive": destructive,
        "requires_pairing": requires_pairing or status == STATUS_PAIRING_REQUIRED,
        "preconditions": list(preconditions or []),
        "check_title": check_title or cve,
    }

def summarize_findings(findings: list[dict]) -> dict:
    """Summarize finding counts in a report-friendly format."""

    status_counts = Counter(f.get("status", LEGACY_STATUS_POTENTIAL) for f in findings)
    severity_counts = Counter(str(f.get("severity", "INFO")).upper() for f in findings)
    skipped = status_counts.get(STATUS_NOT_APPLICABLE, 0)
    return {
        "total": len(findings),
        "displayed": len(findings) - skipped,
        "status_counts": {status: status_counts.get(status, 0) for status in ALL_STATUSES if status_counts.get(status, 0)},
        "severity_counts": dict(severity_counts),
        "confirmed": status_counts.get(STATUS_CONFIRMED, 0),
        "not_detected": status_counts.get(STATUS_NOT_DETECTED, 0),
        "potential": status_counts.get(LEGACY_STATUS_POTENTIAL, 0),
        "unverified": status_counts.get(LEGACY_STATUS_UNVERIFIED, 0),
        "inconclusive": status_counts.get(STATUS_INCONCLUSIVE, 0),
        "pairing_required": status_counts.get(STATUS_PAIRING_REQUIRED, 0),
        "not_applicable": skipped,
        "high_or_critical": sum(
            1 for f in findings if str(f.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
        ),
    }


def summarize_check(findings: list[dict]) -> dict:
    """Summarize the outcome of a single CVE check."""

    status_counts = Counter(f.get("status", STATUS_INCONCLUSIVE) for f in findings)
    primary_status = STATUS_NOT_DETECTED
    if findings:
        ranked = sorted(status_counts, key=lambda s: (STATUS_ORDER.get(s, 99), s))
        primary_status = ranked[0]
    evidence_samples = [str(f.get("evidence", "")).strip() for f in findings if f.get("evidence")]
    return {
        "finding_count": len(findings),
        "primary_status": primary_status,
        "status_counts": dict(status_counts),
        "evidence_samples": evidence_samples[:3],
    }


def build_vulnscan_result(
    *,
    target: str,
    adapter: str,
    active: bool,
    findings: list[dict],
    cve_checks: list[dict],
    non_cve_checks: list[dict] | None = None,
    started_at: str,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict:
    """Build the structured vulnscan envelope for logging and reports."""
    finished = completed_at or now_iso()
    executions: list[dict] = []
    for check in cve_checks:
        summary = check.get("evidence_samples", [])
        evidence = make_evidence(
            summary=summary[0] if summary else f"{check.get('title', check.get('cve', 'check'))} completed",
            confidence="high" if check.get("primary_status") == STATUS_CONFIRMED else "medium",
            observations=summary,
            module_evidence={
                "section": check.get("section", ""),
                "status_counts": check.get("status_counts", {}),
                "finding_count": check.get("finding_count", 0),
                "cve": check.get("cve", ""),
            },
        )
        executions.append(
            make_execution(
                kind="check",
                id=str(check.get("cve", "") or check.get("title", "cve_check")).lower().replace(" ", "_"),
                title=check.get("title", check.get("cve", "CVE Check")),
                module="vulnscan",
                protocol=check.get("section", "CVE").split(":")[0].replace("Check", "").strip() or "CVE",
                execution_status=EXECUTION_ERROR if check.get("error") else EXECUTION_COMPLETED,
                module_outcome=check.get("primary_status", STATUS_INCONCLUSIVE),
                severity=None,
                destructive=False,
                requires_pairing=check.get("primary_status") == STATUS_PAIRING_REQUIRED,
                started_at=started_at,
                completed_at=finished,
                evidence=evidence,
                notes=[check["error"]] if check.get("error") else [],
                tags=["vulnscan", "cve"],
                module_data=dict(check),
            )
        )
    for check in non_cve_checks or []:
        summary = check.get("evidence_samples", [])
        evidence = make_evidence(
            summary=summary[0] if summary else f"{check.get('title', check.get('check_id', 'check'))} completed",
            confidence="medium",
            observations=summary,
            module_evidence={
                "section": check.get("section", ""),
                "status_counts": check.get("status_counts", {}),
                "finding_count": check.get("finding_count", 0),
            },
        )
        executions.append(
            make_execution(
                kind="check",
                id=str(check.get("check_id", "non_cve_check")),
                title=check.get("title", "Non-CVE Check"),
                module="vulnscan",
                protocol=check.get("section", "Posture").split(":")[0].replace("Check", "").strip() or "Posture",
                execution_status=EXECUTION_ERROR if check.get("error") else EXECUTION_COMPLETED,
                module_outcome=check.get("primary_status", STATUS_INCONCLUSIVE),
                severity=None,
                destructive=False,
                requires_pairing=check.get("primary_status") == STATUS_PAIRING_REQUIRED,
                started_at=started_at,
                completed_at=finished,
                evidence=evidence,
                notes=[check["error"]] if check.get("error") else [],
                tags=["vulnscan", "non-cve"],
                module_data=dict(check),
            )
        )
    return build_run_envelope(
        schema="blue_tap.vulnscan.result",
        module="vulnscan",
        target=target,
        adapter=adapter,
        operator_context={"active": active},
        summary=summarize_findings(findings),
        executions=executions,
        module_data={
            "active": active,
            "findings": findings,
            "cve_checks": cve_checks,
            "non_cve_checks": list(non_cve_checks or []),
        },
        started_at=started_at,
        completed_at=finished,
        run_id=run_id,
    )


def build_vuln_probe_result(
    *,
    target: str,
    adapter: str,
    operation: str,
    title: str,
    protocol: str,
    raw_result: dict[str, Any],
    started_at: str,
    run_id: str | None = None,
    observations: list[str] | None = None,
    module_outcome: str | None = None,
) -> dict:
    """Wrap a standalone vulnerability probe in the standardized vuln envelope."""

    raw = dict(raw_result or {})
    outcome = module_outcome or (
        STATUS_CONFIRMED if raw.get("likely_vulnerable") or raw.get("legacy_fallback_possible") else STATUS_NOT_DETECTED
    )
    evidence_bits = list(observations or [])
    for key in ("bt_version", "io_capability", "method", "min_key_size_observed"):
        value = raw.get(key)
        if value not in (None, "", []):
            evidence_bits.append(f"{key}={value}")

    execution = make_execution(
        kind="check",
        id=operation,
        title=title,
        module="vulnscan",
        protocol=protocol,
        execution_status=EXECUTION_COMPLETED,
        module_outcome=outcome,
        started_at=started_at,
        completed_at=now_iso(),
        evidence=make_evidence(
            summary=f"{title} completed",
            confidence="medium",
            observations=evidence_bits,
            module_evidence=raw,
        ),
        tags=["vulnscan", "probe"],
        module_data=raw,
    )
    return build_run_envelope(
        schema="blue_tap.vulnscan.result",
        module="vulnscan",
        target=target,
        adapter=adapter,
        operator_context={"operation": operation, "active": False},
        summary=summarize_findings([]),
        executions=[execution],
        module_data={
            "active": False,
            "findings": [],
            "cve_checks": [],
            "non_cve_checks": [
                {
                    "check_id": operation,
                    "title": title,
                    "section": title,
                    "finding_count": 0,
                    "primary_status": outcome,
                    "status_counts": {outcome: 1},
                    "evidence_samples": evidence_bits,
                }
            ],
            "probe_result": raw,
        },
        started_at=started_at,
        completed_at=now_iso(),
        run_id=run_id,
    )
