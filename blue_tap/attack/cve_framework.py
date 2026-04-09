"""Shared CVE finding schema, summaries, and orchestration helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


STATUS_CONFIRMED = "confirmed"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_PAIRING_REQUIRED = "pairing_required"
STATUS_NOT_APPLICABLE = "not_applicable"

LEGACY_STATUS_POTENTIAL = "potential"
LEGACY_STATUS_UNVERIFIED = "unverified"

ACTIVE_CVE_STATUSES = (
    STATUS_CONFIRMED,
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
    LEGACY_STATUS_POTENTIAL: 1,
    LEGACY_STATUS_UNVERIFIED: 2,
    STATUS_INCONCLUSIVE: 3,
    STATUS_PAIRING_REQUIRED: 4,
    STATUS_NOT_APPLICABLE: 5,
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    primary_status = STATUS_NOT_APPLICABLE
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
) -> dict:
    """Build the structured vulnscan envelope for logging and reports."""

    return {
        "schema": "blue_tap.vulnscan.result",
        "schema_version": 1,
        "target": target,
        "adapter": adapter,
        "active": active,
        "started_at": started_at,
        "completed_at": completed_at or now_iso(),
        "summary": summarize_findings(findings),
        "findings": findings,
        "cve_checks": cve_checks,
        "non_cve_checks": list(non_cve_checks or []),
    }
