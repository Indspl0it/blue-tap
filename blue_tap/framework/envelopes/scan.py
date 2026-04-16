"""Shared discovery scan orchestration helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    build_run_envelope,
    make_evidence,
    make_execution,
    now_iso,
)


@dataclass(frozen=True)
class ScanCollector:
    """Structured metadata for one discovery collector."""

    collector_id: str
    title: str
    runner: Callable[..., list[dict]]
    args: tuple[Any, ...] = field(default_factory=tuple)


def summarize_devices(devices: list[dict]) -> dict:
    """Build a compact summary for CLI/report consumers."""

    type_counts = Counter(str(d.get("type", "Unknown")) for d in devices)
    exact_dual_mode_matches = sum(1 for d in devices if d.get("merge_reason") == "exact_address")
    correlated_candidates = sum(1 for d in devices if d.get("possible_dual_mode_with"))
    devices_with_services = sum(1 for d in devices if d.get("service_uuids"))
    devices_with_mfr = sum(1 for d in devices if d.get("manufacturer_data") or d.get("manufacturer_name"))
    return {
        "device_count": len(devices),
        "type_counts": dict(type_counts),
        "exact_dual_mode_matches": exact_dual_mode_matches,
        "correlated_candidates": correlated_candidates,
        "devices_with_services": devices_with_services,
        "devices_with_manufacturer_data": devices_with_mfr,
    }


def _collector_execution(
    *,
    collector_id: str,
    title: str,
    started_at: str,
    completed_at: str,
    device_count: int,
    adapter: str,
    passive: bool,
    metadata: dict[str, Any],
) -> dict:
    evidence = make_evidence(
        summary=f"{device_count} device(s) observed by {title.lower()}",
        confidence="high",
        observations=[f"adapter={adapter or 'default'}", f"passive={passive}", f"device_count={device_count}"],
        module_evidence=metadata,
    )
    return make_execution(
        kind="collector",
        id=collector_id,
        title=title,
        module="discovery",
        protocol="Discovery",
        execution_status=EXECUTION_COMPLETED,
        module_outcome="observed",
        evidence=evidence,
        started_at=started_at,
        completed_at=completed_at,
        module_data={"device_count": device_count, **metadata},
        tags=["discovery", f"collector:{collector_id}"],
    )


def build_scan_result(
    *,
    scan_mode: str,
    adapter: str,
    duration_requested: int,
    passive: bool,
    devices: list[dict],
    collectors: list[dict],
    started_at: str,
    completed_at: str | None = None,
    run_id: str | None = None,
) -> dict:
    """Build the structured scan envelope for logging, reports, and JSON export."""
    finished = completed_at or now_iso()
    executions = [
        _collector_execution(
            collector_id=collector["collector_id"],
            title=collector["title"],
            started_at=started_at,
            completed_at=finished,
            device_count=collector.get("device_count", 0),
            adapter=str(collector.get("metadata", {}).get("adapter", adapter)),
            passive=bool(collector.get("metadata", {}).get("passive", passive)),
            metadata=collector.get("metadata", {}),
        )
        for collector in collectors
    ]
    return build_run_envelope(
        schema="blue_tap.scan.result",
        module="discovery",
        target="range_scan" if scan_mode != "all" else "combined_range_scan",
        adapter=adapter,
        operator_context={
            "scan_mode": scan_mode,
            "duration_requested": duration_requested,
            "passive": passive,
        },
        summary=summarize_devices(devices),
        executions=executions,
        module_data={
            "scan_mode": scan_mode,
            "duration_requested": duration_requested,
            "passive": passive,
            "devices": devices,
            "collectors": collectors,
        },
        started_at=started_at,
        completed_at=finished,
        run_id=run_id,
    )
