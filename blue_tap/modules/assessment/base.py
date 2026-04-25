"""Base class for CVE check modules with common envelope building logic."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from blue_tap.framework.contracts.result_schema import (
    EXECUTION_COMPLETED,
    EXECUTION_ERROR,
    EXECUTION_SKIPPED,
    build_run_envelope,
    make_evidence,
    make_execution,
    now_iso,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.registry import ModuleFamily

if TYPE_CHECKING:
    from blue_tap.framework.module.options import Opt

logger = logging.getLogger(__name__)


class CveCheckModule(Module):
    """Base class for CVE check modules with common envelope building.

    Subclasses should:
    1. Define module_id, name, description, protocols, options, references
    2. Set check_fn to the underlying _check_* function
    3. Optionally override category, requires, destructive

    The base class handles:
    - Extracting options and calling the check function
    - Building a standardized RunEnvelope from the list[dict] findings
    - Emitting CLI events
    """

    _abstract = True

    family: ModuleFamily = ModuleFamily.ASSESSMENT
    category: str = "cve"
    has_report_adapter: bool = False
    schema_prefix: str = "blue_tap.assessment.cve_check.result"

    # The underlying check function to call
    # Signature varies: (address), (address, services), (address, hci), etc.
    check_fn: Callable[..., list[dict]] | None = None

    # Map option names to check function parameter names
    # e.g., {"RHOST": "address", "SERVICES": "services"}
    option_param_map: dict[str, str] = {"RHOST": "address"}

    def run(self, ctx: RunContext) -> dict:
        """Execute the CVE check and return a standardized envelope.

        The caller (Invoker) already emits ``run_started``/``run_completed``
        around this method, so we do NOT emit them here — doubling the events
        shows the module starting/completing twice in the CLI transcript.
        """
        target = ctx.options.get("RHOST", "")
        adapter = ctx.options.get("HCI", "")
        started_at = ctx.started_at

        findings: list[dict] = []
        execution_status = EXECUTION_COMPLETED
        error_msg = None

        try:
            findings = self._execute_check(ctx)
        except Exception as e:
            logger.exception("CVE check %s failed: %s", self.module_id, e)
            execution_status = EXECUTION_ERROR
            error_msg = str(e)

        # Build execution record from findings
        execution = self._build_execution(findings, execution_status, error_msg, started_at)

        # Determine overall outcome from findings
        outcome = self._determine_outcome(findings)

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            module_id=self.module_id,
            target=target,
            adapter=adapter,
            started_at=started_at,
            executions=[execution],
            summary={
                "outcome": outcome,
                "finding_count": len(findings),
                "cves": list(self.references),
            },
            module_data={
                "findings": findings,
                "check_id": self.check_id,
                "category": self.category,
            },
            run_id=ctx.run_id,
        )

    def _execute_check(self, ctx: RunContext) -> list[dict]:
        """Call the underlying check function with appropriate arguments."""
        if self.check_fn is None:
            raise NotImplementedError(
                f"{self.__class__.__name__}.check_fn must be set to a check function"
            )

        # Build kwargs from options using the param map
        kwargs: dict[str, Any] = {}
        for opt_name, param_name in self.option_param_map.items():
            if opt_name in ctx.options:
                kwargs[param_name] = ctx.options[opt_name]

        return self.check_fn(**kwargs)

    def _build_execution(
        self,
        findings: list[dict],
        status: str,
        error_msg: str | None,
        started_at: str,
    ) -> dict:
        """Build an ExecutionRecord from findings."""
        # Determine outcome from findings
        outcome = self._determine_outcome(findings)

        # Build evidence from findings
        evidence_items = []
        for f in findings:
            evidence_items.append({
                "type": "finding",
                "severity": f.get("severity", "INFO"),
                "name": f.get("name", ""),
                "status": f.get("status", "inconclusive"),
                "evidence": f.get("evidence", ""),
            })

        return make_execution(
            execution_id=f"{self.check_id}_exec",
            kind="check",
            id=self.check_id,
            title=self.name,
            module=self.module_id,
            module_id=self.module_id,
            protocol=self.protocols[0] if self.protocols else "",
            execution_status=status,
            module_outcome=outcome,
            evidence=make_evidence(
                raw={"findings": findings},
                summary=f"{len(findings)} finding(s)",
            ) if findings else make_evidence(raw={}, summary="No findings"),
            destructive=self.destructive,
            requires_pairing=self.requires_pairing,
            started_at=started_at,
            completed_at=now_iso(),
            error=error_msg,
        )

    def _determine_outcome(self, findings: list[dict]) -> str:
        """Determine overall outcome from findings list."""
        if not findings:
            return "inconclusive"

        # Check for confirmed vulnerabilities
        for f in findings:
            status = f.get("status", "").lower()
            if status == "confirmed":
                return "confirmed"

        # Check for inconclusive
        for f in findings:
            status = f.get("status", "").lower()
            if status == "inconclusive":
                return "inconclusive"

        # Check for pairing required
        for f in findings:
            status = f.get("status", "").lower()
            if status == "pairing_required":
                return "pairing_required"

        return "not_applicable"

    @property
    def check_id(self) -> str:
        """Extract check_id from module_id (assessment.cve_xxxx -> cve_xxxx)."""
        return self.module_id.split(".", 1)[1] if "." in self.module_id else self.module_id


class ServiceDiscoveryMixin:
    """Resolve an SDP service list for a CVE check.

    Checks that act on a specific profile (HID, AVRCP, BNEP, etc.) need the
    target's SDP service records. The mixin reads them from ``ctx.options``
    when the caller has already performed discovery (``SERVICES=[...]``),
    otherwise it runs a bounded ``browse_services`` scan. Previously lived
    as a five-way duplicate across the ``checks/*`` files; centralising here
    prevents the call-site drift that hid the ``browse_services(timeout=...)``
    signature bug for months.
    """

    #: Per-check upper bound for the sdptool browse (seconds).
    sdp_browse_timeout: float = 30.0

    def _get_services(self, ctx: Any) -> list[dict]:
        services = ctx.options.get("SERVICES")
        if services:
            return list(services)

        from blue_tap.modules.reconnaissance.sdp import browse_services

        target = str(ctx.options.get("RHOST", ""))
        hci = str(ctx.options.get("HCI", ""))
        if not target:
            return []
        try:
            return browse_services(target, hci=hci, timeout=self.sdp_browse_timeout)
        except Exception as exc:  # defensive — never block the check path
            logger.warning(
                "SDP browse for %s failed during %s: %s",
                target,
                self.module_id,
                exc,
            )
            return []
