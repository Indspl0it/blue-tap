"""Fuzz campaign module — native Module class for the fuzzing.engine module_id.

The FuzzCampaignModule drives ``FuzzCampaign`` (defined in engine.py) via the
standard Module/RunContext interface.  It lives here rather than in engine.py
to keep the campaign orchestration class separate from the framework integration
layer.
"""

from __future__ import annotations

import logging

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import (
    OptAddress,
    OptBool,
    OptEnum,
    OptFloat,
    OptInt,
    OptPath,
    OptString,
)
from blue_tap.framework.registry import ModuleFamily

logger = logging.getLogger(__name__)

# Available fuzzing strategies
STRATEGIES = ("coverage_guided", "random", "mutation", "generation", "replay")

# Supported protocols for fuzzing
PROTOCOLS = (
    "l2cap", "rfcomm", "sdp", "obex", "att", "smp", "bnep", "lmp",
    "a2dp", "avrcp", "hfp", "pbap", "map", "opp",
)


class FuzzCampaignModule(Module):
    """Fuzz Campaign.

    Run multi-protocol Bluetooth fuzzing campaigns with crash tracking.
    Supports coverage-guided, random, mutation-based, and generation-based strategies.
    """

    module_id = "fuzzing.engine"
    family = ModuleFamily.FUZZING
    name = "Fuzz Campaign"
    description = "Run multi-protocol Bluetooth fuzzing campaigns with crash tracking"
    protocols = ("Classic", "BLE", "L2CAP", "RFCOMM", "SDP", "OBEX", "ATT", "SMP", "BNEP", "LMP")
    requires = ("adapter", "target")
    destructive = True
    requires_pairing = False
    schema_prefix = "blue_tap.fuzz.result"
    has_report_adapter = True
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target Bluetooth address"),
        OptString("PROTOCOLS", default="l2cap", description=f"Comma-separated protocols to fuzz ({', '.join(PROTOCOLS)})"),
        OptEnum("STRATEGY", choices=STRATEGIES, default="coverage_guided", description="Fuzzing strategy"),
        OptString("DURATION", default="1h", description="Campaign duration (e.g., 30m, 1h, 24h)"),
        OptInt("MAX_ITERATIONS", default=0, description="Maximum iterations (0=unlimited)"),
        OptPath("SESSION_DIR", default=".", description="Session directory for artifacts"),
        OptFloat("COOLDOWN", default=0.5, description="Seconds between fuzz iterations"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptBool("CONTINUE", default=False, description="Continue previous campaign if exists"),
    )

    def run(self, ctx: RunContext) -> dict:
        """Execute fuzzing campaign."""
        from blue_tap.modules.fuzzing.engine import FuzzCampaign, parse_duration

        target = ctx.options.get("RHOST", "")
        protocols_str = ctx.options.get("PROTOCOLS", "l2cap")
        strategy = ctx.options.get("STRATEGY", "coverage_guided")
        duration_str = ctx.options.get("DURATION", "1h")
        max_iterations = ctx.options.get("MAX_ITERATIONS", 0)
        session_dir = ctx.options.get("SESSION_DIR", ".")
        cooldown = ctx.options.get("COOLDOWN", 0.5)
        hci = ctx.options.get("HCI", "")

        protocols = [p.strip().lower() for p in protocols_str.split(",") if p.strip()]
        if not protocols:
            protocols = ["l2cap"]

        duration = parse_duration(duration_str)

        started_at = ctx.started_at

        transport_overrides = {proto: {"hci": hci} for proto in protocols}

        campaign = FuzzCampaign(
            target=target,
            protocols=protocols,
            strategy=strategy,
            duration=duration if duration > 0 else None,
            max_iterations=max_iterations if max_iterations > 0 else None,
            session_dir=session_dir,
            cooldown=cooldown,
            run_id=ctx.run_id,
            transport_overrides=transport_overrides,
        )

        interrupted = False
        error_text: str | None = None
        try:
            result = campaign.run()
        except KeyboardInterrupt:
            logger.info("Fuzzing campaign interrupted by user")
            interrupted = True
            result = campaign._build_summary() if hasattr(campaign, "_build_summary") else {}
        except Exception as e:
            logger.exception("Fuzzing campaign failed: %s", e)
            error_text = str(e)
            result = campaign._build_summary() if hasattr(campaign, "_build_summary") else {}

        if not isinstance(result, dict):
            result = {}

        # Engine's _build_summary() returns flat keys: iterations, packets_sent,
        # crashes, errors, runtime_seconds, protocol_breakdown, result, etc.
        iterations = int(result.get("iterations", 0) or 0)
        packets_sent = int(result.get("packets_sent", 0) or 0)
        crashes_found = int(result.get("crashes", 0) or 0)
        errors = int(result.get("errors", 0) or 0)
        runtime_seconds = float(result.get("runtime_seconds", 0.0) or 0.0)

        if error_text is not None:
            outcome = "aborted"
            execution_status = "error"
        elif interrupted:
            outcome = "aborted"
            execution_status = "completed"
        elif crashes_found > 0:
            outcome = "crash_found"
            execution_status = "completed"
        elif packets_sent == 0:
            outcome = "not_applicable"
            execution_status = "failed"
        else:
            outcome = "no_findings"
            execution_status = "completed"

        summary_line = (
            f"Ran {iterations:,} iteration(s), sent {packets_sent:,} packet(s), "
            f"found {crashes_found} crash(es) in {runtime_seconds:.1f}s"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[make_execution(
                execution_id="fuzz_campaign",
                kind="phase",
                id="fuzz_campaign",
                title=f"Fuzz Campaign ({strategy})",
                module=self.module_id,
                module_id=self.module_id,
                protocol=",".join(protocols),
                execution_status=execution_status,
                module_outcome=outcome,
                evidence=make_evidence(
                    raw={
                        "iterations": iterations,
                        "packets_sent": packets_sent,
                        "crashes": crashes_found,
                        "errors": errors,
                        "runtime_seconds": runtime_seconds,
                        "protocols": protocols,
                        "strategy": strategy,
                        **({"error": error_text} if error_text else {}),
                    },
                    summary=summary_line,
                ),
                destructive=True,
                requires_pairing=False,
                error=error_text,
            )],
            summary={
                "outcome": outcome,
                "iterations": iterations,
                "packets_sent": packets_sent,
                "crashes": crashes_found,
                "errors": errors,
                "runtime_seconds": runtime_seconds,
                "protocols": protocols,
            },
            module_data=result,
            run_id=ctx.run_id,
        )
