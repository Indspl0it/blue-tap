"""Minimal Blue-Tap plugin: registers one trivial assessment module.

The module always returns ``not_applicable`` — it touches no hardware and
does no real work. Its purpose is to show *exactly* the wiring needed to
register a third-party module with Blue-Tap's registry:

  1. Subclass ``blue_tap.framework.module.Module``.
  2. Set the class attributes (``module_id``, ``family``, ``name`` …).
  3. Implement ``run(self, ctx) -> dict`` returning a ``RunEnvelope``.

Registration happens automatically via ``__init_subclass__``. There is no
``register()`` call to remember.

Once installed (``pip install -e .``), ``blue-tap plugins list`` shows this
plugin and ``blue-tap run example.no_op`` invokes it.
"""

from __future__ import annotations

import logging

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptString
from blue_tap.framework.registry import ModuleFamily

logger = logging.getLogger(__name__)


class ExampleNoOpModule(Module):
    """Assessment check that never actually checks anything.

    Replace this body with your real check logic. The structure here is the
    minimum every plugin needs: class metadata + ``run()`` returning a
    valid ``RunEnvelope``.
    """

    # ── Required metadata ────────────────────────────────────────────────
    # ``module_id`` must be ``<family>.<snake_case_name>`` and must start
    # with the family's lowercase value (``assessment.``, ``exploitation.``,
    # ``reconnaissance.``, ``post_exploitation.``, ``fuzzing.``, ``discovery.``).
    module_id = "assessment.example_no_op"
    family = ModuleFamily.ASSESSMENT
    name = "Example No-Op Plugin Module"
    description = "Template plugin module — always returns not_applicable."
    schema_prefix = "blue_tap.example.result"

    # ── Optional metadata ────────────────────────────────────────────────
    protocols = ()
    requires = ()
    destructive = False
    requires_pairing = False
    has_report_adapter = False
    references = ()

    # Options the operator can pass via ``KEY=VALUE`` on the CLI.
    options = (
        OptString("RHOST", default="", description="Optional target address (ignored)"),
    )

    def run(self, ctx: RunContext) -> dict:
        """Return a well-formed RunEnvelope with module_outcome=not_applicable."""
        target = str(ctx.options.get("RHOST", ""))

        # Build a single ExecutionRecord describing what we (didn't) do.
        execution = make_execution(
            kind="check",
            id="noop",
            title="Example no-op check",
            module="example",
            module_id=self.module_id,
            protocol="none",
            execution_status="completed",
            module_outcome="not_applicable",
            evidence=make_evidence(
                summary="Template plugin — no real check executed.",
                confidence="high",
                observations=["This is the example plugin template."],
            ),
            started_at=ctx.started_at,
        )

        return build_run_envelope(
            schema=f"{self.schema_prefix}",
            module="example",
            module_id=self.module_id,
            target=target,
            adapter="",
            operator_context={},
            summary={
                "outcome": "not_applicable",
                "confirmed": 0,
                "inconclusive": 0,
                "pairing_required": 0,
                "not_applicable": 1,
            },
            executions=[execution],
            artifacts=[],
            module_data={"plugin": "bluetap_example_plugin"},
            started_at=ctx.started_at,
        )
