"""Abstract base class for all BT-Tap fuzzing strategies.

Every strategy that plugs into :class:`~blue_tap.modules.fuzzing.engine.FuzzCampaign`
must inherit from :class:`FuzzStrategy` and implement :meth:`generate`.

Design notes
------------
``generate`` returns ``bytes | list[bytes]`` to accommodate two campaign modes:

- **Single-packet strategies** (:class:`~.random_walk.RandomWalkStrategy`,
  :class:`~.coverage_guided.CoverageGuidedStrategy`): return one ``bytes``
  blob per call.  The engine sends it and waits for a response.

- **Multi-step strategies** (:class:`~.state_machine.StateMachineStrategy`):
  return a ``list[bytes]`` where each element is sent sequentially.  State
  machine attacks require packet ordering (e.g., send AUTH_REQ then
  ENCRYPTION_REQ to test skipping key exchange).

``feedback`` is intentionally *not* abstract.  Stateless strategies (e.g.,
random walk) legitimately have no feedback loop — forcing an empty override
everywhere would be noise.  The no-op default is the right contract.

Note on TargetedStrategy
------------------------
:class:`~.targeted.TargetedStrategy` is **intentionally excluded** from this
hierarchy.  It exposes a different API: named CVE methods that return
generators (``(payload, description)`` tuples), rather than a single
``generate(protocol)`` entry point.  The engine calls it through a separate
code path, not through the strategy dispatch loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class FuzzStrategy(ABC):
    """Common interface for all campaign fuzzing strategies.

    Implementors must provide :meth:`generate`.  They *may* override
    :meth:`feedback` to adapt mutation based on observed responses and
    crashes.

    Contract
    --------
    - ``generate(protocol)`` is called once per campaign iteration to
      produce the next payload(s) to send.
    - ``feedback(...)`` is called immediately after the engine receives
      the target's response (or detects a crash), passing back the
      payload that was sent and the raw response bytes.

    Thread safety
    -------------
    The engine calls ``generate`` and ``feedback`` from a single thread.
    Strategies do not need to be thread-safe unless they share state with
    external components.
    """

    @abstractmethod
    def generate(
        self, protocol: str
    ) -> tuple[bytes | list[bytes], list[str]]:
        """Generate the next fuzz payload(s) for *protocol*.

        Args:
            protocol: Protocol key (e.g. ``"lmp"``, ``"sdp"``, ``"ble-att"``).
                      Must be a member of ``PROTOCOLS`` (from the registry).

        Returns:
            A ``(payload, mutation_log)`` tuple where:

            - *payload* is either a single ``bytes`` blob (single-packet
              send) or a ``list[bytes]`` (ordered multi-step sequence).
            - *mutation_log* is a list of human-readable strings describing
              what mutations were applied — used for crash reproduction
              reports and session logging.

        Raises:
            ValueError: If *protocol* is not recognised by this strategy.
        """

    def feedback(
        self,
        protocol: str,
        payload: bytes,
        response: bytes | None,
        crash: bool = False,
    ) -> None:
        """Incorporate target response into future mutation decisions.

        The default implementation is a no-op.  Override this in
        feedback-driven strategies (e.g. coverage-guided) to update
        internal state — interesting input pools, energy schedules,
        field weights, etc.

        This method is called by the engine:
        - After *every* send/recv cycle with the raw response bytes.
        - With ``crash=True`` and ``response=None`` when the engine
          detects a crash (no response, connection drop, or explicit
          crash classification).

        Args:
            protocol: The protocol key that produced this payload.
            payload:  The exact bytes that were sent to the target.
            response: Raw bytes received from the target, or ``None``
                      if the target crashed / timed out.
            crash:    ``True`` if the engine classified this exchange
                      as a crash event.
        """
