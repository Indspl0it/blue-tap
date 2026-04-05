"""Fuzzing strategy implementations.

Strategies control how the campaign engine selects protocols, mutates
seeds, and adapts based on observed responses and crashes.

All strategies except :class:`TargetedStrategy` inherit from
:class:`~.base.FuzzStrategy` and share the ``generate(protocol)`` /
``feedback(...)`` interface.  :class:`TargetedStrategy` exposes
named CVE generators and is called through a separate engine path.
"""

from blue_tap.fuzz.strategies.base import FuzzStrategy
from blue_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy
from blue_tap.fuzz.strategies.random_walk import RandomWalkStrategy
from blue_tap.fuzz.strategies.state_machine import StateMachineStrategy
from blue_tap.fuzz.strategies.targeted import TargetedStrategy

__all__ = [
    "FuzzStrategy",
    "CoverageGuidedStrategy",
    "RandomWalkStrategy",
    "StateMachineStrategy",
    "TargetedStrategy",
]
