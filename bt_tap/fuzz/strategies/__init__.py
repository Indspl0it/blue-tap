"""Fuzzing strategy implementations.

Strategies control how the campaign engine selects protocols, mutates
seeds, and adapts based on observed responses and crashes.
"""

from bt_tap.fuzz.strategies.coverage_guided import CoverageGuidedStrategy
from bt_tap.fuzz.strategies.random_walk import RandomWalkStrategy
from bt_tap.fuzz.strategies.state_machine import StateMachineStrategy
from bt_tap.fuzz.strategies.targeted import TargetedStrategy

__all__ = [
    "CoverageGuidedStrategy",
    "RandomWalkStrategy",
    "StateMachineStrategy",
    "TargetedStrategy",
]
