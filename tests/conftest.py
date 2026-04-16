"""Shared fixtures for BT-Tap tests."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="session", autouse=True)
def _load_modules():
    """Load all built-in modules once per test session."""
    from blue_tap.framework.module import autoload_builtin_modules
    autoload_builtin_modules()
