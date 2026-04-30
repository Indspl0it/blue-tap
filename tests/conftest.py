"""Shared fixtures for BT-Tap tests."""

from __future__ import annotations

import os

import pytest

# CliRunner invocations exercise the same root + RTL chipset gate as production,
# but tests can't hold raw-HCI caps and have no real dongle. The env-var bypass
# lets userflow tests run the gated subcommands; production paths still require
# actual root.
os.environ.setdefault("BLUE_TAP_SKIP_ROOT_CHECK", "1")


@pytest.fixture(scope="session", autouse=True)
def _load_modules():
    """Load all built-in modules once per test session."""
    from blue_tap.framework.module import autoload_builtin_modules
    autoload_builtin_modules()
