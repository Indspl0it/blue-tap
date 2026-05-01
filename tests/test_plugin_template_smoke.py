"""Smoke test for the bundled plugin template under ``examples/plugin-template``.

Verifies the example plugin actually loads and runs through the registry — a
broken example tutorial is worse than no example at all. Avoids ``pip install``
to keep CI fast and side-effect-free; instead, prepends the example directory
to ``sys.path`` so the plugin's package resolves like an installed dependency.

Imports the package by string from inside the test (the test loader hasn't
seen it at collection time) and asserts:

* The example's ``Module`` subclass registers with the global registry.
* The descriptor has the metadata documented in the example's README.
* Invoking the module via the runtime returns a valid ``RunEnvelope`` with
  ``module_outcome="not_applicable"``.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


_EXAMPLE_ROOT = Path(__file__).resolve().parents[1] / "examples" / "plugin-template"
_PLUGIN_PACKAGE = "bluetap_example_plugin"
_PLUGIN_MODULE_ID = "assessment.example_no_op"


@pytest.fixture(scope="module")
def loaded_plugin():
    """Import the example plugin from the on-disk template, then unimport on teardown."""
    sys.path.insert(0, str(_EXAMPLE_ROOT))
    try:
        # Force a fresh import in case a prior test session imported it.
        if _PLUGIN_PACKAGE in sys.modules:
            del sys.modules[_PLUGIN_PACKAGE]
        importlib.import_module(_PLUGIN_PACKAGE)
        yield
    finally:
        sys.path.remove(str(_EXAMPLE_ROOT))
        sys.modules.pop(_PLUGIN_PACKAGE, None)


def test_example_plugin_directory_exists():
    """Catch a typo in the example tree before we try to import it."""
    assert _EXAMPLE_ROOT.is_dir(), f"Plugin template missing at {_EXAMPLE_ROOT}"
    assert (_EXAMPLE_ROOT / "pyproject.toml").is_file()
    assert (_EXAMPLE_ROOT / "bluetap_example_plugin" / "__init__.py").is_file()
    assert (_EXAMPLE_ROOT / "README.md").is_file()


def test_example_plugin_pyproject_declares_entry_point():
    """The entry-point group must be ``blue_tap.modules`` — that's how the loader finds plugins."""
    text = (_EXAMPLE_ROOT / "pyproject.toml").read_text()
    assert 'project.entry-points."blue_tap.modules"' in text, (
        "Example pyproject.toml must declare a blue_tap.modules entry point"
    )
    assert "bluetap_example_plugin" in text


def test_example_plugin_registers_module(loaded_plugin):
    """Importing the plugin must register the example module with the global registry."""
    from blue_tap.framework.registry import get_registry

    registry = get_registry()
    descriptor = registry.try_get(_PLUGIN_MODULE_ID)
    assert descriptor is not None, (
        f"Plugin module {_PLUGIN_MODULE_ID!r} not found in registry after import"
    )
    assert descriptor.name == "Example No-Op Plugin Module"
    assert descriptor.family.value == "assessment"
    assert descriptor.destructive is False


def test_example_plugin_runs_and_returns_valid_envelope(loaded_plugin):
    """Invoke the example via the framework runtime and validate the envelope."""
    from blue_tap.framework.contracts.result_schema import validate_run_envelope
    from blue_tap.framework.module import Invoker

    invoker = Invoker()
    result = invoker.invoke(
        _PLUGIN_MODULE_ID,
        {"RHOST": "AA:BB:CC:DD:EE:FF"},
    )
    assert result is not None, "Invoker returned None — plugin run failed silently"
    errors = validate_run_envelope(result)
    assert errors == [], f"Plugin envelope failed validation: {errors}"

    # Spot-check the documented contract: outcome is ``not_applicable``.
    summary = result.get("summary", {})
    assert summary.get("outcome") == "not_applicable"
    executions = result.get("executions", [])
    assert executions and executions[0]["module_outcome"] == "not_applicable"
