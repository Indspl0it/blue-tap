"""Per-family registration tests that bypass the conftest preload.

The session-scoped ``_load_modules`` autouse fixture in ``conftest.py`` calls
``autoload_builtin_modules()`` once at collection time, so every other
registration test sees a fully populated global registry. That masks
regressions where a single family's ``__init__.py`` is the only thing keeping
its modules on the registry — a future refactor could break that import and
no in-process test would notice, because the global is already warm.

These tests spawn a fresh Python interpreter per family and import only that
family's package. The subprocess registry starts empty; if the family fails
to register itself on import, the assertion fails.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

# (family enum value, expected subset of module_ids that MUST be registered).
# The subset is what the family commits to as its public surface — changing
# the set is an intentional API change and should land here at the same time.
_FAMILY_SPECS: list[tuple[str, set[str]]] = [
    ("DISCOVERY", {"discovery.scanner"}),
    ("RECONNAISSANCE", {
        "reconnaissance.campaign",
        "reconnaissance.fingerprint",
        "reconnaissance.gatt",
        "reconnaissance.l2cap_scan",
        "reconnaissance.rfcomm_scan",
        "reconnaissance.sdp",
        "reconnaissance.sniffer",
    }),
    ("ASSESSMENT", {
        "assessment.vuln_scanner",
        "assessment.fleet",
        "assessment.cve_2017_0785",
        "assessment.cve_2019_2225",
        "assessment.service_exposure",
        "assessment.pairing_method",
    }),
    ("EXPLOITATION", {
        "exploitation.bias",
        "exploitation.bluffs",
        "exploitation.ctkd",
        "exploitation.dos_runner",
        "exploitation.encryption_downgrade",
        "exploitation.hijack",
        "exploitation.knob",
        "exploitation.pin_brute",
        "exploitation.ssp_downgrade",
    }),
    ("POST_EXPLOITATION", {
        "post_exploitation.pbap",
        "post_exploitation.map",
        "post_exploitation.bluesnarfer",
        "post_exploitation.opp",
        "post_exploitation.hfp",
        "post_exploitation.a2dp",
        "post_exploitation.avrcp",
    }),
    ("FUZZING", {
        "fuzzing.engine",
        "fuzzing.transport",
        "fuzzing.minimizer",
    }),
]


def _probe(family_enum_name: str) -> list[str]:
    """Run a fresh Python subprocess that imports one family and dumps its IDs.

    Returns the list of registered module_ids for the family. If the import
    raises or the family enum value is unknown, the subprocess prints the
    traceback to stderr and returns a non-zero exit code, which fails the
    test with a useful message.
    """
    family_attr = family_enum_name  # e.g. "DISCOVERY"
    package = "blue_tap.modules." + family_enum_name.lower()
    src = textwrap.dedent(
        f"""
        import importlib, json, sys
        importlib.import_module({package!r})
        from blue_tap.framework.registry import get_registry, ModuleFamily
        descs = get_registry().list_family(ModuleFamily.{family_attr})
        print(json.dumps(sorted(d.module_id for d in descs)))
        """
    ).strip()
    result = subprocess.run(
        [sys.executable, "-c", src],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"family {family_enum_name} failed to import in isolation:\n"
            f"stderr:\n{result.stderr}"
        )
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize(("family", "expected"), _FAMILY_SPECS, ids=[s[0] for s in _FAMILY_SPECS])
def test_family_registers_in_isolation(family: str, expected: set[str]) -> None:
    """Each family's package import must, by itself, register its public modules."""
    registered = set(_probe(family))
    missing = expected - registered
    assert not missing, (
        f"family {family} did not register {sorted(missing)} "
        f"when imported in a fresh process. Got: {sorted(registered)}"
    )


def test_module_ids_use_canonical_family_prefix() -> None:
    """Every registered module_id must start with its family value.

    Catches typos like ``post_exp.foo`` or ``recon.bar`` slipping into a
    descriptor — the registry will accept them today, but the family-outcome
    validator infers the family from the prefix and would silently no-op.
    """
    src = textwrap.dedent(
        """
        from blue_tap.framework.module import autoload_builtin_modules
        from blue_tap.framework.registry import get_registry
        autoload_builtin_modules()
        rows = []
        for d in get_registry().list_all():
            rows.append((d.module_id, d.family.value))
        import json
        print(json.dumps(rows))
        """
    ).strip()
    result = subprocess.run(
        [sys.executable, "-c", src],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"autoload failed:\nstderr:\n{result.stderr}"
        )
    rows = json.loads(result.stdout.strip().splitlines()[-1])
    mismatches = [
        (mid, fam) for mid, fam in rows if not mid.startswith(f"{fam}.")
    ]
    assert not mismatches, (
        f"{len(mismatches)} module_id(s) do not start with their family value: "
        f"{mismatches[:10]}"
    )
