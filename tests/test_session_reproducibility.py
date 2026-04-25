"""Reproducibility regression test (paper §10).

Runs the full assessment pipeline (discovery -> assessment -> report) 25 times
into independent session directories, normalises non-deterministic fields
(timestamps, run_ids, execution_ids), then asserts every run produced the
same envelope tree byte-for-byte after normalisation.

The hardware boundary is mocked deterministically — any divergence between
runs has to come from the session/envelope/report machinery itself, which is
exactly what the paper claims is reproducible.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli

TARGET = "AA:BB:CC:DD:EE:FF"
SESSION_NAME = "flow_repro"
ITERATIONS = 25

_SCAN_RESULT = [
    {"address": TARGET, "name": "IVI Device", "type": "classic", "rssi": -55},
]

_VULN_RESULT = {
    "schema": "blue_tap.vulnscan.result",
    "schema_version": 2,
    "module": "vulnscan",
    "run_id": "fixed-repro-run",
    "target": TARGET,
    "adapter": "hci0",
    "started_at": "2026-04-12T00:00:00+00:00",
    "completed_at": "2026-04-12T00:00:01+00:00",
    "operator_context": {},
    "summary": {
        "outcome": "inconclusive",
        "confirmed": 0,
        "inconclusive": 1,
        "pairing_required": 0,
        "not_applicable": 0,
    },
    "executions": [
        {
            "execution_id": "check_ssp",
            "kind": "check",
            "id": "check_ssp",
            "title": "SSP Check",
            "module": "vulnscan",
            "protocol": "Classic",
            "execution_status": "completed",
            "module_outcome": "inconclusive",
            "evidence": {
                "summary": "SSP status uncertain",
                "observations": [],
                "packets": [],
                "responses": [],
                "state_changes": [],
                "artifacts": [],
                "capability_limitations": [],
                "module_evidence": {},
            },
            "started_at": "2026-04-12T00:00:00+00:00",
            "completed_at": "2026-04-12T00:00:01+00:00",
            "destructive": False,
            "requires_pairing": False,
            "notes": [],
            "tags": [],
            "artifacts": [],
            "module_data": {},
        },
    ],
    "artifacts": [],
    "module_data": {"findings": []},
}

# Fields whose value is allowed to vary between runs and must be normalised
# before the structural comparison. Timestamps / ids are wall-clock or uuid
# derived; the report's HTML head carries a generation date.
_VOLATILE_KEYS = frozenset({
    "run_id",
    "execution_id",
    "created",
    "last_updated",
    "timestamp",
    "started_at",
    "completed_at",
    "last_seen",
    "generated_at",
    "report_generated_at",
})

_TS_RE = re.compile(
    # ISO 8601 timestamps used in JSON envelopes and HTML headers
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
    # ...and bare HH:MM:SS shown in the report timeline cells (lookarounds
    # exclude BD_ADDR runs like ``12:34:56:78:9A:BC`` which contain a similar
    # 3-octet sub-pattern).
    r"|(?<![\d:])\d{2}:\d{2}:\d{2}(?![\d:])"
)


def _normalise(value):
    """Recursively replace volatile leaf values with sentinels.

    Returns a new structure; leaves the input untouched. Any dict key in
    ``_VOLATILE_KEYS`` has its value replaced with the sentinel
    ``"<NORMALISED>"`` regardless of whether it originally held a string,
    number or null. List ordering is preserved.
    """
    if isinstance(value, dict):
        return {
            k: ("<NORMALISED>" if k in _VOLATILE_KEYS else _normalise(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    return value


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def _run_one_pipeline(tmp_path: Path) -> dict:
    """Execute discovery -> assessment -> report once and return the
    normalised session tree as a dict keyed by relative path.

    Only JSON artefacts are compared structurally; the HTML report is
    compared after timestamp scrubbing because its full DOM diff is too
    fragile to assert byte-equality on.
    """
    runner = _make_runner(tmp_path)
    with (
        patch("blue_tap.hardware.scanner.scan_all", return_value=deepcopy(_SCAN_RESULT)),
        patch(
            "blue_tap.modules.assessment.vuln_scanner.run_vulnerability_scan",
            return_value=deepcopy(_VULN_RESULT),
        ),
    ):
        r1 = runner.invoke(cli, ["-s", SESSION_NAME, "run", "discovery.scanner", "MODE=all"])
        assert r1.exit_code == 0, f"discovery.scanner failed:\n{r1.output}"
        r2 = runner.invoke(
            cli,
            ["-s", SESSION_NAME, "run", "assessment.vulnscan_meta",
             f"RHOST={TARGET}", "PHONE=11:22:33:44:55:66"],
        )
        assert r2.exit_code == 0, f"assessment.vulnscan_meta failed:\n{r2.output}"
        r3 = runner.invoke(cli, ["-s", SESSION_NAME, "report"])
        assert r3.exit_code == 0, f"report failed:\n{r3.output}"

    session_dir = tmp_path / "sessions" / SESSION_NAME
    tree: dict[str, object] = {}
    for path in sorted(session_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(session_dir).as_posix()
        if path.suffix == ".json":
            tree[rel] = _normalise(json.loads(path.read_text()))
        elif path.suffix == ".html":
            # Scrub embedded timestamps then keep length+hash signature
            scrubbed = _TS_RE.sub("<TS>", path.read_text())
            tree[rel] = ("html", len(scrubbed), hash(scrubbed))
        # other binary artefacts (vCards, audio) skipped — none expected here
    return tree


def test_assessment_pipeline_is_byte_reproducible(tmp_path_factory):
    """25 independent runs of the same pipeline produce the same artefacts.

    Any divergence (new uuid leaking into a non-volatile field, dict
    iteration order changing, report adapter ordering bug) shows up as a
    diff against the canonical first run.
    """
    canonical = _run_one_pipeline(tmp_path_factory.mktemp("repro_0"))
    for i in range(1, ITERATIONS):
        run_tree = _run_one_pipeline(tmp_path_factory.mktemp(f"repro_{i}"))
        assert run_tree.keys() == canonical.keys(), (
            f"Run {i} produced a different file set:\n"
            f"  only in canonical: {sorted(canonical.keys() - run_tree.keys())}\n"
            f"  only in run {i}:   {sorted(run_tree.keys() - canonical.keys())}"
        )
        for rel_path, expected in canonical.items():
            assert run_tree[rel_path] == expected, (
                f"Run {i} diverged from canonical at {rel_path!r}"
            )
