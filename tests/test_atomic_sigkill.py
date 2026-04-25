"""Atomic-write durability under SIGKILL (paper §5).

Spawns 10 concurrent worker processes that hammer
``_atomic_write_bytes_or_text`` with small JSON payloads in a tight loop,
then SIGKILLs each at a random delay between 50-150 ms. After every worker
is reaped, the test walks the target directory and asserts:

  1. No ``*.tmp`` debris remains — the atomic write either committed or
     cleaned up; it never left a partial tempfile behind.
  2. Every target file that exists parses as valid JSON — the rename is
     all-or-nothing; readers never see a half-written record.

Requires SIGKILL; skipped on platforms whose ``signal`` module does not
expose it.
"""

from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not hasattr(signal, "SIGKILL"),
    reason="requires SIGKILL (POSIX signal semantics)",
)

WORKERS = 10
WRITES_PER_WORKER = 200          # design upper bound; killed long before this
TARGETS_PER_WORKER = 5           # round-robin across 5 files per worker
KILL_DELAY_MIN_S = 0.05
KILL_DELAY_MAX_S = 0.15

# Worker script — runs in a fresh interpreter so we can safely SIGKILL it.
# Writes deterministic JSON to a rotating set of target files until killed.
_WORKER_SRC = textwrap.dedent(
    """
    import json, os, sys
    from blue_tap.framework.sessions.store import _atomic_write_bytes_or_text

    out_dir = sys.argv[1]
    worker_id = int(sys.argv[2])
    n_targets = int(sys.argv[3])
    n_writes = int(sys.argv[4])

    os.makedirs(out_dir, exist_ok=True)
    for i in range(n_writes):
        target = os.path.join(out_dir, f"w{worker_id}_t{i % n_targets}.json")
        payload = json.dumps({"worker": worker_id, "seq": i, "pad": "x" * 64})
        _atomic_write_bytes_or_text(target, payload)
    """
).strip()


def _spawn_worker(out_dir: Path, worker_id: int) -> subprocess.Popen:
    """Launch one worker with the source piped in via ``python -c``."""
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _WORKER_SRC,
            str(out_dir),
            str(worker_id),
            str(TARGETS_PER_WORKER),
            str(WRITES_PER_WORKER),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_atomic_write_no_tmp_debris_under_sigkill(tmp_path: Path):
    """After SIGKILL storm, no .tmp files remain and survivors parse cleanly."""
    out_dir = tmp_path / "atomic_storm"
    out_dir.mkdir()

    rng = random.Random(0xBEEF)  # seeded — failures are reproducible
    procs: list[tuple[subprocess.Popen, float]] = []
    start = time.monotonic()
    for worker_id in range(WORKERS):
        proc = _spawn_worker(out_dir, worker_id)
        kill_at = start + rng.uniform(KILL_DELAY_MIN_S, KILL_DELAY_MAX_S)
        procs.append((proc, kill_at))

    # Kill each worker at its scheduled time, in chronological order.
    for proc, kill_at in sorted(procs, key=lambda p: p[1]):
        delay = kill_at - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        if proc.poll() is None:
            proc.send_signal(signal.SIGKILL)

    # Reap all children — should be near-instant since they're all dead.
    for proc, _ in procs:
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)

    # Assertion 1: no .tmp debris anywhere under the storm directory.
    tmp_files = sorted(out_dir.rglob("*.tmp"))
    assert not tmp_files, (
        f"atomic-write left {len(tmp_files)} .tmp file(s) behind after SIGKILL: "
        f"{[p.name for p in tmp_files[:5]]}"
    )

    # Assertion 2: every target file that exists parses as valid JSON.
    # (Some may not exist yet — workers were killed before their first write.)
    json_files = sorted(out_dir.rglob("*.json"))
    assert json_files, "no target files were created — workers died too early to test"
    for path in json_files:
        raw = path.read_text()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"target file {path.name} is not valid JSON after SIGKILL "
                f"(size={len(raw)}): {exc}"
            )
        # Sanity: payload must be a worker record, not garbage.
        assert isinstance(payload, dict)
        assert "worker" in payload and "seq" in payload, (
            f"target file {path.name} parsed but content is unexpected: {payload!r}"
        )
