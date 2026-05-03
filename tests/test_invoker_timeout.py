import signal
import sys
import threading
import time
import types

import pytest

# Stub fcntl on Windows so the framework imports cleanly.
if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.ModuleType("fcntl")


_HAS_SIGALRM = hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")


def test_module_timeout_aborts_hung_run():
    """A module that runs longer than default_timeout must raise ModuleTimeout."""
    from blue_tap.framework.module.invoker import ModuleTimeout, _run_with_timeout

    class _HungModule:
        def run(self, ctx):
            time.sleep(5.0)
            return {}

    with pytest.raises(ModuleTimeout) as exc_info:
        _run_with_timeout(_HungModule(), ctx=object(), module_id="test.hung", timeout=0.2)

    assert exc_info.value.module_id == "test.hung"
    assert exc_info.value.timeout == 0.2


@pytest.mark.skipif(not _HAS_SIGALRM, reason="SIGALRM not supported on this platform")
def test_sigalrm_path_runs_finally_blocks_on_timeout():
    """The SIGALRM path must unwind through finally blocks so resources are released."""
    from blue_tap.framework.module.invoker import ModuleTimeout, _run_with_sigalrm

    cleanup_marker = []

    class _HungWithCleanup:
        def run(self, ctx):
            try:
                time.sleep(5.0)
            finally:
                cleanup_marker.append("cleaned")

    with pytest.raises(ModuleTimeout):
        _run_with_sigalrm(_HungWithCleanup(), ctx=object(), module_id="test.hung", timeout=0.2)

    assert cleanup_marker == ["cleaned"], (
        "finally block must execute on SIGALRM-driven timeout (real interrupt)"
    )


@pytest.mark.skipif(not _HAS_SIGALRM, reason="SIGALRM not supported on this platform")
def test_sigalrm_path_restores_signal_handler():
    """After a successful or failed run, the previous SIGALRM handler must be restored."""
    from blue_tap.framework.module.invoker import _run_with_sigalrm

    sentinel_called = []

    def _sentinel(signum, frame):
        sentinel_called.append(signum)

    old = signal.signal(signal.SIGALRM, _sentinel)
    try:
        class _Quick:
            def run(self, ctx):
                return {"ok": True}

        _run_with_sigalrm(_Quick(), ctx=object(), module_id="test.quick", timeout=2.0)
        # The sentinel should be reinstated.
        current = signal.getsignal(signal.SIGALRM)
        assert current is _sentinel, f"handler not restored: {current!r}"
    finally:
        signal.signal(signal.SIGALRM, old)


def test_thread_watchdog_used_when_not_main_thread():
    """Off the main thread SIGALRM is unavailable; must fall back to thread watchdog."""
    from blue_tap.framework.module.invoker import (
        ModuleTimeout,
        _can_use_sigalrm,
        _run_with_timeout,
    )

    class _Hung:
        def run(self, ctx):
            time.sleep(5.0)
            return {}

    holder = {}

    def _from_worker():
        # Inside this thread, SIGALRM can never be used.
        holder["sigalrm_ok"] = _can_use_sigalrm()
        try:
            _run_with_timeout(_Hung(), ctx=object(), module_id="test.thr", timeout=0.2)
        except ModuleTimeout as exc:
            holder["timed_out"] = exc

    t = threading.Thread(target=_from_worker)
    t.start()
    t.join(5.0)
    assert holder.get("sigalrm_ok") is False
    assert "timed_out" in holder, "Thread watchdog must still raise ModuleTimeout"


def test_module_timeout_returns_envelope_when_under_budget():
    """A module that finishes within the timeout must return its envelope unchanged."""
    from blue_tap.framework.module.invoker import _run_with_timeout

    class _FastModule:
        def run(self, ctx):
            return {"schema": "test", "ok": True}

    result = _run_with_timeout(_FastModule(), ctx=object(), module_id="test.fast", timeout=2.0)
    assert result == {"schema": "test", "ok": True}


def test_module_timeout_propagates_run_exceptions():
    """Exceptions raised inside run() must propagate, not be replaced by ModuleTimeout."""
    from blue_tap.framework.module.invoker import _run_with_timeout

    class _BrokenModule:
        def run(self, ctx):
            raise ValueError("module bug")

    with pytest.raises(ValueError, match="module bug"):
        _run_with_timeout(_BrokenModule(), ctx=object(), module_id="test.broken", timeout=2.0)


def test_descriptor_rejects_negative_timeout():
    """ModuleDescriptor must reject negative default_timeout values."""
    from blue_tap.framework.registry.descriptors import ModuleDescriptor
    from blue_tap.framework.registry.families import ModuleFamily

    with pytest.raises(ValueError, match="default_timeout must be >= 0"):
        ModuleDescriptor(
            module_id="assessment.x",
            family=ModuleFamily.ASSESSMENT,
            name="x",
            description="x",
            protocols=(),
            requires=(),
            destructive=False,
            requires_pairing=False,
            schema_prefix="x",
            has_report_adapter=False,
            entry_point="x:Y",
            default_timeout=-1.0,
        )
