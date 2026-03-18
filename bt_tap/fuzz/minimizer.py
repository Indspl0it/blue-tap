"""Crash minimization for the Bluetooth fuzzer.

Given a crash-triggering payload, finds the SMALLEST variant that still
reproduces the crash.  This is essential for vulnerability research: a 48-byte
crash payload is hard to analyze, but reducing it to 8 essential bytes
immediately reveals which protocol field is the root cause.

Three reduction strategies are provided, each with different trade-offs:

- **BinarySearchReducer** -- Fast, halving approach (~8-15 tests).
- **DeltaDebugReducer** -- Thorough ddmin algorithm (~50-200 tests).
- **FieldReducer** -- Identifies exactly which bytes are essential.

The :class:`CrashMinimizer` orchestrator chains them together and handles
transport lifecycle, cooldown timing, retry logic, and progress reporting.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional, TYPE_CHECKING

from bt_tap.utils.output import info, warning, error

if TYPE_CHECKING:
    from bt_tap.fuzz.crash_db import CrashDB
    from bt_tap.fuzz.transport import BluetoothTransport


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MinimizationResult:
    """Result of crash minimization.

    Captures the original and minimized payloads, an essential-bytes mask,
    statistics about the reduction process, and a human-readable log.

    Attributes:
        original: The original crash payload.
        minimized: The smallest payload that still triggers the crash.
        essential_mask: Same length as ``original``; ``0xFF`` at positions
            whose value matters for the crash, ``0x00`` at positions that
            can be zeroed without affecting reproducibility.  Only populated
            when the field-level reducer runs.
        original_size: Length of the original payload in bytes.
        minimized_size: Length of the minimized payload in bytes.
        reduction_percent: How much smaller the minimized payload is,
            expressed as a percentage (0.0 -- 100.0).
        tests_performed: Total number of crash-test invocations.
        strategy_used: Name of the strategy (or chain) that produced this
            result.
        log: Ordered list of human-readable log lines describing each
            reduction step.
        success: ``False`` if the crash could not be reproduced at all
            during the initial verification pass.
    """

    original: bytes
    minimized: bytes
    essential_mask: bytes
    original_size: int
    minimized_size: int
    reduction_percent: float
    tests_performed: int
    strategy_used: str
    log: list[str] = field(default_factory=list)
    success: bool = True

    def essential_bytes_hex(self) -> str:
        """Render the original payload with non-essential bytes replaced by ``??``.

        Essential positions (mask == 0xFF) show their hex value; all other
        positions are shown as ``??``.  This makes it immediately obvious
        which byte positions matter for the crash.

        Example output::

            80 00 ?? ?? 00 ff ff 46 ?? ?? 79 61

        Returns:
            Space-separated hex string with ``??`` for non-essential bytes.
        """
        if not self.essential_mask or len(self.essential_mask) != len(self.original):
            return self.original.hex(" ")
        parts: list[str] = []
        for i, (b, m) in enumerate(zip(self.original, self.essential_mask)):
            if m == 0xFF:
                parts.append(f"{b:02x}")
            else:
                parts.append("??")
        return " ".join(parts)

    def summary(self) -> str:
        """Generate a human-readable summary of the minimization.

        Returns:
            Multi-line string suitable for terminal display.
        """
        lines = [
            f"Minimization {'succeeded' if self.success else 'FAILED (crash not reproducible)'}",
            f"  Strategy:   {self.strategy_used}",
            f"  Original:   {self.original_size} bytes",
            f"  Minimized:  {self.minimized_size} bytes",
            f"  Reduction:  {self.reduction_percent:.1f}%",
            f"  Tests run:  {self.tests_performed}",
        ]
        if self.essential_mask and any(m == 0xFF for m in self.essential_mask):
            essential_count = sum(1 for m in self.essential_mask if m == 0xFF)
            lines.append(f"  Essential:  {essential_count}/{self.original_size} bytes")
            lines.append(f"  Pattern:    {self.essential_bytes_hex()}")
        if self.minimized_size > 0:
            lines.append(f"  Payload:    {self.minimized.hex()}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 6.3.1  Binary Search Reducer
# ---------------------------------------------------------------------------

class BinarySearchReducer:
    """Halve the payload, test if crash still occurs, refine the boundary.

    Algorithm:

    1. Start with the full payload.
    2. Try the first half -- if crash reproduces, keep the first half.
    3. Try the second half -- if crash reproduces, keep the second half.
    4. If neither half alone crashes, try removing each 1/n-th chunk
       (starting with quarters, then eighths, etc.).
    5. Repeat until no further reduction is possible or ``min_size`` is
       reached.

    Typical reduction: 48 bytes to ~12 bytes in roughly 8 iterations.
    """

    def reduce(
        self,
        payload: bytes,
        crash_test: Callable[[bytes], bool],
        min_size: int = 1,
    ) -> tuple[bytes, list[str]]:
        """Reduce *payload* to the minimum that still crashes.

        Args:
            payload: Original crash-triggering payload.
            crash_test: Callable that sends the payload to the target and
                returns ``True`` if a crash is detected.
            min_size: Stop reducing once the payload is this small or
                smaller.

        Returns:
            A ``(minimized_payload, reduction_log)`` tuple.
        """
        log: list[str] = []
        current = payload

        log.append(f"[binary] Start: {len(current)} bytes")

        # Outer loop: keep trying to shrink until we can't
        changed = True
        while changed and len(current) > min_size:
            changed = False

            # --- Try halves ------------------------------------------------
            mid = len(current) // 2
            if mid >= min_size:
                first_half = current[:mid]
                log.append(f"[binary] Try first half: {len(first_half)} bytes")
                if crash_test(first_half):
                    log.append(f"[binary] First half crashes -> {len(first_half)} bytes")
                    current = first_half
                    changed = True
                    continue

                second_half = current[mid:]
                log.append(f"[binary] Try second half: {len(second_half)} bytes")
                if crash_test(second_half):
                    log.append(f"[binary] Second half crashes -> {len(second_half)} bytes")
                    current = second_half
                    changed = True
                    continue

            # --- Try removing 1/n-th chunks --------------------------------
            # Walk through increasing granularity: 4 chunks, 8 chunks, ...
            n_chunks = 4
            while n_chunks <= len(current):
                chunk_size = max(len(current) // n_chunks, 1)
                found_removal = False

                for i in range(n_chunks):
                    start = i * chunk_size
                    end = min(start + chunk_size, len(current))
                    candidate = current[:start] + current[end:]

                    if len(candidate) < min_size:
                        continue
                    if len(candidate) == len(current):
                        # Nothing was actually removed (rounding)
                        continue

                    log.append(
                        f"[binary] Remove chunk {i + 1}/{n_chunks} "
                        f"[{start}:{end}]: {len(candidate)} bytes"
                    )
                    if crash_test(candidate):
                        log.append(
                            f"[binary] Chunk {i + 1}/{n_chunks} removable "
                            f"-> {len(candidate)} bytes"
                        )
                        current = candidate
                        changed = True
                        found_removal = True
                        break  # restart outer loop with smaller payload

                if found_removal:
                    break  # back to outer while-changed loop

                n_chunks *= 2

        log.append(f"[binary] Done: {len(current)} bytes")
        return current, log


# ---------------------------------------------------------------------------
# 6.3.2  Field-Level Reducer
# ---------------------------------------------------------------------------

class FieldReducer:
    """Zero each byte individually, keep only crash-essential bytes.

    Algorithm:

    1. For each byte position *i* in the payload:

       a. Set byte *i* to ``0x00``.
       b. Test if the crash still occurs.
       c. If the crash persists, byte *i* is **not essential** (keep
          ``0x00``).
       d. If the crash stops, byte *i* **is essential** (restore the
          original value).

    2. The result is a payload where only essential bytes retain their
       original values; everything else is ``0x00``.

    This reveals exactly which byte positions matter for the crash and
    produces the ``essential_mask`` used by :class:`MinimizationResult`.
    """

    def reduce(
        self,
        payload: bytes,
        crash_test: Callable[[bytes], bool],
    ) -> tuple[bytes, list[str], bytes]:
        """Reduce *payload* to essential bytes only.

        Args:
            payload: Crash-triggering payload (typically already size-reduced
                by :class:`BinarySearchReducer` or :class:`DeltaDebugReducer`).
            crash_test: Callable returning ``True`` if crash detected.

        Returns:
            A ``(reduced_payload, log, essential_mask)`` tuple.

            ``reduced_payload`` has non-essential bytes set to ``0x00``.
            ``essential_mask`` is the same length as *payload* with ``0xFF``
            at essential positions and ``0x00`` elsewhere.
        """
        log: list[str] = []
        working = bytearray(payload)
        mask = bytearray(b"\xff" * len(payload))

        log.append(f"[field] Start: {len(payload)} bytes, testing each position")

        essential_count = 0
        for i in range(len(working)):
            original_byte = working[i]

            if original_byte == 0x00:
                # Already zero -- mark as non-essential (zeroing is a no-op)
                mask[i] = 0x00
                continue

            working[i] = 0x00
            if crash_test(bytes(working)):
                # Crash persists without this byte -- not essential
                mask[i] = 0x00
                log.append(
                    f"[field] Byte {i} (0x{original_byte:02x}) -> 0x00: "
                    f"still crashes (not essential)"
                )
            else:
                # Crash stops -- this byte is essential, restore it
                working[i] = original_byte
                mask[i] = 0xFF
                essential_count += 1
                log.append(
                    f"[field] Byte {i} (0x{original_byte:02x}): "
                    f"ESSENTIAL (crash stops without it)"
                )

        log.append(
            f"[field] Done: {essential_count}/{len(payload)} bytes essential"
        )
        return bytes(working), log, bytes(mask)


# ---------------------------------------------------------------------------
# 6.3.3  Delta Debugging (ddmin) Reducer
# ---------------------------------------------------------------------------

class DeltaDebugReducer:
    """Adapted ddmin algorithm for byte sequences.

    The classic Zeller delta-debugging algorithm, adapted for raw byte
    payloads:

    1. Partition the payload into *n* chunks (start with *n* = 2).
    2. Try **removing** each chunk -- if the crash persists, that chunk is
       irrelevant (remove it permanently).
    3. Try **keeping** each chunk individually -- if the crash occurs, only
       that chunk is needed.
    4. If neither single removal nor single keep works, increase *n* (finer
       granularity) and repeat.
    5. Stop when *n* >= ``len(payload)`` (every byte tested individually) or
       ``max_iterations`` is reached.

    This is more thorough than binary search but typically requires more
    test invocations.
    """

    def reduce(
        self,
        payload: bytes,
        crash_test: Callable[[bytes], bool],
        max_iterations: int = 1000,
    ) -> tuple[bytes, list[str]]:
        """Apply the ddmin algorithm.

        Args:
            payload: Original crash-triggering payload.
            crash_test: Callable returning ``True`` if crash detected.
            max_iterations: Safety limit to avoid runaway loops on large
                payloads.

        Returns:
            A ``(minimized_payload, reduction_log)`` tuple.
        """
        log: list[str] = []
        current = payload
        n = 2
        iteration = 0

        log.append(f"[ddmin] Start: {len(current)} bytes")

        while n <= len(current) and iteration < max_iterations:
            iteration += 1
            chunk_size = max(len(current) // n, 1)
            chunks = self._split(current, n)

            reduced = False

            # --- Phase 1: try removing each chunk --------------------------
            for i, chunk in enumerate(chunks):
                iteration += 1
                if iteration > max_iterations:
                    log.append(f"[ddmin] Hit iteration limit ({max_iterations})")
                    break

                candidate = self._remove_chunk(current, chunks, i)
                if len(candidate) == 0:
                    continue

                log.append(
                    f"[ddmin] iter={iteration} n={n}: remove chunk "
                    f"{i + 1}/{len(chunks)} ({len(chunk)}B) -> "
                    f"{len(candidate)}B"
                )

                if crash_test(candidate):
                    log.append(
                        f"[ddmin] Chunk {i + 1} removable -> {len(candidate)} bytes"
                    )
                    current = candidate
                    # Reduce n but keep at least 2
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if reduced:
                continue

            # --- Phase 2: try keeping each chunk alone ---------------------
            for i, chunk in enumerate(chunks):
                iteration += 1
                if iteration > max_iterations:
                    log.append(f"[ddmin] Hit iteration limit ({max_iterations})")
                    break

                if len(chunk) == 0:
                    continue

                log.append(
                    f"[ddmin] iter={iteration} n={n}: keep only chunk "
                    f"{i + 1}/{len(chunks)} ({len(chunk)}B)"
                )

                if crash_test(chunk):
                    log.append(
                        f"[ddmin] Only chunk {i + 1} needed -> "
                        f"{len(chunk)} bytes"
                    )
                    current = chunk
                    n = 2
                    reduced = True
                    break

            if reduced:
                continue

            # --- Neither worked: increase granularity ----------------------
            if n >= len(current):
                # Already at byte-level granularity; done
                log.append("[ddmin] Reached byte-level granularity, stopping")
                break

            n = min(n * 2, len(current))
            log.append(f"[ddmin] Increasing granularity to n={n}")

        log.append(f"[ddmin] Done: {len(current)} bytes ({iteration} iterations)")
        return current, log

    @staticmethod
    def _split(data: bytes, n: int) -> list[bytes]:
        """Split *data* into *n* roughly equal chunks.

        The last chunk absorbs any remainder so no bytes are lost.
        """
        if n <= 0:
            return [data]
        chunk_size = max(len(data) // n, 1)
        chunks: list[bytes] = []
        for i in range(n):
            start = i * chunk_size
            if i == n - 1:
                # Last chunk gets the remainder
                chunks.append(data[start:])
            else:
                chunks.append(data[start : start + chunk_size])
        # Filter out empty chunks that can arise with tiny payloads
        return [c for c in chunks if len(c) > 0]

    @staticmethod
    def _remove_chunk(
        data: bytes, chunks: list[bytes], index: int
    ) -> bytes:
        """Return *data* with chunk at *index* removed.

        Reconstructs the payload from all chunks except the one at
        *index*.
        """
        return b"".join(c for i, c in enumerate(chunks) if i != index)


# ---------------------------------------------------------------------------
# 6.3.4  CrashMinimizer (orchestrator)
# ---------------------------------------------------------------------------

class CrashMinimizer:
    """Orchestrate crash minimization using multiple strategies.

    Workflow:

    1. Verify the crash reproduces with the original payload (baseline).
    2. Run the selected strategy (or chain of strategies for ``"auto"``).
    3. Optionally save the minimized payload back to the crash database.
    4. Return a :class:`MinimizationResult` with full diagnostics.

    The minimizer manages transport lifecycle (connect/send/close) and
    implements cooldown pauses between tests so the target device has time
    to recover after each crash.

    Args:
        target: BD_ADDR of the target device.
        transport_factory: Callable that returns a new, unconnected
            :class:`BluetoothTransport` instance each time it is called.
            The transport must be configured for the correct protocol and
            channel/PSM.
        timeout: Seconds to wait for a response after sending the test
            payload.
        cooldown: Seconds to wait between crash tests, giving the target
            device time to recover.
        max_retries: Number of times to re-test a payload variant before
            declaring it does not crash.  Bluetooth crashes can be flaky;
            requiring >1 positive out of *max_retries* attempts reduces
            false negatives.
    """

    def __init__(
        self,
        target: str,
        transport_factory: Callable[[], "BluetoothTransport"],
        timeout: float = 5.0,
        cooldown: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.target = target
        self.transport_factory = transport_factory
        self.timeout = timeout
        self.cooldown = cooldown
        self.max_retries = max_retries
        self._test_count = 0

    # -- Crash test --------------------------------------------------------

    def _crash_test(self, payload: bytes) -> bool:
        """Send *payload* to the target and return ``True`` if a crash is detected.

        A crash is detected when any of the following occur:

        - ``ConnectionResetError`` or ``BrokenPipeError`` during send.
        - ``socket.timeout`` / empty receive (device stopped responding).
        - Device becomes unreachable after send (``is_alive()`` returns
          ``False``).

        The test includes:

        - **Cooldown**: sleeps ``self.cooldown`` seconds before each test
          so the target has time to recover from the previous crash.
        - **Retry logic**: tests the payload up to ``self.max_retries``
          times. Returns ``True`` if **any** attempt triggers a crash.
          This accounts for flaky Bluetooth crash behavior.

        Args:
            payload: Raw bytes to send to the target.

        Returns:
            ``True`` if a crash was detected, ``False`` otherwise.
        """
        for attempt in range(self.max_retries):
            self._test_count += 1

            # Cooldown between tests (skip on first test of the session)
            if self._test_count > 1:
                time.sleep(self.cooldown)

            transport = self.transport_factory()
            try:
                if not transport.connect():
                    # Cannot connect -- device may already be crashed from
                    # a previous test.  Check liveness.
                    if not transport.is_alive():
                        return True
                    # Device is alive but refused connection -- not a crash
                    continue

                try:
                    transport.send(payload)
                except (ConnectionResetError, BrokenPipeError, ConnectionError):
                    # Connection dropped on send -- crash
                    return True

                response = transport.recv(recv_timeout=self.timeout)

                if response is None:
                    # Connection closed by remote -- crash
                    return True

                if response == b"":
                    # Timeout -- check if device is still alive
                    if not transport.is_alive():
                        return True

                # Got a response -- device is fine, no crash
                # (don't return False yet; retry in case crash is flaky)

            except OSError:
                # General socket error -- check liveness
                if not transport.is_alive():
                    return True
            finally:
                transport.close()

        # All retries completed without detecting a crash
        return False

    # -- Strategy runners ---------------------------------------------------

    def _run_binary(
        self, payload: bytes, log: list[str]
    ) -> bytes:
        """Run binary search reduction and append to *log*."""
        reducer = BinarySearchReducer()
        result, step_log = reducer.reduce(
            payload, self._crash_test, min_size=1
        )
        log.extend(step_log)
        return result

    def _run_ddmin(
        self, payload: bytes, log: list[str]
    ) -> bytes:
        """Run delta debugging reduction and append to *log*."""
        reducer = DeltaDebugReducer()
        result, step_log = reducer.reduce(
            payload, self._crash_test, max_iterations=1000
        )
        log.extend(step_log)
        return result

    def _run_field(
        self,
        payload: bytes,
        original: bytes,
        log: list[str],
    ) -> tuple[bytes, bytes]:
        """Run field-level reduction and append to *log*.

        Args:
            payload: The (already size-reduced) payload to analyze.
            original: The original full-size payload, used to build the
                essential mask at the original payload's length.
            log: Shared log list.

        Returns:
            ``(field_reduced_payload, essential_mask)`` where the mask
            has the same length as *original*.
        """
        reducer = FieldReducer()
        reduced, step_log, mask = reducer.reduce(payload, self._crash_test)
        log.extend(step_log)

        # Build a mask at the original payload's length.  Positions that
        # were already removed by size reduction are non-essential (0x00).
        if len(original) != len(payload):
            full_mask = bytearray(b"\x00" * len(original))
            # The size-reduced payload is a contiguous subset or
            # recombination.  We can only map field results for the
            # payload we actually tested, so place the mask at the start.
            # In practice the caller should use the mask relative to the
            # minimized payload, not the original.
            full_mask[: len(mask)] = mask
            mask = bytes(full_mask)

        return reduced, mask

    # -- Public API ---------------------------------------------------------

    def minimize(
        self,
        payload: bytes,
        strategy: str = "auto",
    ) -> MinimizationResult:
        """Minimize a crash payload.

        Strategies:

        - ``"binary"``: Binary search only (fast, ~8-15 tests).
        - ``"ddmin"``: Delta debugging only (thorough, ~50-200 tests).
        - ``"field"``: Field-level zeroing only (precise, ``len(payload)``
          tests).
        - ``"auto"``: binary, then ddmin, then field (best result, most
          tests).

        Args:
            payload: The crash-triggering payload to minimize.
            strategy: Which reduction strategy to use.

        Returns:
            A :class:`MinimizationResult` with the minimized payload,
            reduction statistics, and essential-bytes mask.

        Raises:
            ValueError: If *strategy* is not one of the recognized names.
        """
        valid_strategies = ("binary", "ddmin", "field", "auto")
        if strategy not in valid_strategies:
            raise ValueError(
                f"Unknown strategy {strategy!r}; "
                f"choose from {valid_strategies}"
            )

        self._test_count = 0
        log: list[str] = []
        original = payload

        # --- Baseline verification -----------------------------------------
        info(f"Verifying crash reproduces with {len(payload)}-byte payload...")
        log.append(f"Baseline verification: {len(payload)} bytes")

        if not self._crash_test(payload):
            warning("Crash could NOT be reproduced -- aborting minimization")
            log.append("FAILED: crash not reproducible")
            return MinimizationResult(
                original=original,
                minimized=original,
                essential_mask=b"",
                original_size=len(original),
                minimized_size=len(original),
                reduction_percent=0.0,
                tests_performed=self._test_count,
                strategy_used=strategy,
                log=log,
                success=False,
            )

        log.append("Baseline verified: crash reproduces")
        info("Crash verified. Beginning minimization...")

        current = payload
        essential_mask = b""

        # --- Run strategies ------------------------------------------------
        if strategy == "binary":
            current = self._run_binary(current, log)

        elif strategy == "ddmin":
            current = self._run_ddmin(current, log)

        elif strategy == "field":
            current, essential_mask = self._run_field(
                current, original, log
            )

        elif strategy == "auto":
            # Phase 1: binary search (fast rough cut)
            before = len(current)
            current = self._run_binary(current, log)
            info(
                f"Binary search: {before}B -> {len(current)}B"
            )

            # Phase 2: delta debugging (thorough refinement)
            before = len(current)
            current = self._run_ddmin(current, log)
            info(
                f"Delta debugging: {before}B -> {len(current)}B"
            )

            # Phase 3: field-level (identify essential bytes)
            current, essential_mask = self._run_field(
                current, original, log
            )
            essential_count = sum(1 for m in essential_mask if m == 0xFF)
            info(
                f"Field analysis: {essential_count}/{len(current)} "
                f"bytes essential"
            )

        # --- Build result --------------------------------------------------
        minimized_size = len(current)
        original_size = len(original)
        if original_size > 0:
            reduction_pct = (
                (original_size - minimized_size) / original_size * 100.0
            )
        else:
            reduction_pct = 0.0

        result = MinimizationResult(
            original=original,
            minimized=current,
            essential_mask=essential_mask,
            original_size=original_size,
            minimized_size=minimized_size,
            reduction_percent=reduction_pct,
            tests_performed=self._test_count,
            strategy_used=strategy,
            log=log,
            success=True,
        )

        info(result.summary())
        return result

    def minimize_from_db(
        self,
        crash_db: "CrashDB",
        crash_id: int,
        strategy: str = "auto",
    ) -> MinimizationResult:
        """Load a crash from the database, minimize it, and save the result.

        Retrieves the crash payload by *crash_id*, runs :meth:`minimize`,
        and on success writes the minimized payload and a summary back to
        the crash record's notes.

        Args:
            crash_db: An open :class:`CrashDB` instance.
            crash_id: Primary key of the crash to minimize.
            strategy: Reduction strategy (see :meth:`minimize`).

        Returns:
            A :class:`MinimizationResult`.

        Raises:
            ValueError: If *crash_id* does not exist in the database.
        """
        crash = crash_db.get_crash_by_id(crash_id)
        if crash is None:
            raise ValueError(f"Crash ID {crash_id} not found in database")

        try:
            payload = bytes.fromhex(crash["payload_hex"])
        except ValueError as exc:
            raise ValueError(
                f"Corrupted payload hex for crash {crash_id}: {exc}"
            ) from exc

        info(
            f"Minimizing crash {crash_id}: {len(payload)} bytes "
            f"({crash.get('protocol', 'unknown')} protocol)"
        )

        result = self.minimize(payload, strategy=strategy)

        # Save results back to the database
        if result.success:
            notes_lines = [
                f"[minimizer] Reduced {result.original_size}B -> "
                f"{result.minimized_size}B "
                f"({result.reduction_percent:.1f}% reduction)",
                f"[minimizer] Strategy: {result.strategy_used}, "
                f"tests: {result.tests_performed}",
                f"[minimizer] Minimized payload: {result.minimized.hex()}",
            ]
            if result.essential_mask:
                notes_lines.append(
                    f"[minimizer] Essential bytes: "
                    f"{result.essential_bytes_hex()}"
                )
            crash_db.add_notes(crash_id, "\n".join(notes_lines))
            info(f"Minimization results saved to crash {crash_id}")
        else:
            crash_db.add_notes(
                crash_id,
                "[minimizer] Could not reproduce crash for minimization",
            )
            warning(f"Crash {crash_id} could not be reproduced")

        return result
