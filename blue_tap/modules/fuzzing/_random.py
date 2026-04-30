"""Pluggable randomness source for the fuzzing pipeline.

Every module under :mod:`blue_tap.modules.fuzzing` that needs random
bytes for fuzz payloads imports :func:`random_bytes` from here instead
of calling :func:`os.urandom` directly. The active source is held in a
:class:`contextvars.ContextVar` so:

- The default everywhere is :func:`os.urandom` (CSPRNG, non-reproducible)
  — production behaviour is unchanged.
- Researchers driving a campaign through
  :func:`blue_tap.modules.fuzzing.run_campaign` can swap the source to
  a seeded callable for byte-level reproducible mutations.
- Concurrent campaigns in different threads / async contexts don't
  cross-contaminate (each context owns its own ContextVar value).

Thread-safety: ContextVar reads/writes are thread-safe by design. Each
thread / task sees the source set in its own context.
"""

from __future__ import annotations

import contextlib
import contextvars
import os
import random
from collections.abc import Callable, Iterator

# The signature is intentionally narrow: ``Callable[[int], bytes]``. Any
# replacement must accept a non-negative integer length and return that
# many bytes. ``os.urandom`` and ``random.Random(seed).randbytes`` both
# satisfy it.
_RANDOM_SOURCE: contextvars.ContextVar[Callable[[int], bytes]] = (
    contextvars.ContextVar("blue_tap_fuzz_random_source", default=os.urandom)
)


def random_bytes(n: int) -> bytes:
    """Return ``n`` random bytes from the active random source.

    Defaults to :func:`os.urandom` outside any
    :func:`set_random_source` block. Inside such a block, returns bytes
    from the injected callable instead.
    """
    if n < 0:
        raise ValueError(f"random_bytes requires non-negative length, got {n}")
    return _RANDOM_SOURCE.get()(n)


@contextlib.contextmanager
def set_random_source(source: Callable[[int], bytes]) -> Iterator[None]:
    """Replace the random source for the duration of the with-block.

    Restores the previous source on exit, even on exception. Uses
    :class:`contextvars.ContextVar` so concurrent campaigns are isolated.

    Example::

        import random
        rng = random.Random(42)
        with set_random_source(rng.randbytes):
            campaign.run()  # all os.urandom-equivalent calls are deterministic
    """
    if not callable(source):
        raise TypeError(
            f"set_random_source requires a callable, got {type(source).__name__}"
        )
    token = _RANDOM_SOURCE.set(source)
    try:
        yield
    finally:
        _RANDOM_SOURCE.reset(token)


def derive_random_source_from_seed(seed: int) -> Callable[[int], bytes]:
    """Return a deterministic ``Callable[[int], bytes]`` derived from *seed*.

    The returned callable is backed by a private :class:`random.Random`
    instance — it does not touch the global :mod:`random` module state,
    so concurrent campaigns with different seeds remain isolated. The
    callable validates non-negative length and matches the signature
    contract of :func:`os.urandom`.

    Used by both :func:`blue_tap.modules.fuzzing.run_campaign` and the
    ``blue-tap fuzz campaign --seed`` CLI flag so the two share one
    canonical seed→bytes mapping. Two campaigns invoked with the same
    seed produce byte-identical fuzz payloads regardless of entry point.
    """
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError(
            f"derive_random_source_from_seed requires int, got {type(seed).__name__}"
        )
    rng = random.Random(seed)

    def _seeded_source(n: int) -> bytes:
        if n < 0:
            raise ValueError(
                f"random_bytes requires non-negative length, got {n}"
            )
        return rng.randbytes(n)

    _seeded_source.__name__ = f"seeded_random_bytes(seed={seed})"
    return _seeded_source


__all__ = [
    "random_bytes",
    "set_random_source",
    "derive_random_source_from_seed",
]
