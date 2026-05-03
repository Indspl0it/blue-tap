import asyncio

import pytest

from blue_tap.hardware.obex_client import ObexError, ObexSession


def test_connect_raises_obex_error_on_timeout():
    """connect() must raise ObexError (not hang) when the async path stalls past timeout."""
    session = ObexSession(
        destination="AA:BB:CC:DD:EE:FF",
        target="00112233-4455-6677-8899-aabbccddeeff",
    )

    async def _stall(*args, **kwargs):
        await asyncio.sleep(10)

    # Replace _async_connect with a coroutine that takes way longer than the timeout.
    session._async_connect = _stall

    with pytest.raises(ObexError, match="timed out after 0.1s"):
        session.connect(timeout=0.1)


def test_connect_propagates_non_timeout_failures():
    """A non-timeout exception must surface as ObexError with original message."""
    session = ObexSession(
        destination="AA:BB:CC:DD:EE:FF",
        target="00112233-4455-6677-8899-aabbccddeeff",
    )

    async def _explode():
        raise RuntimeError("dbus refused")

    session._async_connect = _explode

    with pytest.raises(ObexError, match="connect failed: dbus refused"):
        session.connect(timeout=5.0)
