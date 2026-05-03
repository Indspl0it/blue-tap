import logging
from unittest.mock import MagicMock, patch


def test_disconnect_logs_on_exception(caplog):
    """disconnect() must log at DEBUG when the async call raises, not swallow silently."""
    from blue_tap.hardware.obex_client import ObexSession

    client = ObexSession.__new__(ObexSession)
    client._bus = MagicMock()
    client.session_path = "/org/bluez/obex/client/session0"
    client.session_props = {}
    client.destination = "AA:BB:CC:DD:EE:FF"

    with patch("blue_tap.hardware.obex_client.run_async", side_effect=RuntimeError("dbus gone")):
        with caplog.at_level(logging.DEBUG, logger="blue_tap.hardware.obex_client"):
            client.disconnect()

    assert client.session_path is None, "session_path must be cleared even on exception"
    assert client._bus is None, "_bus must be cleared even on exception"
    assert any(
        "OBEX disconnect error" in r.message for r in caplog.records
    ), f"Expected DEBUG log. Got: {[(r.levelname, r.message) for r in caplog.records]}"


def test_disconnect_cleans_up_when_no_session():
    """disconnect() with no session must return immediately without side effects."""
    from blue_tap.hardware.obex_client import ObexSession

    client = ObexSession.__new__(ObexSession)
    client._bus = None
    client.session_path = None
    client.session_props = {}

    client.disconnect()  # must not raise
