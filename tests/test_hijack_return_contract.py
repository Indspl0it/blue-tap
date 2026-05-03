import sys
import types
from unittest.mock import MagicMock, patch

# hijack.py → reconnaissance → fuzzing/transport.py needs fcntl (Linux-only).
# Stub it so the test can import on Windows/CI without a real HCI device.
if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.ModuleType("fcntl")


def _make_hijack():
    from blue_tap.modules.exploitation.hijack import HijackSession
    h = HijackSession.__new__(HijackSession)
    h.ivi_address = "AA:BB:CC:DD:EE:FF"
    h.output_dir = "/tmp/test_hijack"
    h.pbap_channel = None
    h.map_channel = None
    h.hfp_channel = None
    h._executions = []
    h._run_id = "test-run-id"
    h.session = MagicMock()
    return h


def test_dump_phonebook_returns_none_when_no_channel():
    h = _make_hijack()
    with patch.object(h, "_emit"):
        result = h.dump_phonebook()
    assert result is None, f"Expected None on missing channel, got {result!r}"


def test_dump_phonebook_returns_none_when_connection_fails():
    h = _make_hijack()
    h.pbap_channel = 5
    fake = MagicMock()
    fake.connect.return_value = False
    with patch("blue_tap.modules.exploitation.hijack.PBAPClient", return_value=fake):
        with patch.object(h, "_emit"):
            result = h.dump_phonebook()
    assert result is None, f"Expected None on connection failure, got {result!r}"


def test_dump_phonebook_returns_none_on_dump_exception():
    h = _make_hijack()
    h.pbap_channel = 5
    fake = MagicMock()
    fake.connect.return_value = True
    fake.pull_all_data.side_effect = RuntimeError("OBEX timeout")
    with patch("blue_tap.modules.exploitation.hijack.PBAPClient", return_value=fake):
        with patch.object(h, "_emit"):
            result = h.dump_phonebook()
    assert result is None, f"Expected None on dump exception, got {result!r}"


def test_dump_phonebook_returns_empty_dict_on_zero_contacts():
    """Successful dump with 0 contacts must return {} (not None)."""
    h = _make_hijack()
    h.pbap_channel = 5
    fake = MagicMock()
    fake.connect.return_value = True
    fake.pull_all_data.return_value = {}
    with patch("blue_tap.modules.exploitation.hijack.PBAPClient", return_value=fake):
        with patch.object(h, "_emit"):
            result = h.dump_phonebook()
    assert result == {}, f"Expected empty dict on zero contacts, got {result!r}"


def test_dump_messages_returns_none_when_no_channel():
    h = _make_hijack()
    with patch.object(h, "_emit"):
        result = h.dump_messages()
    assert result is None, f"Expected None on missing channel, got {result!r}"


def test_dump_messages_returns_none_when_connection_fails():
    h = _make_hijack()
    h.map_channel = 7
    fake = MagicMock()
    fake.connect.return_value = False
    with patch("blue_tap.modules.exploitation.hijack.MAPClient", return_value=fake):
        with patch.object(h, "_emit"):
            result = h.dump_messages()
    assert result is None, f"Expected None on connection failure, got {result!r}"


def test_dump_messages_returns_none_on_dump_exception():
    h = _make_hijack()
    h.map_channel = 7
    fake = MagicMock()
    fake.connect.return_value = True
    fake.dump_all_messages.side_effect = RuntimeError("MAP timeout")
    with patch("blue_tap.modules.exploitation.hijack.MAPClient", return_value=fake):
        with patch.object(h, "_emit"):
            result = h.dump_messages()
    assert result is None, f"Expected None on dump exception, got {result!r}"
