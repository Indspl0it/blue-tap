import logging
import sys
import threading
import types
from unittest.mock import MagicMock, patch

# firmware.py pulls in hci_vsc which needs fcntl (Linux-only). Stub it so
# the test can import on Windows/CI without a real HCI device.
if "fcntl" not in sys.modules:
    sys.modules["fcntl"] = types.ModuleType("fcntl")


def test_on_reinit_callback_exception_is_logged(caplog):
    """on_reinit callback that raises must log a warning, not swallow silently."""
    from blue_tap.hardware.firmware import DarkFirmwareWatchdog

    def bad_callback(hci, event):
        raise RuntimeError("callback exploded")

    wd = DarkFirmwareWatchdog.__new__(DarkFirmwareWatchdog)
    wd.hci = "hci1"
    wd.on_reinit = bad_callback
    wd._reinit_count = 0
    wd._reinit_lock = threading.Lock()
    wd._reinit_in_progress = False
    wd._last_reinit = 0.0
    wd._fw = MagicMock()
    wd._fw.is_darkfirmware_loaded.return_value = True
    wd._fw.init_hooks.return_value = {"all_ok": True, "hook1": True, "hook2": True, "hook3": True, "hook4": True}

    with patch("blue_tap.hardware.firmware.time") as mock_time:
        mock_time.monotonic.return_value = 100.0
        mock_time.sleep.return_value = None
        with caplog.at_level(logging.WARNING, logger="blue_tap.hardware.firmware"):
            wd._reinit_hooks("test event")

    assert any(
        "on_reinit callback raised" in r.message
        for r in caplog.records
        if r.levelno >= logging.WARNING
    ), f"Expected warning. Got: {[(r.levelname, r.message) for r in caplog.records]}"


def test_hooks_status_read_failure_is_logged_at_debug(caplog):
    """get_firmware_status() hooks read failure must log at DEBUG, not swallow silently."""
    from blue_tap.hardware.firmware import DarkFirmwareManager

    mgr = DarkFirmwareManager.__new__(DarkFirmwareManager)

    # Patch instance methods so we reach the hooks-read path
    with patch.object(mgr, "_resolve_hci", return_value="hci1"), \
         patch.object(mgr, "get_current_bdaddr", return_value="AA:BB:CC:DD:EE:FF"), \
         patch.object(mgr, "detect_rtl8761b", return_value=True), \
         patch.object(mgr, "is_darkfirmware_loaded", return_value=True), \
         patch("blue_tap.hardware.hci_vsc.HCIVSCSocket", side_effect=OSError("no device")), \
         caplog.at_level(logging.DEBUG, logger="blue_tap.hardware.firmware"):
        mgr.get_firmware_status(hci="hci1")

    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("hooks" in m.lower() or "non-fatal" in m.lower() for m in debug_msgs), (
        f"Expected DEBUG log about hooks read failure. Got: {debug_msgs}"
    )
