"""Tests for CliEvent emission from spoof, adapter, and firmware CLI command handlers."""
from __future__ import annotations

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _captured_events(mock_emit: MagicMock) -> list[str]:
    """Return the list of event_type strings from all emit_cli_event calls."""
    return [call.kwargs["event_type"] for call in mock_emit.call_args_list]


# ---------------------------------------------------------------------------
# Spoof mac — run lifecycle
# ---------------------------------------------------------------------------

def test_spoof_mac_emits_run_lifecycle():
    """spoof mac must emit run_started and run_completed (or run_error)."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {
        "success": True,
        "method_used": "bdaddr",
        "original_mac": "AA:BB:CC:DD:EE:00",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "verified": True,
        "methods_tried": ["bdaddr"],
    }

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.spoofer.spoof_address", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        result = CliRunner().invoke(
            main, ["spoof", "mac", "AA:BB:CC:DD:EE:FF", "--hci", "hci0"]
        )

    assert "run_started" in captured, f"run_started not emitted; got: {captured}"
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal, f"Neither run_completed nor run_error emitted; got: {captured}"


def test_spoof_mac_emits_run_error_on_failure():
    """spoof mac must emit run_error when spoofing fails."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {
        "success": False,
        "method_used": None,
        "error": "Address not changed",
        "methods_tried": ["bdaddr"],
    }

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.spoofer.spoof_address", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["spoof", "mac", "AA:BB:CC:DD:EE:FF", "--hci", "hci0"])

    assert "run_started" in captured
    assert "run_error" in captured, f"Expected run_error on failure; got: {captured}"


# ---------------------------------------------------------------------------
# Spoof clone — run lifecycle
# ---------------------------------------------------------------------------

def test_spoof_clone_emits_run_lifecycle():
    """spoof clone must emit run_started and run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {
        "success": True,
        "mac_spoofed": True,
        "name_set": True,
        "class_set": True,
        "original_mac": "AA:BB:CC:DD:EE:00",
        "target_mac": "AA:BB:CC:DD:EE:FF",
        "target_name": "Galaxy S24",
        "device_class": "0x5a020c",
    }

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.spoofer.clone_device_identity", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(
            main,
            ["spoof", "clone", "AA:BB:CC:DD:EE:FF", "Galaxy S24", "--hci", "hci0"],
        )

    assert "run_started" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal, f"No terminal event; got: {captured}"


# ---------------------------------------------------------------------------
# Spoof restore — run lifecycle
# ---------------------------------------------------------------------------

def test_spoof_restore_emits_run_lifecycle():
    """spoof restore must emit run_started and run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {
        "success": True,
        "restored_mac": "AA:BB:CC:DD:EE:00",
        "hci": "hci0",
        "method": "bdaddr",
    }

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.spoofer.restore_original_mac", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["spoof", "restore", "--hci", "hci0"])

    assert "run_started" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


# ---------------------------------------------------------------------------
# Adapter set-name — CliEvents
# ---------------------------------------------------------------------------

def test_adapter_set_name_emits_run_lifecycle():
    """adapter set-name must emit run_started, execution_result, run_completed."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {"success": True, "name": "TestDevice", "previous_name": "hci0"}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.adapter.set_device_name", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["adapter", "set-name", "hci0", "TestDevice"])

    assert "run_started" in captured
    assert "execution_result" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


def test_adapter_set_name_logs_to_session():
    """adapter set-name must call log_command with an envelope."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    logged: list[tuple] = []

    def fake_log(command, payload, **kwargs):
        logged.append((command, payload))

    fake_result = {"success": True, "name": "TestDevice", "previous_name": "hci0"}

    with patch("blue_tap.hardware.adapter.set_device_name", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command", side_effect=fake_log), \
         patch("blue_tap.cli.emit_cli_event", return_value={}):
        CliRunner().invoke(main, ["adapter", "set-name", "hci0", "TestDevice"])

    assert logged, "log_command was never called"
    cmd, payload = logged[0]
    assert cmd == "adapter_set_name"
    assert isinstance(payload, dict)
    assert payload.get("schema") is not None, "Payload should be an envelope with 'schema'"


# ---------------------------------------------------------------------------
# Adapter set-class — CliEvents
# ---------------------------------------------------------------------------

def test_adapter_set_class_emits_run_lifecycle():
    """adapter set-class must emit run_started, execution_result, run_completed."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {"success": True, "device_class": "0x5a020c"}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.adapter.set_device_class", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["adapter", "set-class", "hci0", "0x5a020c"])

    assert "run_started" in captured
    assert "execution_result" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


# ---------------------------------------------------------------------------
# Adapter up/down/reset — CliEvents
# ---------------------------------------------------------------------------

def test_adapter_up_emits_run_lifecycle():
    """adapter up must emit run_started, execution_result, and run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {"success": True, "hci": "hci0", "operation": "adapter_up"}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.adapter.adapter_up", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["adapter", "up", "hci0"])

    assert "run_started" in captured
    assert "execution_result" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


def test_adapter_down_emits_run_lifecycle():
    """adapter down must emit run_started, execution_result, run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {"success": True, "hci": "hci0", "operation": "adapter_down"}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.adapter.adapter_down", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["adapter", "down", "hci0"])

    assert "run_started" in captured
    assert "execution_result" in captured


def test_adapter_reset_emits_run_lifecycle():
    """adapter reset must emit run_started, execution_result, run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    fake_result = {"success": True, "hci": "hci0", "operation": "adapter_reset"}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.adapter.adapter_reset", return_value=fake_result), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(main, ["adapter", "reset", "hci0"])

    assert "run_started" in captured
    assert "execution_result" in captured


# ---------------------------------------------------------------------------
# Firmware-dump — artifact_saved
# ---------------------------------------------------------------------------

def test_firmware_dump_emits_artifact_saved(tmp_path):
    """firmware-dump must emit artifact_saved after a successful dump."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    output_file = str(tmp_path / "rom.bin")

    def fake_dump(start, end, path, hci):
        # Simulate successful write
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        return True

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.is_darkfirmware_loaded", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.dump_memory", side_effect=fake_dump), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(
            main,
            ["adapter", "firmware-dump", "--region", "rom", "-o", output_file, "--hci", "hci1"],
        )

    assert "artifact_saved" in captured, f"artifact_saved not emitted; got: {captured}"
    assert "run_started" in captured


def test_firmware_dump_emits_run_completed(tmp_path):
    """firmware-dump must emit run_completed on success."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    output_file = str(tmp_path / "rom.bin")

    def fake_dump(start, end, path, hci):
        with open(path, "wb") as f:
            f.write(b"\x00" * 16)
        return True

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.is_darkfirmware_loaded", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.dump_memory", side_effect=fake_dump), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(
            main,
            ["adapter", "firmware-dump", "--region", "ram", "-o", output_file, "--hci", "hci1"],
        )

    assert "run_completed" in captured, f"run_completed not emitted; got: {captured}"


# ---------------------------------------------------------------------------
# Firmware-spoof — CliEvents and session logging
# ---------------------------------------------------------------------------

def test_firmware_spoof_emits_run_lifecycle():
    """firmware-spoof must emit run_started, execution_result, run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.detect_rtl8761b", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.patch_bdaddr", return_value=True), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(
            main, ["adapter", "firmware-spoof", "AA:BB:CC:DD:EE:FF", "--hci", "hci1"]
        )

    assert "run_started" in captured
    assert "execution_result" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


def test_firmware_spoof_logs_to_session():
    """firmware-spoof must call log_command with an envelope."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    logged: list[tuple] = []

    def fake_log(command, payload, **kwargs):
        logged.append((command, payload))

    with patch("blue_tap.hardware.firmware.DarkFirmwareManager.detect_rtl8761b", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.patch_bdaddr", return_value=True), \
         patch("blue_tap.framework.sessions.store.log_command", side_effect=fake_log), \
         patch("blue_tap.cli.emit_cli_event", return_value={}):
        CliRunner().invoke(
            main, ["adapter", "firmware-spoof", "AA:BB:CC:DD:EE:FF", "--hci", "hci1"]
        )

    assert logged, "log_command was never called"
    cmd, payload = logged[0]
    assert cmd == "firmware_spoof"
    assert isinstance(payload, dict)
    assert payload.get("schema") is not None, "Payload should be a RunEnvelope with 'schema'"


# ---------------------------------------------------------------------------
# Firmware-set — CliEvents and session logging
# ---------------------------------------------------------------------------

def test_firmware_set_emits_run_lifecycle():
    """firmware-set must emit run_started, execution_result, run_completed/run_error."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    captured: list[str] = []

    def fake_emit(*, event_type, **kwargs):
        captured.append(event_type)
        return {"event_type": event_type, **kwargs}

    with patch("blue_tap.cli.emit_cli_event", side_effect=fake_emit), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.is_darkfirmware_loaded", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.patch_send_length", return_value=True), \
         patch("blue_tap.framework.sessions.store.log_command"):
        CliRunner().invoke(
            main, ["adapter", "firmware-set", "lmp-size", "17", "--hci", "hci1"]
        )

    assert "run_started" in captured
    assert "execution_result" in captured
    terminal = [e for e in captured if e in ("run_completed", "run_error")]
    assert terminal


def test_firmware_set_logs_to_session():
    """firmware-set must call log_command with a RunEnvelope."""
    from click.testing import CliRunner
    from blue_tap.cli import main

    logged: list[tuple] = []

    def fake_log(command, payload, **kwargs):
        logged.append((command, payload))

    with patch("blue_tap.hardware.firmware.DarkFirmwareManager.is_darkfirmware_loaded", return_value=True), \
         patch("blue_tap.hardware.firmware.DarkFirmwareManager.patch_send_length", return_value=True), \
         patch("blue_tap.framework.sessions.store.log_command", side_effect=fake_log), \
         patch("blue_tap.cli.emit_cli_event", return_value={}):
        CliRunner().invoke(
            main, ["adapter", "firmware-set", "lmp-size", "17", "--hci", "hci1"]
        )

    assert logged, "log_command was never called"
    cmd, payload = logged[0]
    assert cmd == "firmware_set"
    assert isinstance(payload, dict)
    assert payload.get("schema") is not None
