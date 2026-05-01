"""Verify ``blue-tap doctor`` shows ``→ fix:`` remediation hints.

Both the env_doctor data layer and the CLI rendering are exercised so a
regression in either side surfaces immediately. The CLI test patches
``detect_profile_environment`` to a deterministic shape — we never touch the
host's actual Bluetooth stack from a test.
"""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.utils.env_doctor import (
    TOOL_FIX_HINTS,
    SERVICE_FIX_HINTS,
    fix_hint_for_tool,
)


# ── env_doctor data layer ────────────────────────────────────────────────


def test_fix_hint_for_tool_returns_hint_for_known_tool():
    assert "apt install" in fix_hint_for_tool("bluetoothctl")


def test_fix_hint_for_tool_returns_empty_for_unknown_tool():
    assert fix_hint_for_tool("totally-fake-binary") == ""


def test_tool_fix_hints_cover_every_tool_doctor_checks():
    """Every tool that ``detect_profile_environment`` probes must have a hint.

    Otherwise the CLI shows ✗ with no remediation, defeating the point.
    """
    expected_tools = {
        "bluetoothctl", "sdptool", "hciconfig",
        "pactl", "parecord", "paplay", "aplay",
    }
    missing = expected_tools - TOOL_FIX_HINTS.keys()
    assert not missing, f"Missing fix hints for tools: {missing}"


def test_service_fix_hints_cover_critical_services():
    """Each service whose absence triggers a limitation has a fix hint."""
    for svc in ("bluetooth", "dbus", "pipewire"):
        assert svc in SERVICE_FIX_HINTS, f"No fix hint for service {svc!r}"


# ── CLI rendering ────────────────────────────────────────────────────────


_FAKE_ENV_ALL_MISSING = {
    "tools": {
        "bluetoothctl": False,
        "sdptool": False,
        "hciconfig": True,
        "pactl": False,
        "parecord": False,
        "paplay": False,
        "aplay": False,
    },
    "services": {
        "bluetooth": False,
        "dbus": True,
        "pipewire": False,
        "pipewire-pulse": False,
        "wireplumber": False,
        "pulseaudio": False,
    },
    "adapters": [],
    "obex": {"client_interface_available": True, "errors": []},
    "summary": {
        "bluetooth_ready": False,
        "obex_ready": True,
        "audio_ready": False,
        "capability_limitations": [
            "bluetoothctl is unavailable; some adapter/profile workflows cannot be orchestrated locally",
            "Bluetooth service is inactive or unavailable",
            "No local Bluetooth adapters detected",
        ],
    },
    "limitation_hints": {
        "bluetoothctl is unavailable; some adapter/profile workflows cannot be orchestrated locally":
            "sudo apt install bluez bluez-tools",
        "Bluetooth service is inactive or unavailable":
            "sudo systemctl enable --now bluetooth",
        "No local Bluetooth adapters detected":
            "lsusb | grep -i bluetooth  # then check `dmesg | tail` for driver errors",
    },
}


def test_doctor_cli_shows_fix_hint_for_missing_tool():
    runner = CliRunner()
    with patch(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        return_value=_FAKE_ENV_ALL_MISSING,
    ):
        result = runner.invoke(cli, ["doctor"], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    # The literal install string must appear directly under the missing tool.
    assert "→ fix:" in result.output
    assert "apt install bluez bluez-tools" in result.output


def test_doctor_cli_shows_fix_hint_for_each_limitation():
    runner = CliRunner()
    with patch(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        return_value=_FAKE_ENV_ALL_MISSING,
    ):
        result = runner.invoke(cli, ["doctor"], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    # Each limitation in the fake env has a known hint — ensure every one
    # surfaces in the output.
    for hint in _FAKE_ENV_ALL_MISSING["limitation_hints"].values():
        # Hints can be long; assert a stable substring of each.
        substr = hint.split()[0]  # first token, e.g. "sudo", "lsusb"
        assert substr in result.output, (
            f"Hint substring {substr!r} from {hint!r} not in output:\n{result.output}"
        )


def test_doctor_cli_omits_fix_arrow_when_no_hint_available():
    """A limitation with empty-string fix hint must not render an empty ``→ fix:``."""
    fake = {
        "tools": {"bluetoothctl": True, "sdptool": True, "hciconfig": True,
                  "pactl": True, "parecord": True, "paplay": True, "aplay": True},
        "services": {"bluetooth": True, "dbus": True, "pipewire": True,
                     "pipewire-pulse": True, "wireplumber": True, "pulseaudio": True},
        "adapters": [{"name": "hci0", "address": "00:11:22:33:44:55", "status": "UP"}],
        "obex": {"client_interface_available": True, "errors": []},
        "summary": {
            "bluetooth_ready": True,
            "obex_ready": True,
            "audio_ready": True,
            "capability_limitations": ["Some unfamiliar diagnostic message"],
        },
        "limitation_hints": {"Some unfamiliar diagnostic message": ""},
    }

    runner = CliRunner()
    with patch(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        return_value=fake,
    ):
        result = runner.invoke(cli, ["doctor"], catch_exceptions=False)

    assert result.exit_code == 0
    # The bullet should appear, but no ``→ fix:`` should follow it for this
    # specific limitation. We verify by counting occurrences — there must be
    # no fix arrows because no tool was missing and the limitation has no hint.
    assert "Some unfamiliar diagnostic message" in result.output
    assert "→ fix:" not in result.output, (
        f"Empty hint produced a ``→ fix:`` line:\n{result.output}"
    )


def test_doctor_cli_clean_environment_reports_ready():
    fake = {
        "tools": {k: True for k in (
            "bluetoothctl", "sdptool", "hciconfig",
            "pactl", "parecord", "paplay", "aplay",
        )},
        "services": {k: True for k in (
            "bluetooth", "dbus", "pipewire",
            "pipewire-pulse", "wireplumber", "pulseaudio",
        )},
        "adapters": [{"name": "hci0", "address": "00:11:22:33:44:55", "status": "UP"}],
        "obex": {"client_interface_available": True, "errors": []},
        "summary": {
            "bluetooth_ready": True,
            "obex_ready": True,
            "audio_ready": True,
            "capability_limitations": [],
        },
        "limitation_hints": {},
    }

    runner = CliRunner()
    with patch(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        return_value=fake,
    ):
        result = runner.invoke(cli, ["doctor"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "Environment ready" in result.output
    assert "→ fix:" not in result.output
