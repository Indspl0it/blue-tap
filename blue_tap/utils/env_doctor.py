"""Environment diagnostics for Bluetooth profile prerequisites."""

from __future__ import annotations

from blue_tap.hardware.obex_client import detect_obex_capability
from blue_tap.utils.bt_helpers import check_tool, get_hci_adapters, run_cmd


# Remediation hints for missing tools and services. The CLI renders these
# as ``→ fix:`` lines so a fresh operator can copy/paste the next step.
# Distros vary; the apt commands cover Debian/Ubuntu/Kali (the BT-Tap target
# platforms). For other distros operators read the package name and adapt.
TOOL_FIX_HINTS: dict[str, str] = {
    "bluetoothctl": "sudo apt install bluez bluez-tools",
    "sdptool": "sudo apt install bluez bluez-tools",
    "hciconfig": "sudo apt install bluez bluez-tools",
    "pactl": "sudo apt install pulseaudio-utils  # or pipewire-pulse",
    "parecord": "sudo apt install pulseaudio-utils  # or pipewire-pulse",
    "paplay": "sudo apt install pulseaudio-utils  # or pipewire-pulse",
    "aplay": "sudo apt install alsa-utils",
}

SERVICE_FIX_HINTS: dict[str, str] = {
    "bluetooth": "sudo systemctl enable --now bluetooth",
    "dbus": "sudo systemctl enable --now dbus",
    "pipewire": "systemctl --user enable --now pipewire pipewire-pulse",
    "pulseaudio": "systemctl --user enable --now pulseaudio  # only one of pipewire/pulseaudio",
}


def detect_profile_environment() -> dict:
    """Collect host-side prerequisites for profile operations.

    Returns a dict with ``tools``, ``services``, ``adapters``, ``obex``, and
    ``summary`` keys (unchanged from prior versions for backward
    compatibility) plus a ``limitation_hints`` dict mapping each
    limitation message to a copy-paste remediation command (empty string
    when no automatic fix is meaningful).
    """
    result = {
        "tools": {
            "bluetoothctl": check_tool("bluetoothctl"),
            "sdptool": check_tool("sdptool"),
            "hciconfig": check_tool("hciconfig"),
            "pactl": check_tool("pactl"),
            "parecord": check_tool("parecord"),
            "paplay": check_tool("paplay"),
            "aplay": check_tool("aplay"),
        },
        "services": {
            "bluetooth": _service_active("bluetooth"),
            "dbus": _service_active("dbus"),
            "pipewire": _user_service_active("pipewire"),
            "pipewire-pulse": _user_service_active("pipewire-pulse"),
            "wireplumber": _user_service_active("wireplumber"),
            "pulseaudio": _user_service_active("pulseaudio"),
        },
        "adapters": get_hci_adapters(),
    }
    result["obex"] = detect_obex_capability()
    limitations: list[str] = []
    limitation_hints: dict[str, str] = {}

    def _add(message: str, fix: str = "") -> None:
        limitations.append(message)
        limitation_hints[message] = fix

    if not result["tools"]["bluetoothctl"]:
        _add(
            "bluetoothctl is unavailable; some adapter/profile workflows cannot be orchestrated locally",
            TOOL_FIX_HINTS["bluetoothctl"],
        )
    if not result["tools"]["sdptool"]:
        _add(
            "sdptool is unavailable; SDP-based service discovery may require explicit RFCOMM channel selection",
            TOOL_FIX_HINTS["sdptool"],
        )
    if not result["tools"]["pactl"]:
        _add(
            "pactl is unavailable; host audio routing/profile switching cannot be controlled",
            TOOL_FIX_HINTS["pactl"],
        )
    if not result["tools"]["parecord"]:
        _add(
            "parecord is unavailable; Bluetooth microphone capture cannot run on the primary path",
            TOOL_FIX_HINTS["parecord"],
        )
    if not result["tools"]["paplay"] and not result["tools"]["aplay"]:
        _add(
            "No local audio playback helper found; speaker playback/review commands are degraded",
            TOOL_FIX_HINTS["paplay"],
        )
    if not result["services"]["bluetooth"]:
        _add(
            "Bluetooth service is inactive or unavailable",
            SERVICE_FIX_HINTS["bluetooth"],
        )
    if not result["services"]["dbus"]:
        _add(
            "System D-Bus is inactive or unavailable; BlueZ dbus-fast integrations cannot function",
            SERVICE_FIX_HINTS["dbus"],
        )
    audio_services = (
        result["services"]["pipewire"],
        result["services"]["pipewire-pulse"],
        result["services"]["pulseaudio"],
    )
    if not any(state is True for state in audio_services):
        _add(
            "No active PipeWire/PulseAudio user service detected; audio capture/playback commands may not function",
            SERVICE_FIX_HINTS["pipewire"],
        )
    if not result["adapters"]:
        # No automatic fix — the operator needs hardware. Surface the next
        # diagnostic command so they can confirm the kernel sees nothing.
        _add(
            "No local Bluetooth adapters detected",
            "lsusb | grep -i bluetooth  # then check `dmesg | tail` for driver errors",
        )
    if not result["obex"]["client_interface_available"]:
        _add(
            "BlueZ obexd client interface is unavailable; PBAP/MAP/OPP fall back to reduced functionality",
            "sudo systemctl --user enable --now obex  # or: sudo apt install obexftp obex-data-server",
        )
    elif result["obex"].get("errors"):
        for item in result["obex"]["errors"]:
            if item:
                # Errors from obexd diagnostics rarely have a one-line fix —
                # surface them as-is and let the operator triage.
                _add(str(item), "")

    result["summary"] = {
        "bluetooth_ready": bool(result["services"]["bluetooth"]) and bool(result["adapters"]),
        "obex_ready": bool(result["obex"]["client_interface_available"]),
        "audio_ready": bool(result["tools"]["pactl"]) and any(state is True for state in audio_services),
        "capability_limitations": limitations,
    }
    result["limitation_hints"] = limitation_hints
    return result


def fix_hint_for_tool(tool: str) -> str:
    """Return a copy-paste install hint for ``tool``, or empty string if unknown."""
    return TOOL_FIX_HINTS.get(tool, "")


def _service_active(name: str) -> bool | None:
    """Return True/False if systemctl can determine service state, else None."""
    if not check_tool("systemctl"):
        return None
    cp = run_cmd(["systemctl", "is-active", name], timeout=5)
    if cp.returncode == 0:
        return cp.stdout.strip() == "active"
    return False


def _user_service_active(name: str) -> bool | None:
    """Return True/False if systemctl --user can determine service state, else None."""
    if not check_tool("systemctl"):
        return None
    cp = run_cmd(["systemctl", "--user", "is-active", name], timeout=5)
    if cp.returncode == 0:
        return cp.stdout.strip() == "active"
    return False
