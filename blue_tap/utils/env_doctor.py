"""Environment diagnostics for Bluetooth profile prerequisites."""

from __future__ import annotations

from blue_tap.hardware.obex_client import detect_obex_capability
from blue_tap.utils.bt_helpers import check_tool, get_hci_adapters, run_cmd


def detect_profile_environment() -> dict:
    """Collect host-side prerequisites for profile operations."""
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
    if not result["tools"]["bluetoothctl"]:
        limitations.append("bluetoothctl is unavailable; some adapter/profile workflows cannot be orchestrated locally")
    if not result["tools"]["sdptool"]:
        limitations.append("sdptool is unavailable; SDP-based service discovery may require explicit RFCOMM channel selection")
    if not result["tools"]["pactl"]:
        limitations.append("pactl is unavailable; host audio routing/profile switching cannot be controlled")
    if not result["tools"]["parecord"]:
        limitations.append("parecord is unavailable; Bluetooth microphone capture cannot run on the primary path")
    if not result["tools"]["paplay"] and not result["tools"]["aplay"]:
        limitations.append("No local audio playback helper found; speaker playback/review commands are degraded")
    if not result["services"]["bluetooth"]:
        limitations.append("Bluetooth service is inactive or unavailable")
    if not result["services"]["dbus"]:
        limitations.append("System D-Bus is inactive or unavailable; BlueZ dbus-fast integrations cannot function")
    audio_services = (
        result["services"]["pipewire"],
        result["services"]["pipewire-pulse"],
        result["services"]["pulseaudio"],
    )
    if not any(state is True for state in audio_services):
        limitations.append("No active PipeWire/PulseAudio user service detected; audio capture/playback commands may not function")
    if not result["adapters"]:
        limitations.append("No local Bluetooth adapters detected")
    if not result["obex"]["client_interface_available"]:
        limitations.append("BlueZ obexd client interface is unavailable; PBAP/MAP/OPP fall back to reduced functionality")
    elif result["obex"].get("errors"):
        limitations.extend(str(item) for item in result["obex"]["errors"] if item)
    result["summary"] = {
        "bluetooth_ready": bool(result["services"]["bluetooth"]) and bool(result["adapters"]),
        "obex_ready": bool(result["obex"]["client_interface_available"]),
        "audio_ready": bool(result["tools"]["pactl"]) and any(state is True for state in audio_services),
        "capability_limitations": limitations,
    }
    return result


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
