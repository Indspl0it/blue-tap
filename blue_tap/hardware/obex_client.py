"""Pure-Python BlueZ OBEX D-Bus helpers built on dbus-fast.

This module is the shared substrate for PBAP, MAP, and OPP so profile code
does not need to duplicate session creation, transfer polling, or D-Bus
variant/property handling.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import tempfile
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


OBEX_SERVICE = "org.bluez.obex"
OBEX_CLIENT = "org.bluez.obex.Client1"
OBEX_SESSION = "org.bluez.obex.Session1"
OBEX_TRANSFER = "org.bluez.obex.Transfer1"
OBEX_PHONEBOOK = "org.bluez.obex.PhonebookAccess1"
OBEX_MESSAGE_ACCESS = "org.bluez.obex.MessageAccess1"
OBEX_MESSAGE = "org.bluez.obex.Message1"
OBEX_OBJECT_PUSH = "org.bluez.obex.ObjectPush1"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"


def run_async(coro):
    """Run an async coroutine from sync code.

    Guarantees ``coro`` is either awaited or explicitly closed. The threaded
    fallback (used when called from inside a running event loop) can race
    against pytest gc — if the worker raises before scheduling
    ``asyncio.run(coro)``, the coroutine leaks and Python eventually emits a
    ``RuntimeWarning: coroutine '...' was never awaited`` against whichever
    unrelated test was running at gc time. ``finally: coro.close()`` is a
    no-op on already-consumed coroutines and safe to call unconditionally.
    """
    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    finally:
        try:
            coro.close()
        except (RuntimeError, AttributeError):
            pass


def variant_to_python(value):
    """Convert dbus-fast Variants and nested containers to plain Python values."""
    try:
        from dbus_fast import Variant

        if isinstance(value, Variant):
            return variant_to_python(value.value)
    except ImportError:
        pass

    if isinstance(value, dict):
        return {str(key): variant_to_python(item) for key, item in value.items()}
    if isinstance(value, list):
        return [variant_to_python(item) for item in value]
    if isinstance(value, tuple):
        return tuple(variant_to_python(item) for item in value)
    return value


class ObexError(RuntimeError):
    """Raised when an OBEX D-Bus operation fails."""


class ObexSession:
    """Shared BlueZ OBEX session helper."""

    def __init__(
        self,
        destination: str,
        *,
        target: str,
        source: str | None = None,
        channel: int | None = None,
        bus_factory: Callable[[], Any] | None = None,
    ):
        self.destination = destination
        self.target = target
        self.source = source
        self.channel = channel
        self.bus_factory = bus_factory

        self._bus = None
        self.session_path: str | None = None
        self.session_props: dict[str, Any] = {}

    def connect(self, *, timeout: float = 30.0) -> bool:
        """Establish the OBEX session.

        Args:
            timeout: Maximum seconds to wait for ``call_create_session`` and
                property reads. The BlueZ daemon can stall indefinitely on a
                broken phone — without a timeout the entire CLI hangs.

        Raises:
            ObexError: on connection failure or timeout.
        """
        try:
            run_async(self._async_connect_with_timeout(timeout))
            return True
        except asyncio.TimeoutError as exc:
            raise ObexError(f"OBEX session connect timed out after {timeout}s") from exc
        except Exception as exc:
            raise ObexError(f"OBEX session connect failed: {exc}") from exc

    async def _async_connect_with_timeout(self, timeout: float) -> None:
        await asyncio.wait_for(self._async_connect(), timeout=timeout)

    async def _async_connect(self):
        self._bus = await self._create_bus()
        root_obj = await self._get_proxy_object("/org/bluez/obex")
        client = root_obj.get_interface(OBEX_CLIENT)

        args: dict[str, Any] = {"Target": self.target}
        if self.source:
            args["Source"] = self.source
        if self.channel is not None:
            args["Channel"] = self.channel

        session_path = await client.call_create_session(self.destination, self._wrap_dict(args))
        self.session_path = str(variant_to_python(session_path))
        self.session_props = await self._async_get_session_properties()

    def disconnect(self):
        if not self._bus or not self.session_path:
            return
        # Capture the coroutine in a local so we can close it explicitly if
        # ``run_async`` raises before awaiting (e.g. dbus-fast is gone, or the
        # threaded fallback fails to schedule). Without this, Python tags the
        # never-awaited coroutine to whichever test happens to be running at
        # gc time — see the equivalent guard inside ``run_async``.
        coro = self._async_disconnect()
        try:
            run_async(coro)
        except Exception as exc:
            logger.debug("OBEX disconnect error (session already gone?): %s", exc)
            try:
                coro.close()
            except (RuntimeError, AttributeError):
                pass
        finally:
            self.session_path = None
            self.session_props = {}
            self._bus = None

    async def _async_disconnect(self):
        root_obj = await self._get_proxy_object("/org/bluez/obex")
        client = root_obj.get_interface(OBEX_CLIENT)
        try:
            await client.call_remove_session(self.session_path)
        finally:
            if self._bus:
                self._bus.disconnect()

    def get_capabilities(self) -> str:
        return str(run_async(self._async_get_capabilities()))

    async def _async_get_capabilities(self) -> str:
        session = await self._get_session_interface(OBEX_SESSION)
        return str(variant_to_python(await session.call_get_capabilities()))

    def get_session_properties(self) -> dict[str, Any]:
        return run_async(self._async_get_session_properties())

    async def _async_get_session_properties(self) -> dict[str, Any]:
        if not self.session_path:
            raise ObexError("OBEX session not connected")
        return await self._get_all_properties(self.session_path, OBEX_SESSION)

    def get_transfer_properties(self, transfer_path: str) -> dict[str, Any]:
        return run_async(self._async_get_transfer_properties(transfer_path))

    async def _async_get_transfer_properties(self, transfer_path: str) -> dict[str, Any]:
        return await self._get_all_properties(transfer_path, OBEX_TRANSFER)

    def wait_for_transfer(self, transfer_path: str, timeout: float = 60.0, poll_interval: float = 0.2) -> dict[str, Any]:
        return run_async(self._async_wait_for_transfer(transfer_path, timeout=timeout, poll_interval=poll_interval))

    def create_temp_file_path(self, *, prefix: str, suffix: str) -> str:
        """Create an empty temp file path for OBEX downloads/uploads."""
        with tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix, delete=False) as handle:
            return handle.name

    def finalize_transfer_file(
        self,
        transfer_path: str,
        initial_props: dict[str, Any] | None = None,
        *,
        fallback_path: str = "",
        timeout: float = 60.0,
        poll_interval: float = 0.2,
    ) -> tuple[str, dict[str, Any]]:
        """Wait for a transfer to complete and resolve the resulting filename."""
        final_props = self.wait_for_transfer(transfer_path, timeout=timeout, poll_interval=poll_interval)
        filename = str(
            final_props.get("Filename")
            or (initial_props or {}).get("Filename")
            or fallback_path
        )
        if not filename:
            raise ObexError(f"OBEX transfer completed without a filename: {final_props}")
        return filename, final_props

    @staticmethod
    def read_text_file(path: str, *, encoding: str = "utf-8") -> str:
        if not path or not os.path.exists(path):
            raise ObexError(f"OBEX transfer file not found: {path}")
        with open(path, "r", encoding=encoding, errors="replace") as handle:
            return handle.read()

    async def _async_wait_for_transfer(
        self,
        transfer_path: str,
        *,
        timeout: float = 60.0,
        poll_interval: float = 0.2,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_props: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last_props = await self._async_get_transfer_properties(transfer_path)
            status = str(last_props.get("Status", "")).lower()
            if status == "complete":
                return last_props
            if status == "error":
                raise ObexError(f"OBEX transfer failed: {last_props}")
            await asyncio.sleep(poll_interval)
        raise ObexError(f"Timed out waiting for OBEX transfer {transfer_path}: {last_props}")

    async def call_session_method(self, interface_name: str, method_name: str, *args):
        iface = await self._get_session_interface(interface_name)
        method = getattr(iface, f"call_{method_name}")
        return variant_to_python(await method(*args))

    async def _create_bus(self):
        if self.bus_factory is not None:
            bus = self.bus_factory()
            if inspect.isawaitable(bus):
                bus = await bus
            return bus

        try:
            from dbus_fast.aio import MessageBus
            from dbus_fast import BusType
        except ImportError as exc:
            raise ObexError("dbus-fast is not installed") from exc

        return await MessageBus(bus_type=BusType.SYSTEM).connect()

    async def _get_proxy_object(self, path: str):
        introspection = await self._bus.introspect(OBEX_SERVICE, path)
        return self._bus.get_proxy_object(OBEX_SERVICE, path, introspection)

    async def _get_session_interface(self, interface_name: str):
        if not self.session_path:
            raise ObexError("OBEX session not connected")
        session_obj = await self._get_proxy_object(self.session_path)
        return session_obj.get_interface(interface_name)

    async def _get_all_properties(self, path: str, interface_name: str) -> dict[str, Any]:
        obj = await self._get_proxy_object(path)
        props_iface = obj.get_interface(DBUS_PROPERTIES)
        props = await props_iface.call_get_all(interface_name)
        return variant_to_python(props)

    def _wrap_dict(self, values: dict[str, Any]) -> dict[str, Any]:
        try:
            from dbus_fast import Variant
        except ImportError:
            return values

        wrapped: dict[str, Any] = {}
        for key, value in values.items():
            if isinstance(value, bool):
                wrapped[key] = Variant("b", value)
            elif key == "Channel" and isinstance(value, int):
                wrapped[key] = Variant("y", value if value >= 0 else 0)
            elif isinstance(value, int):
                wrapped[key] = Variant("q", value if value >= 0 else 0)
            elif isinstance(value, list):
                wrapped[key] = Variant("as", [str(item) for item in value])
            else:
                wrapped[key] = Variant("s", str(value))
        return wrapped


class PBAPSession(ObexSession):
    """PBAP-specific operations over a shared OBEX session."""

    def __init__(self, destination: str, *, source: str | None = None, channel: int | None = None, bus_factory=None):
        super().__init__(destination, target="pbap", source=source, channel=channel, bus_factory=bus_factory)

    def select(self, location: str, phonebook: str):
        return run_async(self.call_session_method(OBEX_PHONEBOOK, "select", location, phonebook))

    def pull_all(self, targetfile: str, filters: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        return self._normalize_transfer_result(
            run_async(
                self.call_session_method(
                    OBEX_PHONEBOOK,
                    "pull_all",
                    targetfile,
                    self._wrap_dict(filters or {}),
                )
            )
        )

    def list(self, filters: dict[str, Any] | None = None) -> list[dict[str, str]]:
        raw = run_async(
            self.call_session_method(OBEX_PHONEBOOK, "list", self._wrap_dict(filters or {}))
        )
        entries: list[dict[str, str]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    entry = {str(key).lower(): str(value) for key, value in item.items()}
                    if entry:
                        entries.append(entry)
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    entries.append({"handle": str(item[0]), "name": str(item[1])})
        return entries

    def pull(self, vcard: str, targetfile: str, filters: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        return self._normalize_transfer_result(
            run_async(
                self.call_session_method(
                    OBEX_PHONEBOOK,
                    "pull",
                    vcard,
                    targetfile,
                    self._wrap_dict(filters or {}),
                )
            )
        )

    def search(self, field: str, value: str, filters: dict[str, Any] | None = None) -> list[dict[str, str]]:
        raw = run_async(
            self.call_session_method(
                OBEX_PHONEBOOK,
                "search",
                field,
                value,
                self._wrap_dict(filters or {}),
            )
        )
        entries: list[dict[str, str]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    entry = {str(key).lower(): str(val) for key, val in item.items()}
                    if entry:
                        entries.append(entry)
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    entries.append({"handle": str(item[0]), "name": str(item[1])})
        return entries

    def get_size(self) -> int:
        return int(run_async(self.call_session_method(OBEX_PHONEBOOK, "get_size")))

    def update_version(self):
        return run_async(self.call_session_method(OBEX_PHONEBOOK, "update_version"))

    def list_filter_fields(self) -> list[str]:
        raw = run_async(self.call_session_method(OBEX_PHONEBOOK, "list_filter_fields"))
        return [str(item) for item in raw] if isinstance(raw, list) else []

    def get_phonebook_properties(self) -> dict[str, Any]:
        if not self.session_path:
            raise ObexError("OBEX session not connected")
        return run_async(self._get_all_properties(self.session_path, OBEX_PHONEBOOK))

    @staticmethod
    def _normalize_transfer_result(result: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(result, (list, tuple)) and len(result) >= 2:
            transfer_path = str(result[0])
            props = variant_to_python(result[1])
            return transfer_path, props if isinstance(props, dict) else {}
        raise ObexError(f"Unexpected OBEX transfer result: {result!r}")


class MAPSession(ObexSession):
    """MAP-specific operations over a shared OBEX session."""

    def __init__(self, destination: str, *, source: str | None = None, channel: int | None = None, bus_factory=None):
        super().__init__(destination, target="map", source=source, channel=channel, bus_factory=bus_factory)

    def set_folder(self, name: str):
        return run_async(self.call_session_method(OBEX_MESSAGE_ACCESS, "set_folder", name))

    def list_folders(self, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        raw = run_async(
            self.call_session_method(OBEX_MESSAGE_ACCESS, "list_folders", self._wrap_dict(filters or {}))
        )
        return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []

    def list_filter_fields(self) -> list[str]:
        raw = run_async(self.call_session_method(OBEX_MESSAGE_ACCESS, "list_filter_fields"))
        return [str(item) for item in raw] if isinstance(raw, list) else []

    def list_messages(self, folder: str = "", filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        raw = run_async(
            self.call_session_method(
                OBEX_MESSAGE_ACCESS,
                "list_messages",
                folder,
                self._wrap_dict(filters or {}),
            )
        )
        messages: list[dict[str, Any]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    message_path = str(item[0])
                    props = variant_to_python(item[1])
                    payload = props if isinstance(props, dict) else {}
                    payload["path"] = message_path
                    messages.append(payload)
        return messages

    def update_inbox(self):
        return run_async(self.call_session_method(OBEX_MESSAGE_ACCESS, "update_inbox"))

    def push_message(self, sourcefile: str, folder: str = "", args: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        return PBAPSession._normalize_transfer_result(
            run_async(
                self.call_session_method(
                    OBEX_MESSAGE_ACCESS,
                    "push_message",
                    sourcefile,
                    folder,
                    self._wrap_dict(args or {}),
                )
            )
        )

    def set_message_read(self, message_path: str, value: bool):
        return run_async(self._async_set_message_flag(message_path, "read", value))

    def set_message_deleted(self, message_path: str, value: bool):
        return run_async(self._async_set_message_flag(message_path, "deleted", value))

    def get_message_properties(self, message_path: str) -> dict[str, Any]:
        return run_async(self._get_all_properties(message_path, OBEX_MESSAGE))

    def get_message(self, message_path: str, targetfile: str, attachment: bool = False) -> tuple[str, dict[str, Any]]:
        return PBAPSession._normalize_transfer_result(
            run_async(self._async_get_message(message_path, targetfile, attachment))
        )

    async def _async_get_message(self, message_path: str, targetfile: str, attachment: bool):
        obj = await self._get_proxy_object(message_path)
        iface = obj.get_interface(OBEX_MESSAGE)
        return variant_to_python(await iface.call_get(targetfile, attachment))

    async def _async_set_message_flag(self, message_path: str, property_name: str, value: bool):
        obj = await self._get_proxy_object(message_path)
        iface = obj.get_interface(OBEX_MESSAGE)
        setter = getattr(iface, f"set_{property_name}", None)
        if setter is None:
            raise ObexError(f"Message1 property '{property_name}' is not writable via dbus-fast interface")
        await setter(value)


class OPPSession(ObexSession):
    """OPP-specific operations over a shared OBEX session."""

    def __init__(self, destination: str, *, source: str | None = None, channel: int | None = None, bus_factory=None):
        super().__init__(destination, target="opp", source=source, channel=channel, bus_factory=bus_factory)

    def send_file(self, sourcefile: str) -> tuple[str, dict[str, Any]]:
        return PBAPSession._normalize_transfer_result(
            run_async(self.call_session_method(OBEX_OBJECT_PUSH, "send_file", sourcefile))
        )


def detect_obex_capability(bus_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    """Check whether BlueZ obexd is reachable via pure-Python dbus-fast."""
    return run_async(_detect_obex_capability_async(bus_factory=bus_factory))


async def _detect_obex_capability_async(bus_factory: Callable[[], Any] | None = None) -> dict[str, Any]:
    result = {
        "dbus_fast_available": False,
        "obex_service_reachable": False,
        "client_interface_available": False,
        "errors": [],
    }

    try:
        if bus_factory is not None:
            bus = bus_factory()
            if inspect.isawaitable(bus):
                bus = await bus
        else:
            from dbus_fast.aio import MessageBus
            from dbus_fast import BusType

            result["dbus_fast_available"] = True
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        if not result["dbus_fast_available"]:
            result["dbus_fast_available"] = True

        try:
            introspection = await bus.introspect(OBEX_SERVICE, "/org/bluez/obex")
            proxy = bus.get_proxy_object(OBEX_SERVICE, "/org/bluez/obex", introspection)
            proxy.get_interface(OBEX_CLIENT)
            result["obex_service_reachable"] = True
            result["client_interface_available"] = True
        finally:
            try:
                bus.disconnect()
            except Exception:
                pass
    except ImportError as exc:
        result["errors"].append(f"dbus-fast unavailable: {exc}")
    except Exception as exc:
        result["errors"].append(str(exc))

    return result
