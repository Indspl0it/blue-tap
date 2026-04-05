"""Raw HCI socket interface for DarkFirmware vendor-specific commands.

Provides low-level access to the RTL8761B (TP-Link UB500, USB 2357:0604) running
DarkFirmware custom firmware.  Supports three vendor-specific commands:

  - VSC 0xFE22: Inject arbitrary LMP packets into a live connection
  - VSC 0xFC61: Read 32-bit-aligned memory from the Bluetooth controller
  - VSC 0xFC62: Write 32-bit-aligned memory on the Bluetooth controller

Additionally, the firmware hooks incoming LMP packets and reports them as
HCI Event 0xFF (vendor-specific) with a 56-byte structured log.  The
:func:`parse_lmp_log` function decodes that log, and :meth:`HCIVSCSocket.start_lmp_monitor`
runs a background thread to capture them continuously.

Requires root or ``CAP_NET_RAW`` on the process.  Falls back to ``hcitool cmd``
via :func:`send_vsc_hcitool` when raw sockets are unavailable.
"""

from __future__ import annotations

import collections
import logging
import select
import socket
import struct
import threading
import time
from typing import TYPE_CHECKING

from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.utils.output import error, info, warning

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bluetooth / HCI socket constants (from <bluetooth/bluetooth.h>)
# ---------------------------------------------------------------------------
AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_HCI = 1
SOL_HCI = getattr(socket, "SOL_HCI", 0)
HCI_FILTER = getattr(socket, "HCI_FILTER", 2)
HCI_CHANNEL_RAW = 0


# ---------------------------------------------------------------------------
# Standalone parser
# ---------------------------------------------------------------------------

def parse_lmp_log(event_params: bytes) -> dict | None:
    """Parse a 56-byte DarkFirmware LMP RX log from HCI Event 0xFF.

    The firmware hooks incoming LMP packets and emits a vendor-specific HCI
    event containing a structured 56-byte log::

        Offset  Size  Description
        ------  ----  -----------
        0x00    4     0x41414141 (AAAA marker)
        0x04    4     a0 pointer (firmware struct address)
        0x08    4     data_buf pointer
        0x0C    4     unknown_arg2
        0x10    2     opcode-like ushort
        0x12    2     padding
        0x14    4     0x42424242 (BBBB marker)
        0x18    28    LMP payload (if opcode == 0x0480) or 0xCC fill
        0x34    4     0x43434343 (CCCC marker, only when opcode == 0x0480)

    Args:
        event_params: The parameter bytes from the HCI Event 0xFF packet
                      (everything after the event header).

    Returns:
        A dict with keys ``opcode``, ``payload``, ``has_data``, ``raw``,
        ``a0_ptr``, ``data_buf_ptr``, or *None* if the buffer is not a valid
        LMP log (wrong size or missing AAAA marker).
    """
    if len(event_params) != HCIVSCSocket.LMP_LOG_SIZE:
        return None

    marker_a = struct.unpack_from("<I", event_params, 0x00)[0]
    if marker_a != HCIVSCSocket.MARKER_AAAA:
        return None

    a0_ptr = struct.unpack_from("<I", event_params, 0x04)[0]
    data_buf_ptr = struct.unpack_from("<I", event_params, 0x08)[0]
    opcode = struct.unpack_from("<H", event_params, 0x10)[0]

    has_data = opcode == HCIVSCSocket.LMP_OPCODE_PATH
    payload = event_params[0x18:0x34] if has_data else b""

    return {
        "opcode": opcode,
        "payload": payload,
        "has_data": has_data,
        "raw": event_params,
        "a0_ptr": a0_ptr,
        "data_buf_ptr": data_buf_ptr,
    }


# ---------------------------------------------------------------------------
# hcitool fallback
# ---------------------------------------------------------------------------

def send_vsc_hcitool(hci: str, opcode: int, params: bytes) -> str | None:
    """Send a vendor-specific command via ``hcitool cmd`` subprocess.

    This is a fallback for environments where raw HCI sockets are not available
    (e.g., missing ``CAP_NET_RAW``).  It can only return the command-complete
    output; it **cannot** receive asynchronous vendor events (LMP RX logs).

    Args:
        hci:    HCI device name, e.g. ``"hci1"``.
        opcode: 16-bit VSC opcode (e.g. ``0xFE22``).
        params: Raw parameter bytes to append.

    Returns:
        The stdout from ``hcitool``, or *None* on failure.
    """
    ogf = (opcode >> 10) & 0x3F
    ocf = opcode & 0x03FF
    ogf_hex = f"0x{ogf:02x}"
    ocf_hex = f"0x{ocf:04x}"
    param_hex_list = [f"0x{b:02x}" for b in params]

    cmd = ["hcitool", "-i", hci, "cmd", ogf_hex, ocf_hex, *param_hex_list]
    info(f"[hcitool] {' '.join(cmd)}")

    result = run_cmd(cmd, timeout=10)
    if result.returncode != 0:
        warning(f"hcitool failed (rc={result.returncode}): {result.stderr.strip()}")
        return None
    return result.stdout


# ---------------------------------------------------------------------------
# Main HCI VSC socket class
# ---------------------------------------------------------------------------

class HCIVSCSocket:
    """Raw HCI socket for DarkFirmware vendor-specific commands on RTL8761B.

    Usage::

        with HCIVSCSocket(hci_dev=1) as sock:
            sock.send_lmp(b"\\x03\\x01\\x02")
            sock.start_lmp_monitor(lambda log: print(log))
            time.sleep(10)

    The class creates a raw ``AF_BLUETOOTH`` / ``BTPROTO_HCI`` socket bound to
    the given HCI device index and configures an all-pass HCI filter so both
    command-complete and vendor-specific events are received.
    """

    # VSC opcodes
    VSC_LMP_TX: int = 0xFE22
    VSC_MEM_READ: int = 0xFC61
    VSC_MEM_WRITE: int = 0xFC62

    # HCI packet types
    HCI_COMMAND_PKT: int = 0x01
    HCI_EVENT_PKT: int = 0x04
    HCI_VENDOR_EVENT: int = 0xFF
    HCI_CMD_COMPLETE: int = 0x0E

    # LMP RX log markers / constants
    MARKER_AAAA: int = 0x41414141
    MARKER_BBBB: int = 0x42424242
    MARKER_CCCC: int = 0x43434343
    LMP_LOG_SIZE: int = 56
    LMP_OPCODE_PATH: int = 0x0480

    # UB500 patched firmware: send_LMP_reply length raised to 0x11 (17 bytes)
    # Original default was 0x0A (10). Raised via patch_send_length(0x11).
    _LMP_TX_MAX_BYTES: int = 17

    def __init__(self, hci_dev: int = 1) -> None:
        self._hci_dev = hci_dev
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._monitor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.lmp_log_buffer: collections.deque[dict] = collections.deque(maxlen=1000)
        # Queue for command-complete events routed from the monitor thread
        self._cc_queue: collections.deque[tuple[int, bytes]] = collections.deque(maxlen=64)
        self._cc_ready = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Create a raw HCI socket, bind to the device, and set the filter.

        Raises:
            OSError: If socket creation, binding, or filter setup fails
                     (usually a permissions issue).
        """
        if self._sock is not None:
            warning("HCI socket already open; closing previous")
            self.close()

        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        except OSError as exc:
            error(f"Cannot create raw HCI socket: {exc}")
            raise

        try:
            # Bind to the specific HCI device
            # struct sockaddr_hci: family(2) + dev(2) + channel(2)
            sock.bind((self._hci_dev,))
        except OSError as exc:
            sock.close()
            error(f"Cannot bind to hci{self._hci_dev}: {exc}")
            raise

        # Set an all-pass HCI filter so we receive every event type.
        # struct hci_filter: type_mask(4) + event_mask[0](4) + event_mask[1](4) + opcode(2) + pad(2)
        hci_filter = struct.pack("<IIIh2x",
                                 0xFFFFFFFF,   # type_mask: all packet types
                                 0xFFFFFFFF,   # event_mask low 32 bits: all events
                                 0xFFFFFFFF,   # event_mask high 32 bits: all events
                                 0)            # opcode filter: none
        try:
            sock.setsockopt(SOL_HCI, HCI_FILTER, hci_filter)
        except OSError as exc:
            sock.close()
            error(f"Cannot set HCI filter on hci{self._hci_dev}: {exc}")
            raise

        self._sock = sock
        info(f"Opened raw HCI socket on hci{self._hci_dev}")

    def close(self) -> None:
        """Close the socket and stop the monitor thread if running."""
        self.stop_lmp_monitor()
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
                info(f"Closed HCI socket on hci{self._hci_dev}")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> HCIVSCSocket:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "open" if self._sock is not None else "closed"
        monitor = "monitoring" if self._monitor_thread and self._monitor_thread.is_alive() else "idle"
        return f"<HCIVSCSocket hci{self._hci_dev} {state} {monitor}>"

    # ------------------------------------------------------------------
    # Low-level send / recv
    # ------------------------------------------------------------------

    def send_vsc(self, opcode: int, params: bytes = b"", timeout: float = 5.0) -> bytes:
        """Send a vendor-specific HCI command and wait for command-complete.

        Constructs an HCI command packet::

            [0x01] [opcode_lo] [opcode_hi] [param_len] [params...]

        When the LMP monitor is running, command-complete events are routed
        via an internal queue to avoid a race where the monitor thread steals
        the response.  When the monitor is not running, events are read
        directly from the socket.

        Args:
            opcode:  16-bit VSC opcode (e.g. ``0xFE22``).
            params:  Raw parameter bytes.
            timeout: Seconds to wait for the command-complete event.

        Returns:
            The parameter bytes from the command-complete event (after the
            num_hci_pkts and opcode fields).

        Raises:
            OSError:      If the socket is not open.
            TimeoutError: If no matching command-complete arrives in time.
        """
        if self._sock is None:
            raise OSError("HCI socket is not open")

        # Build HCI command packet
        opcode_bytes = struct.pack("<H", opcode)
        pkt = bytes([self.HCI_COMMAND_PKT]) + opcode_bytes + bytes([len(params)]) + params

        logger.debug("TX VSC 0x%04X  params=%s", opcode, params.hex())

        with self._lock:
            self._sock.sendall(pkt)

        monitor_active = (
            self._monitor_thread is not None and self._monitor_thread.is_alive()
        )

        if monitor_active:
            # Monitor thread owns the socket reads.  It routes CC events to
            # _cc_queue and signals _cc_ready.  We wait on that.
            return self._wait_cc_from_monitor(opcode, timeout)
        else:
            # No monitor — read events directly from the socket.
            return self._wait_cc_direct(opcode, timeout)

    def _wait_cc_direct(self, opcode: int, timeout: float) -> bytes:
        """Read events directly until we find a matching command-complete."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No command-complete for VSC 0x{opcode:04X} within {timeout}s")

            result = self.recv_event(timeout=remaining)
            if result is None:
                raise TimeoutError(f"No command-complete for VSC 0x{opcode:04X} within {timeout}s")

            event_code, event_params = result
            logger.debug("RX event 0x%02X (%d bytes)", event_code, len(event_params))

            if event_code == self.HCI_CMD_COMPLETE and len(event_params) >= 3:
                cc_opcode = struct.unpack_from("<H", event_params, 1)[0]
                if cc_opcode == opcode:
                    return event_params[3:]

            logger.debug("Skipped event 0x%02X while waiting for CC 0x%04X", event_code, opcode)

    def _wait_cc_from_monitor(self, opcode: int, timeout: float) -> bytes:
        """Wait for a command-complete event routed by the monitor thread."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No command-complete for VSC 0x{opcode:04X} within {timeout}s")

            self._cc_ready.wait(timeout=min(remaining, 0.5))
            self._cc_ready.clear()

            # Drain the CC queue looking for our opcode
            checked: list[tuple[int, bytes]] = []
            while self._cc_queue:
                cc_opcode, cc_params = self._cc_queue.popleft()
                if cc_opcode == opcode:
                    # Put back any non-matching events
                    for item in checked:
                        self._cc_queue.appendleft(item)
                    return cc_params
                checked.append((cc_opcode, cc_params))

            # None matched; put them all back
            for item in checked:
                self._cc_queue.appendleft(item)

    def recv_event(self, timeout: float = 5.0) -> tuple[int, bytes] | None:
        """Read one HCI event from the socket.

        An HCI event on a raw socket arrives as::

            [0x04] [event_code] [param_len] [params...]

        Args:
            timeout: Seconds to wait for data.

        Returns:
            ``(event_code, params)`` or *None* on timeout.

        Raises:
            OSError: If the socket is not open.
        """
        if self._sock is None:
            raise OSError("HCI socket is not open")

        with self._lock:
            ready, _, _ = select.select([self._sock], [], [], timeout)
            if not ready:
                return None

            data = self._sock.recv(512)

        if len(data) < 3:
            logger.debug("Runt HCI event (%d bytes)", len(data))
            return None

        # data[0] is HCI packet type indicator (0x04 for events)
        pkt_type = data[0]
        if pkt_type != self.HCI_EVENT_PKT:
            logger.debug("Non-event packet type 0x%02X", pkt_type)
            return None

        event_code = data[1]
        param_len = data[2]
        params = data[3:3 + param_len]

        return (event_code, params)

    # ------------------------------------------------------------------
    # VSC wrappers
    # ------------------------------------------------------------------

    def send_lmp(self, lmp_data: bytes, max_bytes: int | None = None) -> bool:
        """Inject an LMP packet via VSC 0xFE22.

        The DarkFirmware ``send_LMP_reply`` function controls the send length
        via a patchable instruction.  The UB500 dongle firmware has been patched
        to 17 bytes (0x11) via
        :meth:`~blue_tap.core.firmware.DarkFirmwareManager.patch_send_length`,
        matching the full over-the-air LMP PDU maximum.

        Args:
            lmp_data: Raw LMP packet data (opcode + params).
            max_bytes: Override max send size.  Defaults to
                       ``_LMP_TX_MAX_BYTES`` (17 on patched UB500 firmware).

        Returns:
            *True* on success, *False* on failure.
        """
        limit = max_bytes if max_bytes is not None else self._LMP_TX_MAX_BYTES
        info(f"Sending LMP via VSC 0xFE22 ({len(lmp_data)} bytes)")
        if len(lmp_data) > limit:
            warning(
                f"LMP data {len(lmp_data)}B exceeds firmware limit "
                f"({limit}B); will be truncated"
            )
            lmp_data = lmp_data[:limit]

        try:
            self.send_vsc(self.VSC_LMP_TX, lmp_data)
            return True
        except (OSError, TimeoutError) as exc:
            error(f"send_lmp failed: {exc}")
            return False

    def read_memory(self, address: int, size: int = 4) -> bytes:
        """Read memory from the Bluetooth controller via VSC 0xFC61.

        Args:
            address: 32-bit memory address to read from.
            size:    Number of bytes to read (default 4).

        Returns:
            The raw bytes read from the controller.

        Raises:
            OSError:      If the socket is not open.
            TimeoutError: If the command-complete is not received.
        """
        info(f"Reading memory at {address:#010x}")
        # Params: size(1B) + address(4B LE)
        params = struct.pack("<BI", size, address)
        result = self.send_vsc(self.VSC_MEM_READ, params)

        # Command complete returns: status(1) + data(...)
        if len(result) < 1:
            error("Empty response from memory read")
            return b""

        status = result[0]
        if status != 0x00:
            error(f"Memory read at 0x{address:08X} failed with status 0x{status:02X}")
            return b""

        return result[1:]

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory on the Bluetooth controller via VSC 0xFC62.

        Args:
            address: 32-bit memory address to write to.
            data:    Bytes to write (typically 4 bytes for 32-bit write).

        Returns:
            *True* on success, *False* on failure.
        """
        info(f"Writing memory at {address:#010x}")
        # Params: size(1B) + address(4B LE) + data
        params = struct.pack("<BI", len(data), address) + data
        try:
            result = self.send_vsc(self.VSC_MEM_WRITE, params)
            status = result[0] if result else 0xFF
            if status != 0x00:
                error(f"Memory write at 0x{address:08X} failed with status 0x{status:02X}")
                return False
            return True
        except (OSError, TimeoutError) as exc:
            error(f"write_memory failed: {exc}")
            return False

    # ------------------------------------------------------------------
    # LMP monitor thread
    # ------------------------------------------------------------------

    def start_lmp_monitor(self, callback: Callable[[dict], None]) -> None:
        """Start a background thread that captures LMP RX logs.

        The thread reads HCI events in a loop, filters for vendor-specific
        events (0xFF), parses them with :func:`parse_lmp_log`, appends valid
        logs to :attr:`lmp_log_buffer`, and calls *callback* for each one.

        Args:
            callback: Called with the parsed log dict for every valid LMP RX
                      event received.
        """
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            warning("LMP monitor already running")
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(callback,),
            name=f"lmp-monitor-hci{self._hci_dev}",
            daemon=True,
        )
        self._monitor_thread.start()
        info(f"LMP monitor started on hci{self._hci_dev}")

    def stop_lmp_monitor(self) -> None:
        """Signal the monitor thread to stop and wait for it to exit."""
        if self._monitor_thread is None or not self._monitor_thread.is_alive():
            return

        self._stop_event.set()
        self._monitor_thread.join(timeout=3.0)
        if self._monitor_thread.is_alive():
            warning("LMP monitor thread did not exit cleanly")
        else:
            info("LMP monitor stopped")
        self._monitor_thread = None

    def _monitor_loop(self, callback: Callable[[dict], None]) -> None:
        """Internal loop for the LMP monitor thread.

        Reads ALL HCI events from the socket.  Vendor events (0xFF) are
        parsed as LMP logs and dispatched to the callback.  Command-complete
        events (0x0E) are routed to :attr:`_cc_queue` so that
        :meth:`send_vsc` can retrieve them without a race condition.
        """
        while not self._stop_event.is_set():
            try:
                result = self.recv_event(timeout=0.5)
            except OSError:
                if self._stop_event.is_set():
                    break
                logger.exception("Socket error in monitor loop")
                break

            if result is None:
                continue

            event_code, event_params = result

            # Route command-complete events to send_vsc() via queue
            if event_code == self.HCI_CMD_COMPLETE and len(event_params) >= 3:
                cc_opcode = struct.unpack_from("<H", event_params, 1)[0]
                cc_return = event_params[3:]
                self._cc_queue.append((cc_opcode, cc_return))
                self._cc_ready.set()
                continue

            # Process vendor events as LMP logs
            if event_code != self.HCI_VENDOR_EVENT:
                continue

            log = parse_lmp_log(event_params)
            if log is None:
                continue

            self.lmp_log_buffer.append(log)
            try:
                callback(log)
            except Exception:
                logger.exception("Exception in LMP monitor callback")
