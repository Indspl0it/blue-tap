"""Bluetooth transport abstraction layer for fuzzing.

Provides unified socket wrappers for L2CAP, RFCOMM, and BLE connections
with automatic reconnect, timeout handling, health checks, and statistics
tracking.  Every transport follows the same connect/send/recv/close interface
so the fuzzing engine can target any Bluetooth layer without caring about
the underlying socket type.
"""

from __future__ import annotations

import collections
import ctypes
import ctypes.util
import fcntl
import os
import re
import select
import socket
import struct
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.utils.output import info, warning, error

# ---------------------------------------------------------------------------
# Bluetooth socket constants (from <bluetooth/bluetooth.h>)
# ---------------------------------------------------------------------------
AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3
BTPROTO_HCI = 1
SOL_BLUETOOTH = 274
BT_SECURITY = 4

# L2CAP socket options
SOL_L2CAP = 6
L2CAP_OPTIONS = 0x01

# BLE address types (for kernel BLE L2CAP)
BDADDR_BREDR = 0x00
BDADDR_LE_PUBLIC = 0x01
BDADDR_LE_RANDOM = 0x02


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class TransportStats:
    """Tracks transport-level statistics for a fuzzing session.

    Updated automatically by BluetoothTransport on every send, recv,
    error, and reconnect event.
    """

    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    errors: int = 0
    reconnects: int = 0
    connection_drops: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def packets_per_second(self) -> float:
        """Calculate average packets sent per second since start."""
        elapsed = time.time() - self.start_time
        return self.packets_sent / max(elapsed, 0.001)

    @property
    def elapsed(self) -> float:
        """Seconds since the stats tracking started."""
        return time.time() - self.start_time

    def reset(self) -> None:
        """Reset all counters and restart the timer."""
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        self.errors = 0
        self.reconnects = 0
        self.connection_drops = 0
        self.start_time = time.time()

    def to_dict(self) -> dict:
        """Serialize stats to a plain dict for JSON export."""
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "errors": self.errors,
            "reconnects": self.reconnects,
            "connection_drops": self.connection_drops,
            "elapsed_seconds": round(self.elapsed, 2),
            "packets_per_second": round(self.packets_per_second, 2),
        }


# ---------------------------------------------------------------------------
# Base transport
# ---------------------------------------------------------------------------

class BluetoothTransport(ABC):
    """Abstract base class for Bluetooth socket transports.

    Subclasses must implement ``_create_socket`` and ``_connect_socket``
    to handle protocol-specific socket creation and address binding.
    The base class provides unified send/recv with stats tracking,
    automatic reconnect with exponential backoff, and health checks
    via ``l2ping``.

    Usage::

        transport = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        if transport.connect():
            transport.send(payload)
            response = transport.recv()
            transport.close()
    """

    def __init__(
        self,
        address: str,
        timeout: float = 5.0,
        max_reconnects: int = 3,
    ) -> None:
        self.address = address
        self.timeout = timeout
        self.max_reconnects = max_reconnects
        self.stats = TransportStats()
        self._sock: socket.socket | None = None
        self._connected = False

    # -- Abstract interface (subclasses implement these) --------------------

    @abstractmethod
    def _create_socket(self) -> socket.socket:
        """Create and return a new Bluetooth socket for this transport type.

        Must NOT connect the socket -- just create and configure it.
        """

    @abstractmethod
    def _connect_socket(self, sock: socket.socket) -> None:
        """Connect the socket to the remote device.

        Raises OSError on failure.
        """

    # -- Public interface ---------------------------------------------------

    def connect(self) -> bool:
        """Establish a connection to the remote Bluetooth device.

        Returns:
            True if the connection succeeded, False otherwise.
        """
        try:
            self.close()  # clean up any prior socket
            self._sock = self._create_socket()
            self._sock.settimeout(self.timeout)
            self._connect_socket(self._sock)
            self._connected = True
            return True
        except OSError as exc:
            error(f"Connect failed ({self.__class__.__name__}): {exc}")
            self.stats.errors += 1
            self._connected = False
            self.close()
            return False

    def send(self, data: bytes) -> int:
        """Send data over the transport.

        Args:
            data: Raw bytes to transmit.

        Returns:
            Number of bytes actually sent, or 0 on failure.

        Raises:
            ConnectionError: If the socket is not connected and auto-reconnect
                fails.
        """
        if self._sock is None or not self._connected:
            if not self.reconnect():
                raise ConnectionError("Not connected and reconnect failed")
            if self._sock is None:
                raise ConnectionError("Socket is None after reconnect")

        try:
            sent = self._sock.send(data)
            self.stats.bytes_sent += sent
            self.stats.packets_sent += 1
            return sent
        except (BrokenPipeError, ConnectionResetError) as exc:
            self.stats.errors += 1
            self.stats.connection_drops += 1
            self._connected = False
            warning(f"Connection dropped on send: {exc}")
            raise
        except OSError as exc:
            self.stats.errors += 1
            error(f"Send error: {exc}")
            return 0

    def recv(self, bufsize: int = 4096, recv_timeout: float | None = None) -> bytes | None:
        """Receive data from the transport.

        Args:
            bufsize: Maximum number of bytes to receive.
            recv_timeout: Per-call timeout override (seconds).  Falls back to
                the transport's default timeout if not specified.

        Returns:
            Received bytes, empty bytes on timeout, or None if the connection
            is closed.
        """
        if self._sock is None or not self._connected:
            return None

        old_timeout = None
        try:
            if recv_timeout is not None:
                old_timeout = self._sock.gettimeout()
                self._sock.settimeout(recv_timeout)

            data = self._sock.recv(bufsize)
            if data:
                self.stats.bytes_received += len(data)
                self.stats.packets_received += 1
                return data
            # Empty recv means remote closed
            self.stats.connection_drops += 1
            self._connected = False
            return None
        except TimeoutError:
            return b""
        except (BrokenPipeError, ConnectionResetError):
            self.stats.errors += 1
            self.stats.connection_drops += 1
            self._connected = False
            return None
        except OSError as exc:
            self.stats.errors += 1
            error(f"Recv error: {exc}")
            return None
        finally:
            if old_timeout is not None and self._sock is not None:
                try:
                    self._sock.settimeout(old_timeout)
                except OSError:
                    pass

    def close(self) -> None:
        """Close the underlying socket, ignoring errors."""
        self._connected = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def is_alive(self) -> bool:
        """Check if the target device is reachable via l2ping.

        Returns:
            True if the device responds to an L2CAP echo within 3 seconds.
        """
        result = run_cmd(["l2ping", "-c", "1", "-t", "3", self.address], timeout=8)
        if result.returncode != 0 and result.stderr:
            stderr_lower = result.stderr.lower()
            if "operation not permitted" in stderr_lower or "permission denied" in stderr_lower:
                warning("l2ping requires root privileges or CAP_NET_RAW capability")
        return result.returncode == 0

    def reconnect(self) -> bool:
        """Attempt reconnection with exponential backoff.

        Tries up to ``max_reconnects`` times with delays of
        1s, 2s, 4s, ... capped at 30s.

        Returns:
            True if reconnection succeeded, False if all attempts failed.
        """
        for attempt in range(self.max_reconnects):
            delay = min(2 ** attempt, 30)
            info(f"Reconnect attempt {attempt + 1}/{self.max_reconnects} "
                 f"(waiting {delay}s)...")
            time.sleep(delay)
            try:
                self.close()
                if self.connect():
                    self.stats.reconnects += 1
                    info("Reconnected successfully")
                    return True
            except OSError:
                continue
        error(f"All {self.max_reconnects} reconnect attempts failed")
        return False

    @property
    def connected(self) -> bool:
        """Whether the transport currently believes it is connected."""
        return self._connected

    def __enter__(self) -> BluetoothTransport:
        if not self.connect():
            raise ConnectionError(
                f"Failed to connect to {self.address} via {self.__class__.__name__}"
            )
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        return f"<{self.__class__.__name__} addr={self.address} {state}>"


# ---------------------------------------------------------------------------
# Mock transport (dry-run / benchmarking)
# ---------------------------------------------------------------------------

class MockTransport(BluetoothTransport):
    """In-process transport with no socket — for dry runs and benchmarks.

    Drops every send into a bounded ring buffer (so memory stays flat
    over long campaigns) and returns canned responses on recv. The
    response factory is injectable so research code can simulate
    protocol-specific replies; the default returns ``b""`` (empty,
    indistinguishable from a timeout).

    Thread-safety: NOT thread-safe — one instance per protocol, used by
    the engine's single fuzzing loop. No lock is held; the engine never
    accesses the same MockTransport from multiple threads.
    """

    DEFAULT_SEND_BUFFER_LEN = 64

    def __init__(
        self,
        address: str,
        *,
        protocol: str = "",
        response_factory: Callable[[bytes], bytes] | None = None,
        send_buffer_len: int = DEFAULT_SEND_BUFFER_LEN,
    ) -> None:
        super().__init__(address, timeout=0.1, max_reconnects=0)
        self.protocol = protocol
        self._response_factory: Callable[[bytes], bytes] = (
            response_factory if response_factory is not None else (lambda _payload: b"")
        )
        if send_buffer_len < 1:
            raise ValueError("send_buffer_len must be >= 1")
        self.sent: collections.deque[bytes] = collections.deque(maxlen=send_buffer_len)

    # The abstract socket hooks are unused — we override connect/send/recv
    # directly to avoid creating any real socket. Keep concrete (no-op)
    # implementations so MockTransport can be instantiated.
    def _create_socket(self) -> socket.socket:
        raise RuntimeError("MockTransport does not create real sockets")

    def _connect_socket(self, sock: socket.socket) -> None:
        raise RuntimeError("MockTransport does not connect real sockets")

    def connect(self) -> bool:
        self._connected = True
        return True

    def send(self, data: bytes) -> int:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"MockTransport.send requires bytes, got {type(data).__name__}")
        payload = bytes(data)
        self.sent.append(payload)
        self.stats.bytes_sent += len(payload)
        self.stats.packets_sent += 1
        return len(payload)

    def recv(self, bufsize: int = 4096, recv_timeout: float | None = None) -> bytes | None:
        last = self.sent[-1] if self.sent else b""
        try:
            response = self._response_factory(last)
        except Exception as exc:
            error(f"MockTransport response_factory raised {type(exc).__name__}: {exc}")
            return None
        if not isinstance(response, (bytes, bytearray)):
            raise TypeError(
                f"MockTransport response_factory must return bytes, got "
                f"{type(response).__name__}"
            )
        response = bytes(response)
        self.stats.bytes_received += len(response)
        self.stats.packets_received += 1
        return response

    def close(self) -> None:
        self._connected = False

    def is_alive(self) -> bool:
        return self._connected

    def reconnect(self) -> bool:
        self._connected = True
        return True


# ---------------------------------------------------------------------------
# L2CAP transport
# ---------------------------------------------------------------------------

class L2CAPTransport(BluetoothTransport):
    """Transport for Bluetooth L2CAP connections.

    L2CAP (Logical Link Control and Adaptation Protocol) provides
    connection-oriented and connectionless data channels.  This transport
    uses SOCK_SEQPACKET for sequenced, reliable, connection-based delivery
    with message boundaries preserved.

    Args:
        address: Target device BD_ADDR (e.g. ``"AA:BB:CC:DD:EE:FF"``).
        psm: Protocol/Service Multiplexer.  Common values:
            1 = SDP, 3 = RFCOMM, 15 = BNEP, 23 = AVCTP, 25 = AVDTP.
        timeout: Socket timeout in seconds.
        max_reconnects: Maximum reconnection attempts on drop.
        mtu: Optional MTU to request via L2CAP socket options.
    """

    def __init__(
        self,
        address: str,
        psm: int = 1,
        timeout: float = 5.0,
        max_reconnects: int = 3,
        mtu: int | None = None,
    ) -> None:
        super().__init__(address, timeout, max_reconnects)
        self.psm = psm
        self.mtu = mtu

    def _create_socket(self) -> socket.socket:
        """Create an L2CAP SEQPACKET socket with optional MTU configuration."""
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        if self.mtu is not None:
            self._set_mtu(sock, self.mtu)
        return sock

    def _connect_socket(self, sock: socket.socket) -> None:
        """Connect to the target's L2CAP PSM."""
        sock.connect((self.address, self.psm))

    @staticmethod
    def _set_mtu(sock: socket.socket, mtu: int) -> None:
        """Set the L2CAP MTU via socket options.

        The L2CAP options structure (struct l2cap_options) on Linux is:
            uint16_t omtu, imtu, flush_to;
            uint8_t  mode, fcs;
            uint8_t  max_tx;
            uint16_t txwin_size;

        We read the current options, patch imtu, and write back.
        """
        try:
            opts = sock.getsockopt(SOL_L2CAP, L2CAP_OPTIONS, 12)
            # Unpack: omtu(H) imtu(H) flush_to(H) mode(B) fcs(B) max_tx(B) pad(B) txwin_size(H)
            parts = list(struct.unpack("<HHHBBBBH", opts))
            parts[1] = mtu  # imtu
            sock.setsockopt(SOL_L2CAP, L2CAP_OPTIONS, struct.pack("<HHHBBBBH", *parts))
        except OSError:
            # Some kernels or socket states don't allow this; non-fatal
            warning(f"Could not set L2CAP MTU to {mtu} (kernel may not support it)")

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        return f"<L2CAPTransport addr={self.address} psm={self.psm} {state}>"


# ---------------------------------------------------------------------------
# RFCOMM transport
# ---------------------------------------------------------------------------

class RFCOMMTransport(BluetoothTransport):
    """Transport for Bluetooth RFCOMM connections.

    RFCOMM provides serial-port emulation over Bluetooth.  This transport
    uses SOCK_STREAM for reliable, ordered byte-stream delivery.

    Args:
        address: Target device BD_ADDR.
        channel: RFCOMM channel number (1-30).
        timeout: Socket timeout in seconds.
        max_reconnects: Maximum reconnection attempts on drop.
    """

    def __init__(
        self,
        address: str,
        channel: int = 1,
        timeout: float = 5.0,
        max_reconnects: int = 3,
    ) -> None:
        super().__init__(address, timeout, max_reconnects)
        self.channel = channel

    def _create_socket(self) -> socket.socket:
        """Create an RFCOMM stream socket."""
        return socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)

    def _connect_socket(self, sock: socket.socket) -> None:
        """Connect to the target's RFCOMM channel."""
        sock.connect((self.address, self.channel))

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        return f"<RFCOMMTransport addr={self.address} ch={self.channel} {state}>"


# ---------------------------------------------------------------------------
# BLE transport
# ---------------------------------------------------------------------------

class BLETransport(BluetoothTransport):
    """Transport for BLE (Bluetooth Low Energy) fixed-channel connections.

    Uses the Linux kernel's BLE L2CAP support to connect directly to
    fixed CIDs:

    - **ATT** (CID 0x0004): Attribute Protocol for GATT operations.
    - **SMP** (CID 0x0006): Security Manager Protocol for pairing.

    The kernel requires binding to the local adapter with the CID before
    connecting.  The remote address type (public vs. random) must be
    specified so the kernel uses the LE link layer rather than BR/EDR.

    Args:
        address: Target device BD_ADDR (may be a random address).
        cid: Fixed L2CAP channel ID.  Defaults to ATT (0x0004).
        address_type: Remote address type.  Use ``BDADDR_LE_PUBLIC`` (1)
            for public addresses or ``BDADDR_LE_RANDOM`` (2) for random.
        timeout: Socket timeout in seconds.
        max_reconnects: Maximum reconnection attempts on drop.
        security_level: BLE security level (1=low, 2=medium, 3=high).
    """

    ATT_CID = 0x0004
    SMP_CID = 0x0006

    def __init__(
        self,
        address: str,
        cid: int = ATT_CID,
        address_type: int = BDADDR_LE_PUBLIC,
        local_address: str | None = None,
        timeout: float = 15.0,
        max_reconnects: int = 3,
        security_level: int = 1,
    ) -> None:
        super().__init__(address, timeout, max_reconnects)
        self.cid = cid
        self.address_type = address_type
        self.local_address = local_address or "00:00:00:00:00:00"
        self.security_level = security_level

    @staticmethod
    def _mac_to_bytes(mac: str) -> bytes:
        """Convert MAC string to bytes in reversed (little-endian) order."""
        return bytes(reversed([int(x, 16) for x in mac.split(":")]))

    @staticmethod
    def _make_sockaddr_l2(bdaddr_str: str, psm: int, cid: int, bdaddr_type: int) -> bytes:
        """Build a raw ``sockaddr_l2`` struct for BLE L2CAP.

        Layout: uint16 family, uint16 psm, bdaddr[6], uint16 cid, uint8 bdaddr_type
        """
        bdaddr = BLETransport._mac_to_bytes(bdaddr_str)
        return struct.pack("<HH6sHB", AF_BLUETOOTH, psm, bdaddr, cid, bdaddr_type)

    # Cache detected address types to avoid repeated probes
    _addr_type_cache: dict[str, int] = {}

    @staticmethod
    def _detect_address_type(address: str) -> int:
        """Auto-detect BLE address type by attempting a quick connection.

        Tries PUBLIC first, then falls back to RANDOM.  Results are
        cached so the probe only runs once per address.
        """
        if address in BLETransport._addr_type_cache:
            return BLETransport._addr_type_cache[address]

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        for addr_type in (BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM):
            try:
                sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
                fd = sock.fileno()
                bind_addr = BLETransport._make_sockaddr_l2(
                    "00:00:00:00:00:00", 0, 0x0004, BDADDR_LE_PUBLIC
                )
                libc.bind(fd, bind_addr, len(bind_addr))

                old_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, old_flags | os.O_NONBLOCK)

                conn_addr = BLETransport._make_sockaddr_l2(address, 0, 0x0004, addr_type)
                ret = libc.connect(fd, conn_addr, len(conn_addr))
                errno_val = ctypes.get_errno()

                if ret != 0 and errno_val == 115:  # EINPROGRESS
                    _, writable, _ = select.select([], [sock], [], 5)
                    if writable:
                        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if err == 0:
                            sock.close()
                            # Wait for device to accept new connections
                            time.sleep(1)
                            BLETransport._addr_type_cache[address] = addr_type
                            return addr_type
                elif ret == 0:
                    sock.close()
                    time.sleep(1)
                    BLETransport._addr_type_cache[address] = addr_type
                    return addr_type
                sock.close()
            except OSError:
                try:
                    sock.close()
                except Exception:
                    pass

        # Fallback to bit-based heuristic
        first_octet = int(address.split(":")[0], 16)
        result = BDADDR_LE_RANDOM if first_octet & 0x40 else BDADDR_LE_PUBLIC
        BLETransport._addr_type_cache[address] = result
        return result

    def _create_socket(self) -> socket.socket:
        """Create a BLE L2CAP socket with security and CID configuration.

        Uses raw ctypes bind to construct a proper ``sockaddr_l2`` with
        BLE address type, since Python 3.13+ does not support the 3-tuple
        L2CAP address format natively.
        """
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)

        # Bind to local adapter with CID using raw sockaddr_l2.
        # Some CIDs (like SMP 0x0006) can't be bound directly — fall back to
        # binding with the target CID in the connect address instead.
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        bind_addr = self._make_sockaddr_l2(
            self.local_address, 0, self.cid, BDADDR_LE_PUBLIC
        )
        ret = libc.bind(sock.fileno(), bind_addr, len(bind_addr))
        if ret != 0:
            # Retry with CID=0 (let kernel pick) - needed for SMP
            bind_addr = self._make_sockaddr_l2(
                self.local_address, 0, 0, BDADDR_LE_PUBLIC
            )
            ret = libc.bind(sock.fileno(), bind_addr, len(bind_addr))
            if ret != 0:
                errno = ctypes.get_errno()
                warning(f"BLE bind to CID {self.cid:#06x} failed: errno={errno} ({os.strerror(errno)})")

        # Set BLE security level
        try:
            sec_struct = struct.pack("<BBH", self.security_level, 0, 0)
            sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, sec_struct)
        except OSError:
            warning("Could not set BLE security level (kernel may not support it)")

        return sock

    def _connect_socket(self, sock: socket.socket) -> None:
        """Connect to the BLE device using raw ctypes for proper LE addressing.

        Python 3.13+ does not support the 3-tuple ``(address, address_type, cid)``
        for BLE L2CAP.  We use ctypes to call ``connect()`` directly with a
        properly structured ``sockaddr_l2`` that includes the BLE address type.
        """
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        conn_addr = self._make_sockaddr_l2(
            self.address, 0, self.cid, self.address_type
        )

        # Use non-blocking connect + select for timeout control
        fd = sock.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        ret = libc.connect(fd, conn_addr, len(conn_addr))
        errno = ctypes.get_errno()

        if ret != 0 and errno == 115:  # EINPROGRESS
            _, writable, _ = select.select([], [sock], [], self.timeout)
            if writable:
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err != 0:
                    raise OSError(err, os.strerror(err))
            else:
                raise OSError("BLE connect timed out")
        elif ret != 0:
            raise OSError(errno, os.strerror(errno))

        # Restore blocking mode
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)

    def is_alive(self) -> bool:
        """Check BLE device reachability.

        BLE devices do not respond to classic l2ping.  Instead, attempt
        a quick ATT connection as a health check.  Returns True if the
        connection succeeds within the timeout.
        """
        probe_sock = None
        try:
            probe_sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

            bind_addr = self._make_sockaddr_l2(
                "00:00:00:00:00:00", 0, self.ATT_CID, BDADDR_LE_PUBLIC
            )
            libc.bind(probe_sock.fileno(), bind_addr, len(bind_addr))

            fd = probe_sock.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            conn_addr = self._make_sockaddr_l2(
                self.address, 0, self.ATT_CID, self.address_type
            )
            ret = libc.connect(fd, conn_addr, len(conn_addr))
            errno_val = ctypes.get_errno()

            if ret != 0 and errno_val == 115:  # EINPROGRESS
                _, writable, _ = select.select([], [probe_sock], [], 3.0)
                if writable:
                    err = probe_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    return err == 0
                return False
            return ret == 0
        except OSError:
            return False
        finally:
            if probe_sock is not None:
                try:
                    probe_sock.close()
                except OSError:
                    pass

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        cid_name = {self.ATT_CID: "ATT", self.SMP_CID: "SMP"}.get(self.cid, f"0x{self.cid:04x}")
        return f"<BLETransport addr={self.address} cid={cid_name} {state}>"


# ---------------------------------------------------------------------------
# LMP transport (DarkFirmware RTL8761B)
# ---------------------------------------------------------------------------

class LMPTransport(BluetoothTransport):
    """Transport for LMP (Link Manager Protocol) via DarkFirmware RTL8761B.

    Sends and receives LMP packets below the HCI layer using vendor-specific
    HCI commands on a DarkFirmware-patched RTL8761B adapter.  Unlike other
    transports, LMPTransport does NOT create the Bluetooth connection -- it
    requires a pre-existing ACL link to the target device.

    The underlying DarkFirmware hooks:
      - VSC 0xFE22: Copies payload into LMP buffer, sends via send_LMP_reply()
      - LMP RX Hook: Incoming LMP packets logged as HCI Event 0xFF

    Limitations:
      - Max 17 bytes per LMP PDU (UB500 firmware patched to 0x11 via patch_send_length())
      - Only operates on connection index 0 (first ACL connection after reset)
      - LMP RX data only available for opcode path 0x0480

    Args:
        address: Target BD_ADDR (used for ACL connection verification).
        hci_dev: HCI device index for the DarkFirmware adapter (default 1).
        timeout: Timeout in seconds for send/recv operations.
        max_reconnects: Max reconnect attempts (reconnect re-verifies ACL link).
    """

    def __init__(
        self,
        address: str,
        hci_dev: int = 1,
        timeout: float = 5.0,
        max_reconnects: int = 3,
    ) -> None:
        super().__init__(address, timeout, max_reconnects)
        self.hci_dev = hci_dev
        self._hci_vsc = None  # Will hold HCIVSCSocket instance
        self._rx_queue: collections.deque | None = None
        self._connection_handle: int | None = None

    # -- Abstract interface (placeholders -- real work is in connect()) ----

    def _create_socket(self) -> socket.socket:
        """Not used — LMPTransport overrides connect() to use HCI VSC."""
        raise NotImplementedError(
            "LMPTransport does not use a regular socket. "
            "Use connect() which opens an HCI VSC socket instead."
        )

    def _connect_socket(self, sock: socket.socket) -> None:
        """Not used — LMPTransport overrides connect() to use HCI VSC."""
        raise NotImplementedError(
            "LMPTransport does not use a regular socket. "
            "Use connect() which opens an HCI VSC socket instead."
        )

    # -- Connection management ---------------------------------------------

    def connect(self) -> bool:
        """Open HCI VSC socket and verify ACL connection to target.

        The ACL connection must already exist (e.g., established via
        bluetoothctl or by the fuzzing engine through an L2CAP probe).
        """
        try:
            self.close()

            from blue_tap.hardware.firmware import DarkFirmwareManager
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            fw = DarkFirmwareManager()
            if not fw.is_darkfirmware_loaded(f"hci{self.hci_dev}"):
                error(f"DarkFirmware not loaded on hci{self.hci_dev} — LMP fuzzing requires RTL8761B firmware hooks")
                return False

            self._hci_vsc = HCIVSCSocket(self.hci_dev)
            self._hci_vsc.open()
            self._rx_queue = collections.deque(maxlen=1000)

            # Verify ACL connection exists
            handle = self._find_acl_handle()
            if handle is None:
                warning(
                    f"No ACL connection to {self.address} found. "
                    f"LMP injection requires an existing connection."
                )
                # Try to establish one via L2CAP SDP probe
                if not self._establish_acl():
                    error("Could not establish ACL connection for LMP transport")
                    self.close()
                    return False
                handle = self._find_acl_handle()
                if handle is None:
                    self.close()
                    return False

            self._connection_handle = handle
            info(f"LMP transport connected (ACL handle={handle:#06x})")

            # Start LMP monitor
            self._hci_vsc.start_lmp_monitor(self._on_lmp_received)
            self._connected = True
            return True
        except OSError as exc:
            error(f"LMP connect failed: {exc}")
            self.stats.errors += 1
            self._connected = False
            self.close()
            return False

    def _find_acl_handle(self) -> int | None:
        """Parse ``hcitool con`` to find ACL connection handle for target."""
        result = run_cmd(
            ["hcitool", "-i", f"hci{self.hci_dev}", "con"], timeout=5,
        )
        if result.returncode != 0:
            return None
        # Parse: "< ACL AA:BB:CC:DD:EE:FF handle 64 state 1 lm CENTRAL"
        for line in result.stdout.splitlines():
            if self.address.upper() in line.upper():
                m = re.search(r"handle\s+(\d+)", line)
                if m:
                    return int(m.group(1))
        return None

    def _establish_acl(self) -> bool:
        """Try to establish ACL connection via L2CAP SDP probe."""
        info(f"Establishing ACL via SDP probe to {self.address}")
        probe = socket.socket(
            AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP,
        )
        try:
            probe.settimeout(5.0)
            probe.connect((self.address, 1))  # PSM 1 = SDP
            time.sleep(0.5)
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def _on_lmp_received(self, lmp_log: dict) -> None:
        """Callback from LMP monitor thread -- push to receive queue."""
        if self._rx_queue is not None:
            self._rx_queue.append(lmp_log)

    # -- Data transfer -----------------------------------------------------

    def send(self, data: bytes) -> int:
        """Send LMP packet via DarkFirmware VSC 0xFE22."""
        if self._hci_vsc is None or not self._connected:
            if not self.reconnect():
                raise ConnectionError("Not connected and reconnect failed")
        try:
            ok = self._hci_vsc.send_lmp(data)
            if ok:
                self.stats.bytes_sent += len(data)
                self.stats.packets_sent += 1
                return len(data)
            warning(f"LMP send returned failure for {len(data)} bytes")
            self.stats.errors += 1
            return 0
        except OSError as exc:
            self.stats.errors += 1
            error(f"LMP send error: {exc}")
            return 0

    def recv(self, bufsize: int = 4096, recv_timeout: float | None = None) -> bytes | None:
        """Receive LMP packet from monitor queue."""
        if self._rx_queue is None or not self._connected:
            return None
        timeout = recv_timeout if recv_timeout is not None else self.timeout
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._rx_queue:
                log_entry = self._rx_queue.popleft()
                payload = log_entry.get("payload", b"")
                if payload:
                    self.stats.bytes_received += len(payload)
                    self.stats.packets_received += 1
                    return payload
            time.sleep(0.05)  # Brief poll interval
        return b""  # Timeout

    # -- Lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Stop LMP monitor and close HCI VSC socket."""
        info(f"Closing LMP transport to {self.address}")
        self._connected = False
        if self._hci_vsc is not None:
            try:
                self._hci_vsc.stop_lmp_monitor()
                self._hci_vsc.close()
            except OSError:
                pass
            self._hci_vsc = None
        self._rx_queue = None
        # Close placeholder socket from base class
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def send_and_collect(self, data: bytes, response_timeout: float = 0.5) -> tuple[int, list[dict]]:
        """Send LMP packet and collect responses for response_timeout seconds.

        Clears the receive queue, sends the packet, then waits up to
        *response_timeout* for LMP log events to arrive via the monitor
        thread.

        Returns:
            (bytes_sent, list_of_response_log_dicts) where each dict has
            keys like 'direction', 'type', 'lmp_opcode_decoded', 'payload', etc.
        """
        # Clear rx_queue before sending
        if self._rx_queue is not None:
            self._rx_queue.clear()

        sent = self.send(data)

        # Wait for responses to arrive via the monitor thread
        time.sleep(response_timeout)

        # Drain all log dicts from rx_queue (populated by _on_lmp_received callback)
        log_responses: list[dict] = []
        if self._rx_queue:
            while self._rx_queue:
                log_responses.append(self._rx_queue.popleft())

        # Also grab any logs from the HCI socket's buffer that the callback
        # may not have caught (e.g., if they arrived between queue clears)
        if self._hci_vsc is not None:
            for entry in list(self._hci_vsc.lmp_log_buffer):
                if entry not in log_responses:
                    log_responses.append(entry)

        return sent, log_responses

    def check_alive(self) -> bool:
        """Check if the DarkFirmware dongle is still responsive.

        Sends a basic HCI Read BD Addr and checks for a response.
        If no response within 2s, the controller may have crashed.
        """
        if self._hci_vsc is None:
            return False
        try:
            # HCI Read BD Addr: OGF=0x04 OCF=0x0009 => opcode 0x1009
            result = self._hci_vsc.send_vsc(0x1009, b"", timeout=2.0)
            return len(result) > 0 and result[0] == 0x00
        except (OSError, TimeoutError):
            return False

    def is_alive(self) -> bool:
        """Check ACL connection still exists (not l2ping -- LMP is below L2CAP)."""
        return self._find_acl_handle() is not None

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        handle = (
            f" handle={self._connection_handle:#06x}"
            if self._connection_handle
            else ""
        )
        return f"<LMPTransport addr={self.address} hci{self.hci_dev}{handle} {state}>"


class RawACLTransport(BluetoothTransport):
    """Transport for below-stack L2CAP injection via DarkFirmware.

    Sends raw HCI ACL data packets directly to the Bluetooth controller,
    bypassing BlueZ's L2CAP stack entirely.  The controller encrypts and
    transmits whatever payload is provided — no L2CAP validation occurs.

    This enables injection of malformed L2CAP frames that BlueZ would
    normally drop before they leave the host (truncated headers, invalid
    CIDs, oversized payloads, etc.).

    Combined with DarkFirmware's Hook 3 (ACLX marker) and Hook 4 (RXLC
    marker), both sent and received ACL data are logged.

    Requires:
      - DarkFirmware loaded on the adapter
      - An existing ACL connection to the target (provides the handle)
      - Root or CAP_NET_RAW for raw HCI socket access

    Args:
        address:  Target BD_ADDR.
        hci_dev:  HCI device index for the DarkFirmware adapter.
        timeout:  Timeout for connection verification.
        max_reconnects: Max reconnect attempts.
    """

    def __init__(
        self,
        address: str,
        hci_dev: int = 1,
        timeout: float = 5.0,
        max_reconnects: int = 3,
    ) -> None:
        super().__init__(address, timeout=timeout, max_reconnects=max_reconnects)
        self.hci_dev = hci_dev
        self._hci_vsc = None
        self._connection_handle: int | None = None
        self._rx_queue: collections.deque | None = None

    def _create_socket(self) -> socket.socket:
        """Not used — RawACLTransport overrides connect() to use HCI VSC."""
        raise NotImplementedError(
            "RawACLTransport does not use a regular socket. "
            "Use connect() which opens an HCI VSC socket instead."
        )

    def _connect_socket(self, sock: socket.socket) -> None:
        """Not used — RawACLTransport overrides connect() to use HCI VSC."""
        raise NotImplementedError(
            "RawACLTransport does not use a regular socket. "
            "Use connect() which opens an HCI VSC socket instead."
        )

    def connect(self) -> bool:
        """Open HCI VSC socket and find the ACL connection handle."""
        from blue_tap.hardware.firmware import DarkFirmwareManager
        from blue_tap.hardware.hci_vsc import HCIVSCSocket

        fw = DarkFirmwareManager()
        if not fw.is_darkfirmware_loaded(f"hci{self.hci_dev}"):
            error(
                f"DarkFirmware not loaded on hci{self.hci_dev} — raw ACL injection "
                "requires RTL8761B firmware hooks"
            )
            return False

        try:
            self._hci_vsc = HCIVSCSocket(hci_dev=self.hci_dev)
            self._hci_vsc.open()
        except OSError as exc:
            error(f"Cannot open HCI socket on hci{self.hci_dev}: {exc}")
            return False

        # Find ACL handle for the target
        self._connection_handle = self._find_acl_handle()
        if self._connection_handle is None:
            # Try to establish ACL via a quick L2CAP SDP probe
            self._establish_acl()
            self._connection_handle = self._find_acl_handle()

        if self._connection_handle is None:
            warning(f"No ACL connection to {self.address} — raw ACL injection requires an active link")
            return False

        # Start monitor for Hook 3/4 events (ACLX, RXLC)
        self._rx_queue = collections.deque(maxlen=1000)
        self._hci_vsc.start_lmp_monitor(lambda evt: self._rx_queue.append(evt))

        self._connected = True
        info(
            f"RawACL transport ready: {self.address} "
            f"handle=0x{self._connection_handle:04X} hci{self.hci_dev}"
        )
        return True

    def _find_acl_handle(self) -> int | None:
        """Parse hcitool con for the ACL handle to target."""
        result = run_cmd(["hcitool", "-i", f"hci{self.hci_dev}", "con"])
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if self.address.upper() in line.upper():
                m = re.search(r"handle\s+(\d+)", line)
                if m:
                    return int(m.group(1))
        return None

    def _establish_acl(self) -> bool:
        """Quick L2CAP SDP probe to establish ACL link."""
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        try:
            s.settimeout(5.0)
            s.connect((self.address, 1))  # SDP PSM
            time.sleep(0.5)
            return True
        except OSError:
            return False
        finally:
            s.close()

    def send(self, data: bytes) -> int:
        """Send raw ACL data (L2CAP frame) via DarkFirmware.

        The *data* parameter should be a complete L2CAP frame:
        [length:2B LE] [CID:2B LE] [payload...].
        """
        if self._hci_vsc is None or not self._connected:
            if not self.reconnect():
                raise ConnectionError("Not connected and reconnect failed")
        if self._connection_handle is None:
            error("No ACL handle — cannot send raw ACL")
            return 0
        try:
            ok = self._hci_vsc.send_raw_acl(self._connection_handle, data)
            if ok:
                self.stats.bytes_sent += len(data)
                self.stats.packets_sent += 1
                return len(data)
            self.stats.errors += 1
            return 0
        except OSError as exc:
            self.stats.errors += 1
            error(f"Raw ACL send error: {exc}")
            return 0

    def recv(self, bufsize: int = 4096, recv_timeout: float | None = None) -> bytes | None:
        """Receive ACL/LC log events from DarkFirmware hooks."""
        if self._rx_queue is None or not self._connected:
            return None
        timeout = recv_timeout if recv_timeout is not None else self.timeout
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._rx_queue:
                log_entry = self._rx_queue.popleft()
                raw = log_entry.get("raw", b"")
                if raw:
                    self.stats.bytes_received += len(raw)
                    self.stats.packets_received += 1
                    return raw
            time.sleep(0.05)
        return b""

    def close(self) -> None:
        """Stop monitor and close HCI socket."""
        info(f"Closing RawACL transport to {self.address}")
        self._connected = False
        if self._hci_vsc is not None:
            try:
                self._hci_vsc.stop_lmp_monitor()
                self._hci_vsc.close()
            except OSError:
                pass
            self._hci_vsc = None
        self._rx_queue = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def is_alive(self) -> bool:
        """Check ACL connection still exists."""
        return self._find_acl_handle() is not None

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        handle = f" handle=0x{self._connection_handle:04X}" if self._connection_handle else ""
        return f"<RawACLTransport addr={self.address} hci{self.hci_dev}{handle} {state}>"


# ---------------------------------------------------------------------------
# Native Module class (replaces modules/fuzzing/modules/transport.py wrapper)
# ---------------------------------------------------------------------------

from blue_tap.framework.contracts.result_schema import (  # noqa: E402
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext  # noqa: E402
from blue_tap.framework.module.options import (  # noqa: E402
    OptAddress,
    OptBool,
    OptFloat,
    OptInt,
    OptString,
)
from blue_tap.framework.registry import ModuleFamily  # noqa: E402

_TRANSPORT_TYPES = ("l2cap", "rfcomm", "ble", "raw_acl")


class FuzzTransportModule(Module):
    """Fuzz Transport.

    Bluetooth transport abstractions for L2CAP, RFCOMM, BLE, and raw ACL fuzzing.
    Use this module to test transport connectivity before running a full campaign.
    """

    module_id = "fuzzing.transport"
    family = ModuleFamily.FUZZING
    name = "Fuzz Transport"
    description = "Fuzz transport: L2CAP, RFCOMM, BLE ATT/SMP, and raw ACL"
    protocols = ("Classic", "BLE", "L2CAP", "RFCOMM", "ATT", "SMP", "LMP")
    requires = ("adapter", "target")
    destructive = True
    requires_pairing = False
    schema_prefix = "blue_tap.fuzz.result"
    has_report_adapter = False
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target Bluetooth address"),
        OptString("TYPE", default="l2cap", description=f"Transport type ({', '.join(_TRANSPORT_TYPES)})"),
        OptInt("PSM", default=1, description="L2CAP PSM (for l2cap transport)"),
        OptInt("CHANNEL", default=1, description="RFCOMM channel (for rfcomm transport)"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptFloat("TIMEOUT", default=5.0, description="Connection timeout in seconds"),
        OptBool("TEST_SEND", default=True, description="Send test payload to verify connectivity"),
    )

    def run(self, ctx: RunContext) -> dict:
        """Test transport connectivity."""
        import logging as _logging

        _log = _logging.getLogger(__name__)

        target = ctx.options.get("RHOST", "")
        transport_type = ctx.options.get("TYPE", "l2cap").lower()
        psm = ctx.options.get("PSM", 1)
        channel = ctx.options.get("CHANNEL", 1)
        hci = ctx.options.get("HCI", "")
        timeout = ctx.options.get("TIMEOUT", 5.0)
        test_send = ctx.options.get("TEST_SEND", True)
        started_at = ctx.started_at

        if transport_type == "l2cap":
            transport = L2CAPTransport(target, psm=psm, timeout=timeout)
        elif transport_type == "rfcomm":
            transport = RFCOMMTransport(target, channel=channel, timeout=timeout)
        elif transport_type == "ble":
            transport = BLETransport(
                target,
                address_type=BLETransport._detect_address_type(target),
                timeout=timeout,
            )
        elif transport_type == "raw_acl":
            hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0
            transport = RawACLTransport(target, hci_dev=hci_idx, timeout=timeout)
        else:
            return build_run_envelope(
                schema=self.schema_prefix,
                module=self.module_id,
                                module_id=self.module_id,
                target=target,
                adapter=hci,
                started_at=started_at,
                executions=[make_execution(
                    execution_id="transport_test",
                    kind="probe",
                    id="transport_test",
                    title="Transport Test",
                    module=self.module_id,
                    module_id=self.module_id,
                    protocol=transport_type,
                    execution_status="failed",
                    module_outcome="not_applicable",
                    evidence=make_evidence(
                        raw={"error": f"Unknown transport type: {transport_type}"},
                        summary=f"Unknown transport type: {transport_type}",
                    ),
                    destructive=False,
                    requires_pairing=False,
                )],
                summary={"outcome": "not_applicable", "error": f"Unknown transport: {transport_type}"},
                module_data={"error": f"Unknown transport type: {transport_type}"},
                run_id=ctx.run_id,
            )

        connected = False
        sent = False
        result: dict = {}

        try:
            connected = transport.connect()
            if connected and test_send:
                try:
                    transport.send(b"\x00" * 4)
                    sent = True
                except Exception as e:
                    _log.warning("Test send failed: %s", e)
                    result["send_error"] = str(e)
        except Exception as e:
            _log.exception("Transport connection failed: %s", e)
            result["connect_error"] = str(e)
        finally:
            try:
                transport.close()
            except Exception:
                pass

        # Fuzzing family outcomes: crash_found, timeout, corpus_grown,
        # no_findings (canonical) plus legacy completed/not_applicable. The
        # transport probe itself is a no-crash reachability check — successful
        # connect is "no_findings", failed connect is "not_applicable".
        outcome = "no_findings" if connected else "not_applicable"
        exec_status = "completed" if connected else "failed"

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            module_id=self.module_id,
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[make_execution(
                execution_id="transport_test",
                kind="probe",
                id="transport_test",
                title=f"Transport Test ({transport_type})",
                module=self.module_id,
                module_id=self.module_id,
                protocol=transport_type,
                execution_status=exec_status,
                module_outcome=outcome,
                evidence=make_evidence(
                    raw={"connected": connected, "sent": sent, "type": transport_type},
                    summary=f"Transport {transport_type}: {'connected' if connected else 'failed'}",
                ),
                destructive=True,
                requires_pairing=False,
            )],
            summary={"outcome": outcome, "connected": connected, "sent": sent, "type": transport_type},
            module_data={**result, "connected": connected, "sent": sent},
            run_id=ctx.run_id,
        )
