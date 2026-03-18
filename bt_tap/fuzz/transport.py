"""Bluetooth transport abstraction layer for fuzzing.

Provides unified socket wrappers for L2CAP, RFCOMM, and BLE connections
with automatic reconnect, timeout handling, health checks, and statistics
tracking.  Every transport follows the same connect/send/recv/close interface
so the fuzzing engine can target any Bluetooth layer without caring about
the underlying socket type.
"""

from __future__ import annotations

import socket
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.utils.output import info, warning, error

# ---------------------------------------------------------------------------
# Bluetooth socket constants (from <bluetooth/bluetooth.h>)
# ---------------------------------------------------------------------------
AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3
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
        self._sock: Optional[socket.socket] = None
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

        try:
            sent = self._sock.send(data)  # type: ignore[union-attr]
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

    def recv(self, bufsize: int = 4096, recv_timeout: Optional[float] = None) -> Optional[bytes]:
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
        except socket.timeout:
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

    def __enter__(self) -> "BluetoothTransport":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        return f"<{self.__class__.__name__} addr={self.address} {state}>"


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
        mtu: Optional[int] = None,
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
        timeout: float = 5.0,
        max_reconnects: int = 3,
        security_level: int = 1,
    ) -> None:
        super().__init__(address, timeout, max_reconnects)
        self.cid = cid
        self.address_type = address_type
        self.security_level = security_level

    def _create_socket(self) -> socket.socket:
        """Create a BLE L2CAP socket with security and CID configuration.

        Binds to the local adapter with the target CID and sets the
        BLE security level via ``BT_SECURITY`` socket option.
        """
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)

        # Bind to local adapter with CID.
        # For BLE L2CAP the bind address is: (bdaddr, addr_type, cid)
        # Some kernels accept the 2-tuple; we try the 3-tuple first.
        try:
            sock.bind(("00:00:00:00:00:00", BDADDR_LE_PUBLIC, self.cid))
        except TypeError:
            # Older kernel/PyBluez: fall back to 2-tuple bind with CID
            try:
                sock.bind(("", self.cid))
            except OSError as exc:
                warning(f"BLE bind to CID {self.cid:#06x} failed: {exc}")

        # Set BLE security level
        # struct bt_security { uint8_t level; uint8_t key_size; }
        # Padded to 4 bytes on most kernels.
        try:
            sec_struct = struct.pack("<BBH", self.security_level, 0, 0)
            sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, sec_struct)
        except OSError:
            warning("Could not set BLE security level (kernel may not support it)")

        return sock

    def _connect_socket(self, sock: socket.socket) -> None:
        """Connect to the BLE device using the LE address type.

        The kernel expects a 3-tuple ``(address, address_type, cid)`` for
        BLE L2CAP connections.  Falls back to 2-tuple if the kernel does
        not support the extended form.
        """
        try:
            sock.connect((self.address, self.address_type, self.cid))
        except TypeError:
            # Fallback: some kernel builds only accept (address, psm)
            # where psm doubles as CID for fixed channels
            sock.connect((self.address, self.cid))

    def is_alive(self) -> bool:
        """Check BLE device reachability.

        BLE devices do not respond to classic l2ping.  Instead, attempt
        a quick ATT connection as a health check.  Returns True if the
        connection succeeds within the timeout.
        """
        probe_sock = None
        try:
            probe_sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            probe_sock.settimeout(3.0)
            try:
                probe_sock.bind(("00:00:00:00:00:00", BDADDR_LE_PUBLIC, self.ATT_CID))
            except TypeError:
                probe_sock.bind(("", self.ATT_CID))
            try:
                probe_sock.connect((self.address, self.address_type, self.ATT_CID))
            except TypeError:
                probe_sock.connect((self.address, self.ATT_CID))
            return True
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
