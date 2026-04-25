"""Raw HCI socket interface for DarkFirmware vendor-specific commands.

Provides low-level access to the RTL8761B (TP-Link UB500, USB 2357:0604) running
DarkFirmware custom firmware.  Supports three vendor-specific commands:

  - VSC 0xFE22: Inject arbitrary LMP packets into a live connection
  - VSC 0xFC61: Read 32-bit-aligned memory from the Bluetooth controller
  - VSC 0xFC62: Write 32-bit-aligned memory on the Bluetooth controller

Additionally, the firmware hooks traffic at the Link Controller layer and
reports it as HCI Event 0xFF (vendor-specific) with structured logs:

  - Hook 2 (tLC_RX_LMP): Incoming LMP, 56-byte log with AAAA marker
  - Hook 3 (tLC_TX):      Outgoing LMP (12B, TXXX) and ACL (16B, ACLX)
  - Hook 4 (tLC_RX):      All incoming LC frames (14B, RXLC)

The parser functions :func:`parse_lmp_log`, :func:`parse_lmp_tx_log`,
:func:`parse_acl_tx_log`, and :func:`parse_rxlc_log` decode these logs.
:meth:`HCIVSCSocket.start_lmp_monitor` runs a background thread to capture
them continuously.

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
# LMP opcode lookup tables (ported from DarkFirmware lmp_monitor.py)
# ---------------------------------------------------------------------------

# Complete LMP opcode table per Bluetooth Core Spec v5.4, Vol 2 Part C Section 4
LMP_OPCODES = {
    0x01: "LMP_NAME_REQ", 0x02: "LMP_NAME_RES", 0x03: "LMP_ACCEPTED",
    0x04: "LMP_NOT_ACCEPTED", 0x05: "LMP_CLKOFFSET_REQ", 0x06: "LMP_CLKOFFSET_RES",
    0x07: "LMP_DETACH", 0x08: "LMP_IN_RAND", 0x09: "LMP_COMB_KEY",
    0x0A: "LMP_UNIT_KEY", 0x0B: "LMP_AU_RAND", 0x0C: "LMP_SRES",
    0x0D: "LMP_TEMP_RAND", 0x0E: "LMP_TEMP_KEY",
    0x0F: "LMP_ENCRYPTION_MODE_REQ", 0x10: "LMP_ENCRYPTION_KEY_SIZE_REQ",
    0x11: "LMP_START_ENCRYPTION_REQ", 0x12: "LMP_STOP_ENCRYPTION_REQ",
    0x13: "LMP_SWITCH_REQ", 0x14: "LMP_HOLD", 0x15: "LMP_HOLD_REQ",
    0x16: "LMP_SNIFF", 0x17: "LMP_SNIFF_REQ", 0x18: "LMP_UNSNIFF_REQ",
    0x19: "LMP_PARK_REQ", 0x1B: "LMP_SET_BROADCAST_SCAN_WINDOW",
    0x1C: "LMP_MODIFY_BEACON", 0x1D: "LMP_SETUP_COMPLETE",
    0x1E: "LMP_USE_SEMI_PERMANENT_KEY", 0x1F: "LMP_MAX_SLOT",
    0x20: "LMP_MAX_SLOT_REQ", 0x21: "LMP_TIMING_ACCURACY_REQ",
    0x22: "LMP_TIMING_ACCURACY_RES", 0x23: "LMP_DETACH_TEMP_KEY",
    0x24: "LMP_SLOT_OFFSET", 0x25: "LMP_VERSION_REQ",
    0x26: "LMP_VERSION_RES", 0x27: "LMP_FEATURES_REQ",
    0x28: "LMP_FEATURES_RES", 0x29: "LMP_CLKADDR",
    0x2A: "LMP_CHANNEL_CLASSIFICATION_REQ",
    0x2B: "LMP_QUALITY_OF_SERVICE", 0x2C: "LMP_QUALITY_OF_SERVICE_REQ",
    0x2D: "LMP_SCO_LINK_REQ", 0x2E: "LMP_REMOVE_SCO_LINK_REQ",
    0x2F: "LMP_MAX_POWER", 0x30: "LMP_MIN_POWER",
    0x31: "LMP_PAGE_MODE_REQ", 0x32: "LMP_PAGE_SCAN_MODE_REQ",
    0x33: "LMP_SUPERVISION_TIMEOUT",
    0x34: "LMP_TEST_ACTIVATE", 0x35: "LMP_TEST_CONTROL",
    0x36: "LMP_ENCRYPTION_KEY_SIZE_MASK_REQ",
    0x37: "LMP_ENCRYPTION_KEY_SIZE_MASK_RES",
    0x38: "LMP_SET_AFH", 0x39: "LMP_ENCAPSULATED_HEADER",
    0x3A: "LMP_ENCAPSULATED_PAYLOAD", 0x3B: "LMP_SIMPLE_PAIRING_CONFIRM",
    0x3C: "LMP_SIMPLE_PAIRING_NUMBER", 0x3D: "LMP_DHKEY_CHECK",
    0x7F: "LMP_ESCAPE_4",
}

# Extended opcodes (via LMP_ESCAPE_4 prefix 0x7F)
LMP_EXT_OPCODES = {
    0x01: "EXT_ACCEPTED", 0x02: "EXT_NOT_ACCEPTED",
    0x03: "EXT_FEATURES_REQ", 0x04: "EXT_FEATURES_RES",
    0x05: "EXT_PACKET_TYPE_TABLE_REQ",
    0x06: "EXT_ESCO_LINK_REQ", 0x07: "EXT_REMOVE_ESCO_LINK_REQ",
    0x08: "EXT_CHANNEL_CLASSIFICATION_REQ",
    0x09: "EXT_CHANNEL_CLASSIFICATION",
    0x0B: "EXT_IO_CAPABILITY_REQ", 0x0C: "EXT_IO_CAPABILITY_RES",
    0x0D: "EXT_NUMERIC_COMPARISON_FAILED", 0x0E: "EXT_PASSKEY_FAILED",
    0x0F: "EXT_OOB_FAILED", 0x10: "EXT_KEYPRESS_NOTIFICATION",
    0x11: "EXT_POWER_CONTROL_REQ", 0x12: "EXT_POWER_CONTROL_RES",
    0x13: "EXT_SAM_SET_TYPE0", 0x14: "EXT_SAM_DEFINE_MAP",
    0x15: "EXT_SAM_SWITCH",
    0x17: "EXT_PING_REQ", 0x18: "EXT_PING_RES",
}


def decode_lmp_opcode(opcode: int, ext_opcode: int | None = None) -> str:
    """Decode LMP opcode to human-readable name.

    Args:
        opcode: Primary LMP opcode (7-bit).
        ext_opcode: Extended opcode when primary is 0x7F (LMP_ESCAPE_4).

    Returns:
        Human-readable opcode name, or ``"UNKNOWN(0xNN)"`` if not recognised.
    """
    if opcode == 0x7F and ext_opcode is not None:
        return LMP_EXT_OPCODES.get(ext_opcode, f"EXT_UNKNOWN(0x{ext_opcode:02x})")
    return LMP_OPCODES.get(opcode, f"UNKNOWN(0x{opcode:02x})")


# ---------------------------------------------------------------------------
# Standalone parsers
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
        "direction": "RX",
        "type": "lmp",
        "opcode": opcode,
        "payload": payload,
        "has_data": has_data,
        "raw": event_params,
        "a0_ptr": a0_ptr,
        "data_buf_ptr": data_buf_ptr,
    }


def parse_lmp_tx_log(event_params: bytes) -> dict | None:
    """Parse a 12-byte DarkFirmware LMP TX log from HCI Event 0xFF (Hook 3).

    Format (12 bytes)::

        Offset  Size  Description
        ------  ----  -----------
        0x00    4     0x58585854 (TXXX marker)
        0x04    1     Connection index
        0x05    1     Encoded opcode: (opcode << 1) | TID
        0x06    5     LMP parameters
        0x0B    1     Length - 1 (firmware convention)

    Args:
        event_params: The parameter bytes from the HCI Event 0xFF packet.

    Returns:
        A dict with direction, type, connection index, decoded opcode, TID,
        params, length, and raw bytes, or *None* if not a valid LMP TX log.
    """
    if len(event_params) < HCIVSCSocket.LMP_TX_LOG_SIZE:
        return None

    marker = struct.unpack_from("<I", event_params, 0x00)[0]
    if marker != HCIVSCSocket.MARKER_TXXX:
        return None

    conn_idx = event_params[0x04]
    encoded_opcode = event_params[0x05]
    lmp_opcode = (encoded_opcode >> 1) & 0x7F
    tid = encoded_opcode & 0x01
    params = event_params[0x06:0x0B]
    length = event_params[0x0B] + 1  # firmware stores length-1

    return {
        "direction": "TX",
        "type": "lmp",
        "conn_index": conn_idx,
        "lmp_opcode_decoded": lmp_opcode,
        "tid": tid,
        "params": params,
        "length": length,
        "raw": event_params,
    }


def parse_start_encryption_req(lmp_payload: bytes) -> dict | None:
    """Extract EN_RAND from an ``LMP_start_encryption_req`` PDU.

    The PDU layout per BT Core Spec Vol 2 Part C §4.2.5 is::

        Byte 0     TID + opcode (opcode 0x11 = LMP_START_ENCRYPTION_REQ)
        Bytes 1-16 EN_RAND (128-bit random)

    This parser consumes the raw LMP payload as emitted by the DarkFirmware
    LMP monitor and returns the extracted EN_RAND plus metadata. Returns
    ``None`` when the payload is not a valid start_encryption_req.

    The extracted EN_RAND is one of the four inputs required to drive a
    real E0 cipher (``blue_tap.modules.exploitation._e0``) during KNOB
    key recovery — the others are K_C (the candidate), the master's
    BD_ADDR, and CLK26_1.

    Args:
        lmp_payload: LMP payload bytes (byte 0 = opcode+TID, rest = params).

    Returns:
        {"opcode": 0x11, "tid": int, "en_rand": bytes (16)} or None.
    """
    if len(lmp_payload) < 17:
        return None
    tid_opcode = lmp_payload[0]
    tid = (tid_opcode >> 7) & 1
    opcode = tid_opcode & 0x7F
    if opcode != 0x11:  # LMP_START_ENCRYPTION_REQ
        return None
    en_rand = lmp_payload[1:17]
    return {
        "opcode": opcode,
        "tid": tid,
        "en_rand": bytes(en_rand),
    }


def parse_acl_tx_log(event_params: bytes) -> dict | None:
    """Parse a 16-byte DarkFirmware ACL TX log from HCI Event 0xFF (Hook 3).

    Format (16 bytes)::

        Offset  Size  Description
        ------  ----  -----------
        0x00    4     0x584C4341 (ACLX marker)
        0x04    4     HCI handle + flags + data length (packed)
        0x08    8     First 8 bytes of ACL payload

    Args:
        event_params: The parameter bytes from the HCI Event 0xFF packet.

    Returns:
        A dict with direction, type, handle/flags, payload preview, and raw
        bytes, or *None* if not a valid ACL TX log.
    """
    if len(event_params) < HCIVSCSocket.LMP_ACL_LOG_SIZE:
        return None

    marker = struct.unpack_from("<I", event_params, 0x00)[0]
    if marker != HCIVSCSocket.MARKER_ACLX:
        return None

    handle_flags = struct.unpack_from("<I", event_params, 0x04)[0]
    payload_preview = event_params[0x08:0x10]

    return {
        "direction": "TX",
        "type": "acl",
        "handle_flags": handle_flags,
        "payload_preview": payload_preview,
        "raw": event_params,
    }


def parse_rxlc_log(event_params: bytes) -> dict | None:
    """Parse a 14-byte DarkFirmware RX Link Controller log from HCI Event 0xFF (Hook 4).

    Format (14 bytes)::

        Offset  Size  Description
        ------  ----  -----------
        0x00    4     0x434C5852 (RXLC marker)
        0x04    2     Message type (little-endian): 0x32E=LMP, 0x320=ACL, 0x32A=SCO
        0x06    4     First data word
        0x0A    4     Second data word

    Args:
        event_params: The parameter bytes from the HCI Event 0xFF packet.

    Returns:
        A dict with direction, resolved type, message_type, two data words,
        and raw bytes, or *None* if not a valid RXLC log.
    """
    if len(event_params) < HCIVSCSocket.LMP_RXLC_LOG_SIZE:
        return None

    marker = struct.unpack_from("<I", event_params, 0x00)[0]
    if marker != HCIVSCSocket.MARKER_RXLC:
        return None

    message_type = struct.unpack_from("<H", event_params, 0x04)[0]
    data_word1 = struct.unpack_from("<I", event_params, 0x06)[0]
    data_word2 = struct.unpack_from("<I", event_params, 0x0A)[0]

    # Resolve message type to a human-readable category
    _MSG_TYPE_MAP = {0x32E: "lmp", 0x320: "acl", 0x32A: "sco"}
    resolved_type = _MSG_TYPE_MAP.get(message_type, "unknown")

    return {
        "direction": "RX",
        "type": resolved_type,
        "message_type": message_type,
        "data_word1": data_word1,
        "data_word2": data_word2,
        "raw": event_params,
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

    # Hook 3 markers (tLC_TX) — outgoing packet logging
    MARKER_TXXX: int = 0x58585854   # Outgoing LMP packet
    MARKER_ACLX: int = 0x584C4341   # Outgoing ACL data

    # Hook 4 marker (tLC_RX) — incoming Link Controller logging
    MARKER_RXLC: int = 0x434C5852   # All incoming LC (LMP + BLE LL + ACL + SCO)

    LMP_LOG_SIZE: int = 56
    LMP_OPCODE_PATH: int = 0x0480

    # Log sizes for each marker type
    LMP_TX_LOG_SIZE: int = 12       # Hook 3 LMP TX log
    LMP_ACL_LOG_SIZE: int = 16      # Hook 3 ACL TX log
    LMP_RXLC_LOG_SIZE: int = 14     # Hook 4 RX LC log

    # DarkFirmware patched buffer supports up to 0x1C (28 bytes) for
    # BrakTooth-style oversize PDU injection. Original was 0x0A (10).
    _LMP_TX_MAX_BYTES: int = 28

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

    def __exit__(self, _exc_type: object, _exc_val: object, _exc_tb: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "open" if self._sock is not None else "closed"
        monitor = "monitoring" if self._monitor_thread and self._monitor_thread.is_alive() else "idle"
        return f"<HCIVSCSocket hci{self._hci_dev} {state} {monitor}>"

    def raw_socket(self) -> socket.socket | None:
        """Return the underlying raw socket, or *None* if not open.

        Intended for callers that need direct socket access (e.g. low-level
        probe routines).  The socket is the same object used by :meth:`send_vsc`
        and :meth:`recv_event`; callers MUST hold ``_lock`` (or perform their
        own serialisation) if they write to the socket concurrently.
        """
        return self._sock

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

            # Guard the entire read-pop-inspect-push sequence with _lock so
            # concurrent callers can't see a torn view of _cc_queue.  This is
            # safe because 9.1 removed the blocking select/recv from under this
            # lock; the monitor thread only appends while not holding _lock.
            with self._lock:
                checked: list[tuple[int, bytes]] = []
                while self._cc_queue:
                    cc_opcode, cc_params = self._cc_queue.popleft()
                    if cc_opcode == opcode:
                        # Put back any non-matching events. We popped in
                        # insertion order (oldest first), so appendleft in
                        # REVERSE to preserve FIFO ordering for the next
                        # caller — appending in forward order would invert
                        # the queue and break event sequencing under load.
                        for item in reversed(checked):
                            self._cc_queue.appendleft(item)
                        return cc_params
                    checked.append((cc_opcode, cc_params))

                # None matched; put them all back preserving FIFO order.
                for item in reversed(checked):
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
            RuntimeError: If called from an external thread while the LMP
                monitor is running (two threads reading the same HCI socket
                can corrupt event frames). The monitor's own loop is allowed.
        """
        if self._sock is None:
            raise OSError("HCI socket is not open")
        monitor = self._monitor_thread
        if (
            monitor is not None
            and monitor.is_alive()
            and threading.get_ident() != monitor.ident
        ):
            raise RuntimeError(
                "recv_event() cannot be called while the LMP monitor thread is "
                "reading the same socket; call stop_lmp_monitor() first or "
                "consume events via the monitor's callback"
            )

        # Release _lock during blocking syscalls (select + recv) so concurrent
        # send_vsc() calls are not blocked for the full timeout duration.
        # We re-acquire _lock only for shared-state mutations (none needed here
        # since _sock itself is stable; sendall callers hold the lock for their
        # own atomic send).
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

        The RTL8761B firmware always returns a full 4-byte word (mode 0x20).
        This wrapper slices the response so callers requesting fewer bytes
        get exactly that many — keeping the API honest for sub-word reads at
        ranges that don't end on a 4-byte boundary.

        Args:
            address: 32-bit memory address (4-byte alignment recommended).
            size:    Number of bytes to return. Must be 1–4. The firmware
                     read is always 4 bytes; the result is sliced to ``size``.

        Returns:
            ``size`` bytes from the controller, or ``b""`` on failure.
        """
        if not 1 <= size <= 4:
            raise ValueError(f"read_memory size must be 1–4, got {size}")
        logger.debug("Reading memory at %#010x (size=%d)", address, size)
        params = struct.pack("<BI", 0x20, address)
        result = self.send_vsc(self.VSC_MEM_READ, params)

        if len(result) < 1:
            error("Empty response from memory read")
            return b""

        status = result[0]
        if status != 0x00:
            error(f"Memory read at 0x{address:08X} failed with status 0x{status:02X}")
            return b""

        return result[1 : 1 + size]

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory on the Bluetooth controller via VSC 0xFC62.

        The RTL8761B firmware interprets the size parameter as a write mode,
        mirroring read_memory: ``0x20`` (32) writes a full 4-byte word,
        while smaller values write only 1 byte.  We always use ``0x20`` for
        4-byte writes and ``1`` for single-byte writes.

        Args:
            address: 32-bit memory address to write to (should be 4-byte
                     aligned for 4-byte writes).
            data:    Bytes to write (4 bytes for word write, 1 byte for
                     single-byte write).

        Returns:
            *True* on success, *False* on failure.
        """
        logger.debug("Writing memory at %#010x", address)
        # Params: size(1B) + address(4B LE) + data
        # Use 0x20 for 4-byte writes (matching read_memory behavior);
        # len(data) for sub-word writes (1-3 bytes).
        size_param = 0x20 if len(data) == 4 else len(data)
        params = struct.pack("<BI", size_param, address) + data
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
    # Raw ACL injection (below-stack)
    # ------------------------------------------------------------------

    def send_raw_acl(
        self,
        handle: int,
        l2cap_data: bytes,
        pb: int = 2,
        bc: int = 0,
    ) -> bool:
        """Send raw HCI ACL data, bypassing the host Bluetooth stack.

        The controller encrypts and transmits whatever payload is provided.
        No L2CAP validation occurs — enables injection of malformed frames
        that BlueZ would normally drop.

        Combined with DarkFirmware's ACLX/RXLC hooks, we can observe both
        the injected frame and the target's response.

        Args:
            handle:     ACL connection handle (12 bits, from ``hcitool con``).
            l2cap_data: Raw L2CAP frame bytes (length + CID + payload).
            pb:         Packet boundary flag (2 = first automatically flushable).
            bc:         Broadcast flag (0 = point-to-point).

        Returns:
            *True* if the packet was sent, *False* on failure.
        """
        if self._sock is None:
            raise OSError("HCI socket is not open")

        handle_flags = (handle & 0xFFF) | ((pb & 0x3) << 12) | ((bc & 0x3) << 14)
        # HCI ACL packet: [type=0x02] [handle_flags:2B LE] [data_len:2B LE] [data]
        hci_pkt = struct.pack("<BHH", 0x02, handle_flags, len(l2cap_data)) + l2cap_data

        info(
            f"Sending raw ACL: handle=0x{handle:04X} "
            f"pb={pb} bc={bc} len={len(l2cap_data)}"
        )

        try:
            with self._lock:
                self._sock.sendall(hci_pkt)
            return True
        except OSError as exc:
            error(f"Raw ACL send failed: {exc}")
            return False

    # ------------------------------------------------------------------
    # In-flight LMP modification (Hook 2 modes)
    # ------------------------------------------------------------------

    def set_mod_mode(
        self,
        mode: int,
        byte_offset: int = 0,
        new_value: int = 0,
        target_opcode: int = 0,
    ) -> bool:
        """Set Hook 2 in-flight LMP modification mode.

        The firmware's Hook 2 checks a mode flag in RAM on every incoming
        LMP packet and can modify, drop, or auto-respond before the
        original handler sees it.

        Modes:
            0 (passthrough): Normal operation — log only.
            1 (modify):      Overwrite data_buf[byte_offset] with new_value.
                             One-shot: auto-clears to mode 0 after first match.
            2 (drop):        Silently drop the next incoming LMP packet.
                             One-shot: auto-clears after one drop.
            3 (opcode-drop): Drop only if opcode matches target_opcode.
                             Persistent: keeps dropping until manually cleared.
            4 (persistent):  Same as mode 1 but does NOT auto-clear.
                             Sustained modification (e.g., KNOB key size rewrite).
            5 (auto-respond):Send pre-loaded response when trigger seen.

        Args:
            mode:           0-5 as described above.
            byte_offset:    Byte offset in data_buf to modify (modes 1, 4).
            new_value:      Value to write at byte_offset (modes 1, 4).
            target_opcode:  Only modify/drop if opcode matches (modes 3, 4).

        Returns:
            True if RAM writes succeeded, False otherwise.
        """
        from blue_tap.hardware.firmware import MOD_FLAG_ADDR, MOD_TABLE_ADDR

        # Write mod_table first (3 bytes packed into a 4-byte word)
        table_word = (
            (byte_offset & 0xFF)
            | ((new_value & 0xFF) << 8)
            | ((target_opcode & 0xFF) << 16)
        )
        ok_table = self.write_memory(
            MOD_TABLE_ADDR, struct.pack("<I", table_word)
        )
        if not ok_table:
            error("Failed to write mod_table")
            return False

        # Write mod_flag (activates the mode)
        ok_flag = self.write_memory(
            MOD_FLAG_ADDR, struct.pack("<I", mode & 0xFF)
        )
        if not ok_flag:
            error("Failed to write mod_flag")
            return False

        mode_names = {
            0: "passthrough", 1: "modify", 2: "drop",
            3: "opcode-drop", 4: "persistent", 5: "auto-respond",
        }
        info(
            f"LMP mod mode set: {mode_names.get(mode, mode)} "
            f"(offset={byte_offset}, value=0x{new_value:02X}, "
            f"opcode=0x{target_opcode:02X})"
        )
        return True

    def clear_mod_mode(self) -> bool:
        """Reset LMP modification mode to passthrough (mode 0)."""
        from blue_tap.hardware.firmware import MOD_FLAG_ADDR

        ok = self.write_memory(MOD_FLAG_ADDR, struct.pack("<I", 0))
        if ok:
            info("LMP mod mode cleared (passthrough)")
        return ok

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

            # Route command-complete events to send_vsc() via queue.
            # Hold _lock while appending so _wait_cc_from_monitor's drain loop
            # (which also holds _lock) sees a consistent queue state.
            if event_code == self.HCI_CMD_COMPLETE and len(event_params) >= 3:
                cc_opcode = struct.unpack_from("<H", event_params, 1)[0]
                cc_return = event_params[3:]
                with self._lock:
                    self._cc_queue.append((cc_opcode, cc_return))
                self._cc_ready.set()
                continue

            # Process vendor events as DarkFirmware logs
            if event_code != self.HCI_VENDOR_EVENT:
                continue

            log = None
            if len(event_params) >= 4:
                marker = struct.unpack_from("<I", event_params, 0)[0]
                if marker == self.MARKER_AAAA and len(event_params) >= self.LMP_LOG_SIZE:
                    log = parse_lmp_log(event_params)
                elif marker == self.MARKER_TXXX and len(event_params) >= self.LMP_TX_LOG_SIZE:
                    log = parse_lmp_tx_log(event_params)
                elif marker == self.MARKER_ACLX and len(event_params) >= self.LMP_ACL_LOG_SIZE:
                    log = parse_acl_tx_log(event_params)
                elif marker == self.MARKER_RXLC and len(event_params) >= self.LMP_RXLC_LOG_SIZE:
                    log = parse_rxlc_log(event_params)

            if log is None:
                continue

            self.lmp_log_buffer.append(log)
            try:
                callback(log)
            except Exception:
                logger.exception("Exception in LMP monitor callback")
