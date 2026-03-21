#!/usr/bin/env python3
"""Vulnerable IVI Simulator — Main Daemon.

Listens on RFCOMM channels and L2CAP PSMs, dispatching connections
to the appropriate protocol handler (OBEX for PBAP/MAP/OPP, AT for HFP/SPP).

Usage:
    sudo python3 ivi_daemon.py
    sudo python3 ivi_daemon.py --hci hci1 --verbose
    sudo python3 ivi_daemon.py --no-ble --no-l2cap
"""

import argparse
import os
import signal
import socket
import sys
import threading
import time

from ivi_config import (
    CH_SPP, CH_HIDDEN, CH_OPP, CH_HFP, CH_PBAP, CH_MAP,
    CUSTOM_L2CAP_PSMS,
    DATA_DIR, RECEIVED_DIR, IVI_NAME,
    read_profile, read_phone_mac,
)
from ivi_log import log, set_verbosity
from obex_servers import PBAPSession, MAPSession, OPPSession, set_data_dir
from at_engine import ATCommandParser, HFPResponder, SPPResponder


# Bluetooth socket constants (may not be available on non-Linux)
try:
    AF_BLUETOOTH = socket.AF_BLUETOOTH       # 31
    BTPROTO_RFCOMM = socket.BTPROTO_RFCOMM   # 3
    BTPROTO_L2CAP = socket.BTPROTO_L2CAP     # 0
except AttributeError:
    AF_BLUETOOTH = 31
    BTPROTO_RFCOMM = 3
    BTPROTO_L2CAP = 0


# ============================================================================
# Connection Statistics
# ============================================================================

class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.connections = 0
        self.unique_addrs = set()
        self.bytes_in = 0
        self.bytes_out = 0
        self.files_received = 0

    def record_connection(self, addr: str):
        with self._lock:
            self.connections += 1
            self.unique_addrs.add(addr)

    def record_bytes(self, in_bytes: int = 0, out_bytes: int = 0):
        with self._lock:
            self.bytes_in += in_bytes
            self.bytes_out += out_bytes

    def record_file(self):
        with self._lock:
            self.files_received += 1

    def summary(self) -> dict:
        with self._lock:
            return {
                "connections": self.connections,
                "unique_addrs": len(self.unique_addrs),
                "bytes": self.bytes_in + self.bytes_out,
                "files_received": self.files_received,
            }


stats = Stats()


# ============================================================================
# RFCOMM Handlers
# ============================================================================

def _recv_obex_packet(conn: socket.socket) -> bytes | None:
    """Read a complete OBEX packet from a stream socket.

    OBEX packets declare their length in bytes 1-2 (big-endian).
    We read the 3-byte header first, then the remaining body.
    Returns None on connection close or error.
    """
    import struct

    # Read opcode + length (3 bytes minimum)
    header = b""
    while len(header) < 3:
        chunk = conn.recv(3 - len(header))
        if not chunk:
            return None
        header += chunk

    declared_len = struct.unpack(">H", header[1:3])[0]
    if declared_len < 3:
        return header  # Malformed but let parser handle it

    # Read remaining bytes
    remaining = declared_len - 3
    body = b""
    while len(body) < remaining:
        chunk = conn.recv(remaining - len(body))
        if not chunk:
            break  # Partial packet — return what we have
        body += chunk

    return header + body


def handle_obex_connection(conn: socket.socket, addr: str, session_cls, name: str):
    """Handle an OBEX connection (PBAP, MAP, or OPP)."""
    session = session_cls()
    stats.record_connection(addr)
    log.connection(name, addr, "connected")

    try:
        conn.settimeout(30.0)
        while True:
            data = _recv_obex_packet(conn)
            if not data:
                break

            stats.record_bytes(in_bytes=len(data))

            response = session.handle_packet(data)
            if response:
                conn.sendall(response)
                stats.record_bytes(out_bytes=len(response))

    except socket.timeout:
        log.info(name, f"Timeout from {addr}")
    except OSError as e:
        if e.errno not in (104, 110, 111):  # Connection reset/timeout/refused
            log.warn(name, f"Socket error from {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log.connection(name, addr, "disconnected")


def handle_at_connection(conn: socket.socket, addr: str, responder, name: str):
    """Handle an AT command connection (HFP or SPP)."""
    parser = ATCommandParser()
    stats.record_connection(addr)
    log.connection(name, addr, "connected")

    try:
        conn.settimeout(30.0)
        while True:
            data = conn.recv(1024)
            if not data:
                break

            stats.record_bytes(in_bytes=len(data))
            parser.feed(data)

            for cmd in parser.get_commands():
                log.at("recv", cmd)
                response = responder.handle(cmd)
                log.at("send", response.strip()[:80])
                conn.sendall(response.encode("utf-8", errors="replace"))
                stats.record_bytes(out_bytes=len(response))

    except socket.timeout:
        log.info(name, f"Timeout from {addr}")
    except OSError as e:
        if e.errno not in (104, 110, 111):
            log.warn(name, f"Socket error from {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log.connection(name, addr, "disconnected")


def handle_hidden_connection(conn: socket.socket, addr: str):
    """Handle connection on hidden RFCOMM channel — absorb + respond to probes."""
    stats.record_connection(addr)
    log.attack("HIDDEN:2", addr, "Connection on unadvertised channel!")

    try:
        conn.settimeout(10.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            stats.record_bytes(in_bytes=len(data))
            # Respond to AT probes so rfcomm-scan classifies as at_modem
            text = data.decode("utf-8", errors="replace").strip()
            if text.startswith("AT") or text == "":
                conn.sendall(b"OK\r\n")
                stats.record_bytes(out_bytes=4)
    except (socket.timeout, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_l2cap_connection(conn: socket.socket, addr: str, psm: int):
    """Handle L2CAP connection — absorb all data (fuzz target)."""
    stats.record_connection(addr)
    log.connection(f"L2CAP:{psm}", addr, "connected")
    total = 0

    try:
        conn.settimeout(10.0)
        while True:
            data = conn.recv(65535)
            if not data:
                break
            total += len(data)
            stats.record_bytes(in_bytes=len(data))
    except (socket.timeout, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log.l2cap(psm, addr, total)


# ============================================================================
# Listener Threads
# ============================================================================

class RFCOMMListener(threading.Thread):
    """Listens on an RFCOMM channel and spawns handler threads."""

    def __init__(self, channel: int, handler, handler_args=(), name: str = ""):
        super().__init__(daemon=True)
        self.channel = channel
        self.handler = handler
        self.handler_args = handler_args
        self.name_tag = name or f"RFCOMM:{channel}"
        self.sock = None
        self._running = True

    def run(self):
        try:
            self.sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.channel))
            self.sock.listen(1)
            self.sock.settimeout(2.0)
            log.info(self.name_tag, f"Listening on RFCOMM channel {self.channel}")

            while self._running:
                try:
                    conn, (addr, _) = self.sock.accept()
                    t = threading.Thread(
                        target=self.handler,
                        args=(conn, addr) + self.handler_args,
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._running:
                        log.warn(self.name_tag, f"Accept error: {e}")
                    break

        except OSError as e:
            log.error(self.name_tag, f"Bind failed on ch {self.channel}: {e}")

    def stop(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


class L2CAPListener(threading.Thread):
    """Listens on an L2CAP PSM and spawns handler threads."""

    def __init__(self, psm: int):
        super().__init__(daemon=True)
        self.psm = psm
        self.sock = None
        self._running = True

    def run(self):
        try:
            self.sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.psm))
            self.sock.listen(1)
            self.sock.settimeout(2.0)
            log.info(f"L2CAP:{self.psm}", f"Listening on PSM {self.psm}")

            while self._running:
                try:
                    conn, (addr, _) = self.sock.accept()
                    t = threading.Thread(
                        target=handle_l2cap_connection,
                        args=(conn, addr, self.psm),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._running:
                        log.warn(f"L2CAP:{self.psm}", f"Accept error: {e}")
                    break

        except OSError as e:
            if e.errno == 98:  # EADDRINUSE
                log.warn(f"L2CAP:{self.psm}", f"PSM {self.psm} already in use (bluetoothd?)")
            elif e.errno == 13:  # EACCES
                log.error(f"L2CAP:{self.psm}", "Permission denied — need root")
            else:
                log.error(f"L2CAP:{self.psm}", f"Bind failed: {e}")

    def stop(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Vulnerable IVI Simulator Daemon")
    parser.add_argument("--hci", default="hci0", help="HCI adapter (default: hci0)")
    parser.add_argument("--data-dir", default=None, help="Data directory (default: ./data/)")
    parser.add_argument("--quiet", action="store_true", help="Suppress info messages")
    parser.add_argument("--verbose", action="store_true", help="Show OBEX hex dumps")
    parser.add_argument("--no-ble", action="store_true", help="Skip BLE GATT server")
    parser.add_argument("--no-l2cap", action="store_true", help="Skip L2CAP listeners")
    args = parser.parse_args()

    # Root check
    if os.geteuid() != 0:
        print("Error: must run as root (sudo python3 ivi_daemon.py)")
        sys.exit(1)

    set_verbosity(quiet=args.quiet, verbose=args.verbose)

    data_dir = args.data_dir or DATA_DIR

    # Verify data exists
    if not os.path.exists(os.path.join(data_dir, "phonebook.vcf")):
        log.error("INIT", f"Data not found in {data_dir} — run: python3 data/gen_data.py")
        sys.exit(1)

    os.makedirs(RECEIVED_DIR, exist_ok=True)

    # Propagate data_dir to OBEX servers
    set_data_dir(data_dir, RECEIVED_DIR)

    # Read config from setup_ivi.sh
    profile = read_profile()
    phone_mac = read_phone_mac()

    # Get adapter MAC
    adapter_mac = "??:??:??:??:??:??"
    try:
        with open(os.path.join(os.path.dirname(__file__), ".ivi_adapter")) as f:
            adapter_mac = f.read().strip()
    except OSError:
        pass
    if phone_mac:
        log.info("INIT", f"Configured paired phone MAC: {phone_mac}")

    # Create responders
    hfp_responder = HFPResponder(data_dir)
    spp_responder = SPPResponder(data_dir)

    # ── Start listeners ────────────────────────────────────────────

    listeners = []

    # RFCOMM channel 15 — PBAP
    listener = RFCOMMListener(CH_PBAP, handle_obex_connection,
                              (PBAPSession, "PBAP"), "PBAP:15")
    listeners.append(listener)

    # RFCOMM channel 16 — MAP
    listener = RFCOMMListener(CH_MAP, handle_obex_connection,
                              (MAPSession, "MAP"), "MAP:16")
    listeners.append(listener)

    # RFCOMM channel 9 — OPP
    listener = RFCOMMListener(CH_OPP, handle_obex_connection,
                              (OPPSession, "OPP"), "OPP:9")
    listeners.append(listener)

    # RFCOMM channel 10 — HFP
    listener = RFCOMMListener(CH_HFP, handle_at_connection,
                              (hfp_responder, "HFP"), "HFP:10")
    listeners.append(listener)

    # RFCOMM channel 1 — SPP
    listener = RFCOMMListener(CH_SPP, handle_at_connection,
                              (spp_responder, "SPP"), "SPP:1")
    listeners.append(listener)

    # RFCOMM channel 2 — Hidden (not in SDP)
    listener = RFCOMMListener(CH_HIDDEN, handle_hidden_connection, (), "HIDDEN:2")
    listeners.append(listener)

    # L2CAP PSMs
    l2cap_listeners = []
    if not args.no_l2cap:
        for psm in CUSTOM_L2CAP_PSMS:
            ll = L2CAPListener(psm)
            l2cap_listeners.append(ll)

    # Start all listeners
    for listener in listeners:
        listener.start()
    for ll in l2cap_listeners:
        ll.start()

    # Give threads a moment to bind
    time.sleep(0.5)

    # Print startup banner
    active_channels = [listener.channel for listener in listeners if listener.sock is not None]
    active_psms = [ll.psm for ll in l2cap_listeners if ll.sock is not None]
    log.banner(IVI_NAME, adapter_mac, profile, active_channels, active_psms)

    # ── Signal handling ────────────────────────────────────────────

    shutdown_event = threading.Event()

    def handle_signal(signum, frame):
        log.info("MAIN", "Shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # ── Wait for shutdown ──────────────────────────────────────────

    try:
        while not shutdown_event.is_set():
            shutdown_event.wait(1.0)
    except KeyboardInterrupt:
        pass

    # ── Cleanup ────────────────────────────────────────────────────

    for listener in listeners:
        listener.stop()
    for ll in l2cap_listeners:
        ll.stop()

    for listener in listeners:
        listener.join(timeout=3)
    for ll in l2cap_listeners:
        ll.join(timeout=3)

    log.shutdown(stats.summary())


if __name__ == "__main__":
    main()
