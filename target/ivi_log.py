"""Colorized logging for the Vulnerable IVI Simulator.

Usage:
    from ivi_log import log, set_verbosity

    log.info("PBAP", "Serving phonebook.vcf")
    log.connection("RFCOMM:15", "AA:BB:CC:DD:EE:FF", "connected")
    log.attack("VULN", "AA:BB:CC:DD:EE:FF", "Unauthenticated OBEX access!")
    log.obex("recv", 0x83, 47)
    log.at("recv", "AT+BRSF=127")
"""

import atexit
import re as _re
import threading
from datetime import datetime


# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_MAGENTA = "\033[95m"
_WHITE = "\033[97m"

# OBEX opcode names for readable logging
_OBEX_OPCODES = {
    0x80: "CONNECT", 0x81: "DISCONNECT", 0x02: "PUT", 0x82: "PUT-FINAL",
    0x03: "GET", 0x83: "GET-FINAL", 0x85: "SETPATH",
    0xA0: "SUCCESS", 0x90: "CONTINUE", 0xC0: "BAD-REQ", 0xC1: "UNAUTH",
    0xC4: "NOT-FOUND", 0xD0: "INT-ERROR",
}


class IVILogger:
    """Thread-safe colorized logger for the IVI simulator."""

    def __init__(self):
        self._lock = threading.Lock()
        self._quiet = False
        self._verbose = False
        self._log_file = None

    def set_verbosity(self, quiet: bool = False, verbose: bool = False):
        self._quiet = quiet
        self._verbose = verbose

    def set_log_file(self, path: str):
        self._log_file = open(path, "a")
        atexit.register(self.close)

    def close(self):
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _write(self, line: str, *, force: bool = False):
        if self._quiet and not force:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        full_line = f"{_DIM}{ts}{_RESET} {line}"
        with self._lock:
            print(full_line, flush=True)
            if self._log_file:
                # Strip all ANSI escape sequences for log file
                clean = _re.sub(r'\033\[[0-9;]*m', '', full_line)
                self._log_file.write(clean + "\n")
                self._log_file.flush()

    # ── Log levels ─────────────────────────────────────────────────────

    def info(self, component: str, message: str):
        self._write(f"{_CYAN}[{component}]{_RESET} {message}")

    def warn(self, component: str, message: str):
        self._write(f"{_YELLOW}[{component}] {message}{_RESET}", force=True)

    def error(self, component: str, message: str):
        self._write(f"{_RED}{_BOLD}[{component}] {message}{_RESET}", force=True)

    def connection(self, component: str, addr: str, action: str):
        self._write(
            f"{_GREEN}[{component}]{_RESET} {_BOLD}{action}{_RESET}: {addr}"
        )

    def attack(self, component: str, addr: str, detail: str):
        """Highlight attack activity in red."""
        self._write(
            f"{_RED}{_BOLD}[{component}] !! {detail}{_RESET} from {addr}",
            force=True,
        )

    # ── Protocol-specific ──────────────────────────────────────────────

    def obex(self, direction: str, opcode: int, length: int):
        arrow = "<-" if direction == "recv" else "->"
        name = _OBEX_OPCODES.get(opcode, f"0x{opcode:02X}")
        self._write(f"{_MAGENTA}[OBEX]{_RESET} {arrow} {name} len={length}")

    def obex_hex(self, label: str, data: bytes, max_bytes: int = 64):
        """Verbose hex dump of OBEX data."""
        if not self._verbose:
            return
        preview = data[:max_bytes].hex(" ")
        suffix = f"... ({len(data)} bytes total)" if len(data) > max_bytes else ""
        self._write(f"{_DIM}[OBEX] {label}: {preview}{suffix}{_RESET}")

    def at(self, direction: str, command: str):
        arrow = "<-" if direction == "recv" else "->"
        # Strip \r\n for display
        clean = command.strip().replace("\r", "\\r").replace("\n", "\\n")
        self._write(f"{_MAGENTA}[AT]{_RESET} {arrow} {clean}")

    def l2cap(self, psm: int, addr: str, nbytes: int):
        self._write(f"{_CYAN}[L2CAP:{psm}]{_RESET} {nbytes} bytes from {addr}")

    def ble(self, component: str, message: str):
        self._write(f"{_CYAN}[BLE:{component}]{_RESET} {message}")

    # ── Startup banner ─────────────────────────────────────────────────

    def banner(self, name: str, mac: str, profile: str, channels: list[int],
               psms: list[int]):
        lines = [
            "",
            f"{_BOLD}{_RED}  ╔══════════════════════════════════════════╗{_RESET}",
            f"{_BOLD}{_RED}  ║   VULNERABLE IVI SIMULATOR               ║{_RESET}",
            f"{_BOLD}{_RED}  ╚══════════════════════════════════════════╝{_RESET}",
            "",
            f"  {_CYAN}Name:{_RESET}     {name}",
            f"  {_CYAN}MAC:{_RESET}      {mac}",
            f"  {_CYAN}Profile:{_RESET}  {profile}",
            f"  {_CYAN}RFCOMM:{_RESET}   {', '.join(f'ch{c}' for c in channels)}",
            f"  {_CYAN}L2CAP:{_RESET}    {', '.join(f'PSM {p}' for p in psms)}",
            "",
            f"  {_YELLOW}Waiting for connections...{_RESET}",
            "",
        ]
        with self._lock:
            for line in lines:
                print(line, flush=True)

    def shutdown(self, stats: dict):
        lines = [
            "",
            f"  {_BOLD}Shutdown Summary:{_RESET}",
            f"    Connections served: {stats.get('connections', 0)}",
            f"    Unique attackers:   {stats.get('unique_addrs', 0)}",
            f"    Files received:     {stats.get('files_received', 0)}",
            f"    Bytes transferred:  {stats.get('bytes', 0)}",
            "",
        ]
        with self._lock:
            for line in lines:
                print(line, flush=True)


# Module-level singleton
log = IVILogger()


def set_verbosity(quiet: bool = False, verbose: bool = False):
    log.set_verbosity(quiet=quiet, verbose=verbose)
