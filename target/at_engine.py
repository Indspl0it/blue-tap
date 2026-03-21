"""AT command parser and responders for HFP and SPP/Bluesnarfer channels.

Provides:
    ATCommandParser  — buffers raw bytes, yields complete AT command strings
    HFPResponder     — handles HFP Service Level Connection + call control
    SPPResponder     — handles bluesnarfer-style AT info/phonebook/SMS exfil
"""

import os

from ivi_config import (
    DATA_DIR,
    FAKE_BATTERY,
    FAKE_IMEI,
    FAKE_IMSI,
    FAKE_OPERATOR,
    FAKE_SIGNAL,
    FAKE_SUBSCRIBER,
    HFP_AG_FEATURES,
    HFP_INDICATOR_VALUES,
    HFP_OPERATOR,
    HFP_SUBSCRIBER,
)
from ivi_log import log


# ── AT Command Parser ────────────────────────────────────────────────────────


class ATCommandParser:
    """Buffers raw bytes from a socket and yields complete AT commands.

    Handles partial reads, multiple commands per recv(), and strips the
    trailing \\r or \\r\\n that AT transports append.
    """

    def __init__(self):
        self._buf = b""

    def feed(self, data: bytes) -> None:
        """Append raw bytes from a socket recv() to the internal buffer."""
        self._buf += data

    def get_commands(self) -> list[str]:
        """Return a list of complete AT command strings from the buffer.

        A command is considered complete when terminated by \\r or \\r\\n.
        Incomplete trailing data stays buffered for the next feed().
        """
        commands: list[str] = []

        while True:
            # Look for \r (may be followed by optional \n)
            idx = self._buf.find(b"\r")
            if idx == -1:
                break

            # Extract the command (everything before \r)
            raw_cmd = self._buf[:idx]

            # Consume \r and optional \n
            end = idx + 1
            if end < len(self._buf) and self._buf[end:end + 1] == b"\n":
                end += 1

            self._buf = self._buf[end:]

            # Decode and skip empty lines
            cmd = raw_cmd.decode("utf-8", errors="replace").strip()
            if cmd:
                commands.append(cmd)

        return commands


# ── HFP Responder ─────────────────────────────────────────────────────────────


class HFPResponder:
    """Handles AT commands on the HFP Audio-Gateway RFCOMM channel.

    Implements the full Service Level Connection (SLC) handshake and
    common HFP AT commands.  Unknown commands get a permissive OK
    (intentionally vulnerable).
    """

    def __init__(self, data_dir: str = DATA_DIR):
        self._phonebook: list[str] = []
        pb_path = os.path.join(data_dir, "at_phonebook.txt")
        if os.path.isfile(pb_path):
            with open(pb_path, "r") as f:
                self._phonebook = [
                    line.rstrip("\n") for line in f if line.strip()
                ]

    def handle(self, command: str) -> str:
        """Dispatch *command* and return the full AT response string."""
        cmd = command.strip()
        upper = cmd.upper()
        log.at("recv", cmd)

        # ── SLC Handshake ─────────────────────────────────────────────
        if upper.startswith("AT+BRSF="):
            return f"\r\n+BRSF: {HFP_AG_FEATURES}\r\n\r\nOK\r\n"

        if upper == "AT+CIND=?":
            descs = ",".join(
                f'("{name}",({lo}-{hi}))'
                for name, lo, hi in [
                    ("service", 0, 1),
                    ("call", 0, 1),
                    ("callsetup", 0, 3),
                    ("callheld", 0, 2),
                    ("signal", 0, 5),
                    ("roam", 0, 1),
                    ("battchg", 0, 5),
                ]
            )
            return f"\r\n+CIND: {descs}\r\n\r\nOK\r\n"

        if upper == "AT+CIND?":
            vals = ",".join(str(v) for v in HFP_INDICATOR_VALUES)
            return f"\r\n+CIND: {vals}\r\n\r\nOK\r\n"

        if upper.startswith("AT+CMER="):
            return "\r\nOK\r\n"

        if upper == "AT+CHLD=?":
            return "\r\n+CHLD: (0,1,2,3,4)\r\n\r\nOK\r\n"

        # ── Call control ──────────────────────────────────────────────
        if upper.startswith("ATD"):
            number = cmd[3:].rstrip(";")
            log.info("HFP", f"Dial request: {number}")
            return "\r\nOK\r\n"

        if upper == "ATA":
            log.info("HFP", "Call answered")
            return "\r\nOK\r\n"

        if upper == "AT+CHUP":
            log.info("HFP", "Call hung up")
            return "\r\nOK\r\n"

        if upper == "AT+CLCC":
            # No active calls
            return "\r\nOK\r\n"

        if upper == "AT+BLDN":
            log.info("HFP", "Last-number redial")
            return "\r\nOK\r\n"

        # ── Info queries ──────────────────────────────────────────────
        if upper == "AT+COPS?":
            return f'\r\n+COPS: 0,0,"{HFP_OPERATOR}"\r\n\r\nOK\r\n'

        if upper == "AT+CNUM":
            return (
                f'\r\n+CNUM: ,"{HFP_SUBSCRIBER}",145,,4\r\n\r\nOK\r\n'
            )

        if upper == "AT+CLIP=1":
            return "\r\nOK\r\n"

        # ── Volume / audio ────────────────────────────────────────────
        if upper.startswith("AT+VGS="):
            level = cmd.split("=", 1)[1]
            log.info("HFP", f"Speaker volume: {level}")
            return "\r\nOK\r\n"

        if upper.startswith("AT+VGM="):
            level = cmd.split("=", 1)[1]
            log.info("HFP", f"Mic volume: {level}")
            return "\r\nOK\r\n"

        if upper == "AT+NREC=0":
            log.info("HFP", "Noise reduction disabled by HF")
            return "\r\nOK\r\n"

        if upper.startswith("AT+BVRA="):
            val = cmd.split("=", 1)[1]
            state = "activated" if val == "1" else "deactivated"
            log.info("HFP", f"Voice recognition {state}")
            return "\r\nOK\r\n"

        # ── Codec negotiation ─────────────────────────────────────────
        if upper.startswith("AT+BAC="):
            # HF reports available codecs; AG selects codec 1 (CVSD)
            return "\r\n+BCS:1\r\n\r\nOK\r\n"

        if upper.startswith("AT+BCS="):
            log.info("HFP", f"Codec confirmed: {cmd.split('=', 1)[1]}")
            return "\r\nOK\r\n"

        # ── DTMF ─────────────────────────────────────────────────────
        if upper.startswith("AT+VTS="):
            digit = cmd.split("=", 1)[1]
            log.info("HFP", f"DTMF tone: {digit}")
            return "\r\nOK\r\n"

        # ── Phonebook via AT ──────────────────────────────────────────
        if upper == 'AT+CPBS="ME"' or upper == "AT+CPBS=\"ME\"":
            return "\r\nOK\r\n"

        if upper.startswith("AT+CPBR="):
            return self._handle_cpbr(cmd)

        # ── Default: permissive OK (intentionally vulnerable!) ────────
        log.info("HFP", f"Unknown AT cmd (OK anyway): {cmd}")
        return "\r\nOK\r\n"

    # ── Private helpers ───────────────────────────────────────────────

    def _handle_cpbr(self, cmd: str) -> str:
        """Handle AT+CPBR=start[,end] — return phonebook entries."""
        args = cmd.split("=", 1)[1]
        parts = args.split(",")
        try:
            start = int(parts[0])
            end = int(parts[1]) if len(parts) > 1 else start
        except (ValueError, IndexError):
            return "\r\nERROR\r\n"

        lines: list[str] = []
        for entry in self._phonebook:
            # Each line starts with "+CPBR: N,..."
            try:
                idx = int(entry.split(":")[1].split(",")[0].strip())
            except (ValueError, IndexError):
                continue
            if start <= idx <= end:
                lines.append(f"\r\n{entry}")

        if lines:
            return "".join(lines) + "\r\n\r\nOK\r\n"
        return "\r\nOK\r\n"


# ── SPP / Bluesnarfer Responder ──────────────────────────────────────────────


class SPPResponder:
    """Handles AT commands on the SPP serial-port channel.

    This is the target for bluesnarfer-style attacks — it exposes device
    info, phonebook, and SMS data via standard AT commands.  Unknown
    commands get a permissive OK (intentionally vulnerable).
    """

    def __init__(self, data_dir: str = DATA_DIR):
        self._current_memory = "ME"

        # Load phonebook
        self._phonebook: list[str] = []
        pb_path = os.path.join(data_dir, "at_phonebook.txt")
        if os.path.isfile(pb_path):
            with open(pb_path, "r") as f:
                self._phonebook = [
                    line.rstrip("\n") for line in f if line.strip()
                ]

        # Load call history as CPBR-format entries
        self._call_entries: dict[str, list[str]] = {"DC": [], "RC": [], "MC": []}
        for mem, fname in [("RC", "ich.vcf"), ("DC", "och.vcf"), ("MC", "mch.vcf")]:
            vcf_path = os.path.join(data_dir, fname)
            if os.path.isfile(vcf_path):
                content = open(vcf_path, "r").read()
                idx = 1
                for block in content.split("BEGIN:VCARD"):
                    block = block.strip()
                    if not block:
                        continue
                    name = number = ""
                    for line in block.splitlines():
                        if line.startswith("FN:"):
                            name = line[3:].strip()
                        elif line.startswith("TEL:"):
                            number = line[4:].strip()
                    if number:
                        ntype = 145 if number.startswith("+") else 129
                        self._call_entries[mem].append(
                            f'+CPBR: {idx},"{number}",{ntype},"{name}"'
                        )
                        idx += 1

        # Load SMS — stored as pairs: header line, body line
        self._sms: list[tuple[str, str]] = []
        sms_path = os.path.join(data_dir, "at_sms.txt")
        if os.path.isfile(sms_path):
            with open(sms_path, "r") as f:
                raw_lines = [line.rstrip("\n") for line in f if line.strip()]
            # Pair up: header (+CMGL: ...) followed by body text
            i = 0
            while i < len(raw_lines):
                if raw_lines[i].startswith("+CMGL:"):
                    body = raw_lines[i + 1] if i + 1 < len(raw_lines) else ""
                    self._sms.append((raw_lines[i], body))
                    i += 2
                else:
                    i += 1

    def handle(self, command: str) -> str:
        """Dispatch *command* and return the full AT response string."""
        cmd = command.strip()
        upper = cmd.upper()
        log.at("recv", cmd)

        # ── Phonebook ─────────────────────────────────────────────────
        if upper == "AT+CPBS=?":
            return '\r\n+CPBS: ("ME","SM","DC","MC","RC")\r\n\r\nOK\r\n'

        if upper.startswith("AT+CPBS="):
            mem = upper.split("=", 1)[1].strip().strip('"')
            if mem in ("ME", "SM", "DC", "MC", "RC"):
                self._current_memory = mem
                return "\r\nOK\r\n"
            return "\r\nERROR\r\n"

        if upper.startswith("AT+CPBR="):
            return self._handle_cpbr(cmd)

        # ── SMS ───────────────────────────────────────────────────────
        if upper == "AT+CMGF=1":
            return "\r\nOK\r\n"

        if upper.startswith("AT+CMGL="):
            return self._handle_cmgl(cmd)

        # ── Device info ───────────────────────────────────────────────
        if upper == "AT+CGSN":
            return f"\r\n{FAKE_IMEI}\r\n\r\nOK\r\n"

        if upper == "AT+CIMI":
            return f"\r\n{FAKE_IMSI}\r\n\r\nOK\r\n"

        if upper == "AT+CNUM":
            return (
                f'\r\n+CNUM: ,"{FAKE_SUBSCRIBER}",145,,4\r\n\r\nOK\r\n'
            )

        if upper == "AT+CBC":
            return f"\r\n+CBC: 0,{FAKE_BATTERY}\r\n\r\nOK\r\n"

        if upper == "AT+CSQ":
            return f"\r\n+CSQ: {FAKE_SIGNAL},99\r\n\r\nOK\r\n"

        if upper == "AT+COPS?":
            return f'\r\n+COPS: 0,0,"{FAKE_OPERATOR}"\r\n\r\nOK\r\n'

        # ── Default: permissive OK (intentionally vulnerable!) ────────
        log.info("SPP", f"Unknown AT cmd (OK anyway): {cmd}")
        return "\r\nOK\r\n"

    # ── Private helpers ───────────────────────────────────────────────

    def _handle_cpbr(self, cmd: str) -> str:
        """Handle AT+CPBR=start[,end] — return entries from current memory."""
        args = cmd.split("=", 1)[1]
        parts = args.split(",")
        try:
            start = int(parts[0])
            end = int(parts[1]) if len(parts) > 1 else start
        except (ValueError, IndexError):
            return "\r\nERROR\r\n"

        # Select data source based on current memory
        if self._current_memory in self._call_entries:
            source = self._call_entries[self._current_memory]
        else:
            source = self._phonebook

        lines: list[str] = []
        for entry in source:
            try:
                idx = int(entry.split(":")[1].split(",")[0].strip())
            except (ValueError, IndexError):
                continue
            if start <= idx <= end:
                lines.append(f"\r\n{entry}")

        if lines:
            return "".join(lines) + "\r\n\r\nOK\r\n"
        return "\r\nOK\r\n"

    def _handle_cmgl(self, cmd: str) -> str:
        """Handle AT+CMGL="ALL"|"REC READ"|"REC UNREAD" — return SMS."""
        # Extract the filter value between quotes
        try:
            filter_val = cmd.split("=", 1)[1].strip().strip('"').upper()
        except IndexError:
            return "\r\nERROR\r\n"

        lines: list[str] = []
        for header, body in self._sms:
            # header looks like: +CMGL: 1,"REC READ","+1925...",,"26/03/12..."
            header_upper = header.upper()
            if filter_val == "ALL":
                lines.append(f"\r\n{header}\r\n{body}")
            elif f'"{filter_val}"' in header_upper:
                lines.append(f"\r\n{header}\r\n{body}")

        if lines:
            return "".join(lines) + "\r\n\r\nOK\r\n"
        return "\r\nOK\r\n"
