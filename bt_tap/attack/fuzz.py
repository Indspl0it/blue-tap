"""Protocol fuzzer for Bluetooth L2CAP and RFCOMM layers.

Provides targeted fuzzing primitives for discovering crashes, hangs, and
unexpected behaviour in remote Bluetooth stacks.  Each method returns a
summary dict so callers can aggregate results programmatically.
"""

import os
import random
import socket
import time

from bt_tap.utils.output import info, success, error, warning
from bt_tap.utils.bt_helpers import run_cmd, check_tool

# Bluetooth socket constants (from <bluetooth/bluetooth.h>)
AF_BLUETOOTH = 31
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3


# ---------------------------------------------------------------------------
# L2CAP fuzzer
# ---------------------------------------------------------------------------

class L2CAPFuzzer:
    """Fuzz the L2CAP layer of a remote Bluetooth device."""

    def __init__(self, address: str):
        self.address = address

    def oversized_mtu(self, psm: int = 1, size: int = 65535) -> dict:
        """Send an oversized L2CAP packet to stress MTU handling."""
        info(f"Sending oversized L2CAP packet ({size} bytes) to {self.address} PSM {psm}")
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            sock.connect((self.address, psm))
            data = os.urandom(size)
            sent = sock.send(data)
            success(f"Sent {sent} bytes")
            return {"result": "sent", "bytes_sent": sent}
        except OSError as exc:
            error(f"L2CAP oversized_mtu error: {exc}")
            return {"result": "error", "bytes_sent": 0, "error": str(exc)}
        except Exception as exc:
            warning(f"Possible crash — connection lost: {exc}")
            return {"result": "crash_suspected", "bytes_sent": 0, "error": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def malformed_packets(self, psm: int = 1, count: int = 100) -> dict:
        """Send randomly corrupted packets over L2CAP."""
        info(f"Sending {count} malformed L2CAP packets to {self.address} PSM {psm}")
        sent = 0
        errors = 0
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            sock.connect((self.address, psm))
            for i in range(count):
                pkt = os.urandom(random.randint(1, 1024))
                try:
                    sock.send(pkt)
                    sent += 1
                except OSError:
                    errors += 1
            success(f"Malformed packets: {sent} sent, {errors} errors")
            return {"result": "complete", "sent": sent, "errors": errors, "total": count}
        except OSError as exc:
            error(f"L2CAP malformed_packets connect error: {exc}")
            return {"result": "error", "sent": sent, "errors": errors, "total": count, "error": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def null_flood(self, psm: int = 1, count: int = 1000) -> dict:
        """Rapid-fire zero-byte packets to stress connection handling."""
        info(f"Flooding {count} null packets to {self.address} PSM {psm}")
        sent = 0
        errors = 0
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            sock.connect((self.address, psm))
            for _ in range(count):
                try:
                    sock.send(b"\x00")
                    sent += 1
                except OSError:
                    errors += 1
            success(f"Null flood: {sent} sent, {errors} errors")
            return {"result": "complete", "sent": sent, "errors": errors, "total": count}
        except OSError as exc:
            error(f"L2CAP null_flood connect error: {exc}")
            return {"result": "error", "sent": sent, "errors": errors, "total": count, "error": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# RFCOMM fuzzer
# ---------------------------------------------------------------------------

class RFCOMMFuzzer:
    """Fuzz the RFCOMM layer of a remote Bluetooth device."""

    def __init__(self, address: str):
        self.address = address

    def channel_exhaustion(self, max_channels: int = 30) -> dict:
        """Open sockets to channels 1-max_channels simultaneously."""
        info(f"Attempting channel exhaustion on {self.address} (1-{max_channels})")
        sockets: list[socket.socket] = []
        opened = 0
        failed = 0
        try:
            for ch in range(1, max_channels + 1):
                try:
                    sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
                    sock.connect((self.address, ch))
                    sockets.append(sock)
                    opened += 1
                except OSError:
                    failed += 1
            success(f"Channel exhaustion: {opened} opened, {failed} failed")
            return {"result": "complete", "opened": opened, "failed": failed, "max_channels": max_channels}
        except Exception as exc:
            error(f"Channel exhaustion unexpected error: {exc}")
            return {"result": "error", "opened": opened, "failed": failed, "error": str(exc)}
        finally:
            for s in sockets:
                try:
                    s.close()
                except OSError:
                    pass

    def large_payload(self, channel: int = 1, size: int = 65535) -> dict:
        """Send an oversized payload on an RFCOMM channel."""
        info(f"Sending {size}-byte payload to {self.address} RFCOMM ch {channel}")
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            sock.connect((self.address, channel))
            data = os.urandom(size)
            sent = sock.send(data)
            success(f"Sent {sent} bytes on RFCOMM ch {channel}")
            return {"result": "sent", "bytes_sent": sent}
        except OSError as exc:
            error(f"RFCOMM large_payload error: {exc}")
            return {"result": "error", "bytes_sent": 0, "error": str(exc)}
        except Exception as exc:
            warning(f"Possible crash — connection lost: {exc}")
            return {"result": "crash_suspected", "bytes_sent": 0, "error": str(exc)}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def at_fuzz(self, channel: int = 1, patterns: list[str] | None = None) -> dict:
        """Send malformed AT commands over RFCOMM to fuzz modem/HFP parsers."""
        default_patterns = [
            "AT" + "A" * 1024 + "\r\n",
            "AT\x00\x00\r\n",
            "AT%n%n%x%x\r\n",
            "AT" + "\u00c4" * 256 + "\r\n",
            "AT+" + "B" * 512 + "\r\n",
        ]
        test_patterns = patterns if patterns is not None else default_patterns
        info(f"AT fuzzing {self.address} RFCOMM ch {channel} with {len(test_patterns)} patterns")

        results: list[dict] = []
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
            sock.settimeout(3)
            sock.connect((self.address, channel))
            for idx, pattern in enumerate(test_patterns):
                entry: dict = {"index": idx, "length": len(pattern)}
                try:
                    sock.send(pattern.encode("utf-8", errors="replace"))
                    time.sleep(0.3)
                    try:
                        resp = sock.recv(1024)
                        entry["response"] = resp.decode("utf-8", errors="replace")
                    except socket.timeout:
                        entry["response"] = None
                    entry["status"] = "sent"
                except OSError as exc:
                    entry["status"] = "error"
                    entry["error"] = str(exc)
                results.append(entry)

            sent = sum(1 for r in results if r["status"] == "sent")
            errs = sum(1 for r in results if r["status"] == "error")
            success(f"AT fuzz complete: {sent} sent, {errs} errors")
            return {"result": "complete", "sent": sent, "errors": errs, "details": results}
        except OSError as exc:
            error(f"RFCOMM at_fuzz connect error: {exc}")
            return {"result": "error", "sent": 0, "errors": 0, "error": str(exc), "details": results}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# External tool wrapper
# ---------------------------------------------------------------------------

def bss_wrapper(target: str, mode: str = "l2cap") -> bool:
    """Run Bluetooth Stack Smasher (bss) against a target.

    Args:
        target: BD_ADDR of the remote device.
        mode: ``"l2cap"`` or ``"rfcomm"``.

    Returns:
        True if bss executed successfully.
    """
    if not check_tool("bss"):
        error("bss (Bluetooth Stack Smasher) not found. Install from: "
              "https://github.com/niccoX/Bluetooth-stack-smasher")
        return False

    cmd = ["bss", "-d", target]
    if mode == "rfcomm":
        cmd += ["-p", "rfcomm"]
    else:
        cmd += ["-p", "l2cap"]

    info(f"Running bss against {target} (mode={mode})")
    result = run_cmd(cmd, timeout=120)
    if result.returncode == 0:
        success(f"bss finished: {result.stdout.strip()}")
        return True
    else:
        error(f"bss failed (rc={result.returncode}): {result.stderr.strip()}")
        return False
