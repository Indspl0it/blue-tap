"""RFCOMM Channel Scanner — probe channels 1-30 for open services."""

import errno
import socket
import string

from blue_tap.recon.spec_interpretation import interpret_rfcomm_probe
from blue_tap.utils.output import info, success, error, warning, verbose


class RFCOMMScanner:
    """Scan and probe RFCOMM channels on a remote Bluetooth device."""

    PROBE_BYTES = [b"\r\n", b"AT\r\n"]
    MAX_CHANNEL = 30

    def __init__(self, address: str):
        self.address = address
        self._local_addr: str | None = None

    def scan_all_channels(self, timeout_per_ch: float = 2.0,
                            hci: str = "hci0",
                            max_retries: int = 1,
                            unreachable_threshold: int = 3) -> list[dict]:
        """Try connecting to RFCOMM channels 1-30.

        Args:
            timeout_per_ch: Timeout per channel probe in seconds.
            hci: HCI adapter to use.
            max_retries: Number of retries for timeout/transient failures.
            unreachable_threshold: Abort after this many consecutive
                host_unreachable results (0 = never abort).

        Returns a list of dicts with keys: channel, status, response_type.
        Status is one of: open, closed, timeout, host_unreachable.
        """
        from blue_tap.utils.bt_helpers import ensure_adapter_ready, get_adapter_address
        if not ensure_adapter_ready(hci):
            return []
        self._local_addr = get_adapter_address(hci)

        info(f"Scanning RFCOMM channels 1-{self.MAX_CHANNEL} on {self.address}...")
        results = []
        consecutive_unreachable = 0

        for ch in range(1, self.MAX_CHANNEL + 1):
            result = self._probe_with_retry(ch, timeout_per_ch, max_retries)
            tag = result["status"]

            if tag == "open":
                success(f"  Channel {ch:>2}: OPEN ({result['response_type']})")
                consecutive_unreachable = 0
            elif tag == "timeout":
                warning(f"  Channel {ch:>2}: TIMEOUT")
                consecutive_unreachable = 0
            elif tag == "closed":
                consecutive_unreachable = 0
            elif tag == "host_unreachable":
                consecutive_unreachable += 1
                error(f"  Channel {ch:>2}: HOST UNREACHABLE")
                if unreachable_threshold > 0 and consecutive_unreachable >= unreachable_threshold:
                    results.append(result)
                    warning(
                        f"Aborting scan — {unreachable_threshold} consecutive "
                        f"unreachable probes (device likely out of range)"
                    )
                    break

            results.append(result)

            # Progress feedback (visible with -v)
            if ch % 5 == 0:
                verbose(f"Progress: {ch}/{self.MAX_CHANNEL} channels scanned")

        open_count = sum(1 for r in results if r["status"] == "open")
        success(f"Scan complete — {open_count} open channel(s) found")
        return results

    def _probe_with_retry(self, channel: int, timeout: float,
                           max_retries: int) -> dict:
        """Probe a channel with retry on transient failures."""
        last_result = None
        for attempt in range(max_retries + 1):
            result = self.probe_channel(channel, timeout)
            if result["status"] != "timeout":
                return result
            last_result = result
            if attempt < max_retries:
                import time
                time.sleep(0.5)
        return last_result

    def probe_channel(self, channel: int, timeout: float = 2.0) -> dict:
        """Connect to a single RFCOMM channel and classify the response.

        Response types: at_modem, obex, raw_data, silent_open, refused, timeout.
        """
        import time

        result = {
            "channel": channel,
            "status": "closed",
            "response_type": "refused",
            "raw_response_hex": "",
            "banner_preview": "",
            "protocol_hints": [],
            "probe_bytes": [probe.hex() for probe in self.PROBE_BYTES],
            "probe_results": [],
            "connect_latency_ms": None,
            "first_response_latency_ms": None,
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
        )
        sock.settimeout(timeout)
        if self._local_addr:
            sock.bind((self._local_addr, 0))

        try:
            connect_started = time.time()
            sock.connect((self.address, channel))
            result["connect_latency_ms"] = round((time.time() - connect_started) * 1000, 1)
        except OSError as exc:
            sock.close()
            if exc.errno == errno.ECONNREFUSED:
                return result
            if exc.errno == errno.ETIMEDOUT or isinstance(exc, socket.timeout):
                result["status"] = "timeout"
                result["response_type"] = "timeout"
                return result
            if exc.errno in (errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ENETDOWN):
                result["status"] = "host_unreachable"
                result["response_type"] = "host_unreachable"
                return result
            result["response_type"] = "refused"
            return result

        # Connection succeeded — channel is open
        result["status"] = "open"

        try:
            # Send probes one at a time, read response after each
            data = b""
            for index, probe in enumerate(self.PROBE_BYTES, 1):
                try:
                    probe_started = time.time()
                    sock.sendall(probe)
                    sock.settimeout(timeout)
                    chunk = sock.recv(1024)
                    elapsed_ms = round((time.time() - probe_started) * 1000, 1)
                    if chunk:
                        data = chunk
                        if result["first_response_latency_ms"] is None:
                            result["first_response_latency_ms"] = elapsed_ms
                        result["probe_results"].append({
                            "index": index,
                            "sent_hex": probe.hex(),
                            "response_hex": chunk[:32].hex(),
                            "response_len": len(chunk),
                            "elapsed_ms": elapsed_ms,
                        })
                        break
                    result["probe_results"].append({
                        "index": index,
                        "sent_hex": probe.hex(),
                        "response_hex": "",
                        "response_len": 0,
                        "elapsed_ms": elapsed_ms,
                    })
                except TimeoutError:
                    result["probe_results"].append({
                        "index": index,
                        "sent_hex": probe.hex(),
                        "response_hex": "",
                        "response_len": 0,
                        "elapsed_ms": timeout * 1000,
                    })
                    continue
                except OSError:
                    result["probe_results"].append({
                        "index": index,
                        "sent_hex": probe.hex(),
                        "response_hex": "",
                        "response_len": 0,
                        "elapsed_ms": None,
                    })
                    break

            # Store as hex for JSON serialization
            result["raw_response_hex"] = data.hex() if data else ""
            result["banner_preview"] = _preview_ascii(data)
            classification = classify_rfcomm_response(data)
            result["response_type"] = classification["response_type"]
            result["protocol_hints"] = classification["protocol_hints"]
            result["evidence"] = classification["evidence"]
            result["spec_interpretation"] = interpret_rfcomm_probe(result, advertised=False)

        except OSError:
            result["response_type"] = "silent_open"
            result["spec_interpretation"] = interpret_rfcomm_probe(result, advertised=False)
        finally:
            sock.close()

        return result

    def find_hidden_services(self, sdp_channels: list[int],
                              scan_results: list[dict] | None = None) -> list[dict]:
        """Diff open RFCOMM channels against known SDP-advertised channels.

        Returns channels that are open but NOT listed in SDP — potential
        hidden/debug services.

        Args:
            sdp_channels: List of channels found via SDP browse.
            scan_results: Pre-scanned RFCOMM results. If None, will scan.
        """
        info("Checking for hidden (unadvertised) RFCOMM services...")
        if scan_results is None:
            scan_results = self.scan_all_channels()

        open_channels = [r for r in scan_results if r["status"] == "open"]
        sdp_set = set(sdp_channels)
        hidden = []

        for result in open_channels:
            if result["channel"] not in sdp_set:
                hidden.append(result)
                warning(
                    f"  Hidden service on channel {result['channel']} "
                    f"({result['response_type']})"
                )

        if hidden:
            success(f"Found {len(hidden)} hidden RFCOMM service(s)")
        else:
            info("No hidden RFCOMM services detected")

        return hidden


def _is_obex(data: bytes) -> bool:
    """Detect OBEX protocol responses.

    OBEX opcodes (first byte):
      0x00 - Connect (request, unusual in response)
      0x80 - Connect Response
      0xA0 - Success (OK)
      0xA1 - Created
      0xC0 - Bad Request
      0xC1 - Unauthorized
      0xCB - Unsupported Media Type
      0xD0 - Internal Server Error
    """
    if not data:
        return False
    first = data[0]
    # OBEX response codes are >= 0x80 with specific patterns
    obex_response_codes = {0x80, 0xA0, 0xA1, 0xC0, 0xC1, 0xC3, 0xC4, 0xCB, 0xD0}
    if first in obex_response_codes:
        return True
    # OBEX Connect request starts with 0x80 followed by version/flags/maxlen
    if first == 0x00 and len(data) >= 4:
        return True
    return False


def classify_rfcomm_response(data: bytes) -> dict:
    if not data:
        return {
            "response_type": "silent_open",
            "protocol_hints": ["open_channel_no_banner"],
            "evidence": "channel accepted a connection but returned no immediate data",
            "ascii_ratio": 0.0,
            "line_count": 0,
        }
    if _is_obex(data):
        return {
            "response_type": "obex",
            "protocol_hints": ["object_transfer", "obex_like"],
            "evidence": f"obex-like leading bytes observed ({data[:4].hex()})",
            "ascii_ratio": _ascii_ratio(data),
            "line_count": _line_count(data),
        }
    upper = data.upper()
    if b"OK" in upper or b"ERROR" in upper or b"AT" in upper:
        return {
            "response_type": "at_modem",
            "protocol_hints": ["at_command_surface", "telephony_or_modem"],
            "evidence": _preview_ascii(data),
            "ascii_ratio": _ascii_ratio(data),
            "line_count": _line_count(data),
        }
    preview = _preview_ascii(data)
    if preview and any(ch in string.ascii_letters for ch in preview):
        return {
            "response_type": "text_banner",
            "protocol_hints": ["textual_banner"],
            "evidence": preview,
            "ascii_ratio": _ascii_ratio(data),
            "line_count": _line_count(data),
        }
    return {
        "response_type": "raw_binary",
        "protocol_hints": ["binary_protocol"],
        "evidence": data[:16].hex(),
        "ascii_ratio": _ascii_ratio(data),
        "line_count": _line_count(data),
    }


def _preview_ascii(data: bytes, limit: int = 60) -> str:
    if not data:
        return ""
    text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data[:limit])
    return text.rstrip(".")


def _ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte <= 126)
    return round(printable / len(data), 3)


def _line_count(data: bytes) -> int:
    if not data:
        return 0
    preview = _preview_ascii(data, limit=max(len(data), 128))
    return preview.count("\n") + 1 if preview else 0
