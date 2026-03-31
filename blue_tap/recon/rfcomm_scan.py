"""RFCOMM Channel Scanner — probe channels 1-30 for open services."""

import errno
import socket

from blue_tap.utils.output import info, success, error, warning


class RFCOMMScanner:
    """Scan and probe RFCOMM channels on a remote Bluetooth device."""

    PROBE_BYTES = [b"\r\n", b"AT\r\n"]
    MAX_CHANNEL = 30

    def __init__(self, address: str):
        self.address = address
        self._local_addr: str | None = None

    def scan_all_channels(self, timeout_per_ch: float = 2.0,
                            hci: str = "hci0") -> list[dict]:
        """Try connecting to RFCOMM channels 1-30.

        Returns a list of dicts with keys: channel, status, response_type.
        Status is one of: open, closed, timeout, host_unreachable.
        """
        from blue_tap.utils.bt_helpers import ensure_adapter_ready, get_adapter_address
        if not ensure_adapter_ready(hci):
            return []
        self._local_addr = get_adapter_address(hci)

        info(f"Scanning RFCOMM channels 1-{self.MAX_CHANNEL} on {self.address}...")
        results = []

        for ch in range(1, self.MAX_CHANNEL + 1):
            result = self.probe_channel(ch, timeout=timeout_per_ch)
            tag = result["status"]
            if tag == "open":
                success(f"  Channel {ch:>2}: OPEN ({result['response_type']})")
            elif tag == "timeout":
                warning(f"  Channel {ch:>2}: TIMEOUT")
            elif tag == "host_unreachable":
                error(f"  Channel {ch:>2}: HOST UNREACHABLE — device may be out of range")
                # No point continuing if device is gone
                results.append(result)
                warning("Aborting scan — device unreachable")
                break
            results.append(result)

        open_count = sum(1 for r in results if r["status"] == "open")
        success(f"Scan complete — {open_count} open channel(s) found")
        return results

    def probe_channel(self, channel: int, timeout: float = 2.0) -> dict:
        """Connect to a single RFCOMM channel and classify the response.

        Response types: at_modem, obex, raw_data, silent_open, refused, timeout.
        """
        result = {
            "channel": channel,
            "status": "closed",
            "response_type": "refused",
            "raw_response_hex": "",
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
        )
        sock.settimeout(timeout)
        if self._local_addr:
            sock.bind((self._local_addr, 0))

        try:
            sock.connect((self.address, channel))
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
            for probe in self.PROBE_BYTES:
                try:
                    sock.sendall(probe)
                    sock.settimeout(timeout)
                    chunk = sock.recv(1024)
                    if chunk:
                        data = chunk
                        break
                except TimeoutError:
                    continue
                except OSError:
                    break

            # Store as hex for JSON serialization
            result["raw_response_hex"] = data.hex() if data else ""

            if not data:
                result["response_type"] = "silent_open"
            elif _is_obex(data):
                result["response_type"] = "obex"
            elif b"OK" in data or b"ERROR" in data or b"AT" in data.upper():
                result["response_type"] = "at_modem"
            else:
                result["response_type"] = "raw_data"

        except OSError:
            result["response_type"] = "silent_open"
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
