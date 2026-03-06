"""RFCOMM Channel Scanner — probe channels 1-30 for open services."""

import errno
import socket

from bt_tap.utils.output import info, success, error, warning


class RFCOMMScanner:
    """Scan and probe RFCOMM channels on a remote Bluetooth device."""

    PROBE_BYTES = [b"\r\n", b"AT\r\n"]
    MAX_CHANNEL = 30

    def __init__(self, address: str):
        self.address = address

    def scan_all_channels(self, timeout_per_ch: float = 2.0) -> list[dict]:
        """Try connecting to RFCOMM channels 1-30.

        Returns a list of dicts with keys: channel, status, response_type.
        Status is one of: open, closed, timeout.
        """
        info(f"Scanning RFCOMM channels 1-{self.MAX_CHANNEL} on {self.address}...")
        results = []

        for ch in range(1, self.MAX_CHANNEL + 1):
            result = self.probe_channel(ch, timeout=timeout_per_ch)
            tag = result["status"]
            if tag == "open":
                success(f"  Channel {ch:>2}: OPEN ({result['response_type']})")
            elif tag == "timeout":
                warning(f"  Channel {ch:>2}: TIMEOUT")
            results.append(result)

        open_count = sum(1 for r in results if r["status"] == "open")
        success(f"Scan complete — {open_count} open channel(s) found")
        return results

    def probe_channel(self, channel: int, timeout: float = 2.0) -> dict:
        """Connect to a single RFCOMM channel and classify the response.

        Response types: at_modem, obex, raw_data, refused, timeout.
        """
        result = {
            "channel": channel,
            "status": "closed",
            "response_type": "refused",
            "raw_response": b"",
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
        )
        sock.settimeout(timeout)

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
            result["response_type"] = "refused"
            return result

        # Connection succeeded — channel is open
        result["status"] = "open"

        try:
            # Send probes one at a time, read response after each
            # to avoid corrupting the response stream
            data = b""
            for probe in self.PROBE_BYTES:
                try:
                    sock.sendall(probe)
                    sock.settimeout(timeout)
                    chunk = sock.recv(1024)
                    if chunk:
                        data = chunk
                        break  # Got a response, classify it
                except socket.timeout:
                    continue
                except OSError:
                    break

            result["raw_response"] = data

            if data.startswith(b"\x00") or b"\xcb" in data[:4]:
                result["response_type"] = "obex"
            elif b"OK" in data or b"ERROR" in data or b"AT" in data.upper():
                result["response_type"] = "at_modem"
            elif len(data) > 0:
                result["response_type"] = "raw_data"
            else:
                result["response_type"] = "raw_data"

        except OSError:
            result["response_type"] = "raw_data"
        finally:
            sock.close()

        return result

    def find_hidden_services(self, sdp_channels: list[int]) -> list[dict]:
        """Diff open RFCOMM channels against known SDP-advertised channels.

        Returns channels that are open but NOT listed in SDP — potential
        hidden/debug services.
        """
        info("Checking for hidden (unadvertised) RFCOMM services...")
        all_results = self.scan_all_channels()
        open_channels = [r for r in all_results if r["status"] == "open"]

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
