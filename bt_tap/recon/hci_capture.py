"""HCI traffic capture and pairing mode detection."""

import json
import os
import re
import signal
import subprocess
import tempfile
import time

from bt_tap.utils.bt_helpers import check_tool, run_cmd
from bt_tap.utils.output import error, info, success, warning


class HCICapture:
    """Capture raw HCI traffic using btmon."""

    PID_FILE = "/tmp/bt_tap_btmon.pid"

    def __init__(self):
        self.process: subprocess.Popen | None = None
        self.output_file: str | None = None
        self._fh = None

    def start(self, output_file: str = "bt_capture.log") -> bool:
        """Start btmon capture in the background.

        Args:
            output_file: Path to write captured HCI traffic.

        Returns:
            True if btmon launched successfully.
        """
        if not check_tool("btmon"):
            error("btmon not found — install bluez-utils")
            return False

        try:
            self._fh = open(output_file, "w")
            self.process = subprocess.Popen(
                ["sudo", "btmon"],
                stdout=self._fh,
                stderr=subprocess.DEVNULL,
            )
            self.output_file = output_file

            # Persist PID so a separate stop invocation can find the process
            with open(self.PID_FILE, "w") as pf:
                json.dump(
                    {"pid": self.process.pid, "output_file": output_file}, pf
                )

            info(f"btmon capture started -> {output_file}")
            return True
        except OSError as exc:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
            error(f"Failed to start btmon: {exc}")
            return False

    def stop(self) -> str:
        """Stop the btmon capture.

        Returns:
            Path to the output file.
        """
        if self.process is not None:
            # Same-process path: we launched btmon in this invocation
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            self.process = None
        else:
            # Cross-invocation path: recover PID from file
            pid, output = self._read_pid_file()
            if pid is None:
                warning("No btmon process to stop")
                return self.output_file or ""
            self.output_file = output
            try:
                os.kill(pid, signal.SIGTERM)
                # Not our child, so waitpid may fail; just give it time
                time.sleep(1)
                # If still alive, force kill
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            except OSError:
                pass  # already dead

        # Close the stdout file handle to avoid resource leak
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

        # Remove PID file
        try:
            os.unlink(self.PID_FILE)
        except OSError:
            pass

        success("btmon capture stopped")
        return self.output_file or ""

    def is_running(self) -> bool:
        """Check whether btmon is still running."""
        if self.process is not None:
            return self.process.poll() is None

        # Fall back to PID file for cross-invocation checks
        try:
            with open(self.PID_FILE, "r") as pf:
                data = json.load(pf)
            pid = data["pid"]
            os.kill(pid, 0)  # signal 0 = existence check
            return True
        except (OSError, KeyError, json.JSONDecodeError, ValueError):
            return False

    @classmethod
    def _read_pid_file(cls) -> tuple[int | None, str | None]:
        """Read PID and output_file from the PID file.

        Returns:
            (pid, output_file) or (None, None) if unavailable.
        """
        try:
            with open(cls.PID_FILE, "r") as pf:
                data = json.load(pf)
            return data["pid"], data.get("output_file")
        except (OSError, KeyError, json.JSONDecodeError, ValueError):
            return None, None


def detect_pairing_mode(address: str, hci: str = "hci0") -> dict:
    """Probe a device's pairing capabilities via btmon + bluetoothctl.

    Initiates (then cancels) a pairing attempt while monitoring HCI traffic
    to extract IO capability, SSP support, and the negotiated pairing method.

    Args:
        address: Target BD_ADDR (e.g. "AA:BB:CC:DD:EE:FF").
        hci: HCI adapter to use.

    Returns:
        Dict with keys: ssp_supported, io_capability, pairing_method, raw_excerpt.
    """
    result = {
        "ssp_supported": False,
        "io_capability": "Unknown",
        "pairing_method": "Unknown",
        "raw_excerpt": "",
    }

    tmp = tempfile.NamedTemporaryFile(
        prefix="bttap_hci_", suffix=".log", delete=False
    )
    tmp_path = tmp.name
    tmp.close()

    cap = HCICapture()
    if not cap.start(tmp_path):
        return result

    try:
        # Give btmon a moment to attach
        time.sleep(1)

        # Initiate a pairing attempt via bluetoothctl
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.stdin.write(f"pair {address}\n".encode())
            proc.stdin.flush()
            time.sleep(4)
            proc.stdin.write(b"quit\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
        except Exception as exc:
            warning(f"bluetoothctl pairing probe error: {exc}")

        cap.stop()

        # Parse btmon output
        try:
            with open(tmp_path, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            lines = []

        relevant: list[str] = []
        for line in lines:
            lower = line.lower()

            if "io capability" in lower:
                relevant.append(line.rstrip())
                m = re.search(r"IO Capability:\s*(.+)", line, re.IGNORECASE)
                if m:
                    result["io_capability"] = m.group(1).strip()

            if "authentication" in lower:
                relevant.append(line.rstrip())
                if "ssp" in lower or "secure simple" in lower:
                    result["ssp_supported"] = True

            if any(kw in lower for kw in ("pairing method", "just works",
                                            "numeric comparison", "passkey")):
                relevant.append(line.rstrip())
                if "just works" in lower:
                    result["pairing_method"] = "Just Works"
                elif "numeric comparison" in lower:
                    result["pairing_method"] = "Numeric Comparison"
                elif "passkey" in lower:
                    result["pairing_method"] = "Passkey Entry"

        result["raw_excerpt"] = "\n".join(relevant[:20])

        # Cancel / remove the pairing so we don't leave state behind
        run_cmd(["bluetoothctl", "cancel-pairing", address], timeout=5)
        run_cmd(["bluetoothctl", "remove", address], timeout=5)
    finally:
        # Clean up temp file even on exceptions
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return result
