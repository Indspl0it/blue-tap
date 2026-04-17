"""HCI traffic capture and pairing mode detection.

Owns ``HCICapture`` and ``detect_pairing_mode`` (both used by assessment/
exploitation/fuzzing) plus the native ``HciCaptureModule`` registered for
``reconnaissance.hci_capture``.
"""

import json
import logging
import os
import re
import signal
import subprocess
import tempfile
import time

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import (
    OptAddress,
    OptBool,
    OptInt,
    OptPath,
    OptString,
)
from blue_tap.framework.registry import ModuleFamily
from blue_tap.utils.bt_helpers import check_tool, run_cmd
from blue_tap.utils.output import error, info, success, warning

logger = logging.getLogger(__name__)


class HCICapture:
    """Capture raw HCI traffic using btmon.

    Supports both text log output and binary pcap/btsnoop format for
    Wireshark analysis.
    """

    _PID_DIR = os.path.join(os.path.expanduser("~"), ".blue_tap")
    PID_FILE = os.path.join(_PID_DIR, "btmon.pid")

    def __init__(self):
        self.process: subprocess.Popen | None = None
        self.output_file: str | None = None
        self._fh = None

    def start(self, output_file: str = "bt_capture.log",
              hci: str | None = None, pcap: bool = False) -> bool:
        """Start btmon capture in the background.

        Args:
            output_file: Path to write captured HCI traffic.
            hci: Optional HCI adapter index to capture (e.g., "<hciX>").
                 If None, captures from all interfaces.
            pcap: If True, write btsnoop binary format (for Wireshark).
                  If False, write human-readable text log.

        Returns:
            True if btmon launched successfully.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        if not check_tool("btmon"):
            error("btmon not found — install bluez-utils")
            return False

        # Check for stale PID file / already running capture
        if os.path.exists(self.PID_FILE):
            pgid, pid, _ = self._read_pid_file()
            if pid is not None:
                try:
                    os.kill(pid, 0)  # Check if process exists
                    warning("btmon capture already running — stop it first with capture-stop")
                    return False
                except OSError:
                    # Process is dead, clean up stale PID file
                    try:
                        os.unlink(self.PID_FILE)
                    except OSError:
                        pass

        try:
            cmd = ["sudo", "btmon"]
            if pcap:
                # -w writes btsnoop format, openable in Wireshark
                cmd.extend(["-w", output_file])
                self._fh = None
            else:
                self._fh = open(output_file, "w")

            if hci is not None:
                # btmon uses index number, not "hci0" — extract the number
                idx = hci.replace("hci", "")
                cmd.extend(["-i", idx])

            if pcap:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    # Use process group so we can kill btmon (not just sudo)
                    preexec_fn=os.setsid,
                )
            else:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=self._fh,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
            self.output_file = output_file

            # Persist PID (process group ID) so a separate stop invocation
            # can find and kill the entire process group
            os.makedirs(self._PID_DIR, exist_ok=True)
            pid_data = json.dumps({
                "pgid": os.getpgid(self.process.pid),
                "pid": self.process.pid,
                "output_file": output_file,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
            # Atomic write: write to temp file then rename
            tmp_pid = self.PID_FILE + ".tmp"
            with open(tmp_pid, "w") as pf:
                pf.write(pid_data)
            os.replace(tmp_pid, self.PID_FILE)

            info(f"btmon capture started -> {output_file}"
                 f"{' (btsnoop/pcap)' if pcap else ''}")
            return True
        except Exception as exc:
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
            # Same-process path: kill the entire process group
            try:
                pgid = os.getpgid(self.process.pid)
                os.killpg(pgid, signal.SIGTERM)
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    self.process.wait(timeout=3)
                except OSError:
                    pass
            self.process = None
        else:
            # Cross-invocation path: recover PGID from file
            pgid, pid, output = self._read_pid_file()
            if pgid is None and pid is None:
                warning("No btmon process to stop")
                return self.output_file or ""
            self.output_file = output

            # Kill by process group first (catches both sudo and btmon)
            try:
                if pgid is not None:
                    os.killpg(pgid, signal.SIGTERM)
                elif pid is not None:
                    os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                # Verify dead
                try:
                    if pgid is not None:
                        os.killpg(pgid, 0)
                        os.killpg(pgid, signal.SIGKILL)
                    elif pid is not None:
                        os.kill(pid, 0)
                        os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass  # already dead
            except OSError:
                pass  # already dead

        # Close the stdout file handle
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

    def status(self) -> dict:
        """Get capture status including runtime and output size."""
        running = self.is_running()
        result = {"running": running, "output_file": None, "size_bytes": 0, "started_at": None}

        try:
            with open(self.PID_FILE) as pf:
                data = json.load(pf)
            result["output_file"] = data.get("output_file")
            result["started_at"] = data.get("started_at")
        except (OSError, json.JSONDecodeError):
            pass

        if result["output_file"]:
            try:
                result["size_bytes"] = os.path.getsize(result["output_file"])
            except OSError:
                pass

        return result

    def is_running(self) -> bool:
        """Check whether btmon is still running."""
        if self.process is not None:
            return self.process.poll() is None

        # Fall back to PID file for cross-invocation checks
        try:
            with open(self.PID_FILE) as pf:
                data = json.load(pf)
            pid = data["pid"]
            os.kill(pid, 0)  # signal 0 = existence check
            return True
        except (OSError, KeyError, json.JSONDecodeError, ValueError):
            return False

    @classmethod
    def _read_pid_file(cls) -> tuple[int | None, int | None, str | None]:
        """Read PGID, PID, and output_file from the PID file.

        Returns:
            (pgid, pid, output_file) or (None, None, None) if unavailable.
        """
        try:
            with open(cls.PID_FILE) as pf:
                data = json.load(pf)
            return data.get("pgid"), data.get("pid"), data.get("output_file")
        except (OSError, KeyError, json.JSONDecodeError, ValueError):
            return None, None, None


def detect_pairing_mode(address: str, hci: str | None = None) -> dict:
    """Probe a device's pairing capabilities via btmon + bluetoothctl.

    Initiates (then cancels) a pairing attempt while monitoring HCI traffic
    to extract IO capability, SSP support, and the negotiated pairing method.

    Args:
        address: Target BD_ADDR (e.g. "AA:BB:CC:DD:EE:FF").
        hci: HCI adapter to use.

    Returns:
        Dict with keys: ssp_supported, io_capability, pairing_method, raw_excerpt.
    """
    if hci is None:

        from blue_tap.hardware.adapter import resolve_active_hci

        hci = resolve_active_hci()
    result = {
        "ssp_supported": None,
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
    if not cap.start(tmp_path, hci=hci):
        warning("HCI capture failed to start — SSP result is inconclusive")
        return result

    try:
        # Give btmon time to attach to the HCI interface
        time.sleep(2)

        # Initiate a pairing attempt via bluetoothctl
        proc = None
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Select the adapter first
            proc.stdin.write(f"select {hci}\n".encode())
            proc.stdin.flush()
            time.sleep(0.5)
            proc.stdin.write(f"pair {address}\n".encode())
            proc.stdin.flush()
            # Wait for pairing negotiation to happen
            time.sleep(6)
            proc.stdin.write(b"quit\n")
            proc.stdin.flush()
            proc.wait(timeout=5)
        except Exception as exc:
            warning(f"bluetoothctl pairing probe error: {exc}")
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)

        cap.stop()

        # Parse btmon output
        try:
            with open(tmp_path, errors="replace") as fh:
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
                                            "numeric comparison", "passkey",
                                            "out of band")):
                relevant.append(line.rstrip())
                if "just works" in lower:
                    result["pairing_method"] = "Just Works"
                elif "numeric comparison" in lower:
                    result["pairing_method"] = "Numeric Comparison"
                elif "passkey" in lower:
                    result["pairing_method"] = "Passkey Entry"
                elif "out of band" in lower:
                    result["pairing_method"] = "Out of Band (OOB)"

            # Also capture link key type indications
            if "link key" in lower:
                relevant.append(line.rstrip())

        result["raw_excerpt"] = "\n".join(relevant[:20])

        # If we got HCI data but no SSP indicators, SSP is likely unsupported
        if result["ssp_supported"] is None and lines:
            result["ssp_supported"] = False

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


# ── Native Module class ─────────────────────────────────────────────────────

class HciCaptureModule(Module):
    """HCI Capture.

    Record HCI traffic to a pcap (btsnoop) or text log for offline analysis.
    Uses ``HCICapture.start()``, sleeps for the requested DURATION, then
    calls ``stop()``. A btmon process must be able to spawn (requires
    ``btmon`` in PATH and sudo where BlueZ restricts raw access).

    The RHOST + FILTER_TARGET options are exposed for future hci-level
    filtering via `btmon -d` and are persisted into ``module_data`` so
    downstream tooling can correlate the capture with a specific target.
    """

    module_id = "reconnaissance.hci_capture"
    family = ModuleFamily.RECONNAISSANCE
    name = "HCI Capture"
    description = "Record HCI traffic to pcap for offline analysis"
    protocols = ("Classic", "BLE", "HCI")
    requires = ("adapter",)
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = False
    references = ()
    options = (
        OptString("HCI", default="", description="HCI adapter to capture on"),
        OptInt("DURATION", default=30, description="Capture duration in seconds"),
        OptPath("OUTPUT", default="hci_capture.pcap", description="Output file path"),
        OptBool("PCAP", default=True, description="Write btsnoop/pcap binary (Wireshark) instead of text log"),
        OptBool("FILTER_TARGET", default=False, description="Annotate capture with target metadata"),
        OptAddress("RHOST", required=False, description="Target address for annotation"),
    )

    def run(self, ctx: RunContext) -> dict:
        hci = str(ctx.options.get("HCI", ""))
        duration = int(ctx.options.get("DURATION", 30))
        output = str(ctx.options.get("OUTPUT", "hci_capture.pcap"))
        pcap = bool(ctx.options.get("PCAP", True))
        filter_target = bool(ctx.options.get("FILTER_TARGET", False))
        target = str(ctx.options.get("RHOST", "") or "") if filter_target else ""
        started_at = ctx.started_at

        capture = HCICapture()
        error_msg: str | None = None
        started_ok = False
        duration_actual = 0
        size_bytes = 0

        try:
            started_ok = capture.start(output_file=output, hci=hci, pcap=pcap)
            if not started_ok:
                error_msg = "btmon failed to start (missing tool, adapter busy, or permissions)"
            else:
                t0 = time.monotonic()
                try:
                    while time.monotonic() - t0 < duration:
                        if not capture.is_running():
                            error_msg = "btmon exited before duration elapsed"
                            break
                        remaining = duration - (time.monotonic() - t0)
                        if remaining <= 0:
                            break
                        time.sleep(min(1.0, remaining))
                finally:
                    capture.stop()
                    duration_actual = int(time.monotonic() - t0)
        except Exception as exc:
            logger.exception("HCI capture failed (hci=%s, output=%s)", hci, output)
            error_msg = str(exc)
            try:
                capture.stop()
            except Exception:
                pass

        try:
            if os.path.exists(output):
                size_bytes = os.path.getsize(output)
        except OSError:
            size_bytes = 0

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        else:
            execution_status = "completed"
            outcome = "observed" if size_bytes > 0 else "not_applicable"

        summary_text = (
            f"HCI capture error: {error_msg}"
            if error_msg
            else f"Captured {size_bytes} bytes over {duration_actual}s to {output}"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="hci_capture",
                    kind="collector",
                    id="hci_capture",
                    title="HCI Traffic Capture",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "output": output,
                            "size_bytes": size_bytes,
                            "duration_s": duration_actual,
                            "pcap": pcap,
                            "error": error_msg,
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "output": output,
                "size_bytes": size_bytes,
                "duration_s": duration_actual,
                "error": error_msg,
            },
            module_data={
                "output": output,
                "pcap": pcap,
                "filter_target": filter_target,
                "target": target,
                "size_bytes": size_bytes,
            },
            run_id=ctx.run_id,
        )
