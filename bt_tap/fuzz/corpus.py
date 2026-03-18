"""Seed corpus management for Bluetooth protocol fuzzing.

Provides persistent storage and retrieval of seed inputs organised by
protocol.  Seeds can be loaded from disk, generated from built-in
templates, or imported from pcap/btsnoop captures.  Interesting inputs
discovered during fuzzing are saved separately for triage.
"""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# CorpusStats — summary statistics
# ---------------------------------------------------------------------------

@dataclass
class CorpusStats:
    """Summary statistics for a :class:`Corpus` instance."""

    total_seeds: int = 0
    protocols: list[str] = field(default_factory=list)
    interesting_count: int = 0
    size_bytes: int = 0


# ---------------------------------------------------------------------------
# Corpus — seed corpus manager
# ---------------------------------------------------------------------------

class Corpus:
    """Manage seed inputs on disk, organised by protocol.

    Directory layout::

        base_dir/
          <protocol>/
            <name>.bin            # seed files
            interesting/
              <reason>_<hash>.bin # inputs that triggered new behaviour
    """

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.seeds: dict[str, list[bytes]] = {}
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_directory(self, path: str) -> int:
        """Load ``.bin`` files from *path* into the corpus.

        Files are expected to be in ``<path>/<protocol>/<name>.bin``
        layout.  Returns the number of seeds loaded.
        """
        loaded = 0
        root = Path(path)
        if not root.is_dir():
            return 0

        for proto_dir in sorted(root.iterdir()):
            if not proto_dir.is_dir():
                continue
            protocol = proto_dir.name
            if protocol == "interesting":
                continue
            for bin_file in sorted(proto_dir.glob("*.bin")):
                try:
                    data = bin_file.read_bytes()
                    if data:
                        self.seeds.setdefault(protocol, []).append(data)
                        loaded += 1
                except OSError:
                    continue
        return loaded

    # ------------------------------------------------------------------
    # Adding seeds
    # ------------------------------------------------------------------

    def add_seed(self, protocol: str, data: bytes, name: str = "") -> None:
        """Add a seed to the corpus and persist it to disk.

        Saved as ``base_dir/<protocol>/<name>.bin``.  If *name* is empty
        a SHA-256 hash of the data is used.
        """
        if not data:
            return

        self.seeds.setdefault(protocol, []).append(data)

        proto_dir = Path(self.base_dir) / protocol
        proto_dir.mkdir(parents=True, exist_ok=True)

        if not name:
            name = hashlib.sha256(data).hexdigest()[:16]
        if not name.endswith(".bin"):
            name += ".bin"

        dest = proto_dir / name
        dest.write_bytes(data)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_random_seed(self, protocol: str) -> bytes | None:
        """Return a random seed for *protocol*, or ``None`` if none exist."""
        pool = self.seeds.get(protocol)
        if not pool:
            return None
        return random.choice(pool)

    def get_all_seeds(self, protocol: str) -> list[bytes]:
        """Return all seeds for a given protocol."""
        return list(self.seeds.get(protocol, []))

    # ------------------------------------------------------------------
    # Interesting inputs
    # ------------------------------------------------------------------

    def save_interesting(self, protocol: str, data: bytes, reason: str) -> None:
        """Save an interesting input to ``base_dir/<protocol>/interesting/``.

        The filename encodes the *reason* and a content hash for
        deduplication.
        """
        if not data:
            return

        interesting_dir = Path(self.base_dir) / protocol / "interesting"
        interesting_dir.mkdir(parents=True, exist_ok=True)

        content_hash = hashlib.sha256(data).hexdigest()[:16]
        safe_reason = "".join(c if c.isalnum() or c in "-_" else "_" for c in reason)
        filename = f"{safe_reason}_{content_hash}.bin"

        dest = interesting_dir / filename
        if not dest.exists():
            dest.write_bytes(data)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def seed_count(self, protocol: str | None = None) -> int:
        """Return the number of seeds, optionally filtered by *protocol*."""
        if protocol is not None:
            return len(self.seeds.get(protocol, []))
        return sum(len(v) for v in self.seeds.values())

    def list_protocols(self) -> list[str]:
        """Return protocols that have at least one seed."""
        return sorted(p for p, seeds in self.seeds.items() if seeds)

    def stats(self) -> CorpusStats:
        """Compute summary statistics for the corpus."""
        total = 0
        size = 0
        interesting = 0

        for protocol, seeds in self.seeds.items():
            total += len(seeds)
            size += sum(len(s) for s in seeds)

        # Count interesting files on disk
        base = Path(self.base_dir)
        if base.is_dir():
            for proto_dir in base.iterdir():
                if not proto_dir.is_dir():
                    continue
                int_dir = proto_dir / "interesting"
                if int_dir.is_dir():
                    interesting += sum(1 for f in int_dir.glob("*.bin"))

        return CorpusStats(
            total_seeds=total,
            protocols=self.list_protocols(),
            interesting_count=interesting,
            size_bytes=size,
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def minimize(self) -> int:
        """Deduplicate seeds by SHA-256 content hash.

        Returns the number of duplicates removed.
        """
        removed = 0
        for protocol in list(self.seeds):
            seen: set[str] = set()
            unique: list[bytes] = []
            for seed in self.seeds[protocol]:
                h = hashlib.sha256(seed).hexdigest()
                if h not in seen:
                    seen.add(h)
                    unique.append(seed)
                else:
                    removed += 1
            self.seeds[protocol] = unique
        return removed

    # ------------------------------------------------------------------
    # Built-in seed generation
    # ------------------------------------------------------------------

    def generate_builtin_seeds(self, protocol: str) -> list[bytes]:
        """Generate valid baseline packets for *protocol*.

        These are minimal-but-valid packets that serve as a starting
        point for mutation.  Actual protocol-specific generation will be
        implemented when protocol builders (TASK 2.x) are complete.

        Currently returns placeholder seeds that are structurally
        representative of each protocol.
        """
        generators = {
            "l2cap": self._builtin_l2cap,
            "sdp": self._builtin_sdp,
            "rfcomm": self._builtin_rfcomm,
            "obex": self._builtin_obex,
            "at": self._builtin_at,
            "att": self._builtin_att,
            "smp": self._builtin_smp,
            "bnep": self._builtin_bnep,
        }

        generator = generators.get(protocol.lower())
        if generator is None:
            return []

        seeds = generator()
        for i, seed in enumerate(seeds):
            self.add_seed(protocol, seed, name=f"builtin_{i:03d}")
        return seeds

    # -- Placeholder seed generators --

    @staticmethod
    def _builtin_l2cap() -> list[bytes]:
        """L2CAP signaling command seeds."""
        seeds = []
        # Connection Request (code=0x02)
        seeds.append(bytes([
            0x02,  # Connection Request
            0x01,  # Identifier
            0x04, 0x00,  # Length = 4
            0x01, 0x00,  # PSM = SDP (0x0001)
            0x40, 0x00,  # Source CID
        ]))
        # Configuration Request (code=0x04)
        seeds.append(bytes([
            0x04,  # Configuration Request
            0x02,  # Identifier
            0x08, 0x00,  # Length = 8
            0x40, 0x00,  # Destination CID
            0x00, 0x00,  # Flags
            0x01, 0x02, 0x00, 0x40,  # MTU option: type=1, len=2, value=64
        ]))
        # Disconnection Request (code=0x06)
        seeds.append(bytes([
            0x06,  # Disconnection Request
            0x03,  # Identifier
            0x04, 0x00,  # Length = 4
            0x40, 0x00,  # Destination CID
            0x41, 0x00,  # Source CID
        ]))
        # Information Request (code=0x0A)
        seeds.append(bytes([
            0x0A,  # Information Request
            0x04,  # Identifier
            0x02, 0x00,  # Length = 2
            0x02, 0x00,  # InfoType = Extended Features
        ]))
        # Echo Request (code=0x08)
        seeds.append(bytes([
            0x08,  # Echo Request
            0x05,  # Identifier
            0x04, 0x00,  # Length = 4
            0xDE, 0xAD, 0xBE, 0xEF,  # Payload
        ]))
        return seeds

    @staticmethod
    def _builtin_sdp() -> list[bytes]:
        """SDP PDU seeds."""
        seeds = []
        # ServiceSearchRequest (PDU ID = 0x02)
        seeds.append(bytes([
            0x02,        # SDP_ServiceSearchRequest
            0x00, 0x01,  # Transaction ID
            0x00, 0x08,  # Parameter length
            0x35, 0x03, 0x19, 0x01, 0x00,  # UUID: L2CAP (0x0100)
            0x00, 0x0A,  # MaxServiceRecordCount
            0x00,        # ContinuationState = 0
        ]))
        # ServiceAttributeRequest (PDU ID = 0x04)
        seeds.append(bytes([
            0x04,        # SDP_ServiceAttributeRequest
            0x00, 0x02,  # Transaction ID
            0x00, 0x0D,  # Parameter length
            0x00, 0x01, 0x00, 0x01,  # ServiceRecordHandle
            0x00, 0x40,  # MaximumAttributeByteCount
            0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF,  # Attr range 0x0000-0xFFFF
            0x00,        # ContinuationState = 0
        ]))
        # ServiceSearchAttributeRequest (PDU ID = 0x06)
        seeds.append(bytes([
            0x06,        # SDP_ServiceSearchAttributeRequest
            0x00, 0x03,  # Transaction ID
            0x00, 0x11,  # Parameter length
            0x35, 0x03, 0x19, 0x01, 0x00,  # UUID: L2CAP
            0x00, 0x40,  # MaximumAttributeByteCount
            0x35, 0x05, 0x0A, 0x00, 0x00, 0xFF, 0xFF,  # Attr range
            0x00,        # ContinuationState = 0
        ]))
        return seeds

    @staticmethod
    def _builtin_rfcomm() -> list[bytes]:
        """RFCOMM frame seeds (raw L2CAP PSM 3)."""
        seeds = []
        # SABM on DLCI 0 (control channel)
        seeds.append(bytes([
            0x03,  # Address: DLCI=0, EA=1, C/R=1
            0x3F,  # Control: SABM (0x2F | P/F=1)
            0x01,  # Length: 0 (EA=1)
            0x1C,  # FCS (placeholder)
        ]))
        # SABM on DLCI 2 (data channel 1)
        seeds.append(bytes([
            0x0B,  # Address: DLCI=2, EA=1
            0x3F,  # Control: SABM
            0x01,  # Length: 0
            0x59,  # FCS (placeholder)
        ]))
        # UIH frame with data on DLCI 2
        seeds.append(bytes([
            0x0B,  # Address: DLCI=2
            0xEF,  # Control: UIH
            0x09,  # Length: 4 (EA=1, len=4)
            0x41, 0x54, 0x0D, 0x0A,  # "AT\r\n"
            0xAA,  # FCS (placeholder)
        ]))
        return seeds

    @staticmethod
    def _builtin_obex() -> list[bytes]:
        """OBEX packet seeds."""
        seeds = []
        # Connect
        seeds.append(bytes([
            0x80,        # Connect opcode
            0x00, 0x07,  # Packet length
            0x10,        # OBEX version 1.0
            0x00,        # Flags
            0x20, 0x00,  # Max packet length = 8192
        ]))
        # Get (Final)
        seeds.append(bytes([
            0x83,        # GET | Final
            0x00, 0x03,  # Packet length (no headers)
        ]))
        # Put (Final)
        seeds.append(bytes([
            0x82,        # PUT | Final
            0x00, 0x03,  # Packet length (no headers)
        ]))
        # Disconnect
        seeds.append(bytes([
            0x81,        # Disconnect
            0x00, 0x03,  # Packet length
        ]))
        return seeds

    @staticmethod
    def _builtin_at() -> list[bytes]:
        """AT command seeds for HFP/modem fuzzing."""
        commands = [
            b"AT\r\n",
            b"AT+BRSF=127\r\n",
            b"AT+CIND=?\r\n",
            b"AT+CIND?\r\n",
            b"AT+CMER=3,0,0,1\r\n",
            b"AT+CPBR=1,10\r\n",
            b'AT+CMGL="ALL"\r\n',
            b"AT+COPS?\r\n",
            b"AT+CLIP=1\r\n",
            b"ATD1234567890;\r\n",
        ]
        return commands

    @staticmethod
    def _builtin_att() -> list[bytes]:
        """BLE ATT PDU seeds."""
        seeds = []
        # Exchange MTU Request (opcode=0x02)
        seeds.append(bytes([0x02, 0x00, 0x02]))  # MTU=512
        # Find Information Request (opcode=0x04)
        seeds.append(bytes([0x04, 0x01, 0x00, 0xFF, 0xFF]))
        # Read By Group Type Request (opcode=0x10) — primary services
        seeds.append(bytes([
            0x10,
            0x01, 0x00,  # Start handle
            0xFF, 0xFF,  # End handle
            0x00, 0x28,  # UUID: Primary Service (0x2800)
        ]))
        # Read Request (opcode=0x0A)
        seeds.append(bytes([0x0A, 0x01, 0x00]))
        # Write Request (opcode=0x12)
        seeds.append(bytes([0x12, 0x01, 0x00, 0x01]))
        return seeds

    @staticmethod
    def _builtin_smp() -> list[bytes]:
        """BLE SMP command seeds."""
        seeds = []
        # Pairing Request — Just Works
        seeds.append(bytes([
            0x01,  # Pairing Request
            0x03,  # IO Capability: NoInputNoOutput
            0x00,  # OOB: not present
            0x01,  # AuthReq: Bonding
            0x10,  # Max Encryption Key Size: 16
            0x07,  # Initiator Key Distribution
            0x07,  # Responder Key Distribution
        ]))
        # Pairing Request — Secure Connections
        seeds.append(bytes([
            0x01,  # Pairing Request
            0x03,  # IO Capability: NoInputNoOutput
            0x00,  # OOB: not present
            0x09,  # AuthReq: Bonding | SC
            0x10,  # Max Encryption Key Size: 16
            0x0F,  # Initiator Key Distribution
            0x0F,  # Responder Key Distribution
        ]))
        return seeds

    @staticmethod
    def _builtin_bnep() -> list[bytes]:
        """BNEP control message seeds."""
        seeds = []
        # BNEP Setup Connection Request
        seeds.append(bytes([
            0x01,        # BNEP_SETUP_CONNECTION_REQUEST_MSG
            0x02,        # UUID Size: 2
            0x11, 0x16,  # Destination UUID: PAN-NAP
            0x11, 0x15,  # Source UUID: PANU
        ]))
        # BNEP Filter Net Type Set
        seeds.append(bytes([
            0x03,        # BNEP_FILTER_NET_TYPE_SET_MSG
            0x00, 0x04,  # List length
            0x08, 0x00,  # Start: IPv4
            0x08, 0x00,  # End: IPv4
        ]))
        return seeds
