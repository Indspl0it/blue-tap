"""Crash database for the Bluetooth fuzzer.

Stores every crash and anomaly with the exact payload, deduplicates by
SHA-256 hash, and supports querying, reproduction, and JSON export.
The database uses SQLite for zero-dependency persistence.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from enum import Enum
from typing import TYPE_CHECKING

from blue_tap.utils.output import info, warning

if TYPE_CHECKING:
    from blue_tap.modules.fuzzing.transport import BluetoothTransport


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CrashSeverity(str, Enum):
    """Severity classification for fuzzer-triggered anomalies.

    Inherits from ``str`` so values serialize cleanly to JSON/SQL.
    """

    CRITICAL = "CRITICAL"
    """Device reboot, firmware crash, or persistent DoS."""

    HIGH = "HIGH"
    """Connection drop with device becoming temporarily unreachable."""

    MEDIUM = "MEDIUM"
    """Unexpected error response or protocol violation."""

    LOW = "LOW"
    """Minor anomaly such as unusual timing or partial response."""

    INFO = "INFO"
    """Informational — notable but not clearly a bug."""


class CrashType(str, Enum):
    """Classification of crash trigger mechanism."""

    CONNECTION_DROP = "connection_drop"
    """Remote device dropped the connection unexpectedly."""

    TIMEOUT = "timeout"
    """Remote device stopped responding (possible hang/crash)."""

    UNEXPECTED_RESPONSE = "unexpected_response"
    """Response did not match any valid protocol reply."""

    DEVICE_DISAPPEARED = "device_disappeared"
    """Device became completely unreachable (possible reboot)."""

    ERROR_RESPONSE = "error_response"
    """Device sent an explicit error code."""

    HANG = "hang"
    """Device accepted the connection but stopped processing."""


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS crashes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL DEFAULT (datetime('now')),
    target_addr         TEXT    NOT NULL,
    protocol            TEXT    NOT NULL,
    payload_hex         TEXT    NOT NULL,
    payload_len         INTEGER NOT NULL,
    payload_description TEXT,
    crash_type          TEXT    NOT NULL CHECK(crash_type IN (
        'connection_drop', 'timeout', 'unexpected_response',
        'device_disappeared', 'error_response', 'hang'
    )),
    response_hex        TEXT,
    response_description TEXT,
    session_id          TEXT,
    mutation_log        TEXT,
    reproduced          INTEGER DEFAULT 0,
    severity            TEXT CHECK(severity IN (
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    )),
    notes               TEXT,
    payload_hash        TEXT    NOT NULL,
    crash_signature     TEXT,
    packet_sequence_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_crashes_hash     ON crashes(payload_hash);
CREATE INDEX IF NOT EXISTS idx_crashes_protocol ON crashes(protocol);
CREATE INDEX IF NOT EXISTS idx_crashes_severity ON crashes(severity);
"""

# Index on crash_signature is created separately after the migration guard so
# it is safe to run against both new databases (where the column is in the
# CREATE TABLE) and existing databases that received the column via ALTER TABLE.
_SIGNATURE_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_crashes_signature ON crashes(crash_signature);"
)


# ---------------------------------------------------------------------------
# CrashDB
# ---------------------------------------------------------------------------

class CrashDB:
    """SQLite-backed crash database for fuzzing campaigns.

    Stores every crash-triggering payload with full metadata, deduplicates
    by SHA-256 hash per (target, protocol) tuple, and provides querying,
    reproduction, and export facilities.

    Usage::

        with CrashDB("sessions/my_session/fuzz/crashes.db") as db:
            crash_id = db.log_crash(
                target="AA:BB:CC:DD:EE:FF",
                protocol="l2cap",
                payload=b"\\x00\\x01\\x02",
                crash_type=CrashType.CONNECTION_DROP,
                severity=CrashSeverity.HIGH,
            )
            print(db.get_crash_by_id(crash_id))

    Args:
        db_path: Filesystem path for the SQLite database file.
            Parent directories are created automatically.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        # Ensure parent directory exists
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        """Create the crashes table and indexes if they don't exist.

        Also runs schema migrations for columns added after initial release.
        SQLite does not support ``ADD COLUMN IF NOT EXISTS``; catching
        ``OperationalError`` for "duplicate column name" is the standard
        migration pattern.
        """
        self._conn.executescript(_SCHEMA_SQL)
        # Migration: add crash_signature column (idempotent)
        try:
            self._conn.execute("ALTER TABLE crashes ADD COLUMN crash_signature TEXT")
            self._conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Migration: add packet_sequence_json column (idempotent)
        try:
            self._conn.execute("ALTER TABLE crashes ADD COLUMN packet_sequence_json TEXT")
            self._conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Create signature index now that the column is guaranteed present.
        # Using execute() (not executescript()) so we stay in the WAL transaction.
        self._conn.execute(_SIGNATURE_INDEX_SQL)
        self._conn.commit()

    # -- Hashing ------------------------------------------------------------

    @staticmethod
    def _payload_hash(payload: bytes) -> str:
        """Compute SHA-256 hex digest for deduplication."""
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _compute_signature(crash_type: str, response: bytes | None) -> str:
        """Compute a behavioral crash signature independent of payload bytes.

        The signature is derived from the crash type, the first 32 bytes of
        the response (or empty if no response), and the total response length.
        Two crashes triggered by different payloads but producing the same
        behavioral fingerprint will share a signature and be deduplicated.

        Args:
            crash_type: The crash type string (e.g. ``"connection_drop"``).
            response: Optional raw response bytes from the device.

        Returns:
            SHA-256 hex digest string.
        """
        resp_bytes = response or b""
        raw = crash_type.encode() + resp_bytes[:32] + str(len(resp_bytes)).encode()
        return hashlib.sha256(raw).hexdigest()

    # -- Logging ------------------------------------------------------------

    def log_crash(
        self,
        target: str,
        protocol: str,
        payload: bytes,
        crash_type: CrashType | str,
        response: bytes | None = None,
        severity: CrashSeverity | str | None = None,
        payload_description: str = "",
        response_description: str = "",
        mutation_log: list[str] | str = "",
        session_id: str = "",
        notes: str = "",
        packet_sequence: list[bytes] | None = None,
    ) -> int:
        """Log a crash to the database.

        Deduplicates by ``(target_addr, protocol, crash_signature)`` — a
        behavioral fingerprint derived from crash type and response bytes.
        Two different payloads that produce the same crash behavior are
        treated as the same bug and the existing crash ID is returned.

        Args:
            target: BD_ADDR of the target device.
            protocol: Protocol name (e.g. ``"l2cap"``, ``"rfcomm"``, ``"att"``).
            payload: Raw payload bytes that triggered the crash (primary packet).
            crash_type: How the crash manifested.
            response: Optional raw response bytes from the device.
            severity: Optional severity classification.
            payload_description: Human-readable description of the payload.
            response_description: Human-readable description of the response.
            mutation_log: Mutations applied to reach this payload.  Accepts
                either a ``list[str]`` (stored as JSON array) or a plain
                ``str`` (stored as-is) for backward compatibility.
            session_id: Fuzzing session identifier.
            notes: Free-form notes.
            packet_sequence: Full multi-packet sequence that drove the target
                to the vulnerable state (including setup packets).  If
                provided, each packet is stored as a hex string in a JSON
                array.  Useful for reproducing state-machine crashes.

        Returns:
            The crash ID (integer primary key).
        """
        # Normalize enum values to their string form
        crash_type_str = crash_type.value if isinstance(crash_type, CrashType) else str(crash_type)
        severity_str: str | None = None
        if severity is not None:
            severity_str = severity.value if isinstance(severity, CrashSeverity) else str(severity)

        payload_hex = payload.hex()
        p_hash = self._payload_hash(payload)
        crash_signature = self._compute_signature(crash_type_str, response)

        # Behavioral deduplication: same target + protocol + crash_signature
        existing = self._conn.execute(
            "SELECT id FROM crashes "
            "WHERE target_addr = ? AND protocol = ? AND crash_signature = ?",
            (target, protocol, crash_signature),
        ).fetchone()

        if existing is not None:
            return existing["id"]

        response_hex = response.hex() if response else None

        # Serialize mutation_log: store list as JSON array, str as-is
        if isinstance(mutation_log, list):
            mutation_log_stored: str | None = json.dumps(mutation_log) if mutation_log else None
        else:
            mutation_log_stored = mutation_log or None

        # Serialize packet sequence as JSON array of hex strings
        packet_sequence_json: str | None = None
        if packet_sequence:
            packet_sequence_json = json.dumps([p.hex() for p in packet_sequence])

        cursor = self._conn.execute(
            """INSERT INTO crashes (
                target_addr, protocol, payload_hex, payload_len,
                payload_description, crash_type, response_hex,
                response_description, session_id, mutation_log,
                severity, notes, payload_hash,
                crash_signature, packet_sequence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target, protocol, payload_hex, len(payload),
                payload_description or None, crash_type_str, response_hex,
                response_description or None, session_id or None,
                mutation_log_stored, severity_str, notes or None, p_hash,
                crash_signature, packet_sequence_json,
            ),
        )
        self._conn.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT succeeded but lastrowid is None")
        return cursor.lastrowid

    # -- Queries ------------------------------------------------------------

    def get_crashes(
        self,
        protocol: str | None = None,
        severity: CrashSeverity | str | None = None,
        limit: int = 0,
    ) -> list[dict]:
        """Retrieve crashes, optionally filtered by protocol and/or severity.

        Args:
            protocol: Filter by protocol name (exact match).
            severity: Filter by severity level.
            limit: Maximum number of results (0 = unlimited).

        Returns:
            List of crash dicts ordered by timestamp descending.
        """
        clauses: list[str] = []
        params: list = []

        if protocol is not None:
            clauses.append("protocol = ?")
            params.append(protocol)
        if severity is not None:
            sev = severity.value if isinstance(severity, CrashSeverity) else str(severity)
            clauses.append("severity = ?")
            params.append(sev)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM crashes{where} ORDER BY timestamp DESC"
        if limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_unique_crashes(self) -> list[dict]:
        """Retrieve crashes deduplicated by crash_signature.

        For each unique behavioral fingerprint, returns the first (earliest)
        crash record.  Crashes that share a signature (same bug triggered by
        different payloads) are collapsed to a single representative record.

        Falls back to deduplication by ``payload_hash`` for legacy records
        that pre-date the ``crash_signature`` column.

        Returns:
            List of unique crash dicts ordered by timestamp descending.
        """
        rows = self._conn.execute(
            """SELECT * FROM crashes
               WHERE id IN (
                   SELECT MIN(id) FROM crashes
                   GROUP BY COALESCE(crash_signature, payload_hash)
               )
               ORDER BY timestamp DESC"""
        ).fetchall()
        return [dict(row) for row in rows]

    def get_crash_by_id(self, crash_id: int) -> dict | None:
        """Retrieve a single crash by its database ID.

        Args:
            crash_id: Primary key of the crash record.

        Returns:
            Crash dict, or None if not found.
        """
        row = self._conn.execute(
            "SELECT * FROM crashes WHERE id = ?", (crash_id,)
        ).fetchone()
        return dict(row) if row else None

    def mark_reproduced(self, crash_id: int, reproduced: bool = True) -> None:
        """Mark a crash as reproduced (or not).

        Args:
            crash_id: Primary key of the crash record.
            reproduced: True if the crash was successfully reproduced.
        """
        self._conn.execute(
            "UPDATE crashes SET reproduced = ? WHERE id = ?",
            (1 if reproduced else 0, crash_id),
        )
        self._conn.commit()

    def update_severity(self, crash_id: int, severity: CrashSeverity | str) -> None:
        """Update the severity of a crash record.

        Args:
            crash_id: Primary key of the crash record.
            severity: New severity classification.
        """
        sev = severity.value if isinstance(severity, CrashSeverity) else str(severity)
        self._conn.execute(
            "UPDATE crashes SET severity = ? WHERE id = ?",
            (sev, crash_id),
        )
        self._conn.commit()

    def add_notes(self, crash_id: int, notes: str) -> None:
        """Append notes to a crash record.

        If the crash already has notes, the new text is appended with
        a newline separator.

        Args:
            crash_id: Primary key of the crash record.
            notes: Text to append.
        """
        existing = self.get_crash_by_id(crash_id)
        if existing is None:
            return
        old_notes = existing.get("notes") or ""
        combined = f"{old_notes}\n{notes}".strip() if old_notes else notes
        self._conn.execute(
            "UPDATE crashes SET notes = ? WHERE id = ?",
            (combined, crash_id),
        )
        self._conn.commit()

    # -- Aggregation --------------------------------------------------------

    def crash_count(self, protocol: str | None = None) -> int:
        """Return the total number of crashes, optionally filtered by protocol.

        Args:
            protocol: If specified, count only crashes for this protocol.

        Returns:
            Integer count.
        """
        if protocol:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM crashes WHERE protocol = ?",
                (protocol,),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM crashes"
            ).fetchone()
        return row["cnt"] if row else 0

    def crash_summary(self) -> dict:
        """Return a summary of crashes grouped by protocol and severity.

        Returns:
            Dict with ``total``, ``by_protocol``, ``by_severity``,
            ``by_type``, and ``unique_payloads`` keys.
        """
        total = self.crash_count()

        by_protocol = {}
        for row in self._conn.execute(
            "SELECT protocol, COUNT(*) AS cnt FROM crashes GROUP BY protocol"
        ).fetchall():
            by_protocol[row["protocol"]] = row["cnt"]

        by_severity = {}
        for row in self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM crashes "
            "WHERE severity IS NOT NULL GROUP BY severity"
        ).fetchall():
            by_severity[row["severity"]] = row["cnt"]

        by_type = {}
        for row in self._conn.execute(
            "SELECT crash_type, COUNT(*) AS cnt FROM crashes GROUP BY crash_type"
        ).fetchall():
            by_type[row["crash_type"]] = row["cnt"]

        unique = self._conn.execute(
            "SELECT COUNT(DISTINCT payload_hash) AS cnt FROM crashes"
        ).fetchone()

        unique_sigs = self._conn.execute(
            "SELECT COUNT(DISTINCT crash_signature) AS cnt FROM crashes "
            "WHERE crash_signature IS NOT NULL"
        ).fetchone()

        return {
            "total": total,
            "unique_payloads": unique["cnt"] if unique else 0,
            "unique_signatures": unique_sigs["cnt"] if unique_sigs else 0,
            "by_protocol": by_protocol,
            "by_severity": by_severity,
            "by_type": by_type,
        }

    # -- Export -------------------------------------------------------------

    def export_json(self, output_path: str) -> None:
        """Export all crashes to a JSON file.

        Args:
            output_path: Filesystem path for the output JSON file.
                Parent directories are created automatically.
        """
        crashes = self.get_crashes()
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(
                {
                    "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "total_crashes": len(crashes),
                    "crashes": crashes,
                },
                f,
                indent=2,
                default=str,
            )

    # -- Reproduction -------------------------------------------------------

    def reproduce_crash(
        self,
        crash_id: int,
        transport: BluetoothTransport,
        recv_timeout: float = 5.0,
    ) -> bool:
        """Replay the exact payload from a crash record and check if it recurs.

        Connects the transport, sends the stored payload, and waits for a
        response.  The crash is considered reproduced if:

        - The connection drops (``ConnectionResetError``, ``BrokenPipeError``).
        - The receive times out (possible device hang/crash).
        - The device disappears (``OSError`` during send).

        On successful reproduction the crash record is automatically marked
        as reproduced in the database.

        Args:
            crash_id: Primary key of the crash to reproduce.
            transport: A configured (but not yet connected) transport
                instance pointing at the same target.
            recv_timeout: How long to wait for a response before declaring
                timeout (seconds).

        Returns:
            True if the crash was reproduced, False otherwise.
        """
        crash = self.get_crash_by_id(crash_id)
        if crash is None:
            warning(f"Crash ID {crash_id} not found in database")
            return False

        # Build the packet list to replay.  If a multi-packet sequence was
        # stored, send each packet in order (the setup sequence matters for
        # state-machine crashes).  Fall back to single payload otherwise.
        packet_sequence_json = crash.get("packet_sequence_json")
        if packet_sequence_json:
            try:
                packets_to_send = [bytes.fromhex(h) for h in json.loads(packet_sequence_json)]
            except (ValueError, json.JSONDecodeError) as exc:
                warning(f"Corrupted packet_sequence_json for crash {crash_id}: {exc}")
                packets_to_send = None
        else:
            packets_to_send = None

        if packets_to_send is None:
            try:
                payload = bytes.fromhex(crash["payload_hex"])
            except ValueError as exc:
                warning(f"Corrupted payload hex for crash {crash_id}: {exc}")
                return False
            packets_to_send = [payload]

        total_bytes = sum(len(p) for p in packets_to_send)
        info(f"Reproducing crash {crash_id}: {len(packets_to_send)} packet(s), "
             f"{total_bytes} total bytes via {crash.get('protocol', 'unknown')}")

        try:
            if not transport.connect():
                # Cannot even connect — device may already be crashed
                if not transport.is_alive():
                    info(f"Crash {crash_id} reproduced: device unreachable on connect")
                    self.mark_reproduced(crash_id, True)
                    return True
                warning(f"Crash {crash_id}: connect failed but device is alive")
                return False

            total_sent = 0
            for pkt in packets_to_send:
                sent = transport.send(pkt)
                total_sent += sent
            info(f"Crash {crash_id}: sent {total_sent} bytes ({len(packets_to_send)} packet(s)), waiting for response")
            response = transport.recv(recv_timeout=recv_timeout)

            if response is None:
                # Connection closed by remote — crash reproduced
                info(f"Crash {crash_id} reproduced: connection closed by remote")
                self.mark_reproduced(crash_id, True)
                return True

            if response == b"":
                # Timeout — possible hang
                info(f"Crash {crash_id}: recv timed out, checking device liveness")
                if not transport.is_alive():
                    info(f"Crash {crash_id} reproduced: device unresponsive after timeout")
                    self.mark_reproduced(crash_id, True)
                    return True

            info(f"Crash {crash_id}: not reproduced (got {len(response)} byte response)")
            return False

        except (ConnectionResetError, BrokenPipeError, ConnectionError):
            # Connection drop — crash confirmed
            info(f"Crash {crash_id} reproduced: connection dropped")
            self.mark_reproduced(crash_id, True)
            return True
        except OSError:
            # General socket error — device may have disappeared
            if not transport.is_alive():
                info(f"Crash {crash_id} reproduced: device disappeared after OSError")
                self.mark_reproduced(crash_id, True)
                return True
            warning(f"Crash {crash_id}: OSError but device still alive")
            return False
        finally:
            transport.close()

    # -- Lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> CrashDB:
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        try:
            count = self.crash_count()
        except sqlite3.ProgrammingError:
            count = -1
        return f"<CrashDB path={self.db_path!r} crashes={count}>"
