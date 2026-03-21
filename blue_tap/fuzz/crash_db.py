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
from typing import TYPE_CHECKING, Optional

from blue_tap.utils.output import info, warning

if TYPE_CHECKING:
    from blue_tap.fuzz.transport import BluetoothTransport


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
    payload_hash        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_crashes_hash     ON crashes(payload_hash);
CREATE INDEX IF NOT EXISTS idx_crashes_protocol ON crashes(protocol);
CREATE INDEX IF NOT EXISTS idx_crashes_severity ON crashes(severity);
"""


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
        """Create the crashes table and indexes if they don't exist."""
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    # -- Hashing ------------------------------------------------------------

    @staticmethod
    def _payload_hash(payload: bytes) -> str:
        """Compute SHA-256 hex digest for deduplication."""
        return hashlib.sha256(payload).hexdigest()

    # -- Logging ------------------------------------------------------------

    def log_crash(
        self,
        target: str,
        protocol: str,
        payload: bytes,
        crash_type: CrashType | str,
        response: Optional[bytes] = None,
        severity: Optional[CrashSeverity | str] = None,
        payload_description: str = "",
        response_description: str = "",
        mutation_log: str = "",
        session_id: str = "",
        notes: str = "",
    ) -> int:
        """Log a crash to the database.

        Deduplicates by ``(target_addr, protocol, payload_hash)``.  If an
        identical payload was already logged for the same target and protocol,
        the existing crash ID is returned without inserting a duplicate.

        Args:
            target: BD_ADDR of the target device.
            protocol: Protocol name (e.g. ``"l2cap"``, ``"rfcomm"``, ``"att"``).
            payload: Raw payload bytes that triggered the crash.
            crash_type: How the crash manifested.
            response: Optional raw response bytes from the device.
            severity: Optional severity classification.
            payload_description: Human-readable description of the payload.
            response_description: Human-readable description of the response.
            mutation_log: Description of mutations applied to reach this payload.
            session_id: Fuzzing session identifier.
            notes: Free-form notes.

        Returns:
            The crash ID (integer primary key).
        """
        # Normalize enum values to their string form
        crash_type_str = crash_type.value if isinstance(crash_type, CrashType) else str(crash_type)
        severity_str: Optional[str] = None
        if severity is not None:
            severity_str = severity.value if isinstance(severity, CrashSeverity) else str(severity)

        payload_hex = payload.hex()
        p_hash = self._payload_hash(payload)

        # Deduplication check: same target + protocol + payload hash
        existing = self._conn.execute(
            "SELECT id FROM crashes "
            "WHERE target_addr = ? AND protocol = ? AND payload_hash = ?",
            (target, protocol, p_hash),
        ).fetchone()

        if existing is not None:
            return existing["id"]

        response_hex = response.hex() if response else None

        cursor = self._conn.execute(
            """INSERT INTO crashes (
                target_addr, protocol, payload_hex, payload_len,
                payload_description, crash_type, response_hex,
                response_description, session_id, mutation_log,
                severity, notes, payload_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target, protocol, payload_hex, len(payload),
                payload_description or None, crash_type_str, response_hex,
                response_description or None, session_id or None,
                mutation_log or None, severity_str, notes or None, p_hash,
            ),
        )
        self._conn.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("INSERT succeeded but lastrowid is None")
        return cursor.lastrowid

    # -- Queries ------------------------------------------------------------

    def get_crashes(
        self,
        protocol: Optional[str] = None,
        severity: Optional[CrashSeverity | str] = None,
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
        """Retrieve crashes deduplicated by payload_hash.

        For each unique payload hash, returns the first (earliest) crash
        record.

        Returns:
            List of unique crash dicts ordered by timestamp descending.
        """
        rows = self._conn.execute(
            """SELECT * FROM crashes
               WHERE id IN (
                   SELECT MIN(id) FROM crashes GROUP BY payload_hash
               )
               ORDER BY timestamp DESC"""
        ).fetchall()
        return [dict(row) for row in rows]

    def get_crash_by_id(self, crash_id: int) -> Optional[dict]:
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

    def crash_count(self, protocol: Optional[str] = None) -> int:
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

        return {
            "total": total,
            "unique_payloads": unique["cnt"] if unique else 0,
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
        transport: "BluetoothTransport",
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

        try:
            payload = bytes.fromhex(crash["payload_hex"])
        except ValueError as exc:
            warning(f"Corrupted payload hex for crash {crash_id}: {exc}")
            return False

        info(f"Reproducing crash {crash_id}: {len(payload)} byte payload "
             f"via {crash.get('protocol', 'unknown')}")

        try:
            if not transport.connect():
                # Cannot even connect — device may already be crashed
                if not transport.is_alive():
                    info(f"Crash {crash_id} reproduced: device unreachable on connect")
                    self.mark_reproduced(crash_id, True)
                    return True
                warning(f"Crash {crash_id}: connect failed but device is alive")
                return False

            sent = transport.send(payload)
            info(f"Crash {crash_id}: sent {sent} bytes, waiting for response")
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

    def __enter__(self) -> "CrashDB":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __repr__(self) -> str:
        try:
            count = self.crash_count()
        except sqlite3.ProgrammingError:
            count = -1
        return f"<CrashDB path={self.db_path!r} crashes={count}>"
