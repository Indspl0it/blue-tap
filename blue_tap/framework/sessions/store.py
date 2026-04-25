"""Session management — accumulates all command outputs for unified reporting.

Every blue-tap command auto-logs its structured output to the active session.
The report command then reads everything from the session directory.

Usage:
    blue-tap -s my_assessment scan classic        # logs scan results
    blue-tap -s my_assessment vulnscan AA:BB:...   # logs vuln findings
    blue-tap -s my_assessment report               # auto-collects everything

Session directory structure:
    sessions/my_assessment/
        session.json             # metadata + command log
        001_scan_classic.json    # first command output
        002_vulnscan.json        # second command output
        pbap/                    # PBAP dumps (vCards)
        map/                     # MAP message dumps
        audio/                   # Audio captures
        report.html              # Generated report
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

from blue_tap.framework.contracts.result_schema import looks_like_run_envelope, validate_run_envelope

_logger = logging.getLogger(__name__)

_USE_O_TMPFILE = (
    sys.platform == "linux"
    and hasattr(os, "O_TMPFILE")
    and os.path.exists("/proc/self/fd")
)


def _now_iso_utc() -> str:
    """Return the current time as a UTC ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _fsync_dir(directory: str) -> None:
    """Best-effort fsync of ``directory`` to commit metadata to disk."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _atomic_write_bytes_or_text(filepath: str, content: str | bytes) -> None:
    """Write ``content`` to ``filepath`` atomically with no SIGKILL debris.

    On Linux the write goes to an unnamed ``O_TMPFILE`` inode that the kernel
    reaps on process death, so a SIGKILL during the write phase leaves nothing
    on disk. The inode is then ``link()``-ed into the directory under a
    PID-suffixed name and ``os.replace()``-d into the target — that final
    materialisation window is on the order of microseconds. The parent
    directory is fsynced after the rename so the entry reaches stable
    storage even if power is lost immediately after ``os.replace`` returns.

    On non-Linux platforms (Windows, BSD without ``O_TMPFILE``) the fallback
    path uses a uniquely named per-PID tempfile and the same rename + dir
    fsync flow. The PID suffix prevents concurrent writers to the same target
    from clobbering each other's temp files.
    """
    directory = os.path.dirname(filepath) or "."
    os.makedirs(directory, exist_ok=True)
    body = content.encode() if isinstance(content, str) else content
    tmp_path = f"{filepath}.tmp.{os.getpid()}"

    if _USE_O_TMPFILE:
        try:
            fd = os.open(directory, os.O_TMPFILE | os.O_RDWR, 0o644)
        except OSError:
            # Filesystems without O_TMPFILE support (9p WSL mounts, some FUSE
            # backends, certain NFS configs) raise EOPNOTSUPP/EISDIR/ENOTSUP
            # at open. Fall through to the named-tmp path.
            fd = -1
        if fd >= 0:
            try:
                written = 0
                while written < len(body):
                    written += os.write(fd, body[written:])
                os.fsync(fd)
                try:
                    os.link(f"/proc/self/fd/{fd}", tmp_path)
                except OSError:
                    # Some filesystems refuse the /proc-symlink linkat even
                    # when O_TMPFILE itself worked. Fall through.
                    pass
                else:
                    try:
                        os.replace(tmp_path, filepath)
                    except Exception:
                        _cleanup_path(tmp_path)
                        raise
                    _fsync_dir(directory)
                    return
            finally:
                os.close(fd)

    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            written = 0
            while written < len(body):
                written += os.write(fd, body[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, filepath)
        _fsync_dir(directory)
    except Exception:
        _cleanup_path(tmp_path)
        raise


def _cleanup_path(path: str) -> None:
    """Best-effort unlink; never raises."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _atomic_write_json(filepath: str, payload: dict | list) -> None:
    """JSON-serialise ``payload`` and write it atomically to ``filepath``."""
    text = json.dumps(payload, indent=2, default=str)
    _atomic_write_bytes_or_text(filepath, text)


def resolve_sessions_base_dir() -> str:
    """Return the directory containing per-session subdirectories.

    Resolution order (first wins):
      1. ``BT_TAP_SESSIONS_DIR`` environment variable — explicit override
      2. ``./sessions`` if it exists in the current working directory — legacy layout
      3. ``~/.blue-tap`` — user-scoped default

    The returned path is the *parent* of individual session dirs. The ``sessions``
    suffix is owned by ``Session.__init__`` (``SESSIONS_DIR``).
    """
    override = os.environ.get("BT_TAP_SESSIONS_DIR")
    if override:
        return override
    cwd_sessions = os.path.join(".", "sessions")
    if os.path.isdir(cwd_sessions):
        return "."
    return os.path.expanduser("~/.blue-tap")


# Module-level active session (set by CLI --session flag)
_active_session: "Session | None" = None


def get_session() -> "Session | None":
    """Get the active session, or None if no session is active."""
    return _active_session


def set_session(session: "Session | None"):
    """Set the active session (called by CLI main group)."""
    global _active_session
    _active_session = session


def set_adapter(adapter: str) -> None:
    """Record which adapter is being used in the active session."""
    session = get_session()
    if session is not None and adapter and not session.metadata.get("adapter"):
        session.metadata["adapter"] = adapter
        session._save_meta()


def log_command(command: str, data: dict | list | str,
                category: str = "general",
                target: str = "") -> str | None:
    """Log a command result to the active session.

    This is the main API for commands to save their output.
    Safe to call even when no session is active (returns None).

    Args:
        command: Command name (e.g., "scan_classic", "vulnscan", "pbap_pull")
        data: Structured output from the command
        category: Category for grouping in reports:
                  "scan", "recon", "attack", "vuln", "data", "fuzz", "dos", "audio"
        target: Target MAC address (if applicable)

    Returns:
        Path to the saved file, or None if no active session.
    """
    session = get_session()
    if session is None:
        return None
    return session.log(command, data, category=category, target=target)


def save_file(filename: str, content: str | bytes,
              subdir: str = "") -> str | None:
    """Save a raw file (vCard, audio, pcap) to the session directory.

    Args:
        filename: File name (e.g., "telecom_pb.vcf")
        content: File content (str or bytes)
        subdir: Subdirectory within session (e.g., "pbap", "audio")

    Returns:
        Full path to saved file, or None if no active session.
    """
    session = get_session()
    if session is None:
        return None
    return session.save_raw(filename, content, subdir=subdir)


class Session:
    """Pentest assessment session — accumulates all command outputs."""

    SESSIONS_DIR = "sessions"

    def __init__(self, name: str, base_dir: str | None = None):
        # Sanitize name to prevent path traversal
        safe_name = os.path.basename(name)
        if not safe_name or safe_name != name:
            raise ValueError(f"Invalid session name: {name!r} (must be a simple name, no path separators)")
        self.name = safe_name
        if base_dir is None:
            base_dir = resolve_sessions_base_dir()
        self.dir = os.path.join(base_dir, self.SESSIONS_DIR, safe_name)
        self.meta_file = os.path.join(self.dir, "session.json")
        self.command_count = 0
        self.metadata = {}

        # Create or resume session
        if os.path.exists(self.meta_file):
            self._load()
        else:
            self._create()

    def _create(self):
        """Create a new session."""
        os.makedirs(self.dir, exist_ok=True)
        self.metadata = {
            "name": self.name,
            "created": _now_iso_utc(),
            "last_updated": _now_iso_utc(),
            "adapter": "",
            "targets": [],
            "hosts": [],
            "commands": [],
            "files": [],
        }
        self._save_meta()

    def _load(self):
        """Resume an existing session."""
        try:
            with open(self.meta_file) as f:
                self.metadata = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Corrupt session file — recreate from scratch
            self._create()
            return
        self.command_count = len(self.metadata.get("commands", []))

    def _save_meta(self):
        """Write session metadata to disk atomically.

        Delegates to ``_atomic_write_json`` so the same tmp-file + fsync +
        rename + parent-dir-fsync protocol is used everywhere. A crash
        mid-write leaves the previous session.json intact instead of
        producing a truncated file that ``_load`` would interpret as
        corrupt and silently recreate.
        """
        self.metadata["last_updated"] = _now_iso_utc()
        _atomic_write_json(self.meta_file, self.metadata)

    def log(self, command: str, data: dict | list | str,
            category: str = "general", target: str = "") -> str:
        """Log a command result to the session.

        Creates a numbered JSON file atomically (temp write + rename) so a
        crash mid-write does not leave a truncated command artefact that the
        report generator would skip silently.
        """
        self.command_count += 1
        seq = f"{self.command_count:03d}"
        safe_cmd = command.replace(" ", "_").replace("/", "_")[:40]
        filename = f"{seq}_{safe_cmd}.json"
        filepath = os.path.join(self.dir, filename)

        # Write the data file
        entry = {
            "command": command,
            "category": category,
            "target": target,
            "timestamp": _now_iso_utc(),
            "data": data,
        }
        if looks_like_run_envelope(data):
            errors = validate_run_envelope(data)
            entry["validation"] = {
                "checked_at_write_time": True,
                "valid": not errors,
                "errors": errors,
            }
        else:
            _logger.debug(
                "Non-envelope data logged for command %s (category=%s)",
                command,
                category,
            )
        _atomic_write_json(filepath, entry)

        # Update command log
        log_entry = {
            "seq": self.command_count,
            "command": command,
            "category": category,
            "target": target,
            "timestamp": _now_iso_utc(),
            "file": filename,
        }
        if "validation" in entry:
            log_entry["validation"] = entry["validation"]
        self.metadata.setdefault("commands", []).append(log_entry)

        # Track unique targets
        if target and target not in self.metadata.get("targets", []):
            self.metadata.setdefault("targets", []).append(target)

        self._save_meta()
        return filepath

    def save_raw(self, filename: str, content: str | bytes | None = None,
                 subdir: str = "", *,
                 data: str | bytes | None = None,
                 artifact_type: str | None = None) -> str:
        """Save a raw file to the session directory atomically.

        ``content`` and ``data`` are accepted as aliases; exactly one must be
        provided. ``artifact_type`` groups files into a per-type subdirectory
        when ``subdir`` is not explicitly set (e.g., ``artifact_type="pcap"``
        → ``<session>/pcap/<filename>``).

        Writes via tempfile + ``os.replace`` so a crash mid-write never leaves
        a partially-written artefact on disk. Path traversal is blocked by
        anchoring the final path under ``self.dir``.
        """
        if content is None and data is None:
            raise TypeError("save_raw requires either 'content' or 'data'")
        if content is None:
            content = data

        if not subdir and artifact_type:
            subdir = artifact_type

        safe_filename = os.path.basename(filename)
        if not safe_filename or safe_filename != filename:
            raise ValueError(f"Invalid artifact filename: {filename!r}")

        if subdir:
            # Only allow single-level subdirs; reject path traversal attempts.
            safe_subdir = os.path.basename(subdir)
            if not safe_subdir or safe_subdir != subdir:
                raise ValueError(f"Invalid subdir: {subdir!r}")
            target_dir = os.path.join(self.dir, safe_subdir)
            os.makedirs(target_dir, exist_ok=True)
            filepath = os.path.join(target_dir, safe_filename)
        else:
            filepath = os.path.join(self.dir, safe_filename)

        _atomic_write_bytes_or_text(filepath, content)

        self.metadata.setdefault("files", []).append({
            "path": os.path.relpath(filepath, self.dir),
            "timestamp": _now_iso_utc(),
            "size": len(content),
            "artifact_type": artifact_type or "",
        })
        self._save_meta()
        return filepath

    def log_host(self, addr: str, name: str = "", device_type: str = "",
                manufacturer: str = "") -> None:
        """Upsert a discovered device into the session hosts table.

        Keyed on ``addr`` (normalised to upper-case). Updates ``name``,
        ``type``, ``manufacturer`` only when the incoming value is non-empty
        so a later call with less information doesn't erase existing data.
        """
        addr = addr.upper().strip()
        if not addr:
            return
        hosts: list[dict] = self.metadata.setdefault("hosts", [])
        for host in hosts:
            if host.get("addr", "").upper() == addr:
                if name:
                    host["name"] = name
                if device_type:
                    host["type"] = device_type
                if manufacturer:
                    host["manufacturer"] = manufacturer
                host["last_seen"] = _now_iso_utc()
                self._save_meta()
                return
        hosts.append({
            "addr": addr,
            "name": name,
            "type": device_type,
            "manufacturer": manufacturer,
            "last_seen": _now_iso_utc(),
        })
        self._save_meta()

    def get_hosts(self) -> list[dict]:
        """Return all discovered hosts for this session."""
        return list(self.metadata.get("hosts", []))

    def get_all_data(self) -> dict:
        """Collect all session data for report generation.

        Reads every numbered JSON command file and groups it by the
        ``category`` field recorded at write time. Unknown categories are
        preserved under their own key rather than collapsing into
        ``general`` — this matters because ``_infer_log_category`` derives
        categories from the envelope schema (``blue_tap.<category>.result``)
        and produces values like ``assessment`` and ``vulnscan`` that were
        not enumerated in the legacy hardcoded list. Dropping them into
        ``general`` made the report generator skip them entirely.
        """
        collected: dict[str, Any] = {
            "session": self.metadata,
            "general": [],
        }

        for cmd_entry in self.metadata.get("commands", []):
            filepath = os.path.join(self.dir, cmd_entry["file"])
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath) as f:
                    entry = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            category = entry.get("category", "general") or "general"
            collected.setdefault(category, []).append(entry)

        # Also collect raw files (vCards, audio, etc.)
        collected["raw_files"] = self.metadata.get("files", [])

        return collected

    def get_output_dir(self, subdir: str = "") -> str:
        """Get a subdirectory path within the session, creating it if needed."""
        if subdir:
            path = os.path.join(self.dir, subdir)
        else:
            path = self.dir
        os.makedirs(path, exist_ok=True)
        return path

    def summary(self) -> dict:
        """Get session summary stats."""
        commands = self.metadata.get("commands", [])
        return {
            "name": self.name,
            "created": self.metadata.get("created", ""),
            "last_updated": self.metadata.get("last_updated", ""),
            "total_commands": len(commands),
            "targets": self.metadata.get("targets", []),
            "categories": list(set(c.get("category", "") for c in commands)),
            "files": len(self.metadata.get("files", [])),
            "directory": self.dir,
        }


__all__ = [
    "Session",
    "get_session",
    "log_command",
    "save_file",
    "set_adapter",
    "set_session",
    "log_host",
]


def log_host(addr: str, name: str = "", device_type: str = "",
             manufacturer: str = "") -> None:
    """Log a discovered host to the active session (module-level convenience)."""
    session = get_session()
    if session is not None:
        session.log_host(addr, name=name, device_type=device_type,
                         manufacturer=manufacturer)
