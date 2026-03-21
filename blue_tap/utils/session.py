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
import os
from datetime import datetime


# Module-level active session (set by CLI --session flag)
_active_session: "Session | None" = None


def get_session() -> "Session | None":
    """Get the active session, or None if no session is active."""
    return _active_session


def set_session(session: "Session | None"):
    """Set the active session (called by CLI main group)."""
    global _active_session
    _active_session = session


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

    def __init__(self, name: str, base_dir: str = "."):
        # Sanitize name to prevent path traversal
        safe_name = os.path.basename(name)
        if not safe_name or safe_name != name:
            raise ValueError(f"Invalid session name: {name!r} (must be a simple name, no path separators)")
        self.name = safe_name
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
            "created": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "adapter": "",
            "targets": [],
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
        """Write session metadata to disk."""
        self.metadata["last_updated"] = datetime.now().isoformat()
        with open(self.meta_file, "w") as f:
            json.dump(self.metadata, f, indent=2, default=str)

    def log(self, command: str, data: dict | list | str,
            category: str = "general", target: str = "") -> str:
        """Log a command result to the session.

        Creates a numbered JSON file and adds an entry to the command log.
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
            "timestamp": datetime.now().isoformat(),
            "data": data,
        }
        with open(filepath, "w") as f:
            json.dump(entry, f, indent=2, default=str)

        # Update command log
        log_entry = {
            "seq": self.command_count,
            "command": command,
            "category": category,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "file": filename,
        }
        self.metadata.setdefault("commands", []).append(log_entry)

        # Track unique targets
        if target and target not in self.metadata.get("targets", []):
            self.metadata.setdefault("targets", []).append(target)

        self._save_meta()
        return filepath

    def save_raw(self, filename: str, content: str | bytes,
                 subdir: str = "") -> str:
        """Save a raw file to the session directory."""
        if subdir:
            target_dir = os.path.join(self.dir, subdir)
            os.makedirs(target_dir, exist_ok=True)
            filepath = os.path.join(target_dir, filename)
        else:
            filepath = os.path.join(self.dir, filename)

        mode = "wb" if isinstance(content, bytes) else "w"
        with open(filepath, mode) as f:
            f.write(content)

        self.metadata.setdefault("files", []).append({
            "path": os.path.relpath(filepath, self.dir),
            "timestamp": datetime.now().isoformat(),
            "size": len(content),
        })
        self._save_meta()
        return filepath

    def get_all_data(self) -> dict:
        """Collect all session data for report generation.

        Reads all numbered JSON files and organizes by category.
        Returns a dict ready for ReportGenerator.
        """
        collected = {
            "session": self.metadata,
            "scan": [],
            "recon": [],
            "vuln": [],
            "attack": [],
            "data": [],
            "fuzz": [],
            "dos": [],
            "audio": [],
            "general": [],
        }

        for cmd_entry in self.metadata.get("commands", []):
            filepath = os.path.join(self.dir, cmd_entry["file"])
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath) as f:
                    entry = json.load(f)
                category = entry.get("category", "general")
                if category in collected:
                    collected[category].append(entry)
                else:
                    collected["general"].append(entry)
            except (json.JSONDecodeError, OSError):
                pass

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
