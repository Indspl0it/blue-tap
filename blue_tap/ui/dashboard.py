"""Real-time attack dashboard using Rich Live display.

Shows LMP packet stream, connection status, and attack progress
in an updating terminal UI.
"""

import time
from collections import deque

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from blue_tap.utils.output import info, warning


class AttackDashboard:
    """Rich Live dashboard for DarkFirmware operations.

    Renders a three-panel layout:
      - Header: target info, connection/encryption status, current phase
      - Body:   scrolling LMP packet stream table (last 20 packets)
      - Footer: packet counters (RX, TX, errors)

    Use as a context manager or call ``start()`` / ``stop()`` manually.
    """

    def __init__(self, target: str = ""):
        self.target = target
        self._packets: deque[dict] = deque(maxlen=20)
        self._status = {"connection": "unknown", "encryption": "unknown", "phase": "idle"}
        self._stats = {"packets_rx": 0, "packets_tx": 0, "errors": 0}
        self._live: Live | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────

    def start(self):
        """Start the live display."""
        self._live = Live(self._render(), auto_refresh=False)
        self._live.start()
        info("AttackDashboard live display started")

    def stop(self):
        """Stop the live display."""
        if self._live:
            self._live.stop()
            self._live = None
            info("AttackDashboard live display stopped")

    # ── Callbacks ─────────────────────────────────────────────────────

    def on_lmp_packet(self, pkt: dict):
        """Callback for LMP packet -- updates the packet table."""
        self._packets.append({
            "time": time.strftime("%H:%M:%S"),
            "opcode": pkt.get("opcode", 0),
            "direction": pkt.get("direction", "rx"),
            "data": pkt.get("payload", b"").hex()[:24] if pkt.get("payload") else "(metadata)",
            "has_data": pkt.get("has_data", False),
        })
        if pkt.get("direction") == "tx":
            self._stats["packets_tx"] += 1
        else:
            self._stats["packets_rx"] += 1
        if self._live:
            self._live.update(self._render())
            self._live.refresh()

    def update_status(self, key: str, value: str):
        """Update a status field (connection, encryption, phase)."""
        self._status[key] = value
        if self._live:
            self._live.update(self._render())
            self._live.refresh()

    def update_stats(self, key: str, value: int):
        """Update a stat counter."""
        self._stats[key] = value
        if self._live:
            self._live.update(self._render())

    # ── Rendering ─────────────────────────────────────────────────────

    def _render(self):
        """Build the dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=5),
        )

        # Header: target info + status
        header = Panel(
            Text(
                f"Target: {self.target}  |  "
                f"Connection: {self._status['connection']}  |  "
                f"Encryption: {self._status['encryption']}  |  "
                f"Phase: {self._status['phase']}",
                style="bold",
            ),
            title="[bold blue]Blue-Tap DarkFirmware Dashboard[/bold blue]",
        )
        layout["header"].update(header)

        # Body: LMP packet stream table
        table = Table(title="LMP Packet Stream", expand=True)
        table.add_column("Time", width=10)
        table.add_column("Dir", width=4)
        table.add_column("Opcode", width=28)
        table.add_column("Data", width=30)
        table.add_column("Full", width=5)

        try:
            from blue_tap.fuzz.protocols.lmp import COMMAND_NAMES
        except ImportError:
            COMMAND_NAMES = {}

        # Security-relevant opcode sets for colour coding
        _auth_ops = {11, 12, 15, 16, 17, 18}
        _feature_ops = {37, 38, 39, 40}

        for pkt in self._packets:
            opcode = pkt["opcode"]
            name = COMMAND_NAMES.get(opcode, f"0x{opcode:04x}")
            style = (
                "red" if opcode in _auth_ops
                else "green" if opcode in _feature_ops
                else ""
            )
            direction = pkt.get("direction", "rx").upper()
            table.add_row(
                pkt["time"],
                direction,
                name,
                pkt["data"],
                "Y" if pkt["has_data"] else "N",
                style=style,
            )

        layout["body"].update(Panel(table))

        # Footer: statistics
        footer = Panel(
            Text(
                f"RX: {self._stats['packets_rx']}  |  "
                f"TX: {self._stats['packets_tx']}  |  "
                f"Errors: {self._stats['errors']}"
            ),
            title="Statistics",
        )
        layout["footer"].update(footer)

        return layout

    # ── Context manager ───────────────────────────────────────────────

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
