"""BT-Tap Rich UI — styled console output with phase tracking and verbosity."""

import time
from contextlib import contextmanager
from datetime import datetime

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Color Palette ──────────────────────────────────────────────────────────
# Raw hex values for use in Style objects (Table headers, columns, etc.)
# Theme names (bt.cyan etc.) only work inside [markup] tags via console.print.

CYAN = "#00d4ff"
GREEN = "#00ff9f"
YELLOW = "#ffaa00"
RED = "#ff3333"
PURPLE = "#bf5af2"
DIM = "#666666"
BLUE = "#4488ff"
ORANGE = "#ff6b35"
PINK = "#ff79c6"

_THEME = Theme(
    {
        "bt.cyan": CYAN,
        "bt.green": GREEN,
        "bt.yellow": YELLOW,
        "bt.red": RED,
        "bt.purple": PURPLE,
        "bt.dim": DIM,
        "bt.blue": BLUE,
        "bt.orange": ORANGE,
        "bt.pink": PINK,
    }
)

console = Console(theme=_THEME)

# ── Verbosity ──────────────────────────────────────────────────────────────

_VERBOSITY = 0  # 0 = normal, 1 = verbose (-v), 2 = debug (-vv)


def set_verbosity(level: int):
    """Set global verbosity: 0=normal, 1=verbose, 2=debug."""
    global _VERBOSITY
    _VERBOSITY = max(0, min(2, level))


def get_verbosity() -> int:
    return _VERBOSITY


# ── Banner ─────────────────────────────────────────────────────────────────

_LOGO = r"""
  [#00d4ff]██████[/#00d4ff] [#00bbee]████████[/#00bbee]        [#9966ff]████████[/#9966ff] [#bf5af2]█████[/#bf5af2]  [#ff3366]██████[/#ff3366]
  [#00d4ff]██[/#00d4ff]   [#00d4ff]██[/#00d4ff]    [#00bbee]██[/#00bbee]              [#9966ff]██[/#9966ff]    [#bf5af2]██[/#bf5af2]   [#bf5af2]██[/#bf5af2] [#ff3366]██[/#ff3366]   [#ff3366]██[/#ff3366]
  [#00ccee]██████[/#00ccee]     [#00aadd]██[/#00aadd]    [#7744dd]██████[/#7744dd]    [#aa55ee]██[/#aa55ee]    [#cc44ee]███████[/#cc44ee] [#ff3366]██████[/#ff3366]
  [#00bbdd]██[/#00bbdd]   [#00bbdd]██[/#00bbdd]    [#0099cc]██[/#0099cc]              [#9944dd]██[/#9944dd]    [#bb44ee]██[/#bb44ee]   [#bb44ee]██[/#bb44ee] [#ff4477]██[/#ff4477]
  [#00aacc]██████[/#00aacc]     [#0088bb]██[/#0088bb]              [#8833cc]██[/#8833cc]    [#aa33dd]██[/#aa33dd]   [#aa33dd]██[/#aa33dd] [#ff5588]██[/#ff5588]
"""

_BANNER_SHOWN = False

def banner():
    """Print the BT-Tap ASCII art banner (once per process)."""
    global _BANNER_SHOWN
    if _BANNER_SHOWN:
        return
    _BANNER_SHOWN = True
    console.print(_LOGO, highlight=False)
    tagline = (
        "[bt.dim]───────── [/bt.dim]"
        "[bt.cyan]Bluetooth/BLE[/bt.cyan] "
        "[bt.purple]Automotive IVI[/bt.purple] "
        "[bt.red]Pentest Toolkit[/bt.red]"
        "[bt.dim] ─────────[/bt.dim]"
    )
    console.print(Align.center(tagline), highlight=False)
    console.print(
        Align.center("[bt.dim]v1.5.0 │ github.com/bt-tap[/bt.dim]"),
        highlight=False,
    )
    console.print()


# ── Timestamp helper ───────────────────────────────────────────────────────

def _ts() -> str:
    """Return a dim HH:MM:SS timestamp."""
    return datetime.now().strftime("%H:%M:%S")


# ── Core log functions ─────────────────────────────────────────────────────

def info(msg: str):
    """Informational message — cyan [*]."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.cyan]●[/bt.cyan]  {msg}")


def success(msg: str):
    """Success message — green [+]."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.green]✔[/bt.green]  {msg}")


def warning(msg: str):
    """Warning message — amber [!]."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.yellow]⚠[/bt.yellow]  {msg}")


def error(msg: str):
    """Error message — red [-]."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.red]✖[/bt.red]  {msg}")


def verbose(msg: str):
    """Only printed when -v or higher."""
    if _VERBOSITY >= 1:
        console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]·[/bt.dim]  [bt.dim]{msg}[/bt.dim]")


def debug(msg: str):
    """Only printed when -vv."""
    if _VERBOSITY >= 2:
        console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]⋯[/bt.dim]  [dim]{msg}[/dim]")


# ── Target highlighting ───────────────────────────────────────────────────

def target(address: str) -> str:
    """Wrap a MAC address in purple styling for inline use."""
    return f"[bt.purple]{address}[/bt.purple]"


def highlight(text: str, style: str = "bt.cyan") -> str:
    """Wrap text in a style for inline use."""
    return f"[{style}]{text}[/{style}]"


# ── Phase / Step tracking ─────────────────────────────────────────────────

_PHASE_COLORS = ["bt.cyan", "bt.yellow", "bt.red", "bt.green", "bt.purple", "bt.orange", "bt.pink", "bt.blue"]


@contextmanager
def phase(name: str, number: int = None, total: int = None):
    """Context manager for a numbered attack/recon phase.

    Usage:
        with phase("Reconnaissance", 1, 5):
            info("Scanning...")
            ...

    Prints a styled header on entry, elapsed time + status on exit.
    """
    if number is not None and total is not None:
        color = _PHASE_COLORS[(number - 1) % len(_PHASE_COLORS)]
        header = f"[bold {color}]▶ Phase {number}/{total}: {name}[/bold {color}]"
    elif number is not None:
        color = _PHASE_COLORS[(number - 1) % len(_PHASE_COLORS)]
        header = f"[bold {color}]▶ Phase {number}: {name}[/bold {color}]"
    else:
        header = f"[bold bt.cyan]▶ {name}[/bold bt.cyan]"

    console.print()
    console.rule(header, style="dim")
    t0 = time.time()
    try:
        yield
    except Exception:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.red]✖[/bt.red]  "
            f"Phase failed after [bt.yellow]{elapsed:.1f}s[/bt.yellow]"
        )
        raise
    else:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.green]✔[/bt.green]  "
            f"Phase complete [bt.dim]({elapsed:.1f}s)[/bt.dim]"
        )


@contextmanager
def step(description: str):
    """Context manager for a sub-step within a phase.

    Usage:
        with step("Fingerprinting target"):
            ...  # work

    Shows a spinner while running, then elapsed time on completion.
    """
    t0 = time.time()
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]├─[/bt.dim] {description}")
    try:
        yield
    except Exception:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│[/bt.dim]  "
            f"[bt.red]└ failed[/bt.red] [bt.dim]({elapsed:.1f}s)[/bt.dim]"
        )
        raise
    else:
        elapsed = time.time() - t0
        if _VERBOSITY >= 1:
            console.print(
                f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│[/bt.dim]  "
                f"[bt.green]└ done[/bt.green] [bt.dim]({elapsed:.1f}s)[/bt.dim]"
            )


def substep(msg: str):
    """Print an indented sub-step line (always visible)."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│  ·[/bt.dim] {msg}")


# ── Section headers ────────────────────────────────────────────────────────

def section(title: str, style: str = "bt.cyan"):
    """Print a styled section divider."""
    console.print()
    console.rule(f"[bold {style}]{title}[/bold {style}]", style="dim")


# ── Summary panel ──────────────────────────────────────────────────────────

def summary_panel(title: str, items: dict, style: str = "cyan"):
    """Print a summary panel with key-value pairs.

    Usage:
        summary_panel("Recon Results", {
            "Target": "AA:BB:CC:DD:EE:FF",
            "Services": "12 found",
            "PBAP Channel": "19",
        })
    """
    text = Text()
    for key, value in items.items():
        text.append(f"  {key}: ", style="bold")
        text.append(f"{value}\n", style="")
    console.print(Panel(text, title=f"[bold]{title}[/bold]", border_style=style, padding=(1, 2)))


# ── Result box ─────────────────────────────────────────────────────────────

def result_box(title: str, content: str, style: str = "green"):
    """Small result panel for single-value outcomes."""
    console.print(
        Panel(content, title=title, border_style=style, padding=(0, 2), expand=False)
    )


# ── Progress helpers ───────────────────────────────────────────────────────

def get_progress(**kwargs) -> Progress:
    """Create a styled Rich Progress bar."""
    return Progress(
        SpinnerColumn("dots", style=CYAN),
        TextColumn(f"[{CYAN}]{{task.description}}[/{CYAN}]"),
        BarColumn(bar_width=30, style=DIM, complete_style=CYAN, finished_style=GREEN),
        TextColumn(f"[{DIM}]{{task.percentage:>3.0f}}%[/{DIM}]"),
        TimeElapsedColumn(),
        console=console,
        **kwargs,
    )


def get_spinner(description: str = "Working..."):
    """Create a simple spinner status."""
    return console.status(f"[bt.cyan]{description}", spinner="dots")


# ── Tables ─────────────────────────────────────────────────────────────────

def device_table(devices: list[dict], title: str = "Discovered Devices") -> Table:
    """Create a styled table of discovered devices."""
    table = Table(
        title=f"[bold {CYAN}]{title}[/bold {CYAN}]",
        show_lines=True,
        border_style=DIM,
        header_style=Style(bold=True, color=CYAN),
        title_style=Style(bold=True, color=CYAN),
    )
    table.add_column("#", style=DIM, width=4, justify="right")
    table.add_column("Address", style=PURPLE)
    table.add_column("Name", style="bold white")
    table.add_column("RSSI", style=YELLOW, justify="right")
    table.add_column("Type", style=BLUE)
    table.add_column("Class", style=DIM)
    table.add_column("Dist", style=DIM, justify="right")
    for i, dev in enumerate(devices, 1):
        rssi = str(dev.get("rssi", "N/A"))
        rssi_style = ""
        if rssi != "N/A":
            try:
                val = int(rssi)
                if val > -50:
                    rssi_style = GREEN
                elif val > -70:
                    rssi_style = YELLOW
                else:
                    rssi_style = RED
                rssi = f"[{rssi_style}]{rssi} dBm[/{rssi_style}]"
            except ValueError:
                pass
        # Device class info
        class_info = dev.get("class_info", {})
        class_str = class_info.get("major", "") if class_info else ""
        if class_info.get("minor") and class_info["minor"] != "Unknown":
            class_str = class_info["minor"]
        # Distance
        dist = dev.get("distance_m")
        dist_str = f"~{dist}m" if dist else ""
        table.add_row(
            str(i),
            dev.get("address", "N/A"),
            dev.get("name", "Unknown"),
            rssi,
            dev.get("type", "Classic"),
            class_str,
            dist_str,
        )
    return table


def service_table(services: list[dict], title: str = "Services") -> Table:
    """Create a styled table of discovered services."""
    table = Table(
        title=f"[bold {CYAN}]{title}[/bold {CYAN}]",
        show_lines=True,
        border_style=DIM,
        header_style=Style(bold=True, color=CYAN),
        title_style=Style(bold=True, color=CYAN),
    )
    table.add_column("#", style=DIM, width=4, justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Protocol", style=CYAN)
    table.add_column("Channel/PSM", style=YELLOW, justify="right")
    table.add_column("Profile", style=PURPLE)
    table.add_column("Ver", style=DIM, width=5)
    for i, svc in enumerate(services, 1):
        table.add_row(
            str(i),
            svc.get("name", "Unknown"),
            svc.get("protocol", "N/A"),
            str(svc.get("channel", "N/A")),
            svc.get("profile", ""),
            svc.get("profile_version", ""),
        )
    return table


def vuln_table(findings: list[dict], title: str = "Vulnerability Findings") -> Table:
    """Create a styled vulnerability findings table."""
    sev_styles = {
        "critical": f"bold {RED}",
        "high": RED,
        "medium": YELLOW,
        "low": GREEN,
        "info": BLUE,
    }
    table = Table(
        title=f"[bold {RED}]{title}[/bold {RED}]",
        show_lines=True,
        border_style=DIM,
        header_style=Style(bold=True, color=RED),
        title_style=Style(bold=True, color=RED),
    )
    status_styles = {
        "confirmed": f"bold {GREEN}",
        "potential": YELLOW,
        "unverified": DIM,
    }
    table.add_column("#", style=DIM, width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Status", width=12)
    table.add_column("Name", style="bold white")
    table.add_column("CVE", style=YELLOW)
    table.add_column("Description", max_width=45)
    for i, v in enumerate(findings, 1):
        sev = v.get("severity", "info").lower()
        style = sev_styles.get(sev, "bt.blue")
        sev_display = f"[{style}]■ {sev.upper()}[/{style}]"
        status = v.get("status", "potential")
        st_style = status_styles.get(status, DIM)
        status_display = f"[{st_style}]{status}[/{st_style}]"
        conf = v.get("confidence", "")
        if conf:
            status_display += f" [dim]({conf})[/dim]"
        table.add_row(
            str(i),
            sev_display,
            status_display,
            v.get("name", ""),
            v.get("cve", "N/A"),
            v.get("description", ""),
        )
    return table


def channel_table(results: list[dict], title: str = "Channel Scan") -> Table:
    """Create a styled table for RFCOMM/L2CAP scan results."""
    table = Table(
        title=f"[bold {CYAN}]{title}[/bold {CYAN}]",
        show_lines=True,
        border_style=DIM,
        header_style=Style(bold=True, color=CYAN),
        title_style=Style(bold=True, color=CYAN),
    )
    # Detect if RFCOMM (has "channel") or L2CAP (has "psm")
    is_rfcomm = any("channel" in r for r in results) if results else True
    if is_rfcomm:
        table.add_column("Channel", style=YELLOW, justify="right", width=8)
    else:
        table.add_column("PSM", style=YELLOW, justify="right", width=8)
    table.add_column("Status", width=16)
    table.add_column("Service/Type", style="bold white")

    status_styles = {
        "open": "[bt.green]● OPEN[/bt.green]",
        "auth_required": "[bt.yellow]◐ AUTH REQ[/bt.yellow]",
        "closed": "[bt.dim]○ closed[/bt.dim]",
        "timeout": "[bt.red]◌ timeout[/bt.red]",
    }

    for r in results:
        ch = str(r.get("channel", r.get("psm", "?")))
        status = r.get("status", "closed")
        status_display = status_styles.get(status, f"[bt.dim]{status}[/bt.dim]")
        name = r.get("name", r.get("response_type", ""))
        table.add_row(ch, status_display, name)
    return table
